"""Quarantine core operations (quarantine design §3.2-§3.4).

Isolate a file into the forensic store and unlink the original — reversibly,
with every post-open step going through the held fd/dirfd, never back through
the user-supplied path string (§3.2 "no re-traversal, ever"). Restore commits
via a link-no-replace through the same symlink-free parent dirfd; delete
removes the blob only when no other reference claims the sha, re-checked
under the capture lock.

Lifecycle: the row is INSERTed as ``isolating`` and flips to ``active`` only
after the unlink succeeds; unlink failure or a detected swap leaves ``failed``
with the blob kept. Status transitions are guarded UPDATEs (rowcount-checked),
never read-then-act.

Audit is fail-open here as everywhere: a dropped audit row must not abort a
user-commanded containment; the audit spec's failure counter covers systemic
failure.

Not handled in v1 (§3.2): processes still holding the unlinked inode (they
are reported, not stopped); directories and symlink targets (refused, not
recursed); re-creation of the path afterwards (FIM watches that); concurrent
writers during streaming (the byte cap or the recorded size absorbs growth);
xattrs/ACLs/capabilities (mode/uid/gid only).
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import logging
import os
import secrets
import stat
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

from inspectord.audit.log import append_audit
from inspectord.cases.store import append_timeline
from inspectord.evidence.store import BlobTooLarge, ForensicStore
from inspectord.ids import uuid7
from inspectord.quarantine.errors import (
    QuarantineBadStatus,
    QuarantineBlobMissing,
    QuarantineDenied,
    QuarantineError,
    QuarantineIOError,
    QuarantineIsolationFailed,
    QuarantineNotActive,
    QuarantineNotFound,
    QuarantineNotRegular,
    QuarantinePathOccupied,
    QuarantineRestoreNoParent,
    QuarantineShaMismatch,
    QuarantineSwapped,
    QuarantineTooLarge,
)
from inspectord.quarantine.paths import QuarantinePaths, open_parent_dirfd, quarantine_deny
from inspectord.storage.db import Database

log = logging.getLogger(__name__)

_MAX_QUARANTINE_BYTES = 256 * 1024 * 1024  # refusal, not truncation (§3.2)
_PACMAN_TIMEOUT_S = 5.0
_LIST_LIMIT_DEFAULT = 200
_LIST_LIMIT_MAX = 1000

#: §3.2 step 6 — carried on every success surface alongside the PID list.
RUNNING_WARNING = "processes already running from this file are NOT stopped"


@dataclass(frozen=True)
class IsolateResult:
    quarantine_id: str
    sha256: str
    pkg_owner: str | None
    running_pids: list[dict[str, Any]]
    warnings: list[str]


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _cas(
    db: Database,
    quarantine_id: str,
    *,
    from_statuses: tuple[str, ...],
    to_status: str,
    ts_column: str | None = None,
) -> bool:
    """Guarded status transition. False = the row was not in ``from_statuses``.

    DuckDB returns the UPDATE's changed-row count as its single result row —
    the same mechanism the hunt store's guarded stamps use. A write-write
    conflict from a concurrent transition means this call lost the race,
    which is exactly a failed CAS.
    """
    sql = "UPDATE quarantine SET status = ?"
    params: list[Any] = [to_status]
    if ts_column is not None:
        sql += f", {ts_column} = ?"  # column names come from literal call sites only
        params.append(_now())
    marks = ", ".join("?" for _ in from_statuses)
    sql += f" WHERE quarantine_id = ? AND status IN ({marks})"
    params += [quarantine_id, *from_statuses]
    try:
        rows = db.query(sql, params).fetchall()
    except duckdb.TransactionException:
        return False
    return bool(rows and int(rows[0][0]) > 0)


def _pacman_owner(path: str, runner: Callable[..., Any]) -> str | None:
    """`LC_ALL=C pacman -Qqo` — stdout is exactly the package name on exit 0.

    ANY nonzero exit, empty stdout, timeout or spawn failure means NULL owner;
    there is no locale-dependent parsing to get wrong (§3.2 step 2).
    """
    try:
        proc = runner(
            ["pacman", "-Qqo", path],
            capture_output=True,
            text=True,
            timeout=_PACMAN_TIMEOUT_S,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if getattr(proc, "returncode", 1) != 0:
        return None
    lines = (proc.stdout or "").strip().splitlines()
    return lines[0] or None if lines else None


def _running_from_inode(dev: int, ino: int) -> list[dict[str, Any]]:
    """PIDs whose /proc/<pid>/exe is the captured inode (§3.2 step 6).

    A stat on ``exe`` follows to the (possibly deleted) inode, so processes
    running from the just-unlinked file still match. Unreadable entries
    (permission, raced exit) are skipped.
    """
    running: list[dict[str, Any]] = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            est = os.stat(f"/proc/{name}/exe")
        except OSError:
            continue
        if (est.st_dev, est.st_ino) != (dev, ino):
            continue
        comm = ""
        with contextlib.suppress(OSError):
            comm = Path(f"/proc/{name}/comm").read_text(encoding="utf-8", errors="replace").strip()
        running.append({"pid": int(name), "comm": comm})
    return running


def _validate_target(path: str, paths: QuarantinePaths) -> None:
    if not os.path.isabs(path) or ".." in Path(path).parts:
        raise QuarantineDenied(f"path must be absolute, without '..': {path!r}")
    if not os.path.basename(path):
        raise QuarantineNotRegular("directories cannot be quarantined")
    if quarantine_deny(os.path.realpath(path), paths):
        raise QuarantineDenied(f"path is on the quarantine deny-list: {path!r}")


def _open_parent(path: str) -> int:
    try:
        return open_parent_dirfd(path)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise QuarantineNotFound(f"parent directory of {path!r} does not exist") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise QuarantineDenied(f"parent path of {path!r} contains a symlink component") from exc
        raise QuarantineIOError(f"cannot open parent directory of {path!r}") from exc


def _open_target(dirfd: int, path: str) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        return os.open(os.path.basename(path), flags, dir_fd=dirfd)
    except FileNotFoundError as exc:
        raise QuarantineNotFound(f"no such file: {path!r}") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise QuarantineNotRegular(
                f"{path!r} is a symlink; quarantining it would leave the target in place"
            ) from exc
        raise QuarantineIOError(f"cannot open {path!r}: {exc.strerror}") from exc


def _capture(
    db: Database,
    store: ForensicStore,
    lock: threading.Lock,
    *,
    fd: int,
    st: os.stat_result,
    path: str,
    pkg_owner: str | None,
    note: str | None,
    alert_id: str | None,
    case_id: str | None,
    max_bytes: int,
) -> tuple[str, str, int]:
    """Stream + INSERT ``isolating`` under the capture lock (§3.2 steps 3-4).

    The lock is the evidence collector's: ``prune_evidence`` runs entirely
    under it, and ``put_stream``'s existence-dedup would otherwise race a
    concurrent prune into unlinking the just-deduped blob.
    """
    with lock:
        try:
            sha, size = store.put_stream(fd, max_bytes=max_bytes)
        except BlobTooLarge as exc:
            raise QuarantineTooLarge(
                f"{path!r} exceeds the {max_bytes}-byte quarantine cap; nothing was stored"
            ) from exc
        # Belt-and-braces (§3.2): the deny-list already covers the configured
        # state dir, but a store rooted elsewhere must still refuse its own
        # blobs — put_stream would dedup, then the unlink would destroy the
        # evidence while reporting success.
        dest = store.path_for(sha)
        try:
            dst_st: os.stat_result | None = os.stat(dest)
        except OSError:
            dst_st = None
        store_root = str(dest.parent.parent)
        if (dst_st is not None and (dst_st.st_dev, dst_st.st_ino) == (st.st_dev, st.st_ino)) or (
            os.path.realpath(path).startswith(store_root.rstrip("/") + "/")
        ):
            raise QuarantineDenied(f"{path!r} is inside the forensic store")
        quarantine_id = str(uuid7())
        db.execute(
            "INSERT INTO quarantine (quarantine_id, sha256, original_path, file_mode, "
            "file_uid, file_gid, size_bytes, pkg_owner, note, alert_id, case_id, "
            "status, quarantined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'isolating', ?)",
            [
                quarantine_id,
                sha,
                path,
                st.st_mode & 0o7777,
                st.st_uid,
                st.st_gid,
                size,
                pkg_owner,
                note,
                alert_id,
                case_id,
                _now(),
            ],
        )
    return quarantine_id, sha, size


def _unlink_guarded(
    db: Database, quarantine_id: str, *, dirfd: int, path: str, st: os.stat_result
) -> None:
    """§3.2 step 5: fstatat must match the captured (st_dev, st_ino), then unlinkat.

    Both calls go through the held dirfd. A missing or different inode means
    the thing at the path is NOT the thing we preserved — a swapped file or
    parent — so nothing is unlinked and the row flips to ``failed``.
    """
    base = os.path.basename(path)
    try:
        st2: os.stat_result | None = os.stat(base, dir_fd=dirfd, follow_symlinks=False)
    except OSError:
        st2 = None
    if st2 is None or (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
        _cas(db, quarantine_id, from_statuses=("isolating",), to_status="failed")
        raise QuarantineSwapped(
            f"{path!r} changed between capture and unlink; nothing was removed "
            "(the captured copy is in the forensic store)"
        )
    try:
        os.unlink(base, dir_fd=dirfd)
    except OSError as exc:
        _cas(db, quarantine_id, from_statuses=("isolating",), to_status="failed")
        raise QuarantineIsolationFailed(
            f"could not remove {path!r} ({exc.strerror}); "
            "the captured copy IS in the forensic store"
        ) from exc
    if not _cas(db, quarantine_id, from_statuses=("isolating",), to_status="active"):
        raise QuarantineIOError("quarantine row changed status mid-isolation")


def isolate(
    db: Database,
    store: ForensicStore,
    lock: threading.Lock,
    *,
    path: str,
    actor: str,
    paths: QuarantinePaths,
    alert_id: str | None = None,
    case_id: str | None = None,
    note: str | None = None,
    qo_runner: Callable[..., Any] = subprocess.run,
    max_bytes: int = _MAX_QUARANTINE_BYTES,
) -> IsolateResult:
    """Isolate ``path`` into the forensic store and unlink the original (§3.2).

    ``lock`` is the supervisor-owned ``EvidenceCollector.capture_lock``.
    Every refusal is audited (``quarantine_refused``) — an attempted
    quarantine of /etc/shadow is itself high-signal — and every success
    writes an audit row plus a case-timeline entry when case-linked.
    """
    try:
        result = _isolate(
            db,
            store,
            lock,
            path=path,
            paths=paths,
            alert_id=alert_id,
            case_id=case_id,
            note=note,
            qo_runner=qo_runner,
            max_bytes=max_bytes,
        )
    except QuarantineError as exc:
        append_audit(
            db.path,
            actor=actor,
            action="quarantine_refused",
            target=path,
            details={"verb": "quarantine", "error_kind": exc.error_kind, "error": str(exc)},
        )
        raise
    append_audit(
        db.path,
        actor=actor,
        action="file_quarantined",
        target=path,
        details={
            "quarantine_id": result.quarantine_id,
            "sha256": result.sha256,
            "pkg_owner": result.pkg_owner,
            "running_pids": [entry["pid"] for entry in result.running_pids],
            "alert_id": alert_id,
            "case_id": case_id,
        },
    )
    if case_id is not None:
        append_timeline(db, case_id=case_id, kind="file_quarantined", text=path)
    return result


def _isolate(
    db: Database,
    store: ForensicStore,
    lock: threading.Lock,
    *,
    path: str,
    paths: QuarantinePaths,
    alert_id: str | None,
    case_id: str | None,
    note: str | None,
    qo_runner: Callable[..., Any],
    max_bytes: int,
) -> IsolateResult:
    _validate_target(path, paths)
    dirfd = _open_parent(path)
    try:
        fd = _open_target(dirfd, path)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise QuarantineNotRegular(f"{path!r} is not a regular file")
            pkg_owner = _pacman_owner(path, qo_runner)
            quarantine_id, sha, _size = _capture(
                db,
                store,
                lock,
                fd=fd,
                st=st,
                path=path,
                pkg_owner=pkg_owner,
                note=note,
                alert_id=alert_id,
                case_id=case_id,
                max_bytes=max_bytes,
            )
            _unlink_guarded(db, quarantine_id, dirfd=dirfd, path=path, st=st)
            running = _running_from_inode(st.st_dev, st.st_ino)
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)
    warnings: list[str] = []
    if pkg_owner is not None:
        warnings.append(f"file is owned by package {pkg_owner}")
    if running:
        warnings.append(RUNNING_WARNING)
    return IsolateResult(
        quarantine_id=quarantine_id,
        sha256=sha,
        pkg_owner=pkg_owner,
        running_pids=running,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# restore (§3.3)
# ---------------------------------------------------------------------------

_RESTORE_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class RestoreResult:
    quarantine_id: str
    original_path: str
    sha256: str
    #: A restored mode carrying 0o6000 bits — restoring a quarantined setuid
    #: binary is the single most dangerous act this feature can perform (§3.3).
    setuid_warning: bool


@dataclass(frozen=True)
class DeleteResult:
    quarantine_id: str
    original_path: str
    blob_removed: bool


def _fetch_row(db: Database, quarantine_id: str) -> tuple[Any, ...]:
    row = db.query(
        "SELECT sha256, original_path, file_mode, file_uid, file_gid, case_id, status "
        "FROM quarantine WHERE quarantine_id = ?",
        [quarantine_id],
    ).fetchone()
    if row is None:
        raise QuarantineNotFound(f"no quarantine row with id {quarantine_id!r}")
    return row


def _verify_blob(blob: Path, sha: str) -> None:
    """Chunked sha256 verification against the row (§3.3 step 2)."""
    hasher = hashlib.sha256()
    try:
        with open(blob, "rb") as fh:
            while chunk := fh.read(_RESTORE_CHUNK_BYTES):
                hasher.update(chunk)
    except FileNotFoundError as exc:
        raise QuarantineBlobMissing(
            f"stored blob for sha256 {sha} is missing from the forensic store (backup/store drift?)"
        ) from exc
    if hasher.hexdigest() != sha:
        raise QuarantineShaMismatch(f"stored blob content does not match the recorded sha256 {sha}")


def _open_parent_for_restore(path: str) -> int:
    try:
        return open_parent_dirfd(path)
    except (FileNotFoundError, NotADirectoryError) as exc:
        parent = os.path.dirname(path)
        raise QuarantineRestoreNoParent(
            f"parent directory {parent!r} no longer exists — recreate it, then retry "
            "(quarantine records no directory metadata to recreate it faithfully)"
        ) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise QuarantineDenied(f"parent path of {path!r} contains a symlink component") from exc
        raise QuarantineIOError(f"cannot open parent directory of {path!r}") from exc


def _write_and_commit(
    dirfd: int, *, blob: Path, path: str, mode: int, uid: int, gid: int, quarantine_id: str
) -> None:
    """§3.3 step 4: tmp 0600 + write + fsync + fchown + fchmod, then link-no-replace.

    fchmod runs AFTER fchown (chown clears setuid/setgid bits). The commit is
    ``linkat`` without replace: EEXIST means something re-created the path —
    evidence, never clobber-fodder. Both link ends go through the held dirfd.
    """
    base = os.path.basename(path)
    tmp_name = f".inspectord-restore-{quarantine_id}-{secrets.token_hex(8)}"
    tfd = os.open(
        tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=dirfd
    )
    try:
        try:
            os.fchmod(tfd, 0o600)  # os.open honors umask; force 0600
            with open(blob, "rb") as src:
                while chunk := src.read(_RESTORE_CHUNK_BYTES):
                    os.write(tfd, chunk)
            os.fsync(tfd)
            os.fchown(tfd, uid, gid)
            os.fchmod(tfd, mode)
        finally:
            os.close(tfd)
        try:
            os.link(tmp_name, base, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
        except FileExistsError as exc:
            raise QuarantinePathOccupied(
                f"{path!r} already exists; something re-created it after quarantine. "
                "The existing file is untouched — that re-creation is evidence"
            ) from exc
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name, dir_fd=dirfd)


def restore(
    db: Database,
    store: ForensicStore,
    *,
    quarantine_id: str,
    actor: str,
    paths: QuarantinePaths,
) -> RestoreResult:
    """Put the quarantined bytes back at ``original_path`` (§3.3).

    CAS-gated ``active → restoring → restored``; every failure path CASes the
    row back to ``active``. The blob stays — bytes are removed only by delete
    or by normal evidence retention once no protecting reference remains.
    """
    try:
        result, case_id = _restore(db, store, quarantine_id=quarantine_id, paths=paths)
    except QuarantineError as exc:
        append_audit(
            db.path,
            actor=actor,
            action="quarantine_refused",
            target=quarantine_id,
            details={"verb": "restore", "error_kind": exc.error_kind, "error": str(exc)},
        )
        raise
    append_audit(
        db.path,
        actor=actor,
        action="quarantine_restored",
        target=result.original_path,
        details={
            "quarantine_id": result.quarantine_id,
            "sha256": result.sha256,
            "setuid_warning": result.setuid_warning,
        },
    )
    if case_id is not None:
        append_timeline(db, case_id=case_id, kind="quarantine_restored", text=result.original_path)
    return result


def _restore(
    db: Database, store: ForensicStore, *, quarantine_id: str, paths: QuarantinePaths
) -> tuple[RestoreResult, str | None]:
    sha, original_path, mode, uid, gid, case_id, _status = _fetch_row(db, quarantine_id)
    # Guarded transition FIRST (§3.3 step 1): a concurrent restore/delete must
    # lose here, before anything touches disk. The row read above is for
    # fields and messaging only — the CAS is the gate.
    if not _cas(db, quarantine_id, from_statuses=("active",), to_status="restoring"):
        current = _fetch_row(db, quarantine_id)[6]
        raise QuarantineNotActive(
            f"quarantine {quarantine_id} is not active (status: {current}); nothing restored"
        )
    try:
        _verify_blob(store.path_for(sha), sha)
        # Deny-list re-validation at restore time (§3.3 step 3).
        if quarantine_deny(os.path.realpath(original_path), paths):
            raise QuarantineDenied(
                f"restore path is on the quarantine deny-list: {original_path!r}"
            )
        dirfd = _open_parent_for_restore(original_path)
        try:
            _write_and_commit(
                dirfd,
                blob=store.path_for(sha),
                path=original_path,
                mode=mode,
                uid=uid,
                gid=gid,
                quarantine_id=quarantine_id,
            )
        finally:
            os.close(dirfd)
    except QuarantineError:
        _cas(db, quarantine_id, from_statuses=("restoring",), to_status="active")
        raise
    except OSError as exc:
        _cas(db, quarantine_id, from_statuses=("restoring",), to_status="active")
        raise QuarantineIOError(f"restore failed: {exc.strerror}") from exc
    if not _cas(
        db,
        quarantine_id,
        from_statuses=("restoring",),
        to_status="restored",
        ts_column="restored_at",
    ):
        raise QuarantineIOError("quarantine row changed status mid-restore")
    result = RestoreResult(
        quarantine_id=quarantine_id,
        original_path=original_path,
        sha256=sha,
        setuid_warning=bool(mode & 0o6000),
    )
    return result, case_id


# ---------------------------------------------------------------------------
# delete (§3.4)
# ---------------------------------------------------------------------------


def delete(
    db: Database,
    store: ForensicStore,
    lock: threading.Lock,
    *,
    quarantine_id: str,
    actor: str,
) -> DeleteResult:
    """Discard a quarantined file for good (§3.4).

    The blob is unlinked ONLY when no ``case_evidence`` row and no other
    non-``deleted`` quarantine row claims the sha — re-checked under the
    capture lock, so a concurrent capture cannot dedup against the blob
    mid-unlink.
    """
    try:
        result, case_id = _delete(db, store, lock, quarantine_id=quarantine_id)
    except QuarantineError as exc:
        append_audit(
            db.path,
            actor=actor,
            action="quarantine_refused",
            target=quarantine_id,
            details={"verb": "delete", "error_kind": exc.error_kind, "error": str(exc)},
        )
        raise
    append_audit(
        db.path,
        actor=actor,
        action="quarantine_deleted",
        target=result.original_path,
        details={"quarantine_id": result.quarantine_id, "blob_removed": result.blob_removed},
    )
    if case_id is not None:
        append_timeline(db, case_id=case_id, kind="quarantine_deleted", text=result.original_path)
    return result


def _delete(
    db: Database, store: ForensicStore, lock: threading.Lock, *, quarantine_id: str
) -> tuple[DeleteResult, str | None]:
    sha, original_path, _mode, _uid, _gid, case_id, _status = _fetch_row(db, quarantine_id)
    if not _cas(
        db, quarantine_id, from_statuses=("active", "restored", "failed"), to_status="deleting"
    ):
        current = _fetch_row(db, quarantine_id)[6]
        raise QuarantineBadStatus(
            f"quarantine {quarantine_id} cannot be deleted from status {current!r}"
        )
    blob_removed = False
    with lock:
        held_by_case = db.query(
            "SELECT 1 FROM case_evidence WHERE sha256 = ? LIMIT 1", [sha]
        ).fetchone()
        held_by_other = db.query(
            "SELECT 1 FROM quarantine WHERE sha256 = ? AND quarantine_id != ? "
            "AND status != 'deleted' LIMIT 1",
            [sha, quarantine_id],
        ).fetchone()
        if held_by_case is None and held_by_other is None:
            blob = store.path_for(sha)
            if blob.exists():
                blob.unlink()
                with contextlib.suppress(OSError):
                    blob.parent.rmdir()
                blob_removed = True
    if not _cas(
        db, quarantine_id, from_statuses=("deleting",), to_status="deleted", ts_column="deleted_at"
    ):
        raise QuarantineIOError("quarantine row changed status mid-delete")
    result = DeleteResult(
        quarantine_id=quarantine_id, original_path=original_path, blob_removed=blob_removed
    )
    return result, case_id


# ---------------------------------------------------------------------------
# list + reconciliation (§3.6, §4)
# ---------------------------------------------------------------------------


def _health_flags(store: ForensicStore, *, status: str, original_path: str, sha: str) -> list[str]:
    """Per-row reconciliation flags — a row must never lie (§3.6).

    ``isolation_incomplete``: an ``isolating`` row (crash between INSERT and
    unlink) or a ``failed`` one — the file may still be on disk; re-run the
    quarantine. ``file_still_present``: an ``active`` row whose original path
    exists again. ``blob_missing``: a non-``deleted`` row whose blob is gone
    from the store (backup drift?) — visible here, not first discovered at
    restore time.
    """
    flags: list[str] = []
    if status in ("isolating", "failed"):
        flags.append("isolation_incomplete")
    if status == "active" and os.path.lexists(original_path):
        flags.append("file_still_present")
    if status != "deleted" and not store.path_for(sha).exists():
        flags.append("blob_missing")
    return flags


def list_quarantine(
    db: Database, store: ForensicStore, *, limit: int = _LIST_LIMIT_DEFAULT
) -> dict[str, Any]:
    """Bounded quarantine listing, newest first, with health flags (§4).

    One query powers the CLI and the panel; ``limit`` is clamped to
    [1, 1000] and echoed hunt-style.
    """
    limit = max(1, min(int(limit), _LIST_LIMIT_MAX))
    rows = db.query(
        "SELECT quarantine_id, sha256, original_path, file_mode, file_uid, file_gid, "
        "size_bytes, pkg_owner, note, alert_id, case_id, status, quarantined_at, "
        "restored_at, deleted_at FROM quarantine "
        "ORDER BY quarantined_at DESC, quarantine_id DESC LIMIT ?",
        [limit],
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        (
            quarantine_id,
            sha,
            original_path,
            file_mode,
            file_uid,
            file_gid,
            size_bytes,
            pkg_owner,
            note,
            alert_id,
            case_id,
            status,
            quarantined_at,
            restored_at,
            deleted_at,
        ) = row
        out.append(
            {
                "quarantine_id": quarantine_id,
                "sha256": sha,
                "original_path": original_path,
                "file_mode": file_mode,
                "file_uid": file_uid,
                "file_gid": file_gid,
                "size_bytes": size_bytes,
                "pkg_owner": pkg_owner,
                "note": note,
                "alert_id": alert_id,
                "case_id": case_id,
                "status": status,
                "quarantined_at": quarantined_at.isoformat() if quarantined_at else None,
                "restored_at": restored_at.isoformat() if restored_at else None,
                "deleted_at": deleted_at.isoformat() if deleted_at else None,
                "flags": _health_flags(store, status=status, original_path=original_path, sha=sha),
            }
        )
    return {"rows": out, "limit": limit}


def log_incomplete_isolations(db: Database) -> int:
    """Startup reconciliation (§3.6): warn per ``isolating`` row, no auto-repair.

    A crash between INSERT and unlink leaves ``isolating`` — the file may
    still be sitting on disk; re-running the quarantine is the user's call.
    Returns the number of rows logged.
    """
    rows = db.query(
        "SELECT quarantine_id, original_path FROM quarantine WHERE status = 'isolating' "
        "ORDER BY quarantined_at"
    ).fetchall()
    for quarantine_id, original_path in rows:
        log.warning(
            "quarantine %s of %r is incomplete (status isolating) — "
            "the file may still be on disk; re-run the quarantine",
            quarantine_id,
            original_path,
        )
    return len(rows)
