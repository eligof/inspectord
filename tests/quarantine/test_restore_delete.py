"""Quarantine restore + delete (quarantine design §3.3/§3.4).

Restore is CAS-gated (``active → restoring → restored``), commits via
link-no-replace through the parent dirfd, and every failure path CASes the
row back to ``active``. Delete unlinks the blob only when nothing else claims
the sha, re-checked under the capture lock. The parent-symlink-swap restore
test is a REAL swap in tmp_path, not a mock of the check.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace, TracebackType
from typing import Any

import pytest

from inspectord.audit.log import reset_for_tests
from inspectord.evidence.store import ForensicStore
from inspectord.quarantine import ops
from inspectord.quarantine.errors import (
    QuarantineBadStatus,
    QuarantineBlobMissing,
    QuarantineDenied,
    QuarantineNotActive,
    QuarantineNotFound,
    QuarantinePathOccupied,
    QuarantineRestoreNoParent,
    QuarantineShaMismatch,
)
from inspectord.quarantine.paths import QuarantinePaths
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

ACTOR = "uid:1000:pid:4242"


@pytest.fixture(autouse=True)
def _audit_reset() -> Iterator[None]:
    reset_for_tests()
    yield
    reset_for_tests()


@dataclass
class Env:
    db: Database
    store: ForensicStore
    paths: QuarantinePaths
    work: Path
    state: Path
    lock: threading.Lock = field(default_factory=threading.Lock)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    state = tmp_path / "state"
    state.mkdir()
    db = Database(state / "db.duckdb")
    db.connect()
    run_migrations(db)
    work = tmp_path / "work"
    work.mkdir()
    yield Env(
        db=db,
        store=ForensicStore(state / "evidence"),
        paths=QuarantinePaths(state_dir=state, socket_dir=state / "run"),
        work=work,
        state=state,
    )
    db.close()


def _qo_unowned(argv: list[str], **kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(returncode=1, stdout="", stderr="")


def _quarantined(env: Env, path: Path, content: bytes = b"payload", mode: int = 0o640) -> str:
    """Round-trip helper: create + isolate ``path``, return the quarantine_id."""
    path.write_bytes(content)
    os.chmod(path, mode)
    result = ops.isolate(
        env.db,
        env.store,
        env.lock,
        path=str(path),
        actor=ACTOR,
        paths=env.paths,
        qo_runner=_qo_unowned,
    )
    return result.quarantine_id


def _restore(env: Env, quarantine_id: str) -> ops.RestoreResult:
    return ops.restore(env.db, env.store, quarantine_id=quarantine_id, actor=ACTOR, paths=env.paths)


def _delete(env: Env, quarantine_id: str, lock: Any | None = None) -> ops.DeleteResult:
    return ops.delete(
        env.db,
        env.store,
        lock if lock is not None else env.lock,
        quarantine_id=quarantine_id,
        actor=ACTOR,
    )


def _status(env: Env, quarantine_id: str) -> str:
    row = env.db.query(
        "SELECT status FROM quarantine WHERE quarantine_id = ?", [quarantine_id]
    ).fetchone()
    assert row is not None
    return str(row[0])


def _newest_audit(env: Env) -> dict[str, Any]:
    row = env.db.query(
        "SELECT actor, action, target, details_json FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    return {"actor": row[0], "action": row[1], "target": row[2], "details": row[3]}


# ---------------------------------------------------------------------------
# restore: happy paths
# ---------------------------------------------------------------------------


def test_restore_round_trip_content_identical(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target, content=b"exact bytes back", mode=0o640)
    assert not target.exists()

    result = _restore(env, qid)

    assert target.read_bytes() == b"exact bytes back"
    st = os.stat(target)
    assert st.st_mode & 0o7777 == 0o640
    assert st.st_uid == os.getuid()
    assert st.st_gid == os.getgid()
    assert result.setuid_warning is False
    assert result.original_path == str(target)
    assert _status(env, qid) == "restored"
    row = env.db.query(
        "SELECT restored_at FROM quarantine WHERE quarantine_id = ?", [qid]
    ).fetchone()
    assert row is not None and row[0] is not None
    # Blob stays: bytes are removed only by delete or by evidence retention.
    audit = _newest_audit(env)
    assert audit["action"] == "quarantine_restored"
    assert audit["actor"] == ACTOR


def test_restore_setuid_mode_restored_and_flagged(env: Env) -> None:
    target = env.work / "suid"
    qid = _quarantined(env, target, content=b"x", mode=0o4755)

    result = _restore(env, qid)

    assert os.stat(target).st_mode & 0o7777 == 0o4755
    assert result.setuid_warning is True
    audit = _newest_audit(env)
    assert '"setuid_warning":true' in audit["details"]


# ---------------------------------------------------------------------------
# restore: guarded CAS
# ---------------------------------------------------------------------------


def test_restore_unknown_id(env: Env) -> None:
    with pytest.raises(QuarantineNotFound):
        _restore(env, "no-such-id")


def test_restore_non_active_row_refused(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target)
    _restore(env, qid)  # now `restored`
    with pytest.raises(QuarantineNotActive):
        _restore(env, qid)


def test_concurrent_restores_one_wins(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def attempt() -> None:
        barrier.wait()
        try:
            _restore(env, qid)
            outcomes.append("ok")
        except QuarantineNotActive:
            outcomes.append("not_active")

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(outcomes) == ["not_active", "ok"]
    assert target.exists()
    assert _status(env, qid) == "restored"


# ---------------------------------------------------------------------------
# restore: failure paths CAS back to active
# ---------------------------------------------------------------------------


def test_restore_occupied_path_refused_existing_untouched(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target, content=b"original")
    target.write_bytes(b"re-created after quarantine")  # something took the path back

    with pytest.raises(QuarantinePathOccupied):
        _restore(env, qid)

    assert target.read_bytes() == b"re-created after quarantine"
    assert _status(env, qid) == "active"
    assert not list(env.work.glob(".inspectord-restore-*"))  # tmp cleaned up


def test_restore_parent_missing(env: Env) -> None:
    sub = env.work / "sub"
    sub.mkdir()
    qid = _quarantined(env, sub / "f")
    sub.rmdir()  # isolate already unlinked the file, so the dir is empty

    with pytest.raises(QuarantineRestoreNoParent):
        _restore(env, qid)
    assert _status(env, qid) == "active"


def test_restore_blob_missing(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target)
    row = env.db.query("SELECT sha256 FROM quarantine WHERE quarantine_id = ?", [qid]).fetchone()
    assert row is not None
    env.store.path_for(str(row[0])).unlink()

    with pytest.raises(QuarantineBlobMissing):
        _restore(env, qid)
    assert _status(env, qid) == "active"
    assert not target.exists()


def test_restore_sha_mismatch(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target, content=b"true content")
    row = env.db.query("SELECT sha256 FROM quarantine WHERE quarantine_id = ?", [qid]).fetchone()
    assert row is not None
    env.store.path_for(str(row[0])).write_bytes(b"corrupted blob")

    with pytest.raises(QuarantineShaMismatch):
        _restore(env, qid)
    assert _status(env, qid) == "active"
    assert not target.exists()


def test_restore_parent_symlink_swap_refused(env: Env) -> None:
    parent = env.work / "dir"
    parent.mkdir()
    qid = _quarantined(env, parent / "payload")
    victim_dir = env.work / "victim"
    victim_dir.mkdir()
    # REAL swap: the parent is now a symlink into the victim directory.
    os.rename(parent, env.work / "aside")
    os.symlink(victim_dir, parent)

    with pytest.raises(QuarantineDenied):
        _restore(env, qid)

    assert not (victim_dir / "payload").exists()  # nothing written through the link
    assert not list(victim_dir.glob(".inspectord-restore-*"))
    assert _status(env, qid) == "active"


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def test_delete_sole_claim_removes_blob(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target)
    row = env.db.query("SELECT sha256 FROM quarantine WHERE quarantine_id = ?", [qid]).fetchone()
    assert row is not None
    sha = str(row[0])

    result = _delete(env, qid)

    assert result.blob_removed is True
    assert not env.store.path_for(sha).exists()
    assert _status(env, qid) == "deleted"
    row2 = env.db.query(
        "SELECT deleted_at FROM quarantine WHERE quarantine_id = ?", [qid]
    ).fetchone()
    assert row2 is not None and row2[0] is not None
    audit = _newest_audit(env)
    assert audit["action"] == "quarantine_deleted"


def test_delete_keeps_blob_held_by_case_evidence(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target)
    row = env.db.query("SELECT sha256 FROM quarantine WHERE quarantine_id = ?", [qid]).fetchone()
    assert row is not None
    sha = str(row[0])
    env.db.execute(
        "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at) "
        "VALUES ('c1', 'file', ?, '', TIMESTAMP '2026-01-01 00:00:00')",
        [sha],
    )

    result = _delete(env, qid)

    assert result.blob_removed is False
    assert env.store.path_for(sha).exists()
    assert _status(env, qid) == "deleted"


def test_delete_keeps_blob_held_by_other_active_quarantine(env: Env) -> None:
    a = env.work / "a"
    b = env.work / "b"
    qid_a = _quarantined(env, a, content=b"same bytes")
    qid_b = _quarantined(env, b, content=b"same bytes")
    row = env.db.query("SELECT sha256 FROM quarantine WHERE quarantine_id = ?", [qid_a]).fetchone()
    assert row is not None
    sha = str(row[0])

    result = _delete(env, qid_a)

    assert result.blob_removed is False
    assert env.store.path_for(sha).exists()
    assert _status(env, qid_a) == "deleted"
    assert _status(env, qid_b) == "active"


def test_delete_bad_status_refused(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target)
    _delete(env, qid)
    with pytest.raises(QuarantineBadStatus):
        _delete(env, qid)  # already deleted
    with pytest.raises(QuarantineNotFound):
        _delete(env, "no-such-id")


class RecordingLock:
    """Context-manager fake asserting the blob unlink happens under the lock."""

    def __init__(self, blob: Path) -> None:
        self.blob = blob
        self.entered = False
        self.blob_gone_at_exit: bool | None = None

    def __enter__(self) -> RecordingLock:
        self.entered = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.blob_gone_at_exit = not self.blob.exists()


def test_delete_unlinks_blob_under_lock(env: Env) -> None:
    target = env.work / "f"
    qid = _quarantined(env, target)
    row = env.db.query("SELECT sha256 FROM quarantine WHERE quarantine_id = ?", [qid]).fetchone()
    assert row is not None
    lock = RecordingLock(env.store.path_for(str(row[0])))

    result = _delete(env, qid, lock=lock)

    assert result.blob_removed is True
    assert lock.entered is True
    assert lock.blob_gone_at_exit is True
