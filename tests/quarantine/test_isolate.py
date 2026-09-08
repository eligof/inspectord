"""Quarantine isolate (quarantine design §3.2): dirfd discipline, deny-list, lifecycle.

The parent-symlink-swap and inode-swap tests are the concilium-BLOCKING
regression tests: they perform REAL swaps in tmp_path via the deliberately
injectable ``qo_runner`` seam (which runs between the file open and the
unlink), never by mocking the check itself.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from inspectord.audit.log import reset_for_tests
from inspectord.evidence.store import ForensicStore
from inspectord.quarantine import ops
from inspectord.quarantine.errors import (
    QuarantineDenied,
    QuarantineIsolationFailed,
    QuarantineNotFound,
    QuarantineNotRegular,
    QuarantineSwapped,
    QuarantineTooLarge,
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
        paths=QuarantinePaths(
            state_dir=state,
            socket_dir=state / "run",
            config_path=state / "config.toml",
        ),
        work=work,
        state=state,
    )
    db.close()


def _qo_unowned(argv: list[str], **kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(returncode=1, stdout="", stderr="error: no package owns it\n")


def _isolate(env: Env, path: Path | str, **kw: Any) -> ops.IsolateResult:
    kw.setdefault("qo_runner", _qo_unowned)
    return ops.isolate(
        env.db, env.store, env.lock, path=str(path), actor=ACTOR, paths=env.paths, **kw
    )


def _row(env: Env) -> tuple[Any, ...] | None:
    return env.db.query(
        "SELECT quarantine_id, sha256, original_path, file_mode, file_uid, file_gid, "
        "size_bytes, pkg_owner, status FROM quarantine"
    ).fetchone()


def _row_count(env: Env) -> int:
    row = env.db.query("SELECT COUNT(*) FROM quarantine").fetchone()
    assert row is not None
    return int(row[0])


def _audit_rows(env: Env) -> list[dict[str, Any]]:
    rows = env.db.query(
        "SELECT actor, action, target, details_json FROM audit_log ORDER BY seq"
    ).fetchall()
    return [{"actor": r[0], "action": r[1], "target": r[2], "details": r[3]} for r in rows]


def _blob_count(env: Env) -> int:
    root = env.state / "evidence"
    if not root.is_dir():
        return 0
    return sum(1 for p in root.rglob("*") if p.is_file() and not p.name.startswith(".tmp"))


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------


def test_happy_path_round_trip(env: Env) -> None:
    target = env.work / "payload.bin"
    content = b"malicious bytes"
    target.write_bytes(content)
    os.chmod(target, 0o640)

    result = _isolate(env, target)

    sha = hashlib.sha256(content).hexdigest()
    assert result.sha256 == sha
    assert result.pkg_owner is None
    assert env.store.path_for(sha).read_bytes() == content
    assert not target.exists()

    row = _row(env)
    assert row is not None
    qid, row_sha, original_path, mode, uid, gid, size, pkg, status = row
    assert qid == result.quarantine_id
    assert row_sha == sha
    assert original_path == str(target)
    assert mode == 0o640
    assert uid == os.getuid()
    assert gid == os.getgid()
    assert size == len(content)
    assert pkg is None
    assert status == "active"

    audits = _audit_rows(env)
    assert audits[-1]["action"] == "file_quarantined"
    assert audits[-1]["actor"] == ACTOR
    assert audits[-1]["target"] == str(target)
    assert result.quarantine_id in audits[-1]["details"]


def test_case_linked_isolate_writes_timeline(env: Env) -> None:
    env.db.execute(
        "INSERT INTO cases (case_id, title, status, opened_at) "
        "VALUES ('c1', 't', 'open', TIMESTAMP '2026-01-01 00:00:00')"
    )
    target = env.work / "f"
    target.write_bytes(b"x")
    _isolate(env, target, case_id="c1")
    kinds = [r[0] for r in env.db.query("SELECT kind FROM case_event").fetchall()]
    assert "file_quarantined" in kinds


# ---------------------------------------------------------------------------
# swaps (the BLOCKING regression tests — real filesystem swaps via the seam)
# ---------------------------------------------------------------------------


def test_parent_symlink_swap_between_open_and_unlink(env: Env) -> None:
    parent = env.work / "dir"
    parent.mkdir()
    target = parent / "payload"
    target.write_bytes(b"bait")
    victim_dir = env.work / "victim"
    victim_dir.mkdir()
    victim = victim_dir / "payload"
    victim.write_bytes(b"innocent victim file")

    def swapping_runner(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        # The attacker replaces the whole parent with a symlink pointing at the
        # victim directory and discards the bait, so the path now names the
        # victim's inode. A path-based unlink would delete the victim; the
        # held-dirfd fstatat sees the bait gone and refuses instead.
        aside = env.work / "aside"
        os.rename(parent, aside)
        os.unlink(aside / "payload")
        os.symlink(victim_dir, parent)
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    with pytest.raises(QuarantineSwapped):
        _isolate(env, target, qo_runner=swapping_runner)

    assert victim.read_bytes() == b"innocent victim file"
    row = _row(env)
    assert row is not None and row[8] == "failed"


def test_inode_swap_during_capture(env: Env) -> None:
    parent = env.work / "dir"
    parent.mkdir()
    target = parent / "payload"
    target.write_bytes(b"original")

    def swapping_runner(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        # Replace the file with a different inode at the same name.
        os.unlink(target)
        target.write_bytes(b"replacement")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    with pytest.raises(QuarantineSwapped):
        _isolate(env, target, qo_runner=swapping_runner)

    assert target.read_bytes() == b"replacement"  # the new inode is untouched
    row = _row(env)
    assert row is not None and row[8] == "failed"


# ---------------------------------------------------------------------------
# deny-list
# ---------------------------------------------------------------------------


def test_deny_matrix(env: Env) -> None:
    state_file = env.state / "config.toml"
    state_file.write_text("x")
    blob_sha = env.store.put(b"case evidence blob")
    denied = [
        "/proc/1/environ",
        str(state_file),
        str(env.store.path_for(blob_sha)),
        "/usr/share/polkit-1/actions/org.inspectord.policy",
    ]
    for path in denied:
        with pytest.raises(QuarantineDenied):
            _isolate(env, path)
    assert _row_count(env) == 0
    assert _blob_count(env) == 1  # only the pre-seeded blob; nothing new written
    audits = [a for a in _audit_rows(env) if a["action"] == "quarantine_refused"]
    assert len(audits) == len(denied)
    assert all(a["actor"] == ACTOR for a in audits)
    assert all('"error_kind":"denied"' in a["details"] for a in audits)


# ---------------------------------------------------------------------------
# size / kind refusals
# ---------------------------------------------------------------------------


def test_oversize_refused_no_row_no_blob(env: Env) -> None:
    target = env.work / "big"
    target.write_bytes(b"z" * 4096)
    with pytest.raises(QuarantineTooLarge):
        _isolate(env, target, max_bytes=1024)
    assert _row_count(env) == 0
    assert _blob_count(env) == 0
    assert not list((env.state / "evidence").rglob(".tmp-*"))
    assert target.exists()  # refusal never touches the original


def test_fifo_refused(env: Env) -> None:
    fifo = env.work / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(QuarantineNotRegular):
        _isolate(env, fifo)
    assert _row_count(env) == 0


def test_directory_refused(env: Env) -> None:
    sub = env.work / "sub"
    sub.mkdir()
    with pytest.raises(QuarantineNotRegular):
        _isolate(env, sub)
    assert _row_count(env) == 0


def test_symlink_final_component_refused(env: Env) -> None:
    real = env.work / "real"
    real.write_bytes(b"x")
    link = env.work / "link"
    link.symlink_to(real)
    with pytest.raises(QuarantineNotRegular):
        _isolate(env, link)
    assert real.exists()
    assert _row_count(env) == 0


def test_missing_file_not_found(env: Env) -> None:
    with pytest.raises(QuarantineNotFound):
        _isolate(env, env.work / "nope")
    assert _row_count(env) == 0


# ---------------------------------------------------------------------------
# unlink failure
# ---------------------------------------------------------------------------


def test_unlink_failure_row_failed_blob_kept(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    target = env.work / "stuck"
    target.write_bytes(b"stuck bytes")
    real_unlink = os.unlink

    def fake_unlink(path: str | os.PathLike[str], *, dir_fd: int | None = None) -> None:
        if dir_fd is not None:
            raise PermissionError(1, "Operation not permitted")
        real_unlink(path)

    monkeypatch.setattr(os, "unlink", fake_unlink)
    with pytest.raises(QuarantineIsolationFailed) as excinfo:
        _isolate(env, target)
    assert "forensic store" in str(excinfo.value)
    row = _row(env)
    assert row is not None and row[8] == "failed"
    assert target.exists()  # unlink failed: original still on disk
    assert _blob_count(env) == 1  # ...and the captured copy is kept


# ---------------------------------------------------------------------------
# running-exe scan
# ---------------------------------------------------------------------------


def test_running_exe_scan_reports_pid(env: Env) -> None:
    target = env.work / "sleeper"
    shutil.copy("/usr/bin/sleep", target)
    proc = subprocess.Popen([str(target), "30"])
    try:
        result = _isolate(env, target)
        assert proc.pid in [entry["pid"] for entry in result.running_pids]
        assert any("NOT stopped" in w for w in result.warnings)
    finally:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# pacman -Qqo parsing
# ---------------------------------------------------------------------------


def test_pacman_owner_recorded(env: Env) -> None:
    target = env.work / "owned"
    target.write_bytes(b"x")
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def runner(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="coreutils\n", stderr="")

    result = _isolate(env, target, qo_runner=runner)
    assert result.pkg_owner == "coreutils"
    assert any("coreutils" in w for w in result.warnings)
    row = _row(env)
    assert row is not None and row[7] == "coreutils"

    (argv, kwargs) = calls[0]
    assert argv == ["pacman", "-Qqo", str(target)]
    assert kwargs["env"]["LC_ALL"] == "C"
    assert kwargs["timeout"] == pytest.approx(5.0)


def test_pacman_nonzero_exit_means_null_owner(env: Env) -> None:
    target = env.work / "unowned"
    target.write_bytes(b"x")
    result = _isolate(env, target)  # default fake runner exits 1
    assert result.pkg_owner is None
    row = _row(env)
    assert row is not None and row[7] is None


def test_pacman_timeout_means_null_owner(env: Env) -> None:
    target = env.work / "slow"
    target.write_bytes(b"x")

    def runner(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(argv, 5.0)

    result = _isolate(env, target, qo_runner=runner)
    assert result.pkg_owner is None
