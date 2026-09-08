"""Quarantine IPC handlers (quarantine design §4): validation, shapes, audit actor.

The polkit gate is server-side and tested in tests/test_ipc_server.py; here the
handlers are called directly. What matters at this layer: param validation
(typed request errors as data), success shapes, and that the server-injected
peer identity lands as the ``uid:pid`` actor in every mutating audit row.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from inspectord.__main__ import _ipc_methods
from inspectord.audit.log import reset_for_tests
from inspectord.authz import PeerIdentity
from inspectord.config import dev_config
from inspectord.evidence.store import ForensicStore
from inspectord.ipc_server import PEER_PARAM
from inspectord.quarantine.ipc_handlers import (
    handle_delete_quarantined,
    handle_list_quarantine,
    handle_quarantine_file,
    handle_restore_quarantined,
)
from inspectord.quarantine.paths import QuarantinePaths
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

PEER = PeerIdentity(pid=4242, uid=1000, start_time=7)
ACTOR = "uid:1000:pid:4242"


@pytest.fixture(autouse=True)
def _audit_reset() -> Iterator[None]:
    reset_for_tests()
    yield
    reset_for_tests()


@dataclass
class Env:
    db_path: Path
    store: ForensicStore
    paths: QuarantinePaths
    work: Path
    lock: threading.Lock = field(default_factory=threading.Lock)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    state = tmp_path / "state"
    state.mkdir()
    db = Database(state / "db.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    work = tmp_path / "work"
    work.mkdir()
    return Env(
        db_path=state / "db.duckdb",
        store=ForensicStore(state / "evidence"),
        paths=QuarantinePaths(state_dir=state, socket_dir=state / "run"),
        work=work,
    )


def _qo_unowned(argv: list[str], **kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(returncode=1, stdout="", stderr="error: no package owns it\n")


def _quarantine(env: Env, params: dict[str, Any]) -> dict[str, Any]:
    params = {PEER_PARAM: PEER, **params}
    return handle_quarantine_file(
        params=params,
        db_path=env.db_path,
        store=env.store,
        lock=env.lock,
        paths=env.paths,
        qo_runner=_qo_unowned,
    )


def _audit_rows(env: Env) -> list[dict[str, Any]]:
    with Database(env.db_path) as db:
        rows = db.query(
            "SELECT actor, action, target, details_json FROM audit_log ORDER BY seq"
        ).fetchall()
    return [
        {"actor": r[0], "action": r[1], "target": r[2], "details": json.loads(r[3])} for r in rows
    ]


# ---------------------------------------------------------------------------
# quarantine_file
# ---------------------------------------------------------------------------


def test_quarantine_file_success_shape_and_audit_actor(env: Env) -> None:
    target = env.work / "malware.bin"
    target.write_bytes(b"evil bytes")
    resp = _quarantine(env, {"path": str(target)})
    assert resp["ok"] is True
    assert set(resp) >= {
        "schema_version",
        "ok",
        "quarantine_id",
        "sha256",
        "pkg_owner",
        "running_pids",
        "warnings",
    }
    assert resp["pkg_owner"] is None
    assert not target.exists()
    row = next(r for r in _audit_rows(env) if r["action"] == "file_quarantined")
    assert row["actor"] == ACTOR
    assert row["target"] == str(target)


def test_quarantine_file_requires_path(env: Env) -> None:
    resp = _quarantine(env, {})
    assert resp["ok"] is False
    assert resp["error_kind"] == "request"
    # Request-level refusals of a mutating verb are audited too, with the actor.
    row = next(r for r in _audit_rows(env) if r["action"] == "quarantine_refused")
    assert row["actor"] == ACTOR
    assert row["details"]["error_kind"] == "request"


def test_quarantine_file_requires_absolute_path(env: Env) -> None:
    resp = _quarantine(env, {"path": "relative/thing.bin"})
    assert resp["ok"] is False
    assert resp["error_kind"] == "request"


def test_quarantine_file_unknown_alert_id_rejected(env: Env) -> None:
    target = env.work / "f.bin"
    target.write_bytes(b"x")
    resp = _quarantine(env, {"path": str(target), "alert_id": "no-such-alert"})
    assert resp["ok"] is False
    assert resp["error_kind"] == "request"
    assert "alert" in resp["error"]
    assert target.exists()  # nothing was touched


def test_quarantine_file_unknown_case_id_rejected(env: Env) -> None:
    target = env.work / "f.bin"
    target.write_bytes(b"x")
    resp = _quarantine(env, {"path": str(target), "case_id": "no-such-case"})
    assert resp["ok"] is False
    assert resp["error_kind"] == "request"
    assert "case" in resp["error"]
    assert target.exists()


def test_quarantine_file_existing_case_accepted_and_timelined(env: Env) -> None:
    with Database(env.db_path) as db:
        db.execute(
            "INSERT INTO cases (case_id, title, status, opened_at) VALUES (?, ?, 'open', ?)",
            ["c-1", "incident", datetime.now(UTC).replace(tzinfo=None)],
        )
    target = env.work / "f.bin"
    target.write_bytes(b"x")
    resp = _quarantine(env, {"path": str(target), "case_id": "c-1"})
    assert resp["ok"] is True
    with Database(env.db_path) as db:
        timeline = db.query("SELECT kind FROM case_event WHERE case_id = 'c-1'").fetchall()
    assert ("file_quarantined",) in timeline


def test_quarantine_file_ops_error_is_data(env: Env) -> None:
    resp = _quarantine(env, {"path": str(env.work / "missing.bin")})
    assert resp["ok"] is False
    assert resp["error_kind"] == "not_found"
    assert "error" in resp


# ---------------------------------------------------------------------------
# restore / delete
# ---------------------------------------------------------------------------


def _restore(env: Env, params: dict[str, Any]) -> dict[str, Any]:
    params = {PEER_PARAM: PEER, **params}
    return handle_restore_quarantined(
        params=params, db_path=env.db_path, store=env.store, paths=env.paths
    )


def _delete(env: Env, params: dict[str, Any]) -> dict[str, Any]:
    params = {PEER_PARAM: PEER, **params}
    return handle_delete_quarantined(
        params=params, db_path=env.db_path, store=env.store, lock=env.lock
    )


def test_restore_success_shape_and_actor(env: Env) -> None:
    target = env.work / "restore-me.bin"
    target.write_bytes(b"contents")
    qid = _quarantine(env, {"path": str(target)})["quarantine_id"]
    resp = _restore(env, {"quarantine_id": qid})
    assert resp["ok"] is True
    assert resp["quarantine_id"] == qid
    assert resp["original_path"] == str(target)
    assert resp["setuid_warning"] is False
    assert target.read_bytes() == b"contents"
    row = next(r for r in _audit_rows(env) if r["action"] == "quarantine_restored")
    assert row["actor"] == ACTOR


def test_restore_unknown_id_is_data(env: Env) -> None:
    resp = _restore(env, {"quarantine_id": "nope"})
    assert resp["ok"] is False
    assert resp["error_kind"] == "not_found"


def test_restore_requires_quarantine_id(env: Env) -> None:
    resp = _restore(env, {})
    assert resp["ok"] is False
    assert resp["error_kind"] == "request"


def test_delete_success_shape_and_actor(env: Env) -> None:
    target = env.work / "delete-me.bin"
    target.write_bytes(b"gone")
    result = _quarantine(env, {"path": str(target)})
    resp = _delete(env, {"quarantine_id": result["quarantine_id"]})
    assert resp["ok"] is True
    assert resp["blob_removed"] is True
    assert not env.store.path_for(result["sha256"]).exists()
    row = next(r for r in _audit_rows(env) if r["action"] == "quarantine_deleted")
    assert row["actor"] == ACTOR


def test_delete_requires_quarantine_id(env: Env) -> None:
    resp = _delete(env, {})
    assert resp["ok"] is False
    assert resp["error_kind"] == "request"


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_list_shape_echoes_limit_and_flags(env: Env) -> None:
    target = env.work / "listed.bin"
    target.write_bytes(b"list me")
    _quarantine(env, {"path": str(target)})
    resp = handle_list_quarantine(params={"limit": 5}, db_path=env.db_path, store=env.store)
    assert resp["ok"] is True
    assert resp["limit"] == 5
    [row] = resp["rows"]
    assert row["original_path"] == str(target)
    assert row["status"] == "active"
    assert row["flags"] == []


def test_list_bad_limit_is_request_error(env: Env) -> None:
    resp = handle_list_quarantine(params={"limit": "many"}, db_path=env.db_path, store=env.store)
    assert resp["ok"] is False
    assert resp["error_kind"] == "request"


# ---------------------------------------------------------------------------
# registration (§4): the four methods, the right actions, two distinct limiters
# ---------------------------------------------------------------------------


def test_methods_registered_with_actions_and_limiters(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    methods = {m.name: m for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]

    quarantine = methods["quarantine_file"]
    listing = methods["list_quarantine"]
    restore = methods["restore_quarantined"]
    delete = methods["delete_quarantined"]

    assert quarantine.polkit_action == "org.inspectord.quarantine"
    assert restore.polkit_action == "org.inspectord.quarantine-restore"
    assert delete.polkit_action == "org.inspectord.quarantine-delete"
    assert listing.polkit_action is None

    assert quarantine.mutates and restore.mutates and delete.mutates
    assert listing.mutates is False

    # Per-verb windows (§4): restore's availability is a security property, so
    # a denied-quarantine flood must not consume restore/delete's window.
    assert quarantine.limiter is not None
    assert restore.limiter is not None
    assert restore.limiter is delete.limiter
    assert quarantine.limiter is not restore.limiter


def test_quarantine_file_polkit_target_extracts_path(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    methods = {m.name: m for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]
    extractor = methods["quarantine_file"].polkit_target
    assert extractor is not None
    assert extractor({"path": "/tmp/x"}) == "/tmp/x"
    assert extractor({}) is None
    assert extractor({"path": 5}) is None
    for name in ("list_quarantine", "restore_quarantined", "delete_quarantined"):
        assert methods[name].polkit_target is None
