"""Tests for the audit log IPC handlers (spec 2026-08-25 §7)."""

from __future__ import annotations

import json
from pathlib import Path

from inspectord.__main__ import _ipc_methods
from inspectord.audit.ipc_handlers import handle_list_audit_log, handle_verify_audit_log
from inspectord.audit.log import append_audit, reset_for_tests
from inspectord.config import dev_config
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def setup_function(_fn) -> None:
    reset_for_tests()  # drop the module connection + counters between tests


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


# --------------------------------------------------------------------------
# list_audit_log
# --------------------------------------------------------------------------


def test_list_shape_and_order(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    for i in range(3):
        append_audit(db_path, actor="user:local", action="a", target=f"t:{i}", details={})
    out = handle_list_audit_log(params={}, db_path=db_path)
    assert out["ok"] and out["schema_version"] == "1.0.0"
    assert [r["seq"] for r in out["rows"]] == [3, 2, 1]  # newest first
    newest = out["rows"][0]
    assert newest["actor"] == "user:local"
    assert newest["action"] == "a"
    assert newest["target"] == "t:2"
    assert newest["details"] == {}
    assert isinstance(newest["ts"], str)


def test_list_limit_applied(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    for i in range(5):
        append_audit(db_path, actor="user:local", action="a", target=f"t:{i}", details={})
    out = handle_list_audit_log(params={"limit": 2}, db_path=db_path)
    assert [r["seq"] for r in out["rows"]] == [5, 4]


def test_list_limit_clamped(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    out = handle_list_audit_log(params={"limit": 99999}, db_path=db_path)
    assert out["ok"]  # clamped to 500, not rejected
    out = handle_list_audit_log(params={"limit": "junk"}, db_path=db_path)
    assert out["ok"]  # non-numeric falls back to the default
    out = handle_list_audit_log(params={"limit": -3}, db_path=db_path)
    assert out["ok"]  # clamped up to 1, not rejected


# --------------------------------------------------------------------------
# verify_audit_log
# --------------------------------------------------------------------------


def test_verify_clean_and_anchor_lookup(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    out = handle_verify_audit_log(params={}, db_path=db_path)
    assert out["ok"] and out["verification"]["ok"] is True
    assert out["verification"]["anchor_checked"] is False  # no anchor event seeded


def _seed_audit_head_event(db_path: Path, seq: int) -> None:
    """Insert a supervisor/audit_head event carrying seq + the REAL row_hash."""
    with Database(db_path) as db:
        row = db.query("SELECT row_hash FROM audit_log WHERE seq = ?", [seq]).fetchone()
        assert row is not None
        payload = json.dumps({"raw": {"seq": seq, "row_hash": row[0]}})
        db.execute(
            "INSERT INTO events_enriched "
            "(event_id, ts, kind, module, action, severity, payload_json) "
            "VALUES ('ev-anchor', TIMESTAMP '2026-08-25 12:00:00', 'event', "
            "'supervisor', 'audit_head', 'info', ?)",
            [payload],
        )


def test_verify_uses_newest_audit_head_event(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    _seed_audit_head_event(db_path, seq=1)  # capture the real row_hash BEFORE the wipe
    with Database(db_path) as db:
        db.execute("DELETE FROM audit_log")  # full wipe: only the anchor can see it
    out = handle_verify_audit_log(params={}, db_path=db_path)
    assert out["verification"]["ok"] is False
    assert out["verification"]["reason"] == "anchor_mismatch"
    assert out["verification"]["anchor_checked"] is True


def test_verify_anchor_event_with_null_payload_is_skipped(tmp_path: Path) -> None:
    """A top-level JSON null/array payload must be treated as no anchor."""
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO events_enriched "
            "(event_id, ts, kind, module, action, severity, payload_json) "
            "VALUES ('ev-null', TIMESTAMP '2026-08-25 12:00:00', 'event', "
            "'supervisor', 'audit_head', 'info', 'null')"
        )
    out = handle_verify_audit_log(params={}, db_path=db_path)  # no raise
    assert out["verification"]["ok"] is True
    assert out["verification"]["anchor_checked"] is False


# --------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------


def test_methods_registered_read_only(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    mutates = {m.name: m.mutates for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]
    assert mutates["list_audit_log"] is False
    assert mutates["verify_audit_log"] is False
