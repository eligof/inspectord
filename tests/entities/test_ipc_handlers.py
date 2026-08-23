"""Tests for the get_entity_card IPC handler."""

from __future__ import annotations

from pathlib import Path

from inspectord.__main__ import _ipc_methods
from inspectord.config import dev_config
from inspectord.entities.ipc_handlers import handle_get_entity_card
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def test_ok_shape(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_get_entity_card(params={"kind": "service", "key": "sshd.service"}, db_path=db_path)
    assert out["ok"] is True
    assert out["schema_version"] == "1.0.0"
    assert out["card"]["kind"] == "service"
    assert out["card"]["found"] is False


def test_invalid_kind_error_shape(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_get_entity_card(params={"kind": "nope", "key": "x"}, db_path=db_path)
    assert out == {"schema_version": "1.0.0", "ok": False, "error": "invalid_kind"}


def test_window_clamped(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_get_entity_card(
        params={"kind": "service", "key": "s.service", "window_h": 99999},
        db_path=db_path,
    )
    assert out["ok"] is True  # clamped, not rejected


def test_registered_in_daemon_method_list(tmp_path):
    cfg = dev_config(base=tmp_path)
    mutates = {m.name: m.mutates for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]
    assert mutates["get_entity_card"] is False
