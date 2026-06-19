"""Tests for migration 0004 — entity-state tables."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations

_TABLES = {
    "process_state",
    "connection_state",
    "listener_state",
    "service_state",
    "device_state",
    "file_state",
    "baseline_entry",
}


def test_migration_creates_entity_state_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 4
    rows = db.query("SELECT table_name FROM information_schema.tables").fetchall()
    present = {r[0] for r in rows}
    assert present >= _TABLES
    db.close()


def test_service_state_upsert_roundtrip(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    db.execute(
        "INSERT INTO service_state (unit, active_state, sub_state, load_state, "
        "first_seen, last_seen, last_event_id) VALUES "
        "('sshd.service', 'active', 'running', 'loaded', "
        "TIMESTAMP '2026-06-16 00:00:00', TIMESTAMP '2026-06-16 00:00:00', 'e1')"
    )
    rows = db.query("SELECT active_state FROM service_state WHERE unit='sshd.service'").fetchall()
    assert rows[0][0] == "active"
    db.close()
