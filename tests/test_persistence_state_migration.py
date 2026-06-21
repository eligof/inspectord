"""Tests for migration 0005 — persistence_state table."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_persistence_state_table_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    # PRAGMA table_info rows are (cid, name, type, notnull, dflt, pk).
    cols = {r[1] for r in db.query("PRAGMA table_info('persistence_state')").fetchall()}
    assert {
        "persist_key",
        "kind",
        "name",
        "source_path",
        "details",
        "first_seen",
        "last_seen",
        "last_event_id",
    } <= cols
    db.close()
