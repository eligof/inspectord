"""Tests for migration 0006 — cases tables."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _cols(db: Database, table: str) -> set[str]:
    # PRAGMA table_info rows are (cid, name, type, notnull, dflt, pk).
    return {r[1] for r in db.query(f"PRAGMA table_info('{table}')").fetchall()}


def test_cases_tables_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert {"case_id", "title", "status", "opened_at", "closed_at"} <= _cols(db, "cases")
    assert {"case_id", "alert_id", "attached_at"} <= _cols(db, "case_alert")
    assert {"case_id", "ts", "seq", "kind", "text"} <= _cols(db, "case_event")
    db.close()
