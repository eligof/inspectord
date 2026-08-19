"""Tests for migration 0008 — scan_run table."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_scan_run_table_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    # PRAGMA table_info rows are (cid, name, type, notnull, dflt, pk).
    cols = {r[1] for r in db.query("PRAGMA table_info('scan_run')").fetchall()}
    assert {
        "run_id",
        "scanner",
        "status",
        "reason",
        "exit_code",
        "duration_s",
        "finding_count",
        "findings_dropped",
        "truncated",
        "output_truncated",
        "output_excerpt",
        "started_at",
        "completed_at",
        "last_event_id",
    } <= cols
    db.close()


def test_scan_run_run_id_is_primary_key(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    pk = {r[1] for r in db.query("PRAGMA table_info('scan_run')").fetchall() if r[5]}
    assert pk == {"run_id"}
    db.close()


def test_scan_run_migration_is_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    first = run_migrations(db)
    second = run_migrations(db)
    assert first == second >= 8
    db.close()
