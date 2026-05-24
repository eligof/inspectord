"""Tests for the schema migrations runner."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def test_run_migrations_on_fresh_db(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 1
    db.close()


def test_run_migrations_is_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    first = current_schema_version(db)
    run_migrations(db)
    second = current_schema_version(db)
    assert first == second
    db.close()


def test_schema_version_table_exists_after_migration(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    rows = db.query(
        "SELECT table_name FROM information_schema.tables WHERE table_name='schema_version'"
    ).fetchall()
    assert rows
    db.close()
