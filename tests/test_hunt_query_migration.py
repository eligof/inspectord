"""Tests for migration 0009 — the hunt_query table (hunt design §8)."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_hunt_query_table_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    # PRAGMA table_info rows are (cid, name, type, notnull, dflt, pk).
    cols = {r[1] for r in db.query("PRAGMA table_info('hunt_query')").fetchall()}
    assert {"name", "expression", "description", "created_at", "updated_at"} <= cols
    db.close()


def test_hunt_query_name_is_primary_key(tmp_path: Path) -> None:
    """The name is the key an investigator types; the database enforces it."""
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    pk = {r[1] for r in db.query("PRAGMA table_info('hunt_query')").fetchall() if r[5]}
    assert pk == {"name"}
    db.close()


def test_hunt_query_expression_is_not_null(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    notnull = {r[1] for r in db.query("PRAGMA table_info('hunt_query')").fetchall() if r[3]}
    assert {"name", "expression", "created_at", "updated_at"} <= notnull
    assert "description" not in notnull
    db.close()


def test_hunt_query_migration_is_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    first = run_migrations(db)
    second = run_migrations(db)
    assert first == second >= 9
    db.close()
