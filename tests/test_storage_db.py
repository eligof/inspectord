"""Tests for the DuckDB connection wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.storage.db import Database


def test_database_creates_file(tmp_path: Path) -> None:
    db_path = tmp_path / "test.duckdb"
    db = Database(db_path)
    db.connect()
    db.close()
    assert db_path.exists()


def test_database_execute_and_query(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    try:
        db.execute("CREATE TABLE t (a INTEGER, b VARCHAR)")
        db.execute("INSERT INTO t VALUES (?, ?)", [1, "hello"])
        rows = db.query("SELECT a, b FROM t").fetchall()
        assert rows == [(1, "hello")]
    finally:
        db.close()


def test_database_context_manager_closes(tmp_path: Path) -> None:
    db_path = tmp_path / "test.duckdb"
    with Database(db_path) as db:
        db.execute("CREATE TABLE t (a INTEGER)")
    with Database(db_path) as db2:
        rows = db2.query("SELECT * FROM t").fetchall()
        assert rows == []


def test_database_reraises_query_after_close(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    db.close()
    with pytest.raises(RuntimeError):
        db.query("SELECT 1")
