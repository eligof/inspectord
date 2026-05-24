"""Tests for the deps migration (0002_deps.sql)."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def test_migration_creates_deps_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 2

    tables = {
        row[0]
        for row in db.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
    }
    for needed in (
        "pending_dep_plans",
        "dep_state",
        "dep_config_backups",
        "dep_audit",
    ):
        assert needed in tables, f"missing table {needed}"
    db.close()


def test_pending_dep_plans_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        row[0]
        for row in db.query(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'pending_dep_plans'"
        ).fetchall()
    }
    expected = {
        "plan_id",
        "created_at",
        "created_by",
        "distro",
        "package_manager",
        "items_json",
        "estimated_disk_mb",
        "expires_at",
        "status",
    }
    assert expected.issubset(cols)
    db.close()


def test_dep_audit_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        row[0]
        for row in db.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'dep_audit'"
        ).fetchall()
    }
    expected = {
        "ts",
        "actor",
        "action",
        "target",
        "plan_id",
        "before_sha256",
        "after_sha256",
        "command",
        "exit_code",
        "stderr_tail",
    }
    assert expected.issubset(cols)
    db.close()
