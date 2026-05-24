"""Tests for migration 0003 — alerts, rule_stats, rule_dryrun_log."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def test_migration_creates_alert_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 3
    tables = {
        r[0]
        for r in db.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
    }
    for needed in ("alerts", "rule_stats", "rule_dryrun_log"):
        assert needed in tables, f"missing table {needed}"
    db.close()


def test_alerts_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        r[0]
        for r in db.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'alerts'"
        ).fetchall()
    }
    expected = {
        "alert_id",
        "rule_id",
        "ts",
        "severity",
        "status",
        "category",
        "dedup_key",
        "dedup_count",
        "first_seen_at",
        "last_seen_at",
        "rendered_short",
        "rendered_detail",
        "payload_json",
    }
    assert expected.issubset(cols)
    db.close()


def test_rule_stats_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        r[0]
        for r in db.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'rule_stats'"
        ).fetchall()
    }
    expected = {
        "rule_id",
        "fire_count",
        "last_fired_at",
        "dryrun_count",
        "suppressed_count",
        "updated_at",
    }
    assert expected.issubset(cols)
    db.close()
