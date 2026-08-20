"""Tests for migration 0010 — first_seen, metric_baseline."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def _tables(db: Database) -> set[str]:
    return {
        r[0]
        for r in db.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
    }


def test_migration_creates_anomaly_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 10
    tables = _tables(db)
    for needed in ("first_seen", "metric_baseline"):
        assert needed in tables, f"missing table {needed}"
    db.close()


def test_first_seen_columns_and_pk(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        r[0]
        for r in db.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'first_seen'"
        ).fetchall()
    }
    assert cols == {"category", "entity_kind", "entity_key", "first_seen_at", "event_id"}
    # The composite PK makes INSERT OR IGNORE the dedup mechanism for re-flushes.
    db.execute("INSERT INTO first_seen VALUES ('process', 'binary', '/usr/bin/xz', now(), 'e1')")
    db.execute(
        "INSERT OR IGNORE INTO first_seen VALUES ('process', 'binary', '/usr/bin/xz', now(), 'e2')"
    )
    rows = db.query("SELECT count(*) FROM first_seen").fetchall()
    assert rows[0][0] == 1
    db.close()
