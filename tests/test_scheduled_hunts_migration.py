"""Tests for migration 0013 — ingest_seq + hunt_query schedule columns.

The ingest sequence is the ground the scheduled-hunt watermark stands on
(hunt-followups design §4.2/§4.3): assigned at INSERT, monotonic, no clocks.
Pre-existing rows keep NULL and are pre-watermark for every schedule.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations


def _insert(db: Database, name: str) -> None:
    event = build_event(
        module="probe",
        action="tick",
        category=["c"],
        type_=["t"],
        severity="info",
        process={"name": name},
        ts=datetime(2026, 9, 7, 12, 0, tzinfo=UTC),
    )
    insert_event(db, event, event.model_dump_json())


def test_migration_0013_is_idempotent(tmp_path: Path) -> None:
    """The runner is not transactional: a crash mid-file re-applies the whole
    file, so every statement must be re-runnable against the altered schema."""
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    first = run_migrations(db)
    assert first >= 13
    # Force a real re-application of 0013's statements, not the runner's
    # schema_version short-circuit.
    db.execute("DELETE FROM schema_version WHERE version = 13")
    second = run_migrations(db)
    assert second == first
    db.close()


def test_events_get_monotonic_ingest_seq(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    _insert(db, "p0")
    _insert(db, "p1")
    rows = db.query("SELECT ingest_seq FROM events_enriched ORDER BY ingest_seq").fetchall()
    seqs = [row[0] for row in rows]
    assert len(seqs) == 2
    assert all(seq is not None for seq in seqs)
    assert seqs[0] < seqs[1]
    db.close()


def test_preexisting_rows_have_null_ingest_seq_and_are_excluded_from_max(
    tmp_path: Path,
) -> None:
    """A pre-migration row is pre-watermark forever: NULL never satisfies
    `ingest_seq > ?` and never inflates MAX(ingest_seq)."""
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    # A row as the pre-0013 insert path would have left it: no ingest_seq.
    db.execute(
        "INSERT INTO events_enriched "
        "(event_id, ts, kind, module, action, severity, payload_json, ingest_seq) "
        "VALUES ('old-row', ?, 'event', 'probe', 'tick', 'info', '{}', NULL)",
        [datetime(2026, 9, 1, 12, 0, tzinfo=UTC)],
    )
    _insert(db, "new")
    (max_seq,) = db.query("SELECT MAX(ingest_seq) FROM events_enriched").fetchall()[0]
    (real_seq,) = db.query(
        "SELECT ingest_seq FROM events_enriched WHERE event_id != 'old-row'"
    ).fetchall()[0]
    assert max_seq == real_seq
    above_zero = db.query("SELECT event_id FROM events_enriched WHERE ingest_seq > 0").fetchall()
    assert [row[0] for row in above_zero] != []
    assert "old-row" not in {row[0] for row in above_zero}
    db.close()


def test_hunt_query_gains_schedule_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {r[1] for r in db.query("PRAGMA table_info('hunt_query')").fetchall()}
    assert {
        "schedule_interval_s",
        "schedule_severity",
        "watermark_seq",
        "last_run_at",
        "last_status",
    } <= cols
    db.close()
