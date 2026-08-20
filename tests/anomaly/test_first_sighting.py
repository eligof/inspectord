"""FirstSightingTracker unit tests."""

from __future__ import annotations

from pathlib import Path

from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _proc_start(sha: str = "abc123", exe: str = "/usr/bin/xz"):
    return build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1, "name": "xz", "executable": exe, "hash": {"sha256": sha}},
    )


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def test_first_observation_stamps_and_queues() -> None:
    t = FirstSightingTracker()
    ev = _proc_start()
    t.observe(ev)
    assert ev.baseline is not None and ev.baseline["first_sighting"] is True
    assert t.pending_count() == 1


def test_second_observation_does_not_stamp() -> None:
    t = FirstSightingTracker()
    t.observe(_proc_start())
    ev2 = _proc_start()
    t.observe(ev2)
    assert ev2.baseline is None
    assert t.pending_count() == 1


def test_catchup_events_populate_silently_but_still_stamp() -> None:
    # Snapshot catch-up (Event.first_seen=True) is skipped by the rule engine,
    # so stamping it costs nothing and keeps observe() uniform.
    t = FirstSightingTracker()
    ev = _proc_start()
    ev.first_seen = True
    t.observe(ev)
    assert t.pending_count() == 1
    live = _proc_start()
    t.observe(live)
    assert live.baseline is None  # already seen via catch-up


def test_event_without_sighting_key_untouched() -> None:
    t = FirstSightingTracker()
    ev = build_event(
        module="healthcheck", action="tick", category=["host"], type_=["info"], severity="info"
    )
    t.observe(ev)
    assert ev.baseline is None
    assert t.pending_count() == 0


def test_flush_persists_and_load_restores(tmp_path: Path) -> None:
    db = _db(tmp_path)
    t = FirstSightingTracker()
    t.observe(_proc_start())
    assert t.flush(db) == 1
    assert t.pending_count() == 0
    rows = db.query("SELECT category, entity_kind, entity_key FROM first_seen").fetchall()
    assert rows == [("process", "binary", "abc123")]

    t2 = FirstSightingTracker()
    assert t2.load(db) == 1
    ev = _proc_start()
    t2.observe(ev)
    assert ev.baseline is None  # restored from table, not re-sighted
    db.close()


def test_flush_survives_duplicate_rows(tmp_path: Path) -> None:
    # A crash between stamp and flush re-marks the sighting next run; the
    # PRIMARY KEY + INSERT OR IGNORE absorbs the duplicate row.
    db = _db(tmp_path)
    t = FirstSightingTracker()
    t.observe(_proc_start())
    t.flush(db)
    t2 = FirstSightingTracker()  # fresh, did not load()
    t2.observe(_proc_start())
    assert t2.flush(db) == 1
    rows = db.query("SELECT count(*) FROM first_seen").fetchall()
    assert rows[0][0] == 1
    db.close()
