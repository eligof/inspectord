"""AnomalyDetector skeleton tests."""

from __future__ import annotations

import time
from pathlib import Path

from inspectord.anomaly.detector import AnomalyDetector
from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.config import AnomalyConfig
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _tracker_with_pending() -> FirstSightingTracker:
    t = FirstSightingTracker()
    ev = build_event(
        module="kmod_watcher",
        action="kmod_loaded",
        category=["driver"],
        type_=["installation"],
        severity="info",
        raw={"module_name": "nft_ct"},
    )
    t.observe(ev)
    return t


class _CountingTracker(FirstSightingTracker):
    def __init__(self) -> None:
        super().__init__()
        self.flush_calls = 0

    def flush(self, db):  # type: ignore[override]
        self.flush_calls += 1
        return super().flush(db)


def test_tick_flushes_pending(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    tracker = _tracker_with_pending()
    det = AnomalyDetector(db=db, tracker=tracker, config=AnomalyConfig(tick_s=0.05))
    det.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and tracker.pending_count():
        time.sleep(0.02)
    assert tracker.pending_count() == 0, "tick never flushed"
    det.stop(timeout=2.0)
    assert db.query("SELECT count(*) FROM first_seen").fetchall()[0][0] == 1
    db.close()


def test_tick_failure_does_not_kill_thread(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()  # run_migrations deliberately NOT run: flush will raise
    tracker = _CountingTracker()
    ev = build_event(
        module="kmod_watcher",
        action="kmod_loaded",
        category=["driver"],
        type_=["installation"],
        severity="info",
        raw={"module_name": "nft_ct"},
    )
    tracker.observe(ev)
    det = AnomalyDetector(db=db, tracker=tracker, config=AnomalyConfig(tick_s=0.05))
    det.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and tracker.flush_calls < 1:
        time.sleep(0.02)
    assert tracker.flush_calls >= 1, "tick never ran"
    assert det.is_alive()
    run_migrations(db)  # heal the DB; stop()'s final flush now succeeds
    tracker.observe(
        build_event(
            module="kmod_watcher",
            action="kmod_loaded",
            category=["driver"],
            type_=["installation"],
            severity="info",
            raw={"module_name": "vfat"},
        )
    )
    det.stop(timeout=2.0)
    assert not det.is_alive()
    # Only 1, not 2: flush() unconditionally clears _pending before attempting
    # inserts (its own docstring: "Raises on DB failure ... the rows are
    # gone"), so the nft_ct row queued before start() is permanently lost by
    # the guaranteed-to-fail pre-heal tick. This still proves recovery: the
    # thread survives the failure and the post-heal vfat sighting persists
    # via stop()'s final flush.
    assert db.query("SELECT count(*) FROM first_seen").fetchall()[0][0] == 1
    db.close()


def test_stop_performs_final_flush(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    tracker = _tracker_with_pending()
    # Huge tick: the loop never fires; only stop()'s final flush can persist.
    det = AnomalyDetector(db=db, tracker=tracker, config=AnomalyConfig(tick_s=3600.0))
    det.start()
    det.stop(timeout=2.0)
    assert db.query("SELECT count(*) FROM first_seen").fetchall()[0][0] == 1
    db.close()
