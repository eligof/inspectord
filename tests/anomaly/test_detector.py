"""AnomalyDetector skeleton tests."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.anomaly.detector import AnomalyDetector
from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.config import AnomalyConfig
from inspectord.parsers.base import build_event
from inspectord.router import DropPolicy, EventRouter
from inspectord.schemas.event import Event
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


# --- PR2: statistical engine integration -----------------------------------

T0 = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)


def _conn_event(ts: datetime, name: str = "curl") -> Event:
    return build_event(
        module="outbound_connection_tracker",
        action="outbound_connection",
        category=["network"],
        type_=["connection", "start"],
        severity="info",
        ts=ts,
        process={"pid": 2, "name": name},
        destination={"ip": "203.0.113.9", "port": 443},
    )


def _stat_detector(db, *, min_samples: int = 5, max_entities: int = 512):
    cfg = AnomalyConfig(
        tick_s=3600.0, min_samples=min_samples, max_entities_per_metric=max_entities
    )
    router = EventRouter()
    sub = router.subscribe(
        name="anomaly",
        queue_size=4096,
        drop_policy=DropPolicy.drop_oldest_non_critical,
        filter_fn=lambda ev: ev.module != "anomaly_detector",
    )
    emitted: list[Event] = []
    det = AnomalyDetector(
        db=db,
        tracker=FirstSightingTracker(),
        config=cfg,
        subscription=sub,
        emit=emitted.append,
    )
    return det, router, emitted


def test_drained_events_produce_signal_after_spike(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, emitted = _stat_detector(db)
    # 6 calm minutes (one wiggle to keep stddev nonzero), then a burst.
    for i, n in enumerate([1, 1, 2, 1, 1, 1]):
        for _ in range(n):
            router.publish(_conn_event(T0 + timedelta(minutes=i)))
        det._tick(now=T0 + timedelta(minutes=i + 1))
        assert emitted == []
    for _ in range(100):
        router.publish(_conn_event(T0 + timedelta(minutes=6)))
    det._tick(now=T0 + timedelta(minutes=7))
    # The burst spikes BOTH metrics fed by outbound events — one signal each.
    assert sorted(s.baseline["metric_kind"] for s in emitted) == [
        "events_per_min",
        "new_conn_per_min",
    ]
    conn = [s for s in emitted if s.baseline["metric_kind"] == "new_conn_per_min"]
    assert len(conn) == 1
    sig = conn[0]
    assert sig.kind.value == "signal"
    assert sig.module == "anomaly_detector"
    assert sig.action == "metric_anomaly"
    assert sig.category == ["anomaly"]
    assert sig.baseline is not None
    assert sig.baseline["window"] == "1h"
    assert sig.baseline["bucket_label"] == "per minute"
    assert sig.baseline["deviation"] > 3.0
    assert sig.baseline["observed"] == 100.0
    assert sig.process == {"name": "curl"}
    db.close()


def test_own_signals_never_reenter_via_filter(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, _emitted = _stat_detector(db)
    sig = build_event(
        module="anomaly_detector",
        action="metric_anomaly",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        kind="signal",
        ts=T0,
        process={"name": "curl"},
    )
    router.publish(sig)  # filter_fn drops it before the queue
    det._tick(now=T0 + timedelta(minutes=1))
    assert det._engine.stats_for("events_per_min", "curl:anomaly") is None
    db.close()


def test_checkpoint_persists_and_reloads(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, _ = _stat_detector(db)
    for i in range(6):
        router.publish(_conn_event(T0 + timedelta(minutes=i)))
        det._tick(now=T0 + timedelta(minutes=i + 1))
    det.checkpoint()
    rows = db.query(
        "SELECT window_name FROM metric_baseline "
        "WHERE metric_kind = 'new_conn_per_min' AND entity_key = 'curl'"
    ).fetchall()
    assert {r[0] for r in rows} == {"1h", "24h", "7d"}

    det2, _, _ = _stat_detector(db)
    det2.load_checkpoints()
    ws = det2._engine.stats_for("new_conn_per_min", "curl")
    assert ws is not None
    assert len(ws.ring("1h")) == 6
    db.close()


def test_corrupt_checkpoint_row_is_discarded(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.execute(
        "INSERT INTO metric_baseline VALUES ('new_conn_per_min', 'curl', '1h', 'garbage', now())"
    )
    det, _, _ = _stat_detector(db)
    det.load_checkpoints()  # must not raise
    assert det._engine.stats_for("new_conn_per_min", "curl") is None
    # The garbage row is gone so it cannot fail every startup forever.
    rows = db.query("SELECT count(*) FROM metric_baseline").fetchall()
    assert rows[0][0] == 0
    db.close()


def test_evicted_entities_lose_their_checkpoint_rows(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, _ = _stat_detector(db, max_entities=1)
    router.publish(_conn_event(T0, name="curl"))
    det._tick(now=T0 + timedelta(minutes=1))
    det.checkpoint()
    router.publish(_conn_event(T0 + timedelta(minutes=1), name="wget"))  # evicts curl
    det._tick(now=T0 + timedelta(minutes=2))
    det.checkpoint()
    rows = db.query(
        "SELECT DISTINCT entity_key FROM metric_baseline WHERE metric_kind = 'new_conn_per_min'"
    ).fetchall()
    assert rows == [("wget",)]
    db.close()


def test_stop_skips_final_writes_when_thread_hung(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, _ = _stat_detector(db)
    router.publish(_conn_event(T0))
    det._tick(now=T0 + timedelta(minutes=1))

    # Simulate a wedged thread: alive dummy that ignores the join.
    class _Wedged:
        def join(self, timeout=None):
            return None

        def is_alive(self):
            return True

    det._thread = _Wedged()  # type: ignore[assignment]
    det.stop(timeout=0.01)
    # No checkpoint rows were written by stop().
    assert db.query("SELECT count(*) FROM metric_baseline").fetchall()[0][0] == 0
    db.close()
