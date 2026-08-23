"""AnomalyDetector skeleton tests."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.anomaly.detector import AnomalyDetector
from inspectord.anomaly.entity_baseline import ResourceSignal
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


# --- PR3: beaconing ---------------------------------------------------------


def _cadence_events(router, n: int, *, start=None, period_s: float = 60.0) -> None:
    base = start if start is not None else T0
    for i in range(n):
        router.publish(_conn_event(base + timedelta(seconds=period_s * i)))


def test_regular_cadence_emits_one_beacon_signal_per_tick(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, emitted = _stat_detector(db)
    # 14 connections 60 s apart → intervals hit 12 and 13: two qualifying
    # observations in one drain, deduped to ONE signal for the key.
    _cadence_events(router, 14)
    det._tick(now=T0 + timedelta(minutes=14))
    beacons = [s for s in emitted if s.action == "beacon_signature"]
    assert len(beacons) == 1
    sig = beacons[0]
    assert sig.kind.value == "signal"
    assert sig.module == "anomaly_detector"
    assert sig.category == ["anomaly"]
    assert sig.process == {"name": "curl"}
    assert sig.destination == {"ip": "203.0.113.9", "port": 443}
    assert sig.baseline is not None
    assert sig.baseline["metric_kind"] == "beacon"
    assert sig.baseline["entity_key"] == "curl->203.0.113.9:443"
    assert sig.baseline["count"] == 13
    assert sig.baseline["interval_mean_s"] == 60.0
    assert sig.baseline["cv"] == 0.0
    db.close()


def test_jittered_cadence_emits_no_beacon_signal(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, emitted = _stat_detector(db)
    ts = T0
    for gap in [10.0, 300.0, 45.0, 900.0, 30.0, 600.0] * 4:
        router.publish(_conn_event(ts))
        ts = ts + timedelta(seconds=gap)
    det._tick(now=ts + timedelta(minutes=1))
    assert [s for s in emitted if s.action == "beacon_signature"] == []
    db.close()


def test_beacon_state_checkpoints_and_reloads(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, _ = _stat_detector(db)
    _cadence_events(router, 10)  # 9 intervals: warm but silent
    det._tick(now=T0 + timedelta(minutes=10))
    det.checkpoint()
    rows = db.query(
        "SELECT metric_kind, entity_key FROM metric_baseline WHERE window_name = 'beacon'"
    ).fetchall()
    assert rows == [("beacon", "curl->203.0.113.9:443")]

    det2, router2, emitted2 = _stat_detector(db)
    det2.load_checkpoints()
    # Reload re-anchors (no cross-restart interval): the first connection
    # anchors, the next 3 add intervals 10..12 — fires without restarting
    # the warm-up.
    _cadence_events(router2, 4, start=T0 + timedelta(seconds=60.0 * 10))
    det2._tick(now=T0 + timedelta(minutes=14))
    assert [s.action for s in emitted2] == ["beacon_signature"]
    db.close()


def test_beacon_rows_survive_engine_checkpoint_rewrite(tmp_path: Path) -> None:
    # checkpoint() rewrites metric_baseline from scratch; beacon rows must be
    # part of the rewrite, not casualties of it.
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, _ = _stat_detector(db)
    _cadence_events(router, 5)
    det._tick(now=T0 + timedelta(minutes=5))
    det.checkpoint()
    det.checkpoint()  # second rewrite must not lose the beacon row
    rows = db.query("SELECT count(*) FROM metric_baseline WHERE window_name = 'beacon'").fetchall()
    assert rows[0][0] == 1
    # Engine windows for the same activity are present alongside.
    other = db.query(
        "SELECT count(*) FROM metric_baseline WHERE window_name != 'beacon'"
    ).fetchall()
    assert other[0][0] > 0
    db.close()


def test_corrupt_beacon_checkpoint_row_is_discarded(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.execute(
        "INSERT INTO metric_baseline VALUES ('beacon', 'curl->x:1', 'beacon', 'garbage', now())"
    )
    det, _, _ = _stat_detector(db)
    det.load_checkpoints()  # must not raise
    assert det._beacon.checkpoint_rows() == []
    rows = db.query("SELECT count(*) FROM metric_baseline").fetchall()
    assert rows[0][0] == 0
    db.close()


def test_connection_without_destination_is_ignored_by_beacon(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, emitted = _stat_detector(db)
    for i in range(20):
        ev = build_event(
            module="outbound_connection_tracker",
            action="outbound_connection",
            category=["network"],
            type_=["connection", "start"],
            severity="info",
            ts=T0 + timedelta(seconds=60.0 * i),
            process={"pid": 2, "name": "curl"},
        )
        router.publish(ev)
    det._tick(now=T0 + timedelta(minutes=20))  # must not raise
    assert [s for s in emitted if s.action == "beacon_signature"] == []
    db.close()


# --- PR4: resource sampling path --------------------------------------------


def _resource_det(tmp_path: Path):
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, _router, emitted = _stat_detector(db)
    return det, emitted


class _StubSampler:
    """Records the unit list it was asked to sample; returns canned signals."""

    def __init__(self, signals: list[ResourceSignal]) -> None:
        self.signals = signals
        self.calls: list[list[str]] = []

    def sample(self, units: list[str], *, now: float) -> list[ResourceSignal]:
        self.calls.append(list(units))
        return self.signals


def _svc_signal() -> ResourceSignal:
    return ResourceSignal(
        entity_key="svc:foo.service",
        unit="foo.service",
        metric_kind="cpu_pct",
        observed=80.0,
        mean=10.0,
        factor=8.0,
        is_self=False,
    )


def _self_signal() -> ResourceSignal:
    return ResourceSignal(
        entity_key="self",
        unit=None,
        metric_kind="rss_bytes",
        observed=800.0 * 1024 * 1024,
        mean=100.0 * 1024 * 1024,
        factor=8.0,
        is_self=True,
    )


def test_sample_resources_emits_service_signal(tmp_path: Path) -> None:
    det, emitted = _resource_det(tmp_path)
    det._sampler = _StubSampler([_svc_signal()])
    det._sample_resources(now=100.0)
    assert len(emitted) == 1
    ev = emitted[0]
    assert ev.kind.value == "signal"
    assert ev.module == "anomaly_detector"
    assert ev.action == "resource_deviation"
    assert ev.service == {"name": "foo.service"}
    assert ev.baseline["metric_kind"] == "cpu_pct"
    assert ev.baseline["deviation"] == 8.0
    assert ev.baseline["entity_key"] == "svc:foo.service"


def test_sample_resources_self_uses_monitor_health_action(tmp_path: Path) -> None:
    det, emitted = _resource_det(tmp_path)
    det._sampler = _StubSampler([_self_signal()])
    det._sample_resources(now=100.0)
    assert len(emitted) == 1
    assert emitted[0].action == "monitor_health_anomaly"
    assert emitted[0].service is None


def test_sample_resources_lists_active_services(tmp_path: Path) -> None:
    det, _emitted = _resource_det(tmp_path)
    det._db.execute(
        "INSERT INTO service_state (unit, active_state, first_seen, last_seen) "
        "VALUES ('a.service', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP), "
        "('b.service', 'inactive', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    stub = _StubSampler([])
    det._sampler = stub
    det._sample_resources(now=100.0)
    assert stub.calls == [["a.service"]]


def test_sample_resources_survives_sampler_error(tmp_path: Path) -> None:
    class _Boom:
        def sample(self, units: list[str], *, now: float) -> list[ResourceSignal]:
            raise RuntimeError("boom")

    det, _emitted = _resource_det(tmp_path)
    det._sampler = _Boom()
    det._sample_resources(now=100.0)  # must not raise


def test_run_loop_fires_both_cadences(tmp_path: Path) -> None:
    """The dual-deadline loop must drive BOTH cadences off one thread: the
    resource sampler on resource_tick_s and the main tick on tick_s."""
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    tracker = _CountingTracker()
    cfg = AnomalyConfig(tick_s=0.15, resource_tick_s=0.05)
    det = AnomalyDetector(db=db, tracker=tracker, config=cfg)
    stub = _StubSampler([])
    det._sampler = stub  # type: ignore[assignment]
    det.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and (len(stub.calls) < 3 or tracker.flush_calls < 2):
        time.sleep(0.02)
    det.stop(timeout=2.0)
    assert len(stub.calls) >= 3, "resource cadence never fired off the run loop"
    assert tracker.flush_calls >= 2, "main tick cadence never fired off the run loop"
    db.close()
