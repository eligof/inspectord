"""BeaconTracker unit tests (spec §5). Clock-injected — no threads."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from inspectord.anomaly.beacon import BeaconHit, BeaconTracker
from inspectord.config import AnomalyConfig

T0 = datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)


def _cfg(**over) -> AnomalyConfig:
    return AnomalyConfig(**over)


def _feed(
    tracker: BeaconTracker,
    intervals: list[float],
    *,
    name: str = "curl",
    ip: str = "203.0.113.9",
    port: int = 443,
    start: datetime = T0,
) -> list[BeaconHit]:
    """Observe one connection, then one more after each interval; collect hits."""
    hits = []
    ts = start
    hit = tracker.observe(process_name=name, dst_ip=ip, dst_port=port, ts=ts)
    if hit is not None:
        hits.append(hit)
    for iv in intervals:
        ts = ts + timedelta(seconds=iv)
        hit = tracker.observe(process_name=name, dst_ip=ip, dst_port=port, ts=ts)
        if hit is not None:
            hits.append(hit)
    return hits


def test_regular_cadence_fires_at_min_events() -> None:
    tracker = BeaconTracker(_cfg())
    # 60 s ± 2 s: cv ≈ 0.033 < 0.1. 12 intervals = beacon_min_events.
    hits = _feed(tracker, [60.0, 62.0] * 6)
    assert len(hits) == 1
    h = hits[0]
    assert h.process_name == "curl"
    assert h.dst_ip == "203.0.113.9"
    assert h.dst_port == 443
    assert h.entity_key == "curl→203.0.113.9:443"
    assert h.count == 12
    assert 60.0 < h.mean_interval_s < 62.0
    assert h.cv < 0.1
    assert h.stddev_interval_s > 0.0


def test_perfectly_regular_cadence_fires_with_zero_cv() -> None:
    tracker = BeaconTracker(_cfg())
    hits = _feed(tracker, [60.0] * 12)
    assert len(hits) == 1
    assert hits[0].cv == 0.0


def test_hit_repeats_on_subsequent_observations() -> None:
    # Per-observation evaluation: the 13th interval also qualifies. The
    # detector dedups per drain; the tracker itself stays stateless about it.
    tracker = BeaconTracker(_cfg())
    hits = _feed(tracker, [60.0] * 13)
    assert len(hits) == 2


def test_jittered_cadence_never_fires() -> None:
    tracker = BeaconTracker(_cfg())
    # Human-ish traffic: wildly varying gaps, cv >> 0.1.
    hits = _feed(tracker, [10.0, 300.0, 45.0, 900.0, 30.0, 600.0] * 4)
    assert hits == []


def test_below_min_events_never_fires() -> None:
    tracker = BeaconTracker(_cfg())
    hits = _feed(tracker, [60.0] * 11)  # 11 intervals < 12
    assert hits == []


def test_interval_below_min_bound_never_fires() -> None:
    tracker = BeaconTracker(_cfg())
    # Regular but 2 s apart: mean < beacon_min_interval_s (5 s).
    hits = _feed(tracker, [2.0] * 20)
    assert hits == []


def test_interval_above_max_bound_never_fires() -> None:
    tracker = BeaconTracker(_cfg())
    # Regular but 2 h apart: mean > beacon_max_interval_s (3600 s).
    hits = _feed(tracker, [7200.0] * 20)
    assert hits == []


def test_same_timestamp_burst_never_fires_or_crashes() -> None:
    tracker = BeaconTracker(_cfg())
    hits = _feed(tracker, [0.0] * 20)
    assert hits == []


def test_distinct_destinations_are_independent_keys() -> None:
    tracker = BeaconTracker(_cfg())
    hits_a = _feed(tracker, [60.0] * 12, port=443)
    hits_b = _feed(tracker, [10.0, 300.0] * 6, port=8443)
    assert len(hits_a) == 1
    assert hits_b == []


def test_checkpoint_round_trip_preserves_warmup() -> None:
    tracker = BeaconTracker(_cfg())
    assert _feed(tracker, [60.0] * 9) == []  # 9 intervals banked
    rows = tracker.checkpoint_rows()
    assert len(rows) == 1
    metric_kind, entity_key, window_name, blob = rows[0]
    assert (metric_kind, entity_key, window_name) == ("beacon", "curl→203.0.113.9:443", "beacon")

    restored = BeaconTracker(_cfg())
    assert restored.load_row(entity_key, blob) is True
    # 3 more on-cadence connections reach 12 intervals: fires without
    # restarting the warm-up. (Continue from where the feed left off.)
    hits = _feed(restored, [60.0] * 3, start=T0 + timedelta(seconds=60.0 * 10))
    assert len(hits) == 1
    assert hits[0].count == 12


def test_load_row_rejects_garbage_without_state() -> None:
    tracker = BeaconTracker(_cfg())
    assert tracker.load_row("curl→203.0.113.9:443", "not json") is False
    assert tracker.load_row("curl→203.0.113.9:443", '{"wrong": "shape"}') is False
    assert tracker.load_row("curl→203.0.113.9:443", '{"last_ts": "x", "intervals": []}') is False
    assert tracker.checkpoint_rows() == []


def test_lru_eviction_at_key_cap() -> None:
    tracker = BeaconTracker(_cfg(max_entities_per_metric=2))
    _feed(tracker, [60.0], port=1111, start=T0)
    _feed(tracker, [60.0], port=2222, start=T0 + timedelta(minutes=10))
    _feed(tracker, [60.0], port=3333, start=T0 + timedelta(minutes=20))  # evicts :1111
    keys = {row[1] for row in tracker.checkpoint_rows()}
    assert keys == {"curl→203.0.113.9:2222", "curl→203.0.113.9:3333"}


def test_ring_caps_at_32_intervals() -> None:
    tracker = BeaconTracker(_cfg(beacon_max_cv=0.5))
    # 40 intervals alternating 60/62; ring keeps the last 32.
    hits = _feed(tracker, [60.0, 62.0] * 20)
    assert hits  # fires once warm
    assert hits[-1].count == 32
