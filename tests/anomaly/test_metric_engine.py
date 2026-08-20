"""MetricEngine unit tests (spec §4.1-4.4). Clock-injected — no threads."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from inspectord.anomaly.stats import MetricEngine, MetricSample
from inspectord.config import AnomalyConfig


def _cfg(**over) -> AnomalyConfig:
    return AnomalyConfig(**{"min_samples": 5, "z_threshold": 3.0, **over})


T0 = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)


def _min(n: int) -> datetime:
    return T0 + timedelta(minutes=n)


def _sample(value: float = 1.0, key: str = "curl") -> MetricSample:
    return MetricSample(
        metric_kind="new_conn_per_min",
        entity_key=key,
        entity={"process": {"name": key}},
        value=value,
    )


def test_signal_after_warmup_spike() -> None:
    eng = MetricEngine(_cfg())
    # Minutes 0..5: calm 1-per-minute with one wiggle; minute 6: burst of 100.
    calm = [1.0, 1.0, 2.0, 1.0, 1.0, 1.0]
    for i, v in enumerate(calm):
        eng.ingest(_sample(v), ts=_min(i))
        assert eng.tick(now=_min(i + 1)) == []
    for _ in range(100):
        eng.ingest(_sample(1.0), ts=_min(6))
    signals = eng.tick(now=_min(7))
    assert len(signals) == 1
    s = signals[0]
    assert s.metric_kind == "new_conn_per_min"
    assert s.entity_key == "curl"
    assert s.window == "1h"
    assert s.observed == 100.0
    assert s.z > 3.0
    assert s.entity == {"process": {"name": "curl"}}


def test_zero_fill_keeps_baseline_honest() -> None:
    eng = MetricEngine(_cfg())
    # Activity in minute 0 only; then 5 silent minutes, ticked one by one.
    eng.ingest(_sample(1.0), ts=_min(0))
    for i in range(6):
        eng.tick(now=_min(i + 1))
    # Ring: [1, 0, 0, 0, 0, 0] — silence was recorded as zeros.
    ws = eng.stats_for("new_conn_per_min", "curl")
    assert ws is not None
    assert list(ws.ring("1h")) == [1.0, 0.0, 0.0, 0.0, 0.0, 0.0]


def test_multi_minute_gap_closes_each_minute() -> None:
    eng = MetricEngine(_cfg())
    eng.ingest(_sample(1.0), ts=_min(0))
    # One tick after a 4-minute gap closes minutes 0..3 individually.
    eng.tick(now=_min(4))
    ws = eng.stats_for("new_conn_per_min", "curl")
    assert ws is not None
    assert list(ws.ring("1h")) == [1.0, 0.0, 0.0, 0.0]


def test_giant_gap_skips_instead_of_zero_flooding() -> None:
    eng = MetricEngine(_cfg())
    eng.ingest(_sample(1.0), ts=_min(0))
    eng.tick(now=_min(1))
    # Two-day suspend: do not push 2880 zeros; skip the span.
    eng.tick(now=_min(1) + timedelta(days=2))
    ws = eng.stats_for("new_conn_per_min", "curl")
    assert ws is not None
    assert len(ws.ring("1h")) < 100


def test_late_event_within_open_minute_still_counts() -> None:
    eng = MetricEngine(_cfg())
    eng.ingest(_sample(1.0), ts=_min(0))
    eng.ingest(_sample(1.0), ts=_min(0))  # same minute, later arrival
    eng.tick(now=_min(1))
    ws = eng.stats_for("new_conn_per_min", "curl")
    assert ws is not None
    assert list(ws.ring("1h")) == [2.0]


def test_lru_eviction_at_entity_cap() -> None:
    eng = MetricEngine(_cfg(max_entities_per_metric=2))
    eng.ingest(_sample(1.0, key="a"), ts=_min(0))
    eng.ingest(_sample(1.0, key="b"), ts=_min(1))
    eng.tick(now=_min(2))
    eng.ingest(_sample(1.0, key="c"), ts=_min(2))  # evicts "a" (least recent)
    assert eng.stats_for("new_conn_per_min", "a") is None
    assert eng.stats_for("new_conn_per_min", "b") is not None
    assert eng.stats_for("new_conn_per_min", "c") is not None
    assert ("new_conn_per_min", "a") in eng.drain_evicted()
    assert eng.drain_evicted() == []  # drained once


def test_checkpoint_rows_round_trip() -> None:
    eng = MetricEngine(_cfg())
    for i in range(7):
        eng.ingest(_sample(float(i)), ts=_min(i))
        eng.tick(now=_min(i + 1))
    rows = eng.checkpoint_rows()
    # 3 windows per tracked entity-metric.
    assert {(r[0], r[1], r[2]) for r in rows} == {
        ("new_conn_per_min", "curl", "1h"),
        ("new_conn_per_min", "curl", "24h"),
        ("new_conn_per_min", "curl", "7d"),
    }
    eng2 = MetricEngine(_cfg())
    for metric_kind, entity_key, window_name, blob in rows:
        assert eng2.load_row(metric_kind, entity_key, window_name, blob) is True
    ws, ws2 = (
        eng.stats_for("new_conn_per_min", "curl"),
        eng2.stats_for("new_conn_per_min", "curl"),
    )
    assert ws is not None and ws2 is not None
    assert list(ws2.ring("1h")) == list(ws.ring("1h"))


def test_load_row_rejects_garbage_without_state() -> None:
    eng = MetricEngine(_cfg())
    assert eng.load_row("new_conn_per_min", "curl", "1h", "not json") is False
    # A rejected row must not leave a half-tracked entity behind.
    assert eng.stats_for("new_conn_per_min", "curl") is None


def test_restored_entity_survives_warmup_reset() -> None:
    # The point of checkpointing: a restart does not reset the warm-up.
    eng = MetricEngine(_cfg())
    for i in range(6):
        eng.ingest(_sample(2.0 if i == 2 else 1.0), ts=_min(i))
        eng.tick(now=_min(i + 1))
    rows = eng.checkpoint_rows()
    eng2 = MetricEngine(_cfg())
    for r in rows:
        eng2.load_row(*r)
    eng2.ingest(_sample(100.0), ts=_min(6))
    signals = eng2.tick(now=_min(7))
    assert any(s.z > 3.0 for s in signals)
