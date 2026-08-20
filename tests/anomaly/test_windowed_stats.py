"""WindowedStats unit tests (spec §4.2)."""

from __future__ import annotations

from inspectord.anomaly.stats import WINDOWS, WindowedStats


def test_window_definitions_match_spec() -> None:
    assert WINDOWS == (("1h", 60, 1), ("24h", 288, 5), ("7d", 672, 15))


def test_warmup_gate_no_deviation_before_min_samples() -> None:
    ws = WindowedStats()
    for _ in range(49):
        assert ws.push_minute(1.0, min_samples=50, z_threshold=3.0) == []
    # 50th push: ring holds 49 pre-push samples — still below min_samples.
    assert ws.push_minute(100.0, min_samples=50, z_threshold=3.0) == []


def test_spike_fires_after_warmup() -> None:
    ws = WindowedStats()
    # 50 calm minutes with slight noise (a constant series has stddev 0 and
    # is skipped by the guard, so wiggle one sample).
    values = [1.0] * 49 + [2.0]
    for v in values:
        ws.push_minute(v, min_samples=50, z_threshold=3.0)
    devs = ws.push_minute(100.0, min_samples=50, z_threshold=3.0)
    fired = [d for d in devs if d.window == "1h"]
    assert len(fired) == 1
    d = fired[0]
    assert d.observed == 100.0
    assert d.z > 3.0
    assert d.mean > 0.0 and d.stddev > 0.0


def test_calm_value_does_not_fire() -> None:
    ws = WindowedStats()
    for v in [1.0] * 49 + [2.0]:
        ws.push_minute(v, min_samples=50, z_threshold=3.0)
    assert ws.push_minute(1.0, min_samples=50, z_threshold=3.0) == []


def test_constant_series_never_fires() -> None:
    # stddev == 0 → z undefined → guarded, not a crash or a fire.
    ws = WindowedStats()
    for _ in range(80):
        assert ws.push_minute(5.0, min_samples=50, z_threshold=3.0) == []


def test_negative_deviation_fires_too() -> None:
    # |z| ≥ threshold is two-sided per spec 12.1.
    ws = WindowedStats()
    for v in [10.0, 12.0] * 30:  # mean ~11, stddev ~1
        ws.push_minute(v, min_samples=50, z_threshold=3.0)
    devs = ws.push_minute(0.0, min_samples=50, z_threshold=3.0)
    assert any(d.window == "1h" and d.z < -3.0 for d in devs)


def test_1h_ring_capacity_rolls() -> None:
    ws = WindowedStats()
    for i in range(100):
        ws.push_minute(float(i), min_samples=999, z_threshold=3.0)
    assert len(ws.ring("1h")) == 60
    assert ws.ring("1h")[0] == 40.0  # oldest surviving minute


def test_24h_window_buckets_every_5_minutes() -> None:
    ws = WindowedStats()
    for _ in range(10):
        ws.push_minute(1.0, min_samples=999, z_threshold=3.0)
    # 10 minutes → two closed 5-minute buckets of sum 5.0 each.
    assert list(ws.ring("24h")) == [5.0, 5.0]
    # 7d bucket (15 min) has not closed yet.
    assert list(ws.ring("7d")) == []


def test_7d_window_buckets_every_15_minutes() -> None:
    ws = WindowedStats()
    for _ in range(30):
        ws.push_minute(2.0, min_samples=999, z_threshold=3.0)
    assert list(ws.ring("7d")) == [30.0, 30.0]


def test_serialize_round_trip() -> None:
    ws = WindowedStats()
    for i in range(23):  # leaves partial 5-min and 15-min accumulators
        ws.push_minute(float(i), min_samples=999, z_threshold=3.0)
    blobs = {name: ws.serialize_window(name) for name, _, _ in WINDOWS}
    restored = WindowedStats()
    for name, blob in blobs.items():
        assert restored.load_window(name, blob) is True
    assert list(restored.ring("1h")) == list(ws.ring("1h"))
    assert list(restored.ring("24h")) == list(ws.ring("24h"))
    assert list(restored.ring("7d")) == list(ws.ring("7d"))
    # Accumulators survive too: 3 more minutes close the next 5-min bucket
    # identically on both instances.
    for v in (1.0, 1.0, 1.0):
        ws.push_minute(v, min_samples=999, z_threshold=3.0)
        restored.push_minute(v, min_samples=999, z_threshold=3.0)
    assert list(restored.ring("24h")) == list(ws.ring("24h"))


def test_load_window_rejects_garbage() -> None:
    ws = WindowedStats()
    assert ws.load_window("1h", "not json") is False
    assert ws.load_window("1h", '{"wrong": "shape"}') is False
    assert ws.load_window("nope", "{}") is False
    # A failed load leaves the instance usable.
    assert ws.push_minute(1.0, min_samples=50, z_threshold=3.0) == []


def test_load_window_rejects_malformed_accum() -> None:
    ws = WindowedStats()
    assert ws.load_window("24h", '{"ring": [], "accum": []}') is False
    assert ws.load_window("24h", '{"ring": [1.0], "accum": [1.0]}') is False
