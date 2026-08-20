# Anomaly detector PR2 — statistical z-score engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land spec §4 (12.1 statistical anomaly): per-metric minute buckets folded into 1h/24h/7d ring windows, z-score threshold signals emitted through the supervisor dispatch path, checkpointed to `metric_baseline`, with four `anomaly.*` statistical starter rules.

**Architecture:** Pure, clock-injected aggregation core (`MetricEngine` + `WindowedStats` in `stats.py`; event→sample extraction in `metrics.py`) driven by the existing `AnomalyDetector` thread: each tick drains the detector's new router subscription, ingests samples, closes minute buckets, evaluates z-scores, and emits `kind=signal` events via a callback into `Supervisor._dispatch`, where declarative YAML rules turn them into alerts. Checkpoints serialize ring state per `(metric_kind, entity_key, window)` into the `metric_baseline` table (created in PR1).

**Tech Stack:** Python 3.12, pydantic, DuckDB, pytest. Pure Python.

**Commands** (repo root):
- Tests: `.venv/bin/python -m pytest <path> -v` · full: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- Lint: `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format inspectord tests`
- Types: `.venv/bin/mypy inspectord`

**Branch:** `anomaly-statistical`, cut from `main` (PR1 #141 is merged).

**Design references:** `docs/superpowers/specs/2026-08-20-anomaly-detector-design.md` §2, §4, §9; PR1 code in `inspectord/anomaly/`.

**Key design decisions baked into this plan** (already settled — do not relitigate):
- The engine is clock-injected (`ts`/`now` params); only the detector thread touches wall-clock. All statistics tests run without threads or sleeps.
- Rate metrics zero-fill: once an entity is tracked, every closed minute without activity pushes `0.0` — absence is signal for rates. Exception: after a gap larger than `_MAX_CATCHUP_MINUTES` (1440, i.e. one day — e.g. laptop suspend), the engine skips the span instead of pushing a day of zeros, preserving baselines at the cost of slight mean bias. Logged.
- Windows evaluate a closing bucket against the ring **before** appending it (the classic "compare against history, then admit" order), so a spike does not dilute the baseline it is compared to.
- Signals carry a stable entity dict (`process`/`user`/`file`) so the alert pipeline's `_primary_entity_for` produces sane dedup keys; without it, dedup would fall back to event-id and every minute of a sustained spike would be a fresh alert row.
- `egress_bytes_per_min` extraction is **dormant today**: outbound-connection events carry no byte counts yet. The metric, engine path, and rule all land now; samples flow the day a byte-counting collector exists. Say so in the PR body.
- `new_conn_per_min` and `file_writes_per_min` emit signals but get **no starter alert rule** in this PR (huntable via the events store; rules can come later once real baselines exist). Say so in the PR body.

---

### Task 0: Branch

(This plan lands on `main` with the PR — commit it as the first commit of the branch.)

- [ ] **Step 1:** `git checkout main && git pull && git checkout -b anomaly-statistical`
- [ ] **Step 2:** `git add docs/superpowers/plans/2026-08-20-anomaly-statistical-pr2.md && git commit -m "docs(plan): anomaly detector PR2 — statistical z-score engine"`

---

### Task 1: `WindowedStats` — rings, z-evaluation, serialization

**Files:**
- Create: `inspectord/anomaly/stats.py`
- Test: `tests/anomaly/test_windowed_stats.py`

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_windowed_stats.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'inspectord.anomaly.stats'`.

- [ ] **Step 3: Implement**

`inspectord/anomaly/stats.py` (this task adds the top half; Task 2 appends `MetricEngine` to the same file):

```python
"""Windowed rolling statistics for the anomaly detector (spec §4.2).

``WindowedStats`` holds, for one ``(metric_kind, entity_key)``, three ring
buffers of bucketed per-minute rates: 1 h of 1-minute buckets, 24 h of
5-minute buckets, 7 d of 15-minute buckets — a deliberate coarsening of
"sliding window" that bounds memory at ~1 020 floats per entity-metric.

A closing bucket is evaluated against its ring *before* being appended, so a
spike never dilutes the baseline it is judged against.
"""

from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import dataclass

# (name, capacity, width in minutes) — spec §4.2 table.
WINDOWS: tuple[tuple[str, int, int], ...] = (("1h", 60, 1), ("24h", 288, 5), ("7d", 672, 15))

_WINDOW_BY_NAME = {name: (capacity, width) for name, capacity, width in WINDOWS}

# Below this, a series is treated as constant: z is undefined, never fired.
_MIN_STDDEV = 1e-9


@dataclass(frozen=True)
class WindowDeviation:
    """One window whose just-closed bucket breached the z threshold."""

    window: str
    observed: float
    mean: float
    stddev: float
    z: float


def _evaluate(
    ring: deque[float], value: float, *, min_samples: int, z_threshold: float, window: str
) -> WindowDeviation | None:
    if len(ring) < min_samples:
        return None
    mean = sum(ring) / len(ring)
    var = sum((x - mean) ** 2 for x in ring) / len(ring)
    stddev = math.sqrt(var)
    if stddev < _MIN_STDDEV:
        return None
    z = (value - mean) / stddev
    if abs(z) < z_threshold:
        return None
    return WindowDeviation(window=window, observed=value, mean=mean, stddev=stddev, z=z)


class WindowedStats:
    """Ring state for one entity-metric. Not thread-safe; the engine owns it."""

    def __init__(self) -> None:
        self._rings: dict[str, deque[float]] = {
            name: deque(maxlen=capacity) for name, capacity, _ in WINDOWS
        }
        # Wider windows accumulate minute values until their bucket closes.
        self._accum: dict[str, tuple[float, int]] = {"24h": (0.0, 0), "7d": (0.0, 0)}

    def push_minute(
        self, value: float, *, min_samples: int, z_threshold: float
    ) -> list[WindowDeviation]:
        out: list[WindowDeviation] = []
        dev = _evaluate(
            self._rings["1h"], value, min_samples=min_samples, z_threshold=z_threshold, window="1h"
        )
        if dev is not None:
            out.append(dev)
        self._rings["1h"].append(value)
        for name in ("24h", "7d"):
            total, minutes = self._accum[name]
            total, minutes = total + value, minutes + 1
            _, width = _WINDOW_BY_NAME[name]
            if minutes >= width:
                dev = _evaluate(
                    self._rings[name],
                    total,
                    min_samples=min_samples,
                    z_threshold=z_threshold,
                    window=name,
                )
                if dev is not None:
                    out.append(dev)
                self._rings[name].append(total)
                total, minutes = 0.0, 0
            self._accum[name] = (total, minutes)
        return out

    def ring(self, name: str) -> deque[float]:
        return self._rings[name]

    def serialize_window(self, name: str) -> str:
        state: dict[str, object] = {"ring": list(self._rings[name])}
        if name in self._accum:
            total, minutes = self._accum[name]
            state["accum"] = [total, minutes]
        return json.dumps(state)

    def load_window(self, name: str, blob: str) -> bool:
        """Restore one window from a checkpoint blob. False (and no state
        change) on any parse or shape problem — reload must never fail."""
        if name not in self._rings:
            return False
        try:
            state = json.loads(blob)
            ring = [float(x) for x in state["ring"]]
            accum: tuple[float, int] | None = None
            if name in self._accum:
                raw = state.get("accum", [0.0, 0])
                accum = (float(raw[0]), int(raw[1]))
        except (KeyError, TypeError, ValueError):
            return False
        capacity, _ = _WINDOW_BY_NAME[name]
        self._rings[name] = deque(ring[-capacity:], maxlen=capacity)
        if accum is not None:
            self._accum[name] = accum
        return True
```

(`json.JSONDecodeError` subclasses `ValueError`, so the except tuple above covers it.)

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly/test_windowed_stats.py -v`
Expected: 11 PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/stats.py tests/anomaly/test_windowed_stats.py
git commit -m "feat(anomaly): WindowedStats — 1h/24h/7d rings, z evaluation, checkpoint blobs"
```

---

### Task 2: `MetricEngine` — buckets, zero-fill, LRU, checkpoints

**Files:**
- Modify: `inspectord/anomaly/stats.py` (append `MetricSample`, `SignalData`, `MetricEngine`; extend imports)
- Test: `tests/anomaly/test_metric_engine.py`

- [ ] **Step 1: Write the failing tests**

```python
"""MetricEngine unit tests (spec §4.1–4.4). Clock-injected — no threads."""

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_metric_engine.py -v`
Expected: FAIL — `ImportError: cannot import name 'MetricEngine'`.

- [ ] **Step 3: Implement** — append to `inspectord/anomaly/stats.py`; extend the module imports to:

```python
from datetime import datetime

from inspectord.config import AnomalyConfig
from inspectord.log import get

log = get(__name__)
```

then append:

```python
@dataclass(frozen=True)
class MetricSample:
    """One extracted contribution to a metric's current minute bucket."""

    metric_kind: str
    entity_key: str
    entity: dict[str, dict[str, object]]  # e.g. {"process": {"name": "curl"}}
    value: float


@dataclass(frozen=True)
class SignalData:
    """One threshold breach, ready to be rendered into a signal Event."""

    metric_kind: str
    entity_key: str
    entity: dict[str, dict[str, object]]
    window: str
    observed: float
    mean: float
    stddev: float
    z: float


# After a gap longer than this (daemon suspend/stopped), skip the span rather
# than pushing a day of zeros per entity: preserves baselines, slight mean bias.
_MAX_CATCHUP_MINUTES = 1440


def _minute_of(ts: datetime) -> int:
    return int(ts.timestamp()) // 60


class MetricEngine:
    """All tracked entity-metrics. Clock-injected; owned by the detector
    thread — not thread-safe on its own."""

    def __init__(self, config: AnomalyConfig) -> None:
        self._cfg = config
        # (metric_kind, entity_key) -> WindowedStats
        self._stats: dict[tuple[str, str], WindowedStats] = {}
        # Same key -> stable entity dict for signal rendering (first seen wins).
        self._entities: dict[tuple[str, str], dict[str, dict[str, object]]] = {}
        # Same key -> last minute with real activity (LRU eviction order).
        self._last_active: dict[tuple[str, str], int] = {}
        # Open minute buckets: (minute, metric_kind, entity_key) -> value.
        self._buckets: dict[tuple[int, str, str], float] = {}
        self._last_closed_minute: int | None = None
        # Evicted keys pending checkpoint-row deletion.
        self._evicted: list[tuple[str, str]] = []

    def ingest(self, sample: MetricSample, *, ts: datetime) -> None:
        key = (sample.metric_kind, sample.entity_key)
        if key not in self._stats:
            self._admit(key, sample.entity)
        elif not self._entities[key]:
            # Heal an entity restored from checkpoint (loaded with no dict).
            self._entities[key] = sample.entity
        minute = _minute_of(ts)
        self._last_active[key] = minute
        bucket = (minute, sample.metric_kind, sample.entity_key)
        self._buckets[bucket] = self._buckets.get(bucket, 0.0) + sample.value

    def tick(self, *, now: datetime) -> list[SignalData]:
        """Close every minute strictly before ``now``'s minute; zero-fill
        silent entities; return threshold breaches."""
        current = _minute_of(now)
        if self._last_closed_minute is None:
            # First tick: nothing is closed yet; start from the earliest open
            # bucket (or from `current` if there is none).
            open_minutes = [m for m, _, _ in self._buckets]
            self._last_closed_minute = min(open_minutes, default=current) - 1
        start = self._last_closed_minute + 1
        if current - start > _MAX_CATCHUP_MINUTES:
            skipped_to = current - _MAX_CATCHUP_MINUTES
            log.warning("anomaly engine skipping %d minutes of downtime", skipped_to - start)
            # Drop any buckets stranded in the skipped span.
            self._buckets = {
                (m, mk, ek): v for (m, mk, ek), v in self._buckets.items() if m >= skipped_to
            }
            start = skipped_to
        out: list[SignalData] = []
        for minute in range(start, current):
            for (metric_kind, entity_key), ws in self._stats.items():
                value = self._buckets.pop((minute, metric_kind, entity_key), 0.0)
                devs = ws.push_minute(
                    value,
                    min_samples=self._cfg.min_samples,
                    z_threshold=self._cfg.z_threshold,
                )
                key = (metric_kind, entity_key)
                out.extend(
                    SignalData(
                        metric_kind=metric_kind,
                        entity_key=entity_key,
                        entity=self._entities[key],
                        window=d.window,
                        observed=d.observed,
                        mean=d.mean,
                        stddev=d.stddev,
                        z=d.z,
                    )
                    for d in devs
                )
            self._last_closed_minute = minute
        return out

    def stats_for(self, metric_kind: str, entity_key: str) -> WindowedStats | None:
        return self._stats.get((metric_kind, entity_key))

    def drain_evicted(self) -> list[tuple[str, str]]:
        evicted, self._evicted = self._evicted, []
        return evicted

    def checkpoint_rows(self) -> list[tuple[str, str, str, str]]:
        rows: list[tuple[str, str, str, str]] = []
        for (metric_kind, entity_key), ws in self._stats.items():
            rows.extend(
                (metric_kind, entity_key, name, ws.serialize_window(name))
                for name, _, _ in WINDOWS
            )
        return rows

    def load_row(self, metric_kind: str, entity_key: str, window_name: str, blob: str) -> bool:
        key = (metric_kind, entity_key)
        created = key not in self._stats
        if created:
            self._admit(key, {})
        if not self._stats[key].load_window(window_name, blob):
            if created:
                del self._stats[key]
                self._entities.pop(key, None)
                self._last_active.pop(key, None)
            return False
        return True

    def _admit(self, key: tuple[str, str], entity: dict[str, dict[str, object]]) -> None:
        metric_kind = key[0]
        tracked = [k for k in self._stats if k[0] == metric_kind]
        if len(tracked) >= self._cfg.max_entities_per_metric:
            victim = min(tracked, key=lambda k: self._last_active.get(k, -1))
            del self._stats[victim]
            self._entities.pop(victim, None)
            self._last_active.pop(victim, None)
            self._evicted.append(victim)
        self._stats[key] = WindowedStats()
        self._entities[key] = entity
        self._last_active.setdefault(key, -1)
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly/test_metric_engine.py tests/anomaly/test_windowed_stats.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/stats.py tests/anomaly/test_metric_engine.py
git commit -m "feat(anomaly): MetricEngine — minute buckets, zero-fill, LRU cap, checkpoints"
```

---

### Task 3: `metrics.py` — event → sample extraction

**Files:**
- Create: `inspectord/anomaly/metrics.py`
- Test: `tests/anomaly/test_metrics.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Event → MetricSample extraction (spec §4.1 table)."""

from __future__ import annotations

from inspectord.anomaly.metrics import extract_samples
from inspectord.parsers.base import build_event


def _kinds(ev):
    return sorted(s.metric_kind for s in extract_samples(ev))


def test_process_event_feeds_events_per_min() -> None:
    ev = build_event(
        module="process_collector", action="process_start", category=["process"],
        type_=["start"], severity="info", process={"pid": 1, "name": "xz"},
    )
    samples = [s for s in extract_samples(ev) if s.metric_kind == "events_per_min"]
    assert len(samples) == 1
    s = samples[0]
    assert s.entity_key == "xz:process"
    assert s.entity == {"process": {"name": "xz"}}
    assert s.value == 1.0


def test_outbound_connection_feeds_conn_rate_and_events() -> None:
    ev = build_event(
        module="outbound_connection_tracker", action="outbound_connection",
        category=["network"], type_=["connection", "start"], severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
    )
    kinds = _kinds(ev)
    assert "new_conn_per_min" in kinds
    assert "events_per_min" in kinds
    assert "egress_bytes_per_min" not in kinds  # no byte count on the event


def test_egress_bytes_when_present() -> None:
    ev = build_event(
        module="outbound_connection_tracker", action="outbound_connection",
        category=["network"], type_=["connection", "start"], severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
        network={"transport": "tcp", "direction": "egress", "bytes": 4096},
    )
    egress = [s for s in extract_samples(ev) if s.metric_kind == "egress_bytes_per_min"]
    assert len(egress) == 1
    assert egress[0].value == 4096.0
    assert egress[0].entity_key == "curl"


def test_login_feeds_logins_per_min() -> None:
    ev = build_event(
        module="log_tailer", action="ssh_login_succeeded", category=["authentication"],
        type_=["start"], severity="info", outcome="success",
        user={"name": "eli"}, process={"name": "sshd", "pid": 4242},
        source={"ip": "198.51.100.7"},
    )
    logins = [s for s in extract_samples(ev) if s.metric_kind == "logins_per_min"]
    assert len(logins) == 1
    assert logins[0].entity_key == "eli"
    assert logins[0].entity == {"user": {"name": "eli"}}


def test_sudo_feeds_sudo_per_min() -> None:
    ev = build_event(
        module="log_tailer", action="sudo_invoked", category=["iam"],
        type_=["start"], severity="info", outcome="success", user={"name": "eli"},
    )
    sudo = [s for s in extract_samples(ev) if s.metric_kind == "sudo_per_min"]
    assert len(sudo) == 1
    assert sudo[0].entity_key == "eli"


def test_fim_write_feeds_file_writes_per_min_keyed_by_parent_dir() -> None:
    ev = build_event(
        module="fim_watcher", action="file_created", category=["file"],
        type_=["creation"], severity="info", file={"path": "/etc/cron.d/evil"},
    )
    writes = [s for s in extract_samples(ev) if s.metric_kind == "file_writes_per_min"]
    assert len(writes) == 1
    assert writes[0].entity_key == "/etc/cron.d"
    assert writes[0].entity == {"file": {"path": "/etc/cron.d"}}


def test_processless_event_yields_nothing() -> None:
    ev = build_event(
        module="healthcheck", action="tick", category=["host"], type_=["info"],
        severity="info",
    )
    assert extract_samples(ev) == []


def test_anomaly_detector_events_are_never_sampled() -> None:
    # Belt to the router filter's braces: the extractor itself refuses its
    # own module's signals.
    ev = build_event(
        module="anomaly_detector", action="metric_anomaly", category=["anomaly"],
        type_=["info"], severity="info", kind="signal",
        process={"name": "curl"},
    )
    assert extract_samples(ev) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_metrics.py -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.anomaly.metrics`.

- [ ] **Step 3: Implement**

`inspectord/anomaly/metrics.py`:

```python
"""Event → MetricSample extraction (spec §4.1).

Each enriched event contributes zero or more samples to the engine's current
minute buckets. Rates are per-minute counters (value 1.0 per occurrence);
egress is a byte sum and stays dormant until a collector emits
``network.bytes`` on outbound events.
"""

from __future__ import annotations

import posixpath

from inspectord.anomaly.stats import MetricSample
from inspectord.schemas.event import Event

# FIM actions that count as writes for the file_writes_per_min rate.
_FIM_WRITE_ACTIONS = ("file_created", "file_modified", "file_attributes_changed")


def extract_samples(ev: Event) -> list[MetricSample]:
    if ev.module == "anomaly_detector":
        # Never feed our own signals back into the baselines.
        return []
    out: list[MetricSample] = []
    proc_name = (ev.process or {}).get("name")
    if proc_name and ev.category:
        out.append(
            MetricSample(
                metric_kind="events_per_min",
                entity_key=f"{proc_name}:{ev.category[0]}",
                entity={"process": {"name": str(proc_name)}},
                value=1.0,
            )
        )
    if ev.action == "outbound_connection" and proc_name:
        out.append(
            MetricSample(
                metric_kind="new_conn_per_min",
                entity_key=str(proc_name),
                entity={"process": {"name": str(proc_name)}},
                value=1.0,
            )
        )
        raw_bytes = (ev.network or {}).get("bytes")
        if raw_bytes is not None:
            out.append(
                MetricSample(
                    metric_kind="egress_bytes_per_min",
                    entity_key=str(proc_name),
                    entity={"process": {"name": str(proc_name)}},
                    value=float(raw_bytes),
                )
            )
    user_name = (ev.user or {}).get("name")
    if ev.action == "ssh_login_succeeded" and user_name:
        out.append(
            MetricSample(
                metric_kind="logins_per_min",
                entity_key=str(user_name),
                entity={"user": {"name": str(user_name)}},
                value=1.0,
            )
        )
    if ev.action == "sudo_invoked" and user_name:
        out.append(
            MetricSample(
                metric_kind="sudo_per_min",
                entity_key=str(user_name),
                entity={"user": {"name": str(user_name)}},
                value=1.0,
            )
        )
    path = (ev.file or {}).get("path")
    if ev.module == "fim_watcher" and ev.action in _FIM_WRITE_ACTIONS and path:
        parent = posixpath.dirname(str(path))
        out.append(
            MetricSample(
                metric_kind="file_writes_per_min",
                entity_key=parent,
                entity={"file": {"path": parent}},
                value=1.0,
            )
        )
    return out
```

(If mypy complains about `float(raw_bytes)` on `object`, cast via `float(str(raw_bytes))`-style is wrong — use `isinstance(raw_bytes, (int, float))` as the guard instead of `is not None`.)

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly/test_metrics.py -v`
Expected: 8 PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/metrics.py tests/anomaly/test_metrics.py
git commit -m "feat(anomaly): metric extraction — six §4.1 rates from enriched events"
```

---

### Task 4: Detector integration — drain, engine tick, signal emission, checkpoints

**Files:**
- Modify: `inspectord/anomaly/detector.py`
- Test: `tests/anomaly/test_detector.py` (extend — existing PR1 tests must keep passing unchanged; the new `subscription`/`emit` kwargs default to `None`)

- [ ] **Step 1: Write the failing tests** (append to `tests/anomaly/test_detector.py`; add the new imports to the file's import block)

```python
# --- PR2: statistical engine integration -----------------------------------

from datetime import UTC, datetime, timedelta

from inspectord.router import DropPolicy, EventRouter
from inspectord.schemas.event import Event

T0 = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)


def _conn_event(ts: datetime, name: str = "curl") -> Event:
    return build_event(
        module="outbound_connection_tracker", action="outbound_connection",
        category=["network"], type_=["connection", "start"], severity="info",
        ts=ts, process={"pid": 2, "name": name},
        destination={"ip": "203.0.113.9", "port": 443},
    )


def _stat_detector(db, *, min_samples: int = 5, max_entities: int = 512):
    cfg = AnomalyConfig(
        tick_s=3600.0, min_samples=min_samples, max_entities_per_metric=max_entities
    )
    router = EventRouter()
    sub = router.subscribe(
        name="anomaly", queue_size=4096,
        drop_policy=DropPolicy.drop_oldest_non_critical,
        filter_fn=lambda ev: ev.module != "anomaly_detector",
    )
    emitted: list[Event] = []
    det = AnomalyDetector(
        db=db, tracker=FirstSightingTracker(), config=cfg,
        subscription=sub, emit=emitted.append,
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
    assert len(emitted) == 1
    sig = emitted[0]
    assert sig.kind.value == "signal"
    assert sig.module == "anomaly_detector"
    assert sig.action == "metric_anomaly"
    assert sig.category == ["anomaly"]
    assert sig.baseline is not None
    assert sig.baseline["metric_kind"] == "new_conn_per_min"
    assert sig.baseline["window"] == "1h"
    assert sig.baseline["deviation"] > 3.0
    assert sig.baseline["observed"] == 100.0
    assert sig.process == {"name": "curl"}
    db.close()


def test_own_signals_never_reenter_via_filter(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, router, emitted = _stat_detector(db)
    sig = build_event(
        module="anomaly_detector", action="metric_anomaly", category=["anomaly"],
        type_=["info"], severity="info", kind="signal",
        ts=T0, process={"name": "curl"},
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
        "INSERT INTO metric_baseline VALUES "
        "('new_conn_per_min', 'curl', '1h', 'garbage', now())"
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
        "SELECT DISTINCT entity_key FROM metric_baseline "
        "WHERE metric_kind = 'new_conn_per_min'"
    ).fetchall()
    assert rows == [("wget",)]
    db.close()
```

Heads-up: `_conn_event` also feeds `events_per_min` (`curl:network`), so eviction/count assertions filter by `metric_kind = 'new_conn_per_min'` — keep that filter.

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_detector.py -v`
Expected: new tests FAIL (`TypeError: unexpected keyword argument 'subscription'`); the 3 PR1 tests still pass.

- [ ] **Step 3: Implement** — rewrite `inspectord/anomaly/detector.py` as:

```python
"""Anomaly detector thread (spec 2026-08-20-anomaly-detector-design.md §2).

Owns the maintenance thread. Each tick: flush the first-sighting queue, drain
the router subscription into the metric engine, close minute buckets, emit a
``kind=signal`` event per threshold breach (re-injected into the supervisor's
dispatch path, where starter-pack ``anomaly.*`` rules turn them into alerts),
and checkpoint engine state to ``metric_baseline`` when due.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from queue import Empty as QueueEmpty
from typing import TYPE_CHECKING

from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.anomaly.metrics import extract_samples
from inspectord.anomaly.stats import MetricEngine, SignalData
from inspectord.config import AnomalyConfig
from inspectord.log import get
from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event
from inspectord.storage.db import Database

if TYPE_CHECKING:
    from inspectord.router import Subscription

log = get(__name__)


def _signal_event(data: SignalData, *, now: datetime) -> Event:
    ev = build_event(
        module="anomaly_detector",
        action="metric_anomaly",
        category=["anomaly"],
        type_=["info"],
        kind="signal",
        severity="info",
        ts=now,
        message=(
            f"{data.metric_kind} for {data.entity_key} deviates from baseline: "
            f"observed {data.observed:g} vs mean {data.mean:g} "
            f"(z={data.z:.1f}, {data.window} window)"
        ),
        **data.entity,  # exactly one of process= / user= / file=
    )
    ev.baseline = {
        "metric_kind": data.metric_kind,
        "entity_key": data.entity_key,
        "window": data.window,
        "observed": data.observed,
        "mean": data.mean,
        "stddev": data.stddev,
        "deviation": data.z,
    }
    return ev


class AnomalyDetector:
    def __init__(
        self,
        *,
        db: Database,
        tracker: FirstSightingTracker,
        config: AnomalyConfig,
        subscription: Subscription | None = None,
        emit: Callable[[Event], None] | None = None,
    ) -> None:
        self._db = db
        self._tracker = tracker
        self._cfg = config
        self._sub = subscription
        self._emit = emit
        self._engine = MetricEngine(config)
        self._last_checkpoint = time.monotonic()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="anomaly-detector", daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def load_checkpoints(self) -> int:
        """Restore engine state from metric_baseline; delete rows that fail to
        parse so a bad row cannot fail every startup forever. Never raises."""
        loaded = 0
        try:
            rows = self._db.query(
                "SELECT metric_kind, entity_key, window_name, state_json FROM metric_baseline"
            ).fetchall()
        except Exception as exc:
            log.warning("could not read metric_baseline checkpoints: %r", exc)
            return 0
        for metric_kind, entity_key, window_name, blob in rows:
            if self._engine.load_row(str(metric_kind), str(entity_key), str(window_name), blob):
                loaded += 1
                continue
            log.warning(
                "discarding corrupt metric_baseline row (%s, %s, %s)",
                metric_kind,
                entity_key,
                window_name,
            )
            try:
                self._db.execute(
                    "DELETE FROM metric_baseline "
                    "WHERE metric_kind = ? AND entity_key = ? AND window_name = ?",
                    [metric_kind, entity_key, window_name],
                )
            except Exception as exc:
                log.warning("could not delete corrupt checkpoint row: %r", exc)
        return loaded

    def checkpoint(self) -> None:
        """Upsert current engine state; drop rows for evicted entities."""
        for metric_kind, entity_key in self._engine.drain_evicted():
            self._db.execute(
                "DELETE FROM metric_baseline WHERE metric_kind = ? AND entity_key = ?",
                [metric_kind, entity_key],
            )
        for metric_kind, entity_key, window_name, blob in self._engine.checkpoint_rows():
            self._db.execute(
                "INSERT OR REPLACE INTO metric_baseline "
                "(metric_kind, entity_key, window_name, state_json, updated_at) "
                "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                [metric_kind, entity_key, window_name, blob],
            )
        self._last_checkpoint = time.monotonic()

    def _run(self) -> None:
        while not self._stop.wait(self._cfg.tick_s):
            self._tick(now=datetime.now(UTC))

    def _drain(self) -> None:
        if self._sub is None:
            return
        while True:
            try:
                ev = self._sub.get_nowait()
            except QueueEmpty:
                return
            for sample in extract_samples(ev):
                self._engine.ingest(sample, ts=ev.ts)

    def _tick(self, *, now: datetime | None = None) -> None:
        if now is None:
            now = datetime.now(UTC)
        try:
            self._tracker.flush(self._db)
        except Exception as exc:
            # One bad flush must never kill the thread; pending rows are gone,
            # and a re-sighting after restart is absorbed by dedup.
            log.error("first-sighting flush failed: %r", exc)
        try:
            self._drain()
            for data in self._engine.tick(now=now):
                if self._emit is not None:
                    self._emit(_signal_event(data, now=now))
            if time.monotonic() - self._last_checkpoint >= self._cfg.checkpoint_interval_s:
                self.checkpoint()
        except Exception as exc:
            log.error("anomaly tick failed: %r", exc)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        # Best-effort final flush + checkpoint so a clean shutdown loses nothing.
        try:
            self._tracker.flush(self._db)
        except Exception as exc:
            log.warning("final anomaly flush failed: %r", exc)
        try:
            self.checkpoint()
        except Exception as exc:
            log.warning("final anomaly checkpoint failed: %r", exc)
```

Implementer notes:
- `build_event` accepts `process=`, `user=`, `file=` kwargs (verify at `inspectord/parsers/base.py:31`); `**data.entity` expands to exactly one of them. It has NO `baseline` kwarg — hence the post-construction assignment.
- DuckDB supports `INSERT OR REPLACE` on tables with a PRIMARY KEY (migration 0010's PK covers the three key columns).
- PR1 `stop()` semantics extend, not change.
- The PR1 test `test_stop_performs_final_flush` may now also write checkpoint rows on stop — that test only asserts `first_seen`, so it stands.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly -v`
Expected: all pass (PR1's 17 + Tasks 1–3 + the 5 new detector tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/detector.py tests/anomaly/test_detector.py
git commit -m "feat(anomaly): detector drains the router, ticks the engine, emits signals, checkpoints"
```

---

### Task 5: Statistical starter rules

**Files:**
- Create: `inspectord/rules/starter_pack/anomaly_egress_volume_spike.yaml`
- Create: `inspectord/rules/starter_pack/anomaly_event_rate_spike.yaml`
- Create: `inspectord/rules/starter_pack/anomaly_sudo_rate_spike.yaml`
- Create: `inspectord/rules/starter_pack/anomaly_login_rate_spike.yaml`
- Test: `tests/rules/starter_pack/test_anomaly_statistical_rules.py`

Severities: egress + sudo = **medium** (notify: strong compromise signals once a baseline exists); event-rate + login-rate = **low** (log-only: noisy on a busy desktop). `new_conn_per_min` / `file_writes_per_min` signals deliberately have no starter rule yet.

- [ ] **Step 1: Write the failing tests**

```python
"""Statistical anomaly.* starter rules match metric_anomaly signals."""

from __future__ import annotations

from importlib.resources import files

import yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule(name: str):
    text = files("inspectord.rules.starter_pack").joinpath(name).read_text(encoding="utf-8")
    return load_yaml_rule_from_dict(yaml.safe_load(text), source=name)


def _signal(metric_kind: str, **entity):
    ev = build_event(
        module="anomaly_detector", action="metric_anomaly", category=["anomaly"],
        type_=["info"], severity="info", kind="signal", **entity,
    )
    ev.baseline = {
        "metric_kind": metric_kind,
        "entity_key": "x",
        "window": "1h",
        "observed": 100.0,
        "mean": 1.0,
        "stddev": 0.5,
        "deviation": 42.0,
    }
    return ev


CASES = [
    ("anomaly_egress_volume_spike.yaml", "anomaly.process_egress_volume_spike",
     "egress_bytes_per_min", "medium", {"process": {"name": "curl"}}),
    ("anomaly_event_rate_spike.yaml", "anomaly.process_event_rate_spike",
     "events_per_min", "low", {"process": {"name": "curl"}}),
    ("anomaly_sudo_rate_spike.yaml", "anomaly.sudo_rate_spike",
     "sudo_per_min", "medium", {"user": {"name": "eli"}}),
    ("anomaly_login_rate_spike.yaml", "anomaly.login_rate_spike",
     "logins_per_min", "low", {"user": {"name": "eli"}}),
]


def test_each_rule_fires_on_its_metric_only() -> None:
    for fname, rule_id, metric, severity, entity in CASES:
        rule = _rule(fname)
        assert rule.severity == severity, fname
        matches = evaluate_yaml_rule(rule, EvalContext(event=_signal(metric, **entity)))
        assert len(matches) == 1, fname
        assert matches[0].rule_id == rule_id
        assert matches[0].category == "anomaly"
        # Wrong metric on an otherwise identical signal: no match.
        other = "sudo_per_min" if metric != "sudo_per_min" else "events_per_min"
        assert not evaluate_yaml_rule(rule, EvalContext(event=_signal(other, **entity))), fname


def test_non_signal_event_with_stamped_metric_kind_does_not_fire() -> None:
    # A hostile or buggy worker cannot forge a statistical alert by writing
    # baseline.metric_kind: the module gate pins these rules to the detector.
    ev = build_event(
        module="log_tailer", action="metric_anomaly", category=["anomaly"],
        type_=["info"], severity="info", process={"name": "curl"},
    )
    ev.baseline = {"metric_kind": "sudo_per_min", "deviation": 99.0}
    for fname, *_ in CASES:
        assert not evaluate_yaml_rule(_rule(fname), EvalContext(event=ev)), fname
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_anomaly_statistical_rules.py -v`
Expected: FAIL — FileNotFoundError on the yamls.

- [ ] **Step 3: Write the four rules**

`anomaly_egress_volume_spike.yaml`:

```yaml
version: 1.0.0
id: anomaly.process_egress_volume_spike
name: "process egress volume spike"
severity: medium
category: anomaly
why: |
  The anomaly detector's rolling baseline says this process is sending far
  more bytes per minute than its history predicts (|z| >= 3 against the 1h,
  24h, or 7d window; the detector emits nothing until a window holds 50
  samples, so this cannot fire on a cold start). Sudden egress inflation
  from a process with a stable history is a classic exfiltration and
  cryptominer-pool signal, so it notifies at `medium`.

  NOTE: no collector currently emits byte counts on outbound events, so this
  rule is dormant until one does. It ships now so the pipeline is complete
  the day `network.bytes` appears.
false_positives:
  - "Backups, cloud sync, and package downloads legitimately spike egress; allowlist the process if it is expected to burst."
detect:
  any_of:
    - event.module == "anomaly_detector" AND event.action == "metric_anomaly" AND baseline.metric_kind == "egress_bytes_per_min"
short: "egress spike: {process.name} ({baseline.observed} B/min vs mean {baseline.mean})"
detail: "Egress volume for {process.name} deviates from its baseline: observed {baseline.observed} bytes/min vs mean {baseline.mean} (stddev {baseline.stddev}, z={baseline.deviation}, window {baseline.window})."
labels: [anomaly, statistical, network]
```

`anomaly_event_rate_spike.yaml`:

```yaml
version: 1.0.0
id: anomaly.process_event_rate_spike
name: "process event rate spike"
severity: low
category: anomaly
why: |
  This process is generating events (per category) at a rate far outside its
  rolling baseline. A compromised or runaway process gets noisy: file writes,
  process spawns, connections. But so does a compiler, a build, a package
  upgrade — which is why this is `low` and log-only. Treat it as a triage
  breadcrumb next to whatever else fired.
false_positives:
  - "Builds, backups, indexers, and package upgrades all burst legitimately."
  - "The baseline needs days of history before the 24h/7d windows mean much; early fires reflect a young baseline, not an attack."
detect:
  any_of:
    - event.module == "anomaly_detector" AND event.action == "metric_anomaly" AND baseline.metric_kind == "events_per_min"
short: "event-rate spike: {process.name} (z={baseline.deviation})"
detail: "Event rate for {baseline.entity_key} deviates from baseline: observed {baseline.observed}/min vs mean {baseline.mean} (z={baseline.deviation}, window {baseline.window})."
labels: [anomaly, statistical]
```

`anomaly_sudo_rate_spike.yaml`:

```yaml
version: 1.0.0
id: anomaly.sudo_rate_spike
name: "sudo rate spike"
severity: medium
category: anomaly
why: |
  This user is invoking sudo far more often than their rolling baseline
  predicts. Privilege-escalation attempts, credential-stuffing scripts, and
  post-compromise enumeration all look like sudden sudo bursts. On a
  single-user machine a genuine burst is rare enough to notify at `medium` —
  you will remember whether it was you.
false_positives:
  - "A long interactive admin session (system surgery, big install) is a legitimate burst."
  - "Configuration-management runs that sudo once per task."
detect:
  any_of:
    - event.module == "anomaly_detector" AND event.action == "metric_anomaly" AND baseline.metric_kind == "sudo_per_min"
short: "sudo rate spike for {user.name} (z={baseline.deviation})"
detail: "sudo invocation rate for {user.name} deviates from baseline: observed {baseline.observed}/min vs mean {baseline.mean} (z={baseline.deviation}, window {baseline.window})."
labels: [anomaly, statistical, iam]
```

`anomaly_login_rate_spike.yaml`:

```yaml
version: 1.0.0
id: anomaly.login_rate_spike
name: "SSH login rate spike"
severity: low
category: anomaly
why: |
  Successful SSH logins for this user are arriving faster than the rolling
  baseline predicts. A burst of *successful* logins can mean a scripted
  attacker with working credentials — but it can also be you, running a
  parallel deployment or a tmux resurrection. Failed-login floods are the
  brute-force signal and belong to the ssh brute-force rule; this rule
  watches the quieter successful side, at `low`, log-only.
false_positives:
  - "Parallel scp/rsync jobs, IDE remote sessions, and CI runners log in in bursts."
detect:
  any_of:
    - event.module == "anomaly_detector" AND event.action == "metric_anomaly" AND baseline.metric_kind == "logins_per_min"
short: "login rate spike for {user.name} (z={baseline.deviation})"
detail: "Successful SSH login rate for {user.name} deviates from baseline: observed {baseline.observed}/min vs mean {baseline.mean} (z={baseline.deviation}, window {baseline.window})."
labels: [anomaly, statistical, authentication]
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_anomaly_statistical_rules.py tests/rules -v`
Expected: new tests pass; whole `tests/rules` tree stays green.

- [ ] **Step 5: Commit**

```bash
git add inspectord/rules/starter_pack/anomaly_*_spike.yaml tests/rules/starter_pack/test_anomaly_statistical_rules.py
git commit -m "feat(rules): four anomaly.* statistical spike rules"
```

---

### Task 6: Supervisor wiring + end-to-end signal path

**Files:**
- Modify: `inspectord/supervisor.py` (two hunks: the `__init__` anomaly block ~line 178, the `start()` anomaly block ~line 200; no `_dispatch`/`stop()` changes)
- Test: `tests/test_supervisor_anomaly.py` (extend)

Wiring: the detector needs (a) a router subscription that excludes its own signals, (b) `emit=self._dispatch`, (c) `load_checkpoints()` at start. `stop()` already calls `detector.stop()`, which now also checkpoints.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_supervisor_anomaly.py`)

```python
# --- PR2: statistical signal path -------------------------------------------

from datetime import UTC, datetime

from inspectord.anomaly.stats import MetricSample


def _signal_event():
    ev = build_event(
        module="anomaly_detector", action="metric_anomaly", category=["anomaly"],
        type_=["info"], severity="info", kind="signal",
        user={"name": "eli"},
    )
    ev.baseline = {
        "metric_kind": "sudo_per_min",
        "entity_key": "eli",
        "window": "1h",
        "observed": 40.0,
        "mean": 0.5,
        "stddev": 0.7,
        "deviation": 56.4,
    }
    return ev


def test_signal_event_becomes_statistical_alert(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        sup._inject_for_test(_signal_event())
        spikes = [a for a in alerts if a.rule.id == "anomaly.sudo_rate_spike"]
        assert len(spikes) == 1
        assert spikes[0].severity.value == "medium"
    finally:
        sup.stop(timeout=10.0)


def test_detector_is_wired_to_router_and_dispatch(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        det = sup._anomaly_detector
        assert det is not None
        assert det._sub is not None
        assert det._emit is not None
        # The subscription filter drops the detector's own signals...
        assert det._sub.filter_fn is not None
        assert det._sub.filter_fn(_signal_event()) is False
        # ...but passes ordinary worker events.
        assert det._sub.filter_fn(_kmod_event()) is True
        # Published events reach the detector's queue.
        sup._inject_for_test(_kmod_event("snd_usb_audio"))
        drained = []
        while True:
            try:
                drained.append(det._sub.get_nowait())
            except Exception:
                break
        assert any(e.action == "kmod_loaded" for e in drained)
    finally:
        sup.stop(timeout=10.0)


def test_stop_checkpoints_engine_state(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    # Huge tick so the detector thread cannot race the direct engine poke.
    cfg = cfg.model_copy(
        update={"anomaly": cfg.anomaly.model_copy(update={"tick_s": 3600.0})}
    )
    sup = Supervisor(cfg)
    sup.start()
    try:
        det = sup._anomaly_detector
        assert det is not None
        det._engine.ingest(
            MetricSample(
                metric_kind="sudo_per_min", entity_key="eli",
                entity={"user": {"name": "eli"}}, value=1.0,
            ),
            ts=datetime.now(UTC),
        )
    finally:
        sup.stop(timeout=10.0)
    db = Database(cfg.storage.db_path)
    db.connect()
    rows = db.query(
        "SELECT count(*) FROM metric_baseline WHERE metric_kind = 'sudo_per_min'"
    ).fetchall()
    assert rows[0][0] == 3  # one row per window
    db.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_supervisor_anomaly.py -v`
Expected: the three new tests FAIL (`det._sub is None` / no alert); PR1's tests still pass.

- [ ] **Step 3: Wire the supervisor**

In `__init__`, replace the PR1 anomaly block with:

```python
        self._first_sighting: FirstSightingTracker | None = None
        self._anomaly_detector: AnomalyDetector | None = None
        if config.anomaly.enabled:
            self._first_sighting = FirstSightingTracker()
            # The detector must never aggregate its own signals (spec §2.1).
            anomaly_sub = self._router.subscribe(
                name="anomaly",
                queue_size=4096,
                drop_policy=DropPolicy.drop_oldest_non_critical,
                filter_fn=lambda ev: ev.module != "anomaly_detector",
            )
            self._anomaly_detector = AnomalyDetector(
                db=self._db,
                tracker=self._first_sighting,
                config=config.anomaly,
                subscription=anomaly_sub,
                emit=self._dispatch,
            )
```

Verify `self._router` is constructed earlier in `__init__` (it is) and `DropPolicy` is imported (it is, for the store subscription). If the router is constructed later, move this block below it.

In `start()`, extend the anomaly startup block to:

```python
        if self._first_sighting is not None:
            self._first_sighting.load(self._db)
        if self._anomaly_detector is not None:
            self._anomaly_detector.load_checkpoints()
            self._anomaly_detector.start()
```

`_dispatch` and `stop()` need no changes: signals emitted via `emit=self._dispatch` flow enrich→first-sighting→rules→publish like any event (the subscription filter keeps them out of the detector's own queue), and `stop()`'s existing `detector.stop()` now checkpoints.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_supervisor_anomaly.py tests/test_supervisor.py tests/anomaly -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add inspectord/supervisor.py tests/test_supervisor_anomaly.py
git commit -m "feat(supervisor): route events to the anomaly engine; signals re-enter dispatch"
```

---

### Task 7: Full gates + PR

- [ ] **Step 1:** `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` — exit 0.
- [ ] **Step 2:** `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format --check inspectord tests` — clean.
- [ ] **Step 3:** `.venv/bin/mypy inspectord` — clean.
- [ ] **Step 4:** Push + PR:

```bash
git push -u origin anomaly-statistical
gh pr create --title "feat(anomaly): statistical z-score engine (PR2)" --body "$(cat <<'EOF'
## Summary
- Spec §4 (12.1): `WindowedStats` (1h/24h/7d rings, evaluate-before-append z-scoring), `MetricEngine` (minute buckets, zero-fill for silent entities, gap-skip after suspend, LRU entity cap), `metrics.py` extraction for the six §4.1 rates
- `AnomalyDetector` now drains a dedicated router subscription (own signals filtered out), ticks the engine, emits `kind=signal` `metric_anomaly` events back through `Supervisor._dispatch`, and checkpoints to `metric_baseline` (periodic + on stop; corrupt rows discarded on load so restarts keep the warm-up)
- Four statistical starter rules: egress + sudo spikes at `medium`, event-rate + login-rate at `low` (log-only)

## Notes for review
- `egress_bytes_per_min` is dormant: no collector emits `network.bytes` yet; the metric, engine path, and rule land now so the pipeline is complete when one does.
- `new_conn_per_min` and `file_writes_per_min` emit signals with no starter alert rule yet — huntable in the events store; rules can follow once real baselines exist.
- Warm-up silence (§21.4) is structural: the engine emits nothing until a window holds `min_samples` (50) buckets.

## Test plan
- [x] Unit: WindowedStats (11), MetricEngine (9), extraction (8), detector integration (5), rules (2 sweeping all four)
- [x] Integration: signal → dispatch → rule → medium alert; detector wired to router with self-exclusion filter; stop() checkpoints
- [x] Local gates: pytest, ruff, mypy clean
- [ ] CI green

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 5:** CI green → `gh pr merge --squash --delete-branch`.

---

## Self-review notes

- **Spec coverage:** §4.1 metrics table → Task 3 (all six; egress conditional on `network.bytes`); §4.2 windows/threshold/evaluate-order → Task 1; §4.3 LRU cap → Task 2; §4.4 checkpoint/reload/corrupt-discard → Tasks 2+4; §2.1 signals-not-alerts + self-exclusion filter → Tasks 4+6; §2.2 warm-up → structural (min_samples gate, tested Tasks 1–2); §9 error handling (tick wrapper, checkpoint-failure tolerance) → Task 4; statistical rules from the §11 delivery table → Task 5.
- **Type consistency:** `MetricSample`/`SignalData` defined in Task 2, consumed in Tasks 3–4 and the Task 6 test; `AnomalyDetector` kwargs optional so PR1 call sites stand; `checkpoint()`/`load_checkpoints()` names consistent across Tasks 4 and 6.
- **Threading judgment call:** engine state is unlocked — the detector thread alone touches it in production (`_drain`, `tick`, `checkpoint` all run on it; the supervisor only constructs). The one test that pokes `_engine` from the test thread pins `tick_s=3600` so the detector thread cannot race it.
