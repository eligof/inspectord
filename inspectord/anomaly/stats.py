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
from datetime import datetime

from inspectord.config import AnomalyConfig
from inspectord.log import get

log = get(__name__)

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
        except (KeyError, TypeError, ValueError, IndexError):
            return False
        capacity, _ = _WINDOW_BY_NAME[name]
        self._rings[name] = deque(ring[-capacity:], maxlen=capacity)
        if accum is not None:
            self._accum[name] = accum
        return True


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


# After a gap longer than this (daemon suspend/stopped), skip the whole span
# rather than zero-filling it: zero-filling would wipe the 1h/24h baselines
# and stall the tick thread. 180 (3h) bounds the normal catch-up work to a
# few seconds worst-case at full entity cap; rings resume where they left off.
_MAX_CATCHUP_MINUTES = 180


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
        if self._last_closed_minute is not None and minute <= self._last_closed_minute:
            # A late event lands in the oldest still-open minute rather than a
            # closed one no tick will ever visit: counted, slightly time-shifted.
            minute = self._last_closed_minute + 1
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
            # Daemon slept (suspend, downtime). Do not replay the span as
            # zeros — that wipes the 1h/24h baselines and stalls the tick
            # thread. Skip it entirely; rings resume where they left off.
            log.warning("anomaly engine skipping %d minutes of downtime", current - start)
            self._buckets = {
                (m, mk, ek): v for (m, mk, ek), v in self._buckets.items() if m >= current
            }
            start = current
            self._last_closed_minute = current - 1
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
                (metric_kind, entity_key, name, ws.serialize_window(name)) for name, _, _ in WINDOWS
            )
            entity = self._entities.get((metric_kind, entity_key))
            if entity:
                # Persist the rendering context too, so a signal that fires
                # between restart and the entity's first fresh observation
                # does not render context-less. Empty dict: no row, no noise.
                rows.append((metric_kind, entity_key, "entity", json.dumps(entity)))
        return rows

    def load_row(self, metric_kind: str, entity_key: str, window_name: str, blob: str) -> bool:
        key = (metric_kind, entity_key)
        if window_name == "entity":
            return self._load_entity_row(key, blob)
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

    def _load_entity_row(self, key: tuple[str, str], blob: str) -> bool:
        """Restore one entity dict from a checkpoint blob. False (and no
        state change) on any parse or shape problem — reload must never fail.
        Order-independent: works whether the key's window rows loaded first
        (dict replaces the empty admit-time one) or load later (the key is
        admitted here and its rings restore into it)."""
        try:
            entity = json.loads(blob)
        except (TypeError, ValueError):
            return False
        if not isinstance(entity, dict) or not all(isinstance(v, dict) for v in entity.values()):
            return False
        if key not in self._stats:
            self._admit(key, entity)
        else:
            self._entities[key] = entity
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
            self._buckets = {
                (m, mk, ek): v for (m, mk, ek), v in self._buckets.items() if (mk, ek) != victim
            }
        self._stats[key] = WindowedStats()
        self._entities[key] = entity
        self._last_active.setdefault(key, -1)
