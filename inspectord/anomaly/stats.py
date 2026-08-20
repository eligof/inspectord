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
