"""Beaconing detection (spec §5, main-spec 12.3).

``BeaconTracker`` keeps, per ``(process.name, dst.ip, dst.port)``, a ring of
the last 32 inter-arrival times of outbound connections. Low-variance
periodic egress — count ≥ ``beacon_min_events``, mean interval within
[``beacon_min_interval_s``, ``beacon_max_interval_s``], coefficient of
variation < ``beacon_max_cv`` — is a classic C2 heartbeat shape and yields a
``BeaconHit`` for the detector to render into a signal event.

Pure and clock-injected: callers pass the event timestamp; no wall-clock, no
threads, no I/O. The detector thread owns the instance — not thread-safe.
"""

from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import dataclass
from datetime import datetime

from inspectord.config import AnomalyConfig

# Spec §5: "a ring of the last 32 inter-arrival times". Must stay >=
# beacon_min_events or the tracker can never fire.
_RING_SIZE = 32


@dataclass(frozen=True)
class BeaconHit:
    """One observation whose key currently satisfies the beacon criteria."""

    process_name: str
    dst_ip: str
    dst_port: int
    entity_key: str
    count: int
    mean_interval_s: float
    stddev_interval_s: float
    cv: float


class _KeyState:
    __slots__ = ("intervals", "last_ts")

    def __init__(self) -> None:
        self.last_ts: float | None = None
        self.intervals: deque[float] = deque(maxlen=_RING_SIZE)


def _entity_key(process_name: str, dst_ip: str, dst_port: int) -> str:
    # Opaque and deterministic; never parsed back. Same separator as
    # first_sighting._outbound_connection_key for greppability.
    return f"{process_name}->{dst_ip}:{dst_port}"


class BeaconTracker:
    """Inter-arrival state for all tracked connection keys."""

    def __init__(self, config: AnomalyConfig) -> None:
        self._cfg = config
        self._keys: dict[str, _KeyState] = {}
        # key -> last observation epoch seconds (LRU eviction order).
        self._last_seen: dict[str, float] = {}

    def observe(
        self, *, process_name: str, dst_ip: str, dst_port: int, ts: datetime
    ) -> BeaconHit | None:
        key = _entity_key(process_name, dst_ip, dst_port)
        state = self._keys.get(key)
        if state is None:
            self._admit(key)
            state = self._keys[key]
        epoch = ts.timestamp()
        if state.last_ts is not None:
            state.intervals.append(epoch - state.last_ts)
        state.last_ts = epoch
        self._last_seen[key] = epoch
        return self._evaluate(state, process_name, dst_ip, dst_port, key)

    def _evaluate(
        self, state: _KeyState, process_name: str, dst_ip: str, dst_port: int, key: str
    ) -> BeaconHit | None:
        n = len(state.intervals)
        if n < self._cfg.beacon_min_events:
            return None
        mean = sum(state.intervals) / n
        # Bounds before the cv division: a mean at or below zero (same-ts
        # bursts, clock skew) can never fire and must never divide.
        if mean <= 0.0:
            return None
        if not (self._cfg.beacon_min_interval_s <= mean <= self._cfg.beacon_max_interval_s):
            return None
        var = sum((x - mean) ** 2 for x in state.intervals) / n
        stddev = math.sqrt(var)
        cv = stddev / mean
        if cv >= self._cfg.beacon_max_cv:
            return None
        return BeaconHit(
            process_name=process_name,
            dst_ip=dst_ip,
            dst_port=dst_port,
            entity_key=key,
            count=n,
            mean_interval_s=mean,
            stddev_interval_s=stddev,
            cv=cv,
        )

    def checkpoint_rows(self) -> list[tuple[str, str, str, str]]:
        """Rows shaped for metric_baseline: (metric_kind, entity_key, window_name, blob)."""
        return [
            (
                "beacon",
                key,
                "beacon",
                json.dumps({"last_ts": state.last_ts, "intervals": list(state.intervals)}),
            )
            for key, state in self._keys.items()
        ]

    def load_row(self, entity_key: str, blob: str) -> bool:
        """Restore one key from a checkpoint blob. False (and no state change)
        on any parse or shape problem — reload must never fail."""
        try:
            raw = json.loads(blob)
            raw_last = raw["last_ts"]
            last_ts = None if raw_last is None else float(raw_last)
            intervals = [float(x) for x in raw["intervals"]]
        except (KeyError, TypeError, ValueError):
            return False
        self._admit(entity_key)
        state = self._keys[entity_key]
        # Deliberately do NOT seed last_ts for diffing: the gap between the
        # last pre-checkpoint observation and the first post-reload one
        # spans an unknown amount of daemon downtime, not real inter-arrival
        # time. Seeding it would inject a bogus interval into the ring on
        # the very next observe(). The persisted last_ts is kept only for
        # LRU eviction ordering below; the ring picks its anchor back up
        # cleanly on the next real observation, same as a brand-new key.
        state.last_ts = None
        state.intervals = deque(intervals[-_RING_SIZE:], maxlen=_RING_SIZE)
        self._last_seen[entity_key] = last_ts if last_ts is not None else float("-inf")
        return True

    def _admit(self, key: str) -> None:
        if key in self._keys:
            return
        if len(self._keys) >= self._cfg.max_entities_per_metric:
            victim = min(self._keys, key=lambda k: self._last_seen.get(k, float("-inf")))
            del self._keys[victim]
            self._last_seen.pop(victim, None)
        self._keys[key] = _KeyState()
