# Anomaly detector PR3 — beaconing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land spec §5 (12.3 temporal-pattern beaconing): per-`(process.name, dst.ip, dst.port)` inter-arrival rings over outbound connections, low-variance-cadence detection, a `beacon_signature` signal event, and the `anomaly.beacon_signature` medium-severity starter rule.

**Architecture:** A pure, clock-injected `BeaconTracker` (`beacon.py`) keeps a 32-slot ring of inter-arrival seconds per tracked key. The existing `AnomalyDetector` drain feeds it every outbound-connection event; a qualifying observation returns a `BeaconHit`, which the tick renders into a `kind=signal` event (action `beacon_signature`) emitted through the same supervisor `_dispatch` callback PR2 uses. Beacon state checkpoints into the existing `metric_baseline` table with `window_name='beacon'`, riding the detector's full-table-rewrite checkpoint. No supervisor changes: the anomaly subscription already delivers outbound events.

**Tech Stack:** Python 3.12, pydantic, DuckDB, pytest. Pure Python.

**Commands** (repo root):
- Tests: `.venv/bin/python -m pytest <path> -v` · full: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- Lint: `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format inspectord tests`
- Types: `.venv/bin/mypy inspectord`

**Branch:** `anomaly-beacon`, cut from `main` (PR2 #142 is merged).

**Design references:** `docs/superpowers/specs/2026-08-20-anomaly-detector-design.md` §2, §5, §9; PR2 code in `inspectord/anomaly/`.

**Key design decisions baked into this plan** (already settled — do not relitigate):
- `BeaconTracker` is pure and clock-injected (`ts` param); only the detector thread touches wall-clock. All beacon unit tests run without threads or sleeps.
- Evaluation happens per observation (spec: "On each new connection it evaluates"), but the detector dedups hits **per drain**, keyed by tracker key (last hit wins) — one signal per beaconing key per tick, bounded event volume. Cross-tick repeats while a beacon persists are absorbed by the existing alert dedup, exactly like PR2's repeated statistical signals.
- Beacon checkpoint rows use `metric_kind='beacon'`, `entity_key=f"{proc}→{ip}:{port}"`, `window_name='beacon'`. The entity_key string is opaque — it is never parsed back; reload only needs it to be deterministic so the same live key maps onto its restored row. IPv6 colons in the key are therefore harmless.
- `AnomalyDetector.checkpoint()` already rewrites `metric_baseline` from scratch (DELETE + bulk INSERT); beacon rows simply join `checkpoint_rows()`'s list. Evicted beacon keys disappear for free; there is no separate delete pass. `load_checkpoints()` routes `window_name == 'beacon'` rows to the tracker and everything else to the engine; the existing corrupt-row delete path covers beacon rows unchanged.
- Degenerate cadences cannot fire by construction: the mean-interval bounds check (`beacon_min_interval_s ≤ mean ≤ beacon_max_interval_s`, with an extra `mean > 0` guard for pathological configs) runs **before** the cv division, so same-timestamp bursts (mean ≈ 0) and backwards clock skew (negative intervals dragging the mean down) are rejected without a ZeroDivisionError.
- Tracked-key cap reuses `max_entities_per_metric` with LRU eviction by last-observation time (spec §5 → §4.3). No new config: all beacon knobs (`beacon_min_events`, `beacon_min_interval_s`, `beacon_max_interval_s`, `beacon_max_cv`) landed in `AnomalyConfig` in PR1.
- The signal event uses a **distinct action** `beacon_signature` (not `metric_anomaly`) so the rule keys on `event.action` and never collides with the statistical rules. It carries both `process` and `destination` dicts; `baseline` holds `metric_kind='beacon'`, `entity_key`, `count`, `interval_mean_s`, `interval_stddev_s`, `cv`.
- Known nuance for the PR body: alert dedup keys on the primary entity (process), so two simultaneous beacons from the same process name to *different* destinations may dedup into one alert while the first is active. Signals for both are still persisted and huntable. Acceptable for a single-user host; note it, don't fix it here.

---

### Task 0: Branch

(This plan lands on `main` with the PR — commit it as the first commit of the branch.)

- [ ] **Step 1:** `git checkout main && git pull && git checkout -b anomaly-beacon`
- [ ] **Step 2:** `git add docs/superpowers/plans/2026-08-21-anomaly-beacon-pr3.md && git commit -m "docs(plan): anomaly detector PR3 — beaconing"`

---

### Task 1: `BeaconTracker` — inter-arrival rings, cadence evaluation, checkpoints

**Files:**
- Create: `inspectord/anomaly/beacon.py`
- Test: `tests/anomaly/test_beacon.py`

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_beacon.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'inspectord.anomaly.beacon'`.

- [ ] **Step 3: Implement**

`inspectord/anomaly/beacon.py`:

```python
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

# Spec §5: "a ring of the last 32 inter-arrival times".
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
    __slots__ = ("last_ts", "intervals")

    def __init__(self) -> None:
        self.last_ts: float | None = None
        self.intervals: deque[float] = deque(maxlen=_RING_SIZE)


def _entity_key(process_name: str, dst_ip: str, dst_port: int) -> str:
    # Opaque and deterministic; never parsed back (see plan design decisions).
    return f"{process_name}→{dst_ip}:{dst_port}"


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
        state.last_ts = last_ts
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
```

Implementer notes:
- `json.JSONDecodeError` subclasses `ValueError`; the except tuple covers it. A non-list `intervals` (e.g. a string) raises `TypeError`/`ValueError` in the comprehension — also covered. A JSON string like `"x"` for `last_ts` raises `ValueError` in `float()` — covered (third garbage case in the test).
- A `float("x")` on JSON string values inside `intervals` also lands in `ValueError`. Good.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly/test_beacon.py -v`
Expected: 13 PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/beacon.py tests/anomaly/test_beacon.py
git commit -m "feat(anomaly): BeaconTracker — inter-arrival rings, low-variance cadence detection"
```

---

### Task 2: Detector wiring — feed, emit, checkpoint routing

**Files:**
- Modify: `inspectord/anomaly/detector.py`
- Test: `tests/anomaly/test_detector.py` (append; all existing PR1/PR2 tests must keep passing unchanged)

- [ ] **Step 1: Write the failing tests** (append to `tests/anomaly/test_detector.py` — `T0`, `_conn_event`, `_stat_detector` already exist in the file's PR2 section and are reused as-is)

```python
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
    assert sig.baseline["entity_key"] == "curl→203.0.113.9:443"
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
    assert rows == [("beacon", "curl→203.0.113.9:443")]

    det2, router2, emitted2 = _stat_detector(db)
    det2.load_checkpoints()
    # 3 more on-cadence connections reach 12 intervals: fires without
    # restarting the warm-up.
    _cadence_events(router2, 3, start=T0 + timedelta(seconds=60.0 * 10))
    det2._tick(now=T0 + timedelta(minutes=13))
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
    rows = db.query(
        "SELECT count(*) FROM metric_baseline WHERE window_name = 'beacon'"
    ).fetchall()
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
        "INSERT INTO metric_baseline VALUES ('beacon', 'curl→x:1', 'beacon', 'garbage', now())"
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_detector.py -v`
Expected: the 6 new tests FAIL (no beacon signals emitted / `AttributeError: _beacon`); all existing tests still pass.

- [ ] **Step 3: Implement** — edit `inspectord/anomaly/detector.py`:

**3a.** Add import:

```python
from inspectord.anomaly.beacon import BeaconHit, BeaconTracker
```

**3b.** In `AnomalyDetector.__init__`, after `self._engine = MetricEngine(config)`:

```python
        self._beacon = BeaconTracker(config)
```

**3c.** Add a module-level signal builder next to `_signal_event`:

```python
def _beacon_event(hit: BeaconHit, *, now: datetime) -> Event:
    ev = build_event(
        module="anomaly_detector",
        action="beacon_signature",
        category=["anomaly"],
        type_=["info"],
        kind="signal",
        severity="info",
        ts=now,
        message=(
            f"{hit.process_name} connects to {hit.dst_ip}:{hit.dst_port} "
            f"every ~{hit.mean_interval_s:.0f}s (cv={hit.cv:.3f}, "
            f"n={hit.count}) — low-variance periodic egress"
        ),
        process={"name": hit.process_name},
        destination={"ip": hit.dst_ip, "port": hit.dst_port},
    )
    ev.baseline = {
        "metric_kind": "beacon",
        "entity_key": hit.entity_key,
        "count": hit.count,
        "interval_mean_s": round(hit.mean_interval_s, 1),
        "interval_stddev_s": round(hit.stddev_interval_s, 2),
        "cv": round(hit.cv, 3),
    }
    return ev
```

**3d.** Change `_drain` to also feed the beacon tracker and return per-key-deduped hits:

```python
    def _drain(self) -> dict[str, BeaconHit]:
        """Drain the subscription into the engine and beacon tracker.

        Returns beacon hits deduped per key (last observation wins), so one
        beaconing key yields at most one signal per tick regardless of how
        many buffered connections qualified during the drain.
        """
        hits: dict[str, BeaconHit] = {}
        if self._sub is None:
            return hits
        while True:
            try:
                ev = self._sub.get_nowait()
            except QueueEmpty:
                return hits
            for sample in extract_samples(ev):
                self._engine.ingest(sample, ts=ev.ts)
            hit = self._observe_beacon(ev)
            if hit is not None:
                hits[hit.entity_key] = hit

    def _observe_beacon(self, ev: Event) -> BeaconHit | None:
        if ev.action != "outbound_connection":
            return None
        name = (ev.process or {}).get("name")
        ip = (ev.destination or {}).get("ip")
        port = (ev.destination or {}).get("port")
        if not name or not ip or not isinstance(port, int):
            return None
        return self._beacon.observe(
            process_name=str(name), dst_ip=str(ip), dst_port=port, ts=ev.ts
        )
```

**3e.** In `_tick`, replace the `self._drain()` call inside the second `try` block:

```python
        try:
            beacon_hits = self._drain()
            for data in self._engine.tick(now=now):
                if self._emit is not None:
                    self._emit(_signal_event(data, now=now))
            if self._emit is not None:
                for hit in beacon_hits.values():
                    self._emit(_beacon_event(hit, now=now))
            if time.monotonic() - self._last_checkpoint >= self._cfg.checkpoint_interval_s:
                self.checkpoint()
        except Exception as exc:
            log.error("anomaly tick failed: %r", exc)
```

**3f.** In `checkpoint()`, include beacon rows in the rewrite — change:

```python
        rows = self._engine.checkpoint_rows()
```

to:

```python
        rows = self._engine.checkpoint_rows() + self._beacon.checkpoint_rows()
```

**3g.** In `load_checkpoints()`, route beacon rows — change the loop's first branch from:

```python
        for metric_kind, entity_key, window_name, blob in rows:
            if self._engine.load_row(str(metric_kind), str(entity_key), str(window_name), blob):
                loaded += 1
                continue
```

to:

```python
        for metric_kind, entity_key, window_name, blob in rows:
            if str(window_name) == "beacon":
                ok = self._beacon.load_row(str(entity_key), blob)
            else:
                ok = self._engine.load_row(
                    str(metric_kind), str(entity_key), str(window_name), blob
                )
            if ok:
                loaded += 1
                continue
```

(The corrupt-row warning + DELETE below the branch stays exactly as-is; it already keys on all three columns and covers beacon rows.)

Implementer notes:
- Update the module docstring's tick description to mention beacon observation (one sentence).
- The PR2 `checkpoint()` docstring explains the full-table rewrite; extend its last sentence to note beacon rows ride along.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly -v`
Expected: all pass (existing PR1/PR2 tests + Task 1's 13 + the 6 new).

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/detector.py tests/anomaly/test_detector.py
git commit -m "feat(anomaly): detector feeds BeaconTracker, emits beacon_signature signals, checkpoints beacon state"
```

---

### Task 3: `anomaly.beacon_signature` starter rule

**Files:**
- Create: `inspectord/rules/starter_pack/anomaly_beacon_signature.yaml`
- Test: `tests/rules/starter_pack/test_anomaly_beacon_rule.py`

- [ ] **Step 1: Write the failing tests**

```python
"""The anomaly.beacon_signature starter rule matches beacon signals only."""

from __future__ import annotations

from importlib.resources import files

import yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict

_FILENAME = "anomaly_beacon_signature.yaml"


def _rule():
    text = files("inspectord.rules.starter_pack").joinpath(_FILENAME).read_text(encoding="utf-8")
    return load_yaml_rule_from_dict(yaml.safe_load(text), source=_FILENAME)


def _beacon_signal():
    ev = build_event(
        module="anomaly_detector",
        action="beacon_signature",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        kind="signal",
        process={"name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
    )
    ev.baseline = {
        "metric_kind": "beacon",
        "entity_key": "curl→203.0.113.9:443",
        "count": 12,
        "interval_mean_s": 60.0,
        "interval_stddev_s": 1.2,
        "cv": 0.02,
    }
    return ev


def test_beacon_rule_fires_on_beacon_signal() -> None:
    rule = _rule()
    assert rule.severity == "medium"
    matches = evaluate_yaml_rule(rule, EvalContext(event=_beacon_signal()))
    assert len(matches) == 1
    assert matches[0].rule_id == "anomaly.beacon_signature"
    assert matches[0].category == "anomaly"


def test_beacon_rule_ignores_statistical_signals() -> None:
    ev = _beacon_signal()
    ev.action = "metric_anomaly"
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev)) == []


def test_beacon_rule_ignores_other_modules() -> None:
    ev = _beacon_signal()
    ev.module = "outbound_connection_tracker"
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev)) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_anomaly_beacon_rule.py -v`
Expected: FAIL — `FileNotFoundError` for the YAML resource.

- [ ] **Step 3: Implement**

`inspectord/rules/starter_pack/anomaly_beacon_signature.yaml` (mirror the header/field style of `anomaly_egress_volume_spike.yaml`):

```yaml
version: 1.0.0
id: anomaly.beacon_signature
name: "periodic outbound beacon"
severity: medium
category: anomaly
why: |
  The anomaly detector observed this process repeatedly connecting to the
  same destination on a near-perfect timer: at least 12 connections whose
  inter-arrival times have a coefficient of variation below 0.1, with a
  mean interval between 5 seconds and 1 hour. Human-driven and normal
  application traffic is bursty; malware command-and-control channels poll
  their server on a fixed heartbeat, which is exactly this low-variance
  periodic shape. A regular cadence to one destination is one of the
  strongest host-side C2 indicators, so it notifies at `medium`.
false_positives:
  - "Legitimate pollers beacon too: NTP/chrony, package-update checks, cloud-sync clients, monitoring agents, mail clients. Allowlist the process/destination pair if the destination is expected."
detect:
  any_of:
    - event.module == "anomaly_detector" AND event.action == "beacon_signature"
short: "beacon: {process.name} → {destination.ip}:{destination.port} every ~{baseline.interval_mean_s}s"
detail: "{process.name} has connected to {destination.ip}:{destination.port} {baseline.count} times at a near-constant interval of ~{baseline.interval_mean_s}s (stddev {baseline.interval_stddev_s}s, cv {baseline.cv}). Low-variance periodic egress to a single destination is a classic C2 beacon signature."
labels: [anomaly, beacon, network, c2]
```

The `why`/`detect` numbers describe the shipped defaults; if a reviewer objects that they can drift from config, that objection was considered — starter rules elsewhere in the pack quote default thresholds the same way.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_anomaly_beacon_rule.py -v`
Expected: 3 PASS. Then `.venv/bin/python -m pytest tests/rules -q` (loader sweep over the whole pack) — all pass.

- [ ] **Step 5: Commit**

```bash
git add inspectord/rules/starter_pack/anomaly_beacon_signature.yaml tests/rules/starter_pack/test_anomaly_beacon_rule.py
git commit -m "feat(rules): anomaly.beacon_signature — medium-severity C2 beacon starter rule"
```

---

### Task 4: Supervisor integration test + full gates

**Files:**
- Test: `tests/test_supervisor_anomaly.py` (append)

- [ ] **Step 1: Write the test** (append; `_quiet_cfg`, `Supervisor`, `build_event` imports already exist in the file)

```python
# --- PR3: beacon signal path ------------------------------------------------


def _beacon_signal_event():
    ev = build_event(
        module="anomaly_detector",
        action="beacon_signature",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        kind="signal",
        process={"name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
    )
    ev.baseline = {
        "metric_kind": "beacon",
        "entity_key": "curl→203.0.113.9:443",
        "count": 12,
        "interval_mean_s": 60.0,
        "interval_stddev_s": 1.2,
        "cv": 0.02,
    }
    return ev


def test_beacon_signal_becomes_alert(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        sup._inject_for_test(_beacon_signal_event())
        beacons = [a for a in alerts if a.rule.id == "anomaly.beacon_signature"]
        assert len(beacons) == 1
        assert beacons[0].severity.value == "medium"
    finally:
        sup.stop(timeout=10.0)
```

- [ ] **Step 2: Run it**

Run: `.venv/bin/python -m pytest tests/test_supervisor_anomaly.py -v`
Expected: PASS on first run with Tasks 1–3 in place — this one is an integration regression net riding generic plumbing, not a TDD driver. All pre-existing tests in the file must also pass.

- [ ] **Step 3: Full local gates**

```bash
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q
.venv/bin/ruff check inspectord tests
.venv/bin/ruff format --check inspectord tests
.venv/bin/mypy inspectord
```

Expected: all green. Fix anything that isn't (format with `.venv/bin/ruff format inspectord tests` if the check flags files).

- [ ] **Step 4: Commit**

```bash
git add tests/test_supervisor_anomaly.py
git commit -m "test(anomaly): supervisor-level beacon signal → alert integration test"
```

---

### Task 5: PR

- [ ] **Step 1:** Push: `git push -u origin anomaly-beacon`
- [ ] **Step 2:** `gh pr create` — title `feat(anomaly): beaconing detection (PR3)`; body summarizes: BeaconTracker (§5), detector wiring, `anomaly.beacon_signature` rule, checkpoint via `metric_baseline` `window_name='beacon'`. Include the dedup nuance from the design decisions (same-process multi-destination beacons may collapse into one alert while the first is active) and note cross-tick repeat signals are absorbed by alert dedup.
- [ ] **Step 3:** Wait for CI (`lint-and-test`, CodeQL, cargo-audit, dependency-review) → `gh pr merge --squash --delete-branch`.
