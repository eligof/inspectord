# Anomaly detector PR4 — entity/resource baselines + self-anomaly — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land spec §6 (main-spec 12.4 + 20.6): sample CPU% and RSS for the main PIDs of running systemd services and for inspectord's own process, fire on the sustained rule (value > `sustained_factor` × baseline mean for `sustained_ticks` consecutive samples), emit `resource_deviation` / `monitor_health_anomaly` signals, and add the two starter rules. Last of the four anomaly PRs.

**Architecture:** A pure, clock-injected `ResourceSampler` (`entity_baseline.py`) owns per-entity `WindowedStats` baselines and streak counters; it reads `/proc/<pid>/stat` + `/proc/<pid>/status` under injectable roots and resolves unit→main-PID via cgroup v2 (`<cgroup_root>/system.slice/<unit>/cgroup.procs`) — no subprocess. The existing `AnomalyDetector` thread gains a dual-deadline loop (resource sampling every `resource_tick_s` = 30 s, existing tick every `tick_s` = 60 s) so all DB access stays on one thread and one handle. Signals re-inject through the same `emit=_dispatch` path; two new starter rules convert them into alerts. **No supervisor changes** — the detector constructs its own sampler.

**Tech Stack:** Python 3.12, pydantic, DuckDB, pytest. Pure Python.

**Commands** (repo root):
- Tests: `.venv/bin/python -m pytest <path> -v` · full: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- Lint: `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format inspectord tests`
- Types: `.venv/bin/mypy inspectord`

**Branch:** `anomaly-entity-baseline`, cut from `main` (PR3 #143 is merged).

**Design references:** `docs/superpowers/specs/2026-08-20-anomaly-detector-design.md` §2, §6, §9, §10; main spec §12.4, §20.6; PR1–3 code in `inspectord/anomaly/`.

**Key design decisions baked into this plan** (already settled — do not relitigate):
- **Unit→PID resolution is cgroup v2 file reads**, not `systemctl show` (no subprocess spawning every 30 s) and not a `service_state` schema change (the table has no PID column and altering it is services_monitor scope). Templated/nested-slice units whose cgroup dir isn't directly under `system.slice/` are silently skipped — an accepted coverage gap for a single-user host.
- **One thread, one DB handle.** `resource_tick_s` (30 s) is faster than `tick_s` (60 s), so `_run` becomes a dual-deadline loop waking at the nearer of the two deadlines. No second thread, no new locks, no second `Database` handle; the `service_state` read and everything else the detector does stays serialized on the detector thread.
- **`ResourceSampler` is pure and clock-injected**: `sample(units, now=<monotonic seconds>)` — the detector passes `time.monotonic()`; tests pass arithmetic. `proc_root`, `cgroup_root`, `self_pid`, and `clk_tck` are constructor-injectable; all unit tests run on tmp-dir fixtures without threads, sleeps, or a real `/proc`.
- **Baselines literally reuse `WindowedStats`** (spec: "feed the same `WindowedStats` machinery"): each sample is pushed via `push_minute(value, min_samples=…, z_threshold=math.inf)` (`inf` ⇒ the z-path never fires), and the sustained rule reads the `"1h"` ring (60-slot ⇒ 30 min sliding baseline at the 30 s tick) — mean only, no stddev. Evaluate-then-push, same as `MetricEngine`: a sample never dilutes the baseline it is judged against.
- **Warm-up:** no firing until the ring holds `min_samples` (50) values ⇒ ~25 min after start. **No checkpointing** of resource baselines: spec §7 fixes `window_name ∈ {'1h','24h','7d','beacon'}` with no resource entry, and a 25-min warm-up after daemon restart is acceptable. Note this in the PR body.
- **Sustained-fire semantics:** a streak counter per (entity, metric) increments when `value > sustained_factor × mean` (with `mean > 0` guard) and the ring is warm; resets on any non-breaching sample; the signal fires exactly once, when the streak *reaches* `sustained_ticks` — a persisting deviation does not re-fire every tick (baseline adaptation + alert dedup absorb the tail; a dip-and-re-sustain fires again).
- *(Amended during Task 1 implementation)* **Baseline freezes while a pre-fire streak is active**: `_observe` pushes the sample into the ring *unless* `0 < streak < sustained_ticks`. Plain evaluate-then-push is mathematically wrong for the sustained rule — each breaching push dilutes the mean the next sample is judged against, so with a full 60-ring the effective threshold is ~7.9× (not 5×), and with small warm-ups a streak can never complete at all. Freezing means every sample in the streak is compared against the *pre-deviation* baseline, which is exactly the spec's "value > 5× baseline mean for N consecutive samples". Once the streak breaks (reset) or fires (streak ≥ ticks), pushes resume, so baseline adaptation still absorbs a persisting tail; a transient spike now also never pollutes the baseline.
- **CPU% needs two samples**: per-entity anchor `(pid, utime+stime ticks, monotonic ts)`; `cpu_pct = Δticks / clk_tck / Δt × 100`. A PID change (service restart) or a vanished PID re-anchors — no CPU sample that round, baseline retained (spec §6). RSS (`VmRSS` from `/proc/<pid>/status`, kB→bytes) samples from the first read. `/proc/<pid>/stat` is parsed after the *last* `')'` — comm may contain spaces and parens.
- **Two signal actions, two rule classes** (spec §2.1/§6 feedback guard): services fire `action="resource_deviation"` → starter rule `anomaly.sustained_resource_deviation` (medium); inspectord itself fires `action="monitor_health_anomaly"` → starter rule id exactly `monitor_health_anomaly` (medium, category `process`, like `daemon.worker_restart_exhausted` — deliberately *not* under `anomaly.*` so self-anomaly never rides ordinary anomaly handling/allowlists). Both events keep `module="anomaly_detector"` so the existing subscription filter excludes them from the aggregators.
- **Entity bookkeeping is bounded by reality**, not an LRU: sampled units are capped at `max_entities_per_metric` per round (`units[:cap]`), and per-entity state lives for the daemon's lifetime (systemd unit namespace on one host is small; spec says retain baselines across PID churn).
- The sampler's per-round unit list comes from `SELECT unit FROM service_state WHERE active_state = 'active'` on the detector thread; a query failure logs a warning and samples only `self` that round (spec §9 spirit: never kill the thread).

---

### Task 0: Branch

(This plan lands on `main` with the PR — commit it as the first commit of the branch.)

- [ ] **Step 1:** `git checkout main && git pull && git checkout -b anomaly-entity-baseline`
- [ ] **Step 2:** `git add docs/superpowers/plans/2026-08-23-anomaly-entity-baseline-pr4.md && git commit -m "docs(plan): anomaly detector PR4 — entity/resource baselines"`

---

### Task 1: `ResourceSampler` — /proc reading, baselines, sustained rule

**Files:**
- Create: `inspectord/anomaly/entity_baseline.py`
- Test: `tests/anomaly/test_entity_baseline.py`

- [ ] **Step 1: Write the failing tests**

```python
"""ResourceSampler unit tests (spec §6). Fake /proc + cgroup fixtures, injected clock."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from inspectord.anomaly.entity_baseline import ResourceSampler, ResourceSignal
from inspectord.config import AnomalyConfig


def _cfg(**kw) -> AnomalyConfig:
    # Small warm-up so tests stay short; ring capacity is 60 so min_samples<=60.
    defaults = dict(min_samples=5, sustained_factor=5.0, sustained_ticks=3)
    defaults.update(kw)
    return AnomalyConfig(**defaults)


def _write_proc(root: Path, pid: int, *, ticks: int, rss_kb: int) -> None:
    d = root / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    # comm contains a space and parens on purpose — parsing must split after the LAST ')'.
    (d / "stat").write_text(
        f"{pid} (fake (svc) x) S 1 1 1 0 -1 0 0 0 0 0 {ticks} 0 0 0\n"
    )
    (d / "status").write_text(f"Name:\tfake\nVmRSS:\t{rss_kb} kB\nThreads:\t1\n")


def _write_cgroup(root: Path, unit: str, pid: int) -> None:
    d = root / "system.slice" / unit
    d.mkdir(parents=True, exist_ok=True)
    (d / "cgroup.procs").write_text(f"{pid}\n")


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    proc = tmp_path / "proc"
    cgroup = tmp_path / "cgroup"
    proc.mkdir()
    cgroup.mkdir()
    return proc, cgroup


def _sampler(
    roots: tuple[Path, Path], *, self_pid: int, cfg: AnomalyConfig | None = None
) -> ResourceSampler:
    proc, cgroup = roots
    return ResourceSampler(
        cfg or _cfg(),
        proc_root=str(proc),
        cgroup_root=str(cgroup),
        self_pid=self_pid,
        clk_tck=100,
    )


def test_main_pid_of_reads_first_pid(roots) -> None:
    proc, cgroup = roots
    _write_cgroup(cgroup, "foo.service", 42)
    s = _sampler(roots, self_pid=1)
    assert s.main_pid_of("foo.service") == 42


def test_main_pid_of_missing_unit_is_none(roots) -> None:
    s = _sampler(roots, self_pid=1)
    assert s.main_pid_of("nope.service") is None


def test_cpu_needs_two_samples_and_computes_percent(roots) -> None:
    proc, cgroup = roots
    _write_proc(proc, 42, ticks=0, rss_kb=1000)
    _write_cgroup(cgroup, "foo.service", 42)
    _write_proc(proc, 7, ticks=0, rss_kb=1000)  # self
    s = _sampler(roots, self_pid=7)
    s.sample(["foo.service"], now=0.0)  # anchor only — no cpu sample yet
    assert len(s.debug_ring("svc:foo.service", "cpu_pct") or []) == 0
    # 1500 ticks over 30 s at clk_tck=100 => 15 s of CPU => 50%
    _write_proc(proc, 42, ticks=1500, rss_kb=1000)
    s.sample(["foo.service"], now=30.0)
    ring = s.debug_ring("svc:foo.service", "cpu_pct")
    assert ring is not None and ring[-1] == pytest.approx(50.0)


def test_rss_samples_from_first_read(roots) -> None:
    proc, cgroup = roots
    _write_proc(proc, 7, ticks=0, rss_kb=2048)
    s = _sampler(roots, self_pid=7)
    s.sample([], now=0.0)
    ring = s.debug_ring("self", "rss_bytes")
    assert ring is not None and ring[-1] == 2048 * 1024


def test_warmup_silence_then_sustained_fires_once(roots) -> None:
    proc, cgroup = roots
    _write_proc(proc, 7, ticks=0, rss_kb=100)
    s = _sampler(roots, self_pid=7)
    fired: list[ResourceSignal] = []
    now = 0.0
    # Warm-up: min_samples=5 baseline samples at rss=100 kB, no signal possible.
    for _ in range(5):
        fired += s.sample([], now=now)
        now += 30.0
    assert fired == []
    # Sustained 10x deviation: streak of 3 (sustained_ticks) fires exactly once.
    _write_proc(proc, 7, ticks=0, rss_kb=1000)
    for _ in range(5):
        fired += s.sample([], now=now)
        now += 30.0
    rss_sigs = [f for f in fired if f.metric_kind == "rss_bytes"]
    assert len(rss_sigs) == 1
    sig = rss_sigs[0]
    assert sig.entity_key == "self" and sig.is_self
    assert sig.observed == 1000 * 1024
    assert sig.factor == pytest.approx(10.0, rel=0.2)


def test_transient_spike_does_not_fire(roots) -> None:
    proc, cgroup = roots
    _write_proc(proc, 7, ticks=0, rss_kb=100)
    s = _sampler(roots, self_pid=7)
    fired: list[ResourceSignal] = []
    now = 0.0
    for _ in range(6):
        fired += s.sample([], now=now)
        now += 30.0
    # 2 elevated samples (< sustained_ticks=3), then back to normal.
    _write_proc(proc, 7, ticks=0, rss_kb=1000)
    for _ in range(2):
        fired += s.sample([], now=now)
        now += 30.0
    _write_proc(proc, 7, ticks=0, rss_kb=100)
    for _ in range(4):
        fired += s.sample([], now=now)
        now += 30.0
    assert [f for f in fired if f.metric_kind == "rss_bytes"] == []


def test_vanished_pid_skipped_baseline_retained(roots) -> None:
    proc, cgroup = roots
    _write_proc(proc, 42, ticks=0, rss_kb=100)
    _write_cgroup(cgroup, "foo.service", 42)
    s = _sampler(roots, self_pid=999999)  # self also absent: exercises the same skip path
    now = 0.0
    for _ in range(3):
        s.sample(["foo.service"], now=now)
        now += 30.0
    before = list(s.debug_ring("svc:foo.service", "rss_bytes") or [])
    assert len(before) == 3
    # PID vanishes between cgroup listing and /proc read.
    shutil.rmtree(proc / "42")
    out = s.sample(["foo.service"], now=now)  # must not raise
    assert out == []
    after = list(s.debug_ring("svc:foo.service", "rss_bytes") or [])
    assert after == before  # baseline retained, nothing appended


def test_pid_change_reanchors_cpu(roots) -> None:
    proc, cgroup = roots
    _write_proc(proc, 42, ticks=0, rss_kb=100)
    _write_cgroup(cgroup, "foo.service", 42)
    _write_proc(proc, 7, ticks=0, rss_kb=100)
    s = _sampler(roots, self_pid=7)
    s.sample(["foo.service"], now=0.0)
    _write_proc(proc, 42, ticks=3000, rss_kb=100)
    s.sample(["foo.service"], now=30.0)
    assert len(s.debug_ring("svc:foo.service", "cpu_pct") or []) == 1
    # Service restarts: new PID with huge tick count must NOT produce a bogus cpu sample.
    _write_proc(proc, 43, ticks=999999, rss_kb=100)
    _write_cgroup(cgroup, "foo.service", 43)
    s.sample(["foo.service"], now=60.0)
    assert len(s.debug_ring("svc:foo.service", "cpu_pct") or []) == 1  # unchanged


def test_unit_list_capped(roots) -> None:
    proc, cgroup = roots
    cfg = _cfg(max_entities_per_metric=2)
    for i, pid in enumerate((41, 42, 43)):
        _write_proc(proc, pid, ticks=0, rss_kb=100)
        _write_cgroup(cgroup, f"u{i}.service", pid)
    _write_proc(proc, 7, ticks=0, rss_kb=100)
    s = _sampler(roots, self_pid=7, cfg=cfg)
    s.sample(["u0.service", "u1.service", "u2.service"], now=0.0)
    assert s.debug_ring("svc:u2.service", "rss_bytes") is None  # beyond cap: never sampled
    assert s.debug_ring("svc:u0.service", "rss_bytes") is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_entity_baseline.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'inspectord.anomaly.entity_baseline'`

- [ ] **Step 3: Write the implementation**

```python
"""Per-entity resource baselines + self-anomaly (spec §6; main-spec 12.4, 20.6).

``ResourceSampler`` samples CPU%% and RSS for the main PIDs of running systemd
services and for inspectord's own process. Unit→main-PID resolution is a
cgroup v2 file read (``<cgroup_root>/system.slice/<unit>/cgroup.procs``) — no
subprocess. Baselines reuse ``WindowedStats`` rings (the ``1h`` ring, 60
slots = a 30-min sliding baseline at the 30 s resource tick); firing is the
main-spec sustained rule — value > ``sustained_factor`` × baseline mean for
``sustained_ticks`` consecutive samples — never a z-score, and exactly once
per streak. Pure and clock-injected: the caller passes monotonic seconds.
"""

from __future__ import annotations

import math
import os
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from inspectord.anomaly.stats import WindowedStats
from inspectord.config import AnomalyConfig

_METRICS = ("cpu_pct", "rss_bytes")


@dataclass(frozen=True)
class ResourceSignal:
    """One sustained-deviation breach, ready to be rendered into a signal Event."""

    entity_key: str  # "svc:<unit>" | "self"
    unit: str | None  # None for self
    metric_kind: str  # "cpu_pct" | "rss_bytes"
    observed: float
    mean: float
    factor: float  # observed / mean
    is_self: bool


def _cpu_ticks(stat_text: str) -> int:
    """utime+stime from /proc/<pid>/stat. comm may contain spaces and parens,
    so fields are taken after the LAST ')'; utime/stime are fields 14/15
    (1-based) => indices 11/12 after the split."""
    rest = stat_text.rsplit(")", 1)[1].split()
    return int(rest[11]) + int(rest[12])


def _rss_bytes(status_text: str) -> int | None:
    for line in status_text.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return None


@dataclass
class _EntityState:
    pid: int | None = None
    prev_ticks: int | None = None
    prev_t: float | None = None
    baselines: dict[str, WindowedStats] = field(
        default_factory=lambda: {m: WindowedStats() for m in _METRICS}
    )
    streaks: dict[str, int] = field(default_factory=lambda: dict.fromkeys(_METRICS, 0))


class ResourceSampler:
    """Owned by the detector thread — not thread-safe on its own."""

    def __init__(
        self,
        config: AnomalyConfig,
        *,
        proc_root: str = "/proc",
        cgroup_root: str = "/sys/fs/cgroup",
        self_pid: int | None = None,
        clk_tck: int | None = None,
    ) -> None:
        self._cfg = config
        self._proc = Path(proc_root)
        self._cgroup = Path(cgroup_root)
        self._self_pid = self_pid if self_pid is not None else os.getpid()
        self._clk = clk_tck if clk_tck is not None else os.sysconf("SC_CLK_TCK")
        self._entities: dict[str, _EntityState] = {}

    def main_pid_of(self, unit: str) -> int | None:
        """First PID in the unit's cgroup.procs, or None (missing unit,
        templated/nested slice, or unreadable) — the caller skips silently."""
        try:
            text = (self._cgroup / "system.slice" / unit / "cgroup.procs").read_text()
        except OSError:
            return None
        for line in text.splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
        return None

    def sample(self, units: list[str], *, now: float) -> list[ResourceSignal]:
        """One resource tick: sample self + each resolvable unit's main PID.

        ``now`` is monotonic seconds (caller-injected). A PID that vanished
        between listing and reading /proc is skipped silently; its baseline is
        retained and resumes next round (spec §6).
        """
        out: list[ResourceSignal] = []
        targets: list[tuple[str, str | None, int]] = [("self", None, self._self_pid)]
        for unit in units[: self._cfg.max_entities_per_metric]:
            pid = self.main_pid_of(unit)
            if pid is not None:
                targets.append((f"svc:{unit}", unit, pid))
        for key, unit, pid in targets:
            self._sample_one(key, unit, pid, now, out)
        return out

    def debug_ring(self, entity_key: str, metric: str) -> deque[float] | None:
        """Test/introspection hook: the entity-metric's 1h baseline ring."""
        st = self._entities.get(entity_key)
        return None if st is None else st.baselines[metric].ring("1h")

    def _sample_one(
        self,
        key: str,
        unit: str | None,
        pid: int,
        now: float,
        out: list[ResourceSignal],
    ) -> None:
        st = self._entities.setdefault(key, _EntityState())
        try:
            stat_text = (self._proc / str(pid) / "stat").read_text()
            status_text = (self._proc / str(pid) / "status").read_text()
        except OSError:
            # Vanished mid-sampling (restart, listing/read race): skip
            # silently, retain baseline, force a CPU re-anchor next round.
            st.pid = None
            st.prev_ticks = None
            return
        try:
            ticks = _cpu_ticks(stat_text)
        except (IndexError, ValueError):
            return
        samples: list[tuple[str, float]] = []
        if (
            pid == st.pid
            and st.prev_ticks is not None
            and st.prev_t is not None
            and now > st.prev_t
        ):
            cpu_pct = (ticks - st.prev_ticks) / self._clk / (now - st.prev_t) * 100.0
            if cpu_pct >= 0:
                samples.append(("cpu_pct", cpu_pct))
        st.pid, st.prev_ticks, st.prev_t = pid, ticks, now
        rss = _rss_bytes(status_text)
        if rss is not None:
            samples.append(("rss_bytes", float(rss)))
        for metric, value in samples:
            sig = self._observe(st, key, unit, metric, value)
            if sig is not None:
                out.append(sig)

    def _observe(
        self, st: _EntityState, key: str, unit: str | None, metric: str, value: float
    ) -> ResourceSignal | None:
        """Sustained rule against the 1h ring mean; evaluate-then-push so this
        sample never dilutes the baseline it is judged against. Fires exactly
        once, when the streak reaches sustained_ticks."""
        ws = st.baselines[metric]
        ring = ws.ring("1h")
        fired: ResourceSignal | None = None
        if len(ring) >= self._cfg.min_samples:
            mean = sum(ring) / len(ring)
            if mean > 0 and value > self._cfg.sustained_factor * mean:
                st.streaks[metric] += 1
                if st.streaks[metric] == self._cfg.sustained_ticks:
                    fired = ResourceSignal(
                        entity_key=key,
                        unit=unit,
                        metric_kind=metric,
                        observed=value,
                        mean=mean,
                        factor=value / mean,
                        is_self=key == "self",
                    )
            else:
                st.streaks[metric] = 0
        # z_threshold=inf: reuse the ring machinery, never the z-path (spec §6).
        ws.push_minute(value, min_samples=self._cfg.min_samples, z_threshold=math.inf)
        return fired
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/anomaly/test_entity_baseline.py -v`
Expected: all PASS

- [ ] **Step 5: Lint + types**

Run: `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format inspectord tests && .venv/bin/mypy inspectord`
Expected: clean (ruff format may rewrite — rerun check after)

- [ ] **Step 6: Commit**

```bash
git add inspectord/anomaly/entity_baseline.py tests/anomaly/test_entity_baseline.py
git commit -m "feat(anomaly): ResourceSampler — /proc CPU/RSS baselines, sustained-deviation rule"
```

---

### Task 2: Detector wiring — dual-deadline loop, `_sample_resources`, signal events

**Files:**
- Modify: `inspectord/anomaly/detector.py`
- Test: `tests/anomaly/test_detector.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/anomaly/test_detector.py`; the file already has `_stat_detector(db, ...) -> (det, router, emitted)` and builds a migrated `Database` inline — reuse both, as below)

```python
# --- PR4: resource sampling path --------------------------------------------

from inspectord.anomaly.entity_baseline import ResourceSignal


def _resource_det(tmp_path: Path):
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    det, _router, emitted = _stat_detector(db)
    return det, emitted


class _StubSampler:
    """Records the unit list it was asked to sample; returns canned signals."""

    def __init__(self, signals):
        self.signals = signals
        self.calls: list[list[str]] = []

    def sample(self, units, *, now):
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


def test_sample_resources_emits_service_signal(tmp_path):
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


def test_sample_resources_self_uses_monitor_health_action(tmp_path):
    det, emitted = _resource_det(tmp_path)
    det._sampler = _StubSampler([_self_signal()])
    det._sample_resources(now=100.0)
    assert len(emitted) == 1
    assert emitted[0].action == "monitor_health_anomaly"
    assert emitted[0].service is None


def test_sample_resources_lists_active_services(tmp_path):
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


def test_sample_resources_survives_sampler_error(tmp_path):
    class _Boom:
        def sample(self, units, *, now):
            raise RuntimeError("boom")

    det, _emitted = _resource_det(tmp_path)
    det._sampler = _Boom()
    det._sample_resources(now=100.0)  # must not raise
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_detector.py -v -k "sample_resources"`
Expected: FAIL — `AttributeError: 'AnomalyDetector' object has no attribute '_sample_resources'`

- [ ] **Step 3: Implement in `detector.py`**

Add import:

```python
from inspectord.anomaly.entity_baseline import ResourceSampler, ResourceSignal
```

Add module-level event builder (next to `_signal_event` / `_beacon_event`):

```python
def _resource_event(sig: ResourceSignal, *, now: datetime) -> Event:
    # Self-anomaly gets its own action so the dedicated monitor_health_anomaly
    # rule (separate rule class, spec §6) is the only thing that matches it.
    action = "monitor_health_anomaly" if sig.is_self else "resource_deviation"
    subject = "inspectord" if sig.is_self else (sig.unit or sig.entity_key)
    if sig.metric_kind == "cpu_pct":
        detail = f"CPU {sig.observed:.1f}% vs baseline {sig.mean:.1f}%"
    else:
        mib = 1024 * 1024
        detail = f"RSS {sig.observed / mib:.0f} MiB vs baseline {sig.mean / mib:.0f} MiB"
    ev = build_event(
        module="anomaly_detector",
        action=action,
        category=["anomaly"],
        type_=["info"],
        kind="signal",
        severity="info",
        ts=now,
        message=(
            f"{subject}: sustained resource deviation — {detail} "
            f"({sig.factor:.1f}x baseline)"
        ),
        service={"name": sig.unit} if sig.unit else None,
        process={"name": "inspectord"} if sig.is_self else None,
    )
    ev.baseline = {
        "metric_kind": sig.metric_kind,
        "entity_key": sig.entity_key,
        "observed": round(sig.observed, 2),
        "mean": round(sig.mean, 2),
        "deviation": round(sig.factor, 2),
    }
    return ev
```

In `__init__`, after `self._beacon = BeaconTracker(config)`:

```python
        self._sampler: ResourceSampler = ResourceSampler(config)
```

Replace `_run` with the dual-deadline loop:

```python
    def _run(self) -> None:
        # Two cadences on one thread (one DB handle, no locks): resource
        # sampling every resource_tick_s (default 30 s), the main tick every
        # tick_s (default 60 s). Wake at the nearer deadline.
        next_tick = time.monotonic() + self._cfg.tick_s
        next_res = time.monotonic() + self._cfg.resource_tick_s
        while True:
            delay = min(next_tick, next_res) - time.monotonic()
            if self._stop.wait(max(delay, 0.0)):
                return
            now_m = time.monotonic()
            if now_m >= next_res:
                self._sample_resources(now=now_m)
                next_res = now_m + self._cfg.resource_tick_s
            if now_m >= next_tick:
                self._tick(now=datetime.now(UTC))
                next_tick = now_m + self._cfg.tick_s
```

Add `_sample_resources`:

```python
    def _sample_resources(self, *, now: float | None = None) -> None:
        """One resource tick (spec §6). Errors are logged, never raised — a
        bad round must not kill the detector thread (spec §9)."""
        if now is None:
            now = time.monotonic()
        units: list[str] = []
        try:
            rows = self._db.query(
                "SELECT unit FROM service_state WHERE active_state = 'active'"
            ).fetchall()
            units = [str(r[0]) for r in rows]
        except Exception as exc:
            log.warning("could not list services for resource sampling: %r", exc)
        try:
            for sig in self._sampler.sample(units, now=now):
                if self._emit is not None:
                    self._emit(_resource_event(sig, now=datetime.now(UTC)))
        except Exception as exc:
            log.error("resource sampling failed: %r", exc)
```

- [ ] **Step 4: Run the anomaly test suite**

Run: `.venv/bin/python -m pytest tests/anomaly/ -v`
Expected: all PASS (existing detector stop/start tests must still pass — the new loop still exits promptly when `_stop` is set)

- [ ] **Step 5: Lint + types**

Run: `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format inspectord tests && .venv/bin/mypy inspectord`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add inspectord/anomaly/detector.py tests/anomaly/test_detector.py
git commit -m "feat(anomaly): detector samples service + self resources on dual-deadline loop"
```

---

### Task 3: Starter rules + supervisor integration tests

**Files:**
- Create: `inspectord/rules/starter_pack/anomaly_sustained_resource_deviation.yaml`
- Create: `inspectord/rules/starter_pack/monitor_health_anomaly.yaml`
- Test: `tests/test_supervisor_anomaly.py` (append)

- [ ] **Step 1: Write the failing tests** (append; mirror the PR3 beacon block at the end of the file — copy its supervisor construction, alert-capture listener, and start/stop teardown verbatim, changing only the injected event and assertions)

```python
# --- PR4: resource-deviation signal path -------------------------------------


def _resource_signal_event(action: str, *, service: dict | None):
    ev = build_event(  # same builder style as _beacon_signal_event above
        module="anomaly_detector",
        action=action,
        category=["anomaly"],
        type_=["info"],
        kind="signal",
        severity="info",
        service=service,
        process={"name": "inspectord"} if service is None else None,
        message="test resource signal",
    )
    ev.baseline = {
        "metric_kind": "cpu_pct",
        "entity_key": "svc:foo.service" if service else "self",
        "observed": 80.0,
        "mean": 10.0,
        "deviation": 8.0,
    }
    return ev


def test_resource_deviation_signal_becomes_alert(tmp_path: Path) -> None:
    # supervisor harness copied from test_beacon_signal_becomes_alert
    sup._inject_for_test(
        _resource_signal_event("resource_deviation", service={"name": "foo.service"})
    )
    hits = [a for a in alerts if a.rule.id == "anomaly.sustained_resource_deviation"]
    assert len(hits) == 1
    assert hits[0].severity.value == "medium"
    assert "foo.service" in hits[0].rendered["short"]


def test_monitor_health_signal_uses_dedicated_rule(tmp_path: Path) -> None:
    # supervisor harness copied from test_beacon_signal_becomes_alert
    sup._inject_for_test(_resource_signal_event("monitor_health_anomaly", service=None))
    hits = [a for a in alerts if a.rule.id == "monitor_health_anomaly"]
    assert len(hits) == 1
    assert hits[0].severity.value == "medium"
    # separate rule class (spec §6): never under anomaly.*
    assert not hits[0].rule.id.startswith("anomaly.")
```

(The two test bodies above elide only the supervisor harness lines — the implementer copies them from `test_beacon_signal_becomes_alert` in the same file; every assertion is as written.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_supervisor_anomaly.py -v -k "resource_deviation or monitor_health"`
Expected: FAIL — 0 matching alerts (rules don't exist yet)

- [ ] **Step 3: Add the two rules**

`inspectord/rules/starter_pack/anomaly_sustained_resource_deviation.yaml`:

```yaml
version: 1.0.0
id: anomaly.sustained_resource_deviation
name: "sustained service resource deviation"
severity: medium
category: anomaly
why: |
  The anomaly detector sampled this service's main process every 30 seconds
  and its CPU or memory stayed above 5x its own recent baseline for six
  consecutive samples (about three minutes). A brief spike never fires this
  rule — only a sustained shift does. A long-lived service that suddenly and
  persistently works this much harder than its own history is the classic
  host-side shape of a cryptominer payload, a runaway loop after compromise,
  or data staging — main-spec §12.4 tracks it for exactly that reason, so it
  notifies at `medium`.
false_positives:
  - "Legitimate load shifts: a backup or indexing job kicking in, a database compaction, a service legitimately handling a burst. If the unit is expected to work in bursts of minutes, allowlist it."
  - "A baseline learned during an idle period (e.g. right after boot) can make the first period of normal load look like a deviation."
detect:
  any_of:
    - event.module == "anomaly_detector" AND event.action == "resource_deviation"
short: "resource anomaly: {service.name} {baseline.metric_kind} at {baseline.deviation}x baseline"
detail: "{service.name} sustained {baseline.metric_kind} = {baseline.observed} against its own baseline mean of {baseline.mean} ({baseline.deviation}x) for the configured sustained window. Persistent deviation from a service's own history is a cryptominer/runaway-process signal."
labels: [anomaly, resource, baseline]
```

`inspectord/rules/starter_pack/monitor_health_anomaly.yaml`:

```yaml
version: 1.0.0
id: monitor_health_anomaly
name: "inspectord self-anomaly"
severity: medium
category: process
why: |
  inspectord tracks its own CPU and memory as a baselined entity (main-spec
  §20.6) and this fired because the monitor itself has been running above 5x
  its own baseline for several consecutive samples. That catches three things
  worth knowing about: a leak or runaway loop in inspectord itself (a
  monitoring bug you want surfaced, not hidden), a misbehaving collector
  flooding the pipeline, or an attacker trying to exhaust or degrade the
  monitor to blind it. It uses its own dedicated rule id — deliberately
  outside the anomaly.* class — so tuning or allowlisting ordinary anomaly
  rules can never silence the monitor's own health signal.
false_positives:
  - "A genuinely busy period for the monitor: a huge event burst (package upgrade, log storm) legitimately raises inspectord's CPU for minutes."
  - "A baseline learned while the host was idle makes the first busy period look anomalous."
detect:
  any_of:
    - event.module == "anomaly_detector" AND event.action == "monitor_health_anomaly"
short: "inspectord self-anomaly: {baseline.metric_kind} at {baseline.deviation}x baseline"
detail: "inspectord's own {baseline.metric_kind} sustained {baseline.observed} against its baseline mean of {baseline.mean} ({baseline.deviation}x). Possible leak, runaway collector, or attempted resource exhaustion of the monitor."
labels: [daemon, health, anomaly, self]
```

- [ ] **Step 4: Run the integration tests**

Run: `.venv/bin/python -m pytest tests/test_supervisor_anomaly.py -v`
Expected: all PASS (old + new)

- [ ] **Step 5: Full gates**

Run: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q && .venv/bin/ruff check inspectord tests && .venv/bin/ruff format --check inspectord tests && .venv/bin/mypy inspectord`
Expected: all clean

- [ ] **Step 6: Commit**

```bash
git add inspectord/rules/starter_pack/anomaly_sustained_resource_deviation.yaml \
        inspectord/rules/starter_pack/monitor_health_anomaly.yaml \
        tests/test_supervisor_anomaly.py
git commit -m "feat(rules): sustained resource deviation + monitor_health_anomaly starter rules"
```

---

### Task 4: PR

- [ ] **Step 1:** `git push -u origin anomaly-entity-baseline`
- [ ] **Step 2:** `gh pr create` — title `feat(anomaly): entity/resource baselines + self-anomaly (PR4)`; body covers: spec §6 mapping, cgroup-v2 PID resolution decision (and the templated-unit coverage gap), single-thread dual-deadline design, no-checkpoint/25-min-warm-up note, sustained-fire-once semantics.
- [ ] **Step 3:** Wait for CI (`lint-and-test`, CodeQL, cargo-audit, dependency-review) — all green.
- [ ] **Step 4:** `gh pr merge --squash --delete-branch`
