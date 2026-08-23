"""Per-entity resource baselines + self-anomaly (spec §6; main-spec 12.4, 20.6).

``ResourceSampler`` samples CPU%% and RSS for the main PIDs of running systemd
services and for inspectord's own process. Unit→main-PID resolution is a
cgroup v2 file read (``<cgroup_root>/system.slice/<unit>/cgroup.procs``) — no
subprocess. Baselines reuse ``WindowedStats`` rings (the ``1h`` ring, 60
slots = a 30-min sliding baseline at the 30 s resource tick); firing is the
main-spec sustained rule — value > ``sustained_factor`` x baseline mean for
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
            try:
                return int(line.split()[1]) * 1024
            except (IndexError, ValueError):
                # Malformed/truncated VmRSS line: treat as absent — a parse
                # failure must never abort the sampling round.
                return None
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
        for raw in text.splitlines():
            line = raw.strip()
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
        for unit_name in units[: self._cfg.max_entities_per_metric]:
            pid = self.main_pid_of(unit_name)
            if pid is not None:
                targets.append((f"svc:{unit_name}", unit_name, pid))
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
        samples: list[tuple[str, float]] = []
        rss = _rss_bytes(status_text)
        if rss is not None:
            samples.append(("rss_bytes", float(rss)))
        # RSS above is independent of stat parsing: a (theoretical) stat parse
        # failure only skips the CPU sample, never the whole entity round.
        try:
            ticks: int | None = _cpu_ticks(stat_text)
        except (IndexError, ValueError):
            ticks = None
        if ticks is not None:
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
        for metric, value in samples:
            sig = self._observe(st, key, unit, metric, value)
            if sig is not None:
                out.append(sig)

    def _observe(
        self, st: _EntityState, key: str, unit: str | None, metric: str, value: float
    ) -> ResourceSignal | None:
        """Sustained rule against the 1h ring mean; evaluate-then-push so this
        sample never dilutes the baseline it is judged against. Fires exactly
        once, when the streak reaches sustained_ticks. While a pre-fire streak
        is accumulating the baseline is frozen (breaching samples are NOT
        pushed) — see the plan's amended design decision."""
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
        # Freeze the baseline while a pre-fire streak accumulates: if every
        # breaching sample were pushed, each one would raise the ring mean the
        # next sample is judged against, and the streak could never reach
        # sustained_ticks — plain evaluate-then-push dilutes the sustained
        # rule away. Every streak sample is judged against the frozen
        # pre-deviation baseline (the spec's literal "value > factor x
        # baseline mean for N consecutive samples"); once the streak resets
        # or fires, pushes resume so adaptation absorbs a persisting tail.
        if not 0 < st.streaks[metric] < self._cfg.sustained_ticks:
            # z_threshold=inf: reuse the ring machinery, never the z-path (spec §6).
            # The 24h/7d rings accumulate unused — only the 1h ring is ever read;
            # the negligible waste beats maintaining a parallel ring type.
            ws.push_minute(value, min_samples=self._cfg.min_samples, z_threshold=math.inf)
        return fired
