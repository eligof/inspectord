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
    (d / "stat").write_text(f"{pid} (fake (svc) x) S 1 1 1 0 -1 0 0 0 0 0 {ticks} 0 0 0\n")
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
    _proc, cgroup = roots
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
    proc, _cgroup = roots
    _write_proc(proc, 7, ticks=0, rss_kb=2048)
    s = _sampler(roots, self_pid=7)
    s.sample([], now=0.0)
    ring = s.debug_ring("self", "rss_bytes")
    assert ring is not None and ring[-1] == 2048 * 1024


def test_warmup_silence_then_sustained_fires_once(roots) -> None:
    proc, _cgroup = roots
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
    proc, _cgroup = roots
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
