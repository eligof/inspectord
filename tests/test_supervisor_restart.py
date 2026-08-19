"""Supervisor worker-restart tests (spec section 3.2).

A crashed worker must be restarted with exponential backoff, and a worker that
crash-loops must eventually be given up on *loudly* -- silence there is a
monitoring blind spot.

Everything here drives a real Supervisor with real child processes; the child
modules are written into tmp_path and reached via PYTHONPATH so `python -m
<name>` finds them. The thresholds are shrunk to milliseconds via constructor
overrides so the suite never waits real seconds.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from inspectord.config import WorkerSpec, dev_config
from inspectord.supervisor import (
    RESTART_BASE_DELAY_S,
    RESTART_MAX_DELAY_S,
    Supervisor,
    backoff_delay,
)


def test_backoff_doubles_from_the_base_delay() -> None:
    assert backoff_delay(1) == 1.0
    assert backoff_delay(2) == 2.0
    assert backoff_delay(3) == 4.0
    assert backoff_delay(4) == 8.0
    assert backoff_delay(5) == 16.0
    assert backoff_delay(6) == 32.0


def test_backoff_is_capped() -> None:
    assert backoff_delay(7) == 60.0
    assert backoff_delay(8) == 60.0
    assert backoff_delay(50) == 60.0


def test_backoff_defaults_match_the_module_constants() -> None:
    assert RESTART_BASE_DELAY_S == 1.0
    assert RESTART_MAX_DELAY_S == 60.0


def test_backoff_first_attempt_is_never_below_the_base() -> None:
    # Defensive: attempt numbers are 1-based; a 0 must not yield a half delay.
    assert backoff_delay(0) == 1.0
    assert backoff_delay(-3) == 1.0


def test_backoff_honours_custom_base_and_cap() -> None:
    assert backoff_delay(1, base=0.01, cap=0.05) == 0.01
    assert backoff_delay(2, base=0.01, cap=0.05) == 0.02
    assert backoff_delay(4, base=0.01, cap=0.05) == 0.05


# --------------------------------------------------------------------------
# Child-process test rig
# --------------------------------------------------------------------------

# Reads the config line the supervisor writes to stdin, then exits with code 3.
_DIES_SRC = """
import sys
sys.stdin.readline()
sys.exit(3)
"""

# Dies by SIGKILL, so the supervisor sees a negative returncode.
_SIGKILLS_SRC = """
import os
import signal
import sys
sys.stdin.readline()
os.kill(os.getpid(), signal.SIGKILL)
"""

# Lives for LIFETIME_S, then exits with code 3.
_LIVES_THEN_DIES_SRC = """
import sys
import time
sys.stdin.readline()
time.sleep({lifetime})
sys.exit(3)
"""

# Never exits on its own; the supervisor terminates it.
_LIVES_SRC = """
import sys
import time
sys.stdin.readline()
time.sleep(3600)
"""


def _install_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, src: str) -> str:
    """Write a throwaway worker module and make `python -m <name>` find it."""
    (tmp_path / f"{name}.py").write_text(src, encoding="utf-8")
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))
    return name


def _supervisor(tmp_path: Path, module: str, **kwargs: Any) -> Supervisor:
    cfg = dev_config(base=tmp_path)
    cfg.workers = [WorkerSpec(name="flaky", module=module, config={})]
    params: dict[str, Any] = {
        "poll_interval_s": 0.02,
        "restart_base_delay_s": 0.01,
        "restart_max_delay_s": 0.05,
        "restart_healthy_after_s": 3600.0,
        "restart_max_attempts": 8,
    }
    params.update(kwargs)
    return Supervisor(cfg, **params)


def _wait_for(predicate: Any, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class _Collector:
    """Collects supervisor events off the router's store subscription."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def __call__(self, ev: Any) -> None:
        if getattr(ev, "module", "") == "supervisor":
            self.events.append(ev)

    def actions(self, action: str) -> list[Any]:
        return [ev for ev in self.events if ev.action == action]


def test_dead_worker_is_restarted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_dies", _DIES_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        first_pid = sup._procs[0].proc.pid
        assert _wait_for(lambda: sup._procs[0].proc.pid != first_pid), (
            "supervisor never restarted the dead worker"
        )
        # Exactly one _WorkerProc per spec -- no stale corpse left behind.
        assert len(sup._procs) == 1
        assert sup._procs[0].spec.name == "flaky"
        assert sup._procs[0].restarts >= 1
    finally:
        sup.stop(timeout=5.0)


def test_restart_does_not_leak_reader_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_dies2", _DIES_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        first = sup._procs[0]
        old_threads = list(first.threads)
        assert _wait_for(lambda: sup._procs[0] is not first)
        assert all(not t.is_alive() for t in old_threads), "old reader threads outlived the child"
        new = sup._procs[0]
        assert len(new.threads) == 2
        assert all(t not in old_threads for t in new.threads)
    finally:
        sup.stop(timeout=5.0)


def test_restarts_are_exhausted_and_the_worker_is_left_dead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_loop", _DIES_SRC)
    sup = _supervisor(tmp_path, mod, restart_max_attempts=3)
    collector = _Collector()
    sup.attach_listener(collector)
    sup.start()
    try:
        assert _wait_for(lambda: collector.actions("worker_restart_exhausted")), (
            "supervisor never gave up on the crash-looping worker"
        )
        restarts_at_exhaustion = len(collector.actions("worker_restarted"))
        assert restarts_at_exhaustion == 3
        # Give the monitor plenty of ticks to (wrongly) restart it again.
        time.sleep(0.5)
        assert len(collector.actions("worker_restarted")) == 3
        assert len(collector.actions("worker_restart_exhausted")) == 1
        assert sup._procs[0].exhausted is True
        assert sup._procs[0].proc.poll() is not None
    finally:
        sup.stop(timeout=5.0)


def test_supervisor_events_carry_the_documented_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_fields", _DIES_SRC)
    sup = _supervisor(tmp_path, mod, restart_max_attempts=2)
    collector = _Collector()
    sup.attach_listener(collector)
    sup.start()
    try:
        assert _wait_for(lambda: collector.actions("worker_restart_exhausted"))

        died = collector.actions("worker_died")[0]
        assert died.severity == "medium"
        assert died.module == "supervisor"
        assert died.category == ["process"]
        assert died.raw["worker"] == "flaky"
        assert died.raw["exit_code"] == 3
        assert died.raw["signal"] is None
        assert died.raw["restarts"] == 0

        restarted = collector.actions("worker_restarted")
        assert [ev.raw["attempt"] for ev in restarted] == [1, 2]
        assert restarted[0].severity == "info"
        assert restarted[0].raw["worker"] == "flaky"
        assert restarted[0].raw["backoff_s"] == backoff_delay(1, base=0.01, cap=0.05)
        assert restarted[1].raw["backoff_s"] == backoff_delay(2, base=0.01, cap=0.05)

        exhausted = collector.actions("worker_restart_exhausted")[0]
        assert exhausted.severity == "high"
        assert exhausted.raw["worker"] == "flaky"
        assert exhausted.raw["attempts"] == 2
    finally:
        sup.stop(timeout=5.0)


def test_worker_killed_by_a_signal_reports_the_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_kill", _SIGKILLS_SRC)
    sup = _supervisor(tmp_path, mod, restart_max_attempts=1)
    collector = _Collector()
    sup.attach_listener(collector)
    sup.start()
    try:
        assert _wait_for(lambda: collector.actions("worker_died"))
        died = collector.actions("worker_died")[0]
        assert died.raw["exit_code"] == -9
        assert died.raw["signal"] == 9
    finally:
        sup.stop(timeout=5.0)


def test_backoff_resets_after_healthy_uptime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(
        tmp_path,
        monkeypatch,
        "sup_restart_healthy",
        _LIVES_THEN_DIES_SRC.format(lifetime=0.35),
    )
    sup = _supervisor(
        tmp_path,
        mod,
        restart_healthy_after_s=0.1,
        restart_max_attempts=2,
    )
    collector = _Collector()
    sup.attach_listener(collector)
    sup.start()
    try:
        # Each incarnation lives 0.35s -- well past the 0.1s healthy threshold --
        # so the consecutive-restart counter must reset every time and the
        # attempt number must stay 1 instead of climbing toward exhaustion.
        assert _wait_for(lambda: len(collector.actions("worker_restarted")) >= 3, timeout=20.0)
        attempts = [ev.raw["attempt"] for ev in collector.actions("worker_restarted")]
        assert attempts[:3] == [1, 1, 1]
        assert not collector.actions("worker_restart_exhausted")
    finally:
        sup.stop(timeout=5.0)


def test_stop_during_a_restart_window_does_not_resurrect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_window", _DIES_SRC)
    # A 30s base delay parks the dead worker in its restart window for the
    # whole test, so stop() lands squarely inside it.
    sup = _supervisor(tmp_path, mod, restart_base_delay_s=30.0, restart_max_delay_s=60.0)
    collector = _Collector()
    sup.attach_listener(collector)
    sup.start()
    try:
        dead_pid = sup._procs[0].proc.pid
        assert _wait_for(lambda: collector.actions("worker_died"))
    finally:
        started = time.monotonic()
        sup.stop(timeout=5.0)
        elapsed = time.monotonic() - started
    assert elapsed < 5.0, f"stop() overran its budget: {elapsed:.2f}s"
    assert sup._monitor_thread is not None and not sup._monitor_thread.is_alive()
    assert sup._procs[0].proc.pid == dead_pid, "monitor resurrected a worker during shutdown"
    assert not collector.actions("worker_restarted")


def test_stop_is_bounded_even_with_stuck_reader_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """stop(timeout=T) must finish in ~T no matter how many readers are wedged.

    Joining each reader thread on a flat per-thread timeout costs 2 seconds per
    worker on top of the caller's budget; the joins have to come out of the
    deadline instead.
    """
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_stuck", _LIVES_SRC)
    wedged = threading.Event()

    def blocking_reader(self: Supervisor, wp: Any) -> None:
        wedged.wait(60.0)

    monkeypatch.setattr(Supervisor, "_read_stdout", blocking_reader)
    monkeypatch.setattr(Supervisor, "_read_stderr", blocking_reader)

    cfg = dev_config(base=tmp_path)
    cfg.workers = [WorkerSpec(name=f"stuck{i}", module=mod, config={}) for i in range(4)]
    sup = Supervisor(cfg, poll_interval_s=0.02)
    sup.start()
    try:
        assert len(sup._procs) == 4
        started = time.monotonic()
        sup.stop(timeout=1.0)
        elapsed = time.monotonic() - started
        # 4 workers x 2 wedged readers would be 8s of flat joins.
        assert elapsed < 2.0, f"stop() overran its budget: {elapsed:.2f}s"
        assert all(wp.proc.poll() is not None for wp in sup._procs)
    finally:
        wedged.set()


def test_stop_without_start_is_harmless(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.stop(timeout=1.0)


def test_worker_that_stays_alive_is_never_restarted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_alive", _LIVES_SRC)
    sup = _supervisor(tmp_path, mod)
    collector = _Collector()
    sup.attach_listener(collector)
    sup.start()
    try:
        pid = sup._procs[0].proc.pid
        time.sleep(0.5)
        assert sup._procs[0].proc.pid == pid
        assert sup._procs[0].restarts == 0
        assert not collector.events
    finally:
        sup.stop(timeout=5.0)


def test_exhaustion_raises_the_starter_pack_alert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: crash loop -> exhausted event -> daemon.worker_restart_exhausted."""
    mod = _install_worker(tmp_path, monkeypatch, "sup_restart_alert", _DIES_SRC)
    sup = _supervisor(tmp_path, mod, restart_max_attempts=1)
    alerts: list[Any] = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        assert _wait_for(
            lambda: any(a.rule.id == "daemon.worker_restart_exhausted" for a in alerts)
        ), "the exhausted event did not raise its starter-pack alert"
        alert = next(a for a in alerts if a.rule.id == "daemon.worker_restart_exhausted")
        assert alert.severity == "high"
        assert "flaky" in alert.rendered.short
    finally:
        sup.stop(timeout=5.0)
