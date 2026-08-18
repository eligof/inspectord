"""Real-subprocess proof of design decision 3: a scan never outlives the worker.

Nothing is mocked here. The runner spawns a real `sh` that backgrounds a real
`sleep` -- a **grandchild** -- and the test asserts that grandchild is dead
after `teardown()` and after a timeout. Killing only the direct child would
leave it running, so this is the test that would catch a regression from
`os.killpg` back to `proc.terminate()`.

No root required.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from collections.abc import Mapping
from io import BytesIO
from pathlib import Path
from typing import Any

from inspectord.workers.scanner_runner.runner import (
    ScannerRunnerWorker,
    default_spawn,
    kill_process_group,
    signal_process_group,
)
from inspectord.workers.scanner_runner.scanners.base import Finding, ScanOutcome

WAIT_S = 10.0


class SleepAdapter:
    """A scanner that is a shell backgrounding one sleep and running another."""

    name = "sleepy"
    binary = "sh"

    def __init__(self, pidfile: Path, *, ignore_sigterm: bool = False) -> None:
        self._pidfile = pidfile
        self._ignore_sigterm = ignore_sigterm

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        # The backgrounded sleep is a grandchild of this worker. `sh` writes its
        # pid out so the test can watch that specific process, not just the group.
        trap = 'trap "" TERM; ' if self._ignore_sigterm else ""
        return ["sh", "-c", f"{trap}sleep 300 & echo $! > {self._pidfile}; sleep 300"]

    def interpret_exit(self, code: int) -> ScanOutcome:
        return ScanOutcome.clean if code == 0 else ScanOutcome.failure

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        return []


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_until(predicate: Any, *, timeout_s: float = WAIT_S) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _start_scan(
    tmp_path: Path,
    *,
    timeout_s: float,
    ignore_sigterm: bool = False,
) -> tuple[ScannerRunnerWorker, BytesIO, list[subprocess.Popen[str]], Path]:
    pidfile = tmp_path / "grandchild.pid"
    adapter = SleepAdapter(pidfile, ignore_sigterm=ignore_sigterm)
    spawned: list[subprocess.Popen[str]] = []

    def recording_spawn(argv: list[str]) -> subprocess.Popen[str]:
        # The REAL spawn -- start_new_session and all.
        proc = default_spawn(argv)
        spawned.append(proc)
        return proc

    buf = BytesIO()
    worker = ScannerRunnerWorker(
        name="scanner_runner",
        adapters=[adapter],
        spawn=recording_spawn,
        config={
            "interval_s": 0.01,
            "startup_delay_s": 0.0,
            "retry_backoff_s": 10_000.0,
            "scanners": {
                "sleepy": {"enabled": True, "interval_s": 10_000.0, "timeout_s": timeout_s}
            },
        },
        stdout=buf,
        stderr=BytesIO(),
        host_name="testhost",
    )
    worker.step()
    # The spawn happens on the job thread, so it is not synchronous with step().
    assert _wait_until(lambda: len(spawned) == 1), "the scan never spawned"
    return worker, buf, spawned, pidfile


def _read_grandchild_pid(pidfile: Path) -> int:
    assert _wait_until(lambda: pidfile.exists() and pidfile.read_text().strip().isdigit())
    return int(pidfile.read_text().strip())


def _events(buf: BytesIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def test_scan_gets_its_own_process_group(tmp_path: Path) -> None:
    """start_new_session makes the scan its own group leader -- the whole point."""
    worker, _buf, spawned, _pidfile = _start_scan(tmp_path, timeout_s=60.0)
    try:
        proc = spawned[0]
        assert os.getpgid(proc.pid) == proc.pid
        # ...and it is NOT in the test runner's group, so a kill can be targeted.
        assert os.getpgid(proc.pid) != os.getpgid(0)
    finally:
        worker.teardown()


def test_teardown_kills_the_whole_group_including_grandchildren(tmp_path: Path) -> None:
    worker, buf, spawned, pidfile = _start_scan(tmp_path, timeout_s=60.0)
    proc = spawned[0]
    pgid = os.getpgid(proc.pid)
    grandchild = _read_grandchild_pid(pidfile)
    assert _pid_alive(grandchild)

    worker.teardown()

    assert _wait_until(lambda: not _pid_alive(grandchild)), (
        f"grandchild {grandchild} survived teardown -- the scan was orphaned"
    )
    assert _wait_until(lambda: not _group_alive(pgid)), f"process group {pgid} survived teardown"
    assert proc.poll() is not None  # reaped, not a zombie we left behind

    completed = [e for e in _events(buf) if e["action"] == "scan_completed"]
    assert len(completed) == 1
    assert completed[0]["outcome"] == "failure"
    assert completed[0]["raw"]["reason"] == "shutdown"


def test_timeout_kills_the_whole_group_including_grandchildren(tmp_path: Path) -> None:
    worker, buf, spawned, pidfile = _start_scan(tmp_path, timeout_s=0.3)
    proc = spawned[0]
    pgid = os.getpgid(proc.pid)
    grandchild = _read_grandchild_pid(pidfile)
    assert _pid_alive(grandchild)

    try:
        assert _wait_until(
            lambda: _tick_and_check(worker, buf, "scan_completed"),
        ), "the scan never timed out"
    finally:
        worker.teardown()

    assert _wait_until(lambda: not _pid_alive(grandchild)), (
        f"grandchild {grandchild} survived the timeout kill"
    )
    assert _wait_until(lambda: not _group_alive(pgid)), f"process group {pgid} survived the timeout"

    completed = [e for e in _events(buf) if e["action"] == "scan_completed"]
    assert completed[0]["outcome"] == "failure"
    assert completed[0]["raw"]["reason"] == "timeout"


def _tick_and_check(worker: ScannerRunnerWorker, buf: BytesIO, action: str) -> bool:
    worker.step()
    return any(e["action"] == action for e in _events(buf))


def test_signalling_a_dead_process_group_never_raises() -> None:
    """The kill path runs against processes that may already be gone."""
    proc = default_spawn(["sh", "-c", "exit 0"])
    proc.communicate(timeout=WAIT_S)
    # Already exited and reaped: every one of these is a no-op, not an error.
    signal_process_group(proc, signal.SIGTERM)
    signal_process_group(proc, signal.SIGKILL)
    kill_process_group(proc, grace_s=0.1)
    kill_process_group(proc, grace_s=0.1)


def test_teardown_fits_the_supervisor_shutdown_budget(tmp_path: Path) -> None:
    """Supervisor.stop() budgets 5s TOTAL for every worker, then SIGKILLs.

    A scan that ignores SIGTERM must still be dead, and teardown must still
    have returned, well inside that budget -- otherwise the worker is killed
    part-way through its own cleanup and orphans the scan it was reaping.
    """
    worker, _buf, spawned, pidfile = _start_scan(tmp_path, timeout_s=600.0, ignore_sigterm=True)
    proc = spawned[0]
    pgid = os.getpgid(proc.pid)
    grandchild = _read_grandchild_pid(pidfile)

    started = time.monotonic()
    worker.teardown()
    elapsed = time.monotonic() - started

    assert elapsed < 4.0, f"teardown took {elapsed:.1f}s, over the 5s shutdown budget"
    assert _wait_until(lambda: not _pid_alive(grandchild), timeout_s=2.0)
    assert _wait_until(lambda: not _group_alive(pgid), timeout_s=2.0)
