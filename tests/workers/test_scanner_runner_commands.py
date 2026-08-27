"""scanner_runner `run_scanner` command tests (worker-command-channel design §7).

`run_scanner {name}` validates against the worker's own config (unknown /
disabled are honest rejections), queues a run-next entry that survives
`_reschedule` and is removed only when `_start_run` resolves it, respects
single-flight ("queued behind current run"), and never consumes the scheduled
slot — triggering a scan must not push the next scheduled scan a full interval
away.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from io import BytesIO
from typing import Any

from inspectord.workers.scanner_runner.runner import ScannerRunnerWorker
from inspectord.workers.scanner_runner.scanners.base import Finding, ScanOutcome


class FakeAdapter:
    """A ScannerAdapter whose scan is a controllable `sh -c` command."""

    def __init__(
        self,
        *,
        argv: Sequence[str],
        findings: Sequence[Finding] = (),
        name: str = "fake",
        binary: str = "sh",
    ) -> None:
        self.name = name
        self.binary = binary
        self._argv = list(argv)
        self._findings = list(findings)

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        return list(self._argv)

    def preflight(self, config: Mapping[str, Any]) -> str | None:
        return None

    def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome:
        return ScanOutcome.clean if code == 0 else ScanOutcome.failure

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        return list(self._findings)


def _make_worker(
    adapters: Sequence[Any], config: dict[str, Any]
) -> tuple[ScannerRunnerWorker, BytesIO]:
    buf = BytesIO()
    worker = ScannerRunnerWorker(
        name="scanner_runner",
        adapters=list(adapters),
        config=config,
        stdout=buf,
        stderr=BytesIO(),
        host_name="testhost",
    )
    return worker, buf


def _events(buf: BytesIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def _actions(buf: BytesIO, action: str) -> list[dict[str, Any]]:
    return [e for e in _events(buf) if e.get("action") == action]


def _pump(
    worker: ScannerRunnerWorker,
    buf: BytesIO,
    *,
    until: Callable[[list[dict[str, Any]]], bool],
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    while True:
        worker.step()
        events = _events(buf)
        if until(events) or time.monotonic() > deadline:
            return events
        time.sleep(0.01)


def _config(**scanner_overrides: Any) -> dict[str, Any]:
    scanner = {"enabled": True, "interval_s": 86400.0, "timeout_s": 10.0}
    scanner.update(scanner_overrides)
    return {
        "scanners": {"fake": scanner},
        # A long startup delay: nothing is ever *scheduled* due in these tests
        # unless a test says so.
        "startup_delay_s": 3600.0,
        "interval_s": 0.01,
    }


# --------------------------------------------------------------------------
# validation: the worker's own config is the authority
# --------------------------------------------------------------------------


def test_unknown_scanner_is_rejected() -> None:
    worker, _buf = _make_worker([FakeAdapter(argv=["sh", "-c", "true"])], _config())
    assert worker.handle_command("run_scanner", {"name": "nope"}) == {
        "status": "rejected",
        "detail": "unknown_scanner",
    }
    assert worker.handle_command("run_scanner", {}) == {
        "status": "rejected",
        "detail": "unknown_scanner",
    }


def test_disabled_scanner_is_rejected_honestly() -> None:
    worker, _buf = _make_worker([FakeAdapter(argv=["sh", "-c", "true"])], _config(enabled=False))
    assert worker.handle_command("run_scanner", {"name": "fake"}) == {
        "status": "rejected",
        "detail": "scanner_disabled",
    }


def test_unknown_command_is_rejected() -> None:
    worker, _buf = _make_worker([FakeAdapter(argv=["sh", "-c", "true"])], _config())
    assert worker.handle_command("frobnicate", {})["status"] == "rejected"


# --------------------------------------------------------------------------
# trigger: runs at the next tick, removed only at launch, slot untouched
# --------------------------------------------------------------------------


def test_triggered_run_starts_at_next_tick_and_is_removed_at_launch() -> None:
    worker, buf = _make_worker([FakeAdapter(argv=["sh", "-c", "true"])], _config())
    worker.step()  # schedules everything far in the future (startup delay)
    assert _actions(buf, "scan_started") == []

    result = worker.handle_command("run_scanner", {"name": "fake"})
    assert result["status"] == "accepted"
    assert "fake" in worker._run_next
    worker.step()
    assert len(_actions(buf, "scan_started")) == 1
    assert "fake" not in worker._run_next, "the trigger must be removed when the run launches"


def test_triggered_run_does_not_consume_the_scheduled_slot() -> None:
    worker, buf = _make_worker([FakeAdapter(argv=["sh", "-c", "true"])], _config())
    worker.step()
    anchor = worker._next_due["fake"]

    worker.handle_command("run_scanner", {"name": "fake"})
    events = _pump(worker, buf, until=lambda evs: any(e["action"] == "scan_completed" for e in evs))
    assert len([e for e in events if e["action"] == "scan_completed"]) == 1
    assert worker._next_due["fake"] == anchor, (
        "the triggered run re-based the scheduled cadence off its own completion"
    )


def test_triggered_run_failure_does_not_burn_the_scheduled_retry() -> None:
    worker, buf = _make_worker([FakeAdapter(argv=["sh", "-c", "exit 7"])], _config())
    worker.step()
    anchor = worker._next_due["fake"]
    worker.handle_command("run_scanner", {"name": "fake"})
    events = _pump(worker, buf, until=lambda evs: any(e["action"] == "scan_completed" for e in evs))
    [completed] = [e for e in events if e["action"] == "scan_completed"]
    assert completed["outcome"] == "failure"
    # No retry re-scheduling either: the user can simply click again.
    assert worker._next_due["fake"] == anchor
    assert worker._retried.get("fake", False) is False


# --------------------------------------------------------------------------
# single-flight: queued behind the current run, surviving _reschedule
# --------------------------------------------------------------------------


def test_trigger_during_a_run_is_queued_and_survives_reschedule() -> None:
    worker, buf = _make_worker(
        [FakeAdapter(argv=["sh", "-c", "sleep 0.3"])],
        {
            "scanners": {"fake": {"enabled": True, "interval_s": 86400.0, "timeout_s": 10.0}},
            "startup_delay_s": 0.0,  # the FIRST run is a scheduled one
            "interval_s": 0.01,
        },
    )
    worker.step()  # starts the scheduled run
    assert len(_actions(buf, "scan_started")) == 1
    assert worker._active is not None

    result = worker.handle_command("run_scanner", {"name": "fake"})
    assert result == {"status": "accepted", "detail": "queued behind current run"}
    assert "fake" in worker._run_next
    # Single-flight: ticking while in flight must not start a second run.
    worker.step()
    assert len(_actions(buf, "scan_started")) == 1

    # Completion runs _reschedule (the scheduled run re-bases next_due). The
    # queued trigger must survive that re-basing and launch right after the
    # current run finishes — if _reschedule clobbered it, no second run would
    # ever start (next_due just moved a day out).
    events = _pump(
        worker,
        buf,
        until=lambda evs: len([e for e in evs if e["action"] == "scan_started"]) >= 2,
    )
    started_indexes = [i for i, e in enumerate(events) if e["action"] == "scan_started"]
    completed_indexes = [i for i, e in enumerate(events) if e["action"] == "scan_completed"]
    assert len(started_indexes) == 2, "_reschedule clobbered the queued trigger"
    # Single-flight held: the second run started only after the first completed.
    assert completed_indexes[0] < started_indexes[1]
    assert "fake" not in worker._run_next


def test_reschedule_itself_leaves_the_run_next_entry_alone() -> None:
    worker, _buf = _make_worker([FakeAdapter(argv=["sh", "-c", "true"])], _config())
    worker._run_next.add("fake")
    worker._reschedule("fake", ScanOutcome.clean, None, now=1000.0)
    assert "fake" in worker._run_next
