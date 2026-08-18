"""Tests for the threaded scan runner.

The adapter is fake but the subprocess is real: `FakeAdapter.argv()` returns a
short `sh -c 'sleep N; ...'`, which keeps every test sub-second while still
exercising the real spawn / communicate / timeout / kill path. Nothing here
needs root.

Covers design §4.4 and §4.5: a run completing, a run timing out and being
killed, `teardown()` during a run, single-flight rejection, a missing binary,
the finding cap with its truncation flag, and the single retry.
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
        self.parse_calls = 0
        self.last_stdout = ""
        self.last_stderr = ""

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        return list(self._argv)

    def interpret_exit(self, code: int) -> ScanOutcome:
        if code == 0:
            return ScanOutcome.clean
        if code == 1:
            return ScanOutcome.findings
        return ScanOutcome.failure

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        self.parse_calls += 1
        self.last_stdout = stdout
        self.last_stderr = stderr
        return list(self._findings)


def _finding(path: str) -> Finding:
    return Finding(
        indicator_type="aide_change",
        indicator_value="changed",
        raw_line=f"f...: {path}",
        category="file",
        path=path,
        message=f"AIDE: changed {path}",
    )


def _make_worker(
    adapters: Sequence[Any],
    config: dict[str, Any],
    **kwargs: Any,
) -> tuple[ScannerRunnerWorker, BytesIO]:
    buf = BytesIO()
    worker = ScannerRunnerWorker(
        name="scanner_runner",
        adapters=list(adapters),
        config=config,
        stdout=buf,
        stderr=BytesIO(),
        host_name="testhost",
        **kwargs,
    )
    return worker, buf


def _events(buf: BytesIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def _pump(
    worker: ScannerRunnerWorker,
    buf: BytesIO,
    *,
    until: Callable[[list[dict[str, Any]]], bool],
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    """Tick the worker until *until* holds over the emitted events (or time out)."""
    deadline = time.monotonic() + timeout_s
    while True:
        worker.step()
        events = _events(buf)
        if until(events) or time.monotonic() > deadline:
            return events
        time.sleep(0.01)


def _actions(events: list[dict[str, Any]]) -> list[str]:
    return [e["action"] for e in events]


def _has(action: str) -> Callable[[list[dict[str, Any]]], bool]:
    return lambda events: any(e["action"] == action for e in events)


def _completed(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The scan_completed events. Never `events[-1]`: a retry may already have started."""
    return [e for e in events if e["action"] == "scan_completed"]


def _base_config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "interval_s": 0.01,
        "startup_delay_s": 0.0,
        "retry_backoff_s": 0.0,
        "scanners": {"fake": {"enabled": True, "interval_s": 1000.0, "timeout_s": 30.0}},
    }
    config.update(overrides)
    return config


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------


def test_run_completes_and_emits_lifecycle_and_findings() -> None:
    adapter = FakeAdapter(
        argv=["sh", "-c", "sleep 0.05; exit 1"],
        findings=[_finding("/etc/passwd"), _finding("/etc/shadow")],
    )
    worker, buf = _make_worker([adapter], _base_config())
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    assert _actions(events) == [
        "scan_started",
        "scan_finding",
        "scan_finding",
        "scan_completed",
    ]
    assert {e["module"] for e in events} == {"scanner_runner"}
    assert {e["kind"] for e in events} == {"event"}

    started, first_finding, _, completed = events
    assert started["severity"] == "info"
    assert started["raw"]["argv"] == ["sh", "-c", "sleep 0.05; exit 1"]

    assert first_finding["severity"] == "low"
    assert first_finding["category"] == ["file"]
    assert first_finding["file"]["path"] == "/etc/passwd"
    assert first_finding["threat"]["indicator"] == {
        "type": "aide_change",
        "value": "changed",
        "source": "fake",
    }
    assert first_finding["raw"]["line"] == "f...: /etc/passwd"

    assert completed["outcome"] == "success"
    assert completed["raw"]["scan_outcome"] == "findings"
    assert completed["raw"]["exit_code"] == 1
    assert completed["raw"]["finding_count"] == 2
    assert completed["raw"]["truncated"] is False
    assert completed["raw"]["duration_s"] >= 0.0

    # One run_id correlates the whole run.
    assert len({e["raw"]["run_id"] for e in events}) == 1


def test_clean_run_emits_no_findings() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "exit 0"])
    worker, buf = _make_worker([adapter], _base_config())
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    assert _actions(events) == ["scan_started", "scan_completed"]
    completed = _completed(events)[0]
    assert completed["outcome"] == "success"
    assert completed["raw"]["scan_outcome"] == "clean"
    assert completed["raw"]["finding_count"] == 0


def test_disabled_scanner_never_runs() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "exit 0"])
    config = _base_config(scanners={"fake": {"enabled": False}})
    worker, buf = _make_worker([adapter], config)
    try:
        for _ in range(5):
            worker.step()
    finally:
        worker.teardown()
    assert _events(buf) == []


def test_startup_delay_defers_the_first_scan() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "exit 0"])
    worker, buf = _make_worker([adapter], _base_config(startup_delay_s=600.0))
    try:
        for _ in range(5):
            worker.step()
    finally:
        worker.teardown()
    assert _events(buf) == []


# --------------------------------------------------------------------------
# timeout and shutdown -- the process group must die (design decision 3)
# --------------------------------------------------------------------------


def test_run_timing_out_is_killed_and_reported_failure() -> None:
    adapter = FakeAdapter(argv=["sleep", "300"])
    config = _base_config(
        scanners={"fake": {"enabled": True, "interval_s": 1000.0, "timeout_s": 0.2}}
    )
    worker, buf = _make_worker([adapter], config)
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    completed = _completed(events)[0]
    assert completed["outcome"] == "failure"
    assert completed["raw"]["scan_outcome"] == "failure"
    assert completed["raw"]["reason"] == "timeout"
    # A failed scan is never parsed for findings.
    assert adapter.parse_calls == 0


def test_teardown_during_a_run_kills_it_and_reports_failure() -> None:
    adapter = FakeAdapter(argv=["sleep", "300"])
    worker, buf = _make_worker([adapter], _base_config())
    worker.step()
    assert _actions(_events(buf)) == ["scan_started"]

    worker.teardown()

    events = _events(buf)
    assert _actions(events) == ["scan_started", "scan_completed"]
    assert events[-1]["outcome"] == "failure"
    assert events[-1]["raw"]["reason"] == "shutdown"


def test_teardown_without_a_run_is_a_silent_noop() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "exit 0"])
    worker, buf = _make_worker([adapter], _base_config(startup_delay_s=600.0))
    worker.teardown()
    worker.teardown()  # idempotent
    assert _events(buf) == []


# --------------------------------------------------------------------------
# single-flight (design §4.4)
# --------------------------------------------------------------------------


def test_single_flight_rejects_a_second_due_scanner() -> None:
    slow = FakeAdapter(name="a_slow", argv=["sh", "-c", "sleep 0.4; exit 0"])
    quick = FakeAdapter(name="b_quick", argv=["sh", "-c", "exit 0"])
    config = _base_config(
        scanners={
            "a_slow": {"enabled": True, "interval_s": 1000.0, "timeout_s": 30.0},
            "b_quick": {"enabled": True, "interval_s": 1000.0, "timeout_s": 30.0},
        }
    )
    worker, buf = _make_worker([slow, quick], config)
    try:
        worker.step()
        first = _events(buf)
        assert first[0]["action"] == "scan_started"
        assert first[0]["raw"]["scanner"] == "a_slow"
        assert first[1]["action"] == "scan_skipped"
        assert first[1]["raw"] == {
            "scanner": "b_quick",
            "reason": "run_in_flight",
            "binary": "sh",
        }

        events = _pump(
            worker,
            buf,
            until=lambda evs: sum(1 for e in evs if e["action"] == "scan_completed") == 2,
        )
    finally:
        worker.teardown()

    # The loser is notified once per due window, not once per tick.
    skips = [e for e in events if e["action"] == "scan_skipped"]
    assert len(skips) == 1

    # ...and it does run, once the slot frees up.
    started = [e["raw"]["scanner"] for e in events if e["action"] == "scan_started"]
    assert started == ["a_slow", "b_quick"]

    # At no point were two runs in flight at once.
    inflight = 0
    for event in events:
        if event["action"] == "scan_started":
            inflight += 1
        elif event["action"] == "scan_completed":
            inflight -= 1
        assert inflight <= 1


# --------------------------------------------------------------------------
# missing binary (design decision 14)
# --------------------------------------------------------------------------


def test_missing_binary_emits_scan_skipped_once_per_due_cycle() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "exit 0"], binary="inspectord-no-such-binary-6f3a1c")
    worker, buf = _make_worker([adapter], _base_config())
    try:
        for _ in range(5):
            worker.step()
    finally:
        worker.teardown()

    events = _events(buf)
    assert _actions(events) == ["scan_skipped"]
    assert events[0]["raw"]["reason"] == "binary_not_found"
    assert events[0]["raw"]["binary"] == "inspectord-no-such-binary-6f3a1c"


# --------------------------------------------------------------------------
# finding cap (design decision 12)
# --------------------------------------------------------------------------


def test_finding_cap_truncates_and_flags() -> None:
    adapter = FakeAdapter(
        argv=["sh", "-c", "exit 1"],
        findings=[_finding(f"/etc/f{i}") for i in range(10)],
    )
    worker, buf = _make_worker([adapter], _base_config(max_findings_per_run=3))
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    findings = [e for e in events if e["action"] == "scan_finding"]
    assert len(findings) == 3
    assert [e["file"]["path"] for e in findings] == ["/etc/f0", "/etc/f1", "/etc/f2"]

    completed = _completed(events)[0]
    assert completed["raw"]["truncated"] is True
    assert completed["raw"]["finding_count"] == 3
    assert completed["raw"]["findings_dropped"] == 7
    # Truncation never turns a successful scan into a failed one.
    assert completed["outcome"] == "success"


# --------------------------------------------------------------------------
# output ceiling -- the memory sibling of the finding cap (decision 12)
# --------------------------------------------------------------------------


def test_output_over_the_ceiling_is_truncated_and_the_child_still_completes() -> None:
    """The cap bounds MEMORY, and the pipe keeps being drained past the cap.

    200 kB per stream is far more than a pipe buffer (64 kB on Linux), so a
    reader that simply stopped at the ceiling would leave the scanner blocked in
    `write()` until its timeout. The child reaching `exit 1` is the proof that
    it did not: a deadlocked scan would be reported as a timeout instead.
    """
    payload = 200_000
    ceiling = 4096
    adapter = FakeAdapter(
        argv=[
            "sh",
            "-c",
            f"yes 0123456789 | head -c {payload}; yes 0123456789 | head -c {payload} >&2; exit 1",
        ],
        findings=[_finding("/etc/passwd")],
    )
    config = _base_config(
        max_output_bytes=ceiling,
        scanners={"fake": {"enabled": True, "interval_s": 1000.0, "timeout_s": 10.0}},
    )
    worker, buf = _make_worker([adapter], config)
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    completed = _completed(events)[0]
    # Not killed: the scanner ran to its own exit status.
    assert completed["outcome"] == "success"
    assert completed["raw"]["exit_code"] == 1
    assert "reason" not in completed["raw"]  # pruned: no failure reason
    # Truncation is visible, never silent (decision 11).
    assert completed["raw"]["output_truncated"] is True
    assert completed["raw"]["output_dropped_bytes"] == 2 * (payload - ceiling)
    # Only the first `ceiling` bytes of each stream were retained.
    assert len(adapter.last_stdout.encode()) == ceiling
    assert len(adapter.last_stderr.encode()) == ceiling
    assert adapter.last_stdout.startswith("0123456789\n")
    # ...and the run is still parsed and reported normally.
    assert sum(1 for e in events if e["action"] == "scan_finding") == 1


def test_output_under_the_ceiling_is_delivered_whole_and_not_flagged() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "echo out; echo err >&2; exit 1"])
    worker, buf = _make_worker([adapter], _base_config(max_output_bytes=4096))
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    completed = _completed(events)[0]
    assert completed["raw"]["output_truncated"] is False
    assert completed["raw"]["output_dropped_bytes"] == 0
    assert adapter.last_stdout == "out\n"
    assert adapter.last_stderr == "err\n"


# --------------------------------------------------------------------------
# failure handling and retry (design §4.4, decision 11)
# --------------------------------------------------------------------------


def test_failure_retries_once_then_waits_for_the_next_slot() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "exit 9"])
    worker, buf = _make_worker([adapter], _base_config())
    try:
        events = _pump(
            worker,
            buf,
            until=lambda evs: sum(1 for e in evs if e["action"] == "scan_completed") == 2,
        )
        assert sum(1 for e in events if e["action"] == "scan_started") == 2
        # No third attempt: after the retry the scanner waits for its next slot
        # (interval_s = 1000s).
        for _ in range(10):
            worker.step()
            time.sleep(0.005)
        events = _events(buf)
    finally:
        worker.teardown()

    assert sum(1 for e in events if e["action"] == "scan_started") == 2
    completed = [e for e in events if e["action"] == "scan_completed"]
    assert [e["outcome"] for e in completed] == ["failure", "failure"]
    assert completed[0]["raw"]["exit_code"] == 9
    # Two runs, two distinct run_ids.
    assert len({e["raw"]["run_id"] for e in completed}) == 2


def test_spawn_failure_is_reported_not_raised() -> None:
    def exploding_spawn(argv: list[str]) -> Any:
        raise FileNotFoundError(argv[0])

    adapter = FakeAdapter(argv=["sh", "-c", "exit 0"])
    worker, buf = _make_worker([adapter], _base_config(), spawn=exploding_spawn)
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    completed = _completed(events)[0]
    assert completed["outcome"] == "failure"
    assert completed["raw"]["reason"] == "spawn_error"
    assert "FileNotFoundError" in completed["raw"]["error"]


def test_a_parser_that_raises_is_reported_as_a_failed_scan() -> None:
    """Adapters promise not to raise; if one does, the run fails loudly."""

    class ExplodingAdapter(FakeAdapter):
        def parse(self, stdout: str, stderr: str) -> list[Finding]:
            raise ValueError("boom")

    worker, buf = _make_worker([ExplodingAdapter(argv=["sh", "-c", "exit 1"])], _base_config())
    try:
        events = _pump(worker, buf, until=_has("scan_completed"))
    finally:
        worker.teardown()

    completed = _completed(events)[0]
    assert completed["outcome"] == "failure"
    assert completed["raw"]["reason"] == "parse_error"


def test_step_interval_comes_from_config() -> None:
    adapter = FakeAdapter(argv=["sh", "-c", "exit 0"])
    worker, _ = _make_worker([adapter], _base_config(interval_s=42.0))
    assert worker.step_interval_s() == 42.0
