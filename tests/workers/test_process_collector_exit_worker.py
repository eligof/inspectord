"""Tests the ProcessCollectorExitWorker independently of the BPF runtime.

The worker is parameterized with a stream factory so tests can inject a fake
that yields a fixed sequence of records.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector_exit.__main__ import ProcessCollectorExitWorker


class FakeStream:
    """Stand-in for inspectord._native.ProcessExitStream."""

    def __init__(self, batches: list[list[dict[str, Any]]]) -> None:
        self._batches = batches
        self._closed = False

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        if not self._batches:
            return []
        return self._batches.pop(0)

    def close(self) -> None:
        self._closed = True


def _read_events(buf: BytesIO) -> list[dict[str, Any]]:
    buf.seek(0)
    return [json.loads(line) for line in buf.read().splitlines() if line]


def _normal_exit_record(*, pid: int = 1234, comm: str = "ls", status: int = 0) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "comm": comm,
        "exit_code": (status & 0xFF) << 8,
        "exit_status": status,
        "killed_by_signal": None,
    }


def _signal_kill_record(
    *, pid: int = 1234, comm: str = "victim", signum: int = 9
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "comm": comm,
        "exit_code": signum & 0x7F,
        "exit_status": None,
        "killed_by_signal": signum,
    }


def test_worker_emits_normal_exit_as_success() -> None:
    sink = BytesIO()
    stream = FakeStream([[_normal_exit_record(pid=4321, comm="true", status=0)]])
    worker = ProcessCollectorExitWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]
    assert ev["module"] == "process_collector_exit"
    assert ev["action"] == "process_exit"
    assert ev["kind"] == "event"
    assert ev["category"] == ["process"]
    assert ev["type"] == ["end"]
    assert ev["severity"] == "info"
    assert ev["outcome"] == "success"
    assert ev["host"]["name"] == "test-host"
    assert ev["process"]["pid"] == 4321
    assert ev["process"]["name"] == "true"
    assert ev["process"]["exit_status"] == 0
    assert "killed_by_signal" not in ev["process"]


def test_worker_emits_signal_kill_as_failure() -> None:
    sink = BytesIO()
    stream = FakeStream([[_signal_kill_record(pid=4321, comm="victim", signum=9)]])
    worker = ProcessCollectorExitWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]
    assert ev["outcome"] == "failure"
    assert ev["process"]["killed_by_signal"] == 9
    assert "exit_status" not in ev["process"]


def test_worker_emits_nonzero_status_as_failure() -> None:
    sink = BytesIO()
    stream = FakeStream([[_normal_exit_record(pid=4321, comm="false", status=1)]])
    worker = ProcessCollectorExitWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    ev = _read_events(sink)[0]
    assert ev["outcome"] == "failure"
    assert ev["process"]["exit_status"] == 1


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorExitWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=1)
    worker.stop()
    assert _read_events(sink) == []


def test_worker_closes_stream_on_stop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorExitWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
