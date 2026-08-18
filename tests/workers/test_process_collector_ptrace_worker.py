"""Tests the ProcessCollectorPtraceWorker independently of the BPF runtime.

Mirror of the process_collector_exit worker test: a fake stream stands in for
inspectord._native.ProcessPtraceStream so the translation logic is exercised
without loading eBPF programs.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector_ptrace.__main__ import (
    ProcessCollectorPtraceWorker,
)


class FakeStream:
    """Stand-in for inspectord._native.ProcessPtraceStream."""

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


def _ptrace_record(
    *,
    pid: int = 1234,
    uid: int = 1000,
    comm: str = "gdb",
    request: int = 16,
    request_name: str = "PTRACE_ATTACH",
    target_pid: int = 5678,
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "uid": uid,
        "comm": comm,
        "request": request,
        "request_name": request_name,
        "target_pid": target_pid,
    }


def test_worker_emits_ptrace_call_event() -> None:
    sink = BytesIO()
    stream = FakeStream([[_ptrace_record()]])
    worker = ProcessCollectorPtraceWorker(
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
    assert ev["module"] == "process_collector_ptrace"
    assert ev["action"] == "ptrace_call"
    assert ev["kind"] == "event"
    assert ev["category"] == ["process"]
    assert ev["type"] == ["access"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["user"]["id"] == "1000"
    assert ev["process"]["pid"] == 1234
    assert ev["process"]["name"] == "gdb"
    assert ev["process"]["ptrace_request"] == "PTRACE_ATTACH"
    assert ev["process"]["target_pid"] == 5678
    assert ev["process"]["target"] == {"pid": 5678}
    assert ev["raw"]["source"] == "ebpf:sys_enter_ptrace"
    assert ev["raw"]["request"] == 16


def test_worker_passes_through_write_family_request_name() -> None:
    sink = BytesIO()
    stream = FakeStream([[_ptrace_record(request=0x4205, request_name="PTRACE_SETREGSET")]])
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    ev = _read_events(sink)[0]
    assert ev["process"]["ptrace_request"] == "PTRACE_SETREGSET"
    assert ev["raw"]["request"] == 0x4205


def test_worker_converts_monotonic_timestamp_to_wall_clock() -> None:
    sink = BytesIO()
    stream = FakeStream([[_ptrace_record()]])
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    # The record's monotonic timestamp is offset by the wall/monotonic delta
    # captured in start(); the emitted ts must not be the raw 1.7e18 ns value
    # interpreted directly as a wall-clock epoch.
    worker.step(poll_timeout_ms=10)
    worker.stop()

    ev = _read_events(sink)[0]
    assert not ev["ts"].startswith("2023-11-14T22:13:20"), ev["ts"]


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorPtraceWorker(
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
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
