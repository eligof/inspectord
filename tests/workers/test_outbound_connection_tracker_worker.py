"""Tests the OutboundConnectionTrackerWorker independently of the BPF runtime.

The worker is parameterized with a stream factory so tests can inject a fake
that yields a fixed sequence of records.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.outbound_connection_tracker.__main__ import (
    OutboundConnectionTrackerWorker,
)


class FakeStream:
    """Stand-in for inspectord._native.ProcessConnectStream."""

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


def _connect_record(
    *,
    pid: int = 1234,
    uid: int = 1000,
    comm: str = "curl",
    saddr: str = "10.0.0.5",
    sport: int = 51234,
    daddr: str = "93.184.216.34",
    dport: int = 443,
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "uid": uid,
        "comm": comm,
        "family": 2,
        "saddr": saddr,
        "sport": sport,
        "daddr": daddr,
        "dport": dport,
    }


def test_worker_emits_outbound_connection_event() -> None:
    sink = BytesIO()
    stream = FakeStream([[_connect_record()]])
    worker = OutboundConnectionTrackerWorker(
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
    assert ev["module"] == "outbound_connection_tracker"
    assert ev["action"] == "outbound_connection"
    assert ev["kind"] == "event"
    assert ev["category"] == ["network"]
    assert ev["type"] == ["connection", "start"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["user"]["id"] == "1000"
    assert ev["process"]["pid"] == 1234
    assert ev["process"]["name"] == "curl"
    assert ev["source"]["ip"] == "10.0.0.5"
    assert ev["source"]["port"] == 51234
    assert ev["destination"]["ip"] == "93.184.216.34"
    assert ev["destination"]["port"] == 443
    assert ev["network"]["transport"] == "tcp"
    assert ev["network"]["direction"] == "egress"


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = OutboundConnectionTrackerWorker(
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
    worker = OutboundConnectionTrackerWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
