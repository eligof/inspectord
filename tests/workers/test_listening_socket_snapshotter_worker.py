"""Tests the ListeningSocketSnapshotterWorker independently of the real /proc/net source.

The worker is parameterised with a stream factory so tests can inject a fake
that yields a fixed sequence of records.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.listening_socket_snapshotter.__main__ import (
    ListeningSocketSnapshotterWorker,
)


class FakeStream:
    """Stand-in for ListeningSocketSource."""

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


def test_worker_emits_listener_added_event() -> None:
    """A listener_added record for tcp/0.0.0.0:22 produces the expected event."""
    sink = BytesIO()
    record: dict[str, Any] = {
        "action": "listener_added",
        "proto": "tcp",
        "ip": "0.0.0.0",
        "port": 22,
    }
    stream = FakeStream([[record]])
    worker = ListeningSocketSnapshotterWorker(
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
    assert ev["module"] == "listening_socket_snapshotter"
    assert ev["action"] == "listener_added"
    assert ev["kind"] == "event"
    assert ev["category"] == ["network"]
    assert ev["type"] == ["start"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["source"]["ip"] == "0.0.0.0"
    assert ev["source"]["port"] == 22
    assert ev["network"]["transport"] == "tcp"
    assert ev["network"]["direction"] == "ingress"
    assert ev["raw"]["source"] == "/proc/net/tcp"
    assert "0.0.0.0" in ev["message"]
    assert "22" in ev["message"]


def test_worker_emits_listener_removed_event() -> None:
    """A listener_removed record for udp6/::1:5353 produces the expected event."""
    sink = BytesIO()
    record: dict[str, Any] = {
        "action": "listener_removed",
        "proto": "udp6",
        "ip": "::1",
        "port": 5353,
    }
    stream = FakeStream([[record]])
    worker = ListeningSocketSnapshotterWorker(
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
    assert ev["module"] == "listening_socket_snapshotter"
    assert ev["action"] == "listener_removed"
    assert ev["kind"] == "event"
    assert ev["category"] == ["network"]
    assert ev["type"] == ["end"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["source"]["ip"] == "::1"
    assert ev["source"]["port"] == 5353
    assert ev["network"]["transport"] == "udp"
    assert ev["network"]["direction"] == "ingress"
    assert ev["raw"]["source"] == "/proc/net/udp6"
    assert "::1" in ev["message"]
    assert "5353" in ev["message"]


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ListeningSocketSnapshotterWorker(
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
    worker = ListeningSocketSnapshotterWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
