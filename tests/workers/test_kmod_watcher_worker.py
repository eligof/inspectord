"""Tests the KmodWatcherWorker independently of the real /proc/modules source.

The worker is parameterized with a stream factory so tests can inject a fake
that yields a fixed sequence of records.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.kmod_watcher.__main__ import KmodWatcherWorker


class FakeStream:
    """Stand-in for ProcModulesSource."""

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


def _loaded_record(
    *,
    name: str = "btrfs",
    size: int = 1638400,
    refcount: int = 0,
) -> dict[str, Any]:
    return {"action": "loaded", "name": name, "size": size, "refcount": refcount}


def _unloaded_record(*, name: str = "btrfs") -> dict[str, Any]:
    return {"action": "unloaded", "name": name}


def test_worker_emits_kmod_loaded_event() -> None:
    sink = BytesIO()
    stream = FakeStream([[_loaded_record(name="btrfs", size=1638400, refcount=2)]])
    worker = KmodWatcherWorker(
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
    assert ev["module"] == "kmod_watcher"
    assert ev["action"] == "kmod_loaded"
    assert ev["kind"] == "event"
    assert ev["category"] == ["driver"]
    assert ev["type"] == ["installation"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert "btrfs" in ev["message"]
    assert ev["raw"]["source"] == "/proc/modules"
    assert ev["raw"]["module_name"] == "btrfs"
    assert ev["raw"]["module_size"] == 1638400
    assert ev["raw"]["module_refcount"] == 2


def test_worker_emits_kmod_unloaded_event() -> None:
    sink = BytesIO()
    stream = FakeStream([[_unloaded_record(name="btrfs")]])
    worker = KmodWatcherWorker(
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
    assert ev["module"] == "kmod_watcher"
    assert ev["action"] == "kmod_unloaded"
    assert ev["kind"] == "event"
    assert ev["category"] == ["driver"]
    assert ev["type"] == ["deletion"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert "btrfs" in ev["message"]
    assert ev["raw"]["source"] == "/proc/modules"
    assert ev["raw"]["module_name"] == "btrfs"
    assert "module_size" not in ev["raw"]
    assert "module_refcount" not in ev["raw"]


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = KmodWatcherWorker(
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
    worker = KmodWatcherWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
