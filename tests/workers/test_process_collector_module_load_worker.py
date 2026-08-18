"""Tests the ProcessCollectorModuleLoadWorker independently of the BPF runtime.

Mirror of the process_collector_ptrace worker test: a fake stream stands in for
inspectord._native.ProcessModuleLoadStream so the translation logic is
exercised without loading eBPF programs.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector_module_load.__main__ import (
    ProcessCollectorModuleLoadWorker,
)


class FakeStream:
    """Stand-in for inspectord._native.ProcessModuleLoadStream."""

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


def _finit_record(
    *,
    pid: int = 1234,
    uid: int = 0,
    comm: str = "modprobe",
    fd: int = 7,
    flags: int = 0,
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "uid": uid,
        "comm": comm,
        "variant": 0,
        "variant_name": "finit_module",
        "fd": fd,
        "flags": flags,
    }


def _init_record(
    *,
    pid: int = 4321,
    uid: int = 0,
    comm: str = "loader",
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "uid": uid,
        "comm": comm,
        "variant": 1,
        "variant_name": "init_module",
        "fd": -1,
        "flags": 0,
    }


def _run(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sink = BytesIO()
    stream = FakeStream([records])
    worker = ProcessCollectorModuleLoadWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()
    return _read_events(sink)


def test_worker_emits_module_load_attempt_event_for_finit_module() -> None:
    events = _run([_finit_record(flags=2)])
    assert len(events) == 1, events
    ev = events[0]
    assert ev["module"] == "process_collector_module_load"
    assert ev["action"] == "module_load_attempt"
    assert ev["kind"] == "event"
    assert ev["category"] == ["driver"]
    assert ev["type"] == ["installation"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["user"]["id"] == "0"
    assert ev["process"]["pid"] == 1234
    assert ev["process"]["name"] == "modprobe"
    assert ev["process"]["module_load_variant"] == "finit_module"
    assert ev["process"]["module_load_fd"] == 7
    assert ev["process"]["module_load_flags"] == 2
    assert ev["raw"]["source"] == "ebpf:sys_enter_finit_module"
    assert ev["raw"]["variant"] == 0
    assert ev["raw"]["fd"] == 7
    assert ev["raw"]["flags"] == 2


def test_worker_emits_module_load_attempt_event_for_init_module() -> None:
    events = _run([_init_record()])
    assert len(events) == 1, events
    ev = events[0]
    assert ev["module"] == "process_collector_module_load"
    assert ev["action"] == "module_load_attempt"
    assert ev["process"]["pid"] == 4321
    assert ev["process"]["name"] == "loader"
    assert ev["process"]["module_load_variant"] == "init_module"
    # init_module takes no fd; the native side reports -1 and 0 flags.
    assert ev["process"]["module_load_fd"] == -1
    assert ev["process"]["module_load_flags"] == 0
    assert ev["raw"]["source"] == "ebpf:sys_enter_init_module"
    assert ev["raw"]["variant"] == 1
    assert ev["raw"]["fd"] == -1
    assert ev["raw"]["flags"] == 0


def test_worker_emits_one_event_per_record_in_a_batch() -> None:
    events = _run([_finit_record(), _init_record()])
    assert [e["process"]["module_load_variant"] for e in events] == [
        "finit_module",
        "init_module",
    ]


def test_worker_converts_monotonic_timestamp_to_wall_clock() -> None:
    # The record's monotonic timestamp is offset by the wall/monotonic delta
    # captured in start(); the emitted ts must not be the raw 1.7e18 ns value
    # interpreted directly as a wall-clock epoch.
    ev = _run([_finit_record()])[0]
    assert not ev["ts"].startswith("2023-11-14T22:13:20"), ev["ts"]


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorModuleLoadWorker(
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
    worker = ProcessCollectorModuleLoadWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
