"""Tests the ProcessCollectorRawSocketWorker independently of the BPF runtime.

Mirror of the process_collector_module_load worker test: a fake stream stands in
for inspectord._native.ProcessRawSocketStream so the translation logic is
exercised without loading eBPF programs.
"""

from __future__ import annotations

import json
import socket
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector_raw_socket.__main__ import (
    ProcessCollectorRawSocketWorker,
)

AF_PACKET = 17
AF_INET = 2


class FakeStream:
    """Stand-in for inspectord._native.ProcessRawSocketStream."""

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


def _packet_record(
    *,
    pid: int = 1234,
    uid: int = 1000,
    comm: str = "tcpdump",
    type_value: int = int(socket.SOCK_RAW),
    protocol: int = 768,
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "uid": uid,
        "comm": comm,
        "family": AF_PACKET,
        "family_name": "AF_PACKET",
        "type": type_value,
        "protocol": protocol,
    }


def _inet_raw_record(
    *,
    pid: int = 4321,
    uid: int = 0,
    comm: str = "ping",
    type_value: int = int(socket.SOCK_RAW),
    protocol: int = 1,
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "uid": uid,
        "comm": comm,
        "family": AF_INET,
        "family_name": "AF_INET",
        "type": type_value,
        "protocol": protocol,
    }


def _run(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sink = BytesIO()
    stream = FakeStream([records])
    worker = ProcessCollectorRawSocketWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()
    return _read_events(sink)


def test_worker_emits_raw_socket_created_event_for_af_packet() -> None:
    events = _run([_packet_record()])
    assert len(events) == 1, events
    ev = events[0]
    assert ev["module"] == "process_collector_raw_socket"
    assert ev["action"] == "raw_socket_created"
    assert ev["kind"] == "event"
    assert ev["category"] == ["network"]
    assert ev["type"] == ["start"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["user"]["id"] == "1000"
    assert ev["process"]["pid"] == 1234
    assert ev["process"]["name"] == "tcpdump"
    assert ev["network"]["socket_family"] == "AF_PACKET"
    assert ev["network"]["socket_type"] == int(socket.SOCK_RAW)
    assert ev["network"]["socket_protocol"] == 768
    assert ev["raw"]["source"] == "ebpf:sys_enter_socket"
    assert ev["raw"]["family"] == AF_PACKET
    assert ev["raw"]["type"] == int(socket.SOCK_RAW)
    assert ev["raw"]["protocol"] == 768


def test_worker_emits_raw_socket_created_event_for_af_inet_sock_raw() -> None:
    events = _run([_inet_raw_record()])
    assert len(events) == 1, events
    ev = events[0]
    assert ev["module"] == "process_collector_raw_socket"
    assert ev["action"] == "raw_socket_created"
    assert ev["user"]["id"] == "0"
    assert ev["process"]["pid"] == 4321
    assert ev["process"]["name"] == "ping"
    assert ev["network"]["socket_family"] == "AF_INET"
    assert ev["network"]["socket_type"] == int(socket.SOCK_RAW)
    assert ev["network"]["socket_protocol"] == 1
    assert ev["raw"]["family"] == AF_INET
    assert ev["raw"]["protocol"] == 1


def test_worker_preserves_socket_type_flag_bits() -> None:
    # The native side stores the type exactly as the caller passed it; the 0xf
    # mask lives only in the BPF filter. CPython opens every socket with
    # SOCK_CLOEXEC, so those bits are real evidence and must not be normalized
    # away by the worker.
    type_value = int(socket.SOCK_RAW) | int(socket.SOCK_CLOEXEC) | int(socket.SOCK_NONBLOCK)
    ev = _run([_packet_record(type_value=type_value)])[0]
    assert ev["network"]["socket_type"] == type_value
    assert ev["network"]["socket_type"] & socket.SOCK_CLOEXEC
    assert ev["network"]["socket_type"] & socket.SOCK_NONBLOCK
    assert ev["network"]["socket_type"] & 0xF == socket.SOCK_RAW
    assert ev["raw"]["type"] == type_value


def test_worker_emits_one_event_per_record_in_a_batch() -> None:
    events = _run([_packet_record(), _inet_raw_record()])
    assert [e["network"]["socket_family"] for e in events] == ["AF_PACKET", "AF_INET"]


def test_worker_converts_monotonic_timestamp_to_wall_clock() -> None:
    # The record's monotonic timestamp is offset by the wall/monotonic delta
    # captured in start(); the emitted ts must not be the raw 1.7e18 ns value
    # interpreted directly as a wall-clock epoch.
    ev = _run([_packet_record()])[0]
    assert not ev["ts"].startswith("2023-11-14T22:13:20"), ev["ts"]


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorRawSocketWorker(
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
    worker = ProcessCollectorRawSocketWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
