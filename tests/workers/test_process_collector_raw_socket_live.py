"""Root-only end-to-end test: a real raw socket becomes an Event.

The other raw-socket tests stop at a boundary -- `tests/test_native_loader.py`
proves the tracepoint reaches the ring buffer at the stream level, and
`tests/workers/test_process_collector_raw_socket_worker.py` proves the
translation works against a fake stream. Neither exercises the whole path, so
this test drives the real `ProcessRawSocketStream` through the real worker and
asserts on the NDJSON the worker writes.

Two deliberate differences from the module-load live test, both taken from
`tests/test_native_loader.py::test_raw_socket_stream_captures_af_packet_but_filters_the_rest`:

- **No CPU pinning.** `sys_enter_socket` takes three scalar ints and copies
  nothing from userspace, so it is not one of the faultable tracepoints whose
  kernel handler is gated on a per-CPU perf event. The module-load test pins
  itself off CPU 0 precisely because finit_module/init_module are gated that
  way; here that would be noise.
- **Ordering makes the negative assertions race-free.** The two sockets that
  must be filtered out are created first and the AF_PACKET one last, so once
  its event arrives the other two syscalls have provably already run -- making
  their absence an assertion rather than a race.

Run with:
  sudo .venv/bin/python -m pytest -m ebpf_load \
    tests/workers/test_process_collector_raw_socket_live.py
"""

from __future__ import annotations

import json
import os
import socket
import time
from io import BytesIO
from typing import Any

import pytest

from inspectord.workers.process_collector_raw_socket.__main__ import (
    ProcessCollectorRawSocketWorker,
)

AF_PACKET = 17
AF_NETLINK = 16  # spelled out to keep the filter's family scope explicit
NETLINK_ROUTE = 0


def _events_since(sink: BytesIO, offset: int) -> list[dict[str, Any]]:
    """Parse the NDJSON the worker appended past `offset`."""
    sink.seek(offset)
    return [json.loads(line) for line in sink.read().splitlines() if line]


@pytest.mark.ebpf_load
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_af_packet_socket_is_emitted_as_an_event() -> None:
    sink = BytesIO()
    worker = ProcessCollectorRawSocketWorker(sink=sink, host_name="test-host")
    worker.start()

    tcp_sock = None
    netlink_sock = None
    packet_sock = None
    try:
        time.sleep(0.2)
        worker.step(poll_timeout_ms=200)  # drain unrelated traffic
        baseline = sink.tell()  # only look at what the sockets below produce

        # Must NOT be captured: an ordinary TCP socket is not raw.
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        # Must NOT be captured: netlink is SOCK_RAW by convention and needs no
        # CAP_NET_RAW, which is why the in-BPF filter is family-scoped.
        netlink_sock = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        # Must be captured: the packet-sniffer socket.
        packet_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)

        events: list[dict[str, Any]] = []
        for _ in range(10):
            worker.step(poll_timeout_ms=200)
            events = _events_since(sink, baseline)
            if any(
                e["process"]["pid"] == os.getpid() and e["network"]["socket_family"] == "AF_PACKET"
                for e in events
            ):
                break

        mine = [e for e in events if e["process"]["pid"] == os.getpid()]
        packets = [e for e in mine if e["network"]["socket_family"] == "AF_PACKET"]
        assert packets, f"no AF_PACKET event emitted; got {events}"

        ev = packets[0]
        assert ev["module"] == "process_collector_raw_socket"
        assert ev["action"] == "raw_socket_created"
        assert ev["kind"] == "event"
        assert ev["category"] == ["network"]
        assert ev["type"] == ["start"]
        assert ev["severity"] == "info"
        assert ev["host"]["name"] == "test-host"
        assert ev["user"]["id"] == "0"
        assert ev["process"]["pid"] == os.getpid()
        assert ev["process"]["name"], f"event carries no process name: {ev}"

        # The base type is SOCK_RAW once the 0xf mask strips the flag bits --
        # the same mask the BPF filter applies. The event carries the type
        # *unmasked*, though, so the flags survive as evidence: CPython opens
        # every socket with SOCK_CLOEXEC, which is what makes the
        # masked-vs-stored distinction observable here.
        assert ev["network"]["socket_type"] & 0xF == socket.SOCK_RAW, ev
        assert ev["network"]["socket_type"] & socket.SOCK_CLOEXEC, (
            f"flag bits were masked out of the emitted socket type: {ev}"
        )
        assert ev["raw"]["type"] == ev["network"]["socket_type"]
        assert ev["raw"]["source"] == "ebpf:sys_enter_socket"
        assert ev["raw"]["family"] == AF_PACKET
        # The wall-clock conversion must land in the present, not at the raw
        # monotonic value reinterpreted as an epoch (which would be ~1970).
        assert ev["ts"] > "2026-01-01", ev["ts"]

        # The reason the in-BPF filter is family-scoped at all.
        assert not [e for e in mine if e["raw"]["family"] == AF_NETLINK], (
            f"AF_NETLINK SOCK_RAW leaked past the family scope: {mine}"
        )
        # A plain AF_INET SOCK_STREAM socket is not raw and must not appear.
        assert not [e for e in mine if e["network"]["socket_family"] == "AF_INET"], (
            f"non-raw AF_INET socket leaked past the type check: {mine}"
        )
    finally:
        for sock in (tcp_sock, netlink_sock, packet_sock):
            if sock is not None:
                sock.close()
        worker.stop()
