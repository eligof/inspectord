"""inspectord-outbound-connection-tracker worker entry point.

Loads the inet_sock_set_state tracepoint via the inspectord_native Rust
extension, polls the CONNECT_EVENTS ring buffer, and emits one normalized
outbound_connection Event per IPv4 SYN_SENT -> ESTABLISHED transition the
kernel observes. Loopback connections are already filtered at the native
boundary.

Run standalone (for debugging):
  sudo python -m inspectord.workers.outbound_connection_tracker --sink-path -

Or under the supervisor (the normal case).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Protocol

from inspectord.parsers.base import build_event


class _StreamProtocol(Protocol):
    def poll(self, timeout_ms: int) -> list[dict[str, Any]]: ...
    def close(self) -> None: ...


_DEFAULT_HOSTNAME = socket.gethostname()


def _default_stream_factory() -> _StreamProtocol:
    from inspectord._native import ProcessConnectStream  # noqa: PLC0415

    stream: _StreamProtocol = ProcessConnectStream()
    return stream


class OutboundConnectionTrackerWorker:
    """Polls a ProcessConnectStream and writes one Event per record.

    The stream_factory + sink injection makes the worker unit-testable
    without loading real eBPF programs.
    """

    def __init__(
        self,
        *,
        stream_factory: Callable[[], _StreamProtocol] = _default_stream_factory,
        sink: IO[bytes],
        host_name: str = _DEFAULT_HOSTNAME,
    ) -> None:
        self._stream_factory = stream_factory
        self._sink = sink
        self._host_name = host_name
        self._stream: _StreamProtocol | None = None
        self._wall_offset_ns: int = 0

    def start(self) -> None:
        self._stream = self._stream_factory()
        wall_ns = int(datetime.now(tz=UTC).timestamp() * 1e9)
        mono_ns = time.monotonic_ns()
        self._wall_offset_ns = wall_ns - mono_ns

    def step(self, *, poll_timeout_ms: int = 200) -> None:
        if self._stream is None:
            raise RuntimeError("worker not started")
        for record in self._stream.poll(poll_timeout_ms):
            event = self._record_to_event(record)
            self._sink.write(json.dumps(event).encode() + b"\n")
            self._sink.flush()

    def stop(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _record_to_event(self, record: dict[str, Any]) -> dict[str, Any]:
        ts_ns = int(record["timestamp_ns"]) + self._wall_offset_ns
        ts = datetime.fromtimestamp(ts_ns / 1e9, tz=UTC)
        process: dict[str, Any] = {
            "pid": int(record["pid"]),
            "name": str(record["comm"]),
        }
        event = build_event(
            module="outbound_connection_tracker",
            action="outbound_connection",
            category=["network"],
            type_=["connection", "start"],
            severity="info",
            ts=ts,
            host={"name": self._host_name},
            user={"id": str(record["uid"])},
            process=process,
            source={"ip": str(record["saddr"]), "port": int(record["sport"])},
            destination={"ip": str(record["daddr"]), "port": int(record["dport"])},
            network={"transport": "tcp", "direction": "egress"},
            raw={"source": "ebpf:inet_sock_set_state"},
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspectord-outbound-connection-tracker",
        description="eBPF outbound IPv4 TCP connection tracker; writes NDJSON Events to a sink.",
    )
    parser.add_argument(
        "--sink-path",
        default="-",
        help="Path to write NDJSON events (default: stdout, '-' = stdout)",
    )
    parser.add_argument(
        "--poll-timeout-ms",
        type=int,
        default=200,
        help="Ring-buffer poll timeout per iteration",
    )
    args = parser.parse_args(argv)

    sink = _open_sink(args.sink_path)
    worker = OutboundConnectionTrackerWorker(sink=sink)
    worker.start()
    try:
        while True:
            worker.step(poll_timeout_ms=args.poll_timeout_ms)
    except KeyboardInterrupt:
        pass
    finally:
        worker.stop()
        if sink not in (sys.stdout.buffer, sys.stderr.buffer):
            sink.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
