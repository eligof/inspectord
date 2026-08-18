"""inspectord-process-collector-ptrace worker entry point.

Loads the sys_enter_ptrace syscall tracepoint via the inspectord_native Rust
extension, polls the PTRACE_EVENTS ring buffer, and emits one normalized
ptrace_call Event per record. Only cross-process calls in the
injection-relevant request set reach userspace; the filtering happens in-BPF
(see docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md
section 3.1).

Run standalone (for debugging):
  sudo python -m inspectord.workers.process_collector_ptrace --sink-path -

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
    from inspectord._native import ProcessPtraceStream  # noqa: PLC0415

    stream: _StreamProtocol = ProcessPtraceStream()
    return stream


class ProcessCollectorPtraceWorker:
    """Polls a ProcessPtraceStream and writes one Event per record.

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
        target_pid = int(record["target_pid"])
        # target_pid is a TID in the *caller's* pid namespace, so for
        # namespaced callers (flatpak/bwrap/docker) it is not a host pid.
        # Rule templates say "as seen by the caller" rather than asserting one.
        process: dict[str, Any] = {
            "pid": int(record["pid"]),
            "name": str(record["comm"]),
            "ptrace_request": str(record["request_name"]),
            "target_pid": target_pid,
            "target": {"pid": target_pid},
        }
        event = build_event(
            module="process_collector_ptrace",
            action="ptrace_call",
            category=["process"],
            type_=["access"],
            severity="info",
            ts=ts,
            host={"name": self._host_name},
            user={"id": str(record["uid"])},
            process=process,
            raw={
                "source": "ebpf:sys_enter_ptrace",
                "request": int(record["request"]),
            },
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspectord-process-collector-ptrace",
        description="eBPF cross-process ptrace collector; writes NDJSON Events to a sink.",
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
    worker = ProcessCollectorPtraceWorker(sink=sink)
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
