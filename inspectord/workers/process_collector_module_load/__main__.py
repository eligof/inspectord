"""inspectord-process-collector-module-load worker entry point.

Loads the sys_enter_finit_module and sys_enter_init_module syscall tracepoints
via the inspectord_native Rust extension, polls the MODULE_LOAD_EVENTS ring
buffer, and emits one normalized module_load_attempt Event per record. There is
no in-BPF filter — module loads are rare, so every call is emitted (see
docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md
section 4).

This is complementary to, not a replacement for, the pure-Python kmod_watcher:
that worker polls loaded-module *state* (which module is loaded now), while
these tracepoints capture the *initiating process* in real time (who loaded
it), including attempts that fail.

Run standalone (for debugging):
  sudo python -m inspectord.workers.process_collector_module_load --sink-path -

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
    from inspectord._native import ProcessModuleLoadStream  # noqa: PLC0415

    stream: _StreamProtocol = ProcessModuleLoadStream()
    return stream


class ProcessCollectorModuleLoadWorker:
    """Polls a ProcessModuleLoadStream and writes one Event per record.

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
        variant_name = str(record["variant_name"])
        # fd/flags are finit_module's arguments; init_module has neither, and
        # the native side reports -1 / 0 for it rather than omitting the keys.
        fd = int(record["fd"])
        flags = int(record["flags"])
        process: dict[str, Any] = {
            "pid": int(record["pid"]),
            "name": str(record["comm"]),
            "module_load_variant": variant_name,
            "module_load_fd": fd,
            "module_load_flags": flags,
        }
        event = build_event(
            module="process_collector_module_load",
            action="module_load_attempt",
            category=["driver"],
            type_=["installation"],
            severity="info",
            ts=ts,
            host={"name": self._host_name},
            user={"id": str(record["uid"])},
            process=process,
            raw={
                "source": f"ebpf:sys_enter_{variant_name}",
                "variant": int(record["variant"]),
                "fd": fd,
                "flags": flags,
            },
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspectord-process-collector-module-load",
        description="eBPF kernel-module load collector; writes NDJSON Events to a sink.",
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
    worker = ProcessCollectorModuleLoadWorker(sink=sink)
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
