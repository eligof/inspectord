"""inspectord-kmod-watcher worker entry point.

Polls /proc/modules via ProcModulesSource, diffs successive snapshots, and
emits one normalized Event per kernel module load or unload detected.
Modules present at startup are baseline-suppressed by the source.

Run standalone (for debugging):
  python -m inspectord.workers.kmod_watcher --sink-path -

Or under the supervisor (the normal case).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
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
    from inspectord.workers.kmod_watcher.source import ProcModulesSource  # noqa: PLC0415

    stream: _StreamProtocol = ProcModulesSource()
    return stream


class KmodWatcherWorker:
    """Polls a ProcModulesSource and writes one Event per kernel module change.

    The stream_factory + sink injection makes the worker unit-testable
    without touching the real /proc/modules.
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

    def start(self) -> None:
        """Open the stream; /proc/modules baseline is captured here."""
        self._stream = self._stream_factory()

    def step(self, *, poll_timeout_ms: int = 1000) -> None:
        """Poll the stream once and write any resulting events to the sink."""
        if self._stream is None:
            raise RuntimeError("worker not started")
        for record in self._stream.poll(poll_timeout_ms):
            event = self._record_to_event(record)
            self._sink.write(json.dumps(event).encode() + b"\n")
            self._sink.flush()

    def stop(self) -> None:
        """Close the stream."""
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _record_to_event(self, record: dict[str, Any]) -> dict[str, Any]:
        ts = datetime.now(tz=UTC)
        action = record["action"]
        name = str(record["name"])

        if action == "loaded":
            event_action = "kmod_loaded"
            type_ = ["installation"]
            message = f"kernel module {name} loaded"
            raw: dict[str, Any] = {
                "source": "/proc/modules",
                "module_name": name,
                "module_size": int(record["size"]),
                "module_refcount": int(record["refcount"]),
            }
        else:
            event_action = "kmod_unloaded"
            type_ = ["deletion"]
            message = f"kernel module {name} unloaded"
            raw = {
                "source": "/proc/modules",
                "module_name": name,
            }

        event = build_event(
            module="kmod_watcher",
            action=event_action,
            category=["driver"],
            type_=type_,
            severity="info",
            ts=ts,
            host={"name": self._host_name},
            labels=["kmod"],
            message=message,
            raw=raw,
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the inspectord-kmod-watcher worker."""
    parser = argparse.ArgumentParser(
        prog="inspectord-kmod-watcher",
        description=(
            "Kernel module load/unload watcher via /proc/modules; writes NDJSON Events to a sink."
        ),
    )
    parser.add_argument(
        "--sink-path",
        default="-",
        help="Path to write NDJSON events (default: stdout, '-' = stdout)",
    )
    parser.add_argument(
        "--poll-timeout-ms",
        type=int,
        default=1000,
        help="Poll interval per iteration in milliseconds (default: 1000)",
    )
    args = parser.parse_args(argv)

    sink = _open_sink(args.sink_path)
    worker = KmodWatcherWorker(sink=sink)
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
