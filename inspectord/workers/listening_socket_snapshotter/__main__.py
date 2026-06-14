"""inspectord-listening-socket-snapshotter worker entry point.

Polls /proc/net/{tcp,tcp6,udp,udp6} via ListeningSocketSource, diffs successive
snapshots, and emits one normalised Event per new or removed listening socket
detected.  Sockets already listening at startup are baseline-suppressed by the
source.

Run standalone (for debugging):
  python -m inspectord.workers.listening_socket_snapshotter --sink-path -

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
    from inspectord.workers.listening_socket_snapshotter.source import (  # noqa: PLC0415
        ListeningSocketSource,
    )

    stream: _StreamProtocol = ListeningSocketSource()
    return stream


class ListeningSocketSnapshotterWorker:
    """Polls a ListeningSocketSource and writes one Event per listening-socket change.

    The stream_factory + sink injection makes the worker unit-testable
    without touching the real /proc/net files.
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
        """Open the stream; the baseline snapshot is captured here."""
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
        transport = "tcp" if record["proto"].startswith("tcp") else "udp"
        ip: str = record["ip"]
        port: int = record["port"]

        if record["action"] == "listener_added":
            action = "listener_added"
            type_ = ["start"]
            message = f"listening socket {ip}:{port}/{transport} opened"
        else:
            action = "listener_removed"
            type_ = ["end"]
            message = f"listening socket {ip}:{port}/{transport} closed"

        event = build_event(
            module="listening_socket_snapshotter",
            action=action,
            category=["network"],
            type_=type_,
            severity="info",
            ts=ts,
            host={"name": self._host_name},
            source={"ip": ip, "port": port},
            network={"transport": transport, "direction": "ingress"},
            labels=["listener"],
            message=message,
            raw={"source": f"/proc/net/{record['proto']}"},
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the inspectord-listening-socket-snapshotter worker."""
    parser = argparse.ArgumentParser(
        prog="inspectord-listening-socket-snapshotter",
        description=(
            "New/removed listening socket watcher via /proc/net/{tcp,tcp6,udp,udp6};"
            " writes NDJSON Events to a sink."
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
    worker = ListeningSocketSnapshotterWorker(sink=sink)
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
