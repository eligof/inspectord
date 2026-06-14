"""inspectord-services-monitor worker entry point.

Polls the systemd service unit list via ServicesSource, diffs successive
snapshots, and emits one normalized Event per service addition, removal, or
state change detected.  The baseline snapshot at startup is suppressed by the
source.

Run standalone (for debugging):
  python -m inspectord.workers.services_monitor --sink-path -

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
    from inspectord.workers.services_monitor.source import ServicesSource  # noqa: PLC0415

    stream: _StreamProtocol = ServicesSource()
    return stream


class ServicesMonitorWorker:
    """Polls a ServicesSource and writes one Event per service change.

    The stream_factory + sink injection makes the worker unit-testable
    without shelling out to systemctl.
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
        """Open the stream; baseline service snapshot is captured here."""
        self._stream = self._stream_factory()

    def step(self, *, poll_timeout_ms: int = 5000) -> None:
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
        """Dispatch on record['action'] and build a normalized Event."""
        action = record["action"]
        unit: str = record["unit"]

        if action == "service_added":
            active: str = record["active"]
            sub: str = record["sub"]
            load: str = record["load"]
            kwargs: dict[str, Any] = dict(
                action="service_added",
                type_=["installation"],
                service={"name": unit, "state": active},
                message=f"service {unit} appeared (active={active}, sub={sub}, load={load})",
                raw={"source": "systemctl", "active": active, "sub": sub, "load": load},
            )
        elif action == "service_removed":
            previous_active: str = record["previous_active"]
            previous_sub: str = record["previous_sub"]
            previous_load: str = record["previous_load"]
            kwargs = dict(
                action="service_removed",
                type_=["deletion"],
                service={"name": unit, "state": previous_active},
                message=(
                    f"service {unit} disappeared (was active={previous_active}, sub={previous_sub})"
                ),
                raw={
                    "source": "systemctl",
                    "previous_active": previous_active,
                    "previous_sub": previous_sub,
                    "previous_load": previous_load,
                },
            )
        elif action == "service_state_changed":
            active = record["active"]
            sub = record["sub"]
            load = record["load"]
            previous_active = record["previous_active"]
            previous_sub = record["previous_sub"]
            previous_load = record["previous_load"]
            kwargs = dict(
                action="service_state_changed",
                type_=["change"],
                service={"name": unit, "state": active},
                message=(
                    f"service {unit} changed: {previous_active}/{previous_sub} -> {active}/{sub}"
                ),
                raw={
                    "source": "systemctl",
                    "active": active,
                    "sub": sub,
                    "load": load,
                    "previous_active": previous_active,
                    "previous_sub": previous_sub,
                    "previous_load": previous_load,
                },
            )
        else:
            raise ValueError(f"unknown action: {action!r}")

        event = build_event(
            module="services_monitor",
            category=["configuration"],
            severity="info",
            ts=datetime.now(tz=UTC),
            host={"name": self._host_name},
            labels=["service"],
            **kwargs,
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the inspectord-services-monitor worker."""
    parser = argparse.ArgumentParser(
        prog="inspectord-services-monitor",
        description=(
            "Systemd service state change detector via systemctl; writes NDJSON Events to a sink."
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
        default=5000,
        help=(
            "Poll interval per iteration in milliseconds (default: 5000; there are"
            " many services and each poll shells out to systemctl, so poll less often"
            " than the /proc collectors)"
        ),
    )
    args = parser.parse_args(argv)

    sink = _open_sink(args.sink_path)
    worker = ServicesMonitorWorker(sink=sink)
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
