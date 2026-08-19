"""inspectord-udev-monitor worker entry point.

Streams device hotplug events from UdevMonitorSource (a long-lived
``udevadm monitor --property --udev`` subprocess) and emits one normalized
Event per device add, remove, or change.

Run standalone (for debugging):
  python -m inspectord.workers.udev_monitor --sink-path -

Or under the supervisor (the normal case).
"""

from __future__ import annotations

import argparse
import json
import signal
import socket
import sys
import threading
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
    from inspectord.workers.udev_monitor.source import UdevMonitorSource  # noqa: PLC0415

    stream: _StreamProtocol = UdevMonitorSource()
    return stream


class UdevMonitorWorker:
    """Polls a UdevMonitorSource and writes one Event per device hotplug event.

    The stream_factory + sink injection makes the worker unit-testable without
    spawning a real udevadm subprocess.
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
        """Open the stream; the udevadm subprocess is spawned here."""
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
        """Dispatch on record['action'] and build a normalized Event."""
        action = record["action"]
        subsystem: str = record["subsystem"]
        name: str = record["name"]
        vendor: str = record["vendor"]
        product: str = record["product"]
        devpath: str = record["devpath"]

        device = {
            "name": name,
            "kind": record["devtype"] or subsystem,
            "vendor": vendor,
            "product": product,
            "serial": record["serial"],
        }

        if action == "add":
            kwargs: dict[str, Any] = dict(
                action="device_added",
                type_=["installation"],
                message=f"{subsystem} device added: {name} {vendor}:{product} at {devpath}",
            )
        elif action == "remove":
            kwargs = dict(
                action="device_removed",
                type_=["deletion"],
                message=f"{subsystem} device removed: {name} {vendor}:{product} at {devpath}",
            )
        else:
            kwargs = dict(
                action="device_changed",
                type_=["change"],
                message=(
                    f"{subsystem} device changed ({action}): {name} {vendor}:{product} at {devpath}"
                ),
            )

        event = build_event(
            module="udev_monitor",
            category=["host"],
            severity="info",
            ts=datetime.now(tz=UTC),
            host={"name": self._host_name},
            labels=["device"],
            device=device,
            # "source" last so a hostile/spoofed property line can't clobber the marker.
            raw={**record["properties"], "source": "udevadm"},
            **kwargs,
        )
        return event.model_dump(mode="json", exclude_none=True)


def _install_stop_handlers(stop: threading.Event) -> None:
    """Make SIGTERM/SIGINT set *stop* instead of killing the process outright.

    The supervisor stops a worker with SIGTERM, and Python's default
    disposition for it terminates the interpreter immediately -- ``finally``
    blocks never run.  For this worker that leaks: ``main`` never reaches
    ``worker.stop()``, so the long-lived ``udevadm monitor`` grandchild is
    never terminated and survives forever, reparented to init.  (Workers built
    on ``workers.contract.Worker`` already do this; this one has its own loop.)

    Signals can only be installed from the main thread; elsewhere this is a
    no-op and the ``KeyboardInterrupt`` path in ``main`` still applies.
    """
    if threading.current_thread() is not threading.main_thread():
        return
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the inspectord-udev-monitor worker."""
    parser = argparse.ArgumentParser(
        prog="inspectord-udev-monitor",
        description=(
            "Device hotplug detector via udevadm monitor; writes NDJSON Events to a sink."
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
        help=(
            "Poll interval per iteration in milliseconds (default: 1000; this is a"
            " streaming source, so poll often to keep event latency low)"
        ),
    )
    args = parser.parse_args(argv)

    sink = _open_sink(args.sink_path)
    worker = UdevMonitorWorker(sink=sink)
    # Installed before start(): a SIGTERM arriving while the child is being
    # spawned must still reach the teardown below, not kill us mid-spawn.
    stop = threading.Event()
    _install_stop_handlers(stop)
    worker.start()
    try:
        while not stop.is_set():
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
