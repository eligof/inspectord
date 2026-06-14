"""inspectord-firewall-inspector worker entry point.

Polls the active firewall ruleset (nftables or iptables) via FirewallSource,
diffs successive snapshots, and emits one normalized Event per ruleset change
detected.  The baseline ruleset at startup is suppressed by the source.

Run standalone (for debugging):
  python -m inspectord.workers.firewall_inspector --sink-path -

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
    from inspectord.workers.firewall_inspector.source import FirewallSource  # noqa: PLC0415

    stream: _StreamProtocol = FirewallSource()
    return stream


class FirewallInspectorWorker:
    """Polls a FirewallSource and writes one Event per firewall ruleset change.

    The stream_factory + sink injection makes the worker unit-testable
    without shelling out to nft or iptables.
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
        """Open the stream; baseline ruleset snapshot is captured here."""
        self._stream = self._stream_factory()

    def step(self, *, poll_timeout_ms: int = 2000) -> None:
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
        # FirewallSource emits a single action, so it's hardcoded below rather
        # than dispatched from record["action"]; assert to keep that explicit.
        assert record["action"] == "firewall_ruleset_changed"
        event = build_event(
            module="firewall_inspector",
            action="firewall_ruleset_changed",
            kind="state",
            category=["configuration"],
            type_=["change"],
            severity="medium",
            ts=datetime.now(tz=UTC),
            host={"name": self._host_name},
            labels=["firewall"],
            message=(
                f"firewall ruleset changed ({record['backend']}): "
                f"+{record['added']} -{record['removed']} lines"
            ),
            raw={
                "source": record["backend"],
                "digest": record["digest"],
                "previous_digest": record["previous_digest"],
                "added": record["added"],
                "removed": record["removed"],
                "diff": record["diff"],
            },
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the inspectord-firewall-inspector worker."""
    parser = argparse.ArgumentParser(
        prog="inspectord-firewall-inspector",
        description=(
            "Firewall ruleset change detector via nft/iptables; writes NDJSON Events to a sink."
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
        default=2000,
        help=(
            "Poll interval per iteration in milliseconds (default: 2000; firewall "
            "changes are rare and each poll shells out to nft/iptables)"
        ),
    )
    args = parser.parse_args(argv)

    sink = _open_sink(args.sink_path)
    worker = FirewallInspectorWorker(sink=sink)
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
