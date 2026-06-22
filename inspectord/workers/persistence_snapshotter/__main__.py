"""inspectord-persistence-snapshotter worker entry point.

Polls the filesystem-only persistence inventory via ``source.snapshot()``, diffs
successive snapshots, and emits one normalised Event per added/removed entry.

Two deliberate divergences from the listening-socket worker (spec §3.2):

1. **No baseline suppression.** ``self._prev`` starts empty, so the FIRST
   ``step()`` emits every current entry as ``persistence_added`` — this is how
   the persistence state table is populated.
2. **Per-source carry-forward diff.** When ``snapshot()`` reports a kind in
   ``failed_kinds`` (its source was unreadable this poll), the previous poll's
   entries of that kind are carried forward instead of being emitted as
   ``persistence_removed`` — a transient read failure must not look like the
   attacker removing their persistence.

Run standalone (for debugging):
  python -m inspectord.workers.persistence_snapshotter --sink-path -

Or under the supervisor (the normal case).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from inspectord.parsers.base import build_event
from inspectord.workers.persistence_snapshotter.source import AUTHKEY, snapshot

_DEFAULT_HOSTNAME = socket.gethostname()

# /proc/net is an event stream; persistence sources are static filesystem state
# that changes slowly, so a coarse poll interval keeps the I/O cost negligible.
_DEFAULT_POLL_INTERVAL_S = 30.0

_SnapshotFn = Callable[[], tuple[dict[str, dict[str, Any]], set[str]]]


class PersistenceSnapshotterWorker:
    """Polls a persistence snapshot fn and writes one Event per persistence change.

    The snapshot_fn + sink injection makes the worker unit-testable without
    touching the real host filesystem.
    """

    def __init__(
        self,
        *,
        snapshot_fn: _SnapshotFn = snapshot,
        sink: IO[bytes],
        host_name: str = _DEFAULT_HOSTNAME,
    ) -> None:
        self._snapshot_fn = snapshot_fn
        self._sink = sink
        self._host_name = host_name
        # Empty baseline: the first step emits the full current inventory as added.
        self._prev: dict[str, dict[str, Any]] = {}
        # First step is the baseline catch-up: its added events are marked
        # first_seen so the rule engine drops them (no flood on daemon restart).
        self._seeded = False

    def start(self) -> None:
        """No-op; the source is stateless and read fresh on every step()."""

    def step(self) -> None:
        """Take one snapshot, diff it against the previous one, emit events."""
        current, failed = self._snapshot_fn()
        baseline = not self._seeded
        self._seeded = True
        effective = dict(current)
        # Carry forward previous entries whose source failed this poll, so a
        # transient read error does not masquerade as a persistence removal.
        for key, attrs in self._prev.items():
            if attrs["kind"] in failed and key not in effective:
                effective[key] = attrs
        for key in effective.keys() - self._prev.keys():
            self._emit("persistence_added", effective[key], first_seen=baseline)
        for key in self._prev.keys() - effective.keys():
            self._emit("persistence_removed", self._prev[key], first_seen=False)
        self._prev = effective

    def stop(self) -> None:
        """No-op; nothing to close."""

    def _emit(self, action: str, attrs: dict[str, Any], *, first_seen: bool = False) -> None:
        sev = "medium" if attrs["kind"] == AUTHKEY else "low"
        ev = build_event(
            module="persistence_snapshotter",
            action=action,
            category=["host"],
            type_=["start"] if action == "persistence_added" else ["end"],
            severity=sev,
            host={"name": self._host_name},
            persistence={
                "kind": attrs["kind"],
                "name": attrs.get("name"),
                "source_path": attrs.get("source_path"),
                "details": attrs.get("details"),
                "key": attrs["key"],
            },
            labels=["persistence", f"persist:{attrs['kind']}"],
            message=f"{action} {attrs['kind']} {attrs.get('name', '')}",
            raw={"source": attrs.get("source_path")},
            first_seen=first_seen,
        )
        self._sink.write(json.dumps(ev.model_dump(mode="json", exclude_none=True)).encode() + b"\n")
        self._sink.flush()


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the inspectord-persistence-snapshotter worker."""
    parser = argparse.ArgumentParser(
        prog="inspectord-persistence-snapshotter",
        description=(
            "New/removed persistence watcher (cron, systemd timers, XDG autostart,"
            " authorized_keys); writes NDJSON Events to a sink."
        ),
    )
    parser.add_argument(
        "--sink-path",
        default="-",
        help="Path to write NDJSON events (default: stdout, '-' = stdout)",
    )
    parser.add_argument(
        "--poll-interval-s",
        type=float,
        default=_DEFAULT_POLL_INTERVAL_S,
        help=(
            "Seconds between snapshots (default: 30; persistence is static "
            "filesystem state and changes slowly)"
        ),
    )
    args = parser.parse_args(argv)

    sink = _open_sink(args.sink_path)
    worker = PersistenceSnapshotterWorker(sink=sink)
    worker.start()
    try:
        while True:
            worker.step()
            time.sleep(args.poll_interval_s)
    except KeyboardInterrupt:
        pass
    finally:
        worker.stop()
        if sink not in (sys.stdout.buffer, sys.stderr.buffer):
            sink.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
