"""kmod_watcher source — polls /proc/modules and diffs snapshots to detect module changes."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any


def _read_proc_modules() -> str:
    """Read and return the raw text of /proc/modules."""
    with open("/proc/modules") as fh:
        return fh.read()


def parse_proc_modules(text: str) -> dict[str, dict[str, Any]]:
    """Parse the text of /proc/modules into a mapping of name -> info.

    Each non-blank line has the form::

        name size refcount deps state address

    where ``deps`` is comma-separated with no spaces, so ``line.split()``
    yields exactly 6 tokens.  Lines with fewer than 3 tokens or
    non-integer size/refcount are silently skipped.

    Returns:
        ``{name: {"size": int, "refcount": int}}``
    """
    result: dict[str, dict[str, Any]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        try:
            size = int(parts[1])
            refcount = int(parts[2])
        except ValueError:
            continue
        result[name] = {"size": size, "refcount": refcount}
    return result


def diff_modules(
    prev: dict[str, dict[str, Any]],
    curr: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compare two parsed /proc/modules snapshots and return change records.

    For each name in ``curr`` but not ``prev``: a ``{"action": "loaded", ...}`` record.
    For each name in ``prev`` but not ``curr``: a ``{"action": "unloaded", "name": ...}`` record.

    The result is sorted by ``(action, name)`` for deterministic output.
    """
    records: list[dict[str, Any]] = []
    for name, info in curr.items():
        if name not in prev:
            records.append(
                {
                    "action": "loaded",
                    "name": name,
                    "size": info["size"],
                    "refcount": info["refcount"],
                }
            )
    for name in prev:
        if name not in curr:
            records.append({"action": "unloaded", "name": name})
    records.sort(key=lambda r: (r["action"], r["name"]))
    return records


class ProcModulesSource:
    """Polls /proc/modules on each call to ``poll`` and returns diff records.

    Inject ``reader`` to avoid touching the real filesystem in tests.

    The baseline snapshot is captured in ``__init__``, so modules already
    present at startup are NOT reported as "loaded".
    """

    def __init__(
        self,
        *,
        reader: Callable[[], str] = _read_proc_modules,
    ) -> None:
        self._reader = reader
        self._closed = False
        self._snapshot = parse_proc_modules(reader())

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        """Sleep for *timeout_ms* ms, read /proc/modules, and return diff records."""
        time.sleep(timeout_ms / 1000)
        curr = parse_proc_modules(self._reader())
        records = diff_modules(self._snapshot, curr)
        self._snapshot = curr
        return records

    def close(self) -> None:
        """Mark the source closed (idempotent; no external resources to release)."""
        self._closed = True
