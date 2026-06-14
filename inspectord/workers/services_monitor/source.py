"""services_monitor source — captures systemd service snapshots and diffs them.

Detects service additions, removals, and state changes by periodically running
``systemctl list-units --type=service --all --output=json`` and comparing
against a baseline.  Tests inject ``runner``/``capture`` callables so no real
systemctl invocation or special capabilities are needed at test time.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from typing import Any


def _capture_units(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Capture the current systemd service unit list as raw JSON text.

    Runs ``systemctl list-units --type=service --all --output=json`` via
    *runner*.  Returns ``result.stdout`` when the command succeeds (returncode
    == 0), or ``""`` on a non-zero exit code, ``FileNotFoundError``, or any
    ``subprocess.SubprocessError`` (including ``TimeoutExpired``).

    An empty string signals "couldn't read" to callers — it is distinct from a
    valid-but-empty JSON array (``"[]"``).
    """
    try:
        result = runner(
            ["systemctl", "list-units", "--type=service", "--all", "--output=json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return ""
    except subprocess.SubprocessError:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout


def parse_units(text: str) -> dict[str, dict[str, Any]]:
    """Parse the JSON text returned by ``systemctl list-units --output=json``.

    The input is a JSON array of objects each containing at least a ``"unit"``
    key.  Elements that are not dicts, or that lack a ``"unit"`` key, are
    silently skipped.  Missing ``"active"``, ``"sub"``, and ``"load"`` fields
    default to ``""``.

    Returns:
        ``{unit_name: {"active": str, "sub": str, "load": str}}``

    Returns ``{}`` for blank/whitespace-only text or invalid JSON.
    """
    if not text or not text.strip():
        return {}
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        unit = item.get("unit")
        if not unit:
            continue
        result[unit] = {
            "active": item.get("active", ""),
            "sub": item.get("sub", ""),
            "load": item.get("load", ""),
        }
    return result


def diff_units(
    prev: dict[str, dict[str, Any]],
    curr: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compare two service unit snapshots and return change records.

    Three change types are detected:

    - **service_added**: unit present in *curr* but not *prev*.
    - **service_removed**: unit present in *prev* but not *curr*.
    - **service_state_changed**: unit in both, but ``(active, sub)`` differ.

    The result list is sorted deterministically by ``(action, unit)``.
    """
    records: list[dict[str, Any]] = []
    for unit, info in curr.items():
        if unit not in prev:
            records.append(
                {
                    "action": "service_added",
                    "unit": unit,
                    "active": info["active"],
                    "sub": info["sub"],
                    "load": info["load"],
                }
            )
    for unit, info in prev.items():
        if unit not in curr:
            records.append(
                {
                    "action": "service_removed",
                    "unit": unit,
                    "previous_active": info["active"],
                    "previous_sub": info["sub"],
                }
            )
    for unit, curr_info in curr.items():
        if unit not in prev:
            continue
        prev_info = prev[unit]
        if (curr_info["active"], curr_info["sub"]) != (prev_info["active"], prev_info["sub"]):
            records.append(
                {
                    "action": "service_state_changed",
                    "unit": unit,
                    "active": curr_info["active"],
                    "sub": curr_info["sub"],
                    "previous_active": prev_info["active"],
                    "previous_sub": prev_info["sub"],
                }
            )
    records.sort(key=lambda r: (r["action"], r["unit"]))
    return records


class ServicesSource:
    """Polls systemd service state and emits records when services change.

    The baseline snapshot is captured in ``__init__``, so services already
    present at startup are NOT emitted on the first ``poll``.  Inject
    *capture* to avoid real subprocess calls in tests.

    Transient capture failures (``capture()`` returning ``""``) are silently
    ignored — the baseline is preserved so a temporary ``systemctl`` failure
    does not trigger a flood of false ``service_removed`` records.

    If the very first capture (in ``__init__``) fails, the baseline is empty.
    The first successful poll after that adopts the returned snapshot silently
    rather than emitting every existing service as ``service_added``.
    """

    def __init__(
        self,
        *,
        capture: Callable[[], str] = _capture_units,
    ) -> None:
        self._capture = capture
        self._closed = False
        self._units = parse_units(capture())

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        """Sleep *timeout_ms* ms, capture service state, and return change records.

        Returns ``[]`` when:
        - the capture returns ``""`` (transient failure — baseline preserved),
        - the parsed snapshot is empty,
        - the baseline was empty and is being adopted for the first time.

        Raises:
            RuntimeError: if the source has been closed.
        """
        if self._closed:
            raise RuntimeError("source is closed")
        time.sleep(timeout_ms / 1000)
        text = self._capture()
        if text == "":
            # Transient failure — do NOT diff against an empty set.
            return []
        curr = parse_units(text)
        if not curr:
            # Parsed to nothing (e.g. valid JSON empty array with no services).
            return []
        if not self._units:
            # Baseline not yet established — adopt silently to avoid a flood.
            self._units = curr
            return []
        records = diff_units(self._units, curr)
        self._units = curr
        return records

    def close(self) -> None:
        """Mark the source closed (idempotent; no external resources to release)."""
        self._closed = True
