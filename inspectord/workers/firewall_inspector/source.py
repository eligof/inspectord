"""firewall_inspector source — captures firewall ruleset snapshots and diffs them.

Supports nftables (``nft list ruleset``) and iptables (``iptables-save``) with
automatic backend detection.  Tests inject ``runner``/``capture`` callables so
no root privileges are required at test time.
"""

from __future__ import annotations

import difflib
import hashlib
import subprocess
import time
from collections.abc import Callable
from typing import Any


def _capture_ruleset(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[str, str]:
    """Capture the active firewall ruleset using the first available backend.

    Tries backends in order:

    1. **nftables**: ``nft list ruleset``
    2. **iptables**: ``iptables-save``

    The injected *runner* replaces ``subprocess.run`` in tests so no shell-out
    occurs.  ``FileNotFoundError``, ``subprocess.SubprocessError``
    (including ``TimeoutExpired``), or a non-zero return code for a backend
    causes a fall-through to the next candidate.

    Returns:
        ``(backend, ruleset_text)`` where *backend* is one of
        ``"nftables"``, ``"iptables"``, or ``"none"``.
    """
    backends: list[tuple[str, list[str]]] = [
        ("nftables", ["nft", "list", "ruleset"]),
        ("iptables", ["iptables-save"]),
    ]
    for name, cmd in backends:
        try:
            result = runner(cmd, capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            continue
        except subprocess.SubprocessError:
            continue
        if result.returncode == 0:
            return (name, result.stdout)
    return ("none", "")


def _digest(text: str) -> str:
    """Return the SHA-256 hex digest of *text* encoded as UTF-8."""
    return hashlib.sha256(text.encode()).hexdigest()


def _diff_summary(old: str, new: str, *, max_lines: int = 50) -> dict[str, Any]:
    """Produce a unified-diff summary between *old* and *new* ruleset texts.

    Counts lines added (starting with ``+`` but not ``+++``) and lines removed
    (starting with ``-`` but not ``---``).  The unified diff is truncated to at
    most *max_lines* lines; a ``… (truncated)`` marker is appended when the
    diff exceeds that limit.

    Returns:
        ``{"added": int, "removed": int, "diff": str}``
    """
    diff_lines = list(
        difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            lineterm="",
        )
    )
    added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    if len(diff_lines) > max_lines:
        truncated_lines = [*diff_lines[:max_lines], "… (truncated)"]
        diff_text = "\n".join(truncated_lines)
    else:
        diff_text = "\n".join(diff_lines)
    return {"added": added, "removed": removed, "diff": diff_text}


class FirewallSource:
    """Polls the active firewall ruleset and emits records when it changes.

    The baseline snapshot is captured in ``__init__``, so the ruleset present
    at startup is NOT emitted on the first ``poll``.  Inject *capture* to
    avoid subprocesses in tests.

    Backend transitions to/from ``"none"`` (firewall not readable) are silently
    adopted as a new baseline rather than emitted as spurious changes.
    """

    def __init__(
        self,
        *,
        capture: Callable[[], tuple[str, str]] = _capture_ruleset,
    ) -> None:
        self._capture = capture
        self._closed = False
        backend, text = capture()
        self._backend = backend
        self._text = text
        self._digest = _digest(text)

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        """Sleep for *timeout_ms* ms, capture the ruleset, and return change records.

        Returns an empty list when the ruleset is unchanged, when readability is
        gained for the first time (``none → backend``), or when the firewall
        becomes unreadable (``backend → none``).

        Raises:
            RuntimeError: if the source has been closed.
        """
        if self._closed:
            raise RuntimeError("source is closed")
        time.sleep(timeout_ms / 1000)
        new_backend, new_text = self._capture()
        new_digest = _digest(new_text)

        if new_digest == self._digest:
            # No change — update stored state (cheap) and return early.
            self._backend = new_backend
            self._text = new_text
            self._digest = new_digest
            return []

        # Silently adopt if either side is "none" / empty.
        prev_is_none = self._backend == "none" or not self._text
        new_is_none = new_backend == "none"
        if prev_is_none or new_is_none:
            self._backend = new_backend
            self._text = new_text
            self._digest = new_digest
            return []

        # Real ruleset change between two readable backends.
        summary = _diff_summary(self._text, new_text)
        record: dict[str, Any] = {
            "action": "firewall_ruleset_changed",
            "backend": new_backend,
            "previous_digest": self._digest,
            "digest": new_digest,
            "added": summary["added"],
            "removed": summary["removed"],
            "diff": summary["diff"],
        }
        self._backend = new_backend
        self._text = new_text
        self._digest = new_digest
        return [record]

    def close(self) -> None:
        """Mark the source closed (idempotent; no external resources to release)."""
        self._closed = True
