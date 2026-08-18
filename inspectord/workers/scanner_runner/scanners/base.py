"""Scanner adapter contract (design §4.1).

One adapter per scanner. An adapter knows three things and nothing else:

* how to invoke its scanner (``argv``),
* what the scanner's exit status *means* (``interpret_exit``) — never a
  boolean, see design decision 10,
* how to turn its output into normalized findings (``parse``).

Everything else — scheduling, single-flight, timeouts, process-group cleanup,
event construction — lives in the runner, so adding a scanner is a small,
pure-function module with pure-function tests.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class ScanOutcome(StrEnum):
    """What one completed scan means.

    ``clean`` and ``findings`` are both *successful* scans; only ``failure``
    means the scan did not produce a trustworthy answer.
    """

    clean = "clean"
    findings = "findings"
    failure = "failure"


@dataclass(frozen=True)
class Finding:
    """One normalized scanner finding; maps 1:1 onto a ``scan_finding`` Event."""

    indicator_type: str
    """``threat.indicator.type`` — "aide_change" | "rkhunter_test" | "yara_rule"."""

    indicator_value: str
    """``threat.indicator.value`` — the scanner-specific identifier."""

    raw_line: str
    """The scanner output line this finding was parsed from (untrusted)."""

    category: str = "file"
    """ECS ``event.category`` for this finding; "process" when not file-scoped."""

    path: str | None = None
    """``file.path``, when the scanner names a file."""

    hashes: dict[str, str] | None = None
    """``file.hash``, when the scanner reports one (e.g. ``{"sha256": "..."}``)."""

    severity: str | None = None
    """The SCANNER's own severity, preserved as data (design decision 7).

    ``None`` when the scanner has no notion of severity — the runner then omits
    the key entirely rather than inventing one.
    """

    message: str | None = None
    """Human-readable one-liner for ``event.message``."""


class ScannerAdapter(Protocol):
    """The three-method surface every scanner adapter implements."""

    name: str
    """Config key and ``raw.scanner`` value: "aide" | "rkhunter" | "yara"."""

    binary: str
    """Probed with ``shutil.which`` before every run (design decision 14)."""

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        """Build the argv for one scan. Never a shell string."""
        ...

    def interpret_exit(self, code: int) -> ScanOutcome:
        """Map the scanner's exit status to an outcome. NEVER a ``code == 0`` boolean."""
        ...

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        """Parse scanner output into findings. MUST NOT raise on garbage input."""
        ...
