"""Scanner adapter contract (design §4.1).

One adapter per scanner. An adapter knows four things and nothing else:

* how to invoke its scanner (``argv``),
* whether the scanner has everything it needs to run at all (``preflight``),
* what one finished run *means* (``interpret_outcome``) — never a boolean, and
  never the exit code alone, see design decision 10,
* how to turn its output into normalized findings (``parse``).

Everything else — scheduling, single-flight, timeouts, process-group cleanup,
event construction — lives in the runner, so adding a scanner is a small,
pure-function module with pure-function tests.

**Why ``interpret_outcome`` takes the output and not just the exit code.**
``man rkhunter``: "rkhunter will return a non-zero exit code if any error or
warning occurs." Measured on rkhunter 1.4.6: a check with real warnings exits
1, and a check refused because of an invalid argument *also* exits 1. The exit
code alone cannot tell a rootkit detection from a scanner that never ran, and
reporting a refusal as a detection is the exact inverse of the bug decision 10
exists to prevent. Only the output separates them, so every adapter is handed
it — AIDE, whose bitmask is self-describing, simply ignores it.

**The outcome principle for output-driven adapters** (rkhunter, YARA):

===================  ===========  =========
output has findings  exit code    outcome
===================  ===========  =========
yes                  anything     findings
no                   0            clean
no                   non-zero     failure
===================  ===========  =========

Parsed findings beat the exit code, so a partly-broken run never *hides* a
detection; "nothing found and a non-zero code" is the refusal case and is
always a failure, never a silent ``clean``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

# Everything a scanner prints is untrusted: it embeds filenames, and the only
# bytes a Linux filename cannot contain are `/` and NUL. A control character
# that survives into an event gets re-interpreted by whatever reads it next --
# a terminal, a log tailer, a line-oriented consumer -- so none of them ever
# reach an event. TAB is kept; it is ordinary whitespace in scanner output.
# DEL, C1 (\x7f-\x9f) and U+2028/U+2029 are in the set because `str.splitlines`
# treats several of them as line breaks.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]")


def sanitize_text(text: str) -> str:
    """Strip control characters from untrusted scanner text. Never raises.

    Sanitizing does **not** undo a line split that already happened: text an
    attacker got a newline into has already become two lines by the time a
    parser sees it. See the rkhunter adapter's "A filename can forge a warning
    header" for what that does and does not allow.
    """
    return _CONTROL_RE.sub("", text)


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

    def preflight(self, config: Mapping[str, Any]) -> str | None:
        """``None`` when the scanner can run; otherwise a short skip *reason*.

        The binary's presence is the runner's business (``shutil.which``); this
        is for per-scanner prerequisites the runner cannot know about — YARA
        with no rulesets shipped yet, for instance. Returning a reason makes
        that an explicit ``scan_skipped`` event instead of an argv that fails in
        a confusing way, and it is the same shape decision 14 already uses for a
        missing binary. MUST NOT raise.
        """
        ...

    def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome:
        """Map one finished run to an outcome. NEVER a ``code == 0`` boolean.

        Takes the output as well as the code because for some scanners the code
        alone is ambiguous — see the module docstring. MUST NOT raise.
        """
        ...

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        """Parse scanner output into findings. MUST NOT raise on garbage input."""
        ...
