"""AIDE adapter — ``aide --check`` against the inspectord-owned database.

AIDE's database is ours and lives under ``/var/lib/inspectord/aide/`` (parent
spec §30.6), so this scanner is fully deterministic and fully offline: nothing
here ever updates a signature database (design decision 8).

**Exit status is a bitmask, not a boolean** (design decision 10).  The
documented ``EXIT STATUS`` section of the AIDE manual (0.16-0.18 series; the
dependency manifest pins ``minimum_version: "0.18"``) defines::

    0   no differences
    1   new entries detected        \\
    2   removed entries detected     >  ORed together -> 1..7
    4   changed entries detected    /
    14  write error
    15  invalid argument error
    16  unimplemented function error
    17  invalid configureline error
    18  IO error
    19  version mismatch error
    20  exec error
    21  file lock error
    22  memory allocation error
    23  thread error
    24  database error
    25  received SIGINT, SIGTERM or SIGHUP

So a non-zero status in ``1..7`` means the scan **succeeded and found
something** — reporting it as a failure would turn every real detection into a
broken scan, which is the worst bug this worker could have.

``interpret_outcome`` is written as a range check with a ``failure`` default
rather than an enumeration of the error codes: a future AIDE that adds a new
error code is then reported as a failure (safe) instead of being silently
misread, while the low-bit range stays exact.

Verified 2026-08-19 against the **installed** AIDE 0.19.3 (``man aide``,
``EXIT STATUS``): 1/2/4 are additive difference flags and the error codes run
14-25 — two more than PR1 recorded, because 0.19 added 24 (database error) and
25 (killed by SIGINT/SIGTERM/SIGHUP). The range check needed no revision: both
already fell through to ``failure``, which is the safe direction, as do the
unallocated codes 8-13. Also measured here: ``--config /nonexistent --check``
exits 18 and an unknown flag exits 15.

Unlike rkhunter, AIDE needs no output to be classified, so
``interpret_outcome`` ignores its ``stdout``/``stderr`` arguments deliberately.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from inspectord.workers.scanner_runner.scanners.base import Finding, ScanOutcome

# Spec §30.6: the AIDE database and config are ours, under /var/lib/inspectord.
DEFAULT_CONFIG_PATH = "/var/lib/inspectord/aide/aide.conf"

# Section headers in an `aide --check` report. Compared against the stripped,
# lower-cased line, so the Summary block's `  Added entries:\t\t1` (which has a
# trailing count) never opens a section.
_SECTION_HEADERS = {
    "added entries:": "added",
    "added files:": "added",
    "removed entries:": "removed",
    "removed files:": "removed",
    "changed entries:": "changed",
    "changed files:": "changed",
}

# `<attribute-string>: <absolute path>` — e.g. `f++++++++++++++++: /etc/x` or
# `f   ...    .C... : /etc/passwd`. Requiring an absolute path is what keeps the
# summary counters (`  Total number of entries:\t42817`) out of the findings.
_ENTRY_RE = re.compile(r"^(?P<attrs>\S[^:]*):[ \t]+(?P<path>/.*\S)[ \t]*$")

# AIDE 0.15-era inline form, emitted with no section headers at all.
_LEGACY_RE = re.compile(r"^(?P<change>added|removed|changed):[ \t]+(?P<path>/.*\S)[ \t]*$", re.I)

# A bare report heading, e.g. `Summary:` or `Detailed information about
# changes:`. Deliberately narrow -- it must start with a letter -- so a line of
# pure punctuation is treated as garbage to skip rather than as a heading that
# silently swallows the rest of the section.
_HEADING_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 ()_.,'\"-]*:$")


class AideAdapter:
    """The AIDE scanner adapter. Stateless; all methods are pure."""

    name = "aide"
    binary = "aide"

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        """``aide --config <ours> --check``.

        Returned as an argv list, never a shell string: the config path is
        operator-supplied and must not be re-interpreted by a shell.
        """
        config_path = str(config.get("config_path") or DEFAULT_CONFIG_PATH)
        return [self.binary, "--config", config_path, "--check"]

    def preflight(self, config: Mapping[str, Any]) -> str | None:
        """Always ready: AIDE's config path is a plain argv value, not a set to expand."""
        del config
        return None

    def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome:
        """Map AIDE's exit bitmask to an outcome. See the module docstring.

        The output is ignored on purpose — AIDE's status says everything, and a
        verdict must not depend on a report body that embeds attacker-
        controllable file paths.
        """
        del stdout, stderr
        if code == 0:
            return ScanOutcome.clean
        if 1 <= code <= 7:
            # Bitmask: 1 = new, 2 = removed, 4 = changed. A successful scan that
            # found differences -- NOT a failure.
            return ScanOutcome.findings
        return ScanOutcome.failure

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        """Parse an ``aide --check`` report into findings.

        Never raises: an unrecognized line is skipped, and the findings parsed
        so far are returned. Scanner output is untrusted input — it embeds
        attacker-controllable file paths — so nothing here is evaluated,
        globbed or shelled out.

        *stderr* is ignored for findings; AIDE writes only diagnostics there,
        and a real error is already visible in the exit status.
        """
        del stderr
        findings: list[Finding] = []
        section: str | None = None

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            lowered = stripped.lower()
            header = _SECTION_HEADERS.get(lowered)
            if header is not None:
                section = header
                continue

            # Any other bare heading ends the current section. This is what
            # stops the trailing "Detailed information about changes:" block
            # from double-counting every changed path.
            if _HEADING_RE.match(stripped) is not None:
                section = None
                continue

            legacy = _LEGACY_RE.match(stripped)
            if legacy is not None:
                findings.append(
                    _finding(legacy.group("change").lower(), legacy.group("path"), stripped)
                )
                continue

            if section is None:
                continue

            entry = _ENTRY_RE.match(stripped)
            if entry is None:
                continue
            findings.append(_finding(section, entry.group("path"), stripped))

        return findings


def _finding(change: str, path: str, raw_line: str) -> Finding:
    """Build one AIDE finding.

    ``indicator_value`` is the change kind ("added" / "removed" / "changed")
    rather than the path: the path already lives in ``file.path``, so keying a
    rule on ``threat.indicator.value == "changed"`` is the useful predicate.
    """
    return Finding(
        indicator_type="aide_change",
        indicator_value=change,
        raw_line=raw_line,
        category="file",
        path=path,
        severity=None,  # AIDE has no severity of its own.
        message=f"AIDE: {change} {path}",
    )
