"""AIDE adapter — ``aide --check`` against the inspectord-owned database.

AIDE's database is ours and lives under ``/var/lib/inspectord/aide/`` (parent
spec §30.6), so this scanner is fully deterministic and fully offline: nothing
here ever updates a signature database (design decision 8).

**But we do not create it.** The repo ships a config —
``packaging/aide.conf.example``, installed to ``DEFAULT_CONFIG_PATH`` by
``packaging/scripts/setup.sh`` — and stops there: ``aide --init`` writes a
baseline of the machine exactly as it is right now, which is the user's decision
and not the daemon's. So a host can be missing the config (setup not run), the
database (baseline not built), or both. ``preflight`` reports those two states
as ``config_missing`` / ``database_missing`` skips; without it the scanner would
exit 18 and report a ``failure`` every night forever. See ``preflight`` below.

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

**A filename can forge a report line.** The only bytes a Linux filename may not
contain are ``/`` and NUL, and every line of an ``aide --check`` report ends in
a path AIDE is reporting on. A break character inside a reported name therefore
splits one report line into two, and the tail — fully attacker-chosen, because
the path is last on the line — is then read as a line of its own. The slashes
of a fake path cost nothing: a *directory* named ``x<break>f+++…: `` with
``etc/shadow`` nested under it makes AIDE print
``f++++++++++++++++: <root>/x<break>f++++++++++++++++: /etc/shadow``.

This parser is **section-driven**, which makes the surface wider than the
rkhunter or YARA one — a forged line can be a section header, a bare heading or
an entry, so it can *hide* a genuine change as well as invent one. Measured
against the **installed AIDE 0.19.3** with a planted tree (four forged names and
two ordinary new files), parsed by the pre-fix ``str.splitlines`` loop:

* a forged ``f++++++++++++++++: /etc/shadow`` line **invented** an ``added``
  finding on ``/etc/shadow`` — attacker-chosen ``file.path``;
* a forged ``Removed entries:`` line **opened a spurious section**, so the next
  genuine ``added`` entry was reported as ``removed`` — the wrong change kind on
  a real path;
* a forged ``added: /etc/passwd`` line forged a finding through the legacy
  inline form, which needs **no open section at all** and so works anywhere in
  the report, including the trailing "Detailed information" block;
* a forged bare heading (``Some heading:``) matched ``_HEADING_RE`` and closed
  the open section, and every genuine entry sorted after it — AIDE sorts a
  section by path — was then **skipped**. One genuinely new file disappeared
  from the findings entirely. That is real **suppression**: rkhunter and YARA
  could only add a finding, never hide one.

What AIDE 0.19.3 actually prints was measured, not assumed. ``man aide``
("NOTES / Control characters") documents that control characters 00-31 and 127
are always escaped in plain report output as a backslash and three octal
digits, and the planted tree confirms it: ``\n``, ``\r``, ``\v``, ``\f`` and
``\x1c``-``\x1e`` all came back as ``\012``, ``\015``, ``\013``, ``\014``,
``\034``-``\036``. **U+0085, U+2028 and U+2029 came back raw** — they are
multi-byte UTF-8, outside the byte range AIDE escapes — and ``str.splitlines``
breaks on all three, so every forgery above was reachable through the real
binary with no special privilege beyond creating a directory in the monitored
tree.

Splitting on ``\n`` alone closes all three (the same planted report now yields
only genuine findings, correctly labelled, with the suppressed one back), and
every line is stripped of control characters so an ESC or a NUL never reaches an
event for a terminal or a log tailer to re-interpret. AIDE's own escaping of
``\n`` is deliberately **not** relied on: the dependency manifest pins
``minimum_version: "0.18"`` and only 0.19.3 was measured here. So an AIDE that
prints a raw newline in a path is assumed reachable, and bounded instead:

* it **cannot** change the outcome. ``interpret_outcome`` reads the exit bitmask
  and nothing else, so no amount of forged report text can turn a ``failure`` or
  a ``clean`` into ``findings`` — the one bound AIDE holds more firmly than
  either sibling. A report body only exists at all when the run already found
  differences;
* it **can** invent a finding, on an attacker-chosen path and with an
  attacker-chosen change kind;
* it **can** mislabel genuine entries by opening a spurious section;
* it **can** suppress genuine entries that follow it in the same section, by
  forging a heading that closes the section;
* it **truncates** the planted name's own entry at the break, so that one
  genuine finding names a prefix of the real path.

Guessing which report lines look "unexpected" was rejected deliberately, as it
was for rkhunter and YARA: a parser that sometimes drops a real AIDE change
would be far worse than one that sometimes shows an extra. The tests pin the
exposure instead — unit tests over all nine break characters plus live ones
that plant the tree against the real binary for each of the three it prints raw
— so nobody later reads the section machinery and concludes a forged line is
impossible.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from inspectord.workers.scanner_runner.scanners.base import Finding, ScanOutcome, sanitize_text

# Spec §30.6: the AIDE database and config are ours, under /var/lib/inspectord.
DEFAULT_CONFIG_PATH = "/var/lib/inspectord/aide/aide.conf"

#: Ceiling on the bytes of config `preflight` reads looking for `database_in`.
#: An AIDE config is a page or two; anything past this is not one, and a
#: preflight must stay cheap enough to run before every scheduled scan.
MAX_CONFIG_BYTES = 1024 * 1024

#: `database_in=file:/path`, or the pre-0.19 `database=` spelling. Spaces around
#: the `=` are accepted -- AIDE 0.19.3 accepts them, measured.
_DATABASE_IN_RE = re.compile(r"^[ \t]*database(?:_in)?[ \t]*=[ \t]*(?P<url>\S.*?)[ \t]*$")

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
        """Report "not set up yet" as a skip reason instead of a nightly failure.

        AIDE cannot bootstrap itself and inspectord will never bootstrap it:
        ``aide --init`` writes a baseline of the machine as it is *right now*,
        and a daemon that does that on the user's behalf silently certifies
        whatever is already on the disk. So the two not-set-up states below are
        the ordinary condition of a fresh install, not errors — and both are
        indistinguishable from a real fault if we let AIDE report them.

        Measured against the installed AIDE 0.19.3 (2026-08-19), each of these
        exits **18** (IO error), which ``interpret_outcome`` correctly but
        uselessly calls a ``failure``::

            aide --config /nonexistent.conf --check
              ERROR: cannot open config file '/nonexistent.conf': ...
            aide --config <ours> --check          # database_in file absent
              ERROR: <ours>:1: open (read-only) failed for file '<db>': ...

        An enabled-but-unconfigured AIDE would therefore emit a ``failure``
        every single night, forever, saying only "exit 18". These two reasons
        say what is actually missing:

        ``config_missing``
            The config named by ``config_path`` (default
            ``/var/lib/inspectord/aide/aide.conf``) does not exist. The repo
            ships one (``packaging/aide.conf.example``) but nothing installs it
            automatically, so this is the state of a host where
            ``packaging/scripts/setup.sh`` has not been run.
        ``database_missing``
            The config exists and names a local ``database_in`` file that does
            not. Run ``aide --config <ours> --init`` yourself, on a machine you
            believe is clean, and move the resulting ``database_out`` into
            place.

        Undecidable cases return ``None`` and let AIDE speak for itself rather
        than inventing a reason: a non-``file:`` ``database_in`` (``stdin``, an
        ``https://`` URL — both legal per ``man aide.conf``), a path built from
        an ``@@{...}`` variable, a config that pulls the setting in through
        ``@@include``, or a config we cannot read. MUST NOT raise, so every
        filesystem and decoding error resolves to one of these answers.
        """
        config_path = str(config.get("config_path") or DEFAULT_CONFIG_PATH)
        if not _is_file(config_path):
            return "config_missing"
        database = _database_in(config_path)
        if database is None:
            return None
        if not _exists(database):
            return "database_missing"
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

        Lines are split on ``\\n`` **only** — not ``str.splitlines``, which also
        breaks on ``\\r``, ``\\v``, ``\\f``, ``\\x1c``-``\\x1e``, ``\\x85`` and
        U+2028/9, every one of them legal in a filename AIDE is about to print —
        and each line is then stripped of control characters. That leaves a raw
        newline in a reported filename as the one remaining way to forge a line;
        see "A filename can forge a report line" in the module docstring for
        what that can and cannot do.
        """
        del stderr
        findings: list[Finding] = []
        section: str | None = None

        for raw_line in stdout.split("\n"):
            stripped = sanitize_text(raw_line).strip()
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


def _is_file(path: str) -> bool:
    """``True`` when *path* is an existing regular file. Never raises."""
    try:
        return Path(path).is_file()
    except (OSError, ValueError):
        return False


def _exists(path: str) -> bool:
    """``True`` when *path* exists at all. Never raises."""
    try:
        return Path(path).exists()
    except (OSError, ValueError):
        return False


def _database_in(config_path: str) -> str | None:
    """The local ``database_in`` file *config_path* names, or ``None``.

    ``None`` means "not decidable here", never "not configured": an unreadable
    config, a database URL that is not a local file (``stdin``, ``https://…`` —
    both legal per ``man aide.conf``), or a path built from an ``@@{...}``
    variable this parser deliberately does not expand. The caller then lets AIDE
    speak for itself rather than skipping on a guess.

    ``man aide.conf``: "There can only be one of these lines. If there are
    multiple database lines then the **first** is used." — so this stops at the
    first match, matching AIDE rather than out-guessing it. Never raises.
    """
    try:
        with Path(config_path).open("r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(MAX_CONFIG_BYTES)
    except (OSError, ValueError):
        return None

    for line in text.split("\n"):
        if line.lstrip().startswith("#"):
            continue
        match = _DATABASE_IN_RE.match(line)
        if match is None:
            continue
        url = match.group("url")
        if "@@" in url:
            # An `@@{DBDIR}`-style variable. Expanding AIDE's config language is
            # not this parser's job, and a wrong expansion would skip a scanner
            # that could have run.
            return None
        path = url.removeprefix("file:")
        return path if path.startswith("/") else None
    return None
