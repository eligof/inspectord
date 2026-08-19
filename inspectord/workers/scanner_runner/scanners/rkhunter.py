"""rkhunter adapter — ``rkhunter --check``, read from stdout (design decision 13).

**The exit code cannot classify an rkhunter run.** ``man rkhunter``: "rkhunter
will return a non-zero exit code if any error or warning occurs." Measured
against rkhunter 1.4.6 on this machine, all with
``--check --sk --nocolors --rwo --nomow --logfile <path>``::

    --enable properties        -> exit 1, five "Warning:" blocks   (a detection)
    --enable hidden_ports      -> exit 0, no output                (clean)
    --disable all              -> exit 1, "'all' cannot be used in the disabled
                                  test list."                      (a refusal)
    --enable bogus_test        -> exit 1, "Unknown enabled test name given: ..."
    --configfile /nonexistent  -> exit 1, "Unable to find configuration file: ..."

So design §4.1's "exit 0 = no warnings, 1 = warnings found, 2 = error" is wrong,
and a classifier reading the code alone would report a scanner that **refused to
run** as a rootkit detection — the inverse of the bug decision 10 exists to
prevent, and the more dangerous direction of the two.

What separates them is the *output*: with ``--report-warnings-only`` a healthy
run prints only ``Warning:`` blocks, and every refusal prints a diagnostic with
no ``Warning:`` line at all. Hence:

===================  ===========  =========
warnings parsed      exit code    outcome
===================  ===========  =========
yes                  anything     findings
no                   0            clean
no                   non-zero     failure
===================  ===========  =========

Two flags are not optional:

* **``--report-warnings-only``** makes stdout the exact finding set, which is
  what lets decision 13 read stdout instead of requiring the
  ``/etc/rkhunter.conf.d/inspectord.conf`` drop-in first.
* **``--no-mail-on-warning``** stops a host ``rkhunter.conf`` with
  ``MAIL-ON-WARNING`` set from making *our* scan send mail off the box. That is
  egress, and parent §18.1 permits none that is not enumerated.

And one flag must never be passed: **``--nolog``**, measured to be incompatible
with ``--report-warnings-only`` ("The logfile has been disabled - unable to
report warnings.", exit 1, no warnings — i.e. a run that classifies as a
failure, correctly but uselessly). rkhunter reports warnings *from* its log, so
the log destination is a config key (``logfile``) instead.

Nothing here ever runs ``--update``, ``--versioncheck`` or ``--propupd``:
the first two are network egress (decision 8), and the third rewrites a system
baseline file, which is not a scanner's job.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from inspectord.workers.scanner_runner.scanners.base import Finding, ScanOutcome

#: Flags every run carries. See the module docstring for why each is mandatory.
BASE_FLAGS = (
    "--check",
    "--skip-keypress",
    "--nocolors",
    "--report-warnings-only",
    "--no-mail-on-warning",
)

#: Config keys that map straight to a single-value option.
_VALUE_OPTIONS = (("configfile", "--configfile"), ("logfile", "--logfile"))
#: Config keys whose value is a test-name list rkhunter wants comma-joined.
_LIST_OPTIONS = (("enable", "--enable"), ("disable", "--disable"))

# A warning opens at COLUMN 0. Continuation lines are indented, and folding them
# into their header is the difference between 5 findings and 10.
_WARNING_RE = re.compile(r"^Warning:[ \t]?(?P<text>.*)$")

# `Checking for prerequisites               [ Warning ]` -> the check's name.
_CHECK_RE = re.compile(r"^(?P<check>.*?)[ \t]*\[[ \t]*Warning[ \t]*\]$")

# The first single-quoted absolute path in a warning, e.g.
# `The command '/usr/bin/egrep' has been replaced by a script: ...`.
_QUOTED_PATH_RE = re.compile(r"'(?P<path>/[^']*)'")

# Scanner output is untrusted and embeds attacker-influenceable paths, so one
# pathological line must not become a multi-megabyte event.
MAX_VALUE_LEN = 256
MAX_MESSAGE_LEN = 4096
MAX_RAW_LEN = 4096


class RkhunterAdapter:
    """The rkhunter scanner adapter. Stateless; all methods are pure."""

    name = "rkhunter"
    binary = "rkhunter"

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        """``rkhunter --check`` plus the mandatory flags and any configured options.

        Returned as an argv list, never a shell string: test names, config paths
        and log paths are operator-supplied and must not be re-parsed by a
        shell.
        """
        argv = [self.binary, *BASE_FLAGS]
        for key, flag in _LIST_OPTIONS:
            value = _joined(config.get(key))
            if value:
                argv += [flag, value]
        for key, flag in _VALUE_OPTIONS:
            path = config.get(key)
            if path:
                argv += [flag, str(path)]
        return argv

    def preflight(self, config: Mapping[str, Any]) -> str | None:
        """Always ready: rkhunter ships its own data files and needs no setup from us."""
        del config
        return None

    def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome:
        """Decide from the OUTPUT as well as the code — see the module docstring.

        Warnings beat the exit code so a partly-broken run can never *hide* a
        detection; no warnings plus a non-zero code is the refusal case and is
        always a failure, never a silent ``clean``.
        """
        del stderr  # rkhunter's own shell noise; never a finding, never a verdict.
        if _warning_blocks(stdout):
            return ScanOutcome.findings
        if code == 0:
            return ScanOutcome.clean
        return ScanOutcome.failure

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        """Parse ``--report-warnings-only`` stdout into one finding per warning.

        Never raises: an unrecognized line is skipped and the findings parsed so
        far are returned. Nothing here is evaluated, globbed or shelled out.

        *stderr* is ignored entirely — on this machine every rkhunter run writes
        unrelated ``grep: warning: stray \\ before -`` noise there, and a real
        error is already visible in the (unusable on its own) exit status plus
        the absence of warnings.
        """
        del stderr
        return [_finding(header, details) for header, details in _warning_blocks(stdout)]


def _joined(value: Any) -> str:
    """A test-name list or a plain string as rkhunter's comma-joined argument."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple, set, frozenset)):
        return ",".join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def _warning_blocks(stdout: str) -> list[tuple[str, list[str]]]:
    """Split stdout into ``(header_line, continuation_lines)`` warning blocks.

    A block opens on a column-0 ``Warning:``; indented non-empty lines belong to
    the open block; anything else closes it and is dropped. Dropping those
    non-warning lines is exactly what makes ``interpret_outcome`` call a refusal
    a failure.
    """
    blocks: list[tuple[str, list[str]]] = []
    details: list[str] | None = None

    for line in stdout.splitlines():
        match = _WARNING_RE.match(line)
        if match is not None:
            details = []
            blocks.append((line, details))
            continue
        if not line.strip():
            continue
        if details is not None and line[:1].isspace():
            details.append(line.strip())
            continue
        # A non-indented, non-warning line: rkhunter has moved on (or refused).
        details = None
    return blocks


def _finding(header: str, details: list[str]) -> Finding:
    """Build one rkhunter finding from a warning block.

    ``indicator_value`` is the check name when rkhunter names one
    (``... [ Warning ]``) and otherwise the warning text itself: a rule keying
    on ``threat.indicator.value == "Checking for prerequisites"`` is the useful
    predicate, and the detail lives in the message either way.
    """
    match = _WARNING_RE.match(header)
    text = (match.group("text") if match else header).strip()

    check = _CHECK_RE.match(text)
    value = (check.group("check").strip() if check else text) or "rkhunter warning"

    path_match = _QUOTED_PATH_RE.search(text)
    path = path_match.group("path") if path_match else None

    message = " ".join(part for part in (text, *details) if part)
    return Finding(
        indicator_type="rkhunter_test",
        indicator_value=_clip(value, MAX_VALUE_LEN),
        raw_line=_clip(header, MAX_RAW_LEN),
        # §4.2: "process" for rkhunter checks that are not file-scoped.
        category="file" if path else "process",
        path=path,
        # Decision 7: rkhunter grades nothing — every report is a "Warning" —
        # so the adapter invents no severity and the runner omits the key.
        severity=None,
        message=_clip(message, MAX_MESSAGE_LEN) or None,
    )


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]
