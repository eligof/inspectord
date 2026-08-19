"""YARA adapter — ``yara`` over the rulesets we ship under ``/var/lib/inspectord/yara``.

**Design §4.1's ``yara -r -w <rules-dir> <target>`` does not work.** Measured
against yara 4.5.7 on this machine:

* a rules *directory* is rejected outright —
  ``rules(1): error: input in flex scanner failed``, exit 1. ``RULES_FILE`` must
  be a file;
* a second target is read as another *rules* file and fails to compile. The
  grammar is ``yara [OPTIONS] RULES_FILE... FILE|DIR|PID``: many rules files,
  exactly **one** target, last.

So this adapter expands the shipped rules *directory* itself — every ``.yar`` /
``.yara`` file under it, ``sorted()`` for a deterministic argv — and passes each
as its own ``RULES_FILE``::

    yara -r -m -w <rules…> <target>

``-r`` recursive, ``-m`` print meta (this is where ``threat.indicator.severity``
comes from, §4.2), ``-w`` suppress compile warnings so stdout is exactly the
match set.

**One target, not a list.** Design §4.4's example config shows
``"targets": ["/home", "/tmp"]``, which yara cannot express; scanning N paths
means N subprocesses and the runner is deliberately one-subprocess-per-run. This
adapter therefore takes **``target``** (singular; default ``/home``) and
multi-target support waits for a runner that can sequence sub-runs. *Recorded as
a deliberate deviation from §4.4.* Silently scanning ``targets[0]`` was rejected:
a config key that is half-ignored is worse than one that does not exist.

Output shapes, all captured::

    Demo_Rule /path/hit.txt
    Demo_Rule [severity="high",description="a, b \\"c\\"",score =42] /path/hit.txt
    Second_Rule [] /path/both.txt
    0x6:$a: SUSPICIOUS_MARKER          <- `-s` string match, INDENTED, not a finding

Note ``score =42``: yara prints integer meta as ``name =value`` and string meta
as ``name="value"``, a meta string may contain commas and escaped quotes, and a
matched path may contain spaces *and* ``]`` (``/tgt3/we ird/a]b c.txt`` was
measured). The meta block is therefore split by a quote-aware scanner rather
than by a greedy or lazy ``\\[.*\\]`` regex, either of which loses such a line.

Exit codes: **0 whether or not anything matched**, and 0 even when individual
files inside the target tree could not be opened (those go to stderr —
unavoidable when scanning ``/home`` unprivileged). Non-zero means a compile
error or an unusable target. Hence the outcome table shared with the rkhunter
adapter: matches ⇒ ``findings``; no matches and 0 ⇒ ``clean``; no matches and
non-zero ⇒ ``failure``, never a silent "nothing found".
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from inspectord.workers.scanner_runner.scanners.base import Finding, ScanOutcome

#: Spec §30.6 — the rulesets are ours, under /var/lib/inspectord.
DEFAULT_RULES_DIR = "/var/lib/inspectord/yara"
#: The single scanned path. See "One target, not a list" above.
DEFAULT_TARGET = "/home"
#: Extensions treated as rules. Anything else in the directory (README, index
#: files, compiled blobs) is left alone -- a non-rule file passed as RULES_FILE
#: is a compile error, i.e. a whole failed scan.
RULE_SUFFIXES = (".yar", ".yara")

# A match line starts at column 0: `<rule> [<meta>] <absolute path>`, the meta
# block optional. Indented lines are `-s` string matches and never findings.
_RULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Scanner output is untrusted -- these paths are attacker-influenceable -- so
# one pathological line must not become a multi-megabyte event.
MAX_VALUE_LEN = 256
MAX_MESSAGE_LEN = 4096
MAX_RAW_LEN = 4096
MAX_SEVERITY_LEN = 64


class YaraAdapter:
    """The YARA scanner adapter. Stateless; ``argv``/``preflight`` read the rules dir."""

    name = "yara"
    binary = "yara"

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        """``yara -r -m -w <rule files…> <target>`` — see the module docstring.

        Returned as an argv list, never a shell string: rule paths and the
        target are operator-supplied and must not be re-parsed by a shell.
        Defensive on its own (an unreadable rules directory yields no rule
        files) even though ``preflight`` normally catches that first.
        """
        rules = _rule_files(_rules_dir(config))
        return [self.binary, "-r", "-m", "-w", *(str(path) for path in rules), _target(config)]

    def preflight(self, config: Mapping[str, Any]) -> str | None:
        """Report "cannot run yet" states instead of letting yara fail obscurely.

        An empty or absent rules directory is an ordinary state — we ship the
        rulesets, and a host may not have them yet — but there is no argv that
        means "nothing to scan with": yara would read the *target* as a rules
        file and exit 1, which looks like a broken scanner. A missing target is
        likewise a bare exit 1. Both become an explicit ``scan_skipped`` reason.
        """
        directory = _rules_dir(config)
        try:
            is_dir = Path(directory).is_dir()
        except (OSError, ValueError):
            is_dir = False
        if not is_dir:
            return "rules_missing"
        if not _rule_files(directory):
            return "rules_empty"
        try:
            target_exists = os.path.exists(_target(config))
        except (OSError, ValueError):
            target_exists = False
        if not target_exists:
            return "target_missing"
        return None

    def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome:
        """Matches beat the exit code; no matches plus non-zero is never clean.

        *stderr* is not consulted: it carries per-file ``error scanning …``
        lines that are normal when sweeping a tree we do not fully own, and yara
        exits 0 for them.
        """
        del stderr
        if self.parse(stdout, ""):
            return ScanOutcome.findings
        if code == 0:
            return ScanOutcome.clean
        return ScanOutcome.failure

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        """Parse yara's match lines into findings.

        Never raises: an unrecognized line is skipped and the findings parsed so
        far are returned. Nothing here is evaluated, globbed or shelled out.

        *stderr* is ignored — it holds compile diagnostics and per-file open
        errors, neither of which is a finding.
        """
        del stderr
        findings: list[Finding] = []
        for line in stdout.splitlines():
            parsed = _match_line(line)
            if parsed is not None:
                findings.append(parsed)
        return findings


def _rules_dir(config: Mapping[str, Any]) -> str:
    return str(config.get("rules_dir") or DEFAULT_RULES_DIR)


def _target(config: Mapping[str, Any]) -> str:
    return str(config.get("target") or DEFAULT_TARGET)


def _rule_files(directory: str) -> list[Path]:
    """Every rule file under *directory*, sorted. Never raises."""
    try:
        return sorted(
            path
            for path in Path(directory).rglob("*")
            if path.suffix.lower() in RULE_SUFFIXES and path.is_file()
        )
    except (OSError, ValueError):
        return []


def _match_line(line: str) -> Finding | None:
    """One match line -> a Finding, or ``None`` when the line is not one.

    Indented lines are ``-s`` string matches, and anything whose remainder is
    not an absolute path is diagnostic output — the adapter always passes an
    absolute target, so a match path is always absolute.
    """
    if not line or line[:1].isspace():
        return None

    rule, _, rest = line.partition(" ")
    if not _RULE_NAME_RE.match(rule) or not rest:
        return None

    severity: str | None = None
    if rest.startswith("["):
        meta, remainder = _split_meta(rest)
        if meta is None or remainder is None:
            return None
        severity = _meta_severity(meta)
        rest = remainder

    if not rest.startswith("/"):
        return None

    return Finding(
        indicator_type="yara_rule",
        indicator_value=_clip(rule, MAX_VALUE_LEN),
        raw_line=_clip(line, MAX_RAW_LEN),
        category="file",
        path=rest,
        # Decision 7: the SCANNER's own severity, preserved as data. The runner
        # omits the key entirely when it is None.
        severity=severity,
        message=_clip(f"YARA: {rule} matched {rest}", MAX_MESSAGE_LEN),
    )


def _split_meta(rest: str) -> tuple[str | None, str | None]:
    """Split ``"[meta] tail"`` into ``(meta, tail)``, honouring quotes.

    Quote-aware because a meta string can contain ``]`` and a matched path can
    too (both measured). A greedy ``\\[.*\\]`` would eat a ``]`` in the path and a
    lazy one would stop inside the meta; either drops a real detection.
    """
    escaped = False
    quoted = False
    for index, char in enumerate(rest[1:], start=1):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "]" and not quoted:
            return rest[1:index], rest[index + 1 :].removeprefix(" ")
    return None, None  # unterminated -- not a match line


def _meta_severity(meta: str) -> str | None:
    """The rule's own ``severity`` meta value, if it declared one.

    Values arrive as ``severity="high"`` or, for integers, ``severity =3``.
    """
    for item in _split_top_level(meta):
        key, sep, value = item.partition("=")
        if not sep or key.strip() != "severity":
            continue
        value = value.strip()
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        return _clip(value, MAX_SEVERITY_LEN) or None
    return None


def _split_top_level(meta: str) -> list[str]:
    """Split a meta block on commas that are not inside a quoted string."""
    items: list[str] = []
    current: list[str] = []
    escaped = False
    quoted = False
    for char in meta:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            items.append("".join(current))
            current = []
            continue
        current.append(char)
    items.append("".join(current))
    return [item.strip() for item in items if item.strip()]


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]
