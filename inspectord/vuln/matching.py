"""Installed-set parsing, alpm version compare, advisory matching (design §4).

Pure functions over strings plus one injectable subprocess wrapper: alpm
version semantics are subtle (epochs, missing pkgrel), so ``vercmp`` is
correct by construction and a pure-Python reimplementation is deliberately
out of scope. Results are cached in a caller-owned (worker-lifetime) dict —
``vercmp`` is a pure function of its two strings — so steady-state rescans
fork almost nothing.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from inspectord.vuln.advisories import Advisory

#: A recognized status set; anything else is skipped, never guessed (§4).
_KNOWN_STATUSES = frozenset({"Not affected", "Vulnerable", "Fixed", "Testing", "Unknown"})

_VERCMP_TIMEOUT_S = 10.0

RunFn = Callable[..., "subprocess.CompletedProcess[str]"]
VercmpFn = Callable[[str, str], int]


class VercmpUnavailableError(Exception):
    """vercmp is missing or not behaving as vercmp; the scan must fail (§6).

    A binary that exists but prints garbage is treated the same as a missing
    one: either way there is no trustworthy comparison, and a partial or
    guessed result would silently corrupt the match set.
    """


def vercmp(
    a: str,
    b: str,
    *,
    cache: dict[tuple[str, str], int],
    run: RunFn = subprocess.run,
) -> int:
    """alpm version compare via the vercmp binary: <0, 0 or >0.

    *cache* is caller-owned so its lifetime is the worker's, not the scan's.
    """
    key = (a, b)
    if key in cache:
        return cache[key]
    try:
        proc = run(
            ["vercmp", a, b],
            capture_output=True,
            text=True,
            timeout=_VERCMP_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError as exc:
        raise VercmpUnavailableError("vercmp binary not found") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise VercmpUnavailableError(f"vercmp failed to run: {exc!r}") from exc
    try:
        result = int(proc.stdout.strip())
    except ValueError as exc:
        raise VercmpUnavailableError(f"vercmp printed garbage: {proc.stdout[:80]!r}") from exc
    cache[key] = result
    return result


def parse_installed(output: str) -> tuple[dict[str, str], int]:
    """Parse ``pacman -Q`` output into {name: version}; count unparseable lines."""
    installed: dict[str, str] = {}
    bad = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            bad += 1
            continue
        installed[parts[0]] = parts[1]
    return installed, bad


@dataclass(frozen=True)
class VulnMatch:
    """One (avg_id, cve_id, package) vulnerability hit."""

    avg_id: str
    cve_id: str
    package: str
    installed_version: str
    fixed_version: str | None
    #: The AVG-level maximum — per-CVE severities are not in the dump (§4).
    severity: str
    status: str
    #: The fix exists only in [testing]; the panel qualifies its -Syu advice.
    fix_in_testing: bool
    advisory_url: str


@dataclass
class MatchResult:
    matches: list[VulnMatch] = field(default_factory=list)
    #: AVGs with an unrecognized status — the sweep protects these too (§5).
    skipped_avg_ids: list[str] = field(default_factory=list)
    warnings: int = 0


def _is_vulnerable(advisory: Advisory, installed_version: str, vercmp_fn: VercmpFn) -> bool:
    if advisory.fixed is not None:
        # The tracker's own semantics: everything < fixed is vulnerable.
        # `affected` is deliberately not used as a lower bound (§4).
        return vercmp_fn(installed_version, advisory.fixed) < 0
    # No fix known anywhere: only an open advisory means exposure. `Unknown`
    # gets a row too (never an alert — the rules exclude it), because hiding
    # an undetermined advisory would be silent optimism.
    return advisory.status in ("Vulnerable", "Unknown")


def match_advisories(
    advisories: Iterable[Advisory],
    installed: Mapping[str, str],
    *,
    vercmp: VercmpFn,
) -> MatchResult:
    """Match parsed advisories against the installed set. Raises only what
    *vercmp* raises (VercmpUnavailableError from the subprocess wrapper)."""
    result = MatchResult()
    for advisory in advisories:
        if advisory.status == "Not affected":
            continue
        if advisory.status not in _KNOWN_STATUSES:
            # No guessing, no resolution side-effects: record the id so the
            # projector sweep leaves this AVG's existing rows alone.
            result.skipped_avg_ids.append(advisory.avg_id)
            result.warnings += 1
            continue
        for package in advisory.packages:
            installed_version = installed.get(package)
            if installed_version is None:
                continue
            if not _is_vulnerable(advisory, installed_version, vercmp):
                continue
            for cve_id in advisory.issues:
                result.matches.append(
                    VulnMatch(
                        avg_id=advisory.avg_id,
                        cve_id=cve_id,
                        package=package,
                        installed_version=installed_version,
                        fixed_version=advisory.fixed,
                        severity=advisory.severity,
                        status=advisory.status,
                        fix_in_testing=advisory.status == "Testing",
                        # Constructed from the validated id, never read from
                        # the file (§5).
                        advisory_url=f"https://security.archlinux.org/{advisory.avg_id}",
                    )
                )
    return result
