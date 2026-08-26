"""Arch Security Advisories parsing (vuln-scanner design §3).

Consumes the security.archlinux.org ``/json`` dump — a JSON array of AVG
objects — under hard caps: the file is refused before reading past 64 MB, the
array is bounded, and every string is control-char-stripped and length-capped.
A malformed AVG is skipped *and its id recorded*: the projector's sweep must
never resolve rows belonging to an AVG that merely failed to parse this scan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

#: Pre-parse stat cap; a legitimate dump is ~5 MB, so 64 MB is generous.
MAX_FILE_BYTES = 64 * 1024 * 1024
#: The real tracker holds a few thousand AVGs; 50 000 means the file is broken.
MAX_ADVISORIES = 50_000
#: Applies to `packages` and `issues` alike.
MAX_ITEMS_PER_AVG = 64
MAX_STRING_LEN = 256

_AVG_ID_RE = re.compile(r"^AVG-[0-9]+$")


class AdvisoryLoadError(Exception):
    """The whole scan must fail; `reason` is the vuln_scan_failed reason (§6)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Advisory:
    avg_id: str
    packages: tuple[str, ...]
    status: str
    severity: str
    fixed: str | None
    #: Parsed but deliberately unused for matching (§4): it is a single version,
    #: not a range, and the tracker's semantics are "everything < fixed".
    affected: str | None
    #: CVE ids.
    issues: tuple[str, ...]


@dataclass(frozen=True)
class ParsedAdvisories:
    advisories: tuple[Advisory, ...]
    #: AVGs whose id validated but whose body did not — the sweep protects these.
    skipped_avg_ids: tuple[str, ...]
    #: Every skipped or unidentifiable entry, including ones with no valid id.
    warnings: int


def _clean(value: str) -> str:
    """Strip control characters (C0 + DEL) and cap the length.

    Pre-slice before stripping: a single multi-megabyte string field would
    otherwise cost a full O(len) pass per scan attempt. 4x the cap leaves
    room for stripped characters without unbounded work.
    """
    value = value[: 4 * MAX_STRING_LEN]
    stripped = "".join(ch for ch in value if ch >= " " and ch != "\x7f")
    return stripped[:MAX_STRING_LEN]


def _clean_optional(value: object) -> str | _Invalid | None:
    if value is None:
        return None
    if isinstance(value, str):
        return _clean(value)
    return _INVALID


class _Invalid:
    """Sentinel: a field that is present but of the wrong shape."""


_INVALID = _Invalid()


def _clean_str_list(value: object) -> tuple[str, ...] | _Invalid:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS_PER_AVG:
        return _INVALID
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return _INVALID
        cleaned = _clean(item)
        if not cleaned:
            return _INVALID
        out.append(cleaned)
    return tuple(out)


def _parse_one(entry: object) -> Advisory | str | None:
    """One AVG object → Advisory, or its id (skip + record), or None (no id)."""
    if not isinstance(entry, dict):
        return None
    raw_id = entry.get("name")
    if not isinstance(raw_id, str):
        return None
    avg_id = _clean(raw_id)
    if not _AVG_ID_RE.match(avg_id):
        return None

    packages = _clean_str_list(entry.get("packages"))
    issues = _clean_str_list(entry.get("issues"))
    status = entry.get("status")
    severity = entry.get("severity")
    fixed = _clean_optional(entry.get("fixed"))
    affected = _clean_optional(entry.get("affected"))
    if (
        isinstance(packages, _Invalid)
        or isinstance(issues, _Invalid)
        or not isinstance(status, str)
        or not isinstance(severity, str)
        or isinstance(fixed, _Invalid)
        or isinstance(affected, _Invalid)
    ):
        return avg_id
    return Advisory(
        avg_id=avg_id,
        packages=packages,
        status=_clean(status),
        severity=_clean(severity),
        fixed=fixed,
        affected=affected,
        issues=issues,
    )


def parse_advisories(data: bytes) -> ParsedAdvisories:
    """Parse the raw dump. Raises AdvisoryLoadError when no scan can proceed."""
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        # RecursionError: ~100 KB of "["*N blows the JSON parser's stack while
        # sitting far under the size cap; it must fail honestly, not escape the
        # worker's typed-failure handling (spec section 6).
        raise AdvisoryLoadError("parse_failed") from exc
    if not isinstance(doc, list):
        raise AdvisoryLoadError("parse_failed")
    if not doc:
        # An empty Arch advisory DB is never legitimate; as data it would
        # mass-resolve every open vulnerability row (§3).
        raise AdvisoryLoadError("advisories_empty")
    if len(doc) > MAX_ADVISORIES:
        raise AdvisoryLoadError("parse_failed")

    advisories: list[Advisory] = []
    skipped: list[str] = []
    warnings = 0
    for entry in doc:
        parsed = _parse_one(entry)
        if isinstance(parsed, Advisory):
            advisories.append(parsed)
        elif isinstance(parsed, str):
            # A valid id with an invalid body: record it so the sweep never
            # resolves this AVG's existing rows off a parse hiccup (§5).
            skipped.append(parsed)
            warnings += 1
        else:
            # No usable id — nothing the sweep could protect, count it only.
            warnings += 1
    return ParsedAdvisories(
        advisories=tuple(advisories),
        skipped_avg_ids=tuple(skipped),
        warnings=warnings,
    )


def load_advisories(path: Path, *, max_bytes: int = MAX_FILE_BYTES) -> ParsedAdvisories:
    """Stat-cap, bounded-read and parse the advisory file at *path*."""
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise AdvisoryLoadError("advisories_missing") from exc
    except OSError as exc:
        raise AdvisoryLoadError("advisories_missing") from exc
    if size > max_bytes:
        raise AdvisoryLoadError("file_too_large")
    try:
        with path.open("rb") as f:
            # One byte past the cap: the file may have grown since the stat
            # (mid-`mv` flap), and the read itself must stay bounded.
            data = f.read(max_bytes + 1)
    except FileNotFoundError as exc:
        raise AdvisoryLoadError("advisories_missing") from exc
    except OSError as exc:
        raise AdvisoryLoadError("advisories_missing") from exc
    if len(data) > max_bytes:
        raise AdvisoryLoadError("file_too_large")
    return parse_advisories(data)
