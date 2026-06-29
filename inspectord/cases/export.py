"""Daemon-side case ZIP export + per-blob reader (spec §2.1).

The web is a pure IPC client and the forensic store is root-only, so artifacts are
built here and shipped base64-over-IPC, hard-capped at _MAX_EXPORT_BYTES raw bytes.
"""

from __future__ import annotations

import io
import logging
import os
import re
import stat
import zipfile

log = logging.getLogger(__name__)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_EXPORT_BYTES = 64 * 1024 * 1024  # cap on RAW bytes (pre-base64); ~85 MiB on the wire


class CaseExportError(Exception):
    """Base for export errors."""


class CaseNotFound(CaseExportError):
    pass


class EvidenceNotFound(CaseExportError):
    pass


class ExportTooLarge(CaseExportError):
    pass


def _read_blob(store, sha: str) -> bytes | None:
    """Read a forensic-store blob by sha. None if missing/invalid/unsafe.

    Opens with O_NOFOLLOW (defense-in-depth — the store holds regular files only) and
    reads from the fd, never re-opening by path. Caller must validate `sha` is hex first
    for any sha that did not originate as a path_for() key.
    """
    path = store.path_for(sha)
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def _build_narrative(case: dict, *, skipped: list[tuple[str, str]]) -> str:
    """Plain-text human summary. `skipped` = (sha, reason) for blobs not included."""
    lines: list[str] = []
    lines.append(f"# Case {case['case_id']}: {case.get('title') or '(untitled)'}")
    lines.append("")
    lines.append(f"Status: {case['status']}")
    lines.append(f"Opened: {case.get('opened_at')}")
    lines.append(f"Closed: {case.get('closed_at') or '-'}")
    lines.append("")
    lines.append("## Alerts")
    for a in case.get("alerts", []):
        lines.append(
            f"- [{a.get('severity')}] {a.get('rule_id')} ({a.get('alert_id')}): "
            f"{a.get('rendered_short') or ''}"
        )
    if not case.get("alerts"):
        lines.append("- (none)")
    lines.append("")
    lines.append("## Timeline")
    for t in case.get("timeline", []):
        lines.append(f"- {t.get('ts')} {t.get('kind')}: {t.get('text') or ''}")
    if not case.get("timeline"):
        lines.append("- (none)")
    lines.append("")
    lines.append("## Evidence")
    for e in case.get("evidence", []):
        lines.append(
            f"- {e.get('kind')} {e.get('sha256')} "
            f"{e.get('original_path') or ''}".rstrip()
        )
    if not case.get("evidence"):
        lines.append("- (none)")
    lines.append("")
    lines.append("## Notes")
    lines.append(
        "v1 export ships 4 of the 6 artifacts in parent spec §13.4: the timeline embedded in "
        "case.json stands in for audit.log (plain, not-yet-tamper-evident), and event bundles "
        "are included as evidence/<sha> blobs (kind=event_bundle), not top-level events/*.jsonl."
    )
    if skipped:
        lines.append("")
        lines.append("## Missing evidence")
        for sha, reason in skipped:
            lines.append(f"- {sha}: {reason}")
    return "\n".join(lines) + "\n"
