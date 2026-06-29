"""Daemon-side case ZIP export + per-blob reader (spec §2.1).

The web is a pure IPC client and the forensic store is root-only, so artifacts are
built here and shipped base64-over-IPC, hard-capped at _MAX_EXPORT_BYTES raw bytes.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import stat
import zipfile
from typing import Any

from inspectord.cases import store as cases_store
from inspectord.evidence.store import ForensicStore
from inspectord.storage.db import Database

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


def _read_blob(store: ForensicStore, sha: str) -> bytes | None:
    """Read a forensic-store blob by sha. None if missing/invalid/unsafe.

    Opens with O_NOFOLLOW (defense-in-depth — the store holds regular files only) and
    reads from the fd, never re-opening by path. Caller must validate `sha` is hex first
    for any sha that did not originate as a path_for() key.
    """
    path = store.path_for(sha)
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        # debug, not info: callers (build_case_zip) log the operational signal with case_id
        # context; this helper only records the low-level cause.
        log.debug("export: cannot open blob %s: %r", path, exc)
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
    except OSError as exc:
        log.debug("export: read failed %s: %r", path, exc)
        return None
    finally:
        os.close(fd)


def _build_narrative(case: dict[str, Any], *, skipped: list[tuple[str, str]]) -> str:
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
        lines.append(f"- {e.get('kind')} {e.get('sha256')} {e.get('original_path') or ''}".rstrip())
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


def _alert_record(db: Database, alert_id: str) -> bytes:
    """Full alert record as JSON bytes (payload_json), or a placeholder for a pruned alert."""
    rows = db.query("SELECT payload_json FROM alerts WHERE alert_id = ?", [alert_id]).fetchall()
    if rows and rows[0][0]:
        payload: str = rows[0][0]
        return payload.encode("utf-8")
    return json.dumps({"alert_id": alert_id, "note": "alert record pruned"}).encode("utf-8")


def _isoify(obj: dict[str, Any], key: str) -> None:
    """Render a datetime value at obj[key] as an ISO string in place (no-op otherwise)."""
    iso = getattr(obj.get(key), "isoformat", None)
    if iso is not None:
        obj[key] = iso()


def build_case_zip(db: Database, store: ForensicStore, case_id: str) -> bytes:
    """Assemble the whole-case ZIP in memory. Raises CaseNotFound / ExportTooLarge."""
    case = cases_store.get_case(db, case_id=case_id)
    if case is None:
        raise CaseNotFound(case_id)
    # get_case returns datetime objects; render them ISO for JSON.
    _isoify(case, "opened_at")
    _isoify(case, "closed_at")
    for a in case["alerts"]:
        _isoify(a, "ts")
    for t in case["timeline"]:
        _isoify(t, "ts")
    for e in case["evidence"]:
        _isoify(e, "captured_at")

    skipped: list[tuple[str, str]] = []
    total = 0
    buf = io.BytesIO()
    written_shas: set[str] = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("case.json", json.dumps(case, indent=2, default=str))
        seen_alerts: set[str] = set()
        for a in case["alerts"]:
            aid = a["alert_id"]
            if aid in seen_alerts:
                continue
            seen_alerts.add(aid)
            zf.writestr(f"alerts/{aid}.json", _alert_record(db, aid))
        for e in case["evidence"]:
            sha = e["sha256"]
            if sha in written_shas:
                continue
            if not _SHA_RE.match(sha):
                log.warning("export: case %s has invalid sha in case_evidence: %r", case_id, sha)
                skipped.append((sha, "invalid sha"))
                continue
            blob = _read_blob(store, sha)
            if blob is None:
                log.info("export: case %s blob missing on disk: %s", case_id, sha)
                skipped.append((sha, "missing on disk"))
                continue
            total += len(blob)
            if total > _MAX_EXPORT_BYTES:
                raise ExportTooLarge(f"case {case_id} exceeds {_MAX_EXPORT_BYTES} bytes")
            zf.writestr(f"evidence/{sha}", blob)
            written_shas.add(sha)
        zf.writestr("narrative.md", _build_narrative(case, skipped=skipped))
    return buf.getvalue()


def _basename(path: str) -> str:
    return os.path.basename(path.rstrip("/")) or ""


def read_evidence_blob(
    db: Database, store: ForensicStore, case_id: str, sha: str
) -> tuple[bytes, str, str]:
    """Return (bytes, filename, media_type) for a sha tied to THIS case. Raises on absence.

    Validates `sha` as hex BEFORE any path op, and confirms the sha is in this case's
    case_evidence rows — never serves an arbitrary store path.
    """
    if not _SHA_RE.match(sha):
        raise EvidenceNotFound(sha)
    rows = db.query(
        "SELECT kind, original_path FROM case_evidence WHERE case_id = ? AND sha256 = ? "
        "ORDER BY original_path LIMIT 1",
        [case_id, sha],
    ).fetchall()
    if not rows:
        raise EvidenceNotFound(sha)
    kind, original_path = rows[0][0], rows[0][1] or ""
    blob = _read_blob(store, sha)
    if blob is None:
        raise EvidenceNotFound(sha)
    if len(blob) > _MAX_EXPORT_BYTES:
        raise ExportTooLarge(sha)
    if kind in ("net_state", "event_bundle"):
        return blob, f"{sha[:12]}-{kind}.json", "application/json"
    filename = _basename(original_path) or f"{sha[:12]}.bin"
    return blob, filename, "application/octet-stream"
