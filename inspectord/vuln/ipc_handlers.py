"""IPC handlers for the vulnerabilities panel (vuln-scanner design §7)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.audit.log import append_audit
from inspectord.storage.db import Database

_SCHEMA_VERSION = "1.0.0"
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500

_ROW_COLUMNS = (
    "avg_id, cve_id, package, installed_version, fixed_version, severity, status,"
    " fix_in_testing, first_seen_at, last_seen, last_event_id, resolved_at,"
    " acked_at, acked_note"
)

#: Summary counters lifted out of a ``vuln_scan_completed`` payload for the
#: panel's freshness line (§6).
_COUNT_KEYS = ("advisories", "matched", "new", "warnings")


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _last_scan(db: Database) -> dict[str, Any] | None:
    """Newest `vuln_scan_completed` OR `vuln_scan_failed` — a perpetually
    failing scan must not render as mute staleness (§6)."""
    row = db.query(
        "SELECT action, ts, payload_json FROM events_enriched"
        " WHERE module = 'vuln_scanner'"
        " AND action IN ('vuln_scan_completed', 'vuln_scan_failed')"
        " ORDER BY ts DESC, event_id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    action, ts, payload_json = row
    try:
        payload = json.loads(payload_json)
    except (TypeError, ValueError):
        payload = None
    raw = payload.get("raw") if isinstance(payload, dict) else None
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, Any] = {"action": action, "ts": _iso(ts)}
    if action == "vuln_scan_failed":
        out["reason"] = raw.get("reason")
    else:
        out["advisory_mtime"] = raw.get("advisory_mtime")
        out["counts"] = {key: raw.get(key) for key in _COUNT_KEYS}
    return out


def handle_list_vulnerabilities(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    try:
        limit = int(params.get("limit", _DEFAULT_LIMIT))
    except (TypeError, ValueError):
        limit = _DEFAULT_LIMIT
    limit = max(1, min(_MAX_LIMIT, limit))
    severity = params.get("severity")
    include_acked = bool(params.get("include_acked", True))
    include_resolved = bool(params.get("include_resolved", False))

    where = "WHERE 1=1"
    args: list[Any] = []
    if severity:
        where += " AND severity = ?"
        args.append(str(severity))
    if not include_acked:
        where += " AND acked_at IS NULL"
    if not include_resolved:
        where += " AND resolved_at IS NULL"

    with Database(db_path) as db:
        rows = db.query(
            f"SELECT {_ROW_COLUMNS} FROM vulnerabilities {where}"
            " ORDER BY first_seen_at DESC LIMIT ?",
            [*args, limit],
        ).fetchall()
        last_scan = _last_scan(db)

    out = []
    for r in rows:
        out.append(
            {
                "avg_id": r[0],
                "cve_id": r[1],
                "package": r[2],
                "installed_version": r[3],
                "fixed_version": r[4],
                "severity": r[5],
                "status": r[6],
                "fix_in_testing": r[7],
                "first_seen_at": _iso(r[8]),
                "last_seen": _iso(r[9]),
                "last_event_id": r[10],
                "resolved_at": _iso(r[11]),
                "acked_at": _iso(r[12]),
                "acked_note": r[13],
            }
        )
    return {
        "schema_version": _SCHEMA_VERSION,
        "ok": True,
        "rows": out,
        "last_scan": last_scan,
    }


def handle_ack_vulnerability(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    avg_id = str(params.get("avg_id", ""))
    cve_id = str(params.get("cve_id", ""))
    package = str(params.get("package", ""))
    raw_note = params.get("note")
    note = str(raw_note) if raw_note else None

    now = datetime.now(UTC).replace(tzinfo=None)
    with Database(db_path) as db:
        row = db.query(
            "SELECT acked_at FROM vulnerabilities WHERE avg_id = ? AND cve_id = ? AND package = ?",
            [avg_id, cve_id, package],
        ).fetchone()
        if row is None:
            return {"schema_version": _SCHEMA_VERSION, "ok": False, "error": "not_found"}
        was_unacked = row[0] is None
        db.execute(
            "UPDATE vulnerabilities SET acked_at = ?, acked_note = ?"
            " WHERE avg_id = ? AND cve_id = ? AND package = ?",
            [now, note, avg_id, cve_id, package],
        )
    # Re-ack is an idempotent no-op for the audit trail: only a genuine
    # NULL→set transition writes a row (no fabricated audit entries).
    if was_unacked:
        append_audit(
            db_path,
            actor="user:local",
            action="vulnerability_acked",
            target=f"vuln:{avg_id}/{cve_id}/{package}",
            details={"note": note} if note else {},
        )
    return {"schema_version": _SCHEMA_VERSION, "ok": True, "acked_at": now.isoformat()}
