"""IPC handlers for the audit log (spec §7). Read-only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inspectord.audit.log import newest_anchor, verify_audit_chain
from inspectord.storage.db import Database

_SCHEMA_VERSION = "1.0.0"
_MAX_LIMIT = 500


def handle_list_audit_log(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    try:
        limit = int(params.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(_MAX_LIMIT, limit))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT seq, ts, actor, action, target, details_json "
            "FROM audit_log ORDER BY seq DESC LIMIT ?",
            [limit],
        ).fetchall()
    out = []
    for seq, ts, actor, action, target, details_json in rows:
        try:
            details = json.loads(details_json)
        except (TypeError, ValueError):
            details = None
        out.append(
            {
                "seq": seq,
                "ts": ts.isoformat(),
                "actor": actor,
                "action": action,
                "target": target,
                "details": details,
            }
        )
    return {"schema_version": _SCHEMA_VERSION, "ok": True, "rows": out}


def handle_verify_audit_log(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        verification = verify_audit_chain(db, anchor=newest_anchor(db))
    return {
        "schema_version": _SCHEMA_VERSION,
        "ok": True,
        "verification": verification.as_dict(),
    }
