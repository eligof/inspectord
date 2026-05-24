"""IPC handlers for alerts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inspectord.alerts.lifecycle import validate_transition
from inspectord.schemas.alert import AlertStatus
from inspectord.storage.db import Database


def handle_list_alerts(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    status = params.get("status")
    severity = params.get("severity")
    limit = int(params.get("limit", 100))
    where = "WHERE 1=1"
    args: list[Any] = []
    if status:
        where += " AND status = ?"
        args.append(str(status))
    if severity:
        where += " AND severity = ?"
        args.append(str(severity))
    with Database(db_path) as db:
        rows = db.query(
            f"SELECT alert_id, rule_id, ts, severity, status, category, dedup_count, "
            f"rendered_short FROM alerts {where} ORDER BY ts DESC LIMIT ?",
            [*args, limit],
        ).fetchall()
    return {
        "schema_version": "1.0.0",
        "alerts": [
            {
                "alert_id": r[0],
                "rule_id": r[1],
                "ts": r[2].isoformat() if r[2] else None,
                "severity": r[3],
                "status": r[4],
                "category": r[5],
                "dedup_count": r[6],
                "rendered_short": r[7],
            }
            for r in rows
        ],
    }


def handle_get_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    alert_id = str(params.get("alert_id", ""))
    with Database(db_path) as db:
        rows = db.query("SELECT payload_json FROM alerts WHERE alert_id = ?", [alert_id]).fetchall()
    if not rows:
        return {"schema_version": "1.0.0", "alert": None}
    return {"schema_version": "1.0.0", "alert": json.loads(rows[0][0])}


def _transition(db_path: Path, *, alert_id: str, target: AlertStatus) -> dict[str, Any]:
    with Database(db_path) as db:
        rows = db.query("SELECT status FROM alerts WHERE alert_id = ?", [alert_id]).fetchall()
        if not rows:
            return {"schema_version": "1.0.0", "ok": False, "error": "not found"}
        current = AlertStatus(rows[0][0])
        validate_transition(current, target)
        db.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            [target.value, alert_id],
        )
    return {"schema_version": "1.0.0", "ok": True, "status": target.value}


def handle_ack_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    return _transition(
        db_path,
        alert_id=str(params.get("alert_id", "")),
        target=AlertStatus.acknowledged,
    )


def handle_resolve_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    return _transition(
        db_path,
        alert_id=str(params.get("alert_id", "")),
        target=AlertStatus.resolved,
    )


def handle_suppress_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    return _transition(
        db_path,
        alert_id=str(params.get("alert_id", "")),
        target=AlertStatus.suppressed,
    )
