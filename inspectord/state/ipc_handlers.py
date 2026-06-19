"""IPC handlers for entity-state panels (spec §5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inspectord.state.baseline import capture_baseline
from inspectord.storage.db import Database

_INACTIVE = {"inactive", "failed", None}


def _diff_status(key: str, current_active: str | None, baseline: dict[str, dict[str, Any]]) -> str:
    if key not in baseline:
        return "new"
    base_active = baseline[key].get("active_state")
    if base_active in _INACTIVE and current_active == "active":
        return "re-enabled"
    return "unchanged"


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def handle_list_services(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    limit = int(params.get("limit", 200))
    want_diff = bool(params.get("diff", False))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT unit, active_state, sub_state, load_state, first_seen, last_seen "
            "FROM service_state ORDER BY unit LIMIT ?",
            [limit],
        ).fetchall()
        baseline: dict[str, dict[str, Any]] = {}
        if want_diff:
            brows = db.query(
                "SELECT key, attrs_json FROM baseline_entry WHERE kind='service'"
            ).fetchall()
            baseline = {k: json.loads(a) for k, a in brows}

    services: list[dict[str, Any]] = []
    current_keys: set[str] = set()
    for unit, active, sub, load, first_seen, last_seen in rows:
        key = f"svc:{unit}"
        current_keys.add(key)
        item: dict[str, Any] = {
            "unit": unit,
            "active_state": active,
            "sub_state": sub,
            "load_state": load,
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
        }
        if want_diff:
            item["diff_status"] = _diff_status(key, active, baseline)
        services.append(item)

    if want_diff:
        for key in sorted(baseline):
            if key not in current_keys:
                services.append(
                    {
                        "unit": key.removeprefix("svc:"),
                        "active_state": None,
                        "sub_state": None,
                        "load_state": None,
                        "first_seen": None,
                        "last_seen": None,
                        "diff_status": "removed",
                    }
                )

    return {"schema_version": "1.0.0", "services": services}


def handle_list_devices(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    limit = int(params.get("limit", 200))
    status = params.get("status")
    sql = (
        "SELECT dev_key, vendor, product, serial, subsystem, devnode, status, first_seen "
        "FROM device_state "
    )
    args: list[Any] = []
    if status is not None:
        sql += "WHERE status = ? "
        args.append(status)
    sql += "ORDER BY dev_key LIMIT ?"
    args.append(limit)
    with Database(db_path) as db:
        rows = db.query(sql, args).fetchall()

    devices: list[dict[str, Any]] = [
        {
            "dev_key": dev_key,
            "vendor": vendor,
            "product": product,
            "serial": serial,
            "subsystem": subsystem,
            "devnode": devnode,
            "status": status_,
            "first_seen": _iso(first_seen),
        }
        for dev_key, vendor, product, serial, subsystem, devnode, status_, first_seen in rows
    ]
    return {"schema_version": "1.0.0", "devices": devices}


def handle_list_processes(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    limit = int(params.get("limit", 200))
    status = params.get("status")
    sql = "SELECT pid, comm, ppid, uid, status, cmdline, first_seen FROM process_state "
    args: list[Any] = []
    if status is not None:
        sql += "WHERE status = ? "
        args.append(status)
    sql += "ORDER BY last_seen DESC LIMIT ?"
    args.append(limit)
    with Database(db_path) as db:
        rows = db.query(sql, args).fetchall()

    processes: list[dict[str, Any]] = [
        {
            "pid": pid,
            "comm": comm,
            "ppid": ppid,
            "uid": uid,
            "status": status_,
            "cmdline": cmdline,
            "first_seen": _iso(first_seen),
        }
        for pid, comm, ppid, uid, status_, cmdline, first_seen in rows
    ]
    return {"schema_version": "1.0.0", "processes": processes}


def handle_capture_baseline(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    kind = str(params.get("kind", "service"))
    with Database(db_path) as db:
        count = capture_baseline(kind, db)
    return {"schema_version": "1.0.0", "captured": count}
