"""IPC handlers for entity-state panels (spec §5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
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


def handle_list_connections(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    active_within_s = int(params.get("active_within_s", 300))
    limit = int(params.get("limit", 200))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT conn_key, pid, comm, saddr, sport, daddr, dport, proto, family, "
            "status, first_seen, last_seen FROM connection_state "
            "ORDER BY last_seen DESC LIMIT ?",
            [limit],
        ).fetchall()

    # DuckDB returns naive datetimes; compare against a naive UTC "now" so we
    # never subtract an aware datetime from a naive one (which raises).
    now = datetime.now(tz=UTC).replace(tzinfo=None)
    connections: list[dict[str, Any]] = []
    for (
        conn_key,
        pid,
        comm,
        saddr,
        sport,
        daddr,
        dport,
        proto,
        family,
        status_,
        first_seen,
        last_seen,
    ) in rows:
        active = last_seen is not None and (now - last_seen).total_seconds() <= active_within_s
        connections.append(
            {
                "conn_key": conn_key,
                "pid": pid,
                "comm": comm,
                "saddr": saddr,
                "sport": sport,
                "daddr": daddr,
                "dport": dport,
                "proto": proto,
                "family": family,
                "status": status_,
                "first_seen": _iso(first_seen),
                "last_seen": _iso(last_seen),
                "active": active,
            }
        )
    return {"schema_version": "1.0.0", "connections": connections}


def handle_list_listeners(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    limit = int(params.get("limit", 200))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT addr, port, proto, family, pid, comm, first_seen FROM listener_state "
            "ORDER BY addr, port LIMIT ?",
            [limit],
        ).fetchall()

    listeners: list[dict[str, Any]] = [
        {
            "addr": addr,
            "port": port,
            "proto": proto,
            "family": family,
            "pid": pid,
            "comm": comm,
            "first_seen": _iso(first_seen),
        }
        for addr, port, proto, family, pid, comm, first_seen in rows
    ]
    return {"schema_version": "1.0.0", "listeners": listeners}


def handle_list_persistence(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    limit = int(params.get("limit", 200))
    want_diff = bool(params.get("diff", False))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT persist_key, kind, name, source_path, details, first_seen, last_seen "
            "FROM persistence_state ORDER BY kind, name LIMIT ?",
            [limit],
        ).fetchall()
        baseline: dict[str, dict[str, Any]] = {}
        if want_diff:
            brows = db.query(
                "SELECT key, attrs_json FROM baseline_entry WHERE kind='persistence'"
            ).fetchall()
            baseline = {k: json.loads(a) for k, a in brows}

    persistence: list[dict[str, Any]] = []
    current_keys: set[str] = set()
    for persist_key, kind, name, source_path, details, first_seen, last_seen in rows:
        current_keys.add(persist_key)
        item: dict[str, Any] = {
            "persist_key": persist_key,
            "kind": kind,
            "name": name,
            "source_path": source_path,
            "details": details,
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
        }
        if want_diff:
            # Persistence diff is simpler than services: new/removed/unchanged only,
            # no "re-enabled" (a persistence mechanism either exists or it does not).
            item["diff_status"] = "new" if persist_key not in baseline else "unchanged"
        persistence.append(item)

    if want_diff:
        for key in sorted(baseline):
            if key not in current_keys:
                persistence.append(
                    {
                        "persist_key": key,
                        "kind": None,
                        "name": None,
                        "source_path": None,
                        "details": None,
                        "first_seen": None,
                        "last_seen": None,
                        "diff_status": "removed",
                    }
                )

    return {"schema_version": "1.0.0", "persistence": persistence}


def handle_list_file_changes(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    limit = int(params.get("limit", 200))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT path, change_type, first_seen, last_seen FROM file_state "
            "ORDER BY last_seen DESC LIMIT ?",
            [limit],
        ).fetchall()

    files: list[dict[str, Any]] = [
        {
            "path": path,
            "change_type": change_type,
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
        }
        for path, change_type, first_seen, last_seen in rows
    ]
    return {"schema_version": "1.0.0", "files": files}


def handle_capture_baseline(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    kind = str(params.get("kind", "service"))
    with Database(db_path) as db:
        count = capture_baseline(kind, db)
    return {"schema_version": "1.0.0", "captured": count}
