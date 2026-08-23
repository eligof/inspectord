"""IPC handlers for entity-state panels (spec §5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.state.baseline import capture_baseline
from inspectord.state.reconcile import current_boot_id
from inspectord.storage.db import Database

_INACTIVE = {"inactive", "failed", None}


def _current_boot_id_or_none() -> str | None:
    try:
        return current_boot_id()
    except OSError:
        return None


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
    return {
        "schema_version": "1.0.0",
        "processes": processes,
        "boot_id": _current_boot_id_or_none(),
    }


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
    return {
        "schema_version": "1.0.0",
        "connections": connections,
        "boot_id": _current_boot_id_or_none(),
    }


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


#: A run still marked `running` this long after it started can only mean the
#: daemon died mid-scan: a live worker always emits `scan_completed`, even on
#: timeout (`reason="timeout"`). Twice the longest default per-scan timeout
#: (aide, 3600 s) so a genuinely long scan is never mislabelled.
INCOMPLETE_AFTER_S = 7200

#: Rows of `scan_finding` events read before filtering. The runner caps findings
#: at 500 per run, so this comfortably covers the newest runs' finding sets.
_FINDINGS_SCAN_LIMIT = 1000


def handle_list_scan_runs(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    """The latest `scan_run` row per scanner (plan 2026-08-20-scanner-panel §4).

    `state` is the display state and is NOT the stored `status`: a row still
    `running` past `incomplete_after_s` is reported as `interrupted`. So a run
    whose `scan_completed` never arrived can never read as `success` (only a
    real completion writes that) and never as running-forever.

    A scanner with no row at all has never run — which a `skipped` row, carrying
    the runner's reason, stays distinct from.
    """
    limit = int(params.get("limit", 50))
    # Clamped: a zero or negative bound would report every in-flight scan as
    # interrupted, which is the one thing this state exists to avoid saying wrongly.
    incomplete_after_s = max(0.0, float(params.get("incomplete_after_s", INCOMPLETE_AFTER_S)))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT run_id, scanner, status, reason, exit_code, duration_s, finding_count, "
            "findings_dropped, truncated, output_truncated, output_excerpt, "
            "started_at, completed_at FROM scan_run "
            "QUALIFY ROW_NUMBER() OVER "
            "  (PARTITION BY scanner ORDER BY started_at DESC, run_id DESC) = 1 "
            "ORDER BY scanner LIMIT ?",
            [limit],
        ).fetchall()

    # DuckDB returns naive datetimes; compare against a naive UTC "now" so we
    # never subtract an aware datetime from a naive one (which raises).
    now = datetime.now(tz=UTC).replace(tzinfo=None)
    scanners: list[dict[str, Any]] = []
    for (
        run_id,
        scanner,
        status,
        reason,
        exit_code,
        duration_s,
        finding_count,
        findings_dropped,
        truncated,
        output_truncated,
        output_excerpt,
        started_at,
        completed_at,
    ) in rows:
        state = status
        if status == "running":
            age_s = (now - started_at).total_seconds() if started_at is not None else 0.0
            if age_s > incomplete_after_s:
                state = "interrupted"
        scanners.append(
            {
                "run_id": run_id,
                "scanner": scanner,
                "state": state,
                "reason": reason,
                "exit_code": exit_code,
                "duration_s": duration_s,
                "finding_count": finding_count,
                "findings_dropped": findings_dropped,
                "truncated": bool(truncated),
                "output_truncated": bool(output_truncated),
                "output_excerpt": output_excerpt,
                "started_at": _iso(started_at),
                "completed_at": _iso(completed_at),
            }
        )
    return {"schema_version": "1.0.0", "scanners": scanners}


def handle_list_scan_findings(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    """Recent `scan_finding` events, optionally restricted to given run ids.

    Findings stay events (scanner design decision 6), so this reads
    `events_enriched` rather than a findings table. Every string it returns is
    scanner output and therefore untrusted: a filename can forge a report line,
    so the path, indicator value and message may be attacker-chosen. They are
    passed through verbatim and must only ever be rendered as escaped text.
    """
    limit = int(params.get("limit", 50))
    scan_limit = int(params.get("scan_limit", _FINDINGS_SCAN_LIMIT))
    raw_run_ids = params.get("run_ids")
    run_ids = {str(r) for r in raw_run_ids} if raw_run_ids is not None else None

    with Database(db_path) as db:
        rows = db.query(
            "SELECT event_id, ts, payload_json FROM events_enriched "
            "WHERE module = 'scanner_runner' AND action = 'scan_finding' "
            "ORDER BY ts DESC, event_id DESC LIMIT ?",
            [scan_limit],
        ).fetchall()

    findings: list[dict[str, Any]] = []
    for event_id, ts, payload_json in rows:
        if len(findings) >= limit:
            break
        try:
            payload = json.loads(payload_json)
        except (TypeError, ValueError):
            # A row the panel cannot decode is skipped, never fatal — the same
            # rule the scanner parsers follow (inspectord/parsers/base.py).
            continue
        if not isinstance(payload, dict):
            continue
        raw = payload.get("raw") or {}
        run_id = raw.get("run_id")
        if run_ids is not None and run_id not in run_ids:
            continue
        indicator = (payload.get("threat") or {}).get("indicator") or {}
        findings.append(
            {
                "event_id": event_id,
                "ts": _iso(ts),
                "scanner": raw.get("scanner"),
                "run_id": run_id,
                "path": (payload.get("file") or {}).get("path"),
                "indicator_type": indicator.get("type"),
                "indicator_value": indicator.get("value"),
                "scanner_severity": indicator.get("severity"),
                "message": payload.get("message"),
            }
        )
    return {"schema_version": "1.0.0", "findings": findings}
