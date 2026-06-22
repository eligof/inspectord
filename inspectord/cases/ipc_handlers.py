"""IPC handlers for the Cases panel (spec §5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectord.cases import store
from inspectord.storage.db import Database


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def handle_open_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        case_id = store.open_case(db, alert_id=str(params["alert_id"]), title=params.get("title"))
    return {"schema_version": "1.0.0", "case_id": case_id}


def handle_attach_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        store.attach_alert(db, case_id=str(params["case_id"]), alert_id=str(params["alert_id"]))
    return {"schema_version": "1.0.0", "ok": True}


def handle_add_note(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        store.add_note(db, case_id=str(params["case_id"]), text=str(params["text"]))
    return {"schema_version": "1.0.0", "ok": True}


def handle_close_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        store.close_case(db, case_id=str(params["case_id"]))
    return {"schema_version": "1.0.0", "ok": True}


def handle_list_cases(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        cases = store.list_cases(db)
    for c in cases:
        c["opened_at"] = _iso(c["opened_at"])
        c["closed_at"] = _iso(c["closed_at"])
    return {"schema_version": "1.0.0", "cases": cases}


def handle_get_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        case = store.get_case(db, case_id=str(params["case_id"]))
    if case is not None:
        case["opened_at"] = _iso(case["opened_at"])
        case["closed_at"] = _iso(case["closed_at"])
        for a in case["alerts"]:
            a["ts"] = _iso(a["ts"])
        for t in case["timeline"]:
            t["ts"] = _iso(t["ts"])
        for ev in case["evidence"]:
            ev["captured_at"] = _iso(ev["captured_at"])
    return {"schema_version": "1.0.0", "case": case}
