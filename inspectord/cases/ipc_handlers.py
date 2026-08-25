"""IPC handlers for the Cases panel (spec §5)."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from inspectord.audit.log import append_audit
from inspectord.cases import export, store
from inspectord.evidence.store import ForensicStore
from inspectord.ipc_errors import IpcParamError
from inspectord.storage.db import Database


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _required(params: dict[str, Any], key: str) -> str:
    """Read a required parameter, or say which one is missing.

    A bare `params[key]` raised `KeyError`, and `_dispatch` used to forward its
    repr — so "which parameter did I forget?" was answered only as a side effect
    of a leak that also forwarded DuckDB's SQL. Now the answer is deliberate:
    `IpcParamError` is client-facing and names a parameter the client chose.
    """
    value = params.get(key)
    if value is None or value == "":
        raise IpcParamError(f"{key} is required")
    return str(value)


def handle_open_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        case_id = store.open_case(
            db, alert_id=_required(params, "alert_id"), title=params.get("title")
        )
        # The stored title may be derived (from the alert) rather than the param.
        title_row = db.query("SELECT title FROM cases WHERE case_id = ?", [case_id]).fetchone()
    append_audit(
        db_path,
        actor="user:local",
        action="case_opened",
        target=f"case:{case_id}",
        details={"title": title_row[0] if title_row else None},
    )
    return {"schema_version": "1.0.0", "case_id": case_id}


def handle_attach_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    case_id = _required(params, "case_id")
    alert_id = _required(params, "alert_id")
    with Database(db_path) as db:
        store.attach_alert(db, case_id=case_id, alert_id=alert_id)
    append_audit(
        db_path,
        actor="user:local",
        action="case_alert_attached",
        target=f"case:{case_id}",
        details={"alert_id": alert_id},
    )
    return {"schema_version": "1.0.0", "ok": True}


def handle_add_note(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    case_id = _required(params, "case_id")
    with Database(db_path) as db:
        store.add_note(db, case_id=case_id, text=_required(params, "text"))
    append_audit(
        db_path,
        actor="user:local",
        action="case_note_added",
        target=f"case:{case_id}",
        details={},  # note text stays in case_event
    )
    return {"schema_version": "1.0.0", "ok": True}


def handle_close_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    case_id = _required(params, "case_id")
    with Database(db_path) as db:
        store.close_case(db, case_id=case_id)
    append_audit(
        db_path,
        actor="user:local",
        action="case_closed",
        target=f"case:{case_id}",
        details={},
    )
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
        case = store.get_case(db, case_id=_required(params, "case_id"))
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


def handle_export_case_zip(
    *, params: dict[str, Any], db_path: Path, evidence_dir: Path
) -> dict[str, Any]:
    case_id = _required(params, "case_id")
    store_ = ForensicStore(evidence_dir)
    with Database(db_path) as db:
        try:
            data = export.build_case_zip(db, store_, case_id)
        except export.CaseNotFound:
            return {"schema_version": "1.0.0", "ok": False, "error": "not found"}
        except export.ExportTooLarge:
            return {"schema_version": "1.0.0", "ok": False, "error": "too_large"}
        store.append_timeline(db, case_id=case_id, kind="exported", text="case exported as ZIP")
    append_audit(
        db_path,
        actor="user:local",
        action="case_exported",
        target=f"case:{case_id}",
        details={"bytes": len(data)},
    )
    return {
        "schema_version": "1.0.0",
        "ok": True,
        "filename": f"case-{case_id[:8]}.zip",
        "content_b64": base64.b64encode(data).decode("ascii"),
    }


def handle_download_evidence(
    *, params: dict[str, Any], db_path: Path, evidence_dir: Path
) -> dict[str, Any]:
    case_id = _required(params, "case_id")
    sha = _required(params, "sha")
    store_ = ForensicStore(evidence_dir)
    with Database(db_path) as db:
        try:
            data, filename, media_type = export.read_evidence_blob(db, store_, case_id, sha)
        except export.EvidenceNotFound:
            return {"schema_version": "1.0.0", "ok": False, "error": "not found"}
        except export.ExportTooLarge:
            return {"schema_version": "1.0.0", "ok": False, "error": "too_large"}
        store.append_timeline(
            db, case_id=case_id, kind="evidence_downloaded", text=f"downloaded {sha[:12]}"
        )
    append_audit(
        db_path,
        actor="user:local",
        action="evidence_downloaded",
        target=f"case:{case_id}",
        details={"sha256": sha},
    )
    return {
        "schema_version": "1.0.0",
        "ok": True,
        "filename": filename,
        "media_type": media_type,
        "content_b64": base64.b64encode(data).decode("ascii"),
    }
