"""GET /vulnerabilities + POST /vulnerabilities/ack (vuln-scanner design §6-§7)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()

#: Mirrors the worker's `advisory_stale_after_s` default (spec §3: 14 days).
#: The panel has no access to daemon config, so the default is a constant here;
#: a user who tunes the worker's threshold will still see the 14-day styling.
_ADVISORY_STALE_AFTER = timedelta(days=14)

#: The one advisory URL shape the panel ever renders. Built server-side from
#: the row's AVG id — never read from the feed (spec §5) — and only ever a
#: rendered link, never fetched (zero egress).
_ADVISORY_URL_BASE = "https://security.archlinux.org/"


def _advisory_age_days(advisory_mtime: Any) -> int | None:
    if not isinstance(advisory_mtime, str):
        return None
    try:
        mtime = datetime.fromisoformat(advisory_mtime)
    except ValueError:
        return None
    if mtime.tzinfo is None:
        mtime = mtime.replace(tzinfo=UTC)
    return max(0, int((datetime.now(UTC) - mtime).total_seconds() // 86400))


def _freshness(last_scan: dict[str, Any] | None) -> dict[str, Any]:
    """The §6 freshness line: latest completed OR failed scan, or never."""
    if last_scan is None:
        return {"mode": "never"}
    if last_scan.get("action") == "vuln_scan_failed":
        return {
            "mode": "failed",
            "ts": last_scan.get("ts"),
            "reason": last_scan.get("reason"),
        }
    age_days = _advisory_age_days(last_scan.get("advisory_mtime"))
    # An unknown advisory age is rendered as a warning, not as freshness: the
    # dead-refresh-cron failure mode gets a face, never an assumption (§6).
    stale = age_days is None or timedelta(days=age_days) > _ADVISORY_STALE_AFTER
    return {
        "mode": "completed",
        "ts": last_scan.get("ts"),
        "age_days": age_days,
        "stale": stale,
        "counts": last_scan.get("counts") or {},
    }


@router.get("/vulnerabilities", response_class=HTMLResponse)
def vulnerabilities_page(
    request: Request,
    severity: str | None = Query(default=None),
    include_acked: int = Query(default=1),
    include_resolved: int = Query(default=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    params: dict[str, Any] = {
        "limit": limit,
        "include_acked": bool(include_acked),
        "include_resolved": bool(include_resolved),
    }
    if severity:
        params["severity"] = severity
    rows: list[dict[str, Any]] = []
    last_scan: dict[str, Any] | None = None
    error: str | None = None
    try:
        result = call(socket_path, "list_vulnerabilities", params)
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        rows = result.get("rows", [])
        last_scan = result.get("last_scan")
    for row in rows:
        row["advisory_url"] = f"{_ADVISORY_URL_BASE}{row.get('avg_id', '')}"
    return templates.TemplateResponse(
        request,
        "vulnerabilities.html",
        {
            "request": request,
            "title": "inspectord — Vulnerabilities",
            "current_path": "/vulnerabilities",
            "rows": rows,
            "freshness": None if error else _freshness(last_scan),
            "severity": severity,
            "include_acked": bool(include_acked),
            "include_resolved": bool(include_resolved),
            "error": error,
        },
    )


@router.post("/vulnerabilities/ack")
def vulnerability_ack(
    request: Request,
    avg_id: str = Form(...),
    cve_id: str = Form(...),
    package: str = Form(...),
    note: str = Form(default=""),
) -> RedirectResponse:
    params: dict[str, Any] = {"avg_id": avg_id, "cve_id": cve_id, "package": package}
    if note:
        params["note"] = note
    try:
        result = call(request.app.state.socket_path, "ack_vulnerability", params)
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if result.get("ok") is not True:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    return RedirectResponse(url="/vulnerabilities", status_code=303)
