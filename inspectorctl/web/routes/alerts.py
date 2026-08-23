"""GET /alerts, GET /alerts/{id}, POST mutations."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/alerts", response_class=HTMLResponse)
def alerts_list(
    request: Request,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    params: dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    alerts: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_alerts", params)
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        alerts = result.get("alerts", [])
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "request": request,
            "title": "inspectord — Alerts",
            "current_path": "/alerts",
            "status": status,
            "severity": severity,
            "alerts": alerts,
            "error": error,
        },
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: str) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    try:
        result = call(socket_path, "get_alert", {"alert_id": alert_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    alert = result.get("alert")
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert not found: {alert_id}")
    # Best-effort: the attach-to-case picker needs open cases, but an IPC error here
    # must not break the alert page (degrade to no picker).
    open_cases: list[dict[str, Any]] = []
    try:
        cases_result = call(socket_path, "list_cases", {})
    except WebIpcError:
        pass
    else:
        open_cases = [c for c in cases_result.get("cases", []) if c.get("status") == "open"]
    return templates.TemplateResponse(
        request,
        "alert_detail.html",
        {
            "request": request,
            "title": f"inspectord — Alert {alert_id[:8]}",
            "current_path": "/alerts",
            "alert": alert,
            "boot_id": result.get("boot_id"),
            "open_cases": open_cases,
        },
    )


def _mutate(socket_path: Any, method: str, alert_id: str) -> RedirectResponse:
    try:
        call(socket_path, method, {"alert_id": alert_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url="/alerts", status_code=303)


@router.post("/alerts/{alert_id}/ack")
def alert_ack(request: Request, alert_id: str) -> RedirectResponse:
    return _mutate(request.app.state.socket_path, "ack_alert", alert_id)


@router.post("/alerts/{alert_id}/resolve")
def alert_resolve(request: Request, alert_id: str) -> RedirectResponse:
    return _mutate(request.app.state.socket_path, "resolve_alert", alert_id)


@router.post("/alerts/{alert_id}/suppress")
def alert_suppress(request: Request, alert_id: str) -> RedirectResponse:
    return _mutate(request.app.state.socket_path, "suppress_alert", alert_id)


@router.post("/alerts/{alert_id}/open-case")
def alert_open_case(request: Request, alert_id: str) -> RedirectResponse:
    socket_path = request.app.state.socket_path
    try:
        result = call(socket_path, "open_case", {"alert_id": alert_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    case_id = result["case_id"]
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@router.post("/alerts/{alert_id}/attach-case")
def alert_attach_case(
    request: Request, alert_id: str, case_id: str = Form(...)
) -> RedirectResponse:
    try:
        call(
            request.app.state.socket_path,
            "attach_alert",
            {"case_id": case_id, "alert_id": alert_id},
        )
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url=f"/alerts/{alert_id}", status_code=303)
