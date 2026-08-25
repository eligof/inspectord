"""GET /audit + POST /audit/verify — audit trail panel (spec §7, PR2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    verified: str | None = Query(default=None),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    rows: list[dict[str, Any]] = []
    verification: dict[str, Any] | None = None
    error: str | None = None
    try:
        result = call(socket_path, "list_audit_log", {"limit": limit})
        rows = result.get("rows", [])
        if verified is not None:
            vres = call(socket_path, "verify_audit_log", {})
            verification = vres.get("verification")
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "request": request,
            "title": "inspectord — Audit log",
            "current_path": "/audit",
            "rows": rows,
            "verification": verification,
            "error": error,
        },
    )


@router.post("/audit/verify")
def audit_verify(request: Request) -> RedirectResponse:
    # POST-redirect keeps the verify user-initiated and un-prefetchable; the
    # GET performs the actual verify only when the ``verified`` flag is present
    # — read-only IPC, so running it on the redirected GET is safe and keeps
    # state out of the web tier.
    return RedirectResponse(url="/audit?verified=1", status_code=303)
