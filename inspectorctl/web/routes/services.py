"""GET /services + /services/feed, POST /services/capture-baseline."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/services", response_class=HTMLResponse)
def services_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "services.html",
        {
            "request": request,
            "title": "inspectord — Services",
            "current_path": "/services",
        },
    )


@router.get("/services/feed", response_class=HTMLResponse)
def services_feed(
    request: Request,
    limit: int = Query(default=300, ge=1, le=1000),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    services: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_services", {"diff": True, "limit": limit})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        services = result.get("services", [])
    return templates.TemplateResponse(
        request,
        "services_feed.html",
        {"request": request, "services": services, "error": error},
    )


@router.post("/services/capture-baseline")
def services_capture_baseline(request: Request) -> RedirectResponse:
    try:
        call(request.app.state.socket_path, "capture_baseline", {"kind": "service"})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url="/services", status_code=303)
