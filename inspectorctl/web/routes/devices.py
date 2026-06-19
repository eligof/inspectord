"""GET /devices + /devices/feed."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/devices", response_class=HTMLResponse)
def devices_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "devices.html",
        {
            "request": request,
            "title": "inspectord — Devices",
            "current_path": "/devices",
        },
    )


@router.get("/devices/feed", response_class=HTMLResponse)
def devices_feed(
    request: Request,
    limit: int = Query(default=300, ge=1, le=1000),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    devices: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_devices", {"limit": limit})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        devices = result.get("devices", [])
    return templates.TemplateResponse(
        request,
        "devices_feed.html",
        {"request": request, "devices": devices, "error": error},
    )
