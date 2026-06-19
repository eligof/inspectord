"""GET /network + /network/feed."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/network", response_class=HTMLResponse)
def network_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "network.html",
        {
            "request": request,
            "title": "inspectord — Network",
            "current_path": "/network",
        },
    )


@router.get("/network/feed", response_class=HTMLResponse)
def network_feed(
    request: Request,
    limit: int = Query(default=300, ge=1, le=1000),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    connections: list[dict[str, Any]] = []
    listeners: list[dict[str, Any]] = []
    error: str | None = None
    try:
        conn_result = call(socket_path, "list_connections", {"limit": limit})
        listener_result = call(socket_path, "list_listeners", {"limit": limit})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        connections = conn_result.get("connections", [])
        listeners = listener_result.get("listeners", [])
    return templates.TemplateResponse(
        request,
        "network_feed.html",
        {
            "request": request,
            "connections": connections,
            "listeners": listeners,
            "error": error,
        },
    )
