"""GET /events + /events/feed — live events panel with HTMX polling."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/events", response_class=HTMLResponse)
def events_shell(
    request: Request,
    module: str | None = Query(default=None),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "events.html",
        {
            "request": request,
            "title": "inspectord — Events",
            "current_path": "/events",
            "module": module,
        },
    )


@router.get("/events/feed", response_class=HTMLResponse)
def events_feed(
    request: Request,
    module: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    params: dict[str, Any] = {"limit": limit}
    if module:
        params["module"] = module
    events: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_events", params)
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        events = list(reversed(result.get("events", [])))
    return templates.TemplateResponse(
        request,
        "events_feed.html",
        {"request": request, "events": events, "error": error},
    )
