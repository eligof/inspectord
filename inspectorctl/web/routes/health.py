"""GET /health — worker status panel."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/health", response_class=HTMLResponse)
def health(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    context: dict[str, Any] = {
        "request": request,
        "title": "inspectord — Health",
        "current_path": "/health",
        "supervisor": "?",
        "workers": [],
        "error": None,
    }
    try:
        report = call(socket_path, "get_health")
    except WebIpcError as exc:
        context["error"] = f"daemon unreachable: {exc}"
    else:
        context["supervisor"] = report.get("supervisor", "?")
        context["workers"] = report.get("workers", [])
    return templates.TemplateResponse(request, "health.html", context)
