"""GET /deps — dependency status panel."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/deps", response_class=HTMLResponse)
def deps(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    context: dict[str, Any] = {
        "request": request,
        "title": "inspectord — Dependencies",
        "current_path": "/deps",
        "dependencies": [],
        "error": None,
    }
    try:
        result = call(socket_path, "list_dependencies")
    except WebIpcError as exc:
        context["error"] = f"daemon unreachable: {exc}"
    else:
        context["dependencies"] = result.get("dependencies", [])
    return templates.TemplateResponse(request, "deps.html", context)
