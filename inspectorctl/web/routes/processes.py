"""GET /processes + /processes/feed."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/processes", response_class=HTMLResponse)
def processes_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "processes.html",
        {
            "request": request,
            "title": "inspectord — Processes",
            "current_path": "/processes",
        },
    )


@router.get("/processes/feed", response_class=HTMLResponse)
def processes_feed(
    request: Request,
    limit: int = Query(default=300, ge=1, le=1000),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    processes: list[dict[str, Any]] = []
    boot_id: str | None = None
    error: str | None = None
    try:
        result = call(socket_path, "list_processes", {"limit": limit})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        processes = result.get("processes", [])
        boot_id = result.get("boot_id")
    return templates.TemplateResponse(
        request,
        "processes_feed.html",
        {"request": request, "processes": processes, "boot_id": boot_id, "error": error},
    )
