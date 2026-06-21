"""GET /persistence + /persistence/feed, POST /persistence/capture-baseline."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/persistence", response_class=HTMLResponse)
def persistence_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "persistence.html",
        {
            "request": request,
            "title": "inspectord — Persistence",
            "current_path": "/persistence",
        },
    )


@router.get("/persistence/feed", response_class=HTMLResponse)
def persistence_feed(
    request: Request,
    limit: int = Query(default=300, ge=1, le=1000),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    persistence: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_persistence", {"diff": True, "limit": limit})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        persistence = result.get("persistence", [])
    return templates.TemplateResponse(
        request,
        "persistence_feed.html",
        {"request": request, "persistence": persistence, "error": error},
    )


@router.post("/persistence/capture-baseline")
def persistence_capture_baseline(request: Request) -> RedirectResponse:
    try:
        call(request.app.state.socket_path, "capture_baseline", {"kind": "persistence"})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url="/persistence", status_code=303)
