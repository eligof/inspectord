"""GET /file-integrity + /file-integrity/feed."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/file-integrity", response_class=HTMLResponse)
def file_integrity_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "file_integrity.html",
        {
            "request": request,
            "title": "inspectord — File integrity",
            "current_path": "/file-integrity",
        },
    )


@router.get("/file-integrity/feed", response_class=HTMLResponse)
def file_integrity_feed(
    request: Request,
    limit: int = Query(default=300, ge=1, le=1000),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    files: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_file_changes", {"limit": limit})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        files = result.get("files", [])
    return templates.TemplateResponse(
        request,
        "file_integrity_feed.html",
        {"request": request, "files": files, "error": error},
    )
