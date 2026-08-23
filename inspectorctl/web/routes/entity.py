"""GET /entity/{kind} — entity context card page (spec §5, PR2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()

_KINDS = frozenset({"process", "executable", "user", "ip", "file", "port", "service", "device"})


@router.get("/entity/{kind}", response_class=HTMLResponse)
def entity_page(
    request: Request,
    kind: str,
    key: str = Query(min_length=1, max_length=512),
    window_h: int = Query(default=24, ge=1, le=168),
) -> _TemplateResponse:
    if kind not in _KINDS:
        raise HTTPException(status_code=404, detail="unknown entity kind")
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    card: dict[str, Any] | None = None
    error: str | None = None
    try:
        result = call(
            socket_path,
            "get_entity_card",
            {"kind": kind, "key": key, "window_h": window_h},
        )
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        if result.get("ok"):
            card = result.get("card")
        else:
            error = str(result.get("error", "unknown error"))
    return templates.TemplateResponse(
        request,
        "entity.html",
        {
            "request": request,
            "title": f"inspectord — {kind}:{key}",
            "current_path": "/entity",
            "kind": kind,
            "key": key,
            "window_h": window_h,
            "card": card,
            "error": error,
        },
    )
