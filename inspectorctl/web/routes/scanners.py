"""GET /scanners + /scanners/feed — the Antivirus / scanners panel (parent spec §2.2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/scanners", response_class=HTMLResponse)
def scanners_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "scanners.html",
        {
            "request": request,
            "title": "inspectord — Scanners",
            "current_path": "/scanners",
        },
    )


@router.get("/scanners/feed", response_class=HTMLResponse)
def scanners_feed(
    request: Request,
    findings_limit: int = Query(default=50, ge=1, le=500),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    scanners: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    error: str | None = None
    try:
        scanners = call(socket_path, "list_scan_runs", {}).get("scanners", [])
        # Findings are scoped to the runs actually on display, so the list can
        # never show a hit from a run the summary above does not mention.
        run_ids = [s["run_id"] for s in scanners if s.get("run_id")]
        findings = call(
            socket_path,
            "list_scan_findings",
            {"run_ids": run_ids, "limit": findings_limit},
        ).get("findings", [])
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    return templates.TemplateResponse(
        request,
        "scanners_feed.html",
        {
            "request": request,
            "scanners": scanners,
            "findings": findings,
            "error": error,
        },
    )
