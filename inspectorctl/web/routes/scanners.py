"""GET /scanners + /scanners/feed — the Antivirus / scanners panel (parent spec §2.2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call
from inspectorctl.web.worker_commands import outcome_banner, run_command_redirect

router = APIRouter()


@router.get("/scanners", response_class=HTMLResponse)
def scanners_shell(
    request: Request,
    cmd_status: str | None = Query(default=None),
    cmd_detail: str | None = Query(default=None),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "scanners.html",
        {
            "request": request,
            "title": "inspectord — Scanners",
            "current_path": "/scanners",
            "command_banner": outcome_banner(cmd_status, cmd_detail),
        },
    )


@router.post("/scanners/run")
def scanners_run(request: Request, name: str = Form(...)) -> RedirectResponse:
    """Run now → run_worker_command (worker-command design §2 PR2, §7).

    ``name`` is forwarded verbatim; the scanner roster lives in the worker's
    own config, so validation (unknown/disabled) is the worker's verdict and
    comes back as a rejected banner rather than being second-guessed here.
    """
    return run_command_redirect(
        request.app.state.socket_path,
        worker="scanner_runner",
        command="run_scanner",
        args={"name": name},
        redirect_to="/scanners",
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
