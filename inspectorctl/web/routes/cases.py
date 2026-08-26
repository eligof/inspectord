"""GET /cases, GET /cases/{id}, POST notes/close."""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/cases", response_class=HTMLResponse)
def cases_list(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    cases: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(request.app.state.socket_path, "list_cases", {})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        cases = result.get("cases", [])
    return templates.TemplateResponse(
        request,
        "cases.html",
        {
            "request": request,
            "title": "inspectord — Cases",
            "current_path": "/cases",
            "cases": cases,
            "error": error,
        },
    )


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: str) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    try:
        result = call(request.app.state.socket_path, "get_case", {"case_id": case_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    case = result.get("case")
    if case is None:
        raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
    return templates.TemplateResponse(
        request,
        "case_detail.html",
        {
            "request": request,
            "title": f"inspectord — Case {case_id[:8]}",
            "current_path": "/cases",
            "case": case,
        },
    )


def _case_mutate(
    socket_path: Any, method: str, params: dict[str, Any], case_id: str
) -> RedirectResponse:
    try:
        call(socket_path, method, params)
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url=f"/cases/{quote(case_id, safe='')}", status_code=303)


@router.post("/cases/{case_id}/notes")
def case_add_note(request: Request, case_id: str, text: str = Form(...)) -> RedirectResponse:
    return _case_mutate(
        request.app.state.socket_path,
        "add_note",
        {"case_id": case_id, "text": text},
        case_id,
    )


@router.post("/cases/{case_id}/close")
def case_close(request: Request, case_id: str) -> RedirectResponse:
    return _case_mutate(request.app.state.socket_path, "close_case", {"case_id": case_id}, case_id)


def _export_error_response(result: dict[str, Any]) -> None:
    """Translate a daemon error dict into an HTTPException. Returns None if no error."""
    if result.get("ok"):
        return None
    error = result.get("error")
    if error == "too_large":
        raise HTTPException(
            status_code=413,
            detail="export too large for browser download — retrieve from the on-disk "
            "forensic store",
        )
    raise HTTPException(status_code=404, detail=error or "not found")


@router.post("/cases/{case_id}/export")
def case_export(request: Request, case_id: str) -> Response:
    try:
        result = call(request.app.state.socket_path, "export_case_zip", {"case_id": case_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    _export_error_response(result)
    data = base64.b64decode(result["content_b64"])
    filename = result["filename"]
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/cases/{case_id}/evidence/{sha}")
def case_evidence_download(request: Request, case_id: str, sha: str) -> Response:
    try:
        result = call(
            request.app.state.socket_path,
            "download_evidence",
            {"case_id": case_id, "sha": sha},
        )
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    _export_error_response(result)
    data = base64.b64decode(result["content_b64"])
    return Response(
        content=data,
        media_type=result["media_type"],
        headers={"Content-Disposition": f'attachment; filename="{result["filename"]}"'},
    )
