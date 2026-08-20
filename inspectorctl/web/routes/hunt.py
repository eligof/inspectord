"""GET /hunt — the Hunt panel (hunt design §9; plan 2026-08-20-hunt-panel).

Three properties of this module are load-bearing.

**It is a pure IPC client.** No filesystem, no database, and no import of the
compiler, the store or the daemon-side handlers. It calls `run_hunt_query` and
`list_hunt_queries` — both `mutates=False` — and renders the answers. The two
`mutates=True` methods (`save_hunt_query`, `delete_hunt_query`) are deliberately
absent: they write durable named state that another caller later runs, a save
with `replace` destroys the previous expression, and a browser page with no CSRF
token is the wrong front door for either. `inspectorctl hunt save/delete` is.

**Bounds are reported, never inferred.** The window, the resolved limit and the
`truncated` flag all come from the daemon's own response (§7). The panel never
recomputes "was this cut off?" by counting rows, and it echoes back the limit the
daemon *resolved* rather than the one the user asked for, so its silent cap at
`MAX_LIMIT` is visible on screen.

**Two kinds of failure stay two kinds.** A `HuntError` is written for the person
who typed the query and reaches us intact as `{ok: False, error, error_kind}`;
an internal failure reaches us as `internal error (error_ref=…)`. Flattening
them into one banner would either blame the user for a daemon bug or bury a
syntax error the user could have fixed in seconds.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

# The CLI's `24h`/`7d` shorthand, reused rather than reimplemented: a second
# parser here would drift from the CLI's, which is the same failure mode the
# design forbids for the query grammar itself (§3).
from inspectorctl.cli.hunt import to_iso
from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()

#: The payload paths a result row shows, in display order. The label *is* the
#: queryable path, so a field on screen can be pasted straight into the next
#: query. Deliberately absent: `raw` (the unparsed source line — reproducing it
#: is what "a wall of raw JSON" means), `host` (single-host product), `labels`,
#: `baseline`, `evidence`, `package`.
_DETAIL_PATHS: tuple[str, ...] = (
    "process.name",
    "process.pid",
    "process.executable",
    "process.command_line",
    "user.name",
    "user.id",
    "file.path",
    "file.hash.sha256",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "network.transport",
    "service.name",
    "service.state",
    "persistence.kind",
    "persistence.name",
    "persistence.source_path",
    "device.name",
    "device.vendor",
    "device.serial",
    "threat.indicator.type",
    "threat.indicator.value",
    "rule.name",
    "rule.id",
)

#: One hostile 4 MB `command_line` must not push the rest of the table off the
#: screen. The clip is marked with an ellipsis, because a silent clip is the
#: same lie as a silent truncation.
_MAX_VALUE_CHARS = 300


def _dig(payload: dict[str, Any], path: str) -> Any:
    """Walk a dotted path through nested dicts, like the query grammar does."""
    current: Any = payload
    for segment in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _clip(value: Any) -> str:
    text = str(value)
    return text if len(text) <= _MAX_VALUE_CHARS else text[:_MAX_VALUE_CHARS] + "…"


def _details(payload: dict[str, Any]) -> list[tuple[str, str]]:
    """The whitelisted, scalar payload fields present on one event."""
    found: list[tuple[str, str]] = []
    for path in _DETAIL_PATHS:
        value = _dig(payload, path)
        # Scalars only: a dict or list here means the event nests deeper than
        # this panel claims to know, and half-rendering it would mislead.
        if value is None or isinstance(value, dict | list):
            continue
        found.append((path, _clip(value)))
    return found


def _rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in result.get("events", []):
        payload = event.get("payload") or {}
        rows.append(
            {
                "event_id": event.get("event_id", ""),
                "ts": event.get("ts") or "",
                "kind": event.get("kind") or "",
                "module": event.get("module") or "",
                "action": event.get("action") or "",
                "severity": event.get("severity") or "",
                "message": _clip(payload.get("message")) if payload.get("message") else "",
                "details": _details(payload),
            }
        )
    return rows


def _ipc_failure(exc: WebIpcError) -> dict[str, str]:
    """Tell "the daemon is not there" apart from "the daemon broke".

    The second carries an `error_ref` the user can paste; neither is the user's
    query being wrong, so neither may render in the query-rejection slot.
    """
    text = str(exc)
    if "error_ref" in text:
        return {"kind": "internal", "message": text}
    return {"kind": "unreachable", "message": f"daemon unreachable: {text}"}


@router.get("/hunt", response_class=HTMLResponse)
def hunt(
    request: Request,
    q: str | None = Query(default=None),
    name: str | None = Query(default=None),
    since: str | None = Query(default=None),
    # Taken as text, not `int`, so a typo is answered by the daemon's own
    # "limit must be a whole number" rather than by a bare FastAPI 422.
    limit: str | None = Query(default=None),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path

    expression = (q or "").strip()
    saved_name = (name or "").strip()

    saved: list[dict[str, Any]] = []
    saved_error: dict[str, str] | None = None
    try:
        listed = call(socket_path, "list_hunt_queries", {})
    except WebIpcError as exc:
        # A broken list must not take the query box down with it.
        saved_error = _ipc_failure(exc)
    else:
        saved = list(listed.get("queries", []))

    result: dict[str, Any] | None = None
    query_error: dict[str, Any] | None = None
    run_error: dict[str, str] | None = None
    if expression or saved_name:
        params: dict[str, Any] = {"expression": expression} if expression else {"name": saved_name}
        if since:
            params["since"] = to_iso(since)
        if limit:
            params["limit"] = limit
        try:
            response = call(socket_path, "run_hunt_query", params)
        except WebIpcError as exc:
            run_error = _ipc_failure(exc)
        else:
            if response.get("ok"):
                result = response
            else:
                query_error = {
                    "kind": response.get("error_kind", "hunt"),
                    "message": response.get("error", "the daemon rejected this query"),
                }

    return templates.TemplateResponse(
        request,
        "hunt.html",
        {
            "request": request,
            "title": "inspectord — Hunt",
            "current_path": "/hunt",
            # Running a saved query fills the box with its expression, so the
            # next question can be asked by editing this one — which is how an
            # investigation actually goes.
            "q": q or (result["expression"] if result else ""),
            "since": since or "",
            # The limit box shows what the daemon actually used, so the screen
            # never claims a bound the query did not run under.
            "limit": str(result["limit"]) if result else (limit or ""),
            "result": result,
            "rows": _rows(result) if result else [],
            "query_error": query_error,
            "run_error": run_error,
            "saved": saved,
            "saved_error": saved_error,
        },
    )
