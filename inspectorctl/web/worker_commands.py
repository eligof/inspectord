"""Panel-side plumbing for worker "Run now" buttons (worker-command design §2 PR2).

One POST-303 helper and one banner builder, shared by every panel that grows a
run button. The worker-authored ``detail`` is untrusted on every surface (§6):
it rides the redirect as a URL-encoded query parameter and is rendered
exclusively through Jinja2 autoescaping — never as markup, never |safe.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi.responses import RedirectResponse

from inspectorctl.web.ipc import WebIpcError, call

#: The banner is a one-line verdict, not a transcript — bound what one outcome
#: may carry through the redirect URL.
_DETAIL_MAX_CHARS = 200
_STATUS_MAX_CHARS = 32

#: status → (banner css class, human phrasing). ``error`` is the web tier's
#: own status for an IPC-level failure (daemon down, allowlist/rate-limit
#: rejection) — the daemon never returns it.
_BANNERS: dict[str, tuple[str, str]] = {
    "accepted": ("notice", "accepted — the worker acts on it at its next loop iteration"),
    "rejected": ("notice-warn", "rejected by the worker"),
    "timeout": ("notice-warn", "no response from the worker in time — the command may still run"),
    "worker_unavailable": (
        "error",
        "worker unavailable — the daemon could not deliver the command",
    ),
    "worker_died": ("error", "the worker died before answering"),
    "error": ("error", "command failed"),
}
_UNKNOWN_BANNER = ("error", "unrecognised outcome")


def run_command_redirect(
    socket_path: Path,
    *,
    worker: str,
    command: str,
    args: dict[str, Any] | None = None,
    redirect_to: str,
) -> RedirectResponse:
    """POST half of the POST-303 pattern: send, carry the outcome as query flags.

    Never raises for a failed send — daemon-down and daemon-side rejections
    (allowlist, caps, rate limit) become the ``error`` outcome, so the button
    always lands the user back on the panel with a banner.
    """
    params: dict[str, Any] = {"worker": worker, "command": command}
    if args is not None:
        params["args"] = args
    try:
        result = call(socket_path, "run_worker_command", params)
    except WebIpcError as exc:
        status, detail = "error", str(exc)
    else:
        status = str(result.get("status", "error"))
        detail = str(result.get("detail", ""))
    query = urlencode(
        {"cmd_status": status[:_STATUS_MAX_CHARS], "cmd_detail": detail[:_DETAIL_MAX_CHARS]}
    )
    return RedirectResponse(url=f"{redirect_to}?{query}", status_code=303)


def outcome_banner(cmd_status: str | None, cmd_detail: str | None) -> dict[str, str] | None:
    """GET half: turn the redirect's query flags into banner context, or None.

    Both inputs are query parameters and therefore attacker-typable directly;
    the css class and message come only from the fixed tables above, and the
    detail is plain text for the autoescaping template.
    """
    if not cmd_status:
        return None
    css, message = _BANNERS.get(cmd_status, _UNKNOWN_BANNER)
    return {"css": css, "message": message, "detail": (cmd_detail or "")[:_DETAIL_MAX_CHARS]}
