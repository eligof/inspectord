"""Same-origin guard for state-changing dashboard requests.

Binding the dashboard to loopback stops a *remote* attacker but not a
*cross-site* one: a plain form POST from any page the user happens to visit is a
CORS-*simple* request, so the browser delivers it to ``http://127.0.0.1:<port>/``
with no preflight. The attacker cannot read the response, but by then the alert
has been suppressed or the baseline re-captured.

This module rejects any request whose method is not in :data:`SAFE_METHODS` and
whose ``Origin`` (falling back to ``Referer``) is not the dashboard's own origin.
It is installed as ASGI middleware in :func:`inspectorctl.web.app.create_app`, so
it runs *before* routing — routes added later are guarded without opting in.

Two decisions worth knowing about:

* **The app's own origin comes from the request's ``Host`` header**, not from
  ``--host``/``--port``. The browser sets ``Host`` from the URL the user
  navigated to and an attacker's page cannot forge it, while the bind address may
  never be the name the user actually types (``--host ::`` reached as
  ``http://localhost:8765``). All loopback spellings — ``localhost``,
  ``*.localhost``, ``127.0.0.0/8``, ``::1`` — canonicalise to one host, because
  they all name this same process. DNS rebinding (a hostile name resolving to
  127.0.0.1) is deliberately out of scope: that needs a ``Host`` allowlist, which
  is a different control.
* **A request carrying neither header is rejected** (fail closed). Every current
  browser sends ``Origin`` on POST, including same-origin POST, so the dashboard
  never lands here; non-browser clients (curl, scripts) must pass
  ``-H 'Origin: http://127.0.0.1:8765'``. Failing open would make the guard
  opt-out for anything that simply omits two headers, and there is no CSRF token
  to fall back on.
"""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger(__name__)

#: Methods that cannot change state and are never guarded. Anything *not* in
#: this set is guarded, so an unusual method on a future route fails closed
#: rather than slipping past a POST/PUT/PATCH/DELETE denylist.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

FORBIDDEN_BODY = (
    "Forbidden: cross-origin request blocked.\n"
    "This dashboard only accepts state-changing requests issued from the "
    "dashboard itself.\n"
)

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_LOOPBACK_HOST = "<loopback>"
_MAX_LOG_VALUE = 200

# A normalised origin: (scheme, canonical host, port).
Origin = tuple[str, str, int]


def _sanitise_for_log(value: str | None) -> str:
    """Make an attacker-supplied header value safe to put in a log line."""

    if value is None:
        return "-"
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in value)
    if len(cleaned) > _MAX_LOG_VALUE:
        cleaned = cleaned[:_MAX_LOG_VALUE] + "..."
    return cleaned


def _canonical_host(host: str) -> str:
    """Lower-case a host, unwrap IPv6 brackets, and fold loopback spellings."""

    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host == "localhost" or host.endswith(".localhost"):
        return _LOOPBACK_HOST
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return _LOOPBACK_HOST if address.is_loopback else address.compressed


def _parse_origin(value: str) -> Origin | None:
    """Normalise an ``Origin``/``Referer``/``scheme://host`` string, or ``None``.

    ``None`` means "not a usable origin" — the literal ``null`` opaque origin, a
    relative or malformed URL, or a scheme with no known default port. Callers
    treat that as a mismatch.
    """

    parts = urlsplit(value)
    if not parts.scheme or not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:  # non-numeric port
        return None
    scheme = parts.scheme.lower()
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    if port is None:
        return None
    return scheme, _canonical_host(parts.hostname), port


def _self_origin(scope: Scope, headers: Headers) -> Origin | None:
    """The origin the browser used to reach us, from the ``Host`` header."""

    scheme = str(scope.get("scheme") or "http").lower()
    authority = headers.get("host")
    if not authority:
        server = scope.get("server")
        if not server:
            return None
        host, port = server
        authority = f"[{host}]" if ":" in str(host) else str(host)
        if port:
            authority = f"{authority}:{port}"
    return _parse_origin(f"{scheme}://{authority}")


class SameOriginMiddleware:
    """Reject unsafe-method requests that did not come from the dashboard."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "") in SAFE_METHODS:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        origin = headers.get("origin")
        referer = headers.get("referer")
        # Origin is authoritative when present: a same-origin Referer must not
        # rescue a request that announced a foreign Origin.
        claimed = origin if origin is not None else referer
        expected = _self_origin(scope, headers)

        if claimed is not None and expected is not None and _parse_origin(claimed) == expected:
            await self.app(scope, receive, send)
            return

        log.warning(
            "blocked cross-origin %s %s (origin=%s referer=%s)",
            _sanitise_for_log(str(scope.get("method", "?"))),
            _sanitise_for_log(str(scope.get("path", "?"))),
            _sanitise_for_log(origin),
            _sanitise_for_log(referer),
        )
        response = PlainTextResponse(FORBIDDEN_BODY, status_code=403)
        await response(scope, receive, send)
