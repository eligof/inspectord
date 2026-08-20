"""Host and origin guards for the dashboard's ASGI stack.

Two related controls live here. Both are installed as middleware in
:func:`inspectorctl.web.app.create_app`, so they run *before* routing and a
route added later is covered without opting in.

:class:`AllowedHostMiddleware` — **every** request
    Rejects any request whose ``Host`` is not a name this app answers to. The
    default allowlist is loopback only (``localhost``, ``*.localhost``,
    ``127.0.0.0/8``, ``::1``, in any bracketed or port-bearing spelling), which
    is the whole normal use of this dashboard; ``create_app(allowed_hosts=...)``
    adds more for the operator who deliberately exposes it (see
    ``inspectorctl-web --host/--allowed-host``).

:class:`SameOriginMiddleware` — unsafe methods only
    Rejects any request whose method is not in :data:`SAFE_METHODS` and whose
    ``Origin`` (falling back to ``Referer``) is not the dashboard's own origin.
    Binding to loopback stops a *remote* attacker but not a *cross-site* one: a
    plain form POST from any page the user happens to visit is a CORS-*simple*
    request, so the browser delivers it to ``http://127.0.0.1:<port>/`` with no
    preflight. The attacker cannot read the response, but by then the alert has
    been suppressed or the baseline re-captured.

Why both, and in that order
---------------------------

The same-origin check derives the app's own origin from the request's ``Host``
header rather than from ``--host``/``--port``: the browser sets ``Host`` from the
URL the user navigated to, an attacker's page cannot forge it, and the bind
address may never be the name the user actually types (``--host ::`` reached as
``http://localhost:8765``).

On its own that is not enough. Under **DNS rebinding** — a hostile name with a
short TTL that resolves first to the attacker's server and then to 127.0.0.1 —
*both* sides of the comparison become attacker-controlled: the browser sends
``Host: evil.example`` and ``Origin: http://evil.example``, they match, and the
request is genuinely same-origin. The ``Host`` allowlist is what closes that,
which is why it runs **outermost**: by the time the origin comparison trusts
``Host``, the allowlist has already established that ``Host`` is one of ours.

The allowlist covers safe methods too, not just the unsafe ones. A rebinding
attacker restricted to ``GET`` can still *read* dashboard pages — alerts, events,
process trees, watched file paths — and that is a disclosure, not a nuisance.
Confidentiality needs the same gate as integrity, so the ``Host`` check is
unconditional and only the origin check keys off the method.

Two further decisions worth knowing about:

* **Loopback spellings fold to one host.** ``localhost``, ``*.localhost``, any
  ``127.0.0.0/8`` address and ``::1`` canonicalise to a single sentinel, for both
  the allowlist and the origin comparison, because they all name this same
  process on a single-user box.
* **A request carrying neither ``Origin`` nor ``Referer`` is rejected** (fail
  closed). Every current browser sends ``Origin`` on POST, including same-origin
  POST, so the dashboard never lands here; non-browser clients (curl, scripts)
  must pass ``-H 'Origin: http://127.0.0.1:8765'``. Failing open would make the
  guard opt-out for anything that simply omits two headers, and there is no CSRF
  token to fall back on.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger(__name__)

#: Methods that cannot change state and are never guarded by the *origin*
#: check. Anything *not* in this set is guarded, so an unusual method on a
#: future route fails closed rather than slipping past a POST/PUT/PATCH/DELETE
#: denylist. The *Host* check ignores this set entirely — see the module
#: docstring.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

FORBIDDEN_BODY = (
    "Forbidden: cross-origin request blocked.\n"
    "This dashboard only accepts state-changing requests issued from the "
    "dashboard itself.\n"
)

BAD_HOST_BODY = (
    "Bad Request: unrecognised Host header.\n"
    "This dashboard only answers to the hosts it was configured for; by "
    "default that is loopback only.\n"
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


def _canonical_authority_host(authority: str) -> str | None:
    """Canonicalise the host out of a ``Host``-style authority, or ``None``.

    Accepts ``example.test``, ``127.0.0.1:8765``, ``[::1]:8765`` and — for
    configured values, which a ``Host`` header may not use — a bare IPv6 literal
    such as ``::1``. Returns ``None`` for anything unparseable or empty, and for
    anything a bare authority may not contain: userinfo, or trailing path/query/
    fragment (which is also what rejects a configured ``http://host``).

    The port is deliberately discarded: the allowlist is about *names*. Which
    port we answer on is decided by the listening socket, and the origin check
    still compares the port of ``Origin`` against the port in ``Host``.
    """

    authority = authority.strip()
    if not authority:
        return None
    # A bare IPv6 literal is ambiguous with host:port, so recognise it first.
    if authority.count(":") > 1 and not authority.startswith("["):
        return _canonical_host(authority)
    try:
        parts = urlsplit(f"//{authority}")
        parts.port  # noqa: B018 - raises ValueError on a non-numeric port
    except ValueError:
        return None
    # A bare authority carries a host, optionally a port, and nothing else: no
    # userinfo, and nothing trailing (which is also what rejects a configured
    # value with a scheme glued on, e.g. ``http://host``).
    if (
        not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path
        or parts.query
        or parts.fragment
    ):
        return None
    return _canonical_host(parts.hostname)


def build_allowed_hosts(extra: Iterable[str] | None = None) -> frozenset[str]:
    """Canonical hosts this app answers to: loopback, plus anything configured.

    ``extra`` holds operator-supplied values (the ``--host`` bind address and any
    ``--allowed-host``), which may be bare names, ``host:port`` or IPv6 literals.
    Unparseable entries are dropped rather than widening the allowlist.
    """

    hosts = {_LOOPBACK_HOST}
    for raw in extra or ():
        host = _canonical_authority_host(raw)
        if host:
            hosts.add(host)
    return frozenset(hosts)


def _parse_origin(value: str) -> Origin | None:
    """Normalise an ``Origin``/``Referer``/``scheme://host`` string, or ``None``.

    ``None`` means "not a usable origin" — the literal ``null`` opaque origin, a
    relative or malformed URL, or a scheme with no known default port. Callers
    treat that as a mismatch.
    """

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:  # malformed URL, or a non-numeric port
        return None
    if not parts.scheme or not parts.hostname:
        return None
    scheme = parts.scheme.lower()
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    if port is None:
        return None
    return scheme, _canonical_host(parts.hostname), port


def _scope_server_host(scope: Scope) -> str | None:
    """The local address we were reached on, for requests with no ``Host``."""

    server = scope.get("server")
    if not server or not server[0]:
        return None
    return str(server[0])


def _self_origin(scope: Scope, headers: Headers) -> Origin | None:
    """The origin the browser used to reach us, from the ``Host`` header.

    Only trustworthy because :class:`AllowedHostMiddleware` has already checked
    that ``Host`` is one of ours.
    """

    scheme = str(scope.get("scheme") or "http").lower()
    authority = headers.get("host")
    if not authority:
        host = _scope_server_host(scope)
        if host is None:
            return None
        authority = f"[{host}]" if ":" in host else host
        server = scope.get("server")
        if server and server[1]:
            authority = f"{authority}:{server[1]}"
    return _parse_origin(f"{scheme}://{authority}")


class AllowedHostMiddleware:
    """Reject any request addressed to a ``Host`` this app does not answer to."""

    def __init__(self, app: ASGIApp, *, allowed_hosts: Iterable[str] | None = None) -> None:
        self.app = app
        self.allowed_hosts = build_allowed_hosts(allowed_hosts)

    def _request_host(self, scope: Scope, headers: Headers) -> str | None:
        values = headers.getlist("host")
        if len(values) > 1:
            # Ambiguous, and a request-smuggling shape. Never allow it.
            return None
        if values:
            return _canonical_authority_host(values[0])
        # HTTP/1.0 clients may omit Host. The local socket address is not
        # attacker-controlled, so falling back to it is safe.
        server_host = _scope_server_host(scope)
        return _canonical_host(server_host) if server_host else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        host = self._request_host(scope, headers)
        if host is not None and host in self.allowed_hosts:
            await self.app(scope, receive, send)
            return

        log.warning(
            "blocked request for unrecognised host %s %s (host=%s)",
            _sanitise_for_log(str(scope.get("method", "?"))),
            _sanitise_for_log(str(scope.get("path", "?"))),
            _sanitise_for_log(headers.get("host")),
        )
        response = PlainTextResponse(BAD_HOST_BODY, status_code=400)
        await response(scope, receive, send)


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
