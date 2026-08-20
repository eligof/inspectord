"""Tests for the Host allowlist and the same-origin guard.

The dashboard binds to loopback, which stops a *remote* attacker but not a
*cross-site* one: a form POST from any page the user visits reaches
``http://127.0.0.1:<port>/...`` with no CORS preflight. The same-origin guard
rejects those.

That guard alone is not enough, because it derives the app's own origin from
``Host``. Under DNS rebinding the attacker controls *both* sides of that
comparison — ``Host: evil.example`` with ``Origin: http://evil.example`` matches.
The Host allowlist closes it, on every request rather than only the mutating
ones, since a rebinding attacker limited to GET can still read the dashboard.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectorctl.web.csrf import _sanitise_for_log, build_allowed_hosts
from inspectord.ipc_server import IpcServer, Method
from tests.web import BASE_URL, web_client

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Every mutating route that exists today. The enumeration test derives its own
# list from the live router; this constant only guards against the enumeration
# silently finding nothing.
KNOWN_MUTATING_ROUTE_COUNT = 11

#: A LAN address the app is *not* reachable at unless explicitly configured.
LAN_HOST = "192.168.1.5:8765"


@pytest.fixture
def bare_client(tmp_path: Path) -> TestClient:
    """A client whose requests never need to reach a route (guard rejects first)."""

    return web_client(create_app(socket_path=tmp_path / "absent.sock"))


@contextmanager
def _serving(
    tmp_path: Path, methods: list[Method], allowed_hosts: list[str] | None = None
) -> Iterator[TestClient]:
    """A live IPC server plus a client for the app in front of it."""

    sock = tmp_path / "ipc.sock"
    server = IpcServer(socket_path=sock, methods=methods, allowed_uids=[])
    server.start()
    try:
        app = create_app(socket_path=sock, allowed_hosts=allowed_hosts)
        yield TestClient(app, base_url=BASE_URL)
    finally:
        server.stop()


def _suppress_alert(calls: list[dict]) -> Method:  # type: ignore[type-arg]
    def handler(params: dict) -> dict:  # type: ignore[type-arg]
        calls.append(params)
        return {"schema_version": "1.0.0", "ok": True, "status": "suppressed"}

    return Method(name="suppress_alert", handler=handler, mutates=True)


def _list_alerts() -> Method:
    return Method(
        name="list_alerts",
        handler=lambda _params: {"schema_version": "1.0.0", "alerts": []},
        mutates=False,
    )


# --- the happy path: the dashboard itself ------------------------------------


def test_same_origin_post_is_allowed(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    calls: list[dict] = []  # type: ignore[type-arg]
    client = ipc_factory([_suppress_alert(calls)])
    response = client.post(
        "/alerts/a1/suppress",
        headers={"Origin": BASE_URL},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert len(calls) == 1


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:8765",
        "http://localhost:8765",
        "http://[::1]:8765",
        "http://127.0.0.2:8765",
        "http://dash.localhost:8765",
        "http://LOCALHOST:8765",
    ],
)
def test_loopback_aliases_count_as_same_origin(tmp_path: Path, origin: str) -> None:
    """A user on http://localhost:8765 must not be blocked by a 127.0.0.1 bind."""

    calls: list[dict] = []  # type: ignore[type-arg]
    with _serving(tmp_path, [_suppress_alert(calls)]) as client:
        response = client.post(
            "/alerts/a1/suppress",
            headers={"Origin": origin},
            follow_redirects=False,
        )
        assert response.status_code == 303, origin
        assert len(calls) == 1


def test_configured_non_loopback_host_is_served(tmp_path: Path) -> None:
    """--host 0.0.0.0 --allowed-host 192.168.1.5, reached by that LAN IP, works."""

    calls: list[dict] = []  # type: ignore[type-arg]
    with _serving(tmp_path, [_suppress_alert(calls)], ["0.0.0.0", "192.168.1.5"]) as client:
        response = client.post(
            "/alerts/a1/suppress",
            headers={"Host": LAN_HOST, "Origin": f"http://{LAN_HOST}"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert len(calls) == 1


# --- the attack --------------------------------------------------------------


def test_cross_origin_post_is_rejected(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    calls: list[dict] = []  # type: ignore[type-arg]
    client = ipc_factory([_suppress_alert(calls)])
    response = client.post(
        "/alerts/a1/suppress",
        headers={"Origin": "https://evil.example"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    # The side effect must not have happened.
    assert calls == []


def test_rejection_body_does_not_reflect_the_origin(bare_client: TestClient) -> None:
    response = bare_client.post(
        "/alerts/a1/suppress",
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "evil.example" not in response.text
    assert response.headers["content-type"].startswith("text/plain")
    assert "cross-origin request blocked" in response.text.lower()


@pytest.mark.parametrize(
    "origin",
    [
        "null",  # opaque origin: sandboxed iframe, data: document
        "https://evil.example",
        "http://evil.example",
        "http://127.0.0.1.evil.example",
        "http://127.0.0.1:9999",  # right host, wrong port
        "https://127.0.0.1:8765",  # right host, wrong scheme
        "http://127.0.0.1",  # loopback, but the default port is not ours
        "",  # present but empty
        "not a url",
    ],
)
def test_foreign_origins_are_rejected(bare_client: TestClient, origin: str) -> None:
    response = bare_client.post("/alerts/a1/suppress", headers={"Origin": origin})
    assert response.status_code == 403, origin


# --- header-absent cases -----------------------------------------------------


def test_referer_is_used_when_origin_is_absent(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    calls: list[dict] = []  # type: ignore[type-arg]
    client = ipc_factory([_suppress_alert(calls)])
    response = client.post(
        "/alerts/a1/suppress",
        headers={"Referer": f"{BASE_URL}/alerts/a1"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert len(calls) == 1


def test_foreign_referer_is_rejected(bare_client: TestClient) -> None:
    response = bare_client.post(
        "/alerts/a1/suppress",
        headers={"Referer": "https://evil.example/attack.html"},
    )
    assert response.status_code == 403


def test_origin_wins_over_referer(bare_client: TestClient) -> None:
    """A good Referer must not rescue a hostile Origin."""

    response = bare_client.post(
        "/alerts/a1/suppress",
        headers={
            "Origin": "https://evil.example",
            "Referer": f"{BASE_URL}/alerts/a1",
        },
    )
    assert response.status_code == 403


def test_no_origin_and_no_referer_is_rejected(bare_client: TestClient) -> None:
    """Fail closed: browsers always send Origin on POST, so absence is not the UI."""

    response = bare_client.post("/alerts/a1/suppress")
    assert response.status_code == 403


# --- safe methods stay untouched ---------------------------------------------


def test_get_with_hostile_origin_is_untouched(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    client = ipc_factory([_list_alerts()])
    response = client.get("/alerts", headers={"Origin": "https://evil.example"})
    assert response.status_code == 200


@pytest.mark.parametrize("method", sorted(SAFE_METHODS))
def test_safe_methods_are_never_blocked(bare_client: TestClient, method: str) -> None:
    response = bare_client.request(method, "/health", headers={"Origin": "https://evil.example"})
    assert response.status_code != 403


def test_static_assets_are_untouched(bare_client: TestClient) -> None:
    response = bare_client.get("/static/styles.css", headers={"Origin": "https://evil.example"})
    assert response.status_code == 200


# --- coverage of every mutating route, enumerated from the router ------------


def _mutating_routes(app) -> list[tuple[str, str]]:  # type: ignore[no-untyped-def]
    """Every (method, concrete path) in the live router that is not a safe method."""

    found: list[tuple[str, str]] = []
    for route in app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if not methods or path is None:
            continue  # Mounts (e.g. /static) carry no methods.
        for method in sorted(set(methods) - SAFE_METHODS):
            found.append((method, re.sub(r"\{[^}]+\}", "x", path)))
    return found


def test_every_mutating_route_rejects_cross_origin(bare_client: TestClient) -> None:
    routes = _mutating_routes(bare_client.app)
    assert len(routes) >= KNOWN_MUTATING_ROUTE_COUNT, routes
    for method, path in routes:
        response = bare_client.request(method, path, headers={"Origin": "https://evil.example"})
        assert response.status_code == 403, f"{method} {path} is not guarded"


def test_a_route_added_later_is_guarded_by_default(bare_client: TestClient) -> None:
    """The guard is middleware, so new routes are covered without opting in."""

    @bare_client.app.post("/newly-added-route")
    def _handler() -> dict[str, str]:  # pragma: no cover - must never be reached
        return {"ok": "yes"}

    assert ("POST", "/newly-added-route") in _mutating_routes(bare_client.app)
    response = bare_client.post("/newly-added-route", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


# --- observability -----------------------------------------------------------


def test_rejection_is_logged(bare_client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="inspectorctl.web.csrf"):
        bare_client.post("/alerts/a1/suppress", headers={"Origin": "https://evil.example"})
    records = [r for r in caplog.records if r.name == "inspectorctl.web.csrf"]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "POST" in message
    assert "/alerts/a1/suppress" in message
    assert "evil.example" in message


def test_logged_header_values_are_sanitised() -> None:
    """An attacker-supplied Origin must not be able to forge extra log lines."""

    forged = _sanitise_for_log("http://a\r\nWARNING forged log line\x00")
    assert "\r" not in forged
    assert "\n" not in forged
    assert "\x00" not in forged
    assert _sanitise_for_log("x" * 500) == "x" * 200 + "..."
    assert _sanitise_for_log(None) == "-"


# --- the Host allowlist ------------------------------------------------------

# These tests set ``Host`` explicitly rather than through the client's base URL:
# it is the header the guard reads, and Starlette's TestClient cannot parse an
# IPv6 base URL at all.


def _app(tmp_path: Path, allowed_hosts: list[str] | None = None) -> TestClient:
    app = create_app(socket_path=tmp_path / "absent.sock", allowed_hosts=allowed_hosts)
    return TestClient(app, base_url=BASE_URL)


@pytest.mark.parametrize(
    ("host", "origin", "expected"),
    [
        # The dashboard as the user actually reaches it.
        ("127.0.0.1:8765", "http://127.0.0.1:8765", 303),
        # An ordinary cross-site POST: the browser reports the attacker's origin.
        ("127.0.0.1:8765", "https://evil.example", 403),
        # DNS rebinding: evil.example now resolves to 127.0.0.1, so Host and
        # Origin agree and the request is *genuinely* same-origin. The origin
        # comparison cannot tell this apart -- only the Host allowlist can.
        ("evil.example", "http://evil.example", 400),
    ],
    ids=["dashboard", "cross-site", "dns-rebinding"],
)
def test_the_three_host_origin_combinations(
    tmp_path: Path, host: str, origin: str, expected: int
) -> None:
    calls: list[dict] = []  # type: ignore[type-arg]
    with _serving(tmp_path, [_suppress_alert(calls)]) as client:
        response = client.post(
            "/alerts/a1/suppress",
            headers={"Host": host, "Origin": origin},
            follow_redirects=False,
        )
    assert response.status_code == expected
    # The side effect happens only on the one legitimate row.
    assert len(calls) == (1 if expected == 303 else 0)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1:8765",
        "localhost:8765",
        "[::1]:8765",
        "127.0.0.2:8765",
        "dash.localhost:8765",
        "LOCALHOST:8765",
        "127.0.0.1",  # no port
        "[::1]",
    ],
)
def test_loopback_hosts_are_allowed_by_default(tmp_path: Path, host: str) -> None:
    """Every loopback spelling names this same process, so all of them are served."""

    response = _app(tmp_path).get("/static/styles.css", headers={"Host": host})
    assert response.status_code == 200, host


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        "192.168.1.5:8765",
        "127.0.0.1.evil.example",  # loopback-looking, but a name we do not own
        "localhost.evil.example",
        "",
        "@evil.example",
        "user@127.0.0.1:8765",  # userinfo is not legal in Host
        "127.0.0.1:notaport",
        "127.0.0.1/evil.example",  # a bare authority has nothing after it
    ],
)
def test_unknown_or_malformed_hosts_are_rejected(tmp_path: Path, host: str) -> None:
    response = _app(tmp_path).get("/alerts", headers={"Host": host})
    assert response.status_code == 400, host


def test_get_is_guarded_too_not_just_mutations(tmp_path: Path) -> None:
    """A rebinding attacker limited to GET can still *read* the dashboard."""

    client = _app(tmp_path)
    hostile = {"Host": "evil.example"}
    for method in sorted(SAFE_METHODS):
        assert client.request(method, "/alerts", headers=hostile).status_code == 400, method
    # Including the assets, which are what make a rebound page render at all.
    assert client.get("/static/styles.css", headers=hostile).status_code == 400


def test_unknown_host_rejection_does_not_echo_the_host(tmp_path: Path) -> None:
    response = _app(tmp_path).get("/alerts", headers={"Host": "evil.example"})
    assert response.status_code == 400
    assert "evil.example" not in response.text
    assert response.headers["content-type"].startswith("text/plain")
    assert "host" in response.text.lower()


def test_host_check_runs_before_the_origin_check(tmp_path: Path) -> None:
    """Host is validated outermost, so nothing downstream trusts an alien Host."""

    response = _app(tmp_path).post(
        "/alerts/a1/suppress",
        headers={"Host": "evil.example", "Origin": "https://elsewhere.example"},
    )
    assert response.status_code == 400  # not 403: the Host layer answered first


def test_duplicate_host_headers_are_rejected(tmp_path: Path) -> None:
    """Two Host headers are ambiguous, and a request-smuggling shape."""

    response = _app(tmp_path).get(
        "/alerts",
        headers=[("host", "127.0.0.1:8765"), ("host", "evil.example")],
    )
    assert response.status_code == 400


def test_unknown_host_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="inspectorctl.web.csrf"):
        _app(tmp_path).get("/alerts", headers={"Host": "evil.example"})
    records = [r for r in caplog.records if r.name == "inspectorctl.web.csrf"]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "GET" in message
    assert "/alerts" in message
    assert "evil.example" in message


def test_logged_host_is_truncated(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A hostile Host goes through the same sanitiser as a hostile Origin."""

    with caplog.at_level(logging.WARNING, logger="inspectorctl.web.csrf"):
        _app(tmp_path).get("/alerts", headers={"Host": "evil.example" + "x" * 500})
    message = caplog.records[0].getMessage()
    assert "x" * 300 not in message  # truncated, so it cannot flood the log
    assert message.endswith("...)")


# --- what the operator configures -------------------------------------------


def test_lan_host_is_refused_when_only_the_wildcard_bind_is_configured(tmp_path: Path) -> None:
    """`--host 0.0.0.0` alone names no browsable host, so the LAN IP stays closed."""

    client = _app(tmp_path, allowed_hosts=["0.0.0.0"])
    assert client.get("/alerts", headers={"Host": LAN_HOST}).status_code == 400


def test_lan_host_is_served_when_configured(tmp_path: Path) -> None:
    """`--host 0.0.0.0 --allowed-host 192.168.1.5` opens exactly that name."""

    client = _app(tmp_path, allowed_hosts=["0.0.0.0", "192.168.1.5"])
    assert client.get("/static/styles.css", headers={"Host": LAN_HOST}).status_code == 200


def test_a_concrete_bind_address_is_allowed_without_extra_flags(tmp_path: Path) -> None:
    """`--host 192.168.1.5` is itself the name the user will type."""

    client = _app(tmp_path, allowed_hosts=["192.168.1.5"])
    assert client.get("/static/styles.css", headers={"Host": LAN_HOST}).status_code == 200


def test_a_configured_host_still_gets_the_origin_check(tmp_path: Path) -> None:
    """Opening a host widens *reachability*, never the cross-site guard."""

    client = _app(tmp_path, allowed_hosts=["192.168.1.5"])
    response = client.post(
        "/alerts/a1/suppress",
        headers={"Host": LAN_HOST, "Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_configuring_one_host_does_not_open_others(tmp_path: Path) -> None:
    client = _app(tmp_path, allowed_hosts=["192.168.1.5"])
    assert client.get("/alerts", headers={"Host": "evil.example"}).status_code == 400


def test_loopback_stays_allowed_alongside_a_configured_host(tmp_path: Path) -> None:
    client = _app(tmp_path, allowed_hosts=["192.168.1.5"])
    assert client.get("/static/styles.css", headers={"Host": "localhost"}).status_code == 200


def test_build_allowed_hosts_normalises_and_drops_junk() -> None:
    hosts = build_allowed_hosts(
        [
            "192.168.1.5:8765",
            "[fe80::1]",
            "::1",
            "NUC.Lan",
            "",
            "  ",
            "h:notaport",
            "u@evil",
            "http://sneaky.lan",  # a scheme is not a host
        ]
    )
    assert "192.168.1.5" in hosts  # port stripped
    assert "fe80::1" in hosts  # brackets stripped
    assert "nuc.lan" in hosts  # lower-cased
    assert build_allowed_hosts(["::1"]) == build_allowed_hosts([])  # folds to loopback
    assert not any(h in hosts for h in ("", "  ", "h", "evil", "u@evil", "http", "sneaky.lan"))


def test_build_allowed_hosts_defaults_to_loopback_only() -> None:
    assert len(build_allowed_hosts()) == 1
    assert build_allowed_hosts([]) == build_allowed_hosts(None)


# --- regression --------------------------------------------------------------


def test_malformed_origin_is_rejected_not_crashed(bare_client: TestClient) -> None:
    """An unparseable URL must reach the 403, not raise out of urlsplit."""

    response = bare_client.post("/alerts/a1/suppress", headers={"Origin": "http://[::1"})
    assert response.status_code == 403
