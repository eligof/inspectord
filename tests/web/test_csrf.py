"""Tests for the same-origin guard on state-changing dashboard requests.

The dashboard binds to loopback, which stops a *remote* attacker but not a
*cross-site* one: a form POST from any page the user visits reaches
``http://127.0.0.1:<port>/...`` with no CORS preflight. These tests pin the
guard that rejects those.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectorctl.web.csrf import _sanitise_for_log
from inspectord.ipc_server import IpcServer, Method

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Every mutating route that exists today. The enumeration test derives its own
# list from the live router; this constant only guards against the enumeration
# silently finding nothing.
KNOWN_MUTATING_ROUTE_COUNT = 11


@pytest.fixture
def bare_client(tmp_path: Path) -> TestClient:
    """A client whose requests never need to reach a route (guard rejects first)."""

    return TestClient(create_app(socket_path=tmp_path / "absent.sock"))


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
        headers={"Origin": "http://testserver"},
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

    sock = tmp_path / "ipc.sock"
    calls: list[dict] = []  # type: ignore[type-arg]
    server = IpcServer(socket_path=sock, methods=[_suppress_alert(calls)], allowed_uids=[])
    server.start()
    try:
        client = TestClient(create_app(socket_path=sock), base_url="http://127.0.0.1:8765")
        response = client.post(
            "/alerts/a1/suppress",
            headers={"Origin": origin},
            follow_redirects=False,
        )
        assert response.status_code == 303, origin
        assert len(calls) == 1
    finally:
        server.stop()


def test_non_loopback_host_matches_itself(tmp_path: Path) -> None:
    """The guard is not loopback-only: --host 0.0.0.0 reached by LAN IP still works."""

    sock = tmp_path / "ipc.sock"
    calls: list[dict] = []  # type: ignore[type-arg]
    server = IpcServer(socket_path=sock, methods=[_suppress_alert(calls)], allowed_uids=[])
    server.start()
    try:
        client = TestClient(create_app(socket_path=sock), base_url="http://192.168.1.5:8765")
        response = client.post(
            "/alerts/a1/suppress",
            headers={"Origin": "http://192.168.1.5:8765"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert len(calls) == 1
    finally:
        server.stop()


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
        "http://testserver.evil.example",
        "http://testserver:9999",  # right host, wrong port
        "https://testserver",  # right host, wrong scheme
        "http://localhost:8765",  # a loopback origin, but this app is `testserver`
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
        headers={"Referer": "http://testserver/alerts/a1"},
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
            "Referer": "http://testserver/alerts/a1",
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
