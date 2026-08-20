"""Tests for the /services panel."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method

# A browser posting from the dashboard always sends Origin; the same-origin guard
# in inspectorctl.web.csrf rejects state-changing requests without it.
SAME_ORIGIN = {"Origin": "http://testserver"}


def _list_services() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "services": [
                {
                    "unit": "sshd.service",
                    "active_state": "active",
                    "sub_state": "running",
                    "load_state": "loaded",
                    "first_seen": "2026-06-16T00:00:00+00:00",
                    "last_seen": "2026-06-16T01:00:00+00:00",
                    "diff_status": "new",
                },
            ],
        }

    return Method(name="list_services", handler=handler, mutates=False)


def _capture_baseline(calls: list[dict]) -> Method:
    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "captured": 1}

    return Method(name="capture_baseline", handler=handler, mutates=True)


def test_services_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_services()])
    response = client.get("/services")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/services/feed" in response.text
    assert "services-feed" in response.text


def test_services_feed_renders_rows(ipc_factory) -> None:
    client = ipc_factory([_list_services()])
    response = client.get("/services/feed")
    assert response.status_code == 200
    assert "sshd.service" in response.text
    assert "new" in response.text
    assert "<nav>" not in response.text


def test_services_feed_empty_state(ipc_factory) -> None:
    def handler(params: dict) -> dict:
        return {"schema_version": "1.0.0", "services": []}

    client = ipc_factory([Method(name="list_services", handler=handler, mutates=False)])
    response = client.get("/services/feed")
    assert response.status_code == 200
    assert "No services observed" in response.text


def test_services_feed_daemon_unreachable(tmp_path: Path) -> None:
    # No server is listening on this socket, so the IPC call fails.
    app = create_app(socket_path=tmp_path / "no.sock")
    client = TestClient(app)
    response = client.get("/services/feed")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_capture_baseline_button_posts(ipc_factory) -> None:
    calls: list[dict] = []
    client = ipc_factory([_list_services(), _capture_baseline(calls)])
    response = client.post(
        "/services/capture-baseline", headers=SAME_ORIGIN, follow_redirects=False
    )
    assert response.status_code == 303
    assert any(c.get("kind") == "service" for c in calls)
