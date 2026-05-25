"""Tests for the /health page."""

from __future__ import annotations

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method


def _ok_health() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "supervisor": "running",
            "workers": [
                {"name": "healthcheck", "status": "up"},
                {"name": "log_tailer", "status": "up"},
            ],
        }

    return Method(name="get_health", handler=handler, mutates=False)


def test_health_page_renders_workers(ipc_factory) -> None:
    client = ipc_factory([_ok_health()])
    response = client.get("/health")
    assert response.status_code == 200
    assert "supervisor" in response.text
    assert "healthcheck" in response.text
    assert "log_tailer" in response.text


def test_health_page_when_daemon_unreachable(tmp_path) -> None:
    """If IPC fails, render an error block instead of 500."""
    app = create_app(socket_path=tmp_path / "absent.sock")
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert "daemon" in response.text.lower() or "error" in response.text.lower()
