"""Smoke test: the FastAPI app boots and serves /static/."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app


def test_create_app_returns_fastapi(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "nonexistent.sock")
    assert app is not None
    assert hasattr(app, "router")


def test_static_files_are_served(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "nonexistent.sock")
    client = TestClient(app)
    response = client.get("/static/htmx.min.js")
    assert response.status_code == 200
    assert len(response.content) > 100


def test_root_redirects_to_alerts(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "nonexistent.sock")
    client = TestClient(app, follow_redirects=False)
    response = client.get("/")
    assert response.status_code in (302, 307)
    assert response.headers["location"].endswith("/alerts")
