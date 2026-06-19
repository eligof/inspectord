"""Tests for the /file-integrity panel."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method


def _list_file_changes() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "files": [
                {
                    "path": "/etc/passwd",
                    "change_type": "modified",
                    "first_seen": "2026-06-16T00:00:00",
                    "last_seen": "2026-06-16T01:00:00",
                },
            ],
        }

    return Method(name="list_file_changes", handler=handler, mutates=False)


def test_file_integrity_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_file_changes()])
    response = client.get("/file-integrity")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/file-integrity/feed" in response.text
    assert "file-integrity-feed" in response.text


def test_file_integrity_feed_renders_rows(ipc_factory) -> None:
    client = ipc_factory([_list_file_changes()])
    response = client.get("/file-integrity/feed")
    assert response.status_code == 200
    assert "/etc/passwd" in response.text
    assert "modified" in response.text
    assert "<nav>" not in response.text


def test_file_integrity_feed_empty_state(ipc_factory) -> None:
    def handler(params: dict) -> dict:
        return {"schema_version": "1.0.0", "files": []}

    client = ipc_factory([Method(name="list_file_changes", handler=handler, mutates=False)])
    response = client.get("/file-integrity/feed")
    assert response.status_code == 200
    assert "No file changes observed" in response.text


def test_file_integrity_feed_daemon_unreachable(tmp_path: Path) -> None:
    # No server is listening on this socket, so the IPC call fails.
    app = create_app(socket_path=tmp_path / "no.sock")
    client = TestClient(app)
    response = client.get("/file-integrity/feed")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text
