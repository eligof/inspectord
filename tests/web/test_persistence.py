"""Tests for the /persistence panel."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method

# A browser posting from the dashboard always sends Origin; the same-origin guard
# in inspectorctl.web.csrf rejects state-changing requests without it.
SAME_ORIGIN = {"Origin": "http://testserver"}


def _list_persistence() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "persistence": [
                {
                    "persist_key": "persist:cron:/etc/crontab:abc",
                    "kind": "cron",
                    "name": "backup",
                    "source_path": "/etc/crontab",
                    "details": "@daily root backup",
                    "first_seen": "2026-06-16T00:00:00",
                    "last_seen": "2026-06-16T01:00:00",
                    "diff_status": "new",
                },
            ],
        }

    return Method(name="list_persistence", handler=handler, mutates=False)


def _capture_baseline(calls: list[dict]) -> Method:
    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "captured": 1}

    return Method(name="capture_baseline", handler=handler, mutates=True)


def test_persistence_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_persistence()])
    response = client.get("/persistence")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/persistence/feed" in response.text
    assert "persistence-feed" in response.text


def test_persistence_feed_renders_rows(ipc_factory) -> None:
    client = ipc_factory([_list_persistence()])
    response = client.get("/persistence/feed")
    assert response.status_code == 200
    assert "cron" in response.text
    assert "backup" in response.text
    assert "/etc/crontab" in response.text
    assert "new" in response.text
    assert "<nav>" not in response.text


def test_persistence_feed_escapes_details(ipc_factory) -> None:
    def handler(params: dict) -> dict:
        return {
            "schema_version": "1.0.0",
            "persistence": [
                {
                    "persist_key": "persist:cron:/etc/crontab:xss",
                    "kind": "cron",
                    "name": "evil",
                    "source_path": "/etc/crontab",
                    "details": "<script>alert(1)</script>",
                    "first_seen": "2026-06-16T00:00:00",
                    "last_seen": "2026-06-16T01:00:00",
                    "diff_status": "new",
                },
            ],
        }

    client = ipc_factory([Method(name="list_persistence", handler=handler, mutates=False)])
    response = client.get("/persistence/feed")
    assert response.status_code == 200
    # Raw payload must be escaped, AND the escaped form must be present — the
    # latter guards against a false pass where the field is silently dropped.
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_persistence_feed_empty_state(ipc_factory) -> None:
    def handler(params: dict) -> dict:
        return {"schema_version": "1.0.0", "persistence": []}

    client = ipc_factory([Method(name="list_persistence", handler=handler, mutates=False)])
    response = client.get("/persistence/feed")
    assert response.status_code == 200
    assert "No persistence entries observed" in response.text


def test_persistence_feed_daemon_unreachable(tmp_path: Path) -> None:
    # No server is listening on this socket, so the IPC call fails.
    app = create_app(socket_path=tmp_path / "no.sock")
    client = TestClient(app)
    response = client.get("/persistence/feed")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_capture_baseline_button_posts(ipc_factory) -> None:
    calls: list[dict] = []
    client = ipc_factory([_list_persistence(), _capture_baseline(calls)])
    response = client.post(
        "/persistence/capture-baseline", headers=SAME_ORIGIN, follow_redirects=False
    )
    assert response.status_code == 303
    assert any(c.get("kind") == "persistence" for c in calls)
