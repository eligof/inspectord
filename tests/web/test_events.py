"""Tests for the /events page."""

from __future__ import annotations

from inspectord.ipc_server import Method


def _list_events() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "events": [
                {
                    "event_id": "01900000-0000-7000-8000-000000000001",
                    "ts": "2026-05-25T14:23:10+00:00",
                    "module": "log_tailer",
                    "action": "package_installed",
                    "severity": "info",
                    "message": "installed audit",
                },
                {
                    "event_id": "01900000-0000-7000-8000-000000000002",
                    "ts": "2026-05-25T14:23:11+00:00",
                    "module": "fim_watcher",
                    "action": "file_created",
                    "severity": "low",
                    "message": "/etc/x",
                },
            ],
        }

    return Method(name="list_events", handler=handler, mutates=False)


def test_events_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_events()])
    response = client.get("/events")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/events/feed" in response.text
    assert "events-feed" in response.text


def test_events_feed_partial_returns_rows(ipc_factory) -> None:
    client = ipc_factory([_list_events()])
    response = client.get("/events/feed")
    assert response.status_code == 200
    assert "package_installed" in response.text
    assert "file_created" in response.text
    # Partial should NOT include the full base.html navigation chrome.
    assert "<nav>" not in response.text


def test_events_feed_supports_module_filter(ipc_factory) -> None:
    calls: list[dict] = []

    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "events": []}

    client = ipc_factory([Method(name="list_events", handler=handler, mutates=False)])
    response = client.get("/events/feed?module=log_tailer")
    assert response.status_code == 200
    assert any(c.get("module") == "log_tailer" for c in calls)
