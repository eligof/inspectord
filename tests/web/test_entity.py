"""Tests for the /entity/{kind} context card page."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method
from tests.web import web_client


def _card_method(response: dict[str, Any]) -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return response

    return Method(name="get_entity_card", handler=handler, mutates=False)


def _ok_card(**overrides: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "kind": "process",
        "key": "42@boot-1",
        "found": True,
        "header": {"pid": 42, "comm": "bash", "uid": 1000},
        "events": [
            {
                "event_id": "e1",
                "ts": "2026-08-23T00:00:00+00:00",
                "module": "exec_tracker",
                "action": "exec",
                "severity": "info",
                "payload": {},
            },
        ],
        "alerts": [
            {
                "alert_id": "a1",
                "rule_id": "lolbin.bash_dev_tcp",
                "ts": "2026-08-23T00:00:00+00:00",
                "severity": "critical",
                "status": "new",
                "rendered_short": "bash opened /dev/tcp",
            },
        ],
        "related": [
            {"kind": "ip", "key": "9.9.9.9", "label": "9.9.9.9", "relation": "connected_to"},
        ],
        "warnings": [],
    }
    card.update(overrides)
    return {"schema_version": "1.0.0", "ok": True, "card": card}


def test_entity_page_renders_card(ipc_factory) -> None:
    client = ipc_factory([_card_method(_ok_card())])
    response = client.get("/entity/process", params={"key": "42@boot-1"})
    assert response.status_code == 200
    assert "42@boot-1" in response.text
    assert "/entity/ip?key=9.9.9.9" in response.text
    assert "/alerts/a1" in response.text


def test_entity_page_unknown_kind_404(ipc_factory) -> None:
    client = ipc_factory([_card_method(_ok_card())])
    response = client.get("/entity/nonsense", params={"key": "x"})
    assert response.status_code == 404


def test_entity_page_invalid_key_shows_error(ipc_factory) -> None:
    client = ipc_factory(
        [_card_method({"schema_version": "1.0.0", "ok": False, "error": "invalid_key"})]
    )
    response = client.get("/entity/process", params={"key": "bad"})
    assert response.status_code == 200
    assert "invalid_key" in response.text


def test_entity_page_daemon_down_banner(tmp_path: Path) -> None:
    # No server is listening on this socket, so the IPC call fails.
    app = create_app(socket_path=tmp_path / "no.sock")
    client = web_client(app)
    response = client.get("/entity/service", params={"key": "sshd.service"})
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_entity_page_escapes_hostile_values(ipc_factory) -> None:
    hostile = "<script>alert(1)</script>"
    client = ipc_factory([_card_method(_ok_card(header={"pid": 42, "comm": hostile}))])
    response = client.get("/entity/process", params={"key": "42@boot-1"})
    assert response.status_code == 200
    assert "<script>alert(1)" not in response.text
    assert "&lt;script&gt;" in response.text
