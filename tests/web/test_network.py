"""Tests for the /network panel."""

from __future__ import annotations

from pathlib import Path

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method
from tests.web import web_client


def _list_connections() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "connections": [
                {
                    "conn_key": "1234:1.2.3.4:443:tcp",
                    "pid": 1234,
                    "comm": "curl",
                    "saddr": "10.0.0.5",
                    "sport": 54321,
                    "daddr": "1.2.3.4",
                    "dport": 443,
                    "proto": "tcp",
                    "family": "ipv4",
                    "status": "observed",
                    "first_seen": "2026-06-16T00:00:00",
                    "last_seen": "2026-06-16T01:00:00",
                    "active": True,
                }
            ],
        }

    return Method(name="list_connections", handler=handler, mutates=False)


def _list_listeners() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "listeners": [
                {
                    "addr": "0.0.0.0",
                    "port": 22,
                    "proto": "tcp",
                    "family": "ipv4",
                    "pid": None,
                    "comm": None,
                    "first_seen": "2026-06-16T00:00:00",
                }
            ],
        }

    return Method(name="list_listeners", handler=handler, mutates=False)


def test_network_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_connections(), _list_listeners()])
    response = client.get("/network")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/network/feed" in response.text
    assert "network-feed" in response.text


def test_network_feed_renders_both_tables(ipc_factory) -> None:
    client = ipc_factory([_list_connections(), _list_listeners()])
    response = client.get("/network/feed")
    assert response.status_code == 200
    # Connection values.
    assert "1.2.3.4" in response.text
    assert "443" in response.text
    assert "curl" in response.text
    # Listener values.
    assert "0.0.0.0" in response.text
    assert "22" in response.text
    # Both section headings.
    assert "<h2>Connections</h2>" in response.text
    assert "<h2>Listeners</h2>" in response.text
    assert "<nav>" not in response.text


def test_network_feed_empty_states(ipc_factory) -> None:
    def conns(params: dict) -> dict:
        return {"schema_version": "1.0.0", "connections": []}

    def listeners(params: dict) -> dict:
        return {"schema_version": "1.0.0", "listeners": []}

    client = ipc_factory(
        [
            Method(name="list_connections", handler=conns, mutates=False),
            Method(name="list_listeners", handler=listeners, mutates=False),
        ]
    )
    response = client.get("/network/feed")
    assert response.status_code == 200
    assert "No connections observed" in response.text
    assert "No listeners observed" in response.text


def test_network_feed_daemon_unreachable(tmp_path: Path) -> None:
    # No server is listening on this socket, so the IPC call fails.
    app = create_app(socket_path=tmp_path / "no.sock")
    client = web_client(app)
    response = client.get("/network/feed")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text
