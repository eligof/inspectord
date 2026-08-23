"""Tests for the /processes panel."""

from __future__ import annotations

from pathlib import Path

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method
from tests.web import web_client


def _list_processes() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "processes": [
                {
                    "pid": 1234,
                    "comm": "sshd",
                    "ppid": 1,
                    "uid": 0,
                    "status": "running",
                    "cmdline": "/usr/sbin/sshd -D",
                    "first_seen": "2026-06-16T00:00:00",
                },
            ],
        }

    return Method(name="list_processes", handler=handler, mutates=False)


def test_processes_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_processes()])
    response = client.get("/processes")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/processes/feed" in response.text
    assert "processes-feed" in response.text


def test_processes_feed_renders_rows(ipc_factory) -> None:
    client = ipc_factory([_list_processes()])
    response = client.get("/processes/feed")
    assert response.status_code == 200
    assert "1234" in response.text
    assert "sshd" in response.text
    assert "running" in response.text  # status column
    assert "/usr/sbin/sshd -D" in response.text  # cmdline column
    assert "<nav>" not in response.text


def test_processes_feed_empty_state(ipc_factory) -> None:
    def handler(params: dict) -> dict:
        return {"schema_version": "1.0.0", "processes": []}

    client = ipc_factory([Method(name="list_processes", handler=handler, mutates=False)])
    response = client.get("/processes/feed")
    assert response.status_code == 200
    assert "No processes observed" in response.text


def test_processes_feed_daemon_unreachable(tmp_path: Path) -> None:
    # No server is listening on this socket, so the IPC call fails.
    app = create_app(socket_path=tmp_path / "no.sock")
    client = web_client(app)
    response = client.get("/processes/feed")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def _list_processes_with_boot_id() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "boot_id": "boot-1",
            "processes": [
                {
                    "pid": 1234,
                    "comm": "sshd",
                    "ppid": 1,
                    "uid": 0,
                    "status": "running",
                    "cmdline": "/usr/sbin/sshd -D",
                    "first_seen": "2026-06-16T00:00:00",
                },
            ],
        }

    return Method(name="list_processes", handler=handler, mutates=False)


def test_processes_feed_links_pid_to_entity_card(ipc_factory) -> None:
    client = ipc_factory([_list_processes_with_boot_id()])
    response = client.get("/processes/feed")
    assert response.status_code == 200
    assert "/entity/process?key=1234%40boot-1" in response.text


def test_processes_feed_no_entity_link_without_boot_id(ipc_factory) -> None:
    client = ipc_factory([_list_processes()])
    response = client.get("/processes/feed")
    assert response.status_code == 200
    assert "/entity/process" not in response.text
    assert "1234" in response.text
