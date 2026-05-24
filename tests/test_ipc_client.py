"""Tests for the IPC client library."""

from __future__ import annotations

from pathlib import Path

from inspectorctl.ipc_client import IpcClient
from inspectord.ipc_server import IpcServer, Method


def test_client_can_call_method(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {"ok": True}

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="get_health", handler=handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        client = IpcClient(socket_path=sock_path)
        result = client.call("get_health")
        assert result == {"ok": True}
    finally:
        server.stop()
