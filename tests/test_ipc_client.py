"""Tests for the IPC client library."""

from __future__ import annotations

from pathlib import Path

import pytest

import inspectorctl.ipc_client as ipc_client_mod
from inspectorctl.ipc_client import IpcClient, IpcError
from inspectord.ipc_server import IpcServer, Method


def _server(tmp_path, methods):
    sock_path = tmp_path / "ipc.sock"
    server = IpcServer(socket_path=sock_path, methods=methods, allowed_uids=[])
    server.start()
    return server, sock_path


def test_client_reassembles_large_multichunk_response(tmp_path) -> None:
    # A payload far bigger than the 4096-byte recv chunk must reassemble intact.
    big = "x" * (512 * 1024)  # 512 KiB string, ~128 recv chunks

    def handler(_params):
        return {"blob": big}

    server, sock_path = _server(tmp_path, [Method(name="get_big", handler=handler, mutates=False)])
    try:
        result = IpcClient(socket_path=sock_path).call("get_big")
        assert result["blob"] == big
    finally:
        server.stop()


def test_client_rejects_oversized_response(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ipc_client_mod, "_MAX_RESPONSE_BYTES", 1024)  # tiny guard

    def handler(_params):
        return {"blob": "y" * (8 * 1024)}  # 8 KiB > guard

    server, sock_path = _server(tmp_path, [Method(name="get_big", handler=handler, mutates=False)])
    try:
        with pytest.raises(IpcError):
            IpcClient(socket_path=sock_path).call("get_big")
    finally:
        server.stop()


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
