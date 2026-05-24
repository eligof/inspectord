"""Tests for the IPC server."""

from __future__ import annotations

import json
import socket
from pathlib import Path

from inspectord.ipc_server import IpcServer, Method


def test_ipc_get_health(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def get_health() -> dict[str, object]:
        return {"workers": [{"name": "healthcheck", "events_processed": 42}]}

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="get_health", handler=lambda params: get_health(), mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(sock_path))
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_health",
            "params": {},
            "schema_version": "1.0.0",
        }
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            line += chunk
        sock.close()
        response = json.loads(line.decode("utf-8"))
        assert response["id"] == 1
        assert response["result"]["workers"][0]["events_processed"] == 42
    finally:
        server.stop()


def test_ipc_rejects_unknown_method(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"
    server = IpcServer(socket_path=sock_path, methods=[], allowed_uids=[])
    server.start()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(sock_path))
        req = {"jsonrpc": "2.0", "id": 1, "method": "nope", "params": {}, "schema_version": "1.0.0"}
        sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            line += chunk
        sock.close()
        resp = json.loads(line)
        assert resp["error"]["code"] == -32601
    finally:
        server.stop()
