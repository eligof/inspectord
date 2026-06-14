"""Tests for the IPC server."""

from __future__ import annotations

import grp
import json
import os
import socket
import stat
from pathlib import Path

from inspectord.config import IpcConfig
from inspectord.ipc_server import IpcServer, Method
from inspectord.schemas.versions import IPC_PROTOCOL_VERSION


def _roundtrip(sock_path: Path) -> None:
    """Connect to the IPC server and perform a single echo roundtrip."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(sock_path))
    req = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "ping",
        "params": {},
        "schema_version": IPC_PROTOCOL_VERSION,
    }
    sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
    line = b""
    while not line.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        line += chunk
    sock.close()
    resp = json.loads(line)
    assert resp["id"] == 99


def _make_ping_server(sock_path: Path, **kwargs: object) -> IpcServer:
    """Return an IpcServer with a trivial 'ping' method registered."""
    return IpcServer(
        socket_path=sock_path,
        methods=[Method(name="ping", handler=lambda _params: "pong", mutates=False)],
        allowed_uids=[],
        **kwargs,  # type: ignore[arg-type]
    )


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


# ---------------------------------------------------------------------------
# Permission hardening tests
# ---------------------------------------------------------------------------


def test_socket_is_owner_only_by_default(tmp_path: Path) -> None:
    """Without socket_group the socket must be created mode 0o600 (owner-only)."""
    sock_path = tmp_path / "ipc.sock"
    server = _make_ping_server(sock_path)
    server.start()
    try:
        mode = stat.S_IMODE(os.stat(sock_path).st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
    finally:
        server.stop()


def test_socket_group_sets_group_and_mode(tmp_path: Path) -> None:
    """With socket_group set to the caller's own group, socket mode is 0o660 and gid matches."""
    own_gid = os.getgid()
    own_group_name = grp.getgrgid(own_gid).gr_name
    sock_path = tmp_path / "ipc.sock"
    server = _make_ping_server(sock_path, socket_group=own_group_name)
    server.start()
    try:
        st = os.stat(sock_path)
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o660, f"expected 0o660, got {oct(mode)}"
        assert st.st_gid == own_gid, f"expected gid={own_gid}, got {st.st_gid}"
    finally:
        server.stop()


def test_unknown_socket_group_falls_back_to_owner_only(tmp_path: Path) -> None:
    """An unknown socket_group must not crash the server; socket falls back to 0o600."""
    sock_path = tmp_path / "ipc.sock"
    server = _make_ping_server(sock_path, socket_group="definitely_not_a_real_group_xyz")
    server.start()
    try:
        # Server must still serve requests (fail-closed, not crash).
        _roundtrip(sock_path)
        mode = stat.S_IMODE(os.stat(sock_path).st_mode)
        assert mode == 0o600, f"expected 0o600 fallback, got {oct(mode)}"
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Config model test
# ---------------------------------------------------------------------------


def test_ipc_config_socket_group_field() -> None:
    """IpcConfig must accept socket_group and default to None."""
    cfg_default = IpcConfig(socket_path="/run/inspectord/ipc.sock")
    assert cfg_default.socket_group is None

    cfg_set = IpcConfig(socket_path="/run/inspectord/ipc.sock", socket_group="mygroup")
    assert cfg_set.socket_group == "mygroup"
