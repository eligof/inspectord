"""Client for the inspectord IPC server."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from inspectord.schemas.versions import IPC_PROTOCOL_VERSION


class IpcError(RuntimeError):
    pass


class IpcClient:
    def __init__(self, *, socket_path: Path) -> None:
        self._path = Path(socket_path)
        self._next_id = 0

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(self._path))
        except FileNotFoundError as exc:
            raise IpcError(f"socket not found: {self._path} (is inspectord running?)") from exc
        try:
            self._next_id += 1
            req = {
                "jsonrpc": "2.0",
                "id": self._next_id,
                "method": method,
                "params": params or {},
                "schema_version": IPC_PROTOCOL_VERSION,
            }
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            line = b""
            while not line.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                line += chunk
            resp = json.loads(line.decode("utf-8"))
            if "error" in resp:
                raise IpcError(f"{resp['error']['code']}: {resp['error']['message']}")
            return resp["result"]
        finally:
            sock.close()
