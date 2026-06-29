"""Client for the inspectord IPC server."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from inspectord.schemas.versions import IPC_PROTOCOL_VERSION

# Guard on the response size. The largest legitimate response is a base64-encoded case
# export (daemon-capped at 64 MiB raw → ~85 MiB base64) plus JSON envelope; 96 MiB gives
# headroom while bounding a runaway/oversized response.
_MAX_RESPONSE_BYTES = 96 * 1024 * 1024


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
            buf = bytearray()
            while not buf.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk  # bytearray += is amortized O(1) (no quadratic recopy)
                if len(buf) > _MAX_RESPONSE_BYTES:
                    raise IpcError(
                        f"response exceeds {_MAX_RESPONSE_BYTES} bytes (too large for IPC)"
                    )
            resp = json.loads(bytes(buf).decode("utf-8"))
            if "error" in resp:
                raise IpcError(f"{resp['error']['code']}: {resp['error']['message']}")
            return resp["result"]
        finally:
            sock.close()
