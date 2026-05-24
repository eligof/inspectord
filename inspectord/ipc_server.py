"""Minimal JSON-RPC 2.0 server over a Unix socket.

Each connection is line-delimited JSON. Authentication is SO_PEERCRED:
if `allowed_uids` is non-empty, the caller's uid must be in the list.
Mutating methods can require a polkit check in a later phase; here we
only check the allowlist.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from inspectord.log import get
from inspectord.schemas.versions import IPC_PROTOCOL_VERSION

log = get(__name__)

_SO_PEERCRED = 17
_CRED_FMT = "iII"  # pid, uid, gid


@dataclass
class Method:
    name: str
    handler: Callable[[dict[str, Any]], Any]
    mutates: bool = False


def _peer_uid(sock: socket.socket) -> int:
    raw = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, struct.calcsize(_CRED_FMT))
    _pid, uid, _gid = struct.unpack(_CRED_FMT, raw)
    return int(uid)


def _err(req_id: object, code: int, message: str) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": code, "message": message},
            }
        )
        + "\n"
    ).encode("utf-8")


def _ok(req_id: object, result: object) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }
        )
        + "\n"
    ).encode("utf-8")


class IpcServer:
    def __init__(
        self,
        *,
        socket_path: Path,
        methods: list[Method],
        allowed_uids: list[int],
    ) -> None:
        self._path = Path(socket_path)
        self._methods = {m.name: m for m in methods}
        self._allowed_uids = list(allowed_uids)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._path.exists():
            self._path.unlink()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(self._path))
        os.chmod(self._path, 0o660)
        s.listen(16)
        self._sock = s
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            if self._allowed_uids and _peer_uid(conn) not in self._allowed_uids:
                conn.sendall(_err(None, -32000, "peer uid not allowed"))
                return
            with conn.makefile("rb") as rf:
                for line in rf:
                    stripped = line.rstrip(b"\n")
                    if not stripped:
                        continue
                    try:
                        req = json.loads(stripped.decode("utf-8"))
                    except Exception:
                        conn.sendall(_err(None, -32700, "parse error"))
                        continue
                    self._dispatch(conn, req)
        finally:
            conn.close()

    def _dispatch(self, conn: socket.socket, req: dict[str, Any]) -> None:
        req_id = req.get("id")
        if req.get("jsonrpc") != "2.0":
            conn.sendall(_err(req_id, -32600, "invalid request"))
            return
        if req.get("schema_version") != IPC_PROTOCOL_VERSION:
            msg = f"unsupported schema_version, expected {IPC_PROTOCOL_VERSION}"
            conn.sendall(_err(req_id, -32602, msg))
            return
        method = self._methods.get(req.get("method", ""))
        if method is None:
            conn.sendall(_err(req_id, -32601, "method not found"))
            return
        try:
            result = method.handler(req.get("params") or {})
            conn.sendall(_ok(req_id, result))
        except Exception as exc:
            log.exception("handler raised")
            conn.sendall(_err(req_id, -32000, repr(exc)))
