"""Thin adapter so routes never touch IpcClient directly.

Centralising the calls makes future swaps (e.g. async IPC) a one-place change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectorctl.ipc_client import IpcClient, IpcError


class WebIpcError(RuntimeError):
    """Raised when the daemon isn't reachable or returns an RPC error."""


def call(socket_path: Path, method: str, params: dict[str, Any] | None = None) -> Any:
    try:
        return IpcClient(socket_path=Path(socket_path)).call(method, params)
    except IpcError as exc:
        raise WebIpcError(str(exc)) from exc
