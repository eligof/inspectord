"""inspectorctl version — print the client + server versions."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint

import inspectorctl
from inspectorctl.ipc_client import IpcClient, IpcError

_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def cmd(
    socket: Annotated[
        Path,
        typer.Option("--socket", "-s"),
    ] = _DEFAULT_SOCKET,
) -> None:
    """Print client + daemon versions."""
    rprint(f"client: {inspectorctl.__version__}")
    try:
        report = IpcClient(socket_path=socket).call("get_health")
        rprint(f"daemon schema: {report.get('schema_version', '?')}")
    except IpcError:
        rprint("daemon: not running")
