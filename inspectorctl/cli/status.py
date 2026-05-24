"""inspectorctl status — show daemon + worker health."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint

from inspectorctl.ipc_client import IpcClient, IpcError

_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def cmd(
    socket: Annotated[
        Path,
        typer.Option("--socket", "-s", help="Path to the inspectord IPC socket"),
    ] = _DEFAULT_SOCKET,
) -> None:
    """Show daemon and worker health."""
    client = IpcClient(socket_path=socket)
    try:
        report = client.call("get_health")
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    rprint(report)
