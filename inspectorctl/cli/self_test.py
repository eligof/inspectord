"""inspectorctl self-test — verify the daemon is alive and accepting calls."""

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
    """End-to-end self-test: connect, call get_health, exit non-zero on failure."""
    client = IpcClient(socket_path=socket)
    try:
        report = client.call("get_health")
    except IpcError as exc:
        rprint(f"[red]FAIL[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if report.get("supervisor") == "running":
        rprint("[green]PASS[/green] inspectord is responding and supervisor is running")
        return
    rprint(f"[red]FAIL[/red] unexpected health report: {report!r}")
    raise typer.Exit(code=1)
