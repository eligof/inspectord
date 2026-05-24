"""inspectorctl events subcommands."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint

from inspectorctl.ipc_client import IpcClient, IpcError

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Browse events flowing through the daemon.",
)


_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def _client(socket: Path) -> IpcClient:
    return IpcClient(socket_path=socket)


def _render(ev: dict[str, object]) -> str:
    ts = ev.get("ts") or ""
    module = ev.get("module") or "?"
    severity = ev.get("severity") or "?"
    action = ev.get("action") or "?"
    message = ev.get("message") or ""
    return f"{ts}  [{severity:<6}] {module:<18} {action:<28} {message}"


@app.command("search")
def search_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    module: Annotated[str | None, typer.Option("--module")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 100,
) -> None:
    """Print the most recent events (one-shot)."""
    params: dict[str, object] = {"limit": limit}
    if module:
        params["module"] = module
    try:
        result = _client(socket).call("list_events", params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    for ev in result.get("events", []):
        rprint(_render(ev))


@app.command("tail")
def tail_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    module: Annotated[str | None, typer.Option("--module")] = None,
    poll_interval: Annotated[float, typer.Option("--poll-interval")] = 1.0,
) -> None:
    """Stream new events as they arrive (polling)."""
    client = _client(socket)
    since: str | None = None
    try:
        while True:
            params: dict[str, object] = {"limit": 200}
            if module:
                params["module"] = module
            if since:
                params["since_id"] = since
            try:
                result = client.call("list_events", params)
            except IpcError as exc:
                rprint(f"[red]ERROR[/red] {exc}")
                raise typer.Exit(code=1) from exc
            for ev in result.get("events", []):
                rprint(_render(ev))
                since_raw = ev.get("event_id")
                if isinstance(since_raw, str):
                    since = since_raw
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        rprint("\n[dim]stopped[/dim]")
