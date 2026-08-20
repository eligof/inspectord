"""inspectorctl events subcommands."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint

from inspectorctl.cli.hunt import run_query
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
    query: Annotated[
        str | None,
        typer.Argument(help="hunt expression, e.g. 'process.name == \"curl\"'"),
    ] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    module: Annotated[str | None, typer.Option("--module")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 100,
    since: Annotated[str | None, typer.Option("--since", help="ISO-8601 or 7d/24h/30m")] = None,
    until: Annotated[str | None, typer.Option("--until", help="ISO-8601 or 7d/24h/30m")] = None,
) -> None:
    """Search stored events (spec §24), or list the most recent ones.

    With a QUERY this is a hunt: the expression is the YAML-rule grammar,
    compiled to SQL, bounded and newest-first. Without one it keeps the older
    behaviour of printing the most recent events.
    """
    if query is None:
        _recent(socket=socket, module=module, limit=limit)
        return
    if module is not None:
        # Refused rather than ignored: a filter that silently does nothing is
        # how a hunt comes back with the wrong answer and no error.
        rprint(
            "[red]ERROR[/red] --module does not apply to a query; write it in the "
            "query instead, e.g. 'event.module == \"log_tailer\"'"
        )
        raise typer.Exit(code=2)
    run_query(socket=socket, expression=query, limit=limit, since=since, until=until)


def _recent(*, socket: Path, module: str | None, limit: int) -> None:
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
