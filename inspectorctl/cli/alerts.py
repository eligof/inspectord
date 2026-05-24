"""inspectorctl alerts subcommands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint
from rich.table import Table

from inspectorctl.ipc_client import IpcClient, IpcError

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Alert triage commands.")


_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def _client(socket: Path) -> IpcClient:
    return IpcClient(socket_path=socket)


_SEVERITY_STYLE: dict[str, str] = {
    "critical": "[red]critical[/red]",
    "high": "[yellow]high[/yellow]",
    "medium": "[cyan]medium[/cyan]",
    "low": "[blue]low[/blue]",
    "info": "[dim]info[/dim]",
}


@app.command("list")
def list_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    status: Annotated[str | None, typer.Option("--status")] = None,
    severity: Annotated[str | None, typer.Option("--severity")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 50,
) -> None:
    """List alerts."""
    params: dict[str, object] = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    try:
        result = _client(socket).call("list_alerts", params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Alerts")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Rule")
    table.add_column("Dedup")
    table.add_column("Summary")
    for a in result.get("alerts", []):
        table.add_row(
            (a.get("alert_id") or "")[:8],
            _SEVERITY_STYLE.get(str(a.get("severity")), str(a.get("severity"))),
            str(a.get("status")),
            str(a.get("rule_id")),
            str(a.get("dedup_count", 1)),
            str(a.get("rendered_short", "")),
        )
    rprint(table)


@app.command("show")
def show_cmd(
    alert_id: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Show full detail for one alert."""
    try:
        result = _client(socket).call("get_alert", {"alert_id": alert_id})
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    alert = result.get("alert")
    if alert is None:
        rprint(f"[red]not found[/red]: {alert_id}")
        raise typer.Exit(code=1)
    rprint(alert)


def _mutate(method: str, alert_id: str, socket: Path, *, note: str | None = None) -> None:
    params: dict[str, object] = {"alert_id": alert_id}
    if note:
        params["note"] = note
    try:
        result = _client(socket).call(method, params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if not result.get("ok"):
        rprint(f"[red]FAIL[/red] {result.get('error', 'unknown')}")
        raise typer.Exit(code=1)
    rprint(f"[green]OK[/green] {alert_id} → {result['status']}")


@app.command("ack")
def ack_cmd(
    alert_id: str,
    note: Annotated[str | None, typer.Option("--note")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Acknowledge an alert (new → acknowledged)."""
    _mutate("ack_alert", alert_id, socket, note=note)


@app.command("resolve")
def resolve_cmd(
    alert_id: str,
    note: Annotated[str | None, typer.Option("--note")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Mark an alert resolved (terminal)."""
    _mutate("resolve_alert", alert_id, socket, note=note)


@app.command("suppress")
def suppress_cmd(
    alert_id: str,
    note: Annotated[str | None, typer.Option("--note")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Mark an alert suppressed (terminal — implies user added an allowlist entry)."""
    _mutate("suppress_alert", alert_id, socket, note=note)
