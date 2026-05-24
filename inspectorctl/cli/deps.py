"""inspectorctl deps subcommands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint
from rich.table import Table

from inspectorctl.ipc_client import IpcClient, IpcError

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Dependency management commands.",
)


_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def _client(socket: Path) -> IpcClient:
    return IpcClient(socket_path=socket)


@app.command("status")
def status_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Show the status of every declared dependency."""
    try:
        result = _client(socket).call("list_dependencies")
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Dependencies")
    table.add_column("Name")
    table.add_column("Installed")
    table.add_column("Version")
    table.add_column("Drop-in")
    table.add_column("Last verify")
    for d in result.get("dependencies", []):
        installed_flag = d.get("installed")
        if installed_flag is True:
            installed_cell = "[green]yes[/green]"
        elif installed_flag is False:
            installed_cell = "[red]no[/red]"
        else:
            installed_cell = "[dim]—[/dim]"

        verify_flag = d.get("last_verify_pass")
        if verify_flag is True:
            verify_cell = "[green]pass[/green]"
        elif verify_flag is False:
            verify_cell = "[red]fail[/red]"
        else:
            verify_cell = "[dim]—[/dim]"

        table.add_row(
            d["name"],
            installed_cell,
            d.get("installed_version") or "",
            "[green]yes[/green]" if d.get("dropin_present") else "[dim]—[/dim]",
            verify_cell,
        )
    rprint(table)


@app.command("plan")
def plan_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    profile: Annotated[str, typer.Option("--profile")] = "standard",
    flag: Annotated[list[str] | None, typer.Option("--flag")] = None,
) -> None:
    """Create an install plan; print it; do not apply."""
    flags: list[str] = flag or []
    try:
        result = _client(socket).call(
            "plan_dependency_install",
            {"profile": profile, "flags": flags, "actor": "cli@local"},
        )
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    rprint(f"[bold]Plan {result['plan_id']}[/bold]")
    rprint(f"distro: {result['distro']}, package_manager: {result['package_manager']}")
    rprint(f"expires_at: {result['expires_at']}")
    items = result.get("items", [])
    if not items:
        rprint("[green]Nothing to install — all required deps are already present.[/green]")
        return
    for item in items:
        rprint(
            f"  {item['name']}: install {item['packages']}; "
            f"service_actions={item['service_actions']}; "
            f"dropin={item.get('config_dropin') or '—'}"
        )
    rprint(f"\n[dim]Run `inspectorctl deps install --plan-id {result['plan_id']}` to apply.[/dim]")


@app.command("install")
def install_cmd(
    plan_id: Annotated[str | None, typer.Option("--plan-id")] = None,
    profile: Annotated[str, typer.Option("--profile")] = "standard",
    flag: Annotated[list[str] | None, typer.Option("--flag")] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt.")] = False,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Apply an install plan; create one first if --plan-id not given."""
    flags: list[str] = flag or []
    client = _client(socket)
    if plan_id is None:
        plan_result = client.call(
            "plan_dependency_install",
            {"profile": profile, "flags": flags, "actor": "cli@local"},
        )
        plan_id = plan_result["plan_id"]
        if not plan_result["items"]:
            rprint("[green]Nothing to install.[/green]")
            return
        if not yes:
            rprint(f"[yellow]Plan {plan_id} created. Items:[/yellow]")
            for item in plan_result["items"]:
                rprint(f"  {item['name']}: install {item['packages']}")
            confirm = typer.confirm("Apply this plan?", default=False)
            if not confirm:
                raise typer.Exit(code=1)

    try:
        result = client.call("apply_dependency_plan", {"plan_id": plan_id})
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if result.get("ok"):
        rprint(f"[green]Plan {plan_id} applied successfully.[/green]")
        for note in result.get("notes", []):
            rprint(f"  {note}")
    else:
        rprint(f"[red]Plan {plan_id} failed at: {result.get('failed_dep')}[/red]")
        raise typer.Exit(code=1)


@app.command("audit")
def audit_cmd(
    target: Annotated[str | None, typer.Option("--target")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Show the deps audit log (optionally filtered by target dep)."""
    try:
        result = _client(socket).call("get_dep_audit", {"target": target})
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    for e in result.get("entries", []):
        rprint(
            f"{e['ts']}  {e['actor']:<12} {e['action']:<24} "
            f"{e.get('target') or '—'}  {e.get('command') or ''}"
        )
