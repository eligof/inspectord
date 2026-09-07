# `inspectorctl scanners run` (PR2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** CLI parity with the web Run-now buttons: `inspectorctl scanners run <aide|rkhunter|yara|vuln>` triggers the worker over the existing audited `run_worker_command` IPC.

**Architecture:** Pure IPC client (spec `2026-09-07-hunt-followups-design.md` §3). One new CLI module mirroring the params the web routes send (`inspectorctl/web/routes/scanners.py:45` and `routes/vulnerabilities.py:116`); zero daemon changes. Daemon response shape: `{ok, status, detail}` with `status ∈ {accepted, rejected, timeout, worker_unavailable, worker_died}`.

**Tech Stack:** Python 3.14, typer/rich, pytest.

**Branch:** new branch `scanners-run-cli` off up-to-date `main` (create AFTER PR1 merges).

**Gates before push:** same five commands as every PR (unit pytest marker run, integration marker run, ruff check, ruff format --check, mypy).

---

### Task 1: the verb

**Files:**
- Create: `inspectorctl/cli/scanners.py`
- Modify: `inspectorctl/cli/app.py`
- Test: `tests/test_cli_scanners.py`

- [ ] **Step 1: Write the failing tests**

Read `tests/test_cli_hunt.py` first and mirror its style for invoking typer commands and faking `IpcClient` (monkeypatch or its existing fake). Create `tests/test_cli_scanners.py`:

```python
"""CLI `scanners run` — mapping, passthrough, exit codes (spec §3)."""

import pytest

# mirror test_cli_hunt.py's imports/harness (typer CliRunner or direct calls)


@pytest.mark.parametrize(
    ("name", "expected_params"),
    [
        ("aide", {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "aide"}}),
        ("rkhunter", {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "rkhunter"}}),
        ("yara", {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "yara"}}),
        ("vuln", {"worker": "vuln_scanner", "command": "rescan"}),
    ],
)
def test_run_sends_the_web_buttons_params(name, expected_params, fake_ipc):
    # fake_ipc returns {"ok": True, "status": "accepted", "detail": ""}
    # invoke: scanners run <name>
    # assert fake_ipc captured method == "run_worker_command" and params == expected_params
    # assert exit code 0 and "triggered" in output
    ...

def test_run_unknown_name_rejected_client_side(fake_ipc):
    # invoke: scanners run clamav
    # assert exit code != 0, no IPC call made, output lists aide/rkhunter/yara/vuln
    ...

def test_run_daemon_rejection_passes_through(fake_ipc):
    # fake_ipc returns {"ok": False, "status": "rejected", "detail": "scanner disabled: aide"}
    # assert exit code 1, output contains "rejected" and "scanner disabled: aide" (escaped)
    ...

def test_run_daemon_unreachable(fake_ipc_raising_IpcError):
    # assert exit code 1, output contains the IpcError text
    ...
```

Fill the `...` bodies concretely in the style the harness dictates — the four behaviors above are the contract.

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/python -m pytest tests/test_cli_scanners.py -q`
Expected: FAIL with `ModuleNotFoundError: inspectorctl.cli.scanners`.

- [ ] **Step 3: Implement**

`inspectorctl/cli/scanners.py`:

```python
"""inspectorctl scanners subcommands (parent spec §24; hunt-followups spec §3).

`run` is a *trigger*, not a wait: the command channel is at-most-once and
trigger-only, so success here means "the worker was told", never "the scan
finished". The daemon's allowlist, rate limit and audit apply unchanged —
the name check below is UX, not enforcement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich import print as rprint
from rich.markup import escape

from inspectorctl.ipc_client import IpcClient, IpcError

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Trigger the periodic scanners on demand.",
)

_DEFAULT_SOCKET = Path("var") / "inspectord.sock"

#: name → run_worker_command params, mirroring the web Run-now buttons
#: (inspectorctl/web/routes/scanners.py / routes/vulnerabilities.py) exactly —
#: a second derivation of these dicts would drift.
_TRIGGERS: dict[str, dict[str, Any]] = {
    "aide": {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "aide"}},
    "rkhunter": {
        "worker": "scanner_runner",
        "command": "run_scanner",
        "args": {"name": "rkhunter"},
    },
    "yara": {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "yara"}},
    "vuln": {"worker": "vuln_scanner", "command": "rescan"},
}


@app.command("run")
def run_cmd(
    name: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Trigger one scanner now: aide, rkhunter, yara or vuln."""
    params = _TRIGGERS.get(name)
    if params is None:
        rprint(f"[red]unknown scanner[/red] {escape(name)}")
        rprint(f"[dim]valid names: {', '.join(sorted(_TRIGGERS))}[/dim]")
        raise typer.Exit(code=2)
    try:
        result = IpcClient(socket_path=socket).call("run_worker_command", params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc
    status = str(result.get("status", "error"))
    detail = str(result.get("detail", ""))
    if status == "accepted":
        rprint(f"[green]triggered[/green] {escape(name)}")
        rprint("[dim]watch /scanners or the events feed for the result[/dim]")
        return
    rprint(f"[red]{escape(status)}[/red] {escape(name)}")
    if detail:
        rprint(f"  {escape(detail)}")
    raise typer.Exit(code=1)
```

`inspectorctl/cli/app.py` — add `scanners` to the existing import line and register after `hunt`:

```python
from inspectorctl.cli import alerts, deps, events, hunt, scanners, self_test, status, version
...
app.add_typer(scanners.app, name="scanners")
```

- [ ] **Step 4: Run tests, verify pass**

Run: `.venv/bin/python -m pytest tests/test_cli_scanners.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/cli/scanners.py inspectorctl/cli/app.py tests/test_cli_scanners.py
git commit -m "feat(cli): inspectorctl scanners run — on-demand trigger over the command channel"
```

---

### Task 2: gates, push, PR

- [ ] **Step 1: Run all gates.** All green.
- [ ] **Step 2: Push, `gh pr create` (title `feat(cli): scanners run (PR2)`), watch CI via Monitor, squash-merge, sync main.**
