"""Tests for inspectorctl events CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from inspectorctl.cli.app import app
from inspectord.ipc_server import IpcServer, Method

runner = CliRunner()


def test_events_search_calls_ipc(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def list_events(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "events": [
                {
                    "event_id": "01900000-0000-7000-8000-000000000000",
                    "ts": "2026-05-24T14:23:10+00:00",
                    "module": "log_tailer",
                    "action": "package_installed",
                    "severity": "info",
                    "message": "installed audit",
                }
            ],
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="list_events", handler=list_events, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(
            app, ["events", "search", "--socket", str(sock_path), "--limit", "5"]
        )
        assert result.exit_code == 0
        assert "package_installed" in result.stdout
    finally:
        server.stop()


def test_events_search_with_a_query_hunts(tmp_path: Path) -> None:
    """Spec §24: `inspectorctl events search "<query>"` is the hunt verb."""
    sock_path = tmp_path / "ipc.sock"
    seen: list[dict[str, object]] = []

    def run_hunt_query(params: dict[str, object]) -> dict[str, object]:
        seen.append(params)
        return {
            "schema_version": "1.0.0",
            "ok": True,
            "name": None,
            "expression": params.get("expression"),
            "since": "2026-08-13T00:00:00+00:00",
            "until": None,
            "limit": 100,
            "truncated": False,
            "count": 1,
            "events": [
                {
                    "event_id": "01900000-0000-7000-8000-000000000000",
                    "ts": "2026-08-20T14:23:10+00:00",
                    "kind": "event",
                    "module": "log_tailer",
                    "action": "package_installed",
                    "severity": "info",
                    "payload": {"message": "installed audit"},
                }
            ],
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="run_hunt_query", handler=run_hunt_query, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(
            app,
            [
                "events",
                "search",
                'event.module == "log_tailer"',
                "--socket",
                str(sock_path),
                "--since",
                "24h",
            ],
            env={"COLUMNS": "220", "TERM": "dumb"},
        )
    finally:
        server.stop()
    assert result.exit_code == 0
    assert "package_installed" in result.stdout
    assert seen[0]["expression"] == 'event.module == "log_tailer"'
    # `24h` is client-side sugar resolved to an absolute bound before the call.
    assert str(seen[0]["since"]).startswith("20")
    assert "h" not in str(seen[0]["since"])[:4]


def test_events_search_refuses_module_together_with_a_query(tmp_path: Path) -> None:
    """A filter that silently does nothing is how a hunt returns the wrong answer."""
    result = runner.invoke(
        app,
        [
            "events",
            "search",
            'process.name == "curl"',
            "--module",
            "log_tailer",
            "--socket",
            str(tmp_path / "ipc.sock"),
        ],
        env={"COLUMNS": "220", "TERM": "dumb"},
    )
    assert result.exit_code == 2
    assert "--module" in result.stdout
