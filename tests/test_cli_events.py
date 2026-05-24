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
