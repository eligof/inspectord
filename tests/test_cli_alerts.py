"""Tests for inspectorctl alerts CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from inspectorctl.cli.app import app
from inspectord.ipc_server import IpcServer, Method

runner = CliRunner()


def test_alerts_list_renders(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alerts": [
                {
                    "alert_id": "a1",
                    "rule_id": "lolbin.bash_dev_tcp",
                    "ts": "2026-05-24T14:23:10+00:00",
                    "severity": "critical",
                    "status": "new",
                    "dedup_count": 1,
                    "rendered_short": "Reverse shell pid 1234",
                }
            ],
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="list_alerts", handler=handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["alerts", "list", "--socket", str(sock_path)])
        assert result.exit_code == 0
        assert "lolbin.bash_dev_tcp" in result.stdout
    finally:
        server.stop()


def test_alerts_show_renders(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def get_handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alert": {
                "alert_id": "a1",
                "rule": {"id": "lolbin.bash_dev_tcp", "name": "Reverse shell"},
                "severity": "critical",
                "status": "new",
                "rendered": {"short": "rs", "detail": "rs detail"},
            },
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="get_alert", handler=get_handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["alerts", "show", "a1", "--socket", str(sock_path)])
        assert result.exit_code == 0
        assert "Reverse shell" in result.stdout
    finally:
        server.stop()
