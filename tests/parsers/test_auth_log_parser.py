"""Tests for the /var/log/auth.log parser."""

from __future__ import annotations

from pathlib import Path

from inspectord.parsers.auth_log import parse_auth_log_line

FIXTURE = Path(__file__).parent / "fixtures" / "auth.log"


def _lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def test_ssh_accepted() -> None:
    ev = parse_auth_log_line(_lines()[0], source="/var/log/auth.log")
    assert ev is not None
    assert ev.action == "ssh_login_succeeded"
    assert ev.category == ["authentication"]
    assert ev.type == ["start"]
    assert ev.outcome is not None and ev.outcome.value == "success"
    assert ev.user == {"name": "eli"}
    assert ev.source == {"ip": "1.2.3.4", "port": 51234}
    assert ev.process is not None
    assert ev.process["name"] == "sshd"
    assert ev.process["pid"] == 1234


def test_ssh_failed() -> None:
    ev = parse_auth_log_line(_lines()[1], source="/var/log/auth.log")
    assert ev is not None
    assert ev.action == "ssh_login_failed"
    assert ev.outcome is not None and ev.outcome.value == "failure"
    assert ev.severity.value == "medium"
    assert ev.source == {"ip": "1.2.3.5", "port": 51234}


def test_sudo_invocation() -> None:
    ev = parse_auth_log_line(_lines()[2], source="/var/log/auth.log")
    assert ev is not None
    assert ev.action == "sudo_invoked"
    assert ev.category == ["iam"]
    assert ev.user == {"name": "eli", "effective": {"name": "root"}}
    assert ev.process is not None
    assert ev.process["command_line"].endswith("/usr/bin/pacman -S audit")


def test_cron_session_ignored() -> None:
    assert parse_auth_log_line(_lines()[3], source="/var/log/auth.log") is None


def test_unrelated_line_returns_none() -> None:
    assert parse_auth_log_line("garbage", source="/var/log/auth.log") is None
    assert parse_auth_log_line("", source="/var/log/auth.log") is None
