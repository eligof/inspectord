"""Tests for the pacman.log parser."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.parsers.pacman import parse_pacman_line

FIXTURE = Path(__file__).parent / "fixtures" / "pacman.log"


def _lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def test_installed_line() -> None:
    ev = parse_pacman_line(_lines()[0], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_installed"
    assert ev.category == ["package"]
    assert ev.type == ["installation"]
    assert ev.severity.value == "info"
    assert ev.package == {
        "name": "audit",
        "version": "3.1.5-1",
        "action": "installed",
    }
    assert ev.ts == datetime(2026, 5, 24, 14, 23, 10, tzinfo=UTC)
    assert ev.raw is not None
    assert ev.raw["source_file"] == "/var/log/pacman.log"


def test_removed_line() -> None:
    ev = parse_pacman_line(_lines()[1], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_removed"
    assert ev.type == ["deletion"]
    assert ev.package == {
        "name": "yara",
        "version": "4.5.0-1",
        "action": "removed",
    }


def test_upgraded_line_captures_both_versions() -> None:
    ev = parse_pacman_line(_lines()[2], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_upgraded"
    assert ev.type == ["change"]
    assert ev.package == {
        "name": "suricata",
        "version": "7.0.0-1",
        "previous_version": "6.0.0-1",
        "action": "upgraded",
    }


def test_reinstalled_line() -> None:
    ev = parse_pacman_line(_lines()[3], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_reinstalled"
    assert ev.package == {
        "name": "libudev",
        "version": "250-1",
        "action": "reinstalled",
    }


def test_non_alpm_line_returns_none() -> None:
    assert parse_pacman_line(_lines()[4], source="/var/log/pacman.log") is None


def test_unparseable_line_returns_none() -> None:
    assert parse_pacman_line("not a pacman line", source="/var/log/pacman.log") is None
    assert parse_pacman_line("", source="/var/log/pacman.log") is None
