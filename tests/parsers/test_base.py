"""Tests for the parser framework."""

from __future__ import annotations

import time

from inspectord.parsers.base import ParsedLine, build_event


def test_parsedline_carries_raw_and_fields() -> None:
    pl = ParsedLine(raw="hello", fields={"k": "v"})
    assert pl.raw == "hello"
    assert pl.fields == {"k": "v"}


def test_build_event_minimum_fields() -> None:
    ev = build_event(
        module="log_tailer",
        action="package_installed",
        category=["package"],
        type_=["installation"],
        severity="info",
        message="installed audit",
        raw={"source_file": "/var/log/pacman.log", "line": "..."},
    )
    assert ev.module == "log_tailer"
    assert ev.action == "package_installed"
    assert ev.severity.value == "info"
    assert ev.message == "installed audit"
    assert ev.raw == {"source_file": "/var/log/pacman.log", "line": "..."}


def test_build_event_carries_persistence_block() -> None:
    ev = build_event(
        module="persistence_snapshotter",
        action="persistence_added",
        category=["host"],
        type_=["start"],
        severity="low",
        persistence={
            "kind": "cron",
            "name": "backup",
            "source_path": "/etc/crontab",
            "details": "@daily root backup",
            "key": "persist:cron:/etc/crontab:abc123",
        },
    )
    assert ev.persistence is not None
    assert ev.persistence["key"] == "persist:cron:/etc/crontab:abc123"


def test_build_event_carries_first_seen() -> None:
    ev = build_event(
        module="m",
        action="a",
        category=["host"],
        type_=["start"],
        severity="low",
        first_seen=True,
    )
    assert ev.first_seen is True
    ev2 = build_event(module="m", action="a", category=["host"], type_=["start"], severity="low")
    assert ev2.first_seen is False


def test_build_event_includes_uuidv7_event_id() -> None:
    ev2 = build_event(
        module="log_tailer", action="x", category=["host"], type_=["info"], severity="info"
    )
    time.sleep(0.005)
    ev3 = build_event(
        module="log_tailer", action="x", category=["host"], type_=["info"], severity="info"
    )
    assert ev2.event_id < ev3.event_id
