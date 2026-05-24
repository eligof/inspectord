"""Tests for the journald JSON parser."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from inspectord.parsers.journald import parse_journald_entry

FIXTURE = Path(__file__).parent / "fixtures" / "journald.jsonl"


def _entries() -> list[dict[str, object]]:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def test_priority_6_maps_to_info() -> None:
    ev = parse_journald_entry(_entries()[0], source="journald")
    assert ev is not None
    assert ev.severity.value == "info"
    assert ev.module == "log_tailer"
    assert ev.action == "journal_message"
    assert ev.service == {"name": "sshd", "unit": "sshd.service"}
    assert ev.process is not None
    assert ev.process["name"] == "sshd"
    assert ev.process["pid"] == 1234
    assert ev.process["executable"] == "/usr/sbin/sshd"
    assert ev.user == {"id": 0}
    assert ev.host == {"hostname": "laptop", "os": {"family": "linux"}}
    assert "Accepted publickey" in (ev.message or "")
    assert ev.ts == datetime.fromtimestamp(1716576190.123456, UTC)


def test_priority_3_maps_to_high() -> None:
    ev = parse_journald_entry(_entries()[1], source="journald")
    assert ev is not None
    assert ev.severity.value == "high"


def test_priority_5_maps_to_low() -> None:
    ev = parse_journald_entry(_entries()[2], source="journald")
    assert ev is not None
    assert ev.severity.value == "low"


def test_unparseable_dict_returns_none() -> None:
    assert parse_journald_entry({"_PID": "1"}, source="journald") is None
    assert parse_journald_entry({}, source="journald") is None
