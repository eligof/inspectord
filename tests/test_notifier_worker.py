"""Tests for the in-process NotifierWorker."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

from inspectord.schemas.alert import (
    Alert,
    AlertStatus,
    EntityRef,
    RenderedAlert,
    RuleRef,
)
from inspectord.schemas.event import Severity
from inspectord.workers.notifier.__main__ import NotifierWorker


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False):
        self.calls.append(tuple(argv))
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"", stderr=b"")


def _alert(severity: str = "critical") -> Alert:
    now = datetime.now(UTC)
    return Alert(
        alert_id="01900000-0000-7000-8000-000000000000",
        rule=RuleRef(
            id="lolbin.bash_dev_tcp",
            name="Reverse-shell pattern",
            ruleset="starter-pack",
            version="1.0.0",
            severity=Severity(severity),
            why="",
        ),
        ts=now,
        severity=Severity(severity),
        status=AlertStatus.new,
        category="intrusion_detection",
        event_ids=["e1"],
        entities=[EntityRef(kind="process", key="pid:1234")],
        dedup_key="lolbin.bash_dev_tcp:pid:1234",
        dedup_count=1,
        first_seen_at=now,
        last_seen_at=now,
        rendered=RenderedAlert(short="rs short", detail="rs detail"),
    )


def test_critical_alert_dispatches() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("critical"))
    assert runner.calls
    assert "rs short" in runner.calls[0]


def test_low_severity_skipped_by_default_routing() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("low"))
    assert runner.calls == []


def test_info_severity_skipped() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("info"))
    assert runner.calls == []


def test_high_severity_dispatches() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("high"))
    assert runner.calls


def test_medium_severity_dispatches() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("medium"))
    assert runner.calls
