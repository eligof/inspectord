"""Tests for the alert builder."""

from __future__ import annotations

from inspectord.alerts.builder import build_alert
from inspectord.parsers.base import build_event
from inspectord.rules.base import Match


def test_build_alert_from_match() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1234, "name": "bash"},
    )
    m = Match(
        rule_id="lolbin.bash_dev_tcp",
        rule_name="Reverse-shell pattern",
        severity="critical",
        category="intrusion_detection",
        dedup_key="lolbin.bash_dev_tcp:pid:1234",
        primary_entity_kind="process",
        primary_entity_key="pid:1234",
        short="short",
        detail="detail",
        why="why text",
        false_positives=["fp1"],
        triggering_event_ids=[ev.event_id],
    )
    a = build_alert(match=m, event=ev)
    assert a.rule.id == "lolbin.bash_dev_tcp"
    assert a.rule.severity.value == "critical"
    assert a.severity.value == "critical"
    assert a.category == "intrusion_detection"
    assert a.dedup_key == "lolbin.bash_dev_tcp:pid:1234"
    assert a.dedup_count == 1
    assert a.entities[0].kind == "process"
    assert a.entities[0].key == "pid:1234"
    assert a.rendered.short == "short"
    assert a.rendered.detail == "detail"
    assert a.event_ids == [ev.event_id]
    assert a.status.value == "new"
