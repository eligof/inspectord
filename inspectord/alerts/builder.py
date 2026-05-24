"""Convert a rule Match + triggering Event into a full Alert."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.ids import uuid7
from inspectord.rules.base import Match
from inspectord.schemas.alert import (
    Alert,
    AlertStatus,
    EntityRef,
    RenderedAlert,
    RuleRef,
)
from inspectord.schemas.event import Event, Severity


def build_alert(*, match: Match, event: Event) -> Alert:
    now = event.ts if event.ts is not None else datetime.now(UTC)
    rule_ref = RuleRef(
        id=match.rule_id,
        name=match.rule_name or match.rule_id,
        ruleset="starter-pack",
        version="1.0.0",
        severity=Severity(match.severity),
        why=match.why or "",
        false_positives=list(match.false_positives),
    )
    return Alert(
        alert_id=str(uuid7()),
        rule=rule_ref,
        ts=now,
        severity=Severity(match.severity),
        status=AlertStatus.new,
        category=match.category,
        event_ids=list(match.triggering_event_ids) or [event.event_id],
        entities=[EntityRef(kind=match.primary_entity_kind, key=match.primary_entity_key)],
        dedup_key=match.dedup_key,
        dedup_count=1,
        first_seen_at=now,
        last_seen_at=now,
        rendered=RenderedAlert(short=match.short, detail=match.detail),
        labels=list(match.labels),
    )
