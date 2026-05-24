"""Tests for the Alert schema."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from inspectord.schemas.alert import Alert, AlertStatus, RuleRef


def _minimal_alert_dict() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "alert_id": "01900000-0000-7000-8000-000000000000",
        "rule": {
            "id": "test.rule",
            "name": "Test rule",
            "ruleset": "starter-pack",
            "version": "1.0.0",
            "severity": "medium",
            "why": "Detects test events",
            "false_positives": [],
        },
        "ts": datetime.now(UTC).isoformat(),
        "severity": "medium",
        "status": "new",
        "category": "test",
        "event_ids": ["01900000-0000-7000-8000-000000000001"],
        "entities": [{"kind": "process", "key": "pid:1234@boot:X"}],
        "dedup_key": "test.rule:pid:1234",
        "dedup_count": 1,
        "first_seen_at": datetime.now(UTC).isoformat(),
        "last_seen_at": datetime.now(UTC).isoformat(),
        "rendered": {"short": "test alert", "detail": "test details"},
    }


def test_minimal_alert_validates() -> None:
    a = Alert.model_validate(_minimal_alert_dict())
    assert a.status == AlertStatus.new
    assert isinstance(a.rule, RuleRef)


def test_status_must_be_known() -> None:
    bad = _minimal_alert_dict() | {"status": "elaborated"}
    with pytest.raises(ValidationError):
        Alert.model_validate(bad)


def test_dedup_count_minimum_is_one() -> None:
    bad = _minimal_alert_dict() | {"dedup_count": 0}
    with pytest.raises(ValidationError):
        Alert.model_validate(bad)
