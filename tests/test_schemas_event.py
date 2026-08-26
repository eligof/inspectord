"""Tests for the Event schema."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from inspectord.schemas.event import Event, EventKind, Severity


def _minimal_event_dict() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "ts": datetime.now(UTC).isoformat(),
        "event_id": "0190d3e1-0000-7000-8000-000000000000",
        "kind": "event",
        "category": ["host"],
        "type": ["start"],
        "action": "synthetic_heartbeat",
        "severity": "info",
        "module": "healthcheck",
    }


def test_minimal_event_validates() -> None:
    ev = Event.model_validate(_minimal_event_dict())
    assert ev.kind == EventKind.event
    assert ev.severity == Severity.info


def test_severity_must_be_known() -> None:
    bad = _minimal_event_dict() | {"severity": "catastrophic"}
    with pytest.raises(ValidationError):
        Event.model_validate(bad)


def test_kind_must_be_known() -> None:
    bad = _minimal_event_dict() | {"kind": "epiphany"}
    with pytest.raises(ValidationError):
        Event.model_validate(bad)


def test_extra_fields_in_raw_are_allowed() -> None:
    payload = _minimal_event_dict() | {"raw": {"source_file": "/x", "line": "abc"}}
    ev = Event.model_validate(payload)
    assert ev.raw == {"source_file": "/x", "line": "abc"}


def test_roundtrip_json() -> None:
    original = Event.model_validate(_minimal_event_dict())
    payload = original.model_dump_json()
    parsed = Event.model_validate_json(payload)
    assert parsed == original


def test_vulnerability_namespace_roundtrips() -> None:
    payload = _minimal_event_dict() | {
        "vulnerability": {"avg_id": "AVG-1", "cve_id": "CVE-2026-1", "package": "p"}
    }
    ev = Event.model_validate(payload)
    assert ev.vulnerability == {"avg_id": "AVG-1", "cve_id": "CVE-2026-1", "package": "p"}
    parsed = Event.model_validate_json(ev.model_dump_json())
    assert parsed == ev


def test_unknown_namespace_still_rejected() -> None:
    # extra="forbid" is the reason the vulnerability field is a schema change,
    # not an optional convenience — pin that it still rejects unknown blocks.
    bad = _minimal_event_dict() | {"vulnerabilty": {"avg_id": "AVG-1"}}
    with pytest.raises(ValidationError):
        Event.model_validate(bad)
