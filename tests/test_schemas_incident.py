from __future__ import annotations

from datetime import UTC, datetime

from inspectord.schemas.incident import Incident


def test_incident_validates() -> None:
    inc = Incident.model_validate(
        {
            "schema_version": "1.0.0",
            "incident_id": "01900000-0000-7000-8000-000000000010",
            "opened_at": datetime.now(UTC).isoformat(),
            "closed_at": None,
            "status": "open",
            "primary_entity": {"kind": "process", "key": "pid:1234@boot:X"},
            "entity_set": [],
            "alert_ids": [],
            "severity_max": "high",
            "narrative": "5 alerts in 10 minutes",
            "case_id": None,
        }
    )
    assert inc.status == "open"
