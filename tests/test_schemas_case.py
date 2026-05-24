from __future__ import annotations

from datetime import UTC, datetime

from inspectord.schemas.case import Case


def test_case_validates() -> None:
    case = Case.model_validate(
        {
            "schema_version": "1.0.0",
            "case_id": "01900000-0000-7000-8000-000000000030",
            "opened_at": datetime.now(UTC).isoformat(),
            "title": "Suspicious activity",
            "alert_ids": [],
            "incident_ids": [],
            "entities": [],
            "evidence": [],
            "notes": "",
            "status": "open",
            "exported_at": None,
        }
    )
    assert case.status == "open"
