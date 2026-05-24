from __future__ import annotations

from datetime import UTC, datetime

from inspectord.schemas.allowlist import AllowlistEntry


def test_allowlist_validates_with_minimal_scope() -> None:
    entry = AllowlistEntry.model_validate(
        {
            "schema_version": "1.0.0",
            "id": "01900000-0000-7000-8000-000000000020",
            "scope": {"rule_id": "test.rule"},
            "reason": "user trusts this",
            "created_by": "eli@local",
            "created_at": datetime.now(UTC).isoformat(),
            "auto_origin": False,
            "stats": {"suppressed_count": 0, "last_suppressed_at": None},
        }
    )
    assert entry.scope.rule_id == "test.rule"
