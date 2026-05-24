"""Tests for the allowlist evaluator."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.allowlist.evaluator import is_suppressed
from inspectord.rules.base import Match
from inspectord.schemas.alert import EntityRef
from inspectord.schemas.allowlist import AllowlistEntry, AllowlistScope, AllowlistStats


def _entry(scope: AllowlistScope) -> AllowlistEntry:
    return AllowlistEntry(
        id="x",
        scope=scope,
        reason="test",
        created_by="eli@local",
        created_at=datetime.now(UTC),
        auto_origin=False,
        stats=AllowlistStats(),
    )


def _match(
    *,
    rule_id: str = "lolbin.bash_dev_tcp",
    entity_kind: str = "process",
    entity_key: str = "pid:1234",
) -> Match:
    return Match(
        rule_id=rule_id,
        severity="high",
        category="test",
        dedup_key=f"{rule_id}:{entity_kind}:{entity_key}",
        primary_entity_kind=entity_kind,
        primary_entity_key=entity_key,
        short="m",
        detail="d",
    )


def test_rule_id_match_suppresses() -> None:
    entries = [_entry(AllowlistScope(rule_id="lolbin.bash_dev_tcp"))]
    assert is_suppressed(_match(), entries) is True


def test_rule_id_mismatch_does_not_suppress() -> None:
    entries = [_entry(AllowlistScope(rule_id="other.rule"))]
    assert is_suppressed(_match(), entries) is False


def test_entity_match_suppresses() -> None:
    entries = [_entry(AllowlistScope(entity=EntityRef(kind="process", key="pid:1234")))]
    assert is_suppressed(_match(), entries) is True


def test_path_glob_suppresses_file_entity() -> None:
    entries = [_entry(AllowlistScope(path_glob="/home/eli/dev/**"))]
    assert (
        is_suppressed(
            _match(entity_kind="file", entity_key="/home/eli/dev/project/x"),
            entries,
        )
        is True
    )


def test_path_glob_does_not_match_outside() -> None:
    entries = [_entry(AllowlistScope(path_glob="/home/eli/dev/**"))]
    assert (
        is_suppressed(
            _match(entity_kind="file", entity_key="/etc/sudoers"),
            entries,
        )
        is False
    )


def test_empty_allowlist_does_not_suppress() -> None:
    assert is_suppressed(_match(), []) is False
