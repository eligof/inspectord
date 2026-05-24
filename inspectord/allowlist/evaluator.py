"""Allowlist scope evaluator.

A Match is suppressed if ANY entry in the list matches it. Evaluation order
per spec §7.4: rule_id → entity → path_glob. Within an entry, the scope is
an AND of its non-None fields.
"""

from __future__ import annotations

import fnmatch

from inspectord.rules.base import Match
from inspectord.schemas.allowlist import AllowlistEntry


def is_suppressed(match: Match, entries: list[AllowlistEntry]) -> bool:
    return any(_entry_matches(match, entry) for entry in entries)


def _entry_matches(match: Match, entry: AllowlistEntry) -> bool:
    scope = entry.scope
    if scope.rule_id is not None and scope.rule_id != match.rule_id:
        return False
    if scope.entity is not None:
        if scope.entity.kind != match.primary_entity_kind:
            return False
        if scope.entity.key != match.primary_entity_key:
            return False
    if scope.path_glob is not None:
        if match.primary_entity_kind != "file":
            return False
        if not fnmatch.fnmatch(match.primary_entity_key, _glob_to_fnmatch(scope.path_glob)):
            return False
    return any(
        [
            scope.rule_id is not None,
            scope.entity is not None,
            scope.path_glob is not None,
            scope.user_id is not None,
        ]
    )


def _glob_to_fnmatch(glob: str) -> str:
    """Translate `**` (multi-segment) into fnmatch's `*` (works on full strings)."""
    return glob.replace("**", "*")
