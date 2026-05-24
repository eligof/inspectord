"""Rule framework primitives (spec §8).

A Rule is anything matching the ``Rule`` Protocol below. Rules consume an
``EvalContext`` (the current event plus a sliding-window history) and return
zero-or-more ``Match`` objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol

from inspectord.schemas.event import Event


@dataclass
class Match:
    """A rule fired. The dedup engine and alert builder consume these."""

    rule_id: str
    severity: str
    category: str
    dedup_key: str
    primary_entity_kind: str
    primary_entity_key: str
    short: str
    detail: str
    rule_name: str = ""
    why: str = ""
    false_positives: list[str] = field(default_factory=list)
    triggering_event_ids: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)


@dataclass
class EvalContext:
    event: Event
    history: list[Event] = field(default_factory=list)

    def recent_events(self, *, window_s: float) -> list[Event]:
        cutoff = self.event.ts - timedelta(seconds=window_s)
        return [e for e in self.history if e.ts >= cutoff]


class Rule(Protocol):
    rule_id: str
    severity: str
    category: str

    def evaluate(self, ctx: EvalContext) -> list[Match]: ...
