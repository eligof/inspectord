"""Parser helpers.

A parser is a callable: ``(line: str, source: str) -> Event | None``.
It MUST return ``None`` for unparseable / empty / comment lines rather than
raise — bad input is normal in log streams.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from inspectord.ids import uuid7
from inspectord.schemas.event import Event, EventKind, Outcome, Severity
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION


@dataclass
class ParsedLine:
    raw: str
    fields: dict[str, Any] = field(default_factory=dict)


class Parser(Protocol):
    """A parser turns one raw line into one Event (or None to drop the line)."""

    def __call__(self, line: str, source: str) -> Event | None: ...


def build_event(
    *,
    module: str,
    action: str,
    category: list[str],
    type_: list[str],
    severity: str,
    kind: str = "event",
    outcome: str | None = None,
    message: str | None = None,
    process: dict[str, Any] | None = None,
    file: dict[str, Any] | None = None,
    user: dict[str, Any] | None = None,
    source: dict[str, Any] | None = None,
    destination: dict[str, Any] | None = None,
    network: dict[str, Any] | None = None,
    service: dict[str, Any] | None = None,
    package: dict[str, Any] | None = None,
    device: dict[str, Any] | None = None,
    raw: dict[str, Any] | None = None,
    labels: list[str] | None = None,
    ts: datetime | None = None,
) -> Event:
    """Construct a normalized Event with sensible defaults."""
    return Event(
        schema_version=EVENT_SCHEMA_VERSION,
        ts=ts if ts is not None else datetime.now(UTC),
        event_id=str(uuid7()),
        kind=EventKind(kind),
        category=category,
        type=type_,
        action=action,
        outcome=Outcome(outcome) if outcome is not None else None,
        severity=Severity(severity),
        module=module,
        message=message,
        process=process,
        file=file,
        user=user,
        source=source,
        destination=destination,
        network=network,
        service=service,
        package=package,
        device=device,
        raw=raw,
        labels=labels or [],
    )
