"""The one INSERT into `events_enriched`.

Kept as a function rather than inlined in the supervisor so that anything which
needs a *real* row — tests, in particular the hunt differential test — writes
it through the same call the daemon uses, instead of a hand-copied statement
that can quietly drift from the real column order.
"""

from __future__ import annotations

from inspectord.schemas.event import Event
from inspectord.storage.db import Database

_INSERT = (
    "INSERT INTO events_enriched "
    "(event_id, ts, kind, module, action, severity, payload_json) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)


def insert_event(db: Database, event: Event, payload_json: str) -> None:
    """Persist one enriched event.

    `payload_json` is passed in rather than recomputed: the caller has already
    serialized the event for the journal, and the two must be the same bytes.
    """
    db.execute(
        _INSERT,
        [
            event.event_id,
            event.ts,
            event.kind.value,
            event.module,
            event.action,
            event.severity.value,
            payload_json,
        ],
    )
