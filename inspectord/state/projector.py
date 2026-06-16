"""Materialize current entity state from the event stream.

`project(event, db)` is invoked from the supervisor's single-threaded persist
path, so transitions apply in order with no locking. Unknown (module, action)
pairs are a no-op — adding collectors never breaks projection.
"""

from __future__ import annotations

from inspectord.schemas.event import Event
from inspectord.storage.db import Database


def project(event: Event, db: Database) -> None:
    if event.module == "services_monitor":
        _project_service(event, db)


def _project_service(event: Event, db: Database) -> None:
    unit = (event.service or {}).get("name")
    if not unit:
        return
    if event.action == "service_removed":
        # Removal short-circuits before the raw read: services_monitor's
        # service_removed events carry only previous_* keys in raw, no live state.
        db.execute("DELETE FROM service_state WHERE unit = ?", [unit])
        return
    raw = event.raw or {}
    db.execute(
        """
        INSERT INTO service_state
            (unit, active_state, sub_state, load_state, first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (unit) DO UPDATE SET
            active_state  = excluded.active_state,
            sub_state     = excluded.sub_state,
            load_state    = excluded.load_state,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id
        """,
        [
            unit,
            raw.get("active"),
            raw.get("sub"),
            raw.get("load"),
            event.ts,
            event.ts,
            event.event_id,
        ],
    )
