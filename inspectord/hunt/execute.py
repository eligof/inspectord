"""Running a `CompiledQuery` and reporting truncation (hunt design §7).

Read-only by construction: the only statement this module runs is the SELECT
the compiler produced.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from inspectord.hunt.compiler import CompiledQuery
from inspectord.storage.db import Database

__all__ = ["HuntResult", "HuntRow", "run_hunt_query"]


@dataclass(frozen=True)
class HuntRow:
    """One `events_enriched` row. `payload_json` is the event as persisted."""

    event_id: str
    ts: datetime
    kind: str
    module: str
    action: str
    severity: str
    payload_json: str


@dataclass(frozen=True)
class HuntResult:
    """Rows plus whether the daemon had more to give.

    A silently-cut result set during an investigation is actively misleading,
    so truncation is a field, not something the caller has to infer by counting.
    """

    rows: tuple[HuntRow, ...]
    truncated: bool
    limit: int

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(row.event_id for row in self.rows)


def run_hunt_query(db: Database, query: CompiledQuery) -> HuntResult:
    """Execute `query` and return at most `query.limit` rows, newest first."""
    # The compiled SQL asks for limit + 1 rows; the extra one only ever exists
    # to prove there was more, and is dropped here.
    fetched = db.query(query.sql, list(query.params)).fetchall()
    rows = tuple(
        HuntRow(
            event_id=str(row[0]),
            ts=row[1],
            kind=str(row[2]),
            module=str(row[3]),
            action=str(row[4]),
            severity=str(row[5]),
            payload_json=str(row[6]),
        )
        for row in fetched[: query.limit]
    )
    return HuntResult(rows=rows, truncated=len(fetched) > query.limit, limit=query.limit)
