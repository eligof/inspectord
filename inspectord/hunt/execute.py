"""Running a `CompiledQuery` and reporting truncation (hunt design §7).

Read-only by construction: the only statement this module runs is the SELECT
the compiler produced.

A query that compiles can still fail at run time — DuckDB's RE2 rejects
repetitions Python's `re` accepts, and storage itself can fail. Those arrive as
`duckdb.Error`, whose message can quote the failing SQL, and the IPC server
sends `repr(exc)` straight to the client. So every DuckDB failure is converted
into a `HuntExecutionError` that carries the *user's* expression and nothing
else; the DuckDB detail goes to the daemon log.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import duckdb

from inspectord.hunt.compiler import CompiledQuery
from inspectord.hunt.errors import HuntExecutionError
from inspectord.log import get
from inspectord.storage.db import Database

log = get(__name__)

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
    try:
        fetched = db.query(query.sql, list(query.params)).fetchall()
    except duckdb.Error as exc:
        # Logged, not re-raised: `exc` can contain the generated SQL.
        log.warning("hunt query failed in the database: %s", exc)
        raise HuntExecutionError(
            f"the database could not run this query: {query.expression}. "
            "It compiled, so this is a limit of the query engine rather than a "
            "syntax problem — check any regular expression in it. The daemon log "
            "has the database's own message."
        ) from exc
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
