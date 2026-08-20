"""Saved hunt queries (hunt design §8) — the `hunt_query` table.

Two rules make this more than a key/value table.

**Saving compiles.** `save_query` runs the expression through
`compile_hunt_query` before it writes. Saving deliberately does *not* check the
query against events — a hunt that matches nothing today is exactly the hunt
worth keeping — but a query that cannot compile is refused now rather than at
2am when someone needs the answer.

**A name is never silently overwritten.** `save_query` refuses a name that
already exists and quotes the existing expression back, unless the caller
passes `replace=True`. A saved query replacing another without a word is the
kind of thing that costs an investigation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from inspectord.hunt.compiler import compile_hunt_query
from inspectord.hunt.errors import (
    HuntBoundsError,
    HuntNameError,
    HuntQueryExists,
    HuntQueryNotFound,
)
from inspectord.storage.db import Database

__all__ = [
    "MAX_DESCRIPTION_CHARS",
    "MAX_EXPRESSION_CHARS",
    "MAX_NAME_CHARS",
    "NAME_PATTERN",
    "HuntQuery",
    "SaveOutcome",
    "check_expression_length",
    "delete_query",
    "get_query",
    "list_queries",
    "save_query",
    "validate_name",
]

MAX_NAME_CHARS = 64
MAX_EXPRESSION_CHARS = 4096
MAX_DESCRIPTION_CHARS = 512

#: Deliberately narrow. The name is echoed into a terminal today and into HTML
#: in PR3, so the pattern excludes whitespace, quotes, `<`, `&`, control
#: characters, ANSI escape introducers and every non-ASCII codepoint — no
#: right-to-left override, no homoglyph. It must also start with an
#: alphanumeric so a name can never be mistaken for a command-line option.
NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_NAME_RE = re.compile(f"^{NAME_PATTERN}$")

_COLUMNS = "name, expression, description, created_at, updated_at"


@dataclass(frozen=True)
class HuntQuery:
    """One saved query, as stored."""

    name: str
    expression: str
    description: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class SaveOutcome:
    """What a save actually did — never ambiguous about replacement."""

    name: str
    expression: str
    created_at: datetime
    updated_at: datetime
    replaced: bool
    previous_expression: str | None


def validate_name(name: str) -> str:
    """Return `name` if it is a usable saved-query name, else raise."""
    if not name:
        raise HuntNameError(
            f"a saved query needs a name: 1 to {MAX_NAME_CHARS} characters matching {NAME_PATTERN}"
        )
    if len(name) > MAX_NAME_CHARS:
        raise HuntNameError(
            f"saved query name is {len(name)} characters; the limit is {MAX_NAME_CHARS}"
        )
    if not _NAME_RE.match(name):
        raise HuntNameError(
            f"invalid saved query name {name!r}: start with a letter or digit, then use "
            "letters, digits, '.', '_' or '-' only"
        )
    return name


def check_expression_length(expression: str) -> str:
    """Bound the query text before anything tries to compile it (§7).

    Enforced here rather than only at the IPC edge so the store can never hold
    a query the edge would refuse to run.
    """
    if len(expression) > MAX_EXPRESSION_CHARS:
        raise HuntBoundsError(
            f"query is {len(expression)} characters; the limit is {MAX_EXPRESSION_CHARS}"
        )
    return expression


def _check_description(description: str | None) -> str | None:
    if description is not None and len(description) > MAX_DESCRIPTION_CHARS:
        # Rejected, not truncated: a half-stored description is a lie about
        # what the query is for.
        raise HuntBoundsError(
            f"description is {len(description)} characters; the limit is {MAX_DESCRIPTION_CHARS}"
        )
    return description


def _utc(value: Any) -> datetime:
    """DuckDB hands back naive TIMESTAMPs; the session timezone is UTC."""
    stamp: datetime = value
    return stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp


def _row_to_query(row: tuple[Any, ...]) -> HuntQuery:
    return HuntQuery(
        name=str(row[0]),
        expression=str(row[1]),
        description=None if row[2] is None else str(row[2]),
        created_at=_utc(row[3]),
        updated_at=_utc(row[4]),
    )


def get_query(db: Database, name: str) -> HuntQuery | None:
    """Return the saved query called `name`, or `None`."""
    validate_name(name)
    rows = db.query(f"SELECT {_COLUMNS} FROM hunt_query WHERE name = ?", [name]).fetchall()
    return _row_to_query(rows[0]) if rows else None


def list_queries(db: Database) -> list[HuntQuery]:
    """Every saved query, alphabetically by name."""
    rows = db.query(f"SELECT {_COLUMNS} FROM hunt_query ORDER BY name").fetchall()
    return [_row_to_query(row) for row in rows]


def save_query(
    db: Database,
    *,
    name: str,
    expression: str,
    description: str | None = None,
    replace: bool = False,
) -> SaveOutcome:
    """Compile `expression`, then store it under `name`.

    Raises `HuntQueryExists` if `name` is taken and `replace` is not set; the
    message carries the existing expression so the caller can see what it
    nearly destroyed. Every validation happens before the first write, so a
    rejected save leaves any existing query untouched.
    """
    validate_name(name)
    check_expression_length(expression)
    _check_description(description)
    # §8: compile, but do not run. Raises HuntError on a query that cannot
    # compile — the whole point of validating at save time.
    compile_hunt_query(expression)

    existing = get_query(db, name)
    if existing is not None and not replace:
        raise HuntQueryExists(
            f"a saved query named {name!r} already exists (its expression is: "
            f"{existing.expression}). Pass replace to overwrite it, or choose "
            "another name."
        )

    now = datetime.now(tz=UTC)
    if existing is None:
        db.execute(
            f"INSERT INTO hunt_query ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
            [name, expression, description, now, now],
        )
        return SaveOutcome(
            name=name,
            expression=expression,
            created_at=now,
            updated_at=now,
            replaced=False,
            previous_expression=None,
        )

    db.execute(
        "UPDATE hunt_query SET expression = ?, description = ?, updated_at = ? WHERE name = ?",
        [expression, description, now, name],
    )
    return SaveOutcome(
        name=name,
        expression=expression,
        created_at=existing.created_at,
        updated_at=now,
        replaced=True,
        previous_expression=existing.expression,
    )


def delete_query(db: Database, name: str) -> HuntQuery:
    """Delete the saved query called `name` and return what was deleted.

    Returning the row is not decoration: it is what lets the caller print the
    expression it just removed, so a mistaken delete can be undone by typing
    the query back.
    """
    existing = get_query(db, name)
    if existing is None:
        raise HuntQueryNotFound(f"no saved query named {name!r}")
    db.execute("DELETE FROM hunt_query WHERE name = ?", [name])
    return existing
