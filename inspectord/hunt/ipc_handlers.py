"""IPC handlers for Hunt (hunt design §7, §8) — the compiler's first caller.

This module is the *edge*, and an edge has three jobs the layers behind it
deliberately do not do.

**Bounds (§7).** Query text is capped here before anything compiles it, and a
query with no `since` gets the default recent window, so the common case never
scans all history. The window that was actually applied is reported back in
every response: a default window the user cannot see is itself a silent
truncation of their results.

**Errors are data, not exceptions.** `IpcServer._dispatch` turns an escaping
exception into `repr(exc)`, which is neither readable nor safe. So every
`HuntError` is caught and rendered as `{ok: False, error, error_kind}` with the
error's own message — which names what was wrong with *the user's query* — and
a machine-readable kind for the CLI and the panel to branch on.

**Read-only.** `run_hunt_query` executes exactly one statement, the SELECT the
compiler produced. Only save and delete write, and only to `hunt_query`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from inspectord.audit.log import append_audit
from inspectord.hunt import store
from inspectord.hunt.compiler import compile_hunt_query
from inspectord.hunt.errors import (
    HuntBoundsError,
    HuntError,
    HuntExecutionError,
    HuntNameError,
    HuntPathError,
    HuntQueryExists,
    HuntQueryNotFound,
    HuntRequestError,
    HuntSyntaxError,
    HuntUnsupportedError,
)
from inspectord.hunt.execute import HuntResult, run_hunt_query
from inspectord.hunt.store import HuntQuery
from inspectord.log import get
from inspectord.storage.db import Database

log = get(__name__)

__all__ = [
    "DEFAULT_WINDOW",
    "handle_delete_hunt_query",
    "handle_get_hunt_query",
    "handle_list_hunt_queries",
    "handle_run_hunt_query",
    "handle_save_hunt_query",
]

_SCHEMA = "1.0.0"

#: §7 — every query gets a time bound, defaulted to a recent window so the
#: common case never scans all history. Widen it with an explicit `since`.
DEFAULT_WINDOW = timedelta(days=7)

#: Machine-readable error kinds. The message is for the human; this is for the
#: CLI and the panel, so neither has to match on error text.
_ERROR_KINDS: dict[type[HuntError], str] = {
    HuntSyntaxError: "syntax",
    HuntPathError: "path",
    HuntUnsupportedError: "unsupported",
    HuntBoundsError: "bounds",
    HuntExecutionError: "execution",
    HuntNameError: "name",
    HuntQueryExists: "exists",
    HuntQueryNotFound: "not_found",
    HuntRequestError: "request",
}


def _failure(exc: HuntError) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA,
        "ok": False,
        "error": str(exc),
        "error_kind": _ERROR_KINDS.get(type(exc), "hunt"),
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _required_str(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise HuntRequestError(f"{key} is required")
    return value


def _optional_str(params: dict[str, Any], key: str) -> str | None:
    value = params.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise HuntRequestError(f"{key} must be a string")
    return value


def _timestamp(params: dict[str, Any], key: str) -> datetime | None:
    """Parse an ISO-8601 bound. Relative shorthand is the CLI's job, not ours."""
    raw = _optional_str(params, key)
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise HuntBoundsError(
            f"could not read {key}={raw!r}: give an ISO-8601 timestamp, "
            "for example 2026-08-20T00:00:00+00:00"
        ) from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _limit(params: dict[str, Any]) -> int | None:
    raw = params.get("limit")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise HuntBoundsError(f"limit must be a whole number, got {raw!r}") from exc


def _query_dict(query: HuntQuery) -> dict[str, Any]:
    return {
        "name": query.name,
        "expression": query.expression,
        "description": query.description,
        "created_at": _iso(query.created_at),
        "updated_at": _iso(query.updated_at),
    }


def _payload(row_json: str) -> dict[str, Any]:
    """Decode one stored payload, tolerating a row we cannot parse.

    One unreadable row must not cost an investigator the whole result set, so a
    decode failure logs and yields an empty payload; the row's real columns
    (module, action, severity, ts) are still there.
    """
    try:
        decoded = json.loads(row_json)
    except json.JSONDecodeError:
        log.warning("hunt: skipping an event payload that is not valid JSON")
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _result_dict(
    result: HuntResult,
    *,
    expression: str,
    name: str | None,
    since: datetime | None,
    until: datetime | None,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "name": name,
        "expression": expression,
        "since": _iso(since),
        "until": _iso(until),
        "limit": result.limit,
        # `truncated` is a field rather than something the caller infers by
        # counting: a silently-cut result set reads as "there were exactly N".
        "truncated": result.truncated,
        "count": len(result.rows),
        "events": [
            {
                "event_id": row.event_id,
                "ts": _iso(row.ts),
                "kind": row.kind,
                "module": row.module,
                "action": row.action,
                "severity": row.severity,
                "payload": _payload(row.payload_json),
            }
            for row in result.rows
        ],
    }


def handle_run_hunt_query(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    """Run an ad-hoc `expression`, or the saved query called `name`."""
    try:
        expression = _optional_str(params, "expression")
        name = _optional_str(params, "name")
        if expression is not None and name is not None:
            raise HuntRequestError(
                "pass expression or name, not both: a saved query already has an expression"
            )
        limit = _limit(params)
        until = _timestamp(params, "until")
        since = _timestamp(params, "since")
        if since is None:
            since = datetime.now(tz=UTC) - DEFAULT_WINDOW

        with Database(db_path) as db:
            if name is not None:
                saved = store.get_query(db, name)
                if saved is None:
                    raise HuntQueryNotFound(f"no saved query named {name!r}")
                text = saved.expression
            elif expression is not None:
                text = expression
            else:
                raise HuntRequestError("pass an expression to run, or the name of a saved query")
            store.check_expression_length(text)
            compiled = compile_hunt_query(text, since=since, until=until, limit=limit)
            result = run_hunt_query(db, compiled)
    except HuntError as exc:
        return _failure(exc)
    return _result_dict(result, expression=text, name=name, since=since, until=until)


def handle_save_hunt_query(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    """Compile and store a query under a name (§8)."""
    try:
        name = _required_str(params, "name")
        expression = _required_str(params, "expression")
        description = _optional_str(params, "description")
        replace = bool(params.get("replace", False))
        with Database(db_path) as db:
            outcome = store.save_query(
                db,
                name=name,
                expression=expression,
                description=description,
                replace=replace,
            )
    except HuntError as exc:
        return _failure(exc)
    append_audit(
        db_path,
        actor="user:local",
        action="hunt_query_saved",
        target=f"hunt:{outcome.name}",
        details={},
    )
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "name": outcome.name,
        "expression": outcome.expression,
        # Never ambiguous about which of the two things just happened.
        "replaced": outcome.replaced,
        "previous_expression": outcome.previous_expression,
        "created_at": _iso(outcome.created_at),
        "updated_at": _iso(outcome.updated_at),
    }


def handle_list_hunt_queries(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    """Every saved query, alphabetically."""
    try:
        with Database(db_path) as db:
            queries = store.list_queries(db)
    except HuntError as exc:
        return _failure(exc)
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "queries": [_query_dict(query) for query in queries],
    }


def handle_get_hunt_query(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    """One saved query, or `query: null` if there is no such name."""
    try:
        name = _required_str(params, "name")
        with Database(db_path) as db:
            query = store.get_query(db, name)
    except HuntError as exc:
        return _failure(exc)
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "query": None if query is None else _query_dict(query),
    }


def handle_delete_hunt_query(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    """Delete a saved query, returning what was deleted so it can be retyped."""
    try:
        name = _required_str(params, "name")
        with Database(db_path) as db:
            deleted = store.delete_query(db, name)
    except HuntError as exc:
        return _failure(exc)
    append_audit(
        db_path,
        actor="user:local",
        action="hunt_query_deleted",
        target=f"hunt:{deleted.name}",
        details={},
    )
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "name": deleted.name,
        "expression": deleted.expression,
        "description": deleted.description,
    }
