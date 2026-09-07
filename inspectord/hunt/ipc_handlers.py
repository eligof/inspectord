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

import hashlib
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
    HuntScheduledError,
    HuntSyntaxError,
    HuntUnsupportedError,
)
from inspectord.hunt.execute import HuntResult, run_hunt_query
from inspectord.hunt.store import HuntQuery
from inspectord.log import get
from inspectord.ratelimit import SlidingWindowLimiter
from inspectord.storage.db import Database

log = get(__name__)

__all__ = [
    "DEFAULT_WINDOW",
    "MUTATION_RATE_LIMIT_PER_MIN",
    "handle_delete_hunt_query",
    "handle_get_hunt_query",
    "handle_list_hunt_queries",
    "handle_run_hunt_query",
    "handle_save_hunt_query",
    "handle_schedule_hunt_query",
    "handle_unschedule_hunt_query",
]

_SCHEMA = "1.0.0"

#: One shared sliding window across ALL mutating hunt methods (§4.6): each of
#: them writes an audit row, and attacker-drivable append-only audit growth is
#: exactly what the command channel's limiter exists to bound.
MUTATION_RATE_LIMIT_PER_MIN = 12

#: Audit rows echo caller-typed names; bound what rides into the log.
_NAME_AUDIT_MAX_CHARS = 64

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
    HuntScheduledError: "scheduled",
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
        "schedule_interval_s": query.schedule_interval_s,
        "schedule_severity": query.schedule_severity,
        "watermark_seq": query.watermark_seq,
        "last_run_at": _iso(query.last_run_at),
        "last_status": query.last_status,
    }


def _sha256(expression: str) -> str:
    return hashlib.sha256(expression.encode()).hexdigest()


def _rate_limited(
    limiter: SlidingWindowLimiter | None, *, db_path: Path, params: dict[str, Any]
) -> dict[str, Any] | None:
    """The shared-limiter gate every mutating hunt method passes through first.

    Returns the rejection response, or None when the call may proceed. Only
    the FIRST rejection of a saturated window is audited (the limiter's own
    contract) — one row per window, however hard a client hammers.
    """
    if limiter is None:
        return None
    allowed, audit_rejection = limiter.check()
    if allowed:
        return None
    if audit_rejection:
        append_audit(
            db_path,
            actor="user:local",
            action="hunt_mutation_rate_limited",
            target=f"hunt:{str(params.get('name', ''))[:_NAME_AUDIT_MAX_CHARS]}",
            details={"reason": "rate_limited"},
        )
    return {
        "schema_version": _SCHEMA,
        "ok": False,
        "error": f"hunt mutation rate limit exceeded ({MUTATION_RATE_LIMIT_PER_MIN}/min)",
        "error_kind": "rate_limited",
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


def _data_horizon(db: Database) -> datetime | None:
    """MIN(ts) over the store — the oldest surviving event, None when empty.

    Advisory (spec §2): a log-derived event carries its log line's timestamp,
    so one backdated line can overstate coverage. It is also a second
    statement, not one transaction with the query SELECT — a retention prune
    committing between the two skews the value by at most one prune cycle.
    """
    row = db.query("SELECT MIN(ts) FROM events_enriched").fetchone()
    return row[0] if row is not None else None


def _result_dict(
    result: HuntResult,
    *,
    expression: str,
    name: str | None,
    since: datetime | None,
    until: datetime | None,
    data_horizon: datetime | None,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "name": name,
        "expression": expression,
        "since": _iso(since),
        "until": _iso(until),
        "data_horizon": _iso(data_horizon),
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
            horizon = _data_horizon(db)
    except HuntError as exc:
        return _failure(exc)
    return _result_dict(
        result, expression=text, name=name, since=since, until=until, data_horizon=horizon
    )


def handle_save_hunt_query(
    *,
    params: dict[str, Any],
    db_path: Path,
    limiter: SlidingWindowLimiter | None = None,
) -> dict[str, Any]:
    """Compile and store a query under a name (§8).

    The expression IS the detection (§4.6): a replace whose target is
    currently scheduled rewrites what a standing detection matches, so it
    requires an explicit `scheduled_ok: true` — and the schedule columns
    (watermark included) survive the replace.
    """
    rejection = _rate_limited(limiter, db_path=db_path, params=params)
    if rejection is not None:
        return rejection
    try:
        name = _required_str(params, "name")
        expression = _required_str(params, "expression")
        description = _optional_str(params, "description")
        replace = bool(params.get("replace", False))
        with Database(db_path) as db:
            existing = store.get_query(db, name)
            was_scheduled = existing is not None and existing.schedule_interval_s is not None
            if was_scheduled and replace and params.get("scheduled_ok") is not True:
                raise HuntScheduledError(
                    f"{name!r} is a scheduled standing detection; replacing it rewrites "
                    "what that detection matches. Pass scheduled_ok to confirm."
                )
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
        # The trail must distinguish "edited an idle saved query" from
        # "gutted a standing detection" (§4.6).
        details={
            "replaced": outcome.replaced,
            "was_scheduled": was_scheduled,
            "old_expression_sha256": (
                None
                if outcome.previous_expression is None
                else _sha256(outcome.previous_expression)
            ),
            "new_expression_sha256": _sha256(outcome.expression),
        },
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


def handle_delete_hunt_query(
    *,
    params: dict[str, Any],
    db_path: Path,
    limiter: SlidingWindowLimiter | None = None,
) -> dict[str, Any]:
    """Delete a saved query, returning what was deleted so it can be retyped.

    Deleting a scheduled query destroys a standing detection (§4.6), so it
    requires an explicit `scheduled_ok: true`.
    """
    rejection = _rate_limited(limiter, db_path=db_path, params=params)
    if rejection is not None:
        return rejection
    try:
        name = _required_str(params, "name")
        with Database(db_path) as db:
            existing = store.get_query(db, name)
            was_scheduled = existing is not None and existing.schedule_interval_s is not None
            if was_scheduled and params.get("scheduled_ok") is not True:
                raise HuntScheduledError(
                    f"{name!r} is a scheduled standing detection; deleting it destroys "
                    "that detection AND its watermark. Pass scheduled_ok to confirm."
                )
            deleted = store.delete_query(db, name)
    except HuntError as exc:
        return _failure(exc)
    append_audit(
        db_path,
        actor="user:local",
        action="hunt_query_deleted",
        target=f"hunt:{deleted.name}",
        details={
            "expression_sha256": _sha256(deleted.expression),
            "was_scheduled": was_scheduled,
            "schedule_interval_s": deleted.schedule_interval_s,
        },
    )
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "name": deleted.name,
        "expression": deleted.expression,
        "description": deleted.description,
    }


def handle_schedule_hunt_query(
    *,
    params: dict[str, Any],
    db_path: Path,
    limiter: SlidingWindowLimiter | None = None,
) -> dict[str, Any]:
    """Schedule a saved query as a standing detection (§4.6).

    Validation (interval floor, severity enum, name exists) is daemon-side and
    happens in the store BEFORE any write or audit row; the CLI's own checks
    are UX only.
    """
    rejection = _rate_limited(limiter, db_path=db_path, params=params)
    if rejection is not None:
        return rejection
    try:
        name = _required_str(params, "name")
        raw_interval = params.get("interval_s")
        try:
            interval_s = int(raw_interval)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise HuntRequestError(
                f"interval_s must be a whole number of seconds, got {raw_interval!r}"
            ) from exc
        severity = _optional_str(params, "severity") or "medium"
        with Database(db_path) as db:
            existing = store.get_query(db, name)
            watermark_preserved = existing is not None and existing.watermark_seq is not None
            row = db.query("SELECT COALESCE(MAX(ingest_seq), 0) FROM events_enriched").fetchone()
            max_ingest_seq = int(row[0]) if row is not None else 0
            scheduled = store.schedule_query(
                db,
                name=name,
                interval_s=interval_s,
                severity=severity,
                max_ingest_seq=max_ingest_seq,
            )
    except HuntError as exc:
        return _failure(exc)
    append_audit(
        db_path,
        actor="user:local",
        action="hunt_query_scheduled",
        target=f"hunt:{scheduled.name}",
        details={
            "interval_s": scheduled.interval_s,
            "severity": scheduled.severity,
            # A preserved watermark means the off-gap WILL be scanned (§4.3).
            "watermark_preserved": watermark_preserved,
        },
    )
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "name": scheduled.name,
        "interval_s": scheduled.interval_s,
        "severity": scheduled.severity,
        "watermark_seq": scheduled.watermark_seq,
        "last_run_at": _iso(scheduled.last_run_at),
        "last_status": scheduled.last_status,
    }


def handle_unschedule_hunt_query(
    *,
    params: dict[str, Any],
    db_path: Path,
    limiter: SlidingWindowLimiter | None = None,
) -> dict[str, Any]:
    """Stop a scheduled query; the response and audit say what was destroyed.

    Only the schedule pair is cleared — the watermark survives, so a later
    re-schedule scans the off-gap (§4.3).
    """
    rejection = _rate_limited(limiter, db_path=db_path, params=params)
    if rejection is not None:
        return rejection
    try:
        name = _required_str(params, "name")
        with Database(db_path) as db:
            prior = store.unschedule_query(db, name=name)
    except HuntError as exc:
        return _failure(exc)
    append_audit(
        db_path,
        actor="user:local",
        action="hunt_query_unscheduled",
        target=f"hunt:{prior.name}",
        details={"interval_s": prior.interval_s, "severity": prior.severity},
    )
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "name": prior.name,
        "interval_s": prior.interval_s,
        "severity": prior.severity,
    }
