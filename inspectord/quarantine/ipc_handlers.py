"""IPC handlers for quarantine (quarantine design §4) — the edge.

The polkit gate, the per-verb rate limiters and the -32001 denial channel all
live in `IpcServer` (§2.3); by the time a handler runs, the peer has been
authorized. What the edge still owes:

**Identity.** The server injects the accept-time `PeerIdentity` under the
reserved `PEER_PARAM` key for gated methods; the handlers format it into the
`uid:pid` audit actor (§3.2) that rides every mutating success AND refusal row.

**Errors are data, not exceptions.** Every `QuarantineError` is rendered as
`{ok: False, error, error_kind}` — the ops layer's typed errors already carry
their stable `error_kind`, so the CLI and the panel branch without string
matching. Request-shape problems (missing param, unknown alert/case id) get
the same treatment via `QuarantineRequestError`, and are audited as refusals
too: they are refused *mutating* verbs.

**Reference validation.** `alert_id`/`case_id` are checked to exist before
anything touches disk — a quarantine row must never point at a phantom.
"""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from inspectord.audit.log import append_audit
from inspectord.authz import PeerIdentity
from inspectord.evidence.store import ForensicStore
from inspectord.ipc_server import PEER_PARAM
from inspectord.quarantine import ops
from inspectord.quarantine.errors import QuarantineError, QuarantineRequestError
from inspectord.quarantine.paths import QuarantinePaths
from inspectord.storage.db import Database

__all__ = [
    "handle_delete_quarantined",
    "handle_list_quarantine",
    "handle_quarantine_file",
    "handle_restore_quarantined",
]

_SCHEMA = "1.0.0"

#: Audit rows echo caller-typed strings; bound what rides into the log.
_TARGET_AUDIT_MAX_CHARS = 512


def _actor(params: dict[str, Any]) -> str:
    """`uid:pid` audit actor from the server-injected peer identity (§3.2)."""
    peer = params.get(PEER_PARAM)
    if isinstance(peer, PeerIdentity):
        return f"uid:{peer.uid}:pid:{peer.pid}"
    return "user:local"  # direct/ungated call — no peer was injected


def _failure(exc: QuarantineError) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA,
        "ok": False,
        "error": str(exc),
        "error_kind": exc.error_kind,
    }


def _audit_refusal(
    db_path: Path, *, actor: str, verb: str, target: str, exc: QuarantineError
) -> None:
    """Request-level refusals of mutating verbs are audited like ops' own.

    Only for errors raised BEFORE ops runs — ops audits everything it raises
    itself, and a second row for the same refusal would double-count.
    """
    append_audit(
        db_path,
        actor=actor,
        action="quarantine_refused",
        target=target[:_TARGET_AUDIT_MAX_CHARS],
        details={"verb": verb, "error_kind": exc.error_kind, "error": str(exc)},
    )


def _required_str(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise QuarantineRequestError(f"{key} is required")
    return value


def _optional_str(params: dict[str, Any], key: str) -> str | None:
    value = params.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise QuarantineRequestError(f"{key} must be a string")
    return value


def _check_reference(db: Database, *, table: str, column: str, value: str, what: str) -> None:
    row = db.query(f"SELECT 1 FROM {table} WHERE {column} = ? LIMIT 1", [value]).fetchone()
    if row is None:
        raise QuarantineRequestError(f"no such {what}: {value!r}")


def handle_quarantine_file(
    *,
    params: dict[str, Any],
    db_path: Path,
    store: ForensicStore,
    lock: threading.Lock,
    paths: QuarantinePaths,
    qo_runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Isolate `path` into the forensic store (§3.2) — polkit-gated server-side."""
    actor = _actor(params)
    path = ""
    try:
        path = _required_str(params, "path")
        if not path.startswith("/"):
            raise QuarantineRequestError(f"path must be absolute: {path!r}")
        note = _optional_str(params, "note")
        alert_id = _optional_str(params, "alert_id")
        case_id = _optional_str(params, "case_id")
        with Database(db_path) as db:
            if alert_id is not None:
                _check_reference(
                    db, table="alerts", column="alert_id", value=alert_id, what="alert"
                )
            if case_id is not None:
                _check_reference(db, table="cases", column="case_id", value=case_id, what="case")
    except QuarantineRequestError as exc:
        _audit_refusal(db_path, actor=actor, verb="quarantine", target=path or "?", exc=exc)
        return _failure(exc)
    try:
        with Database(db_path) as db:
            result = ops.isolate(
                db,
                store,
                lock,
                path=path,
                actor=actor,
                paths=paths,
                alert_id=alert_id,
                case_id=case_id,
                note=note,
                qo_runner=qo_runner,
            )
    except QuarantineError as exc:  # already audited by ops
        return _failure(exc)
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "quarantine_id": result.quarantine_id,
        "sha256": result.sha256,
        "pkg_owner": result.pkg_owner,
        "running_pids": result.running_pids,
        "warnings": result.warnings,
    }


def handle_list_quarantine(
    *, params: dict[str, Any], db_path: Path, store: ForensicStore
) -> dict[str, Any]:
    """Bounded listing with health flags (§3.6/§4); read-only, ungated."""
    try:
        raw = params.get("limit")
        try:
            limit = None if raw is None else int(raw)
        except (TypeError, ValueError) as exc:
            raise QuarantineRequestError(f"limit must be a whole number, got {raw!r}") from exc
        with Database(db_path) as db:
            listing = (
                ops.list_quarantine(db, store)
                if limit is None
                else ops.list_quarantine(db, store, limit=limit)
            )
    except QuarantineError as exc:
        return _failure(exc)
    return {"schema_version": _SCHEMA, "ok": True, **listing}


def handle_restore_quarantined(
    *,
    params: dict[str, Any],
    db_path: Path,
    store: ForensicStore,
    paths: QuarantinePaths,
) -> dict[str, Any]:
    """Put the quarantined bytes back at their original path (§3.3)."""
    actor = _actor(params)
    try:
        quarantine_id = _required_str(params, "quarantine_id")
    except QuarantineRequestError as exc:
        _audit_refusal(db_path, actor=actor, verb="restore", target="?", exc=exc)
        return _failure(exc)
    try:
        with Database(db_path) as db:
            result = ops.restore(db, store, quarantine_id=quarantine_id, actor=actor, paths=paths)
    except QuarantineError as exc:  # already audited by ops
        return _failure(exc)
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "quarantine_id": result.quarantine_id,
        "original_path": result.original_path,
        "sha256": result.sha256,
        "setuid_warning": result.setuid_warning,
    }


def handle_delete_quarantined(
    *,
    params: dict[str, Any],
    db_path: Path,
    store: ForensicStore,
    lock: threading.Lock,
) -> dict[str, Any]:
    """Discard a quarantined file for good (§3.4)."""
    actor = _actor(params)
    try:
        quarantine_id = _required_str(params, "quarantine_id")
    except QuarantineRequestError as exc:
        _audit_refusal(db_path, actor=actor, verb="delete", target="?", exc=exc)
        return _failure(exc)
    try:
        with Database(db_path) as db:
            result = ops.delete(db, store, lock, quarantine_id=quarantine_id, actor=actor)
    except QuarantineError as exc:  # already audited by ops
        return _failure(exc)
    return {
        "schema_version": _SCHEMA,
        "ok": True,
        "quarantine_id": result.quarantine_id,
        "original_path": result.original_path,
        "blob_removed": result.blob_removed,
    }
