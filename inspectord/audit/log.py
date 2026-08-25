"""Hash-chained audit log (spec 2026-08-25-audit-log-design).

Append-only at the application layer. Each row's ``prev_hash`` is the previous
row's ``row_hash``; genesis uses ``journal.ZERO_HASH``. The chain detects
tampering with WRITTEN rows (interior edits/deletes/inserts). It cannot detect
fail-open drops (rows never written) or suffix truncation newer than the last
``audit_head`` journal anchor — see spec §8 for the honest threat model.

Concurrency: one module-owned Database connection + one module lock. Writers
never pass their own connection (a caller mid-transaction would break the
read-max-then-insert protocol). Daemon-process-only: helper processes must not
write audit_log; the seq PRIMARY KEY makes a cross-process double-append fail
loudly instead of forking the chain. No retry — a retry must re-enter the lock
and recompute seq/prev_hash.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.journal import ZERO_HASH
from inspectord.log import get
from inspectord.storage.db import Database

log = get(__name__)

# Rolling-window escalation, mirroring supervisor persistence_failing.
FAILURE_WINDOW = 20
FAILURE_ALERT_THRESHOLD = 5
FAILURE_COOLDOWN_S = 300.0

_lock = threading.Lock()
_db: Database | None = None
_db_path: Path | None = None
_outcomes: deque[bool] = deque(maxlen=FAILURE_WINDOW)
_last_alert_mono: float | None = None
_failure_listener: Callable[[int, int], None] | None = None


def set_failure_listener(cb: Callable[[int, int], None] | None) -> None:
    """Register a callback(failures, window) fired past the failure threshold."""
    global _failure_listener  # noqa: PLW0603
    _failure_listener = cb


def reset_for_tests() -> None:
    """Drop module state (connection, counters). Test helper only."""
    global _db, _db_path, _last_alert_mono  # noqa: PLW0603
    with _lock:
        if _db is not None:
            _db.close()
        _db = None
        _db_path = None
        _outcomes.clear()
        _last_alert_mono = None


def _conn(db_path: Path) -> Database:
    global _db, _db_path  # noqa: PLW0603
    if _db is None or _db_path != db_path:
        if _db is not None:
            _db.close()
        _db = Database(db_path)
        _db.connect()
        _db_path = db_path
    return _db


def _canon_ts(ts: datetime) -> str:
    return ts.isoformat(sep="T", timespec="microseconds")


def _row_hash_from_stored(
    *,
    seq: int,
    ts: datetime,
    actor: str,
    action: str,
    target: str | None,
    details_json: str,
    prev_hash: str,
) -> str:
    payload = json.dumps(
        {
            "seq": seq,
            "ts": _canon_ts(ts),
            "actor": actor,
            "action": action,
            "target": target,
            "details": details_json,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit(
    db_path: Path,
    *,
    actor: str,
    action: str,
    target: str | None,
    details: dict[str, Any],
    _ts: datetime | None = None,
) -> int | None:
    """Append one chained row. Returns seq, or None on a swallowed failure.

    Fail-open (spec §6): a failure here never propagates to the wrapped
    action, and the dropped row is UNDETECTABLE by verify — no seq is
    consumed. Failures escalate via the registered failure listener.
    """
    global _last_alert_mono  # noqa: PLW0603
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)
    ts = (_ts or datetime.now(UTC)).replace(tzinfo=None)
    try:
        with _lock:
            db = _conn(db_path)
            head = db.query(
                "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = 1 if head is None else head[0] + 1
            prev_hash = ZERO_HASH if head is None else head[1]
            row_hash = _row_hash_from_stored(
                seq=seq,
                ts=ts,
                actor=actor,
                action=action,
                target=target,
                details_json=details_json,
                prev_hash=prev_hash,
            )
            db.execute(
                "INSERT INTO audit_log (seq, ts, actor, action, target, "
                "details_json, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [seq, ts, actor, action, target, details_json, prev_hash, row_hash],
            )
    except Exception as exc:
        log.error("audit append failed for %s %s: %r", action, target, exc)
        fire = False
        with _lock:
            _outcomes.append(False)
            failures = sum(1 for ok in _outcomes if not ok)
            now = time.monotonic()
            if failures >= FAILURE_ALERT_THRESHOLD and (
                _last_alert_mono is None or now - _last_alert_mono >= FAILURE_COOLDOWN_S
            ):
                _last_alert_mono = now
                fire = True
        if fire and _failure_listener is not None:
            _failure_listener(failures, FAILURE_WINDOW)
        return None
    with _lock:
        _outcomes.append(True)
    return seq
