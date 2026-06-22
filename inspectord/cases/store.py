"""Manual cases store (spec §4) — user-curated bundles of alerts + notes.

case_event is an append-only activity/notes log, NOT a tamper-evident chain-of-custody
(spec §1.1); the daemon can mutate it. uuid7 ids match events/alerts.
"""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.ids import uuid7
from inspectord.storage.db import Database

_MAX_TEXT = 16384


def _bound(text: str | None) -> str | None:
    if text is None:
        return None
    return text[:_MAX_TEXT]


def _append_event(
    db: Database, case_id: str, ts: datetime, seq: int, kind: str, text: str | None
) -> None:
    db.execute(
        "INSERT INTO case_event (case_id, ts, seq, kind, text) VALUES (?, ?, ?, ?, ?)",
        [case_id, ts, seq, kind, _bound(text)],
    )


def _case_exists(db: Database, case_id: str) -> bool:
    return bool(db.query("SELECT 1 FROM cases WHERE case_id = ?", [case_id]).fetchall())


def _link_exists(db: Database, case_id: str, alert_id: str) -> bool:
    return bool(
        db.query(
            "SELECT 1 FROM case_alert WHERE case_id = ? AND alert_id = ?", [case_id, alert_id]
        ).fetchall()
    )


def _attach(db: Database, case_id: str, alert_id: str, ts: datetime, seq: int) -> bool:
    """Link alert→case if not already linked. Returns True if newly linked."""
    if _link_exists(db, case_id, alert_id):
        return False
    db.execute(
        "INSERT INTO case_alert (case_id, alert_id, attached_at) VALUES (?, ?, ?)",
        [case_id, alert_id, ts],
    )
    _append_event(db, case_id, ts, seq, "alert_attached", alert_id)
    return True


def open_case(db: Database, *, alert_id: str, title: str | None = None) -> str:
    case_id = str(uuid7())
    now = datetime.now(tz=UTC)
    if title is None:
        rows = db.query(
            "SELECT rendered_short FROM alerts WHERE alert_id = ?", [alert_id]
        ).fetchall()
        title = rows[0][0] if rows else f"Case {case_id[:8]}"
    db.execute("BEGIN TRANSACTION")
    try:
        db.execute(
            "INSERT INTO cases (case_id, title, status, opened_at, closed_at) "
            "VALUES (?, ?, 'open', ?, NULL)",
            [case_id, _bound(title), now],
        )
        _append_event(db, case_id, now, 0, "opened", None)
        _attach(db, case_id, alert_id, now, 1)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return case_id


def attach_alert(db: Database, *, case_id: str, alert_id: str) -> None:
    if not _case_exists(db, case_id):
        return
    _attach(db, case_id, alert_id, datetime.now(tz=UTC), 0)
