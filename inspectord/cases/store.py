"""Manual cases store (spec §4) — user-curated bundles of alerts + notes.

case_event is an append-only activity/notes log, NOT a tamper-evident chain-of-custody
(spec §1.1); the daemon can mutate it. uuid7 ids match events/alerts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

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


def add_note(db: Database, *, case_id: str, text: str) -> None:
    if not _case_exists(db, case_id):
        return
    _append_event(db, case_id, datetime.now(tz=UTC), 0, "note", text)


def close_case(db: Database, *, case_id: str) -> None:
    rows = db.query("SELECT status FROM cases WHERE case_id = ?", [case_id]).fetchall()
    if not rows or rows[0][0] == "closed":
        return
    now = datetime.now(tz=UTC)
    db.execute(
        "UPDATE cases SET status = 'closed', closed_at = ? WHERE case_id = ?", [now, case_id]
    )
    _append_event(db, case_id, now, 0, "closed", None)


def list_cases(db: Database) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT c.case_id, c.title, c.status, c.opened_at, c.closed_at, "
        "  (SELECT COUNT(*) FROM case_alert a WHERE a.case_id = c.case_id) AS alert_count "
        "FROM cases c ORDER BY c.opened_at DESC"
    ).fetchall()
    return [
        {
            "case_id": r[0],
            "title": r[1],
            "status": r[2],
            "opened_at": r[3],
            "closed_at": r[4],
            "alert_count": r[5],
        }
        for r in rows
    ]


def get_case(db: Database, *, case_id: str) -> dict[str, Any] | None:
    crows = db.query(
        "SELECT case_id, title, status, opened_at, closed_at FROM cases WHERE case_id = ?",
        [case_id],
    ).fetchall()
    if not crows:
        return None
    c = crows[0]
    # LEFT JOIN so a pruned alert still appears (placeholder) and len(alerts) == alert_count.
    arows = db.query(
        "SELECT ca.alert_id, al.rule_id, al.severity, al.status, al.rendered_short, al.ts "
        "FROM case_alert ca LEFT JOIN alerts al ON al.alert_id = ca.alert_id "
        "WHERE ca.case_id = ? ORDER BY ca.attached_at",
        [case_id],
    ).fetchall()
    alerts = [
        {
            "alert_id": a[0],
            "rule_id": a[1],
            "severity": a[2],
            "status": a[3],
            "rendered_short": a[4],
            "ts": a[5],
        }
        for a in arows
    ]
    trows = db.query(
        "SELECT ts, seq, kind, text FROM case_event WHERE case_id = ? ORDER BY ts, seq",
        [case_id],
    ).fetchall()
    timeline = [{"ts": t[0], "seq": t[1], "kind": t[2], "text": t[3]} for t in trows]
    return {
        "case_id": c[0],
        "title": c[1],
        "status": c[2],
        "opened_at": c[3],
        "closed_at": c[4],
        "alerts": alerts,
        "timeline": timeline,
    }
