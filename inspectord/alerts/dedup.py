"""Dedup engine: persists Alerts; same dedup_key within window bumps counter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.schemas.alert import Alert
from inspectord.storage.db import Database


class DedupEngine:
    def __init__(self, *, db_path: Path, window_s: float = 600.0) -> None:
        self._db_path = Path(db_path)
        self._window = timedelta(seconds=window_s)

    def persist(self, alert: Alert) -> tuple[Alert, bool]:
        """Persist or update. Returns (final_alert, was_new)."""
        cutoff = alert.ts - self._window
        with Database(self._db_path) as db:
            rows = db.query(
                "SELECT alert_id, dedup_count, first_seen_at FROM alerts "
                "WHERE dedup_key = ? AND last_seen_at >= ? "
                "ORDER BY last_seen_at DESC LIMIT 1",
                [alert.dedup_key, cutoff],
            ).fetchall()
            if rows:
                existing_id = rows[0][0]
                new_count = int(rows[0][1]) + 1
                first_seen = rows[0][2] if rows[0][2] is not None else alert.ts
                if isinstance(first_seen, str):
                    first_seen = datetime.fromisoformat(first_seen)
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=UTC)
                db.execute(
                    "UPDATE alerts SET dedup_count = ?, last_seen_at = ?, "
                    "rendered_short = ?, rendered_detail = ?, payload_json = ? "
                    "WHERE alert_id = ?",
                    [
                        new_count,
                        alert.last_seen_at,
                        alert.rendered.short,
                        alert.rendered.detail,
                        alert.model_dump_json(),
                        existing_id,
                    ],
                )
                return (
                    alert.model_copy(
                        update={
                            "alert_id": existing_id,
                            "dedup_count": new_count,
                            "first_seen_at": first_seen,
                        }
                    ),
                    False,
                )
            db.execute(
                "INSERT INTO alerts ("
                "alert_id, rule_id, ts, severity, status, category, dedup_key, "
                "dedup_count, first_seen_at, last_seen_at, rendered_short, "
                "rendered_detail, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    alert.alert_id,
                    alert.rule.id,
                    alert.ts,
                    alert.severity.value,
                    alert.status.value,
                    alert.category,
                    alert.dedup_key,
                    alert.dedup_count,
                    alert.first_seen_at,
                    alert.last_seen_at,
                    alert.rendered.short,
                    alert.rendered.detail,
                    alert.model_dump_json(),
                ],
            )
            return alert, True
