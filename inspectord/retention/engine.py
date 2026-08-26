"""Retention pruners (spec 2026-08-26-retention-design.md §5).

Age-based pruning of the daemon's unbounded surfaces. Every cutoff derives
from one caller-supplied ``now`` that MUST be timezone-aware UTC; "today" is
``now.date()`` in UTC — exactly the Journal's rotation date. SQL parameters
are converted to naive UTC at the query boundary, matching the DB convention
(the session runs with ``TimeZone='UTC'``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from inspectord.storage.db import Database

# One DELETE per chunk keeps individual statements bounded; the per-run budget
# (events_max_rows_per_run) caps the total across chunks (§5.1).
_EVENTS_DELETE_CHUNK = 10_000

_JOURNAL_SUFFIX = ".jsonl.gz"


@dataclass
class RetentionReport:
    """Outcome of one retention run (§5)."""

    events_deleted: int = 0
    journal_files_deleted: int = 0
    alerts_deleted: int = 0
    evidence_blobs_deleted: int = 0
    pruned_shas: list[str] = field(default_factory=list)
    # Unparseable journal names — reported in audit details, NOT errors (§5.2).
    skipped_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    quota_overage_bytes: int = 0

    @property
    def any_deletions(self) -> bool:
        """True when the run actually deleted something (drives the audit row, §6)."""
        return (
            self.events_deleted > 0
            or self.journal_files_deleted > 0
            or self.alerts_deleted > 0
            or self.evidence_blobs_deleted > 0
        )


@dataclass
class JournalPruneResult:
    """Outcome of the journal pruner alone (folded into RetentionReport)."""

    files_deleted: int = 0
    skipped_files: list[str] = field(default_factory=list)
    quota_overage_bytes: int = 0


def _naive_utc(now: datetime) -> datetime:
    """Validate ``now`` is tz-aware and return it as naive UTC for SQL params."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware UTC (use datetime.now(UTC))")
    return now.astimezone(UTC).replace(tzinfo=None)


def prune_events(db: Database, *, now: datetime, days: int, max_rows: int) -> int:
    """Delete enriched events older than ``days``, at most ``max_rows`` per run (§5.1).

    The newest ``supervisor``/``audit_head`` row is structurally exempt (§4.5):
    it is the tamper-detection anchor and must survive outages longer than the
    retention window. A run that exhausts its budget stops; the backlog drains
    over subsequent daily runs.
    """
    cutoff = _naive_utc(now) - timedelta(days=days)
    deleted = 0
    while deleted < max_rows:
        limit = min(_EVENTS_DELETE_CHUNK, max_rows - deleted)
        row = db.query(
            "DELETE FROM events_enriched WHERE event_id IN ("
            "  SELECT event_id FROM events_enriched"
            "  WHERE ts < ?"
            "  AND event_id NOT IN ("
            "    SELECT event_id FROM events_enriched"
            "    WHERE module = 'supervisor' AND action = 'audit_head'"
            "    ORDER BY ts DESC LIMIT 1)"
            "  LIMIT ?)",
            [cutoff, limit],
        ).fetchone()
        chunk = int(row[0]) if row is not None else 0
        deleted += chunk
        if chunk < limit:
            break
    return deleted


def _critical_alert_days(db: Database) -> set[date]:
    """Days on which a critical alert fired — their journal files are protected (§4.3)."""
    rows = db.query(
        "SELECT DISTINCT CAST(ts AS DATE) FROM alerts WHERE severity = 'critical'"
    ).fetchall()
    days: set[date] = set()
    for (value,) in rows:
        days.add(value.date() if isinstance(value, datetime) else value)
    return days


def prune_journal_files(
    db: Database,
    journal_dir: Path,
    *,
    now: datetime,
    days: int,
    quota_mb: int,
    floor_days: int,
) -> JournalPruneResult:
    """Age pass then quota pass over ``YYYY-MM-DD.jsonl.gz`` files (§5.2).

    Protected (never deleted): today's file and files for days with a critical
    alert. Unparseable names are reported in ``skipped_files``, never deleted.
    The quota pass evicts oldest-first but never files younger than
    ``floor_days``; residual overage is reported, not an error.
    """
    today = _naive_utc(now).date()
    result = JournalPruneResult()
    journal_dir = Path(journal_dir)
    if not journal_dir.is_dir():
        return result

    dated: list[tuple[date, Path]] = []
    unparseable: list[Path] = []
    for path in sorted(journal_dir.iterdir()):
        if not path.name.endswith(_JOURNAL_SUFFIX) or not path.is_file():
            continue
        try:
            file_date = date.fromisoformat(path.name.removesuffix(_JOURNAL_SUFFIX))
        except ValueError:
            result.skipped_files.append(path.name)
            unparseable.append(path)
            continue
        dated.append((file_date, path))

    protected = _critical_alert_days(db) | {today}

    # Age pass: delete unprotected files older than `days`.
    age_cutoff = today - timedelta(days=days)
    remaining: list[tuple[date, Path]] = []
    for file_date, path in dated:
        if file_date < age_cutoff and file_date not in protected:
            path.unlink()
            result.files_deleted += 1
        else:
            remaining.append((file_date, path))

    # Quota pass: evict oldest-first while over quota; the floor bounds a flood.
    quota_bytes = quota_mb * 2**20
    usage = sum(p.stat().st_size for _, p in remaining)
    usage += sum(p.stat().st_size for p in unparseable)
    floor_cutoff = today - timedelta(days=floor_days)
    deletable = sorted(
        (file_date, path)
        for file_date, path in remaining
        if file_date < floor_cutoff and file_date not in protected
    )
    for _file_date, path in deletable:
        if usage <= quota_bytes:
            break
        size = path.stat().st_size
        path.unlink()
        usage -= size
        result.files_deleted += 1
    if usage > quota_bytes:
        result.quota_overage_bytes = usage - quota_bytes
    return result


def prune_alerts(db: Database, *, now: datetime, days: int) -> int:
    """Delete stale non-critical alerts by recency, not first-seen (§5.3).

    Dedup keeps one row alive across re-firings by updating ``last_seen_at``
    while ``ts`` stays at the first firing, so the cutoff compares
    ``last_seen_at``. Critical alerts (§4.1) and alerts attached to open cases
    (§4.4) are exempt regardless of age.
    """
    cutoff = _naive_utc(now) - timedelta(days=days)
    row = db.query(
        "DELETE FROM alerts "
        "WHERE last_seen_at < ? "
        "  AND severity != 'critical' "
        "  AND alert_id NOT IN ("
        "    SELECT ca.alert_id FROM case_alert ca "
        "    JOIN cases c ON c.case_id = ca.case_id WHERE c.status = 'open')",
        [cutoff],
    ).fetchone()
    return int(row[0]) if row is not None else 0
