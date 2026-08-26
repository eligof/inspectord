"""Retention pruners (spec 2026-08-26-retention-design.md §5).

Age-based pruning of the daemon's unbounded surfaces. Every cutoff derives
from one caller-supplied ``now`` that MUST be timezone-aware UTC; "today" is
``now.date()`` in UTC — exactly the Journal's rotation date. SQL parameters
are converted to naive UTC at the query boundary, matching the DB convention
(the session runs with ``TimeZone='UTC'``).
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from inspectord.config import RetentionConfig
from inspectord.evidence.store import ForensicStore
from inspectord.storage.db import Database

# One DELETE per chunk keeps individual statements bounded; the per-run budget
# (events_max_rows_per_run) caps the total across chunks (§5.1).
_EVENTS_DELETE_CHUNK = 10_000

_JOURNAL_SUFFIX = ".jsonl.gz"

# Crashed-put() debris (`.tmp-*` under evidence_root) older than this is swept (§5.4).
_TMP_DEBRIS_MAX_AGE_S = 86400.0


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


def _size_or_zero(path: Path) -> int:
    """stat() that tolerates a file vanishing between iterdir and stat.

    Note: a .jsonl.gz-named symlink is followed here, so quota accounting uses
    the target's size while deletion would unlink only the link -- accounting
    skew only, never over-deletion; the dir is daemon-owned 0700.
    """
    try:
        return path.stat().st_size
    except OSError:
        return 0


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
            "    ORDER BY ts DESC, event_id DESC LIMIT 1)"
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
    usage = sum(_size_or_zero(p) for _, p in remaining)
    usage += sum(_size_or_zero(p) for p in unparseable)
    floor_cutoff = today - timedelta(days=floor_days)
    deletable = sorted(
        (file_date, path)
        for file_date, path in remaining
        if file_date < floor_cutoff and file_date not in protected
    )
    for _file_date, path in deletable:
        if usage <= quota_bytes:
            break
        size = _size_or_zero(path)
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


@dataclass
class EvidencePruneResult:
    """Outcome of the evidence pruner alone (folded into RetentionReport)."""

    blobs_deleted: int = 0
    pruned_shas: list[str] = field(default_factory=list)


def _has_younger_row(db: Database, sha: str, cutoff: datetime) -> bool:
    row = db.query(
        "SELECT 1 FROM case_evidence WHERE sha256 = ? AND captured_at >= ? LIMIT 1",
        [sha, cutoff],
    ).fetchone()
    return row is not None


def _stamp_tombstones(db: Database, sha: str, pruned_at_iso: str) -> None:
    """Merge the pruned-provenance marker into every tombstone row for ``sha`` (§5.4).

    A missing blob WITHOUT this marker is itself an indicator of tampering;
    the marker also removes the sha from future candidate scans.
    """
    rows = db.query(
        "SELECT case_id, kind, original_path, meta_json FROM case_evidence WHERE sha256 = ?",
        [sha],
    ).fetchall()
    for case_id, kind, original_path, meta_json in rows:
        meta: dict[str, object] = {}
        if meta_json:
            with contextlib.suppress(ValueError):
                parsed = json.loads(meta_json)
                if isinstance(parsed, dict):
                    meta = parsed
        meta["pruned_at"] = pruned_at_iso
        meta["pruned_by"] = "auto:retention"
        db.execute(
            "UPDATE case_evidence SET meta_json = ? "
            "WHERE case_id = ? AND kind = ? AND sha256 = ? AND original_path = ?",
            [json.dumps(meta), case_id, kind, sha, original_path],
        )


def prune_evidence(
    db: Database,
    evidence_root: Path,
    *,
    now: datetime,
    days: int,
    capture_lock: threading.Lock | None,
) -> EvidencePruneResult:
    """Delete forensic blobs whose every reference is stale and unprotected (§5.4).

    Candidates are the DISTINCT shas among ``case_evidence`` rows older than
    the cutoff whose ``meta_json`` does not already carry a ``pruned_at``
    marker. A sha is prunable iff it has no younger row, every referencing
    case is closed, and no referencing case has a critical alert (§4.2). The
    whole body runs under the EvidenceCollector's capture lock so a concurrent
    capture cannot dedup against a blob mid-unlink. ``case_evidence`` rows are
    never deleted; on unlink (or an already-missing blob) every row for the
    sha is stamped with pruned provenance — but a missing blob counts nothing.
    Also sweeps ``.tmp-*`` debris older than one day under ``evidence_root``.
    """
    cutoff = _naive_utc(now) - timedelta(days=days)
    pruned_at_iso = now.astimezone(UTC).isoformat()
    result = EvidencePruneResult()
    store = ForensicStore(evidence_root)
    lock: contextlib.AbstractContextManager[object] = (
        capture_lock if capture_lock is not None else contextlib.nullcontext()
    )
    with lock:
        candidates = [
            str(r[0])
            for r in db.query(
                "SELECT DISTINCT sha256 FROM case_evidence "
                "WHERE captured_at < ? "
                "  AND (meta_json IS NULL OR meta_json NOT LIKE '%\"pruned_at\"%') "
                "ORDER BY sha256",
                [cutoff],
            ).fetchall()
        ]
        for sha in candidates:
            if _has_younger_row(db, sha, cutoff):
                continue
            not_closed = db.query(
                "SELECT 1 FROM case_evidence ce JOIN cases c ON c.case_id = ce.case_id "
                "WHERE ce.sha256 = ? AND c.status != 'closed' LIMIT 1",
                [sha],
            ).fetchone()
            if not_closed is not None:
                continue
            critical = db.query(
                "SELECT 1 FROM case_evidence ce "
                "JOIN case_alert ca ON ca.case_id = ce.case_id "
                "JOIN alerts a ON a.alert_id = ca.alert_id "
                "WHERE ce.sha256 = ? AND a.severity = 'critical' LIMIT 1",
                [sha],
            ).fetchone()
            if critical is not None:
                continue
            blob = store.path_for(sha)
            if blob.exists():
                # Belt-and-braces inside the lock: re-check for a row captured
                # since the candidate scan immediately before the unlink.
                if _has_younger_row(db, sha, cutoff):
                    continue
                blob.unlink()
                # Best-effort: drop the shard dir once its last blob is gone.
                with contextlib.suppress(OSError):
                    blob.parent.rmdir()
                result.blobs_deleted += 1
                result.pruned_shas.append(sha)
            # Already-missing blob: stamp the tombstones the same way, but
            # count nothing — no phantom daily counts.
            _stamp_tombstones(db, sha, pruned_at_iso)
        # Sweep crashed-put() debris.
        root = Path(evidence_root)
        if root.is_dir():
            debris_cutoff = time.time() - _TMP_DEBRIS_MAX_AGE_S
            for tmp in root.rglob(".tmp-*"):
                with contextlib.suppress(OSError):
                    if tmp.is_file() and tmp.stat().st_mtime < debris_cutoff:
                        tmp.unlink()
    return result


def run_retention(
    db: Database,
    *,
    cfg: RetentionConfig,
    journal_dir: Path,
    evidence_root: Path,
    now: datetime,
    capture_lock: threading.Lock | None = None,
) -> RetentionReport:
    """Run every pruner, each independently guarded, then checkpoint (§5, §5.5).

    ``cfg.enabled`` is the caller's gate (the supervisor tick); the engine
    always runs. A failing surface lands in ``errors`` and the remaining
    surfaces still run. When any DB-surface count is > 0, a best-effort
    ``CHECKPOINT`` makes the freed blocks reusable (failure → ``errors``).
    """
    _naive_utc(now)  # a naive `now` must raise at the caller, not land in errors
    report = RetentionReport()
    try:
        report.events_deleted = prune_events(
            db, now=now, days=cfg.events_days, max_rows=cfg.events_max_rows_per_run
        )
    except Exception as exc:
        report.errors.append(f"events: {exc!r}")
    try:
        journal = prune_journal_files(
            db,
            journal_dir,
            now=now,
            days=cfg.journal_days,
            quota_mb=cfg.journal_quota_mb,
            floor_days=cfg.journal_quota_floor_days,
        )
        report.journal_files_deleted = journal.files_deleted
        report.skipped_files = journal.skipped_files
        report.quota_overage_bytes = journal.quota_overage_bytes
    except Exception as exc:
        report.errors.append(f"journal: {exc!r}")
    try:
        report.alerts_deleted = prune_alerts(db, now=now, days=cfg.alerts_days)
    except Exception as exc:
        report.errors.append(f"alerts: {exc!r}")
    try:
        evidence = prune_evidence(
            db, evidence_root, now=now, days=cfg.evidence_days, capture_lock=capture_lock
        )
        report.evidence_blobs_deleted = evidence.blobs_deleted
        report.pruned_shas = evidence.pruned_shas
    except Exception as exc:
        report.errors.append(f"evidence: {exc!r}")
    if report.events_deleted or report.alerts_deleted or report.evidence_blobs_deleted:
        try:
            db.execute("CHECKPOINT")
        except Exception as exc:
            report.errors.append(f"checkpoint: {exc!r}")
    return report
