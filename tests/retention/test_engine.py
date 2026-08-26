"""Events / journal / alerts pruners (retention spec §5.1-§5.3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.parsers.base import build_event
from inspectord.retention.engine import (
    RetentionReport,
    prune_alerts,
    prune_events,
    prune_journal_files,
)
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
NAIVE_NOW = NOW.replace(tzinfo=None)


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_event(
    db: Database,
    *,
    ts: datetime,
    module: str = "probe",
    action: str = "tick",
) -> None:
    event = build_event(
        module=module,
        action=action,
        category=["c"],
        type_=["t"],
        severity="info",
        ts=ts,
    )
    insert_event(db, event, event.model_dump_json())


def _event_count(db: Database) -> int:
    row = db.query("SELECT COUNT(*) FROM events_enriched").fetchone()
    assert row is not None
    return int(row[0])


def _seed_alert(
    db: Database,
    alert_id: str,
    *,
    ts: datetime,
    last_seen_at: datetime | None = None,
    severity: str = "medium",
) -> None:
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
        "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
        "VALUES (?, 'r1', ?, ?, 'new', 'auth', ?, 1, ?, ?, 'short', 'detail', '{}')",
        [alert_id, ts, severity, f"dk-{alert_id}", ts, last_seen_at if last_seen_at else ts],
    )


def _alert_ids(db: Database) -> set[str]:
    return {r[0] for r in db.query("SELECT alert_id FROM alerts").fetchall()}


def _seed_case(db: Database, case_id: str, alert_id: str, *, status: str) -> None:
    db.execute(
        "INSERT INTO cases (case_id, title, status, opened_at) "
        "VALUES (?, 't', ?, TIMESTAMP '2026-01-01 00:00:00')",
        [case_id, status],
    )
    db.execute(
        "INSERT INTO case_alert (case_id, alert_id, attached_at) "
        "VALUES (?, ?, TIMESTAMP '2026-01-01 00:00:00')",
        [case_id, alert_id],
    )


# --- events pruner (§5.1) ---


def test_prune_events_deletes_old_keeps_recent(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_event(db, ts=NOW - timedelta(days=40))
    _seed_event(db, ts=NOW - timedelta(days=1))
    deleted = prune_events(db, now=NOW, days=30, max_rows=100_000)
    assert deleted == 1
    assert _event_count(db) == 1


def test_prune_events_spares_newest_audit_head_even_when_ancient(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # The only anchor, 90 days old — far outside the window.
    _seed_event(db, ts=NOW - timedelta(days=90), module="supervisor", action="audit_head")
    _seed_event(db, ts=NOW - timedelta(days=90))
    deleted = prune_events(db, now=NOW, days=30, max_rows=100_000)
    assert deleted == 1
    rows = db.query("SELECT module, action FROM events_enriched").fetchall()
    assert rows == [("supervisor", "audit_head")]


def test_prune_events_only_newest_audit_head_is_exempt(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_event(db, ts=NOW - timedelta(days=100), module="supervisor", action="audit_head")
    _seed_event(db, ts=NOW - timedelta(days=90), module="supervisor", action="audit_head")
    deleted = prune_events(db, now=NOW, days=30, max_rows=100_000)
    assert deleted == 1
    rows = db.query("SELECT ts FROM events_enriched").fetchall()
    assert rows == [(NAIVE_NOW - timedelta(days=90),)]


def test_prune_events_budget_bounds_a_run_and_resumes(tmp_path: Path) -> None:
    db = _db(tmp_path)
    for i in range(25):
        _seed_event(db, ts=NOW - timedelta(days=40, minutes=i))
    assert prune_events(db, now=NOW, days=30, max_rows=10) == 10
    assert _event_count(db) == 15
    assert prune_events(db, now=NOW, days=30, max_rows=10) == 10
    assert prune_events(db, now=NOW, days=30, max_rows=10) == 5
    assert _event_count(db) == 0


def test_prune_events_rejects_naive_now(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(ValueError, match="timezone-aware"):
        prune_events(db, now=NAIVE_NOW, days=30, max_rows=100_000)


# --- journal pruner (§5.2) ---


def _journal_file(journal_dir: Path, name: str, *, size: int = 100) -> Path:
    journal_dir.mkdir(parents=True, exist_ok=True)
    path = journal_dir / name
    path.write_bytes(b"x" * size)
    return path


def _name_for(days_ago: int) -> str:
    return f"{(NOW - timedelta(days=days_ago)).date().isoformat()}.jsonl.gz"


def test_journal_age_pass_deletes_old_keeps_recent_and_today(tmp_path: Path) -> None:
    db = _db(tmp_path)
    journal_dir = tmp_path / "journal"
    old = _journal_file(journal_dir, _name_for(40))
    recent = _journal_file(journal_dir, _name_for(5))
    today = _journal_file(journal_dir, _name_for(0))
    result = prune_journal_files(db, journal_dir, now=NOW, days=30, quota_mb=500, floor_days=7)
    assert result.files_deleted == 1
    assert not old.exists()
    assert recent.exists()
    assert today.exists()
    assert result.skipped_files == []
    assert result.quota_overage_bytes == 0


def test_journal_age_pass_keeps_critical_alert_day(tmp_path: Path) -> None:
    db = _db(tmp_path)
    journal_dir = tmp_path / "journal"
    critical_day = _journal_file(journal_dir, _name_for(40))
    plain_old = _journal_file(journal_dir, _name_for(41))
    _seed_alert(db, "crit1", ts=NOW - timedelta(days=40), severity="critical")
    result = prune_journal_files(db, journal_dir, now=NOW, days=30, quota_mb=500, floor_days=7)
    assert result.files_deleted == 1
    assert critical_day.exists()
    assert not plain_old.exists()


def test_journal_unparseable_name_skipped_not_deleted_not_error(tmp_path: Path) -> None:
    db = _db(tmp_path)
    journal_dir = tmp_path / "journal"
    junk = _journal_file(journal_dir, "not-a-date.jsonl.gz")
    result = prune_journal_files(db, journal_dir, now=NOW, days=30, quota_mb=500, floor_days=7)
    assert result.files_deleted == 0
    assert junk.exists()
    assert result.skipped_files == ["not-a-date.jsonl.gz"]


def test_journal_quota_floor_holds_under_flood(tmp_path: Path) -> None:
    """A log flood cannot compress history to zero: young files always survive."""
    db = _db(tmp_path)
    journal_dir = tmp_path / "journal"
    young = [_journal_file(journal_dir, _name_for(d), size=2**20) for d in range(1, 6)]
    # 5 MiB of young files against a 1 MiB quota — nothing is deletable.
    result = prune_journal_files(db, journal_dir, now=NOW, days=30, quota_mb=1, floor_days=7)
    assert result.files_deleted == 0
    assert all(p.exists() for p in young)
    assert result.quota_overage_bytes == 4 * 2**20


def test_journal_quota_evicts_oldest_first_and_stops_under_quota(tmp_path: Path) -> None:
    db = _db(tmp_path)
    journal_dir = tmp_path / "journal"
    size = 600 * 1024  # 3 x 600 KiB = 1800 KiB against a 1 MiB quota
    oldest = _journal_file(journal_dir, _name_for(20), size=size)
    middle = _journal_file(journal_dir, _name_for(15), size=size)
    newest = _journal_file(journal_dir, _name_for(10), size=size)
    result = prune_journal_files(db, journal_dir, now=NOW, days=30, quota_mb=1, floor_days=7)
    # Deleting the two oldest gets under quota; the newest survives.
    assert result.files_deleted == 2
    assert not oldest.exists()
    assert not middle.exists()
    assert newest.exists()
    assert result.quota_overage_bytes == 0


def test_journal_quota_never_deletes_critical_day(tmp_path: Path) -> None:
    db = _db(tmp_path)
    journal_dir = tmp_path / "journal"
    critical_day = _journal_file(journal_dir, _name_for(20), size=2**20)
    plain = _journal_file(journal_dir, _name_for(15), size=2**20)
    _seed_alert(db, "crit1", ts=NOW - timedelta(days=20), severity="critical")
    result = prune_journal_files(db, journal_dir, now=NOW, days=30, quota_mb=1, floor_days=7)
    assert critical_day.exists()
    assert not plain.exists()
    assert result.files_deleted == 1
    # The protected file alone fills the quota exactly — no residual overage.
    assert result.quota_overage_bytes == 0


def test_journal_quota_exhaustion_reports_residual_overage(tmp_path: Path) -> None:
    db = _db(tmp_path)
    journal_dir = tmp_path / "journal"
    deletable = _journal_file(journal_dir, _name_for(20), size=2**20)
    protected = _journal_file(journal_dir, _name_for(15), size=2 * 2**20)
    _seed_alert(db, "crit1", ts=NOW - timedelta(days=15), severity="critical")
    result = prune_journal_files(db, journal_dir, now=NOW, days=30, quota_mb=1, floor_days=7)
    assert not deletable.exists()
    assert protected.exists()
    # 2 MiB remain against a 1 MiB quota: reported, not an error.
    assert result.quota_overage_bytes == 2**20


def test_journal_rejects_naive_now(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(ValueError, match="timezone-aware"):
        prune_journal_files(
            db, tmp_path / "journal", now=NAIVE_NOW, days=30, quota_mb=500, floor_days=7
        )


# --- alerts pruner (§5.3) ---


def test_prune_alerts_deletes_old_non_critical(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "old", ts=NOW - timedelta(days=400))
    _seed_alert(db, "fresh", ts=NOW - timedelta(days=1))
    assert prune_alerts(db, now=NOW, days=365) == 1
    assert _alert_ids(db) == {"fresh"}


def test_prune_alerts_recency_not_first_seen(tmp_path: Path) -> None:
    """Dedup keeps one row alive across re-firings: old ts + fresh last_seen_at survives."""
    db = _db(tmp_path)
    _seed_alert(db, "deduped", ts=NOW - timedelta(days=400), last_seen_at=NOW - timedelta(days=1))
    assert prune_alerts(db, now=NOW, days=365) == 0
    assert _alert_ids(db) == {"deduped"}


def test_prune_alerts_critical_survives(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "crit", ts=NOW - timedelta(days=400), severity="critical")
    assert prune_alerts(db, now=NOW, days=365) == 0
    assert _alert_ids(db) == {"crit"}


def test_prune_alerts_attached_to_open_case_survives(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "attached", ts=NOW - timedelta(days=400))
    _seed_case(db, "c1", "attached", status="open")
    assert prune_alerts(db, now=NOW, days=365) == 0
    assert _alert_ids(db) == {"attached"}


def test_prune_alerts_attached_to_closed_case_prunes(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "attached", ts=NOW - timedelta(days=400))
    _seed_case(db, "c1", "attached", status="closed")
    assert prune_alerts(db, now=NOW, days=365) == 1
    assert _alert_ids(db) == set()


def test_prune_alerts_rejects_naive_now(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(ValueError, match="timezone-aware"):
        prune_alerts(db, now=NAIVE_NOW, days=365)


# --- RetentionReport ---


def test_report_no_deletions_by_default() -> None:
    assert RetentionReport().any_deletions is False


@pytest.mark.parametrize(
    "field_name",
    ["events_deleted", "journal_files_deleted", "alerts_deleted", "evidence_blobs_deleted"],
)
def test_report_any_deletions_per_count(field_name: str) -> None:
    report = RetentionReport(**{field_name: 1})
    assert report.any_deletions is True


def test_report_skips_and_overage_are_not_deletions() -> None:
    report = RetentionReport(skipped_files=["junk.jsonl.gz"], quota_overage_bytes=42)
    assert report.any_deletions is False
