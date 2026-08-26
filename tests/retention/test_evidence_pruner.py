"""Evidence-blob pruner (retention spec §5.4): protection rules, tombstones, lock."""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.evidence.collector import EvidenceCollector
from inspectord.evidence.store import ForensicStore
from inspectord.retention.engine import prune_evidence
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
OLD = NOW - timedelta(days=400)
SHA = "ab" * 32


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_alert(db: Database, alert_id: str, *, severity: str = "medium") -> None:
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
        "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
        "VALUES (?, 'r1', ?, ?, 'new', 'auth', ?, 1, ?, ?, 'short', 'detail', '{}')",
        [alert_id, OLD, severity, f"dk-{alert_id}", OLD, OLD],
    )


def _seed_case(db: Database, case_id: str, *, status: str, alert_id: str | None = None) -> None:
    db.execute(
        "INSERT INTO cases (case_id, title, status, opened_at) "
        "VALUES (?, 't', ?, TIMESTAMP '2026-01-01 00:00:00')",
        [case_id, status],
    )
    if alert_id is not None:
        _seed_alert(db, alert_id)
        db.execute(
            "INSERT INTO case_alert (case_id, alert_id, attached_at) "
            "VALUES (?, ?, TIMESTAMP '2026-01-01 00:00:00')",
            [case_id, alert_id],
        )


def _attach_critical(db: Database, case_id: str, alert_id: str) -> None:
    _seed_alert(db, alert_id, severity="critical")
    db.execute(
        "INSERT INTO case_alert (case_id, alert_id, attached_at) "
        "VALUES (?, ?, TIMESTAMP '2026-01-01 00:00:00')",
        [case_id, alert_id],
    )


def _seed_evidence(
    db: Database,
    case_id: str,
    sha: str,
    *,
    captured_at: datetime = OLD,
    meta_json: str | None = '{"alert_id": "a1"}',
) -> None:
    db.execute(
        "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, meta_json) "
        "VALUES (?, 'file', ?, '', ?, ?)",
        [case_id, sha, captured_at, meta_json],
    )


def _blob(root: Path, sha: str) -> Path:
    path = root / sha[:2] / sha
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"blob")
    return path


def _meta(db: Database, sha: str) -> list[dict[str, object]]:
    rows = db.query("SELECT meta_json FROM case_evidence WHERE sha256 = ?", [sha]).fetchall()
    return [json.loads(r[0]) if r[0] else {} for r in rows]


# --- capture lock exposure ---


def test_collector_capture_lock_property(tmp_path: Path) -> None:
    collector = EvidenceCollector(tmp_path / "t.duckdb", ForensicStore(tmp_path / "ev"))
    assert collector.capture_lock is collector._lock


# --- protection rules (§4.2) + tombstone stamping ---


def test_prunes_old_blob_of_closed_noncritical_case(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_evidence(db, "c1", SHA)
    blob = _blob(root, SHA)
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 1
    assert result.pruned_shas == [SHA]
    assert not blob.exists()
    (meta,) = _meta(db, SHA)
    assert meta["pruned_by"] == "auto:retention"
    assert isinstance(meta["pruned_at"], str) and meta["pruned_at"]
    assert meta["alert_id"] == "a1"  # original meta preserved through the merge


def test_prune_removes_emptied_shard_dir(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_evidence(db, "c1", SHA)
    _blob(root, SHA)
    prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert not (root / SHA[:2]).exists()


def test_open_case_blob_survives_unstamped(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="open", alert_id="a1")
    _seed_evidence(db, "c1", SHA)
    blob = _blob(root, SHA)
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 0
    assert result.pruned_shas == []
    assert blob.exists()
    (meta,) = _meta(db, SHA)
    assert "pruned_at" not in meta


def test_any_open_referencing_case_protects_shared_blob(tmp_path: Path) -> None:
    """Prunable only if EVERY referencing case is closed."""
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_case(db, "c2", status="open", alert_id="a2")
    _seed_evidence(db, "c1", SHA)
    _seed_evidence(db, "c2", SHA)
    blob = _blob(root, SHA)
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 0
    assert blob.exists()


def test_critical_case_blob_survives(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _attach_critical(db, "c1", "crit1")
    _seed_evidence(db, "c1", SHA)
    blob = _blob(root, SHA)
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 0
    assert blob.exists()
    (meta,) = _meta(db, SHA)
    assert "pruned_at" not in meta


def test_younger_row_for_same_sha_protects_blob(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_case(db, "c2", status="closed", alert_id="a2")
    _seed_evidence(db, "c1", SHA)
    _seed_evidence(db, "c2", SHA, captured_at=NOW - timedelta(days=1))
    blob = _blob(root, SHA)
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 0
    assert blob.exists()


def test_all_tombstone_rows_for_sha_stamped_blob_counted_once(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_case(db, "c2", status="closed", alert_id="a2")
    _seed_evidence(db, "c1", SHA)
    _seed_evidence(db, "c2", SHA)
    _blob(root, SHA)
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 1
    assert result.pruned_shas == [SHA]
    metas = _meta(db, SHA)
    assert len(metas) == 2
    assert all(m.get("pruned_by") == "auto:retention" for m in metas)


def test_second_run_over_stamped_tombstones_counts_nothing(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_evidence(db, "c1", SHA)
    _blob(root, SHA)
    first = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert first.blobs_deleted == 1
    second = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert second.blobs_deleted == 0
    assert second.pruned_shas == []


def test_missing_blob_stamped_but_not_counted(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_evidence(db, "c1", SHA, meta_json=None)  # NULL meta must still be a candidate
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 0
    assert result.pruned_shas == []
    (meta,) = _meta(db, SHA)
    assert meta["pruned_at"]
    assert meta["pruned_by"] == "auto:retention"


# --- .tmp-* debris sweep (§5.4) ---


def test_tmp_debris_older_than_a_day_swept_fresh_kept(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    (root / "ab").mkdir(parents=True)
    stale = root / "ab" / ".tmp-stale"
    stale.write_bytes(b"x")
    two_days_ago = time.time() - 2 * 86400
    os.utime(stale, (two_days_ago, two_days_ago))
    fresh = root / "ab" / ".tmp-fresh"
    fresh.write_bytes(b"x")
    result = prune_evidence(db, root, now=NOW, days=365, capture_lock=None)
    assert result.blobs_deleted == 0
    assert not stale.exists()
    assert fresh.exists()


# --- concurrency + input guards ---


def test_pruner_blocks_while_capture_lock_held(tmp_path: Path) -> None:
    db = _db(tmp_path)
    root = tmp_path / "ev"
    _seed_case(db, "c1", status="closed", alert_id="a1")
    _seed_evidence(db, "c1", SHA)
    blob = _blob(root, SHA)
    lock = threading.Lock()
    done = threading.Event()

    def run() -> None:
        prune_evidence(db, root, now=NOW, days=365, capture_lock=lock)
        done.set()

    with lock:
        thread = threading.Thread(target=run)
        thread.start()
        assert not done.wait(0.3)  # the whole body waits on the capture lock
        assert blob.exists()
    assert done.wait(5.0)
    thread.join(timeout=5.0)
    assert not blob.exists()


def test_prune_evidence_rejects_naive_now(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(ValueError, match="timezone-aware"):
        prune_evidence(
            db, tmp_path / "ev", now=NOW.replace(tzinfo=None), days=365, capture_lock=None
        )
