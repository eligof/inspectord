"""Tests for the evidence collector (spec §3.5 implicated_paths, §3.6 collector)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from inspectord.evidence import collector as collector_mod
from inspectord.evidence.collector import EvidenceCollector, implicated_paths
from inspectord.evidence.store import ForensicStore
from inspectord.schemas.alert import Alert, EntityRef, RenderedAlert, RuleRef
from inspectord.schemas.event import Event, EventKind, Severity
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db_path(tmp_path: Path) -> Path:
    """Return the path to a freshly migrated database (connection closed)."""
    path = tmp_path / "t.duckdb"
    db = Database(path)
    db.connect()
    run_migrations(db)
    db.close()
    return path


def _seed_alert(db_path: Path, alert_id: str, severity: str, short: str) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
            "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, "
            "payload_json) "
            "VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', ?, 'new', 'auth', 'dk', 1, "
            "TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', ?, 'detail', '{}')",
            [alert_id, severity, short],
        )


def _make_alert(
    *,
    alert_id: str = "a1",
    severity: Severity = Severity.high,
    short: str = "suspicious",
    entities: list[EntityRef] | None = None,
) -> Alert:
    ts = datetime(2026, 6, 20, tzinfo=UTC)
    return Alert(
        alert_id=alert_id,
        rule=RuleRef(
            id="r1",
            name="rule",
            ruleset="rs",
            version="1",
            severity=severity,
            why="because",
        ),
        ts=ts,
        severity=severity,
        category="auth",
        event_ids=["ev-1"],
        entities=entities or [],
        dedup_key="dk",
        first_seen_at=ts,
        last_seen_at=ts,
        rendered=RenderedAlert(short=short, detail="detail"),
    )


def _make_event(
    *,
    event_id: str = "ev-1",
    file: dict | None = None,
    persistence: dict | None = None,
) -> Event:
    return Event(
        ts=datetime(2026, 6, 20, tzinfo=UTC),
        event_id=event_id,
        kind=EventKind.event,
        category=["file"],
        type=["change"],
        action="file_modified",
        severity=Severity.info,
        module="fim_watcher",
        file=file,
        persistence=persistence,
    )


def _fixed_snapshot(*_args: object, **_kwargs: object) -> dict:
    return {"captured_at": "2026-06-20T00:00:00+00:00", "truncated": False, "sockets": []}


# --- implicated_paths ---


def test_implicated_paths_union_and_dedup() -> None:
    alert = _make_alert(
        entities=[
            EntityRef(kind="file", key="/etc/passwd"),
            EntityRef(kind="process", key="1234"),  # ignored (not a file)
            EntityRef(kind="file", key="/etc/sudoers"),  # dup of event.file below
        ]
    )
    event = _make_event(
        file={"path": "/etc/sudoers"},
        persistence={"source_path": "/usr/bin/evil"},
    )
    paths = implicated_paths(alert, event)
    assert paths == ["/etc/sudoers", "/usr/bin/evil", "/etc/passwd"]


def test_implicated_paths_empty_when_none() -> None:
    alert = _make_alert(entities=[EntityRef(kind="process", key="9")])
    event = _make_event()
    assert implicated_paths(alert, event) == []


# --- severity gate ---


def test_severity_gate_low_alert_captures_nothing(tmp_path: Path) -> None:
    db_path = _db_path(tmp_path)
    _seed_alert(db_path, "low-1", "low", "meh")
    store = ForensicStore(tmp_path / "ev")
    collector = EvidenceCollector(db_path, store)
    alert = _make_alert(alert_id="low-1", severity=Severity.low)
    collector.capture(alert, _make_event())
    with Database(db_path) as db:
        assert db.query("SELECT COUNT(*) FROM cases").fetchall()[0][0] == 0
        assert db.query("SELECT COUNT(*) FROM case_evidence").fetchall()[0][0] == 0


# --- idempotent under concurrency ---


def test_idempotent_under_concurrency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collector_mod, "network_snapshot", _fixed_snapshot)
    db_path = _db_path(tmp_path)
    _seed_alert(db_path, "a1", "high", "suspicious")
    store = ForensicStore(tmp_path / "ev")
    collector = EvidenceCollector(db_path, store)
    alert = _make_alert(alert_id="a1")
    event = _make_event()

    barrier = threading.Barrier(2)

    def _run() -> None:
        barrier.wait()
        collector.capture(alert, event)

    threads = [threading.Thread(target=_run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with Database(db_path) as db:
        assert db.query("SELECT COUNT(*) FROM cases").fetchall()[0][0] == 1
        assert (
            db.query("SELECT COUNT(*) FROM case_alert WHERE alert_id = 'a1'").fetchall()[0][0] == 1
        )


# --- net + event_bundle always captured ---


def test_net_and_bundle_always_captured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collector_mod, "network_snapshot", _fixed_snapshot)
    db_path = _db_path(tmp_path)
    _seed_alert(db_path, "a1", "high", "suspicious")
    store = ForensicStore(tmp_path / "ev")
    collector = EvidenceCollector(db_path, store)
    collector.capture(_make_alert(alert_id="a1"), _make_event())

    with Database(db_path) as db:
        assert db.query("SELECT COUNT(*) FROM cases").fetchall()[0][0] == 1
        kinds = {r[0] for r in db.query("SELECT kind FROM case_evidence").fetchall()}
        assert "net_state" in kinds
        assert "event_bundle" in kinds


# --- file capture ---


def test_file_capture_and_missing_path_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collector_mod, "network_snapshot", _fixed_snapshot)
    db_path = _db_path(tmp_path)
    _seed_alert(db_path, "a1", "high", "suspicious")
    store = ForensicStore(tmp_path / "ev")
    collector = EvidenceCollector(db_path, store)

    target = tmp_path / "evil.bin"
    target.write_bytes(b"malware bytes")

    alert = _make_alert(
        alert_id="a1",
        entities=[EntityRef(kind="file", key=str(tmp_path / "does-not-exist"))],
    )
    event = _make_event(file={"path": str(target)})
    collector.capture(alert, event)

    with Database(db_path) as db:
        files = db.query(
            "SELECT original_path, sha256 FROM case_evidence WHERE kind = 'file'"
        ).fetchall()
        assert len(files) == 1
        assert files[0][0] == str(target)
        sha = files[0][1]
        # blob is in the store
        assert store.path_for(sha).exists()
        # net + bundle still captured despite the missing path
        kinds = {r[0] for r in db.query("SELECT kind FROM case_evidence").fetchall()}
        assert "net_state" in kinds
        assert "event_bundle" in kinds


# --- bounds ---


def test_bounds_partial_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collector_mod, "network_snapshot", _fixed_snapshot)
    monkeypatch.setattr(collector_mod, "_MAX_FILES", 1)
    db_path = _db_path(tmp_path)
    _seed_alert(db_path, "a1", "high", "suspicious")
    store = ForensicStore(tmp_path / "ev")
    collector = EvidenceCollector(db_path, store)

    f1 = tmp_path / "one.bin"
    f1.write_bytes(b"first")
    f2 = tmp_path / "two.bin"
    f2.write_bytes(b"second")

    alert = _make_alert(
        alert_id="a1",
        entities=[
            EntityRef(kind="file", key=str(f1)),
            EntityRef(kind="file", key=str(f2)),
        ],
    )
    collector.capture(alert, _make_event())

    with Database(db_path) as db:
        files = db.query("SELECT COUNT(*) FROM case_evidence WHERE kind = 'file'").fetchall()[0][0]
        assert files == 1
        texts = db.query("SELECT text FROM case_event WHERE kind = 'evidence_captured'").fetchall()
        assert len(texts) == 1
        assert "partial" in texts[0][0]


# --- timeline ---


def test_timeline_evidence_captured_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collector_mod, "network_snapshot", _fixed_snapshot)
    db_path = _db_path(tmp_path)
    _seed_alert(db_path, "a1", "high", "suspicious")
    store = ForensicStore(tmp_path / "ev")
    collector = EvidenceCollector(db_path, store)
    collector.capture(_make_alert(alert_id="a1"), _make_event())

    with Database(db_path) as db:
        rows = db.query(
            "SELECT COUNT(*) FROM case_event WHERE kind = 'evidence_captured'"
        ).fetchall()
        assert rows[0][0] == 1
