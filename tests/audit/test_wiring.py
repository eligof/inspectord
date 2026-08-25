"""Every mutating surface writes its audit row (spec 2026-08-25 §5 catalog)."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from inspectord.alerts.ipc_handlers import (
    handle_ack_alert,
    handle_resolve_alert,
    handle_suppress_alert,
)
from inspectord.audit.log import reset_for_tests
from inspectord.cases import ipc_handlers as cases_h
from inspectord.cases import store as cases_store
from inspectord.dependencies.applier import apply_plan
from inspectord.dependencies.distro import Distro
from inspectord.dependencies.ipc_handlers import handle_plan_dependency_install
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.evidence.collector import EvidenceCollector
from inspectord.evidence.store import ForensicStore
from inspectord.hunt.ipc_handlers import handle_delete_hunt_query, handle_save_hunt_query
from inspectord.schemas.alert import Alert, RenderedAlert, RuleRef
from inspectord.schemas.event import Event, EventKind, Severity
from inspectord.state.ipc_handlers import handle_capture_baseline
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def setup_function(_fn) -> None:
    reset_for_tests()  # drop the module connection + counters between tests


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _newest_audit(db_path: Path) -> dict[str, Any] | None:
    with Database(db_path) as db:
        row = db.query(
            "SELECT seq, actor, action, target, details_json "
            "FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    return {
        "seq": row[0],
        "actor": row[1],
        "action": row[2],
        "target": row[3],
        "details": json.loads(row[4]),
    }


def _audit_count(db_path: Path) -> int:
    with Database(db_path) as db:
        return db.query("SELECT COUNT(*) FROM audit_log").fetchone()[0]


def _seed_alert(db_path: Path, alert_id: str, short: str = "sshd brute force") -> None:
    # Mirrors tests/cases/test_ipc_handlers.py::_seed_alert.
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
            "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, "
            "payload_json) VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', 'high', 'new', "
            "'auth', 'dk', 1, TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', "
            "?, 'detail', '{}')",
            [alert_id, short],
        )


# --------------------------------------------------------------------------
# alerts: ack / resolve / suppress
# --------------------------------------------------------------------------


def test_ack_alert_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    assert handle_ack_alert(params={"alert_id": "a1"}, db_path=db_path)["ok"] is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "alert_acked",
        "alert:a1",
        "user:local",
    )
    assert row["details"] == {}


def test_resolve_alert_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    assert handle_resolve_alert(params={"alert_id": "a1"}, db_path=db_path)["ok"] is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "alert_resolved",
        "alert:a1",
        "user:local",
    )
    assert row["details"] == {}


def test_suppress_alert_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    assert handle_suppress_alert(params={"alert_id": "a1"}, db_path=db_path)["ok"] is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "alert_suppressed",
        "alert:a1",
        "user:local",
    )
    assert row["details"] == {}


def test_failed_ack_writes_no_audit_row(tmp_path: Path) -> None:
    """Negative: a failed handler call must write NO row (spec §1: success only)."""
    db_path = _fresh(tmp_path)
    result = handle_ack_alert(params={"alert_id": "missing"}, db_path=db_path)
    assert result["ok"] is False
    assert _audit_count(db_path) == 0


# --------------------------------------------------------------------------
# cases: open / attach / note / close / export / download
# --------------------------------------------------------------------------


def test_open_case_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1", short="sshd brute force")
    case_id = cases_h.handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "case_opened",
        f"case:{case_id}",
        "user:local",
    )
    assert row["details"] == {"title": "sshd brute force"}


def test_attach_alert_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    _seed_alert(db_path, "a2")
    case_id = cases_h.handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    cases_h.handle_attach_alert(params={"case_id": case_id, "alert_id": "a2"}, db_path=db_path)
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "case_alert_attached",
        f"case:{case_id}",
        "user:local",
    )
    assert row["details"] == {"alert_id": "a2"}


def test_add_note_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    case_id = cases_h.handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    cases_h.handle_add_note(params={"case_id": case_id, "text": "secret note"}, db_path=db_path)
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "case_note_added",
        f"case:{case_id}",
        "user:local",
    )
    assert row["details"] == {}  # note text stays in case_event, not the audit log


def test_close_case_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    case_id = cases_h.handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    cases_h.handle_close_case(params={"case_id": case_id}, db_path=db_path)
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "case_closed",
        f"case:{case_id}",
        "user:local",
    )
    assert row["details"] == {}


def _seed_case_with_evidence(db_path: Path, evidence_dir: Path) -> tuple[str, str]:
    # Mirrors tests/cases/test_ipc_handlers.py::_seed_case_with_evidence.
    fstore = ForensicStore(evidence_dir)
    _seed_alert(db_path, "a1")
    with Database(db_path) as db:
        case_id = cases_store.open_case(db, alert_id="a1")
        sha = fstore.put(b"payload")
        db.execute(
            "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, "
            "meta_json) VALUES (?, 'file', ?, '/etc/x', TIMESTAMP '2026-06-20 00:00:00', '{}')",
            [case_id, sha],
        )
    return case_id, sha


def test_export_case_zip_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    case_id, _sha = _seed_case_with_evidence(db_path, tmp_path / "evidence")
    resp = cases_h.handle_export_case_zip(
        params={"case_id": case_id}, db_path=db_path, evidence_dir=tmp_path / "evidence"
    )
    assert resp["ok"] is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "case_exported",
        f"case:{case_id}",
        "user:local",
    )
    assert isinstance(row["details"]["bytes"], int) and row["details"]["bytes"] > 0


def test_export_case_zip_not_found_writes_no_row(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    resp = cases_h.handle_export_case_zip(
        params={"case_id": "nope"}, db_path=db_path, evidence_dir=tmp_path / "evidence"
    )
    assert resp["ok"] is False
    assert _audit_count(db_path) == 0


def test_download_evidence_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    case_id, sha = _seed_case_with_evidence(db_path, tmp_path / "evidence")
    resp = cases_h.handle_download_evidence(
        params={"case_id": case_id, "sha": sha},
        db_path=db_path,
        evidence_dir=tmp_path / "evidence",
    )
    assert resp["ok"] is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "evidence_downloaded",
        f"case:{case_id}",
        "user:local",
    )
    assert row["details"] == {"sha256": sha}


# --------------------------------------------------------------------------
# state: capture_baseline
# --------------------------------------------------------------------------


def test_capture_baseline_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    result = handle_capture_baseline(params={"kind": "service"}, db_path=db_path)
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "baseline_captured",
        "baseline:service",
        "user:local",
    )
    assert row["details"] == {"entries": result["captured"]}


# --------------------------------------------------------------------------
# hunt: save / delete
# --------------------------------------------------------------------------


def test_save_hunt_query_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    resp = handle_save_hunt_query(
        params={"name": "curl-runs", "expression": 'process.name == "curl"'},
        db_path=db_path,
    )
    assert resp["ok"] is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "hunt_query_saved",
        "hunt:curl-runs",
        "user:local",
    )
    assert row["details"] == {}


def test_delete_hunt_query_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    handle_save_hunt_query(
        params={"name": "curl-runs", "expression": 'process.name == "curl"'},
        db_path=db_path,
    )
    resp = handle_delete_hunt_query(params={"name": "curl-runs"}, db_path=db_path)
    assert resp["ok"] is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "hunt_query_deleted",
        "hunt:curl-runs",
        "user:local",
    )
    assert row["details"] == {}


# --------------------------------------------------------------------------
# dependencies: plan + apply
# --------------------------------------------------------------------------


class _Runner:
    # Mirrors tests/test_dependencies_applier.py::_Runner.
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._scripts = scripts

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        key = tuple(argv)
        self.calls.append(key)
        default = subprocess.CompletedProcess(
            args=argv, returncode=0, stdout=b"active\n", stderr=b""
        )
        return self._scripts.get(key, default)


def _ok(code: int = 0, out: bytes = b"", err: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr=err)


def _missing() -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"")


def test_plan_dependency_install_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = _fresh(tmp_path)
    runner = _Runner(
        {
            ("pacman", "-Qi", "audit"): _missing(),
            ("pacman", "-Qi", "aide"): _missing(),
            ("pacman", "-Qi", "yara"): _missing(),
        }
    )
    monkeypatch.setattr("inspectord.dependencies.ipc_handlers.detect_distro", lambda: Distro.arch)
    result = handle_plan_dependency_install(
        params={"profile": "minimal", "flags": []},
        manifests=load_packaged_manifests(),
        backend=PacmanBackend(runner=runner),
        db_path=db_path,
    )
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["actor"]) == ("dep_plan_created", "user:local")
    assert row["target"] is not None and row["target"].startswith("dep:")
    assert row["details"] == {"plan_id": result["plan_id"]}


_PLAN_ID = "01930000-0000-7000-8000-000000000003"


def _seed_plan(db_path: Path) -> None:
    # Mirrors tests/test_dependencies_applier.py::_seed_plan (single auditd item).
    with Database(db_path) as db:
        created = datetime.now(UTC)
        items = [
            {
                "name": "auditd",
                "action": "install",
                "packages": ["audit"],
                "expected_command": "pacman install audit",
                "config_dropin": None,
                "service_actions": ["systemctl enable --now auditd.service"],
                "permission_actions": [],
                "post_install_hooks": [],
            }
        ]
        db.execute(
            "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
            "package_manager, items_json, estimated_disk_mb, expires_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                _PLAN_ID,
                created,
                "test",
                "arch",
                "pacman",
                json.dumps(items),
                0,
                created + timedelta(hours=1),
                "pending",
            ],
        )


def test_apply_plan_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_plan(db_path)
    sidecar_root = tmp_path / "etc" / "audit" / "rules.d"
    sidecar_root.mkdir(parents=True)
    runner = _Runner(
        {
            ("pacman", "-Sy"): _ok(),
            ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
            ("systemctl", "enable", "--now", "auditd.service"): _ok(),
            ("systemctl", "is-active", "auditd.service"): _ok(out=b"active\n"),
        }
    )
    backend = PacmanBackend(
        runner=runner,
        lock_path=tmp_path / "absent.lck",
        helper_command=["__in_process__"],
        db_path=db_path,
    )
    result = apply_plan(
        plan_id=_PLAN_ID,
        db_path=db_path,
        manifests=load_packaged_manifests(),
        backend=backend,
        runner=runner,
        sidecar_dirs={"auditd": sidecar_root},
        chown=False,
    )
    assert result.ok is True
    row = _newest_audit(db_path)
    assert row is not None
    assert (row["action"], row["target"], row["actor"]) == (
        "dep_plan_applied",
        "dep:auditd",
        "user:local",
    )
    assert row["details"] == {"plan_id": _PLAN_ID}


# --------------------------------------------------------------------------
# evidence collector auto-case
# --------------------------------------------------------------------------


def _make_alert(alert_id: str = "a1") -> Alert:
    # Mirrors tests/evidence/test_collector.py::_make_alert.
    ts = datetime(2026, 6, 20, tzinfo=UTC)
    return Alert(
        alert_id=alert_id,
        rule=RuleRef(
            id="r1",
            name="rule",
            ruleset="rs",
            version="1",
            severity=Severity.high,
            why="because",
        ),
        ts=ts,
        severity=Severity.high,
        category="auth",
        event_ids=["ev-1"],
        entities=[],
        dedup_key="dk",
        first_seen_at=ts,
        last_seen_at=ts,
        rendered=RenderedAlert(short="suspicious", detail="detail"),
    )


def _make_event(event_id: str = "ev-1") -> Event:
    return Event(
        ts=datetime(2026, 6, 20, tzinfo=UTC),
        event_id=event_id,
        kind=EventKind.event,
        category=["file"],
        type=["change"],
        action="file_modified",
        severity=Severity.info,
        module="fim_watcher",
    )


def test_evidence_collector_auto_case_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    collector = EvidenceCollector(db_path, ForensicStore(tmp_path / "evidence"))
    collector.capture(_make_alert("a1"), _make_event())
    with Database(db_path) as db:
        case_id = db.query("SELECT case_id FROM case_alert WHERE alert_id = 'a1'").fetchone()[0]
    rows_with_action = [r for r in _all_audit(db_path) if r["action"] == "case_opened"]
    assert len(rows_with_action) == 1
    row = rows_with_action[0]
    assert (row["target"], row["actor"]) == (f"case:{case_id}", "auto:evidence_collector")
    assert row["details"] == {"auto": True, "alert_id": "a1"}


def _all_audit(db_path: Path) -> list[dict[str, Any]]:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT seq, actor, action, target, details_json FROM audit_log ORDER BY seq"
        ).fetchall()
    return [
        {
            "seq": r[0],
            "actor": r[1],
            "action": r[2],
            "target": r[3],
            "details": json.loads(r[4]),
        }
        for r in rows
    ]


# --------------------------------------------------------------------------
# cases: no-ops on a nonexistent case must not be audited
# --------------------------------------------------------------------------


def test_attach_alert_to_missing_case_writes_no_row(tmp_path: Path) -> None:
    """The store silently no-ops on a missing case; an audit row would record a lie."""
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    resp = cases_h.handle_attach_alert(
        params={"case_id": "nope", "alert_id": "a1"}, db_path=db_path
    )
    assert resp["ok"] is True  # handler response semantics unchanged
    assert _audit_count(db_path) == 0


def test_add_note_to_missing_case_writes_no_row(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    resp = cases_h.handle_add_note(params={"case_id": "nope", "text": "n"}, db_path=db_path)
    assert resp["ok"] is True
    assert _audit_count(db_path) == 0


def test_close_missing_case_writes_no_row(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    resp = cases_h.handle_close_case(params={"case_id": "nope"}, db_path=db_path)
    assert resp["ok"] is True
    assert _audit_count(db_path) == 0
