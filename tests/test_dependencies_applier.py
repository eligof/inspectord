"""Tests for the plan applier."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.dependencies.applier import ApplierResult, apply_plan
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _Runner:
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


_PLAN_ID = "01930000-0000-7000-8000-000000000003"


def _seed_plan(db_path: Path) -> None:
    with Database(db_path) as db:
        run_migrations(db)
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


def test_apply_plan_installs_and_drops_config(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
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
    manifests = load_packaged_manifests()
    result = apply_plan(
        plan_id=_PLAN_ID,
        db_path=db_path,
        manifests=manifests,
        backend=backend,
        runner=runner,
        sidecar_dirs={"auditd": sidecar_root},
        chown=False,
    )
    assert isinstance(result, ApplierResult)
    assert result.ok is True
    assert (sidecar_root / "inspectord.rules").exists()
    assert ("systemctl", "enable", "--now", "auditd.service") in runner.calls


def test_apply_plan_records_audit_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
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
    apply_plan(
        plan_id=_PLAN_ID,
        db_path=db_path,
        manifests=load_packaged_manifests(),
        backend=backend,
        runner=runner,
        sidecar_dirs={"auditd": sidecar_root},
        chown=False,
    )
    with Database(db_path) as db:
        actions = {
            r[0]
            for r in db.query(
                "SELECT action FROM dep_audit WHERE plan_id = ?", [_PLAN_ID]
            ).fetchall()
        }
    assert "dropin_written" in actions
    assert "service_action" in actions
    assert "verify_pass" in actions or "verify_fail" in actions


def test_apply_plan_install_failure_skips_dropin(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_plan(db_path)
    sidecar_root = tmp_path / "etc" / "audit" / "rules.d"
    sidecar_root.mkdir(parents=True)
    runner = _Runner(
        {
            ("pacman", "-Sy"): _ok(),
            ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(code=1, err=b"boom"),
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
    assert result.ok is False
    assert not (sidecar_root / "inspectord.rules").exists()


_MANUAL_PLAN_ID = "01930000-0000-7000-8000-000000000004"


def _seed_manual_plan(db_path: Path) -> None:
    """A plan whose single item is a manual (not auto-installable) dependency."""
    with Database(db_path) as db:
        run_migrations(db)
        created = datetime.now(UTC)
        items = [
            {
                "name": "aide",
                "action": "manual",
                "packages": [],
                "expected_command": None,
                "config_dropin": None,
                "service_actions": [],
                "permission_actions": [],
                "post_install_hooks": [],
                "manual_reason": "AUR-only",
                "manual_instructions": "paru -S aide",
            }
        ]
        db.execute(
            "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
            "package_manager, items_json, estimated_disk_mb, expires_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                _MANUAL_PLAN_ID,
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


def test_apply_plan_never_installs_or_marks_a_manual_item(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_manual_plan(db_path)
    runner = _Runner({})
    backend = PacmanBackend(
        runner=runner,
        lock_path=tmp_path / "absent.lck",
        helper_command=["__in_process__"],
        db_path=db_path,
    )
    result = apply_plan(
        plan_id=_MANUAL_PLAN_ID,
        db_path=db_path,
        manifests=load_packaged_manifests(),
        backend=backend,
        runner=runner,
        chown=False,
    )
    assert result.ok is True
    assert not any(call[:2] == ("pacman", "-S") for call in runner.calls)
    # It is NOT installed — dep_state must not claim otherwise.
    with Database(db_path) as db:
        rows = db.query("SELECT name FROM dep_state WHERE name = 'aide'").fetchall()
    assert rows == []
