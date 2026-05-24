"""Tests for the privileged pkg-helper module."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.dependencies.pkg_helper import HelperResult, PkgHelperError, run_helper
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _FakeRunner:
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
        return self._scripts.get(
            key,
            subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"unscripted"),
        )


def _ok(code: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=b"", stderr=b"")


_AUDIT_PLAN = "01910000-0000-7000-8000-000000000001"
_AUDIT_ITEMS = [
    {
        "name": "auditd",
        "action": "install",
        "packages": ["audit"],
        "expected_command": "pacman -S --noconfirm --needed audit",
        "config_dropin": None,
        "service_actions": [],
        "permission_actions": [],
        "post_install_hooks": [],
    }
]


def _insert_plan(
    db: Database,
    *,
    plan_id: str,
    items: list[dict[str, object]],
    expires_in_hours: int = 1,
    distro: str = "arch",
    pm: str = "pacman",
    status: str = "pending",
) -> None:
    created = datetime.now(UTC)
    expires = created + timedelta(hours=expires_in_hours)
    db.execute(
        "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
        "package_manager, items_json, estimated_disk_mb, expires_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [plan_id, created, "eli@local", distro, pm, json.dumps(items), 0, expires, status],
    )


def test_helper_refuses_unknown_plan(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    runner = _FakeRunner({})
    with pytest.raises(PkgHelperError):
        run_helper(plan_id="00000000-0000-0000-0000-000000000000", db_path=db_path, runner=runner)


def test_helper_refuses_expired_plan(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS, expires_in_hours=-1)
    with pytest.raises(PkgHelperError):
        run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=_FakeRunner({}))


def test_helper_refuses_wrong_distro_under_pacman(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS, distro="debian")
    with pytest.raises(PkgHelperError):
        run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=_FakeRunner({}))


def test_helper_refuses_package_not_in_manifest(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    bad = [{**_AUDIT_ITEMS[0], "name": "evil", "packages": ["malware"]}]
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=bad)
    with pytest.raises(PkgHelperError):
        run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=_FakeRunner({}))


def test_helper_invokes_pacman_for_valid_plan(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS)
    runner = _FakeRunner(
        {
            ("pacman", "-Sy"): _ok(),
            ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
        }
    )
    result = run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=runner)
    assert isinstance(result, HelperResult)
    assert result.exit_code == 0
    assert ("pacman", "-S", "--noconfirm", "--needed", "audit") in runner.calls


def test_helper_marks_plan_applied(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS)
    runner = _FakeRunner(
        {
            ("pacman", "-Sy"): _ok(),
            ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
        }
    )
    run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=runner)
    with Database(db_path) as db:
        row = db.query(
            "SELECT status FROM pending_dep_plans WHERE plan_id = ?", [_AUDIT_PLAN]
        ).fetchall()[0][0]
    assert row == "applied"


def test_helper_records_audit_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS)
    runner = _FakeRunner(
        {
            ("pacman", "-Sy"): _ok(),
            ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
        }
    )
    run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=runner)
    with Database(db_path) as db:
        actions = {
            r[0]
            for r in db.query(
                "SELECT action FROM dep_audit WHERE plan_id = ?", [_AUDIT_PLAN]
            ).fetchall()
        }
    assert "plan_applied" in actions
    assert "install" in actions
