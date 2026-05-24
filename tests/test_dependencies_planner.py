"""Tests for the planner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from inspectord.dependencies.distro import Distro
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.dependencies.planner import build_plan, persist_plan
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _FakeRunner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self._scripts = scripts

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self._scripts.get(
            tuple(argv),
            subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b""),
        )


def _missing() -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"not found")


def _present(version: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=f"Name : x\nVersion : {version}\n".encode(), stderr=b""
    )


def test_plan_includes_missing_deps_only(tmp_path: Path) -> None:
    manifests = load_packaged_manifests()
    runner = _FakeRunner(
        {
            ("pacman", "-Qi", "audit"): _missing(),
            ("pacman", "-Qi", "aide"): _present("0.18-1"),
            ("pacman", "-Qi", "yara"): _missing(),
        }
    )
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    names = {item.name for item in plan.items}
    assert "auditd" in names
    assert "yara" in names
    assert "aide" not in names


def test_plan_excludes_verify_only_deps(tmp_path: Path) -> None:
    manifests = load_packaged_manifests()
    runner = _FakeRunner({})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    names = {item.name for item in plan.items}
    assert "libudev" not in names
    assert "ebpf_features" not in names


def test_persist_plan_writes_row(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    manifests = load_packaged_manifests()
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _missing()})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    persist_plan(plan, db_path=db_path)
    with Database(db_path) as db:
        rows = db.query(
            "SELECT plan_id, distro, package_manager, status FROM pending_dep_plans"
        ).fetchall()
    assert rows[0][0] == plan.plan_id
    assert rows[0][1] == "arch"
    assert rows[0][2] == "pacman"
    assert rows[0][3] == "pending"


def test_persist_plan_serialises_items_json(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    manifests = load_packaged_manifests()
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _missing()})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    persist_plan(plan, db_path=db_path)
    with Database(db_path) as db:
        items_json = db.query(
            "SELECT items_json FROM pending_dep_plans WHERE plan_id = ?", [plan.plan_id]
        ).fetchall()[0][0]
    items = json.loads(items_json)
    assert any(i["name"] == "auditd" for i in items)
