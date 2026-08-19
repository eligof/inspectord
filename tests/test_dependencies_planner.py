"""Tests for the planner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from inspectord.dependencies.distro import Distro
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.dependencies.planner import build_plan, persist_plan
from inspectord.dependencies.schemas import DependencyManifest
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


def _manifest(
    name: str,
    *,
    packages: list[str],
    manual: dict[str, str] | None = None,
) -> DependencyManifest:
    """A minimal required-on-`minimal` manifest for planner tests."""
    data: dict[str, object] = {
        "name": name,
        "description": f"{name} — planner test manifest",
        "required_when": {"profiles": ["minimal"]},
        "distro_packages": {"arch": packages},
        "verify": {
            "binary_paths": [f"/usr/bin/{name}"],
            "health_probe": {"kind": "binary_exists_and_runs"},
        },
    }
    if manual is not None:
        data["manual_install"] = manual
    return DependencyManifest.model_validate(data)


_MANUAL = {
    "reason": "only packaged in the AUR",
    "instructions": "install it yourself with an AUR helper, e.g. `paru -S widget`",
}


def test_plan_marks_manual_only_dep_as_manual(tmp_path: Path) -> None:
    """A required, not-auto-installable, missing dep surfaces as an inert manual item."""
    manifests = {"widget": _manifest("widget", packages=["widget"], manual=_MANUAL)}
    runner = _FakeRunner({("pacman", "-Qi", "widget"): _missing()})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    assert len(plan.items) == 1
    item = plan.items[0]
    assert item.name == "widget"
    assert item.action == "manual"
    # No packages and no command: the applier must never try to install this.
    assert item.packages == []
    assert item.expected_command is None
    assert item.manual_reason == _MANUAL["reason"]
    assert item.manual_instructions == _MANUAL["instructions"]


def test_plan_omits_manual_dep_that_is_already_installed(tmp_path: Path) -> None:
    """An AUR-installed package still lands in the pacman DB, so detection must win."""
    manifests = {"widget": _manifest("widget", packages=["widget"], manual=_MANUAL)}
    runner = _FakeRunner({("pacman", "-Qi", "widget"): _present("1.2.3-1")})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    assert plan.items == []


def test_plan_leaves_repo_installable_dep_unaffected(tmp_path: Path) -> None:
    manifests = {"widget": _manifest("widget", packages=["widget"])}
    runner = _FakeRunner({("pacman", "-Qi", "widget"): _missing()})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    assert len(plan.items) == 1
    item = plan.items[0]
    assert item.action == "install"
    assert item.packages == ["widget"]
    assert item.expected_command == "pacman install widget"
    assert item.manual_reason is None
    assert item.manual_instructions is None


def test_plan_surfaces_manual_dep_with_no_package_name(tmp_path: Path) -> None:
    """Nothing to detect with is not a reason to hide a required dependency."""
    manifests = {"widget": _manifest("widget", packages=[], manual=_MANUAL)}
    backend = PacmanBackend(runner=_FakeRunner({}), lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    assert [i.action for i in plan.items] == ["manual"]


def test_aide_is_planned_as_manual_when_missing(tmp_path: Path) -> None:
    """Regression: `pacman -S aide` fails — aide is AUR-only, never auto-installed."""
    manifests = load_packaged_manifests()
    runner = _FakeRunner(
        {
            ("pacman", "-Qi", "audit"): _present("3.1.5-1"),
            ("pacman", "-Qi", "aide"): _missing(),
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
    aide = next(i for i in plan.items if i.name == "aide")
    assert aide.action == "manual"
    assert aide.packages == []
    assert aide.manual_instructions
    # yara really is in the official repos and must still be auto-installable.
    yara = next(i for i in plan.items if i.name == "yara")
    assert yara.action == "install"
    assert yara.packages == ["yara"]
