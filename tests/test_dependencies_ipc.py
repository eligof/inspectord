"""Tests for deps IPC handlers."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from inspectord.dependencies import distro as distro_mod
from inspectord.dependencies.ipc_handlers import (
    handle_apply_dependency_plan,
    handle_get_dep_audit,
    handle_list_dependencies,
    handle_plan_dependency_install,
)
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
        return self._scripts.get(
            key,
            subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"active\n", stderr=b""),
        )


def _present(version: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=f"Name : x\nVersion : {version}\n".encode(), stderr=b""
    )


def _missing() -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"")


def test_handle_list_dependencies(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    runner = _Runner(
        {
            ("pacman", "-Qi", "audit"): _present("3.1.5-1"),
            ("pacman", "-Qi", "aide"): _missing(),
            ("pacman", "-Qi", "yara"): _present("4.5.0-1"),
        }
    )
    result = handle_list_dependencies(
        params={},
        manifests=load_packaged_manifests(),
        backend=PacmanBackend(runner=runner),
        db_path=db_path,
    )
    names = {d["name"] for d in result["dependencies"]}
    assert {"auditd", "aide", "yara"} <= names
    audit = next(d for d in result["dependencies"] if d["name"] == "auditd")
    assert audit["installed"] is True
    assert audit["installed_version"] == "3.1.5-1"


def test_handle_plan_returns_plan_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    runner = _Runner(
        {
            ("pacman", "-Qi", "audit"): _missing(),
            ("pacman", "-Qi", "aide"): _missing(),
            ("pacman", "-Qi", "yara"): _missing(),
        }
    )
    # detect_distro reads /etc/os-release; force arch-family content via monkeypatch.
    monkeypatch.setattr(distro_mod, "detect_distro", lambda **kwargs: distro_mod.Distro.arch)

    result = handle_plan_dependency_install(
        params={"profile": "minimal", "flags": [], "actor": "eli@local"},
        manifests=load_packaged_manifests(),
        backend=PacmanBackend(runner=runner),
        db_path=db_path,
    )
    assert "plan_id" in result
    with Database(db_path) as db:
        rows = db.query(
            "SELECT plan_id FROM pending_dep_plans WHERE plan_id = ?", [result["plan_id"]]
        ).fetchall()
    assert rows


def test_handle_get_dep_audit_empty(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    result = handle_get_dep_audit(params={"target": "auditd"}, db_path=db_path)
    assert result["entries"] == []


def test_handle_apply_dependency_plan_invokes_applier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    _ok = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
    runner = _Runner(
        {
            ("pacman", "-Qi", "audit"): _missing(),
            ("pacman", "-Qi", "aide"): _missing(),
            ("pacman", "-Qi", "yara"): _missing(),
            ("pacman", "-Sy"): _ok,
            ("pacman", "-S", "--noconfirm", "--needed", "audit", "aide", "yara"): _ok,
            ("systemctl", "enable", "--now", "auditd.service"): _ok,
            ("systemctl", "enable", "--now", "systemd-journald.service"): _ok,
            ("systemctl", "is-active", "auditd.service"): subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"active\n", stderr=b""
            ),
            ("systemctl", "is-active", "systemd-journald.service"): subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"active\n", stderr=b""
            ),
            ("aide", "--version"): subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"Aide 0.18", stderr=b""
            ),
            ("yara", "--version"): subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"4.5.0", stderr=b""
            ),
        }
    )
    backend = PacmanBackend(
        runner=runner,
        lock_path=tmp_path / "absent.lck",
        helper_command=["__in_process__"],
        db_path=db_path,
    )
    monkeypatch.setattr(distro_mod, "detect_distro", lambda **kwargs: distro_mod.Distro.arch)

    plan_result = handle_plan_dependency_install(
        params={"profile": "minimal", "flags": [], "actor": "eli@local"},
        manifests=load_packaged_manifests(),
        backend=backend,
        db_path=db_path,
    )
    sidecar_dirs = {
        "auditd": tmp_path / "etc" / "audit" / "rules.d",
        "journald": tmp_path / "etc" / "systemd" / "journald.conf.d",
    }
    for d in sidecar_dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    apply_result = handle_apply_dependency_plan(
        params={"plan_id": plan_result["plan_id"]},
        manifests=load_packaged_manifests(),
        backend=backend,
        runner=runner,
        db_path=db_path,
        sidecar_dirs=sidecar_dirs,
        chown=False,
    )
    assert apply_result["ok"] is True
