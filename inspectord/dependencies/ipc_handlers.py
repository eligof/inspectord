"""IPC handlers for the dependency_manager subsystem."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Protocol

from inspectord.dependencies.applier import apply_plan
from inspectord.dependencies.backend import PackageBackend
from inspectord.dependencies.distro import detect_distro
from inspectord.dependencies.planner import build_plan, persist_plan
from inspectord.dependencies.schemas import DependencyManifest
from inspectord.storage.db import Database


class _Runner(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]: ...


def handle_list_dependencies(
    *,
    params: dict[str, Any],
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    db_path: Path,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with Database(db_path) as db:
        state_rows = {
            r[0]: r
            for r in db.query(
                "SELECT name, installed, installed_version, dropin_present, "
                "last_verify_ts, last_verify_pass, last_verify_detail FROM dep_state"
            ).fetchall()
        }
    for name, manifest in sorted(manifests.items()):
        pkgs = manifest.distro_packages.get("arch", [])
        installed: bool | None = all(backend.is_installed(p) for p in pkgs) if pkgs else None
        version: str | None = None
        if pkgs and installed:
            version = backend.installed_version(pkgs[0])
        prior = state_rows.get(name)
        rows.append(
            {
                "name": name,
                "description": manifest.description,
                "required_when_profiles": manifest.required_when.profiles,
                "packages_for_arch": pkgs,
                "installed": installed,
                "installed_version": version,
                "dropin_present": bool(prior[3]) if prior else False,
                "last_verify_ts": prior[4].isoformat() if prior and prior[4] else None,
                "last_verify_pass": prior[5] if prior else None,
                "last_verify_detail": prior[6] if prior else None,
            }
        )
    return {"schema_version": "1.0.0", "dependencies": rows}


def handle_plan_dependency_install(
    *,
    params: dict[str, Any],
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    db_path: Path,
) -> dict[str, Any]:
    profile = str(params.get("profile", "standard"))
    flags = set(params.get("flags", []) or [])
    actor = str(params.get("actor", "ipc"))
    distro = detect_distro()
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=distro,
        profile=profile,
        flags=flags,
        created_by=actor,
    )
    persist_plan(plan, db_path=db_path)
    return {
        "schema_version": "1.0.0",
        "plan_id": plan.plan_id,
        "distro": plan.distro,
        "package_manager": plan.package_manager,
        "items": [item.model_dump(mode="json") for item in plan.items],
        "expires_at": plan.expires_at.isoformat(),
    }


def handle_get_dep_audit(
    *,
    params: dict[str, Any],
    db_path: Path,
) -> dict[str, Any]:
    target = params.get("target")
    with Database(db_path) as db:
        if target:
            rows = db.query(
                "SELECT ts, actor, action, target, plan_id, command, exit_code, stderr_tail "
                "FROM dep_audit WHERE target = ? ORDER BY ts DESC LIMIT 200",
                [target],
            ).fetchall()
        else:
            rows = db.query(
                "SELECT ts, actor, action, target, plan_id, command, exit_code, stderr_tail "
                "FROM dep_audit ORDER BY ts DESC LIMIT 200"
            ).fetchall()
    return {
        "schema_version": "1.0.0",
        "entries": [
            {
                "ts": r[0].isoformat() if r[0] else None,
                "actor": r[1],
                "action": r[2],
                "target": r[3],
                "plan_id": r[4],
                "command": r[5],
                "exit_code": r[6],
                "stderr_tail": r[7],
            }
            for r in rows
        ],
    }


def handle_apply_dependency_plan(
    *,
    params: dict[str, Any],
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    runner: _Runner,
    db_path: Path,
    sidecar_dirs: dict[str, Path] | None = None,
    chown: bool = True,
) -> dict[str, Any]:
    plan_id = str(params.get("plan_id", ""))
    if not plan_id:
        raise ValueError("plan_id required")
    result = apply_plan(
        plan_id=plan_id,
        db_path=db_path,
        manifests=manifests,
        backend=backend,
        runner=runner,
        sidecar_dirs=sidecar_dirs,
        chown=chown,
    )
    return {
        "schema_version": "1.0.0",
        "plan_id": result.plan_id,
        "ok": result.ok,
        "failed_dep": result.failed_dep,
        "notes": result.notes,
    }
