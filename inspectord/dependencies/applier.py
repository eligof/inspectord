"""Applier — orchestrate install + config + verify for a persisted plan."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.audit import log_dep_action
from inspectord.dependencies.backend import PackageBackend
from inspectord.dependencies.probes import ProbeResult, run_probe
from inspectord.dependencies.schemas import DependencyManifest, DependencyPlanItem
from inspectord.dependencies.sidecar import SidecarError, write_sidecar
from inspectord.storage.db import Database


class _Runner(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]: ...


@dataclass
class ApplierResult:
    plan_id: str
    ok: bool
    failed_dep: str | None = None
    notes: list[str] = field(default_factory=list)


def _load_items(db_path: Path, plan_id: str) -> list[DependencyPlanItem]:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT items_json FROM pending_dep_plans WHERE plan_id = ?",
            [plan_id],
        ).fetchall()
    if not rows:
        raise RuntimeError(f"plan not found: {plan_id}")
    return [DependencyPlanItem.model_validate(i) for i in json.loads(rows[0][0])]


def apply_plan(
    *,
    plan_id: str,
    db_path: Path,
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    runner: _Runner,
    sidecar_dirs: dict[str, Path] | None = None,
    chown: bool = True,
) -> ApplierResult:
    sidecar_dirs = dict(sidecar_dirs or {})
    items = _load_items(db_path, plan_id)
    notes: list[str] = []

    install_items = [i for i in items if i.action == "install" and i.packages]
    if install_items:
        all_pkgs = [pkg for i in install_items for pkg in i.packages]
        result = backend.install(all_pkgs, plan_id=plan_id)  # type: ignore[call-arg]
        log_dep_action(
            db_path=db_path,
            actor="applier",
            action="install" if not result.failed else "install_failed",
            plan_id=plan_id,
            command=result.command,
            exit_code=result.exit_code,
            stderr_tail=result.stderr_tail,
        )
        if result.failed:
            return ApplierResult(
                plan_id=plan_id,
                ok=False,
                failed_dep="install",
                notes=[result.stderr_tail],
            )

    for item in items:
        manifest = manifests.get(item.name)
        if manifest is None or manifest.config is None or manifest.config.dropin is None:
            continue
        include_dir = sidecar_dirs.get(item.name) or Path(manifest.config.include_dir or "/")
        try:
            target = write_sidecar(manifest, include_dir=include_dir, chown=chown)
        except SidecarError as exc:
            log_dep_action(
                db_path=db_path,
                actor="applier",
                action="dropin_failed",
                target=item.name,
                plan_id=plan_id,
                stderr_tail=str(exc),
            )
            return ApplierResult(plan_id=plan_id, ok=False, failed_dep=item.name, notes=[str(exc)])
        log_dep_action(
            db_path=db_path,
            actor="applier",
            action="dropin_written",
            target=item.name,
            plan_id=plan_id,
            command=str(target),
        )
        notes.append(f"wrote {target}")

    for item in items:
        for action in item.service_actions:
            argv = action.split()
            result_cp = runner.run(argv)
            log_dep_action(
                db_path=db_path,
                actor="applier",
                action="service_action" if result_cp.returncode == 0 else "service_action_failed",
                target=item.name,
                plan_id=plan_id,
                command=action,
                exit_code=result_cp.returncode,
                stderr_tail=result_cp.stderr.decode("utf-8", "replace"),
            )

    for item in items:
        manifest = manifests.get(item.name)
        if manifest is None:
            continue
        probe: ProbeResult = run_probe(
            manifest.verify.health_probe,
            binary_paths=manifest.verify.binary_paths,
            version_cmd=manifest.verify.version_cmd,
            runner=runner,
        )
        log_dep_action(
            db_path=db_path,
            actor="applier",
            action="verify_pass" if probe.ok else "verify_fail",
            target=item.name,
            plan_id=plan_id,
            stderr_tail=probe.detail,
        )
        installed_version = backend.installed_version(item.packages[0]) if item.packages else None
        dropin_present = item.config_dropin is not None
        now_ts = datetime.now(UTC)
        with Database(db_path) as db:
            db.execute(
                "INSERT INTO dep_state "
                "(name, installed, installed_version, dropin_present, dropin_sha256, "
                "last_verify_ts, last_verify_pass, last_verify_detail, updated_at) "
                "VALUES (?, TRUE, ?, ?, NULL, ?, ?, ?, ?) "
                "ON CONFLICT (name) DO UPDATE SET "
                "installed = excluded.installed, "
                "installed_version = excluded.installed_version, "
                "dropin_present = excluded.dropin_present, "
                "last_verify_ts = excluded.last_verify_ts, "
                "last_verify_pass = excluded.last_verify_pass, "
                "last_verify_detail = excluded.last_verify_detail, "
                "updated_at = excluded.updated_at",
                [
                    item.name,
                    installed_version,
                    dropin_present,
                    now_ts,
                    probe.ok,
                    probe.detail,
                    now_ts,
                ],
            )

    return ApplierResult(plan_id=plan_id, ok=True, notes=notes)
