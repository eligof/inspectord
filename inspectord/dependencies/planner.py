"""Planner — builds a DependencyPlan and persists it to pending_dep_plans."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.dependencies.audit import log_dep_action
from inspectord.dependencies.backend import PackageBackend
from inspectord.dependencies.distro import Distro
from inspectord.dependencies.schemas import (
    DependencyManifest,
    DependencyPlan,
    DependencyPlanItem,
)
from inspectord.ids import uuid7
from inspectord.storage.db import Database

_PLAN_TTL = timedelta(hours=1)


def _is_required(manifest: DependencyManifest, profile: str, flags: set[str]) -> bool:
    if profile in manifest.required_when.profiles:
        if not manifest.required_when.flags:
            return True
        return any(flag in flags for flag in manifest.required_when.flags)
    return False


def _packages_for(distro: Distro, manifest: DependencyManifest) -> list[str]:
    return list(manifest.distro_packages.get(distro.value, []))


def build_plan(
    *,
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    distro: Distro,
    profile: str,
    flags: set[str],
    created_by: str,
) -> DependencyPlan:
    items: list[DependencyPlanItem] = []
    for name, manifest in sorted(manifests.items()):
        if not _is_required(manifest, profile, flags):
            continue
        packages = _packages_for(distro, manifest)
        if not packages:
            continue
        missing = [pkg for pkg in packages if not backend.is_installed(pkg)]
        if not missing:
            continue
        config_dropin: str | None = None
        if manifest.config and manifest.config.dropin and manifest.config.include_dir:
            config_dropin = f"{manifest.config.include_dir}{manifest.config.dropin.filename}"
        service_actions: list[str] = []
        if manifest.service and manifest.service.enable:
            service_actions = [f"systemctl enable --now {manifest.service.systemd_unit}"]
        items.append(
            DependencyPlanItem(
                name=name,
                action="install",
                packages=missing,
                expected_command=f"{backend.name} install {' '.join(missing)}",
                config_dropin=config_dropin,
                service_actions=service_actions,
                permission_actions=[],
                post_install_hooks=[" ".join(h.command) for h in manifest.post_install_hooks],
            )
        )

    created_at = datetime.now(UTC)
    return DependencyPlan(
        plan_id=str(uuid7()),
        created_at=created_at,
        created_by=created_by,
        distro=distro.value,
        package_manager=backend.name,
        items=items,
        estimated_disk_mb=0,
        expires_at=created_at + _PLAN_TTL,
    )


def persist_plan(plan: DependencyPlan, *, db_path: Path) -> None:
    items_json = json.dumps([item.model_dump(mode="json") for item in plan.items])
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
            "package_manager, items_json, estimated_disk_mb, expires_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            [
                plan.plan_id,
                plan.created_at,
                plan.created_by,
                plan.distro,
                plan.package_manager,
                items_json,
                plan.estimated_disk_mb,
                plan.expires_at,
            ],
        )
    log_dep_action(
        db_path=db_path,
        actor=plan.created_by,
        action="plan_created",
        plan_id=plan.plan_id,
    )
