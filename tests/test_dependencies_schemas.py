"""Tests for the dependency_manager Pydantic schemas."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from inspectord.dependencies.schemas import (
    ConfigStrategy,
    DependencyManifest,
    DependencyPlan,
    DependencyPlanItem,
    DependencyState,
    ProbeKind,
)


def _minimal_manifest_dict() -> dict[str, object]:
    return {
        "version": "1.0.0",
        "name": "auditd",
        "description": "Linux audit daemon",
        "required_when": {"profiles": ["minimal", "standard"], "flags": []},
        "optional_when": {"profiles": [], "flags": []},
        "distro_packages": {"arch": ["audit"], "cachyos": ["audit"]},
        "minimum_version": "3.0.0",
        "service": None,
        "config": None,
        "permissions": None,
        "verify": {
            "binary_paths": ["/sbin/auditctl"],
            "version_cmd": ["auditctl", "--version"],
            "version_regex": "auditctl version (\\d+\\.\\d+\\.\\d+)",
            "health_probe": {"kind": "binary_exists_and_runs"},
        },
        "post_install_hooks": [],
        "rollback": {
            "remove_dropin": False,
            "reload_service": False,
            "remove_group_membership": False,
        },
    }


def test_manifest_minimal_validates() -> None:
    m = DependencyManifest.model_validate(_minimal_manifest_dict())
    assert m.name == "auditd"
    assert m.version == "1.0.0"


def test_manifest_unknown_strategy_rejected() -> None:
    bad = _minimal_manifest_dict()
    bad["config"] = {"strategy": "magic", "include_dir": "/etc/audit"}
    with pytest.raises(ValidationError):
        DependencyManifest.model_validate(bad)


def test_manifest_unknown_probe_kind_rejected() -> None:
    bad = _minimal_manifest_dict()
    bad["verify"]["health_probe"]["kind"] = "voodoo"  # type: ignore[index]
    with pytest.raises(ValidationError):
        DependencyManifest.model_validate(bad)


def test_plan_item_validates() -> None:
    item = DependencyPlanItem.model_validate(
        {
            "name": "auditd",
            "action": "install",
            "packages": ["audit"],
            "expected_command": "pacman -S --noconfirm --needed audit",
            "config_dropin": "/etc/audit/rules.d/inspectord.rules",
            "service_actions": ["systemctl enable --now auditd.service"],
            "permission_actions": [],
            "post_install_hooks": [],
        }
    )
    assert item.action == "install"


def test_plan_full_validates_and_expires() -> None:
    created = datetime.now(UTC)
    plan = DependencyPlan.model_validate(
        {
            "schema_version": "1.0.0",
            "plan_id": "01900000-0000-7000-8000-000000000000",
            "created_at": created.isoformat(),
            "created_by": "eli@local",
            "distro": "arch",
            "package_manager": "pacman",
            "items": [
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
            ],
            "estimated_disk_mb": 10,
            "expires_at": (created + timedelta(hours=1)).isoformat(),
        }
    )
    assert plan.distro == "arch"
    assert len(plan.items) == 1


def test_dependency_state_default() -> None:
    state = DependencyState(name="auditd")
    assert state.installed is False
    assert state.dropin_present is False
    assert state.last_verify_pass is None


def test_probe_kind_enum_values() -> None:
    expected = {
        "binary_exists_and_runs",
        "service_active",
        "file_exists",
        "file_exists_and_growing",
        "command_exit_zero",
        "journal_pattern_recent",
    }
    assert {k.value for k in ProbeKind} == expected


def test_config_strategy_enum_values() -> None:
    assert {s.value for s in ConfigStrategy} == {"sidecar", "edit-with-backup"}
