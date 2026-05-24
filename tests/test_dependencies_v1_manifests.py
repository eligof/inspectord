"""Tests that the six v1 manifests load and have expected shape."""

from __future__ import annotations

from inspectord.dependencies.manifest import load_packaged_manifests


def test_all_six_v1_manifests_load() -> None:
    manifests = load_packaged_manifests()
    expected = {"auditd", "journald", "aide", "yara", "libudev", "ebpf_features"}
    assert set(manifests) >= expected


def test_auditd_has_pacman_package() -> None:
    m = load_packaged_manifests()["auditd"]
    assert "audit" in m.distro_packages.get("arch", [])


def test_journald_uses_sidecar_strategy() -> None:
    m = load_packaged_manifests()["journald"]
    assert m.config is not None
    assert m.config.strategy.value == "sidecar"


def test_libudev_has_no_install_packages() -> None:
    m = load_packaged_manifests()["libudev"]
    assert m.distro_packages.get("arch", []) == []


def test_ebpf_features_is_verify_only() -> None:
    m = load_packaged_manifests()["ebpf_features"]
    assert m.distro_packages.get("arch", []) == []
    assert m.config is None
