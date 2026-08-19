"""Tests that the shipped v1 manifests load and have the expected shape."""

from __future__ import annotations

from inspectord.dependencies.manifest import load_packaged_manifests


def test_all_v1_manifests_load() -> None:
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


def test_aide_is_not_auto_installable() -> None:
    """aide is AUR-only on Arch/CachyOS: `pacman -S aide` fails."""
    m = load_packaged_manifests()["aide"]
    assert m.manual_install is not None
    assert m.manual_install.reason
    assert m.manual_install.instructions


def test_aide_keeps_package_name_for_detection() -> None:
    """An AUR install still registers in the pacman DB, so keep the name."""
    m = load_packaged_manifests()["aide"]
    assert m.distro_packages.get("arch", []) == ["aide"]
    assert m.distro_packages.get("cachyos", []) == ["aide"]


def test_yara_stays_auto_installable() -> None:
    """yara really is in the official repos — it must not be marked manual."""
    m = load_packaged_manifests()["yara"]
    assert m.manual_install is None
    assert m.distro_packages.get("arch", []) == ["yara"]


def test_rkhunter_manifest_loads() -> None:
    assert "rkhunter" in load_packaged_manifests()


def test_rkhunter_is_optional_not_required() -> None:
    """Spec §30.13 lists rkhunter under "Optional (asked)", never under required."""
    m = load_packaged_manifests()["rkhunter"]
    assert m.required_when.profiles == []
    assert "minimal" in m.optional_when.profiles


def test_rkhunter_is_auto_installable_from_the_official_repos() -> None:
    """`pacman -Si rkhunter` resolves (extra) — unlike aide, it needs no manual step."""
    m = load_packaged_manifests()["rkhunter"]
    assert m.manual_install is None
    assert m.distro_packages.get("arch", []) == ["rkhunter"]
    assert m.distro_packages.get("cachyos", []) == ["rkhunter"]


def test_rkhunter_probe_does_not_execute_the_binary() -> None:
    """/usr/bin/rkhunter is 0700 root:root: probing it by execution fails unprivileged."""
    m = load_packaged_manifests()["rkhunter"]
    assert m.verify.health_probe.kind.value == "file_exists"
    assert m.verify.health_probe.path == "/usr/bin/rkhunter"
    assert m.verify.version_cmd is None


def test_rkhunter_declares_no_post_install_hooks() -> None:
    """The applier does not execute post_install_hooks; declaring one would be inert."""
    m = load_packaged_manifests()["rkhunter"]
    assert m.post_install_hooks == []
    assert m.config is None
