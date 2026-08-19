"""Tests that the shipped v1 manifests load and have the expected shape."""

from __future__ import annotations

import os
from pathlib import Path

from inspectord.dependencies.manifest import load_packaged_manifests

_TEMPLATES_ROOT = Path(__file__).parent.parent / "inspectord" / "dependencies" / "templates"


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


def test_rkhunter_dropin_targets_rkhunter_d_not_rkhunter_conf_d() -> None:
    """§30.6 names /etc/rkhunter.conf.d/; rkhunter 1.4.6 never reads that path.

    /usr/bin/rkhunter sets `LOCALCONFIGDIR="${configdir}/rkhunter.d"` and globs
    it for `*.conf`. Shipping to §30.6's path would write a file rkhunter never
    opens -- a silent no-op that looks configured. This test is the guard rail
    against someone "fixing" the path back to match the spec text.
    """
    m = load_packaged_manifests()["rkhunter"]
    assert m.config is not None
    assert m.config.include_dir == "/etc/rkhunter.d/"
    assert m.config.dropin is not None
    assert m.config.dropin.filename == "inspectord.conf"


def test_rkhunter_dropin_whitelists_exactly_the_three_arch_wrappers() -> None:
    """SCRIPTWHITELIST is per-path: every entry is an exemption we must justify.

    Each of these three is a genuine shell script on Arch/CachyOS. A fourth
    entry appearing here without a measurement behind it is a regression, so
    the set is pinned exactly rather than merely checked for membership.
    """
    m = load_packaged_manifests()["rkhunter"]
    assert m.config is not None and m.config.dropin is not None
    body = (_TEMPLATES_ROOT / m.config.dropin.template.replace("/", os.sep)).read_text(
        encoding="utf-8"
    )
    whitelisted = {
        line.split("=", 1)[1].strip()
        for line in body.splitlines()
        if line.startswith("SCRIPTWHITELIST=")
    }
    assert whitelisted == {"/usr/bin/egrep", "/usr/bin/fgrep", "/usr/bin/ldd"}


def test_rkhunter_dropin_declares_no_other_option() -> None:
    """The drop-in must not smuggle in unrelated rkhunter settings.

    A drop-in is read as ordinary config, so any option here silently overrides
    /etc/rkhunter.conf. Keeping it to SCRIPTWHITELIST keeps the blast radius
    equal to what the comment in the file claims it is.
    """
    m = load_packaged_manifests()["rkhunter"]
    assert m.config is not None and m.config.dropin is not None
    body = (_TEMPLATES_ROOT / m.config.dropin.template.replace("/", os.sep)).read_text(
        encoding="utf-8"
    )
    settings = [line for line in body.splitlines() if line and not line.startswith("#")]
    assert all(line.startswith("SCRIPTWHITELIST=") for line in settings), settings


def test_no_manifest_declares_a_cachyos_key() -> None:
    """`Distro` has no `cachyos` member — CachyOS is mapped onto `arch` at
    detection — so a `cachyos:` key can never be looked up. Keeping one would be
    a second, unreadable copy of the arch package list, free to rot out of sync
    with the one that is actually used.
    """
    for name, m in load_packaged_manifests().items():
        assert "cachyos" not in m.distro_packages, (
            f"{name}.yaml declares a cachyos package list that nothing can ever read"
        )
