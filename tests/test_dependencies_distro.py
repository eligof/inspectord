"""Tests for distro detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.dependencies.distro import (
    Distro,
    DistroDetectionError,
    detect_distro,
    detect_distro_from_text,
)


def test_detect_arch() -> None:
    text = 'ID=arch\nID_LIKE=""\n'
    assert detect_distro_from_text(text) == Distro.arch


def test_detect_cachyos_maps_to_arch_family() -> None:
    text = "ID=cachyos\nID_LIKE=arch\n"
    assert detect_distro_from_text(text) == Distro.arch


def test_detect_manjaro_maps_to_arch_family() -> None:
    text = "ID=manjaro\nID_LIKE=arch\n"
    assert detect_distro_from_text(text) == Distro.arch


def test_detect_ubuntu_maps_to_debian_family() -> None:
    text = "ID=ubuntu\nID_LIKE=debian\n"
    assert detect_distro_from_text(text) == Distro.debian


def test_detect_fedora() -> None:
    text = 'ID=fedora\nID_LIKE=""\n'
    assert detect_distro_from_text(text) == Distro.fedora


def test_detect_opensuse_tumbleweed() -> None:
    text = 'ID=opensuse-tumbleweed\nID_LIKE="suse opensuse"\n'
    assert detect_distro_from_text(text) == Distro.opensuse


def test_detect_unknown_raises() -> None:
    text = 'ID=alpine\nID_LIKE=""\n'
    with pytest.raises(DistroDetectionError):
        detect_distro_from_text(text)


def test_detect_missing_id_raises() -> None:
    with pytest.raises(DistroDetectionError):
        detect_distro_from_text("# empty file\n")


def test_detect_from_path_raises_on_missing(tmp_path: Path) -> None:
    with pytest.raises(DistroDetectionError):
        detect_distro(os_release_path=tmp_path / "missing")
