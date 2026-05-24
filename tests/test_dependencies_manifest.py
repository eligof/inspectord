"""Tests for the manifest YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.dependencies.manifest import (
    ManifestLoadError,
    load_manifest_from_path,
    load_packaged_manifests,
)


def _write_yaml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_load_valid_manifest(tmp_path: Path) -> None:
    p = _write_yaml(
        tmp_path / "auditd.yaml",
        """
version: 1.0.0
name: auditd
description: Linux audit daemon
distro_packages:
  arch: [audit]
verify:
  binary_paths: [/sbin/auditctl]
  health_probe:
    kind: binary_exists_and_runs
""".lstrip(),
    )
    m = load_manifest_from_path(p)
    assert m.name == "auditd"
    assert m.distro_packages["arch"] == ["audit"]


def test_load_manifest_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ManifestLoadError):
        load_manifest_from_path(tmp_path / "nope.yaml")


def test_load_manifest_malformed_yaml(tmp_path: Path) -> None:
    p = _write_yaml(tmp_path / "bad.yaml", "name: : :")
    with pytest.raises(ManifestLoadError):
        load_manifest_from_path(p)


def test_load_manifest_invalid_schema(tmp_path: Path) -> None:
    p = _write_yaml(
        tmp_path / "bad.yaml",
        """
version: 1.0.0
name: x
""".lstrip(),
    )
    with pytest.raises(ManifestLoadError):
        load_manifest_from_path(p)


def test_load_packaged_manifests_returns_dict() -> None:
    result = load_packaged_manifests()
    assert isinstance(result, dict)
