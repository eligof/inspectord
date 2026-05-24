"""Tests for the sidecar config writer."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.sidecar import SidecarError, write_sidecar


def test_write_sidecar_auditd(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert written.name == "inspectord.rules"
    assert "execve" in written.read_text()


def test_write_sidecar_journald(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["journald"]
    target_dir = tmp_path / "journald.conf.d"
    target_dir.mkdir()
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert "Storage=persistent" in written.read_text()


def test_write_sidecar_atomic_no_tmp_leftover(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert not list(target_dir.glob("*.tmp"))


def test_write_sidecar_overwrites_existing(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    (target_dir / "inspectord.rules").write_text("STALE")
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert "STALE" not in written.read_text()


def test_write_sidecar_sets_mode(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert (os.stat(written).st_mode & 0o777) == 0o640


def test_write_sidecar_raises_when_no_config(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["aide"]
    with pytest.raises(SidecarError):
        write_sidecar(manifest, include_dir=tmp_path, chown=False)
