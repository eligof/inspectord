"""Tests for the PackageBackend Protocol and helper types."""

from __future__ import annotations

import pytest

from inspectord.dependencies.backend import (
    BackendLockedError,
    BackendNotAvailableError,
    InstallResult,
    PackageBackend,
    RemoveResult,
)


class _DummyBackend:
    schema_version = "1.0.0"
    name = "dummy"

    def is_installed(self, pkg: str) -> bool:
        return False

    def installed_version(self, pkg: str) -> str | None:
        return None

    def candidate_version(self, pkg: str) -> str | None:
        return None

    def install(self, pkgs: list[str], *, dry_run: bool = False) -> InstallResult:
        return InstallResult(installed=pkgs, command=f"dummy install {' '.join(pkgs)}", exit_code=0)

    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult:
        return RemoveResult(removed=pkgs, command=f"dummy remove {' '.join(pkgs)}", exit_code=0)

    def is_locked(self) -> bool:
        return False

    def refresh_metadata(self) -> None:
        return None


def test_dummy_matches_protocol() -> None:
    backend: PackageBackend = _DummyBackend()
    assert backend.is_installed("foo") is False


def test_install_result_dataclass() -> None:
    r = InstallResult(installed=["foo"], command="x", exit_code=0)
    assert r.installed == ["foo"]
    assert r.failed is False


def test_install_result_failure_helper() -> None:
    r = InstallResult(installed=[], command="x", exit_code=1, stderr_tail="permission denied")
    assert r.failed is True


def test_remove_result_dataclass() -> None:
    r = RemoveResult(removed=["foo"], command="x", exit_code=0)
    assert r.removed == ["foo"]
    assert r.failed is False


def test_locked_error_is_runtime() -> None:
    with pytest.raises(RuntimeError):
        raise BackendLockedError("pacman lock at /var/lib/pacman/db.lck")


def test_not_available_error_is_runtime() -> None:
    with pytest.raises(RuntimeError):
        raise BackendNotAvailableError("pkexec missing")
