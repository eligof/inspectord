"""Tests for PacmanBackend (non-privileged operations)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from inspectord.dependencies.backend import BackendLockedError, BackendNotAvailableError
from inspectord.dependencies.pacman_backend import PacmanBackend


class _FakeRunner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._scripts = scripts

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        key = tuple(argv)
        self.calls.append(key)
        return self._scripts.get(
            key,
            subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"unscripted"),
        )


def _ok(out: str = "", err: str = "", code: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=[], returncode=code, stdout=out.encode(), stderr=err.encode()
    )


def test_is_installed_true() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _ok(out="Name : audit\nVersion : 3.1.5-1\n")})
    assert PacmanBackend(runner=runner).is_installed("audit") is True


def test_is_installed_false() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "ghost"): _ok(code=1)})
    assert PacmanBackend(runner=runner).is_installed("ghost") is False


def test_installed_version() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _ok(out="Name : audit\nVersion : 3.1.5-1\n")})
    assert PacmanBackend(runner=runner).installed_version("audit") == "3.1.5-1"


def test_installed_version_missing_returns_none() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "ghost"): _ok(code=1)})
    assert PacmanBackend(runner=runner).installed_version("ghost") is None


def test_candidate_version() -> None:
    out = "Repository : core\nName : audit\nVersion : 3.1.5-1\n"
    runner = _FakeRunner({("pacman", "-Si", "audit"): _ok(out=out)})
    assert PacmanBackend(runner=runner).candidate_version("audit") == "3.1.5-1"


def test_candidate_version_missing_returns_none() -> None:
    runner = _FakeRunner({("pacman", "-Si", "ghost"): _ok(code=1)})
    assert PacmanBackend(runner=runner).candidate_version("ghost") is None


def test_is_locked_true(tmp_path: Path) -> None:
    lock = tmp_path / "db.lck"
    lock.write_text("")
    assert PacmanBackend(lock_path=lock).is_locked() is True


def test_is_locked_false(tmp_path: Path) -> None:
    assert PacmanBackend(lock_path=tmp_path / "absent.lck").is_locked() is False


def test_refresh_metadata_not_available() -> None:
    with pytest.raises(BackendNotAvailableError):
        PacmanBackend().refresh_metadata()


def test_install_requires_helper() -> None:
    with pytest.raises(BackendNotAvailableError):
        PacmanBackend(helper_command=None).install(["audit"])


def test_install_refuses_when_locked(tmp_path: Path) -> None:
    lock = tmp_path / "db.lck"
    lock.write_text("")
    with pytest.raises(BackendLockedError):
        PacmanBackend(lock_path=lock, helper_command=["true"]).install(["audit"])
