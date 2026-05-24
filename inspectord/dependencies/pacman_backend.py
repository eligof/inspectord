"""PacmanBackend — Arch / CachyOS package backend (spec §30.4).

Non-privileged operations only at this stage. The privileged install path
lands in a later task once the pkg-helper exists.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.backend import (
    BackendLockedError,
    BackendNotAvailableError,
    InstallResult,
    RemoveResult,
)


class _Runner(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(argv, timeout=timeout, check=check, capture_output=True)


_VERSION_RE = re.compile(r"^Version\s*:\s*(\S+)", re.MULTILINE)


class PacmanBackend:
    """Pacman backend for Arch-family distros."""

    schema_version = "1.0.0"
    name = "pacman"

    def __init__(
        self,
        *,
        runner: _Runner | None = None,
        lock_path: Path = Path("/var/lib/pacman/db.lck"),
        helper_command: list[str] | None = None,
    ) -> None:
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()
        self._lock_path = Path(lock_path)
        self._helper_command = list(helper_command) if helper_command else None

    def is_installed(self, pkg: str) -> bool:
        return self._runner.run(["pacman", "-Qi", pkg]).returncode == 0

    def installed_version(self, pkg: str) -> str | None:
        return self._parse_version(["pacman", "-Qi", pkg])

    def candidate_version(self, pkg: str) -> str | None:
        return self._parse_version(["pacman", "-Si", pkg])

    def _parse_version(self, argv: list[str]) -> str | None:
        result = self._runner.run(argv)
        if result.returncode != 0:
            return None
        match = _VERSION_RE.search(result.stdout.decode("utf-8", "replace"))
        return match.group(1) if match else None

    def is_locked(self) -> bool:
        return self._lock_path.exists()

    def refresh_metadata(self) -> None:
        raise BackendNotAvailableError(
            "refresh_metadata requires root; runs via pkg-helper as part of install"
        )

    def install(self, pkgs: list[str], *, dry_run: bool = False) -> InstallResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        if self._helper_command is None:
            raise BackendNotAvailableError("install path not configured (pkg-helper command unset)")
        raise NotImplementedError("install() implementation lands in a later task")

    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        raise BackendNotAvailableError("remove not supported in Phase 1")
