"""PacmanBackend — Arch / CachyOS package backend (spec §30.4)."""

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
from inspectord.dependencies.pkg_helper import PkgHelperError, run_helper


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
_IN_PROCESS = "__in_process__"


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
        db_path: Path | None = None,
    ) -> None:
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()
        self._lock_path = Path(lock_path)
        self._helper_command = list(helper_command) if helper_command else None
        self._db_path = Path(db_path) if db_path else None

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
        raise BackendNotAvailableError("refresh_metadata runs via pkg-helper as part of install")

    def install(
        self,
        pkgs: list[str],
        *,
        dry_run: bool = False,
        plan_id: str | None = None,
    ) -> InstallResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        if self._helper_command is None:
            raise BackendNotAvailableError("install path not configured (pkg-helper command unset)")
        if plan_id is None:
            raise BackendNotAvailableError(
                "PacmanBackend.install requires plan_id (use the applier)"
            )
        if dry_run:
            return InstallResult(
                installed=pkgs,
                command=f"(dry-run) helper plan {plan_id}",
                exit_code=0,
            )
        return self._invoke_helper(pkgs, plan_id)

    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        raise BackendNotAvailableError("remove not supported in Phase 1")

    def _invoke_helper(self, pkgs: list[str], plan_id: str) -> InstallResult:
        assert self._helper_command is not None
        command_text = f"helper plan={plan_id} pkgs={','.join(pkgs)}"
        if self._helper_command == [_IN_PROCESS]:
            if self._db_path is None:
                raise BackendNotAvailableError("in-process helper requires db_path (test-only)")
            try:
                result = run_helper(plan_id=plan_id, db_path=self._db_path, runner=self._runner)
            except PkgHelperError as exc:
                return InstallResult(
                    installed=[],
                    command=command_text,
                    exit_code=3,
                    stderr_tail=str(exc),
                )
            return InstallResult(
                installed=pkgs if result.exit_code == 0 else [],
                command=command_text,
                exit_code=result.exit_code,
                stdout_tail=result.stdout[-2000:],
                stderr_tail=result.stderr[-2000:],
            )
        argv = [*self._helper_command, "--plan-id", plan_id]
        completed = self._runner.run(argv)
        return InstallResult(
            installed=pkgs if completed.returncode == 0 else [],
            command=" ".join(argv),
            exit_code=completed.returncode,
            stdout_tail=completed.stdout.decode("utf-8", "replace")[-2000:],
            stderr_tail=completed.stderr.decode("utf-8", "replace")[-2000:],
        )
