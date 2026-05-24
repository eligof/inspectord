"""Package-manager backend abstraction. Spec §30.4."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class BackendError(RuntimeError):
    """Base class for backend errors."""


class BackendLockedError(BackendError):
    """The package manager DB is locked (another install in progress)."""


class BackendNotAvailableError(BackendError):
    """The backend cannot run (missing binary, missing privilege channel, etc.)."""


@dataclass
class InstallResult:
    installed: list[str]
    command: str
    exit_code: int = 0
    stdout_tail: str = ""
    stderr_tail: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.exit_code != 0


@dataclass
class RemoveResult:
    removed: list[str]
    command: str
    exit_code: int = 0
    stdout_tail: str = ""
    stderr_tail: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.exit_code != 0


@runtime_checkable
class PackageBackend(Protocol):
    schema_version: str
    name: str

    def is_installed(self, pkg: str) -> bool: ...
    def installed_version(self, pkg: str) -> str | None: ...
    def candidate_version(self, pkg: str) -> str | None: ...
    def install(self, pkgs: list[str], *, dry_run: bool = False) -> InstallResult: ...
    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult: ...
    def is_locked(self) -> bool: ...
    def refresh_metadata(self) -> None: ...
