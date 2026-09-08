"""dirfd-disciplined path handling for quarantine (quarantine design §3.2).

The target of a quarantine is, by threat model, a file in an
attacker-writable directory: no code path may re-traverse a user-supplied
path string once its fd/dirfd is open. This module provides the two building
blocks — a symlink-free parent-directory open, and the quarantine deny-list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from inspectord.evidence.capture import DENY_PREFIXES

#: Deleting the policy file would brick the polkit gate fail-closed (§3.2).
_POLKIT_DIR = "/usr/share/polkit-1"

_DIR_OPEN_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC


@dataclass(frozen=True)
class QuarantinePaths:
    """The daemon's own control plane — non-negotiable deny-list entries.

    Quarantining the DB, audit chain, journal, forensic store, socket dir or
    config would let a root unlink destroy the daemon's evidence or brick it
    while reporting success (§3.2).
    """

    state_dir: Path
    socket_dir: Path
    config_path: Path | None = None


def quarantine_deny(path_resolved: str, paths: QuarantinePaths) -> bool:
    """True when ``path_resolved`` (an ``os.path.realpath`` result) is refused.

    Superset of evidence capture's read deny-list: capture's list was scoped
    for reads; quarantine adds a root unlink, so the daemon's own control
    plane and the polkit policy directory join it.
    """
    deny = [*DENY_PREFIXES, _POLKIT_DIR, str(paths.state_dir), str(paths.socket_dir)]
    if paths.config_path is not None:
        deny.append(str(paths.config_path))
    return any(
        path_resolved == entry or path_resolved.startswith(entry.rstrip("/") + "/")
        for entry in deny
    )


def open_parent_dirfd(path: str) -> int:
    """Open the parent directory of ``path`` as an O_PATH dirfd, symlink-free.

    Component-wise walk from ``/`` with ``O_NOFOLLOW | O_DIRECTORY`` on every
    component: CPython exposes no ``openat2(RESOLVE_NO_SYMLINKS)``, so this
    walk IS the no-symlink resolution mechanism. A symlink component fails
    with ELOOP (ENOTDIR on some paths), a missing one with ENOENT; callers
    map the OSError to their typed refusal. The returned fd is the caller's
    to close.
    """
    parent = os.path.dirname(path)
    fd = os.open("/", _DIR_OPEN_FLAGS)
    try:
        for component in parent.split("/"):
            if not component:
                continue
            nxt = os.open(component, _DIR_OPEN_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError:
        os.close(fd)
        raise
    return fd
