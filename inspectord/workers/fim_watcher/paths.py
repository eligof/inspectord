"""Hardcoded watched-path set (spec §0.1 / §5.1)."""

from __future__ import annotations

import os
from pathlib import Path


def default_watch_paths() -> list[str]:
    paths: list[str] = [
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/boot",
        "/etc/sudoers",
        "/etc/sudoers.d",
    ]
    home = os.environ.get("HOME")
    if home:
        for rel in (".bashrc", ".zshrc", ".profile", ".zprofile", ".config/autostart"):
            paths.append(str(Path(home) / rel))
    return paths
