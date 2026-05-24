"""File-based allowlist loader (spec §31 Phase 1: file-based; UI later)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from inspectord.schemas.allowlist import AllowlistEntry

_DEFAULT_PATH = Path("/etc/inspectord/allowlist.yaml")


class AllowlistFileError(RuntimeError):
    pass


def load_allowlist_from_path(path: Path) -> list[AllowlistEntry]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AllowlistFileError(f"{p}: invalid YAML: {exc}") from exc
    if data is None:
        return []
    if not isinstance(data, dict) or "entries" not in data:
        raise AllowlistFileError(f"{p}: top-level must be a mapping with 'entries' list")
    raw_entries: Any = data["entries"]
    if not isinstance(raw_entries, list):
        raise AllowlistFileError(f"{p}: 'entries' must be a list")
    out: list[AllowlistEntry] = []
    for i, raw in enumerate(raw_entries):
        try:
            out.append(AllowlistEntry.model_validate(raw))
        except ValidationError as exc:
            raise AllowlistFileError(f"{p}: entry [{i}] invalid: {exc}") from exc
    return out


def load_allowlist_file() -> list[AllowlistEntry]:
    """Load the default allowlist file. Returns [] if missing."""
    return load_allowlist_from_path(_DEFAULT_PATH)
