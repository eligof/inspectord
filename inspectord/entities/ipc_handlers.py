"""IPC handler for entity context cards (spec 2026-08-23-entity-context-cards §6)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.entities.card import InvalidEntity, build_entity_card
from inspectord.state.reconcile import current_boot_id
from inspectord.storage.db import Database

_SCHEMA_VERSION = "1.0.0"
_MIN_WINDOW_H = 1
_MAX_WINDOW_H = 168  # one week


def handle_get_entity_card(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    kind = str(params.get("kind", ""))
    key = str(params.get("key", ""))
    try:
        window_h = int(params.get("window_h", 24))
    except (TypeError, ValueError):
        window_h = 24
    window_h = max(_MIN_WINDOW_H, min(_MAX_WINDOW_H, window_h))
    try:
        boot_id: str | None = current_boot_id()
    except OSError:
        boot_id = None
    try:
        with Database(db_path) as db:
            card = build_entity_card(
                db,
                kind=kind,
                key=key,
                now=datetime.now(UTC),
                boot_id=boot_id,
                window_h=window_h,
            )
    except InvalidEntity as exc:
        return {"schema_version": _SCHEMA_VERSION, "ok": False, "error": str(exc)}
    return {"schema_version": _SCHEMA_VERSION, "ok": True, "card": card}
