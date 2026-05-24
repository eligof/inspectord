"""Audit log writer for dependency manager actions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.storage.db import Database


def log_dep_action(
    *,
    db_path: Path,
    actor: str,
    action: str,
    target: str | None = None,
    plan_id: str | None = None,
    before_sha256: str | None = None,
    after_sha256: str | None = None,
    command: str | None = None,
    exit_code: int | None = None,
    stderr_tail: str | None = None,
) -> None:
    truncated = (stderr_tail or "")[:2000] if stderr_tail else None
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO dep_audit (ts, actor, action, target, plan_id, "
            "before_sha256, after_sha256, command, exit_code, stderr_tail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                datetime.now(UTC),
                actor,
                action,
                target,
                plan_id,
                before_sha256,
                after_sha256,
                command,
                exit_code,
                truncated,
            ],
        )
