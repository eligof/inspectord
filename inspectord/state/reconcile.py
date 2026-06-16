"""Boot-scoped reconciliation for process state.

A missed exit event leaves a stale 'running' row. Because the process entity
key is boot-scoped (spec §14.1), any 'running' row whose boot_id differs from
the current boot can be safely marked exited at startup.
"""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database

_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def current_boot_id() -> str:
    return _BOOT_ID_PATH.read_text(encoding="utf-8").strip()


def reconcile_processes(db: Database, boot_id: str) -> None:
    db.execute(
        "UPDATE process_state SET status='exited' WHERE boot_id <> ? AND status='running'",
        [boot_id],
    )
