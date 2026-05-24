"""Edit-with-backup utility (spec §30.6)."""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from inspectord.ids import uuid7
from inspectord.storage.db import Database

BEGIN_MARKER = "# >>> inspectord BEGIN"
END_MARKER = "# <<< inspectord END"
_BLOCK_RE = re.compile(
    rf"{re.escape(BEGIN_MARKER)}.*?{re.escape(END_MARKER)}\n?",
    re.DOTALL,
)


@dataclass
class BackupRecord:
    backup_id: str
    dep_name: str
    original_path: str
    backup_path: str
    original_sha256: str


def _default_backup_root(dep_name: str) -> Path:
    return Path("/var/lib/inspectord/dep_config_backups") / dep_name


def _record_backup(
    db_path: Path,
    *,
    dep_name: str,
    target_path: Path,
    original_text: str,
    backup_root: Path | None,
) -> BackupRecord:
    root = backup_root if backup_root is not None else _default_backup_root(dep_name)
    root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe = str(target_path).replace("/", "_").lstrip("_")
    backup_path = root / f"{safe}.{ts}.bak"
    backup_path.write_text(original_text, encoding="utf-8")
    sha = hashlib.sha256(original_text.encode("utf-8")).hexdigest()
    backup_id = str(uuid7())
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO dep_config_backups (backup_id, dep_name, original_path, "
            "backup_path, original_sha256) VALUES (?, ?, ?, ?, ?)",
            [backup_id, dep_name, str(target_path), str(backup_path), sha],
        )
    return BackupRecord(
        backup_id=backup_id,
        dep_name=dep_name,
        original_path=str(target_path),
        backup_path=str(backup_path),
        original_sha256=sha,
    )


def apply_edit_with_backup(
    *,
    db_path: Path,
    dep_name: str,
    target_path: Path,
    managed_block: str,
    backup_root: Path | None = None,
) -> BackupRecord:
    text = Path(target_path).read_text(encoding="utf-8")
    rec = _record_backup(
        db_path,
        dep_name=dep_name,
        target_path=Path(target_path),
        original_text=text,
        backup_root=backup_root,
    )
    block = f"{BEGIN_MARKER}\n{managed_block}{END_MARKER}\n"
    if _BLOCK_RE.search(text):
        new_text = _BLOCK_RE.sub(block, text)
    else:
        new_text = text + ("\n" if not text.endswith("\n") else "") + block
    Path(target_path).write_text(new_text, encoding="utf-8")
    return rec


def list_backups(*, db_path: Path, dep_name: str) -> list[BackupRecord]:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT backup_id, dep_name, original_path, backup_path, original_sha256 "
            "FROM dep_config_backups WHERE dep_name = ? ORDER BY created_at DESC",
            [dep_name],
        ).fetchall()
    return [
        BackupRecord(
            backup_id=r[0],
            dep_name=r[1],
            original_path=r[2],
            backup_path=r[3],
            original_sha256=r[4],
        )
        for r in rows
    ]


def restore_backup(*, db_path: Path, backup_id: str) -> None:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT original_path, backup_path FROM dep_config_backups WHERE backup_id = ?",
            [backup_id],
        ).fetchall()
    if not rows:
        raise FileNotFoundError(f"backup not found: {backup_id}")
    original_path, backup_path = rows[0]
    shutil.copy2(backup_path, original_path)
