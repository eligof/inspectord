"""Schema migrations runner.

Migrations are numbered SQL files in `migrations_data/`. They are applied
in order; each gets a row in `schema_version` so applying twice is a no-op.
"""

from __future__ import annotations

import re
from importlib.resources import files

from inspectord.storage.db import Database

_MIGRATION_NAME_RE = re.compile(r"^(\d{4})_.+\.sql$")


def _bootstrap(db: Database) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(version INTEGER NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    )


def current_schema_version(db: Database) -> int:
    _bootstrap(db)
    rows = db.query("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchall()
    return int(rows[0][0])


def _list_migrations() -> list[tuple[int, str, str]]:
    """Return [(num, name, sql), ...] sorted by num."""
    migrations: list[tuple[int, str, str]] = []
    pkg = files("inspectord.storage.migrations_data")
    for entry in pkg.iterdir():
        match = _MIGRATION_NAME_RE.match(entry.name)
        if not match:
            continue
        num = int(match.group(1))
        sql = entry.read_text(encoding="utf-8")
        migrations.append((num, entry.name, sql))
    migrations.sort(key=lambda t: t[0])
    return migrations


def run_migrations(db: Database) -> int:
    """Apply pending migrations. Returns the new schema version."""
    _bootstrap(db)
    applied = current_schema_version(db)
    for num, _name, sql in _list_migrations():
        if num <= applied:
            continue
        for statement in _split_sql(sql):
            db.execute(statement)
        db.execute("INSERT INTO schema_version (version) VALUES (?)", [num])
        applied = num
    return applied


def _split_sql(text: str) -> list[str]:
    """Split a SQL file into statements on semicolons (simple, no escaping).

    Comment lines (starting with --) are stripped before splitting so that
    semicolons embedded in comments do not produce spurious fragments.
    """
    # Remove comment lines before splitting on semicolons
    lines = [line for line in text.splitlines() if not line.strip().startswith("--")]
    stripped = "\n".join(lines)
    parts = [s.strip() for s in stripped.split(";")]
    return [p for p in parts if p]
