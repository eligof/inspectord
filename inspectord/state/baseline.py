"""Capture entity-state baselines (spec §19.3).

A baseline is a point-in-time snapshot of an entity set, stored in
`baseline_entry`, used to compute new/removed/re-enabled diffs. Supports the
'service' and 'persistence' kinds; other kinds reuse the same table later.
"""

from __future__ import annotations

import json

from inspectord.storage.db import Database

_SUPPORTED = {"service", "persistence"}


def capture_baseline(kind: str, db: Database) -> int:
    if kind not in _SUPPORTED:
        raise ValueError(f"unsupported baseline kind: {kind!r}")
    # Replace the previous baseline for this kind only (other kinds untouched).
    db.execute("DELETE FROM baseline_entry WHERE kind = ?", [kind])

    if kind == "persistence":
        prows = db.query(
            "SELECT persist_key, kind, name, source_path, details FROM persistence_state"
        ).fetchall()
        for pk, k, name, source_path, details in prows:
            attrs = json.dumps(
                {"kind": k, "name": name, "source_path": source_path, "details": details}
            )
            db.execute(
                "INSERT INTO baseline_entry (kind, key, attrs_json, captured_at) "
                "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                ["persistence", pk, attrs],
            )
        return len(prows)

    rows = db.query(
        "SELECT unit, active_state, sub_state, load_state FROM service_state"
    ).fetchall()
    for unit, active, sub, load in rows:
        attrs = json.dumps({"active_state": active, "sub_state": sub, "load_state": load})
        db.execute(
            "INSERT INTO baseline_entry (kind, key, attrs_json, captured_at) "
            "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            [kind, f"svc:{unit}", attrs],
        )
    return len(rows)
