"""Capture entity-state baselines (spec §19.3).

A baseline is a point-in-time snapshot of an entity set, stored in
`baseline_entry`, used to compute new/removed/re-enabled diffs. PR1 supports
the 'service' kind; other kinds reuse the same table later.
"""

from __future__ import annotations

import json

from inspectord.storage.db import Database

_SUPPORTED = {"service"}


def capture_baseline(kind: str, db: Database) -> int:
    if kind not in _SUPPORTED:
        raise ValueError(f"unsupported baseline kind: {kind!r}")
    db.execute("DELETE FROM baseline_entry WHERE kind = ?", [kind])
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
