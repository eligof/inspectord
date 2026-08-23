# Entity Context Cards PR1 (daemon) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Daemon-side entity card builder + read-only `get_entity_card` IPC method, per
`docs/superpowers/specs/2026-08-23-entity-context-cards-design.md` (PR1 of 2).

**Architecture:** New `inspectord/entities/` package. `card.py` holds a pure
`build_entity_card(db, *, kind, key, now, boot_id, window_h)` that aggregates four
sections (header, events, alerts, related) from existing DuckDB tables; `ipc_handlers.py`
wraps it as `get_entity_card` (mutates=False), registered in `inspectord/__main__.py`.
One projector fix rides along: `_project_process` starts writing the dormant
`exe_path`/`exe_sha256` columns.

**Tech Stack:** Python 3.13, DuckDB (JSON functions on `payload_json` VARCHAR), pytest.

**Gates (run before every commit claim):**
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

**Verified codebase facts** (do not re-derive):
- Event payload field names: `process.pid`, `process.name`, `process.command_line`,
  `process.parent.pid`, `process.executable` (path), `process.hash.sha256`,
  `destination.ip`, `destination.port`, `source.ip`, `network.transport`,
  `service.name`, `file.path`, `user.name`, `user.id`, `device.vendor/product/serial`,
  `raw.DEVPATH`. (Sources: `inspectord/state/projector.py`,
  `inspectord/enrichment/process.py`.)
- `device_state.dev_key` = `raw.DEVPATH` or `device.name` (projector `_device_key`) —
  NOT `vendor:product:serial`.
- `process_state.exe_path`/`exe_sha256` exist in migration 0004 but are never written —
  Task 1 fixes that.
- Test DB seeding pattern: `tests/state/test_ipc_handlers.py` (`_fresh(tmp_path)` +
  `Database`/`run_migrations`, seed with raw INSERTs).
- Events are seeded through `inspectord.storage.events.insert_event(db, event, payload_json)`.
- IPC registration pattern: `Method(name=..., handler=lambda params: handle_x(params=params, db_path=cfg.storage.db_path), mutates=False)` in `_ipc_methods` (`inspectord/__main__.py`).
- IPC response shape: `{"schema_version": "1.0.0", "ok": bool, ...}` / error key on failure.
- `inspectord.state.reconcile.current_boot_id()` reads `/proc/sys/kernel/random/boot_id`.

---

### Task 1: Projector writes exe_path / exe_sha256

**Files:**
- Modify: `inspectord/state/projector.py` (`_project_process` fallthrough INSERT, ~line 259)
- Test: `tests/state/test_projector.py` (append)

- [ ] **Step 1: Write the failing test** (match the file's existing test style/helpers —
read the top of `tests/state/test_projector.py` first and reuse its event-building
helper if one exists):

```python
def test_process_start_writes_exe_fields(tmp_path):
    db_path = _fresh(tmp_path)  # or the file's equivalent fixture
    ev = _event(  # the file's process-event helper; must produce action="process_start"
        process={
            "pid": 4242,
            "name": "nc",
            "executable": "/usr/bin/nc",
            "hash": {"sha256": "ab" * 32},
            "command_line": "nc -l 4444",
        },
    )
    with Database(db_path) as db:
        project(ev, db, "boot-1")
        row = db.query(
            "SELECT exe_path, exe_sha256 FROM process_state WHERE pid=4242"
        ).fetchone()
    assert row == ("/usr/bin/nc", "ab" * 32)


def test_process_start_without_hash_preserves_existing_exe_fields(tmp_path):
    db_path = _fresh(tmp_path)
    with_hash = _event(process={"pid": 7, "name": "x", "executable": "/bin/x",
                                "hash": {"sha256": "cd" * 32}})
    without = _event(process={"pid": 7, "name": "x"})
    with Database(db_path) as db:
        project(with_hash, db, "boot-1")
        project(without, db, "boot-1")
        row = db.query(
            "SELECT exe_path, exe_sha256 FROM process_state WHERE pid=7"
        ).fetchone()
    assert row == ("/bin/x", "cd" * 32)
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/state/test_projector.py -k exe_fields -v`
Expected: FAIL (row is `(None, None)`).

- [ ] **Step 3: Implement** — in `_project_process`'s process_start INSERT, add the two
columns and preserve-on-null conflict handling:

```python
    ppid = (process.get("parent") or {}).get("pid")
    exe_path = process.get("executable")
    exe_sha256 = (process.get("hash") or {}).get("sha256")
    db.execute(
        """
        INSERT INTO process_state
            (pid, boot_id, ppid, comm, exe_path, exe_sha256, uid, cmdline, status,
             first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)
        ON CONFLICT (pid, boot_id) DO UPDATE SET
            ppid          = excluded.ppid,
            comm          = excluded.comm,
            exe_path      = COALESCE(excluded.exe_path, process_state.exe_path),
            exe_sha256    = COALESCE(excluded.exe_sha256, process_state.exe_sha256),
            uid           = excluded.uid,
            cmdline       = excluded.cmdline,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id,
            status        = 'running'
        """,
        [pid, boot_id, ppid, comm, exe_path, exe_sha256,
         _parse_uid(event.user), process.get("command_line"),
         event.ts, event.ts, event.event_id],
    )
```

- [ ] **Step 4: Run full gates** (all four commands in the header). Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/state/projector.py tests/state/test_projector.py
git commit -m "fix(state): projector writes exe_path/exe_sha256 (dormant since 0004)"
```

---

### Task 2: Card module — validation, key parsing, process card

**Files:**
- Create: `inspectord/entities/__init__.py` (empty)
- Create: `inspectord/entities/card.py`
- Test: `tests/entities/__init__.py` (empty), `tests/entities/test_card.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for the entity card builder (spec 2026-08-23-entity-context-cards)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.entities.card import InvalidEntity, build_entity_card
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

NOW = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
BOOT = "boot-1"


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _seed_process(db, pid, *, ppid=None, comm="proc", exe_sha=None, exe_path=None,
                  uid=1000, boot=BOOT, status="running"):
    db.execute(
        "INSERT INTO process_state (pid, boot_id, ppid, comm, exe_path, exe_sha256, "
        "uid, cmdline, status, first_seen, last_seen, last_event_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'cmd', ?, ?, ?, 'e1')",
        [pid, boot, ppid, comm, exe_path, exe_sha, uid, status, NOW, NOW],
    )


def test_unknown_kind_raises(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db, pytest.raises(InvalidEntity, match="invalid_kind"):
        build_entity_card(db, kind="nope", key="x", now=NOW, boot_id=BOOT)


@pytest.mark.parametrize("key", ["", "a" * 513, "x\x00y", "x\ny", "12@"])
def test_bad_process_keys_raise(tmp_path, key):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db, pytest.raises(InvalidEntity):
        build_entity_card(db, kind="process", key=key, now=NOW, boot_id=BOOT)


def test_process_card_header_and_related(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        _seed_process(db, 100, comm="parent")
        _seed_process(db, 200, ppid=100, comm="target", exe_sha="ab" * 32,
                      exe_path="/usr/bin/target")
        _seed_process(db, 300, ppid=200, comm="child")
        db.execute(
            "INSERT INTO connection_state (conn_key, pid, comm, saddr, sport, daddr, "
            "dport, proto, family, status, first_seen, last_seen, last_event_id) VALUES "
            "('200:9.9.9.9:443:tcp', 200, 'target', '10.0.0.1', 5555, '9.9.9.9', 443, "
            "'tcp', 'inet', 'open', ?, ?, 'e2')",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="process", key=f"200@{BOOT}", now=NOW,
                                 boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["comm"] == "target"
    assert card["header"]["exe_sha256"] == "ab" * 32
    rel = {(r["relation"], r["kind"], r["key"]) for r in card["related"]}
    assert ("parent", "process", f"100@{BOOT}") in rel
    assert ("child", "process", f"300@{BOOT}") in rel
    assert ("executable", "executable", "ab" * 32) in rel
    assert ("outbound", "ip", "9.9.9.9") in rel


def test_process_card_not_found_still_returns_card(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        card = build_entity_card(db, kind="process", key=f"9@{BOOT}", now=NOW,
                                 boot_id=BOOT)
    assert card["found"] is False
    assert card["events"] == []
    assert card["alerts"] == []
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/entities/ -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.entities`.

- [ ] **Step 3: Implement `inspectord/entities/card.py`**

```python
"""Entity context cards (spec 2026-08-23-entity-context-cards, parent §14).

Read-only aggregation over the existing state/event/alert tables. One card =
header + recent events + alerts + related entities, always returned even when
the entity has no state row (``found: false``) so history stays inspectable.

Boot-scoping caveat (spec §4): ``connection_state``/``listener_state`` carry no
boot_id, so pid joins assume the caller's ``boot_id`` (the current boot). A
stale pid can therefore produce a wrong-but-clickable process link; its own
card immediately reveals the mismatch.
"""

from __future__ import annotations

import json
import pwd
from datetime import datetime, timedelta
from typing import Any

from inspectord.storage.db import Database

KINDS = frozenset(
    {"process", "executable", "user", "ip", "file", "port", "service", "device"}
)
_MAX_KEY_LEN = 512
_EVENTS_CAP = 100
_ALERTS_CAP = 50
_RELATED_CAP = 50
_CHILD_CAP = 20
_IP_CAP = 20


class InvalidEntity(ValueError):
    """Raised for an unknown kind or a syntactically invalid key."""


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _validate(kind: str, key: str) -> None:
    if kind not in KINDS:
        raise InvalidEntity("invalid_kind")
    if not key or len(key) > _MAX_KEY_LEN or any(ord(c) < 0x20 or ord(c) == 0x7F for c in key):
        raise InvalidEntity("invalid_key")


def _split_process_key(key: str) -> tuple[int, str]:
    pid_s, sep, boot = key.partition("@")
    if not sep or not pid_s.isdigit() or not boot:
        raise InvalidEntity("invalid_key")
    return int(pid_s), boot


def _split_port_key(key: str) -> tuple[str, int, str]:
    addr_port, sep, proto = key.rpartition("/")
    if not sep or not proto:
        raise InvalidEntity("invalid_key")
    addr, sep2, port_s = addr_port.rpartition(":")
    if not sep2 or not addr or not port_s.isdigit():
        raise InvalidEntity("invalid_key")
    return addr, int(port_s), proto


def _related_process(pid: int, boot: str, label: str, relation: str) -> dict[str, Any]:
    return {"kind": "process", "key": f"{pid}@{boot}", "label": label, "relation": relation}


def _uid_for(username: str) -> int | None:
    try:
        return pwd.getpwnam(username).pw_uid
    except (KeyError, OSError):
        return None


# --- per-kind event/alert payload predicates --------------------------------
# Fragments run against payload_json with json_extract_string; params returned
# alongside. ``None`` = this kind has no event scan (spec §6: port).


def _payload_predicate(kind: str, key: str) -> tuple[str, list[Any]] | None:
    j = "json_extract_string(payload_json, ?)"
    if kind == "process":
        pid, _boot = _split_process_key(key)
        return f"{j} = ?", ["$.process.pid", str(pid)]
    if kind == "executable":
        return f"{j} = ?", ["$.process.hash.sha256", key]
    if kind == "ip":
        return f"({j} = ? OR {j} = ?)", ["$.destination.ip", key, "$.source.ip", key]
    if kind == "file":
        return f"{j} = ?", ["$.file.path", key]
    if kind == "service":
        return f"{j} = ?", ["$.service.name", key]
    if kind == "device":
        return f"({j} = ? OR {j} = ?)", ["$.raw.DEVPATH", key, "$.device.name", key]
    if kind == "user":
        uid = _uid_for(key)
        frag = f"({j} = ?"
        params: list[Any] = ["$.user.name", key]
        if uid is not None:
            frag += f" OR {j} = ?"
            params += ["$.user.id", str(uid)]
        return frag + ")", params
    return None  # port


def _events_section(
    db: Database, kind: str, key: str, now: datetime, window_h: int
) -> list[dict[str, Any]]:
    pred = _payload_predicate(kind, key)
    if pred is None:
        return []
    frag, params = pred
    rows = db.query(
        "SELECT event_id, ts, module, action, severity, payload_json "
        f"FROM events_enriched WHERE ts >= ? AND {frag} "
        f"ORDER BY ts DESC LIMIT {_EVENTS_CAP}",
        [now - timedelta(hours=window_h), *params],
    ).fetchall()
    out = []
    for event_id, ts, module, action, severity, payload_json in rows:
        try:
            payload = json.loads(payload_json)
        except (TypeError, ValueError):
            payload = None
        out.append(
            {"event_id": event_id, "ts": _iso(ts), "module": module,
             "action": action, "severity": severity, "payload": payload}
        )
    return out


def _alerts_section(db: Database, kind: str, key: str) -> list[dict[str, Any]]:
    pred = _payload_predicate(kind, key)
    if pred is None:
        return []
    frag, params = pred
    rows = db.query(
        "SELECT alert_id, rule_id, ts, severity, status, rendered_short "
        f"FROM alerts WHERE {frag} ORDER BY ts DESC LIMIT {_ALERTS_CAP}",
        params,
    ).fetchall()
    return [
        {"alert_id": a, "rule_id": r, "ts": _iso(ts), "severity": sev,
         "status": st, "rendered_short": short}
        for a, r, ts, sev, st, short in rows
    ]


# --- per-kind header + related ----------------------------------------------


def _process_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    pid, boot = _split_process_key(key)
    row = db.query(
        "SELECT pid, boot_id, ppid, comm, exe_path, exe_sha256, uid, cmdline, "
        "status, exit_code, first_seen, last_seen FROM process_state "
        "WHERE pid = ? AND boot_id = ?",
        [pid, boot],
    ).fetchone()
    if row is None:
        return False, {}, []
    (_, _, ppid, comm, exe_path, exe_sha, uid, cmdline, status, exit_code,
     first_seen, last_seen) = row
    header = {
        "pid": pid, "boot_id": boot, "ppid": ppid, "comm": comm,
        "exe_path": exe_path, "exe_sha256": exe_sha, "uid": uid,
        "cmdline": cmdline, "status": status, "exit_code": exit_code,
        "first_seen": _iso(first_seen), "last_seen": _iso(last_seen),
    }
    related: list[dict[str, Any]] = []
    if ppid is not None:
        related.append(_related_process(ppid, boot, f"ppid {ppid}", "parent"))
    for child_pid, child_comm in db.query(
        "SELECT pid, comm FROM process_state WHERE ppid = ? AND boot_id = ? "
        f"ORDER BY pid LIMIT {_CHILD_CAP}",
        [pid, boot],
    ).fetchall():
        related.append(_related_process(child_pid, boot, child_comm or str(child_pid), "child"))
    if exe_sha:
        related.append({"kind": "executable", "key": exe_sha,
                        "label": exe_path or exe_sha[:12], "relation": "executable"})
    if uid is not None:
        try:
            name = pwd.getpwuid(uid).pw_name
        except (KeyError, OSError):
            name = None
        if name:
            related.append({"kind": "user", "key": name, "label": name, "relation": "user"})
    if boot_id is not None and boot == boot_id:
        for (daddr,) in db.query(
            "SELECT DISTINCT daddr FROM connection_state WHERE pid = ? "
            f"ORDER BY daddr LIMIT {_IP_CAP}",
            [pid],
        ).fetchall():
            related.append({"kind": "ip", "key": daddr, "label": daddr, "relation": "outbound"})
        for addr, port, proto in db.query(
            "SELECT addr, port, proto FROM listener_state WHERE pid = ? "
            f"ORDER BY port LIMIT {_CHILD_CAP}",
            [pid],
        ).fetchall():
            k = f"{addr}:{port}/{proto}"
            related.append({"kind": "port", "key": k, "label": k, "relation": "listens"})
    return True, header, related


def build_entity_card(
    db: Database,
    *,
    kind: str,
    key: str,
    now: datetime,
    boot_id: str | None,
    window_h: int = 24,
) -> dict[str, Any]:
    _validate(kind, key)
    # Key-shape errors must raise unguarded, before the degraded-section trys.
    if kind == "process":
        _split_process_key(key)
    elif kind == "port":
        _split_port_key(key)
    warnings: list[str] = []
    found, header, related = False, {}, []
    try:
        if kind == "process":
            found, header, related = _process_header_related(db, key, boot_id)
        else:  # Task 3 replaces this stub with the _BUILDERS dispatch
            found, header, related = False, {}, []
    except Exception:  # noqa: BLE001 — degraded section beats a failed card (spec §7)
        warnings.append("header_failed")
    try:
        events = _events_section(db, kind, key, now, window_h)
    except Exception:  # noqa: BLE001
        events, warnings = [], [*warnings, "events_failed"]
    try:
        alerts = _alerts_section(db, kind, key)
    except Exception:  # noqa: BLE001
        alerts, warnings = [], [*warnings, "alerts_failed"]
    return {
        "kind": kind, "key": key, "found": found, "header": header,
        "events": events, "alerts": alerts, "related": related[:_RELATED_CAP],
        "warnings": warnings,
    }
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/entities/ -v`
Expected: PASS.

- [ ] **Step 5: Run full gates.** Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add inspectord/entities/ tests/entities/
git commit -m "feat(entities): card builder skeleton + process card"
```

---

### Task 3: Remaining kind builders

**Files:**
- Modify: `inspectord/entities/card.py`
- Test: `tests/entities/test_card.py` (append)

- [ ] **Step 1: Write failing tests** (one per kind; reuse `_fresh`/`_seed_process`; seed
the other state tables with the same INSERT style — column lists are in
`inspectord/storage/migrations_data/0004_entity_state.sql`):

```python
def test_executable_card(tmp_path):
    db_path = _fresh(tmp_path)
    sha = "ab" * 32
    with Database(db_path) as db:
        _seed_process(db, 200, comm="a", exe_sha=sha, exe_path="/usr/bin/a")
        _seed_process(db, 201, comm="b", exe_sha=sha, exe_path="/usr/bin/a")
        card = build_entity_card(db, kind="executable", key=sha, now=NOW, boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["sha256"] == sha
    assert card["header"]["paths"] == ["/usr/bin/a"]
    keys = {r["key"] for r in card["related"] if r["kind"] == "process"}
    assert keys == {f"200@{BOOT}", f"201@{BOOT}"}


def test_ip_card(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO connection_state (conn_key, pid, comm, saddr, sport, daddr, "
            "dport, proto, family, status, first_seen, last_seen, last_event_id) VALUES "
            "('7:9.9.9.9:443:tcp', 7, 'curl', '10.0.0.1', 5555, '9.9.9.9', 443, 'tcp', "
            "'inet', 'open', ?, ?, 'e1')",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="ip", key="9.9.9.9", now=NOW, boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["connection_count"] == 1
    assert {r["key"] for r in card["related"]} == {f"7@{BOOT}"}


def test_file_card(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO file_state (path, change_type, sha256, size, mode, uid, gid, "
            "first_seen, last_seen, last_event_id) VALUES "
            "('/etc/passwd', 'modified', NULL, 1234, 420, 0, 0, ?, ?, 'e1')",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="file", key="/etc/passwd", now=NOW, boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["size"] == 1234


def test_port_card(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO listener_state (addr, port, proto, family, pid, comm, "
            "first_seen, last_seen, snapshot_gen) VALUES "
            "('0.0.0.0', 8080, 'tcp', 'inet', 7, 'python', ?, ?, 1)",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="port", key="0.0.0.0:8080/tcp", now=NOW,
                                 boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["comm"] == "python"
    assert {(r["kind"], r["key"]) for r in card["related"]} == {("process", f"7@{BOOT}")}


def test_service_card(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO service_state (unit, active_state, sub_state, load_state, "
            "first_seen, last_seen, last_event_id) VALUES "
            "('sshd.service', 'active', 'running', 'loaded', ?, ?, 'e1')",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="service", key="sshd.service", now=NOW,
                                 boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["active_state"] == "active"
    assert card["related"] == []


def test_device_card(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO device_state (dev_key, vendor, product, serial, subsystem, "
            "devnode, status, first_seen, last_seen, last_event_id) VALUES "
            "('/devices/usb1', '1d6b', '0002', 'ser1', 'usb', '/dev/usb1', 'present', "
            "?, ?, 'e1')",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="device", key="/devices/usb1", now=NOW,
                                 boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["vendor"] == "1d6b"


def test_user_card_unresolvable_user_not_found(tmp_path):
    # "zz-no-such-user" resolves no uid; with no matching rows the card is not found.
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        card = build_entity_card(db, kind="user", key="zz-no-such-user", now=NOW,
                                 boot_id=BOOT)
    assert card["found"] is False
```

- [ ] **Step 2: Run to verify failure** — `pytest tests/entities/ -v`: new tests FAIL
(`found is False` / missing header keys).

- [ ] **Step 3: Implement** the per-kind builders in `card.py` and wire the dispatch:

```python
def _executable_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    rows = db.query(
        "SELECT pid, boot_id, comm, exe_path, first_seen, last_seen "
        "FROM process_state WHERE exe_sha256 = ? ORDER BY pid "
        f"LIMIT {_RELATED_CAP}",
        [key],
    ).fetchall()
    if not rows:
        return False, {}, []
    header = {
        "sha256": key,
        "paths": sorted({r[3] for r in rows if r[3]}),
        "process_count": len(rows),
        "first_seen": _iso(min(r[4] for r in rows)),
        "last_seen": _iso(max(r[5] for r in rows)),
    }
    related = [
        _related_process(pid, boot, comm or str(pid), "runs-as")
        for pid, boot, comm, _path, _f, _l in rows
    ]
    return True, header, related


def _user_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    uid = _uid_for(key)
    header: dict[str, Any] = {"username": key, "uid": uid}
    if uid is None:
        return False, header, []
    rows = db.query(
        "SELECT pid, boot_id, comm FROM process_state WHERE uid = ? "
        f"ORDER BY pid LIMIT {_RELATED_CAP}",
        [uid],
    ).fetchall()
    related = [_related_process(pid, boot, comm or str(pid), "runs") for pid, boot, comm in rows]
    return True, header, related


def _ip_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    count, first_seen, last_seen = db.query(
        "SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM connection_state "
        "WHERE daddr = ? OR saddr = ?",
        [key, key],
    ).fetchone()
    if not count:
        return False, {}, []
    header = {"address": key, "connection_count": count,
              "first_seen": _iso(first_seen), "last_seen": _iso(last_seen)}
    related = []
    if boot_id is not None:
        for pid, comm in db.query(
            "SELECT DISTINCT pid, comm FROM connection_state "
            "WHERE (daddr = ? OR saddr = ?) AND pid IS NOT NULL "
            f"ORDER BY pid LIMIT {_RELATED_CAP}",
            [key, key],
        ).fetchall():
            related.append(_related_process(pid, boot_id, comm or str(pid), "talked-to"))
    return True, header, related


def _file_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    row = db.query(
        "SELECT path, change_type, sha256, size, mode, uid, gid, first_seen, last_seen "
        "FROM file_state WHERE path = ?",
        [key],
    ).fetchone()
    if row is None:
        return False, {}, []
    path, change_type, sha256, size, mode, uid, gid, first_seen, last_seen = row
    header = {"path": path, "change_type": change_type, "sha256": sha256, "size": size,
              "mode": mode, "uid": uid, "gid": gid,
              "first_seen": _iso(first_seen), "last_seen": _iso(last_seen)}
    related = []
    exe = db.query(
        "SELECT DISTINCT exe_sha256 FROM process_state "
        "WHERE exe_path = ? AND exe_sha256 IS NOT NULL LIMIT 1",
        [key],
    ).fetchone()
    if exe:
        related.append({"kind": "executable", "key": exe[0], "label": key,
                        "relation": "executed-as"})
    return True, header, related


def _port_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    addr, port, proto = _split_port_key(key)
    row = db.query(
        "SELECT addr, port, proto, family, pid, comm, first_seen, last_seen "
        "FROM listener_state WHERE addr = ? AND port = ? AND proto = ?",
        [addr, port, proto],
    ).fetchone()
    if row is None:
        return False, {}, []
    _a, _p, _pr, family, pid, comm, first_seen, last_seen = row
    header = {"addr": addr, "port": port, "proto": proto, "family": family,
              "pid": pid, "comm": comm,
              "first_seen": _iso(first_seen), "last_seen": _iso(last_seen)}
    related = []
    if pid is not None and boot_id is not None:
        related.append(_related_process(pid, boot_id, comm or str(pid), "owner"))
    return True, header, related


def _service_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    row = db.query(
        "SELECT unit, active_state, sub_state, load_state, first_seen, last_seen "
        "FROM service_state WHERE unit = ?",
        [key],
    ).fetchone()
    if row is None:
        return False, {}, []
    unit, active, sub, load, first_seen, last_seen = row
    return True, {"unit": unit, "active_state": active, "sub_state": sub,
                  "load_state": load, "first_seen": _iso(first_seen),
                  "last_seen": _iso(last_seen)}, []


def _device_header_related(
    db: Database, key: str, boot_id: str | None
) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
    row = db.query(
        "SELECT dev_key, vendor, product, serial, subsystem, devnode, status, "
        "first_seen, last_seen FROM device_state WHERE dev_key = ?",
        [key],
    ).fetchone()
    if row is None:
        return False, {}, []
    dev_key, vendor, product, serial, subsystem, devnode, status, first_seen, last_seen = row
    return True, {"dev_key": dev_key, "vendor": vendor, "product": product,
                  "serial": serial, "subsystem": subsystem, "devnode": devnode,
                  "status": status, "first_seen": _iso(first_seen),
                  "last_seen": _iso(last_seen)}, []


_BUILDERS = {
    "process": _process_header_related,
    "executable": _executable_header_related,
    "user": _user_header_related,
    "ip": _ip_header_related,
    "file": _file_header_related,
    "port": _port_header_related,
    "service": _service_header_related,
    "device": _device_header_related,
}
```

In `build_entity_card`, replace the Task-2 if/else stub with:

```python
    try:
        found, header, related = _BUILDERS[kind](db, key, boot_id)
    except Exception:  # noqa: BLE001 — degraded section beats a failed card (spec §7)
        warnings.append("header_failed")
```

(`_BUILDERS` must be defined above `build_entity_card` in the file.)

- [ ] **Step 4: Run tests** — `pytest tests/entities/ -v`: PASS.

- [ ] **Step 5: Run full gates.** Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add inspectord/entities/card.py tests/entities/test_card.py
git commit -m "feat(entities): executable/user/ip/file/port/service/device cards"
```

---

### Task 4: Events + alerts sections against real payloads

**Files:**
- Modify: `inspectord/entities/card.py` (only if tests expose bugs)
- Test: `tests/entities/test_card.py` (append)

- [ ] **Step 1: Write failing tests** — seed `events_enriched` through the real
`insert_event`, and `alerts` with a raw INSERT (column list in
`inspectord/storage/migrations_data/0003_alerts.sql`; include `payload_json`).
**First check `build_event`'s actual signature in `inspectord/parsers/base.py`** and
adjust the `_seed_event` kwargs (`type_` vs `type`, severity enum vs str, how ts is set)
to what it really takes:

```python
from inspectord.parsers.base import build_event
from inspectord.storage.events import insert_event


def _seed_event(db, *, ts, action="test_action", module="test", **fields):
    ev = build_event(
        module=module, action=action, category=["host"], type_=["info"],
        severity="info", **fields,
    )
    ev.ts = ts
    insert_event(db, ev, ev.model_dump_json(exclude_none=True))
    return ev


def test_events_section_matches_ip_and_respects_window(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        _seed_event(db, ts=NOW - timedelta(hours=1),
                    destination={"ip": "9.9.9.9", "port": 443})
        _seed_event(db, ts=NOW - timedelta(hours=48),  # outside 24 h window
                    destination={"ip": "9.9.9.9", "port": 443})
        _seed_event(db, ts=NOW - timedelta(hours=1),
                    destination={"ip": "1.1.1.1", "port": 53})
        card = build_entity_card(db, kind="ip", key="9.9.9.9", now=NOW, boot_id=BOOT)
    assert len(card["events"]) == 1
    assert card["events"][0]["payload"]["destination"]["ip"] == "9.9.9.9"


def test_events_cap(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        for i in range(110):
            _seed_event(db, ts=NOW - timedelta(minutes=i),
                        file={"path": "/etc/passwd"})
        card = build_entity_card(db, kind="file", key="/etc/passwd", now=NOW,
                                 boot_id=BOOT)
    assert len(card["events"]) == 100


def test_alerts_section_matches_process_pid(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, "
            "dedup_key, dedup_count, first_seen_at, last_seen_at, rendered_short, "
            "rendered_detail, payload_json) VALUES "
            "('a1', 'proc.test', ?, 'high', 'new', 'process', 'dk1', 1, ?, ?, "
            "'short', 'detail', ?)",
            [NOW, NOW, NOW, '{"process": {"pid": 4242}}'],
        )
        card = build_entity_card(db, kind="process", key=f"4242@{BOOT}", now=NOW,
                                 boot_id=BOOT)
    assert [a["alert_id"] for a in card["alerts"]] == ["a1"]
    assert card["found"] is False  # no state row; history still shown
```

(Before writing the alerts INSERT, check `0003_alerts.sql` for the full column list and
NOT NULL columns — extend the INSERT if the migration has more required columns than
shown here.)

- [ ] **Step 2: Run** — `pytest tests/entities/ -v`. The sections were implemented in
Task 2, so these may pass immediately; any FAIL is a real predicate/seeding bug — fix
until green. Expected end state: PASS.

- [ ] **Step 3: Run full gates.** Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/entities/test_card.py inspectord/entities/card.py
git commit -m "test(entities): event/alert matching against real payloads"
```

---

### Task 5: IPC handler + registration

**Files:**
- Create: `inspectord/entities/ipc_handlers.py`
- Modify: `inspectord/__main__.py` (import + one `Method` entry in `_ipc_methods`)
- Test: `tests/entities/test_ipc_handlers.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for the get_entity_card IPC handler."""

from __future__ import annotations

from pathlib import Path

from inspectord.entities.ipc_handlers import handle_get_entity_card
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def test_ok_shape(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_get_entity_card(
        params={"kind": "service", "key": "sshd.service"}, db_path=db_path
    )
    assert out["ok"] is True
    assert out["schema_version"] == "1.0.0"
    assert out["card"]["kind"] == "service"
    assert out["card"]["found"] is False


def test_invalid_kind_error_shape(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_get_entity_card(params={"kind": "nope", "key": "x"}, db_path=db_path)
    assert out == {"schema_version": "1.0.0", "ok": False, "error": "invalid_kind"}


def test_window_clamped(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_get_entity_card(
        params={"kind": "service", "key": "s.service", "window_h": 99999},
        db_path=db_path,
    )
    assert out["ok"] is True  # clamped, not rejected
```

For registration coverage: `grep -rn "_ipc_methods" tests/` first — if an existing test
builds the real method list (fake supervisor/config) asserting method names, extend it
with `get_entity_card`; only if no such pattern exists, add a source-level assertion:

```python
def test_registered_in_daemon_method_list():
    import inspect

    from inspectord.__main__ import _ipc_methods

    src = inspect.getsource(_ipc_methods)
    assert "get_entity_card" in src
```

- [ ] **Step 2: Run to verify failure** — `ModuleNotFoundError`.

- [ ] **Step 3: Implement `inspectord/entities/ipc_handlers.py`**

```python
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
                db, kind=kind, key=key, now=datetime.now(UTC), boot_id=boot_id,
                window_h=window_h,
            )
    except InvalidEntity as exc:
        return {"schema_version": _SCHEMA_VERSION, "ok": False, "error": str(exc)}
    return {"schema_version": _SCHEMA_VERSION, "ok": True, "card": card}
```

Registration in `inspectord/__main__.py` — add the import next to the other handler
imports and one entry inside `_ipc_methods`'s list, after the state-panel methods:

```python
from inspectord.entities.ipc_handlers import handle_get_entity_card
...
        Method(
            name="get_entity_card",
            handler=lambda params: handle_get_entity_card(
                params=params, db_path=cfg.storage.db_path
            ),
            mutates=False,
        ),
```

- [ ] **Step 4: Run tests** — `pytest tests/entities/ -v`: PASS.

- [ ] **Step 5: Run full gates + integration**
(`.venv/bin/python -m pytest -m "integration" -q` — the daemon fixture exercises
`_ipc_methods`, CI runs integration in a separate step, and a registration typo only
shows there). Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add inspectord/entities/ipc_handlers.py inspectord/__main__.py tests/entities/
git commit -m "feat(entities): get_entity_card IPC method"
```

---

### Task 6: Ship PR1

- [ ] **Step 1:** Full gates one more time (unit + integration + ruff check + ruff
format + mypy). Expected: all green.
- [ ] **Step 2:** `git push -u origin entity-context-cards`
- [ ] **Step 3:** `gh pr create` — title
`feat(entities): entity context cards — card builder + IPC (PR1)`; body summarizes the
spec (link it), notes the spec is autonomously drafted/unreviewed, lists the projector
exe-fields fix, ends with the standard generated-with footer.
- [ ] **Step 4:** `gh pr checks <N> --watch` until green.
- [ ] **Step 5:** `gh pr merge <N> --squash --delete-branch`, then
`git checkout main && git pull --ff-only`.
