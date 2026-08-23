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

KINDS = frozenset({"process", "executable", "user", "ip", "file", "port", "service", "device"})
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
    return {
        "kind": "process",
        "key": f"{pid}@{boot}",
        "label": label,
        "relation": relation,
    }


def _uid_for(username: str) -> int | None:
    try:
        return pwd.getpwnam(username).pw_uid
    except (KeyError, OSError):
        return None


# --- per-kind event/alert payload predicates --------------------------------
# Fragments run against payload_json with json_extract_string; params returned
# alongside. ``None`` = this kind has no event scan (spec §6: port).


def _payload_predicate(  # noqa: PLR0911 — one return per entity kind
    kind: str, key: str
) -> tuple[str, list[Any]] | None:
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
            {
                "event_id": event_id,
                "ts": _iso(ts),
                "module": module,
                "action": action,
                "severity": severity,
                "payload": payload,
            }
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
        {
            "alert_id": a,
            "rule_id": r,
            "ts": _iso(ts),
            "severity": sev,
            "status": st,
            "rendered_short": short,
        }
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
    (
        _,
        _,
        ppid,
        comm,
        exe_path,
        exe_sha,
        uid,
        cmdline,
        status,
        exit_code,
        first_seen,
        last_seen,
    ) = row
    header = {
        "pid": pid,
        "boot_id": boot,
        "ppid": ppid,
        "comm": comm,
        "exe_path": exe_path,
        "exe_sha256": exe_sha,
        "uid": uid,
        "cmdline": cmdline,
        "status": status,
        "exit_code": exit_code,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
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
        related.append(
            {
                "kind": "executable",
                "key": exe_sha,
                "label": exe_path or exe_sha[:12],
                "relation": "executable",
            }
        )
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
    row = db.query(
        "SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM connection_state "
        "WHERE daddr = ? OR saddr = ?",
        [key, key],
    ).fetchone()
    if row is None or not row[0]:  # aggregate always yields a row; guard for mypy
        return False, {}, []
    count, first_seen, last_seen = row
    header = {
        "address": key,
        "connection_count": count,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
    }
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
    header = {
        "path": path,
        "change_type": change_type,
        "sha256": sha256,
        "size": size,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
    }
    related = []
    exe = db.query(
        "SELECT DISTINCT exe_sha256 FROM process_state "
        "WHERE exe_path = ? AND exe_sha256 IS NOT NULL LIMIT 1",
        [key],
    ).fetchone()
    if exe:
        related.append(
            {"kind": "executable", "key": exe[0], "label": key, "relation": "executed-as"}
        )
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
    header = {
        "addr": addr,
        "port": port,
        "proto": proto,
        "family": family,
        "pid": pid,
        "comm": comm,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
    }
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
    return (
        True,
        {
            "unit": unit,
            "active_state": active,
            "sub_state": sub,
            "load_state": load,
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
        },
        [],
    )


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
    return (
        True,
        {
            "dev_key": dev_key,
            "vendor": vendor,
            "product": product,
            "serial": serial,
            "subsystem": subsystem,
            "devnode": devnode,
            "status": status,
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
        },
        [],
    )


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
    found = False
    header: dict[str, Any] = {}
    related: list[dict[str, Any]] = []
    try:
        found, header, related = _BUILDERS[kind](db, key, boot_id)
    # Broad excepts: a degraded section beats a failed card (spec §7).
    except Exception:
        warnings.append("header_failed")
    try:
        events = _events_section(db, kind, key, now, window_h)
    except Exception:
        events, warnings = [], [*warnings, "events_failed"]
    try:
        alerts = _alerts_section(db, kind, key)
    except Exception:
        alerts, warnings = [], [*warnings, "alerts_failed"]
    return {
        "kind": kind,
        "key": key,
        "found": found,
        "header": header,
        "events": events,
        "alerts": alerts,
        "related": related[:_RELATED_CAP],
        "warnings": warnings,
    }
