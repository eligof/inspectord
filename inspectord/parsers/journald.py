"""Parser for journalctl --output=json entries."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Any

from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event

_PRIORITY_SEVERITY: dict[int, str] = {
    0: "high",
    1: "high",
    2: "high",
    3: "high",
    4: "medium",
    5: "low",
    6: "info",
    7: "info",
}


def _severity_from_priority(value: object) -> str:
    try:
        p = int(str(value)) if value is not None else 6
    except (TypeError, ValueError):
        return "info"
    return _PRIORITY_SEVERITY.get(p, "info")


def _ts_from_realtime(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        micros = int(str(value))
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(micros / 1_000_000, UTC)


def parse_journald_entry(entry: dict[str, Any], source: str) -> Event | None:
    if not isinstance(entry, dict):
        return None
    message = entry.get("MESSAGE")
    if not isinstance(message, str) or not message:
        return None

    pid_raw = entry.get("_PID")
    uid_raw = entry.get("_UID")
    comm = entry.get("_COMM")
    exe = entry.get("_EXE")
    unit = entry.get("_SYSTEMD_UNIT")
    hostname = entry.get("_HOSTNAME")
    priority = entry.get("PRIORITY")

    process: dict[str, Any] | None = None
    if isinstance(comm, str) or pid_raw is not None or isinstance(exe, str):
        process = {}
        if isinstance(comm, str):
            process["name"] = comm
        if pid_raw is not None:
            with contextlib.suppress(TypeError, ValueError):
                process["pid"] = int(pid_raw)
        if isinstance(exe, str):
            process["executable"] = exe

    user: dict[str, Any] | None = None
    if uid_raw is not None:
        try:
            user = {"id": int(uid_raw)}
        except (TypeError, ValueError):
            user = None

    service: dict[str, Any] | None = None
    if isinstance(unit, str):
        name = unit
        if name.endswith(".service"):
            name = name[: -len(".service")]
        service = {"name": name, "unit": unit}

    host: dict[str, Any] | None = None
    if isinstance(hostname, str):
        host = {"hostname": hostname, "os": {"family": "linux"}}

    ts = _ts_from_realtime(entry.get("__REALTIME_TIMESTAMP"))

    return build_event(
        module="log_tailer",
        action="journal_message",
        category=["host"],
        type_=["info"],
        severity=_severity_from_priority(priority),
        message=message,
        process=process,
        user=user,
        service=service,
        host=host,
        raw={"source_file": source, "line": message, "fields": entry},
        ts=ts,
    )
