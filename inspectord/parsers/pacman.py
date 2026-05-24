"""Parser for /var/log/pacman.log entries."""

from __future__ import annotations

import re
from datetime import datetime

from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event

# [2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)
# [2026-05-24T14:23:12+0000] [ALPM] upgraded suricata (6.0.0-1 -> 7.0.0-1)
_LINE_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<src>[A-Z]+)\]\s+"
    r"(?P<verb>installed|removed|upgraded|reinstalled)\s+"
    r"(?P<name>\S+)\s+\((?P<vers>[^)]+)\)\s*$"
)

_VERB_TO_TYPE: dict[str, list[str]] = {
    "installed": ["installation"],
    "removed": ["deletion"],
    "upgraded": ["change"],
    "reinstalled": ["change"],
}


def parse_pacman_line(line: str, source: str) -> Event | None:
    line = line.rstrip("\n")
    if not line:
        return None
    match = _LINE_RE.match(line)
    if match is None:
        return None
    if match.group("src") != "ALPM":
        return None

    verb = match.group("verb")
    name = match.group("name")
    vers_field = match.group("vers")

    try:
        ts = datetime.fromisoformat(match.group("ts"))
    except ValueError:
        return None

    if verb == "upgraded" and "->" in vers_field:
        prev, _, new = vers_field.partition("->")
        package = {
            "name": name,
            "version": new.strip(),
            "previous_version": prev.strip(),
            "action": "upgraded",
        }
    else:
        package = {"name": name, "version": vers_field.strip(), "action": verb}

    return build_event(
        module="log_tailer",
        action=f"package_{verb}",
        category=["package"],
        type_=_VERB_TO_TYPE[verb],
        severity="info",
        message=f"{verb} {name} {vers_field}",
        package=package,
        raw={"source_file": source, "line": line, "fields": {}},
        ts=ts,
    )
