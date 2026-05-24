"""Parser for /var/log/auth.log (Debian-family format)."""

from __future__ import annotations

import re

from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event

_SSH_ACCEPTED_RE = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Accepted\s+\S+\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_SSH_FAILED_RE = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Failed\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_SUDO_RE = re.compile(
    r"sudo:\s*(?P<user>\S+)\s*:\s+TTY=\S+\s*;\s+PWD=\S+\s*;\s+USER=(?P<target>\S+)\s*;\s+COMMAND=(?P<cmd>.+)$"
)


def parse_auth_log_line(line: str, source: str) -> Event | None:
    line = line.rstrip("\n")
    if not line:
        return None

    m = _SSH_ACCEPTED_RE.search(line)
    if m is not None:
        return build_event(
            module="log_tailer",
            action="ssh_login_succeeded",
            category=["authentication"],
            type_=["start"],
            severity="info",
            outcome="success",
            message=f"sshd accepted login for {m.group('user')} from {m.group('ip')}",
            user={"name": m.group("user")},
            process={"name": "sshd", "pid": int(m.group("pid"))},
            source={"ip": m.group("ip"), "port": int(m.group("port"))},
            raw={"source_file": source, "line": line, "fields": {}},
        )

    m = _SSH_FAILED_RE.search(line)
    if m is not None:
        return build_event(
            module="log_tailer",
            action="ssh_login_failed",
            category=["authentication"],
            type_=["end"],
            severity="medium",
            outcome="failure",
            message=f"sshd failed login for {m.group('user')} from {m.group('ip')}",
            user={"name": m.group("user")},
            process={"name": "sshd", "pid": int(m.group("pid"))},
            source={"ip": m.group("ip"), "port": int(m.group("port"))},
            raw={"source_file": source, "line": line, "fields": {}},
        )

    m = _SUDO_RE.search(line)
    if m is not None:
        return build_event(
            module="log_tailer",
            action="sudo_invoked",
            category=["iam"],
            type_=["start"],
            severity="info",
            outcome="success",
            message=f"sudo: {m.group('user')} ran '{m.group('cmd')}' as {m.group('target')}",
            user={"name": m.group("user"), "effective": {"name": m.group("target")}},
            process={"name": "sudo", "command_line": m.group("cmd")},
            raw={"source_file": source, "line": line, "fields": {}},
        )

    return None
