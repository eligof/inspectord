"""Process-ancestry snapshot with secret scrubbing (proc-tree spec §3, §4).

`capture_process_tree` walks the ancestry chain (implicated pid → PID 1 or a
kernel-spawned root) and records identity, exe path + sha256, scrubbed command line,
cwd, uid/euid and redacted environment per node — so "who spawned this?" survives the
processes exiting. Pure, bounded, best-effort: per-field failures land in the node's
``errors`` list, never abort the walk.

The whole secret policy (spec §4) lives in the module constants below, reviewable at a
glance: name-based env redaction, exact-name exemptions, URL-credential scrub, a
known-prefix value backstop, and the cmdline scrub — one philosophy for both surfaces.
Variable NAMES are deliberately kept (forensic signal); values are what get redacted,
with no length leak.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.evidence.capture import _MAX_FILE_BYTES

log = logging.getLogger(__name__)

_MAX_DEPTH = 32  # ancestry nodes, root included (spec §3)
_MAX_ENV_BYTES = 64 * 1024  # env read cap; cap+1 read detects truncation (spec §3)
_MAX_CMDLINE_BYTES = 64 * 1024  # bounded like everything else (silent truncation)

_REDACTED = "<redacted>"
_REDACTED_EMPTY = "<redacted:empty>"  # empty value: distinct marker, still no length leak

# §4 rule 1 — redact the value when the variable NAME case-insensitively contains any
# of these. PASS subsumes PASSWORD/PASSWD/PASSPHRASE/SSHPASS/VAULT_PASS; _PWD catches
# MYSQL_PWD without hitting PWD/OLDPWD.
_SECRET_NAME_SUBSTRINGS: tuple[str, ...] = (
    "TOKEN",
    "SECRET",
    "PASS",
    "_PWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE",
    "CREDENTIAL",
    "AUTH",
    "SESSION",
    "COOKIE",
    "DSN",
    "ACCESS_KEY",
    "CONNECTION_STRING",
    "BEARER",
    "WEBHOOK",
)

# §4 rule 2 — exact-name exemptions, checked FIRST: desktop plumbing the investigator
# needs raw (their values are sockets/paths, not credentials).
_EXEMPT_NAMES: frozenset[str] = frozenset(
    {
        "SSH_AUTH_SOCK",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_SESSION_ID",
        "XDG_SESSION_TYPE",
        "XDG_SESSION_CLASS",
        "XDG_SESSION_DESKTOP",
        "SESSION_MANAGER",
    }
)

# §4 rule 3 — scheme://user:password@rest keeps scheme/user/host; only the password
# component is redacted (where it was exfiltrating to is signal; the password is not).
_URL_CRED_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+):([^/\s]+)@")

# §4 rule 4 — known-prefix backstop: unambiguous secret formats scrubbed regardless of
# name. Each pattern covers the full token (prefix + body) so no secret tail survives;
# the PEM pattern spans BEGIN..END (or end of value) for the same reason.
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"(?:ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]+"),  # GitHub tokens
    re.compile(r"glpat-[A-Za-z0-9_-]+"),  # GitLab PAT
    re.compile(r"sk-ant-[A-Za-z0-9_-]+"),  # Anthropic
    re.compile(r"(?:sk_live_|rk_live_)[A-Za-z0-9]+"),  # Stripe live keys
    re.compile(r"xox[bpca]-[A-Za-z0-9-]+"),  # Slack tokens
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),  # Google API key
    re.compile(
        r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?(?:-----END[A-Z ]*PRIVATE KEY-----|\Z)",
        re.DOTALL,
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT shape
)

# §4 rule 5 — cmdline scrub building blocks (positional cases live in scrub_cmdline).
_AUTH_HEADER_RE = re.compile(r"(?i)(authorization\s*:\s*).+$", re.DOTALL)
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)\S+")
_PASSWORD_FLAG_RE = re.compile(r"(?i)^(--password=).*$", re.DOTALL)
_USER_FLAG_RE = re.compile(r"^(--user=[^:]*:).+$", re.DOTALL)
_ENV_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)


def _name_is_secret(name: str) -> bool:
    upper = name.upper()
    return any(s in upper for s in _SECRET_NAME_SUBSTRINGS)


def scrub_value(value: str) -> str:
    """Rules 3+4: URL-credential scrub + known-prefix backstop, on any kept value."""
    value = _URL_CRED_RE.sub(rf"\1:{_REDACTED}@", value)
    for pattern in _SECRET_VALUE_PATTERNS:
        value = pattern.sub(_REDACTED, value)
    return value


def scrub_env_value(name: str, value: str) -> tuple[str, bool]:
    """Apply the §4 env policy to one variable. Returns (stored_value, was_redacted)."""
    if name in _EXEMPT_NAMES:  # rule 2 first
        scrubbed = scrub_value(value)
        return scrubbed, scrubbed != value
    if _name_is_secret(name):  # rule 1
        return (_REDACTED_EMPTY if value == "" else _REDACTED), True
    scrubbed = scrub_value(value)  # rules 3+4 on kept values
    return scrubbed, scrubbed != value


def _scrub_cmdline_arg(arg: str) -> str:
    scrubbed = _AUTH_HEADER_RE.sub(rf"\1{_REDACTED}", arg)
    scrubbed = _BEARER_RE.sub(rf"\1{_REDACTED}", scrubbed)
    scrubbed = _PASSWORD_FLAG_RE.sub(rf"\1{_REDACTED}", scrubbed)
    scrubbed = _USER_FLAG_RE.sub(rf"\1{_REDACTED}", scrubbed)
    assign = _ENV_ASSIGN_RE.match(scrubbed)
    if assign and assign.group(1) not in _EXEMPT_NAMES and _name_is_secret(assign.group(1)):
        return f"{assign.group(1)}={_REDACTED}"
    return scrub_value(scrubbed)


# Tools whose glued -pSECRET form carries the password (mysql family).
_GLUED_P_TOOLS = frozenset({"mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump"})


def scrub_cmdline(argv: list[str]) -> str:
    """Rule 5: scrub secret-bearing argv positions, everything else verbatim.

    Caveat: the 64 KiB cmdline read cap can in principle cut a credentialed
    URL just before its '@', leaving a partial password the URL rule cannot
    match — accepted (requires a >64 KiB cmdline straddling the boundary).
    """
    argv0 = os.path.basename(argv[0]) if argv else ""
    out: list[str] = []
    redact_next: str | None = None
    for arg in argv:
        if redact_next == "whole":
            if arg == "Bearer":
                # Three-arg header split ["Authorization:", "Bearer", "<token>"]:
                # keep the scheme word visible, redact the token that follows.
                out.append(arg)
            else:
                out.append(_REDACTED)
                redact_next = None
        elif redact_next == "colon":
            redact_next = None
            if ":" in arg:
                user, _, _pw = arg.partition(":")
                out.append(f"{user}:{_REDACTED}")
            else:
                out.append(_scrub_cmdline_arg(arg))
        elif arg in ("-u", "--user"):
            out.append(arg)
            redact_next = "colon"
        elif (argv0 == "sshpass" and arg == "-p") or arg == "--password":
            out.append(arg)
            redact_next = "whole"
        elif argv0 in _GLUED_P_TOOLS and arg.startswith("-p") and len(arg) > 2:
            out.append(f"-p{_REDACTED}")
        elif arg.lower().rstrip() == "authorization:":
            out.append(arg)
            redact_next = "whole"
        else:
            out.append(_scrub_cmdline_arg(arg))
    return shlex.join(out)


# --- walk (spec §3) ---


def _read_stat(proc_root: Path, pid: int) -> tuple[str, int] | None:
    """Return (comm, ppid) from /proc/<pid>/stat, or None if unreadable/unparseable.

    comm may contain spaces and parens — fields are parsed after the LAST ')'.
    """
    try:
        raw = (proc_root / str(pid) / "stat").read_bytes()
    except OSError:
        return None
    text = raw.decode("utf-8", "replace")
    open_paren = text.find("(")
    close_paren = text.rfind(")")
    if open_paren == -1 or close_paren == -1 or close_paren < open_paren:
        return None
    fields = text[close_paren + 1 :].split()
    if len(fields) < 2:
        return None
    try:
        ppid = int(fields[1])
    except ValueError:
        return None
    return text[open_paren + 1 : close_paren], ppid


def _read_link(d: Path, name: str, node: dict[str, Any], errors: list[str]) -> None:
    try:
        node[name] = os.readlink(d / name)
    except OSError as exc:
        errors.append(f"{name}: {exc!r}")


def _read_exe_sha(d: Path, node: dict[str, Any], errors: list[str]) -> None:
    # /proc/<pid>/exe content is readable even for deleted binaries — the whole point.
    hasher = hashlib.sha256()
    total = 0
    try:
        with (d / "exe").open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_FILE_BYTES:
                    errors.append(f"exe_sha256: exceeds {_MAX_FILE_BYTES} byte cap, omitted")
                    return
                hasher.update(chunk)
    except OSError as exc:
        errors.append(f"exe_sha256: {exc!r}")
        return
    node["exe_sha256"] = hasher.hexdigest()


def _read_cmdline(d: Path, node: dict[str, Any], errors: list[str]) -> None:
    try:
        with (d / "cmdline").open("rb") as fh:
            data = fh.read(_MAX_CMDLINE_BYTES)
    except OSError as exc:
        errors.append(f"cmdline: {exc!r}")
        return
    parts = data.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    argv = [p.decode("utf-8", "replace") for p in parts]
    node["cmdline"] = scrub_cmdline(argv)


def _read_uids(d: Path, node: dict[str, Any], errors: list[str]) -> None:
    try:
        text = (d / "status").read_bytes().decode("utf-8", "replace")
    except OSError as exc:
        errors.append(f"status: {exc!r}")
        return
    for line in text.splitlines():
        if not line.startswith("Uid:"):
            continue
        parts = line.split()
        try:
            node["uid"] = int(parts[1])
            node["euid"] = int(parts[2])  # real + effective: the setuid-escalation signal
            return
        except (IndexError, ValueError):
            break
    errors.append("status: Uid line missing or malformed")


def _read_environ(d: Path, node: dict[str, Any], errors: list[str]) -> None:
    try:
        with (d / "environ").open("rb") as fh:
            data = fh.read(_MAX_ENV_BYTES + 1)
    except OSError as exc:
        errors.append(f"environ: {exc!r}")
        return
    truncated = len(data) > _MAX_ENV_BYTES
    node["env_bytes"] = len(data)
    node["env_truncated"] = truncated
    if not data:  # zombies/kthreads: empty env is normal, NOT an error
        node["env"] = {}
        node["env_redacted"] = 0
        return
    parse_data = data
    if truncated and not data.endswith(b"\x00"):
        # the read hit the cap: the final fragment is not NUL-terminated → drop it
        parse_data = data[: data.rfind(b"\x00") + 1]
    pairs, malformed = _parse_environ(parse_data)
    if malformed:
        errors.append(f"environ: {malformed} malformed fragment(s) skipped")
    if not pairs:
        # non-empty content yielding zero parseable entries → env omitted
        errors.append("environ: no parseable entries, env omitted")
        return
    env: dict[str, str] = {}
    redacted = 0
    for name, value in pairs:
        scrubbed, was_redacted = scrub_env_value(name, value)
        env[name] = scrubbed
        redacted += int(was_redacted)
    node["env"] = env
    node["env_redacted"] = redacted


def _parse_environ(data: bytes) -> tuple[list[tuple[str, str]], int]:
    """Split NUL-separated environ content → ([(name, value), ...], malformed_count)."""
    pairs: list[tuple[str, str]] = []
    malformed = 0
    for frag in data.split(b"\x00"):
        if not frag:
            continue
        text = frag.decode("utf-8", "replace")
        name, sep, value = text.partition("=")
        if not sep or not name:
            malformed += 1
            continue
        pairs.append((name, value))
    return pairs, malformed


def _capture_node(proc_root: Path, pid: int, comm: str, ppid: int) -> dict[str, Any]:
    d = proc_root / str(pid)
    node: dict[str, Any] = {"pid": pid, "ppid": ppid, "comm": comm}
    errors: list[str] = []
    _read_link(d, "exe", node, errors)
    _read_exe_sha(d, node, errors)
    _read_link(d, "cwd", node, errors)
    _read_cmdline(d, node, errors)
    _read_uids(d, node, errors)
    _read_environ(d, node, errors)
    node["errors"] = errors
    return node


def capture_process_tree(pid: int, *, proc_root: str = "/proc") -> dict[str, Any] | None:
    """Snapshot the ancestry chain of `pid`. None if the root is already gone.

    Terminates (not truncated) at pid 1 inclusive or when ppid is 0 (kernel-spawned
    chains). `truncated: true` only for the depth cap or an ancestor vanishing
    mid-walk (prior nodes kept). An empty `nodes` list is never emitted.
    """
    root = Path(proc_root)
    parsed = _read_stat(root, pid)
    if parsed is None:
        return None  # dead root: no blob, no row
    nodes: list[dict[str, Any]] = []
    truncated = False
    current = pid
    for _ in range(_MAX_DEPTH):
        comm, ppid = parsed
        nodes.append(_capture_node(root, current, comm, ppid))
        if current == 1 or ppid == 0:
            break
        parsed = _read_stat(root, ppid)
        if parsed is None:
            truncated = True  # ancestor vanished mid-walk; keep what we have
            break
        current = ppid
    else:
        truncated = True  # depth cap
    return {
        "captured_at": datetime.now(tz=UTC).isoformat(),
        "root_pid": pid,
        "truncated": truncated,
        "nodes": nodes,
    }
