"""persistence_snapshotter source — pure, filesystem-only inventory of host persistence.

Four enumerators (cron, systemd timers, XDG autostart, ``authorized_keys``) are
merged by :func:`snapshot` into ``{persist_key: attrs}``.

**No subprocess use anywhere** — every source is read directly off the filesystem
(no ``systemctl``, ``crontab -l``, or ``ssh-keygen``).

**Robustness contract (spec §3.1):** a parse error on *readable* content skips
that one entry; a *missing or unreadable* source (absent file/dir, OSError,
PermissionError) contributes zero entries and marks its kind unreadable.
``snapshot()`` and every enumerator MUST NEVER raise on bad/missing input.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# kind constants (locked — the worker, projector, and spec depend on these)
CRON, TIMER, AUTOSTART, AUTHKEY = "cron", "timer", "autostart", "authorized_key"

# Privacy bound: cron commands / Exec lines / key comments embed secrets (spec §6.2).
_DETAILS_MAX = 256

# Known SSH public-key type prefixes (spec §3.1.3).
_SSH_KEYTYPES: tuple[str, ...] = (
    "ssh-rsa",
    "ssh-ed25519",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)


@dataclass
class Roots:
    """Overridable base paths so tests use ``tmp_path``, not the real host."""

    etc_crontab: Path
    cron_d_dir: Path
    run_parts_dirs: list[Path]  # /etc/cron.{hourly,daily,weekly,monthly}
    user_crontab: Path  # /var/spool/cron/<user>
    timer_wants: list[tuple[str, Path]]  # (scope, .../timers.target.wants dir)
    autostart_dirs: list[Path]  # ~/.config/autostart, /etc/xdg/autostart
    authorized_keys: Path  # ~/.ssh/authorized_keys


def default_roots() -> Roots:
    """Return the real host paths from spec §3.1, relative to the invoking user."""
    home = Path.home()
    return Roots(
        etc_crontab=Path("/etc/crontab"),
        cron_d_dir=Path("/etc/cron.d"),
        run_parts_dirs=[
            Path("/etc/cron.hourly"),
            Path("/etc/cron.daily"),
            Path("/etc/cron.weekly"),
            Path("/etc/cron.monthly"),
        ],
        user_crontab=Path("/var/spool/cron") / os.environ.get("USER", "root"),
        timer_wants=[
            ("system", Path("/etc/systemd/system/timers.target.wants")),
            ("system", Path("/usr/lib/systemd/system/timers.target.wants")),
            ("user", home / ".config/systemd/user/timers.target.wants"),
            ("user", Path("/etc/systemd/user/timers.target.wants")),
        ],
        autostart_dirs=[
            home / ".config/autostart",
            Path("/etc/xdg/autostart"),
        ],
        authorized_keys=home / ".ssh/authorized_keys",
    )


def _bound_details(text: str) -> str:
    """Bound *text* to ``_DETAILS_MAX`` chars, ending with ``…`` if truncated."""
    if len(text) <= _DETAILS_MAX:
        return text
    return text[:_DETAILS_MAX] + "…"


# ---------------------------------------------------------------------------
# Cron (3 sub-parsers — spec §3.1.1)
# ---------------------------------------------------------------------------


def _parse_cron_line(line: str, has_user_field: bool) -> tuple[str, str] | None:
    """Parse one crontab line into ``(schedule, command)`` or ``None``.

    Skips blank lines, ``#`` comments, and ``NAME=value`` environment
    assignments.  Supports ``@``-shortcuts (``@daily``, ``@reboot``, …).
    Returns ``None`` when there are too few fields to form a command.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    # ENV=value assignment line: a leading NAME= token with no schedule.
    first_token = stripped.split(None, 1)[0]
    if "=" in first_token and first_token.split("=", 1)[0].isidentifier():
        return None

    if stripped.startswith("@"):
        # @shortcut [user] command
        n_fields = 3 if has_user_field else 2
        parts = stripped.split(None, n_fields - 1)
        if len(parts) < n_fields:
            return None
        schedule = parts[0]
        command = parts[-1]
        return schedule, command

    # 5-field schedule [user] command
    n_lead = 6 if has_user_field else 5
    parts = stripped.split(None, n_lead)
    if len(parts) <= n_lead:
        return None
    schedule = " ".join(parts[:5])
    command = parts[n_lead]
    return schedule, command


def _cron_key(path: Path, schedule: str, command: str) -> str:
    digest = hashlib.sha256(f"{schedule} {command}".encode()).hexdigest()[:12]
    return f"persist:cron:{path}:{digest}"


def _enum_cron(roots: Roots) -> tuple[dict[str, dict[str, Any]], bool]:
    """Enumerate cron persistence across the three sub-parsers.

    Returns ``(entries, readable)``; ``readable`` is True if *any* cron source
    was successfully read this call.
    """
    entries: dict[str, dict[str, Any]] = {}
    any_readable = False

    def _parse_crontab(path: Path, has_user_field: bool) -> bool:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return False
        for raw in text.splitlines():
            parsed = _parse_cron_line(raw, has_user_field)
            if parsed is None:
                continue
            schedule, command = parsed
            key = _cron_key(path, schedule, command)
            entries[key] = {
                "kind": CRON,
                "name": command,
                "source_path": str(path),
                "details": _bound_details(raw.strip()),
                "key": key,
            }
        return True

    # System crontab (schedule user command)
    if _parse_crontab(roots.etc_crontab, has_user_field=True):
        any_readable = True

    # /etc/cron.d/* (schedule user command)
    try:
        cron_d_files = sorted(p for p in roots.cron_d_dir.iterdir() if p.is_file())
    except OSError:
        cron_d_files = []
    else:
        any_readable = True
    for fpath in cron_d_files:
        _parse_crontab(fpath, has_user_field=True)

    # User crontab (schedule command — no user field)
    if _parse_crontab(roots.user_crontab, has_user_field=False):
        any_readable = True

    # Run-parts dirs: each entry is a script file, keyed by path (no hash).
    for rp_dir in roots.run_parts_dirs:
        try:
            scripts = sorted(p for p in rp_dir.iterdir() if p.is_file())
        except OSError:
            continue
        any_readable = True
        for script in scripts:
            key = f"persist:cron:{script}"
            entries[key] = {
                "kind": CRON,
                "name": script.name,
                "source_path": str(script),
                "details": _bound_details(f"run-parts {rp_dir}"),
                "key": key,
            }

    return entries, any_readable


# ---------------------------------------------------------------------------
# Timers (enabled-only — spec §3.1.2)
# ---------------------------------------------------------------------------


def _enum_timers(roots: Roots) -> tuple[dict[str, dict[str, Any]], bool]:
    """Enumerate enabled systemd timers via ``timers.target.wants`` symlinks.

    Returns ``(entries, readable)``; ``readable`` is True if *any* wants dir was
    listable this call.  Masked (``→ /dev/null``) and template (``*@.timer``)
    units are skipped.
    """
    entries: dict[str, dict[str, Any]] = {}
    any_readable = False

    for scope, wants_dir in roots.timer_wants:
        try:
            links = sorted(p for p in wants_dir.iterdir() if p.name.endswith(".timer"))
        except OSError:
            continue
        any_readable = True
        for link in links:
            unit = link.name
            if unit.endswith("@.timer"):
                continue  # template unit
            try:
                target = os.path.realpath(link)
            except OSError:
                continue
            if target == "/dev/null":
                continue  # masked
            details = ""
            try:
                unit_text = Path(target).read_text(errors="replace")
            except OSError:
                unit_text = ""
            schedule_lines = [
                ln.strip()
                for ln in unit_text.splitlines()
                if ln.strip().startswith(("OnCalendar=", "OnBootSec="))
            ]
            if schedule_lines:
                details = " ".join(schedule_lines)
            key = f"persist:timer:{scope}:{unit}"
            entries[key] = {
                "kind": TIMER,
                "name": unit,
                "source_path": target,
                "details": _bound_details(details),
                "key": key,
            }

    return entries, any_readable


# ---------------------------------------------------------------------------
# Autostart (spec §3.1) + authorized_keys (spec §3.1.3)
# ---------------------------------------------------------------------------


def _enum_autostart(roots: Roots) -> tuple[dict[str, dict[str, Any]], bool]:
    """Enumerate ``*.desktop`` autostart entries.

    Parses minimally: the first top-level ``Name=`` and ``Exec=``.  A file with
    no ``Exec=`` is skipped.  Returns ``(entries, readable)``.
    """
    entries: dict[str, dict[str, Any]] = {}
    any_readable = False

    for ad in roots.autostart_dirs:
        try:
            desktops = sorted(p for p in ad.iterdir() if p.name.endswith(".desktop"))
        except OSError:
            continue
        any_readable = True
        for dfile in desktops:
            try:
                text = dfile.read_text(errors="replace")
            except OSError:
                continue
            name = None
            exec_val = None
            for raw in text.splitlines():
                ln = raw.strip()
                if name is None and ln.startswith("Name="):
                    name = ln[len("Name=") :]
                elif exec_val is None and ln.startswith("Exec="):
                    exec_val = ln[len("Exec=") :]
            if exec_val is None:
                continue  # nothing to launch → not a persistence vector
            key = f"persist:autostart:{dfile}"
            entries[key] = {
                "kind": AUTOSTART,
                "name": name or dfile.name,
                "source_path": str(dfile),
                "details": _bound_details(exec_val),
                "key": key,
            }

    return entries, any_readable


def _ssh_fingerprint(blob: bytes) -> str:
    """Render a SHA-256 fingerprint matching ``ssh-keygen -E sha256``."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _parse_authorized_key_line(line: str) -> dict[str, Any] | None:
    """Parse one ``authorized_keys`` line into an entry attrs dict, or ``None``.

    Options-prefixed lines (``command="..." ssh-ed25519 AAAA... comment``) are
    handled by scanning tokens for the first known keytype.  The base64 blob is
    decoded and its embedded length-prefixed type validated; any mismatch or
    decode error returns ``None``.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    tokens = stripped.split()
    keytype_idx = None
    for i, tok in enumerate(tokens):
        if tok in _SSH_KEYTYPES:
            keytype_idx = i
            break
    if keytype_idx is None or keytype_idx + 1 >= len(tokens):
        return None
    keytype = tokens[keytype_idx]
    b64field = tokens[keytype_idx + 1]
    try:
        blob = base64.b64decode(b64field, validate=True)
    except ValueError:  # binascii.Error subclasses ValueError
        return None
    # Validate embedded length-prefixed type string equals the keytype.
    try:
        (type_len,) = struct.unpack(">I", blob[:4])
        embedded = blob[4 : 4 + type_len].decode("ascii")
    except (struct.error, UnicodeDecodeError, ValueError):
        return None
    if embedded != keytype:
        return None
    fingerprint = _ssh_fingerprint(blob)
    comment = " ".join(tokens[keytype_idx + 2 :]) or fingerprint
    key = f"persist:authkey:{keytype}:{fingerprint}"
    return {
        "kind": AUTHKEY,
        "name": comment,
        "source_path": None,  # filled in by the caller
        "details": _bound_details(f"{keytype} {fingerprint}"),
        "key": key,
    }


def _enum_authorized_keys(roots: Roots) -> tuple[dict[str, dict[str, Any]], bool]:
    """Enumerate SSH ``authorized_keys`` entries.  Returns ``(entries, readable)``."""
    entries: dict[str, dict[str, Any]] = {}
    try:
        text = roots.authorized_keys.read_text(errors="replace")
    except OSError:
        return entries, False
    for raw in text.splitlines():
        attrs = _parse_authorized_key_line(raw)
        if attrs is None:
            continue
        attrs["source_path"] = str(roots.authorized_keys)
        entries[attrs["key"]] = attrs
    return entries, True


# ---------------------------------------------------------------------------
# snapshot()
# ---------------------------------------------------------------------------


def snapshot(roots: Roots | None = None) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Return ``({persist_key: attrs}, failed_kinds)``.

    ``attrs`` keys are exactly ``{"kind", "name", "source_path", "details",
    "key"}`` (``key`` duplicates the dict key for the event block).
    ``failed_kinds`` ⊆ ``{CRON, TIMER, AUTOSTART, AUTHKEY}`` — kinds whose source
    was unreadable this call.  Never raises.
    """
    if roots is None:
        roots = default_roots()

    merged: dict[str, dict[str, Any]] = {}
    failed: set[str] = set()

    for kind, enumerator in (
        (CRON, _enum_cron),
        (TIMER, _enum_timers),
        (AUTOSTART, _enum_autostart),
        (AUTHKEY, _enum_authorized_keys),
    ):
        entries, readable = enumerator(roots)
        if not readable:
            failed.add(kind)
        for key, attrs in entries.items():
            attrs["key"] = key  # invariant: attrs["key"] == its dict key
            attrs["details"] = _bound_details(attrs.get("details") or "")
            merged[key] = attrs

    return merged, failed
