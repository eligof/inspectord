"""Tests for the persistence_snapshotter pure snapshot source.

All tests use ``tmp_path`` fixtures via an overridable ``Roots`` so they never
touch the real host.  The source must never raise on missing/unreadable input.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from inspectord.workers.persistence_snapshotter.source import (
    AUTHKEY,
    AUTOSTART,
    CRON,
    TIMER,
    Roots,
    _enum_cron,
    _parse_cron_line,
    default_roots,
    snapshot,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_roots(tmp_path: Path) -> Roots:
    """A Roots pointing entirely at non-existent paths under tmp_path."""
    missing = tmp_path / "nope"
    return Roots(
        etc_crontab=missing / "crontab",
        cron_d_dir=missing / "cron.d",
        run_parts_dirs=[missing / "cron.daily"],
        user_crontab=missing / "spool",
        timer_wants=[("system", missing / "timers.target.wants")],
        autostart_dirs=[missing / "autostart"],
        authorized_keys=missing / "authorized_keys",
    )


def _cron_key(path: Path, schedule: str, command: str) -> str:
    digest = hashlib.sha256(f"{schedule} {command}".encode()).hexdigest()[:12]
    return f"persist:cron:{path}:{digest}"


# ---------------------------------------------------------------------------
# _parse_cron_line
# ---------------------------------------------------------------------------


def test_parse_cron_line_with_user_field() -> None:
    assert _parse_cron_line("0 3 * * * root /usr/bin/backup", has_user_field=True) == (
        "0 3 * * *",
        "/usr/bin/backup",
    )


def test_parse_cron_line_without_user_field() -> None:
    assert _parse_cron_line("*/5 * * * * /home/u/run.sh", has_user_field=False) == (
        "*/5 * * * *",
        "/home/u/run.sh",
    )


def test_parse_cron_line_shortcut_with_user() -> None:
    assert _parse_cron_line("@daily root /usr/bin/backup", has_user_field=True) == (
        "@daily",
        "/usr/bin/backup",
    )


def test_parse_cron_line_shortcut_without_user() -> None:
    assert _parse_cron_line("@reboot /home/u/boot.sh", has_user_field=False) == (
        "@reboot",
        "/home/u/boot.sh",
    )


def test_parse_cron_line_skips_blank_comment_env() -> None:
    assert _parse_cron_line("", has_user_field=True) is None
    assert _parse_cron_line("   ", has_user_field=True) is None
    assert _parse_cron_line("# a comment", has_user_field=True) is None
    assert _parse_cron_line("PATH=/usr/bin:/bin", has_user_field=True) is None
    assert _parse_cron_line("FOO=bar", has_user_field=False) is None


def test_parse_cron_line_too_few_fields() -> None:
    assert _parse_cron_line("0 3 * *", has_user_field=True) is None


# ---------------------------------------------------------------------------
# _enum_cron — system crontab
# ---------------------------------------------------------------------------


def test_enum_cron_system_crontab(tmp_path: Path) -> None:
    crontab = tmp_path / "crontab"
    crontab.write_text(
        "# /etc/crontab\n"
        "PATH=/usr/bin\n"
        "\n"
        "@daily root /usr/bin/backup\n"
        "0 3 * * * root /usr/bin/backup\n"
    )
    roots = _empty_roots(tmp_path)
    roots.etc_crontab = crontab
    entries, readable = _enum_cron(roots)
    assert readable is True

    k1 = _cron_key(crontab, "@daily", "/usr/bin/backup")
    k2 = _cron_key(crontab, "0 3 * * *", "/usr/bin/backup")
    assert set(entries) == {k1, k2}
    assert entries[k1]["kind"] == CRON
    assert entries[k1]["name"] == "/usr/bin/backup"
    assert entries[k1]["details"] == "@daily root /usr/bin/backup"
    assert entries[k1]["source_path"] == str(crontab)


def test_enum_cron_d_dir(tmp_path: Path) -> None:
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    job = cron_d / "job"
    job.write_text("*/10 * * * * root /usr/bin/poll\n")
    roots = _empty_roots(tmp_path)
    roots.cron_d_dir = cron_d
    entries, readable = _enum_cron(roots)
    assert readable is True
    k = _cron_key(job, "*/10 * * * *", "/usr/bin/poll")
    assert k in entries
    assert entries[k]["name"] == "/usr/bin/poll"


def test_enum_cron_user_crontab_no_user_field(tmp_path: Path) -> None:
    spool = tmp_path / "spool_user"
    spool.write_text("*/5 * * * * /home/u/run.sh\n")
    roots = _empty_roots(tmp_path)
    roots.user_crontab = spool
    entries, readable = _enum_cron(roots)
    assert readable is True
    k = _cron_key(spool, "*/5 * * * *", "/home/u/run.sh")
    assert k in entries
    assert entries[k]["name"] == "/home/u/run.sh"


def test_enum_cron_run_parts(tmp_path: Path) -> None:
    daily = tmp_path / "cron.daily"
    daily.mkdir()
    script = daily / "logrotate"
    script.write_text("#!/bin/sh\necho hi\n")
    roots = _empty_roots(tmp_path)
    roots.run_parts_dirs = [daily]
    entries, readable = _enum_cron(roots)
    assert readable is True
    k = f"persist:cron:{script}"
    assert k in entries
    assert entries[k]["name"] == "logrotate"
    assert entries[k]["details"] == f"run-parts {daily}"
    assert entries[k]["source_path"] == str(script)


def test_enum_cron_malformed_line_never_raises(tmp_path: Path) -> None:
    crontab = tmp_path / "crontab"
    crontab.write_text("this is not valid\n0 3 * * * root /ok\n")
    roots = _empty_roots(tmp_path)
    roots.etc_crontab = crontab
    entries, readable = _enum_cron(roots)
    assert readable is True
    # the valid line still parsed; the malformed one skipped, no raise
    assert any(e["name"] == "/ok" for e in entries.values())


def test_enum_cron_all_missing_marks_unreadable(tmp_path: Path) -> None:
    roots = _empty_roots(tmp_path)
    entries, readable = _enum_cron(roots)
    assert entries == {}
    assert readable is False


def test_snapshot_all_missing_returns_all_failed(tmp_path: Path) -> None:
    entries, failed = snapshot(_empty_roots(tmp_path))
    assert entries == {}
    assert failed == {CRON, TIMER, AUTOSTART, AUTHKEY}


def test_default_roots_is_roots() -> None:
    assert isinstance(default_roots(), Roots)
