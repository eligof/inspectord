"""Tests for the entity card builder (spec 2026-08-23-entity-context-cards)."""

from __future__ import annotations

from datetime import UTC, datetime
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


def _seed_process(
    db,
    pid,
    *,
    ppid=None,
    comm="proc",
    exe_sha=None,
    exe_path=None,
    uid=1000,
    boot=BOOT,
    status="running",
):
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
        _seed_process(
            db, 200, ppid=100, comm="target", exe_sha="ab" * 32, exe_path="/usr/bin/target"
        )
        _seed_process(db, 300, ppid=200, comm="child")
        db.execute(
            "INSERT INTO connection_state (conn_key, pid, comm, saddr, sport, daddr, "
            "dport, proto, family, status, first_seen, last_seen, last_event_id) VALUES "
            "('200:9.9.9.9:443:tcp', 200, 'target', '10.0.0.1', 5555, '9.9.9.9', 443, "
            "'tcp', 'inet', 'open', ?, ?, 'e2')",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="process", key=f"200@{BOOT}", now=NOW, boot_id=BOOT)
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
        card = build_entity_card(db, kind="process", key=f"9@{BOOT}", now=NOW, boot_id=BOOT)
    assert card["found"] is False
    assert card["events"] == []
    assert card["alerts"] == []
