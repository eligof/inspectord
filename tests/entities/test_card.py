"""Tests for the entity card builder (spec 2026-08-23-entity-context-cards)."""

from __future__ import annotations

import os
import pwd
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.entities.card import InvalidEntity, build_entity_card
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
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
    assert card["warnings"] == []


def test_process_card_not_found_still_returns_card(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        card = build_entity_card(db, kind="process", key=f"9@{BOOT}", now=NOW, boot_id=BOOT)
    assert card["found"] is False
    assert card["events"] == []
    assert card["alerts"] == []


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
        card = build_entity_card(db, kind="port", key="0.0.0.0:8080/tcp", now=NOW, boot_id=BOOT)
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
        card = build_entity_card(db, kind="service", key="sshd.service", now=NOW, boot_id=BOOT)
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
        card = build_entity_card(db, kind="device", key="/devices/usb1", now=NOW, boot_id=BOOT)
    assert card["found"] is True
    assert card["header"]["vendor"] == "1d6b"


def test_user_card_unresolvable_user_not_found(tmp_path):
    # "zz-no-such-user" resolves no uid; with no matching rows the card is not found.
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        card = build_entity_card(db, kind="user", key="zz-no-such-user", now=NOW, boot_id=BOOT)
    assert card["found"] is False


def _seed_event(db, *, ts, action="test_action", module="test", **fields):
    ev = build_event(
        module=module,
        action=action,
        category=["host"],
        type_=["info"],
        severity="info",
        ts=ts,
        **fields,
    )
    insert_event(db, ev, ev.model_dump_json(exclude_none=True))
    return ev


def test_events_section_matches_ip_and_respects_window(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        _seed_event(db, ts=NOW - timedelta(hours=1), destination={"ip": "9.9.9.9", "port": 443})
        _seed_event(
            db,
            ts=NOW - timedelta(hours=48),  # outside 24 h window
            destination={"ip": "9.9.9.9", "port": 443},
        )
        _seed_event(db, ts=NOW - timedelta(hours=1), destination={"ip": "1.1.1.1", "port": 53})
        card = build_entity_card(db, kind="ip", key="9.9.9.9", now=NOW, boot_id=BOOT)
    assert len(card["events"]) == 1
    assert card["events"][0]["payload"]["destination"]["ip"] == "9.9.9.9"


def test_events_cap(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        for i in range(110):
            _seed_event(db, ts=NOW - timedelta(minutes=i), file={"path": "/etc/passwd"})
        card = build_entity_card(db, kind="file", key="/etc/passwd", now=NOW, boot_id=BOOT)
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
        card = build_entity_card(db, kind="process", key=f"4242@{BOOT}", now=NOW, boot_id=BOOT)
    assert [a["alert_id"] for a in card["alerts"]] == ["a1"]
    assert card["found"] is False  # no state row; history still shown


# --- spec-review additions ---------------------------------------------------


def _seed_alert(db, alert_id, payload_json):
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, "
        "dedup_key, dedup_count, first_seen_at, last_seen_at, rendered_short, "
        "rendered_detail, payload_json) VALUES "
        "(?, 'r.test', ?, 'high', 'new', 'file', ?, 1, ?, ?, 'short', 'detail', ?)",
        [alert_id, NOW, alert_id, NOW, NOW, payload_json],
    )


def test_malformed_event_payload_degrades_events_section(tmp_path):
    # One malformed payload_json row poisons the section query; the card
    # degrades to an empty section plus a warning instead of failing (spec S7).
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO events_enriched (event_id, ts, kind, module, action, "
            "severity, payload_json) VALUES ('bad1', ?, 'event', 'test', "
            "'test_action', 'info', 'not json')",
            [NOW],
        )
        _seed_event(db, ts=NOW - timedelta(hours=1), file={"path": "/etc/passwd"})
        card = build_entity_card(db, kind="file", key="/etc/passwd", now=NOW, boot_id=BOOT)
    assert card["events"] == []
    assert "events_failed" in card["warnings"]


def test_malformed_alert_payload_degrades_alerts_section(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        _seed_alert(db, "bad1", "not json")
        _seed_alert(db, "ok1", '{"file": {"path": "/etc/passwd"}}')
        card = build_entity_card(db, kind="file", key="/etc/passwd", now=NOW, boot_id=BOOT)
    assert card["alerts"] == []
    assert "alerts_failed" in card["warnings"]


def test_user_card_resolvable_user_with_no_data_not_found(tmp_path):
    # Spec S3: user exists-check means "any event/process match", not a passwd hit.
    username = pwd.getpwuid(os.getuid()).pw_name
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        card = build_entity_card(db, kind="user", key=username, now=NOW, boot_id=BOOT)
    assert card["found"] is False


def test_user_card_found_via_process_match(tmp_path):
    username = pwd.getpwuid(os.getuid()).pw_name
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        _seed_process(db, 600, comm="shell", uid=os.getuid())
        card = build_entity_card(db, kind="user", key=username, now=NOW, boot_id=BOOT)
    assert card["found"] is True


def test_user_card_found_via_event_match(tmp_path):
    # Unresolvable user, but a matching event still flips found (spec S3).
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        _seed_event(db, ts=NOW - timedelta(hours=1), user={"name": "zz-no-such-user"})
        card = build_entity_card(db, kind="user", key="zz-no-such-user", now=NOW, boot_id=BOOT)
    assert card["found"] is True


def test_ip_card_saddr_only_header_found_related_empty(tmp_path):
    # Spec S4: saddr counts for the exists-check, but related pids match daddr only.
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO connection_state (conn_key, pid, comm, saddr, sport, daddr, "
            "dport, proto, family, status, first_seen, last_seen, last_event_id) VALUES "
            "('7:9.9.9.9:443:tcp', 7, 'curl', '4.4.4.4', 5555, '9.9.9.9', 443, 'tcp', "
            "'inet', 'open', ?, ?, 'e1')",
            [NOW, NOW],
        )
        card = build_entity_card(db, kind="ip", key="4.4.4.4", now=NOW, boot_id=BOOT)
    assert card["found"] is True
    assert card["related"] == []


def test_alerts_cap(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        for i in range(55):
            _seed_alert(db, f"a{i}", '{"file": {"path": "/etc/passwd"}}')
        card = build_entity_card(db, kind="file", key="/etc/passwd", now=NOW, boot_id=BOOT)
    assert len(card["alerts"]) == 50


def test_children_cap(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        _seed_process(db, 500, comm="parent")
        for i in range(25):
            _seed_process(db, 1000 + i, ppid=500, comm=f"c{i}")
        card = build_entity_card(db, kind="process", key=f"500@{BOOT}", now=NOW, boot_id=BOOT)
    children = [r for r in card["related"] if r["relation"] == "child"]
    assert len(children) == 20


@pytest.mark.parametrize("key", ["noproto", "0.0.0.0:x/tcp", ":80/tcp", "/tcp"])
def test_bad_port_keys_raise(tmp_path, key):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db, pytest.raises(InvalidEntity):
        build_entity_card(db, kind="port", key=key, now=NOW, boot_id=BOOT)
