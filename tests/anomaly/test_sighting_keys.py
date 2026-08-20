"""sighting_keys() extraction for the five starter cases (spec §3)."""

from __future__ import annotations

from inspectord.anomaly.first_sighting import SightingKey, sighting_keys
from inspectord.parsers.base import build_event


def test_binary_prefers_hash_over_path() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={
            "pid": 1,
            "name": "xz",
            "executable": "/usr/bin/xz",
            "hash": {"sha256": "deadbeef"},
        },
    )
    assert sighting_keys(ev) == [SightingKey("process", "binary", "deadbeef")]


def test_binary_falls_back_to_executable_then_skips() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1, "name": "xz", "executable": "/usr/bin/xz"},
    )
    assert sighting_keys(ev) == [SightingKey("process", "binary", "/usr/bin/xz")]
    bare = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1, "name": "kworker/0:1"},
    )
    assert sighting_keys(bare) == []


def test_outbound_dest_key() -> None:
    ev = build_event(
        module="outbound_connection_tracker",
        action="outbound_connection",
        category=["network"],
        type_=["connection", "start"],
        severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
    )
    assert sighting_keys(ev) == [SightingKey("network", "proc_dest", "curl->203.0.113.9:443")]


def test_outbound_ipv6_worker_matches_by_action() -> None:
    ev = build_event(
        module="outbound_connection_tracker6",
        action="outbound_connection",
        category=["network"],
        type_=["connection", "start"],
        severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "2001:db8::9", "port": 443},
    )
    assert sighting_keys(ev)[0].entity_key == "curl->2001:db8::9:443"


def test_login_ip_key() -> None:
    ev = build_event(
        module="log_tailer",
        action="ssh_login_succeeded",
        category=["authentication"],
        type_=["start"],
        severity="info",
        outcome="success",
        user={"name": "eli"},
        source={"ip": "198.51.100.7", "port": 50000},
    )
    assert sighting_keys(ev) == [SightingKey("authentication", "login_ip", "198.51.100.7")]


def test_failed_login_is_not_a_sighting() -> None:
    ev = build_event(
        module="log_tailer",
        action="ssh_login_failed",
        category=["authentication"],
        type_=["start"],
        severity="low",
        outcome="failure",
        source={"ip": "198.51.100.7"},
    )
    assert sighting_keys(ev) == []


def test_kmod_key_from_raw() -> None:
    ev = build_event(
        module="kmod_watcher",
        action="kmod_loaded",
        category=["driver"],
        type_=["installation"],
        severity="info",
        raw={"source": "/proc/modules", "module_name": "nft_ct"},
    )
    assert sighting_keys(ev) == [SightingKey("driver", "kmod", "nft_ct")]


def test_suid_key_requires_setuid_true() -> None:
    suid = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["creation"],
        severity="info",
        file={"path": "/usr/local/bin/backdoor", "setuid": True},
    )
    assert sighting_keys(suid) == [SightingKey("file", "suid", "/usr/local/bin/backdoor")]
    plain = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["creation"],
        severity="info",
        file={"path": "/tmp/x", "setuid": False},
    )
    assert sighting_keys(plain) == []
