"""Event → MetricSample extraction (spec §4.1 table)."""

from __future__ import annotations

from inspectord.anomaly.metrics import extract_samples
from inspectord.parsers.base import build_event


def _kinds(ev):
    return sorted(s.metric_kind for s in extract_samples(ev))


def test_process_event_feeds_events_per_min() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1, "name": "xz"},
    )
    samples = [s for s in extract_samples(ev) if s.metric_kind == "events_per_min"]
    assert len(samples) == 1
    s = samples[0]
    assert s.entity_key == "xz:process"
    assert s.entity == {"process": {"name": "xz"}}
    assert s.value == 1.0


def test_outbound_connection_feeds_conn_rate_and_events() -> None:
    ev = build_event(
        module="outbound_connection_tracker",
        action="outbound_connection",
        category=["network"],
        type_=["connection", "start"],
        severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
    )
    kinds = _kinds(ev)
    assert "new_conn_per_min" in kinds
    assert "events_per_min" in kinds
    assert "egress_bytes_per_min" not in kinds  # no byte count on the event


def test_egress_bytes_when_present() -> None:
    ev = build_event(
        module="outbound_connection_tracker",
        action="outbound_connection",
        category=["network"],
        type_=["connection", "start"],
        severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
        network={"transport": "tcp", "direction": "egress", "bytes": 4096},
    )
    egress = [s for s in extract_samples(ev) if s.metric_kind == "egress_bytes_per_min"]
    assert len(egress) == 1
    assert egress[0].value == 4096.0
    assert egress[0].entity_key == "curl"


def test_login_feeds_logins_per_min() -> None:
    ev = build_event(
        module="log_tailer",
        action="ssh_login_succeeded",
        category=["authentication"],
        type_=["start"],
        severity="info",
        outcome="success",
        user={"name": "eli"},
        process={"name": "sshd", "pid": 4242},
        source={"ip": "198.51.100.7"},
    )
    logins = [s for s in extract_samples(ev) if s.metric_kind == "logins_per_min"]
    assert len(logins) == 1
    assert logins[0].entity_key == "eli"
    assert logins[0].entity == {"user": {"name": "eli"}}


def test_sudo_feeds_sudo_per_min() -> None:
    ev = build_event(
        module="log_tailer",
        action="sudo_invoked",
        category=["iam"],
        type_=["start"],
        severity="info",
        outcome="success",
        user={"name": "eli"},
    )
    sudo = [s for s in extract_samples(ev) if s.metric_kind == "sudo_per_min"]
    assert len(sudo) == 1
    assert sudo[0].entity_key == "eli"


def test_fim_write_feeds_file_writes_per_min_keyed_by_parent_dir() -> None:
    ev = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["creation"],
        severity="info",
        file={"path": "/etc/cron.d/evil"},
    )
    writes = [s for s in extract_samples(ev) if s.metric_kind == "file_writes_per_min"]
    assert len(writes) == 1
    assert writes[0].entity_key == "/etc/cron.d"
    assert writes[0].entity == {"file": {"path": "/etc/cron.d"}}


def test_processless_event_yields_nothing() -> None:
    ev = build_event(
        module="healthcheck",
        action="tick",
        category=["host"],
        type_=["info"],
        severity="info",
    )
    assert extract_samples(ev) == []


def test_anomaly_detector_events_are_never_sampled() -> None:
    # Belt to the router filter's braces: the extractor itself refuses its
    # own module's signals.
    ev = build_event(
        module="anomaly_detector",
        action="metric_anomaly",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        kind="signal",
        process={"name": "curl"},
    )
    assert extract_samples(ev) == []
