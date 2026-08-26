"""Worker-through-projector lifecycle tests (vuln-scanner design §5, §8).

Each scenario drives the real worker (fake clock, fake pacman, fake vercmp),
parses its emitted NDJSON back into Events, and feeds every event through the
real RuleEngine (with the shipped vuln starter rules) and the real projector
into a migrated DuckDB — the same path the supervisor runs in production.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml as _yaml

from inspectord.rule_engine import RuleEngine
from inspectord.rules.registry import Registry
from inspectord.rules.yaml_loader import YamlRule, load_yaml_rule_from_dict
from inspectord.schemas.alert import Alert
from inspectord.schemas.event import Event
from inspectord.state.projector import project
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations
from tests.workers.vuln_scanner.test_worker import (
    _INTERVAL_S,
    _POLL_S,
    _avg,
    _Harness,
)


def _vuln_rule(filename: str) -> YamlRule:
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / filename
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")), source=path.name
    )


class _Pipeline:
    """The supervisor's persist path in miniature: RuleEngine + projector."""

    def __init__(self, tmp_path: Path) -> None:
        self.db_path = tmp_path / "state.duckdb"
        with Database(self.db_path) as db:
            run_migrations(db)
        registry = Registry(
            yaml_rules=[_vuln_rule("vuln_new_critical.yaml"), _vuln_rule("vuln_new_high.yaml")]
        )
        self.engine = RuleEngine(registry=registry, db_path=self.db_path, allowlist_entries=[])

    def feed(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.engine.process(event))
            with Database(self.db_path) as db:
                project(event, db)
        return alerts

    def rows(self) -> dict[tuple[str, str, str], dict[str, object]]:
        with Database(self.db_path) as db:
            fetched = db.query(
                "SELECT avg_id, cve_id, package, first_seen_at, last_seen, resolved_at,"
                " acked_at, acked_note FROM vulnerabilities"
            ).fetchall()
        return {
            (r[0], r[1], r[2]): {
                "first_seen_at": r[3],
                "last_seen": r[4],
                "resolved_at": r[5],
                "acked_at": r[6],
                "acked_note": r[7],
            }
            for r in fetched
        }


def test_baseline_suppression_end_to_end(tmp_path: Path) -> None:
    """First scan populates state but the rule engine drops every event."""
    harness = _Harness(tmp_path)
    harness.write_advisories([_avg("AVG-1", "openssl")])
    pipeline = _Pipeline(tmp_path)
    worker = harness.worker()

    worker.step()
    alerts = pipeline.feed(harness.drain())

    assert alerts == []
    rows = pipeline.rows()
    assert set(rows) == {("AVG-1", "CVE-1", "openssl")}
    assert rows[("AVG-1", "CVE-1", "openssl")]["resolved_at"] is None


def test_new_match_alerts_and_projects(tmp_path: Path) -> None:
    """A genuinely new Critical match on a later scan raises exactly one alert."""
    harness = _Harness(tmp_path)
    harness.write_advisories([_avg("AVG-1", "openssl")])
    pipeline = _Pipeline(tmp_path)
    worker = harness.worker()

    worker.step()
    assert pipeline.feed(harness.drain()) == []

    harness.write_advisories([_avg("AVG-1", "openssl"), _avg("AVG-9", "bash")])
    harness.clock.advance(_POLL_S)
    worker.step()
    alerts = pipeline.feed(harness.drain())

    # AVG-1 is re-emitted (full-set emission) but new=false: one alert only.
    assert len(alerts) == 1
    assert alerts[0].rule.id == "vuln.new_critical"
    assert alerts[0].severity.value == "high"
    assert [(e.kind, e.key) for e in alerts[0].entities] == [("package", "AVG-9/bash")]
    assert set(pipeline.rows()) == {
        ("AVG-1", "CVE-1", "openssl"),
        ("AVG-9", "CVE-9", "bash"),
    }


def test_sweep_resolves_rows_fixed_while_daemon_was_down(tmp_path: Path) -> None:
    """The failure mode that killed the delta design (§5): upgrade during downtime.

    Worker A sees the match; the daemon goes down; the package is upgraded; a
    FRESH worker's first scan emits no match for it — only the projector sweep
    can resolve the stale row, and it must do so without any alert.
    """
    harness = _Harness(tmp_path)
    harness.write_advisories([_avg("AVG-1", "openssl")])
    pipeline = _Pipeline(tmp_path)

    worker_a = harness.worker()
    worker_a.step()
    pipeline.feed(harness.drain())
    assert pipeline.rows()[("AVG-1", "CVE-1", "openssl")]["resolved_at"] is None

    # Daemon restart: new worker lifetime, package upgraded past the fix.
    harness.pacman_output = "openssl 5.0-1\nbash 1.0-1\n"
    worker_b = harness.worker()
    worker_b.step()
    alerts = pipeline.feed(harness.drain())

    assert alerts == []
    rows = pipeline.rows()
    assert set(rows) == {("AVG-1", "CVE-1", "openssl")}  # never deleted
    assert rows[("AVG-1", "CVE-1", "openssl")]["resolved_at"] is not None


def test_skipped_avg_survives_the_sweep_end_to_end(tmp_path: Path) -> None:
    """An AVG that turns malformed must not silently resolve its real rows."""
    harness = _Harness(tmp_path)
    harness.write_advisories([_avg("AVG-1", "openssl")])
    pipeline = _Pipeline(tmp_path)
    worker = harness.worker()

    worker.step()
    pipeline.feed(harness.drain())

    harness.write_advisories([_avg("AVG-1", "openssl", packages="broken")])
    harness.clock.advance(_POLL_S)
    worker.step()
    events = harness.drain()
    completed = [e for e in events if e.action == "vuln_scan_completed"]
    assert len(completed) == 1
    assert (completed[0].raw or {})["skipped_avg_ids"] == ["AVG-1"]
    pipeline.feed(events)

    # The row's advisory was skipped, not absent: it survives unresolved.
    assert pipeline.rows()[("AVG-1", "CVE-1", "openssl")]["resolved_at"] is None


def test_resolve_then_reappear(tmp_path: Path) -> None:
    """Upgrade resolves the row; a downgrade back un-resolves it and alerts."""
    harness = _Harness(tmp_path)
    harness.write_advisories([_avg("AVG-1", "openssl")])
    pipeline = _Pipeline(tmp_path)
    worker = harness.worker()

    worker.step()
    pipeline.feed(harness.drain())
    original_first_seen = pipeline.rows()[("AVG-1", "CVE-1", "openssl")]["first_seen_at"]

    # Scan 2: upgraded past the fix -> sweep resolves the row.
    harness.pacman_output = "openssl 5.0-1\nbash 1.0-1\n"
    harness.touch_pacman_db()
    harness.clock.advance(_POLL_S)
    worker.step()
    assert pipeline.feed(harness.drain()) == []
    assert pipeline.rows()[("AVG-1", "CVE-1", "openssl")]["resolved_at"] is not None

    # Scan 3: downgraded back to the vulnerable version, same worker lifetime:
    # genuinely new again -> alert fires, resolved_at clears, first_seen_at is
    # still the original sighting.
    harness.pacman_output = "openssl 1.0-1\nbash 1.0-1\n"
    harness.touch_pacman_db()
    harness.clock.advance(_INTERVAL_S)
    worker.step()
    alerts = pipeline.feed(harness.drain())

    assert [a.rule.id for a in alerts] == ["vuln.new_critical"]
    row = pipeline.rows()[("AVG-1", "CVE-1", "openssl")]
    assert row["resolved_at"] is None
    assert row["first_seen_at"] == original_first_seen
