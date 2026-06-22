# Persistence detection rules + first_seen suppression Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. TDD throughout: write tests first, watch fail, implement, watch pass, run gates, commit.

**Goal:** Add four `persistence.*` detection rules that alert on genuinely-new persistence mechanisms, gated behind a `first_seen` baseline-suppression mechanism so they don't flood on daemon restart.

**Architecture:** Two-part suppression — the `persistence_snapshotter` marks its first-poll (baseline catch-up) `persistence_added` events `first_seen=True`, and `RuleEngine.process` globally drops `first_seen` events before evaluating rules. Then four declarative YAML rules (one per persistence kind) match non-baseline `persistence_added` events.

**Tech Stack:** Python 3.14, the existing YAML rule DSL, pytest. No new deps. Single PR.

**Spec:** `docs/superpowers/specs/2026-06-22-persistence-detection-rules-design.md` (§2 components, §2.3 rule table, §3 tests).

**Gates (run from repo root, all must pass before done):**
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests`
- `.venv/bin/mypy inspectord`

**Branch:** `feat/persistence-rules` (already checked out; spec + this plan ride along).

**Key codebase facts:**
- `Event.first_seen: bool = False` already exists in `inspectord/schemas/event.py` (no schema change). `build_event` (`inspectord/parsers/base.py`) does NOT yet forward it — add the kwarg (same shape as the existing `persistence`/`device` kwargs).
- The persistence worker `step()`/`_emit` are in `inspectord/workers/persistence_snapshotter/__main__.py` (lines 69-107). `_emit(action, attrs)` builds the event via `build_event`.
- `RuleEngine.process(event)` is in `inspectord/rule_engine.py:36` — top of the method appends to `self._history` then evaluates.
- YAML rules auto-load from `inspectord/rules/starter_pack/*.yaml` (the supervisor globs them; `tests/rules/test_registry.py` may assert the rule count — update it if so). Rule DSL: `event.module`/`event.action`/`persistence.kind` etc. resolve via path lookup into the event's typed blocks. Test a rule with `evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))` (see `tests/rules/starter_pack/test_persistence_sudoers.py`).

---

## Task 1: `first_seen` plumbing + global rule-engine suppression

**Files:**
- Modify: `inspectord/parsers/base.py` (`build_event` first_seen kwarg)
- Modify: `inspectord/workers/persistence_snapshotter/__main__.py` (`_seeded` flag + mark baseline)
- Modify: `inspectord/rule_engine.py` (drop first_seen events)
- Test: `tests/parsers/test_base.py`, `tests/workers/persistence_snapshotter/test_worker.py`, `tests/test_rule_engine.py`

### 1a — `build_event` first_seen kwarg

- [ ] **Step 1: Write the failing test** in `tests/parsers/test_base.py` (mirror the existing `test_build_event_carries_persistence_block`):
```python
def test_build_event_carries_first_seen():
    ev = build_event(module="m", action="a", category=["host"], type_=["start"],
                     severity="low", first_seen=True)
    assert ev.first_seen is True
    ev2 = build_event(module="m", action="a", category=["host"], type_=["start"], severity="low")
    assert ev2.first_seen is False
```
- [ ] **Step 2: Run — expect failure** (`unexpected keyword argument 'first_seen'`).
- [ ] **Step 3: Implement** in `inspectord/parsers/base.py`: add `first_seen: bool = False,` to the `build_event` signature (after `ts`), and `first_seen=first_seen,` to the `Event(...)` constructor body.
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit.** `feat(schema): build_event forwards first_seen`.

### 1b — Worker marks first-poll events `first_seen=True`

- [ ] **Step 1: Write failing tests** in `tests/workers/persistence_snapshotter/test_worker.py`:
  - First `step()` with snapshot `({k1: a1}, set())` emits a `persistence_added` event whose JSON has `first_seen == True`.
  - After that first step, a `step()` returning `({k1: a1, k2: a2}, set())` emits the new `k2` `persistence_added` with `first_seen == False`.
  - **Zero-persistence edge:** first `step()` with `({}, set())` (no entries) emits nothing but still flips the seeded flag; the next `step()` with `({k1: a1}, set())` emits `k1` with `first_seen == False` (NOT treated as baseline).
  (Mirror the existing worker tests' fake-snapshot + `io.BytesIO` sink + `json.loads` style.)
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** in `inspectord/workers/persistence_snapshotter/__main__.py`:
  - In `__init__`, add `self._seeded = False` (next to `self._prev`).
  - In `step()`, capture `baseline` at the top and flip the flag, and pass it to the added emits:
```python
    def step(self) -> None:
        current, failed = self._snapshot_fn()
        baseline = not self._seeded
        self._seeded = True
        effective = dict(current)
        for key, attrs in self._prev.items():
            if attrs["kind"] in failed and key not in effective:
                effective[key] = attrs
        for key in effective.keys() - self._prev.keys():
            self._emit("persistence_added", effective[key], first_seen=baseline)
        for key in self._prev.keys() - effective.keys():
            self._emit("persistence_removed", self._prev[key], first_seen=False)
        self._prev = effective
```
  - Change `_emit` signature to `def _emit(self, action: str, attrs: dict[str, Any], *, first_seen: bool = False) -> None:` and pass `first_seen=first_seen` into the `build_event(...)` call.
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit.** `feat(persistence): mark first-poll baseline events first_seen`.

### 1c — Rule engine drops first_seen events

- [ ] **Step 1: Write failing tests** in `tests/test_rule_engine.py` (mirror its existing style — construct a `RuleEngine` with a registry; check the existing tests for the constructor/helpers):
  - `engine.process(ev_with_first_seen_True)` returns `[]` even when a rule would otherwise match.
  - A first_seen event does NOT grow the engine's correlation history (e.g. assert via a windowed rule, or that a subsequent matching non-baseline event still behaves as if the baseline one never entered history). If history isn't easily observable, at minimum assert the `[]` return for a first_seen event that matches a registered rule, and that a normal (first_seen=False) matching event still returns an alert.
- [ ] **Step 2: Run — expect failure** (the first_seen event currently produces an alert).
- [ ] **Step 3: Implement** in `inspectord/rule_engine.py` `process`, as the FIRST lines:
```python
    def process(self, event: Event) -> list[Alert]:
        if event.first_seen:
            # Baseline catch-up (snapshot collectors re-emit existing state on startup)
            # is not a detection: skip rule evaluation and the correlation history.
            return []
        self._history.append(event)
        ...
```
- [ ] **Step 4: Run — expect pass.** Run the full suite to confirm no existing rule test regresses (existing events have `first_seen=False` by default, so they're unaffected).
- [ ] **Step 5: Commit.** `feat(rules): rule engine ignores first_seen baseline events`.

---

## Task 2: The four persistence rules

**Files:**
- Create: `inspectord/rules/starter_pack/persistence_new_cron.yaml`, `persistence_new_systemd_timer.yaml`, `persistence_autostart_changed.yaml`, `persistence_authorized_keys_changed.yaml`
- Test: `tests/rules/starter_pack/test_persistence_rules.py`
- Possibly modify: `tests/rules/test_registry.py` (if it asserts a rule count — bump it by 4)

- [ ] **Step 1: Write failing tests** `tests/rules/starter_pack/test_persistence_rules.py` (mirror `test_persistence_sudoers.py`). A helper to load a rule by filename, then per rule:
  - it fires on a matching `persistence_added` event of its kind and the match `severity` is correct (high for authorized_key, medium for the other three);
  - it does NOT fire on a `persistence_added` of a different kind;
  - it does NOT fire on a `persistence_removed` of its kind.
  Build events with `build_event(module="persistence_snapshotter", action="persistence_added", category=["host"], type_=["start"], severity="low", persistence={"kind": "<kind>", "name": "n", "source_path": "/p", "details": "d", "key": "k"})`. Evaluate via `evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))`.

Example for one rule:
```python
def test_new_cron_fires_on_cron_added():
    rule = _rule("persistence_new_cron.yaml")
    ev = build_event(module="persistence_snapshotter", action="persistence_added",
                     category=["host"], type_=["start"], severity="low",
                     persistence={"kind": "cron", "name": "backup", "source_path": "/etc/crontab",
                                  "details": "@daily root backup", "key": "k"})
    matches = evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))
    assert matches and matches[0].severity == "medium"


def test_new_cron_ignores_other_kind():
    rule = _rule("persistence_new_cron.yaml")
    ev = build_event(module="persistence_snapshotter", action="persistence_added",
                     category=["host"], type_=["start"], severity="low",
                     persistence={"kind": "timer", "name": "x", "source_path": "/p", "details": "d", "key": "k"})
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []
```

- [ ] **Step 2: Run — expect failure** (rule files don't exist).
- [ ] **Step 3: Create the four YAML files** (mirror `persistence_sudoers.yaml`'s shape exactly — `version`, `id`, `name`, `severity`, `category`, `why`, `false_positives`, `detect.any_of`, `short`, `detail`, `labels`). Use these exact ids/kinds/severities:

`persistence_new_cron.yaml`:
```yaml
version: 1.0.0
id: persistence.new_cron
name: "new cron persistence"
severity: medium
category: persistence
why: |
  A new cron entry appeared. Scheduled jobs are a classic persistence mechanism.
false_positives:
  - "You added a cron job yourself."
  - "A package install registered a cron entry."
detect:
  any_of:
    - event.module == "persistence_snapshotter" AND event.action == "persistence_added" AND persistence.kind == "cron"
short: "new cron persistence: {persistence.name}"
detail: "A new cron entry appeared at {persistence.source_path}: {persistence.details}"
labels: [persistence, cron]
```
`persistence_new_systemd_timer.yaml` — id `persistence.new_systemd_timer`, kind `timer`, severity `medium`, short `"new systemd timer: {persistence.name}"`, detail referencing `{persistence.source_path}` + `{persistence.details}`, labels `[persistence, timer]`, why/false_positives about timers.
`persistence_autostart_changed.yaml` — id `persistence.autostart_changed`, kind `autostart`, severity `medium`, short `"new autostart entry: {persistence.name}"`, labels `[persistence, autostart]`.
`persistence_authorized_keys_changed.yaml` — id `persistence.authorized_keys_changed`, kind `authorized_key`, **severity `high`**, short `"new SSH authorized_key: {persistence.name}"`, detail referencing `{persistence.details}`, labels `[persistence, authorized_key]`, why/false_positives about adding your own SSH key.

- [ ] **Step 4: Run — expect pass.** If `tests/rules/test_registry.py` (or any test) asserts a fixed loaded-rule count, bump it by 4. Run the FULL suite + ruff + mypy.
- [ ] **Step 5: Commit.** `feat(rules): persistence.new_cron/new_systemd_timer/autostart_changed/authorized_keys_changed`.

---

## Self-review checklist (before handoff)
- [ ] Spec §2.1 (build_event first_seen + worker `_seeded` baseline marking incl. zero-persistence edge) → Task 1a/1b. ✓
- [ ] Spec §2.2 (engine drops first_seen, no history) → Task 1c. ✓
- [ ] Spec §2.3 (4 rules, ids/kinds/severities per the table; authorized_keys=high) → Task 2. ✓
- [ ] Spec §3 tests: build_event, worker first/second-poll + zero-persistence edge, engine suppression, each rule fires/ignores-other-kind/ignores-removed. ✓
- [ ] No schema migration (Event.first_seen already exists). No web changes. Out of scope: persistence_removed alerts.
- [ ] Signature consistency: `_emit(self, action, attrs, *, first_seen=False)`; `build_event(..., first_seen=False)`; rules match `persistence.kind == "<kind>"` (cron/timer/autostart/authorized_key — matching the collector's kind constants).
