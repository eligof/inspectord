# Persistence detection rules + first_seen baseline suppression — design

| Field | Value |
| --- | --- |
| Date | 2026-06-22 |
| Status | Approved (brainstorming) — ready for implementation plan |
| Spec section refs | §21 (rules), §1166 (persistence rule ids), §5 (collectors) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Related | `docs/superpowers/specs/2026-06-19-persistence-panel-design.md` (the Persistence panel; §10 deferred these rules) |

## 1. Purpose & context

The Persistence panel (sub-project 2, PRs #105–#106) ships inventory + baseline-diff but **no
alerting** — the `persistence.new_*` rules were deferred (panel spec §10). This adds them.

**The core problem:** the `persistence_snapshotter` starts each run with an empty snapshot and
re-emits *every* existing cron job / systemd timer / autostart entry / SSH key as
`persistence_added` on its first poll (by design, to populate `persistence_state`). A naive
detection rule on `persistence_added` would therefore fire an alert for **all pre-existing
persistence on every daemon restart** — unusable. There is currently **no baseline-suppression
mechanism**: `Event.first_seen` exists in the schema but no collector sets it, and no worker
reads the DB (so "persist the snapshot across restarts" is not an option — it would break the
worker→event-only boundary).

**The fix (two parts):** the worker marks its baseline-catch-up events `first_seen=True`, and
the **rule engine globally drops `first_seen` events** before evaluating rules. This makes
this and every future snapshot collector flood-proof, and rule authors never need a per-rule
clause.

### Design decisions (locked during brainstorming 2026-06-22)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Suppression location | **Global — rule engine ignores `first_seen` events** | One central change; all snapshot collectors get it for free; rule authors can't forget it. |
| Baseline marker | **Worker sets `first_seen=True` on first-poll added events**, gated on a `self._seeded` flag | A host with zero persistence at startup must NOT mis-mark a later genuine entry as baseline — so gate on "have we completed a poll yet", not on "is prev empty". |
| Rules | **4, one per kind**, matching parent spec §1166 ids | Distinct severity + messaging per kind. |
| Severity | **authorized_keys = high; cron / timer / autostart = medium** | A new SSH key is the highest-value persistence vector. |
| Trigger | **Additions only** (`persistence_added`) | Removal alerting deferred; in-place edits already surface as a new entry (removed+added → new key). |

## 2. Components (single pure-Python PR)

### 2.1 `first_seen` plumbing — `inspectord/parsers/base.py`, the worker

- Add a `first_seen: bool = False` kwarg to `build_event` (`inspectord/parsers/base.py`),
  forwarding into the existing `Event.first_seen` field (mirrors how `persistence`/`device`
  were added).
- `inspectord/workers/persistence_snapshotter/__main__.py`: add `self._seeded = False` in
  `__init__`. In `step()`, capture `baseline = not self._seeded` **before** diffing, set
  `self._seeded = True` after, and pass `first_seen=baseline` through `_emit` →
  `build_event(..., first_seen=...)` for `persistence_added` events. (Removed events can't
  occur on the first poll — `self._prev` is empty — so they always carry `first_seen=False`.)

### 2.2 Global suppression — `inspectord/rule_engine.py`

At the top of `RuleEngine.process(event)`:

```python
def process(self, event: Event) -> list[Alert]:
    if event.first_seen:
        return []   # baseline catch-up is not a detection; skip rules + correlation history
    self._history.append(event)
    ...
```

`first_seen` events do not evaluate rules and do not enter the correlation history (they are
baseline, irrelevant to windowed rules).

### 2.3 Four YAML rules — `inspectord/rules/starter_pack/`

Auto-discovered (the supervisor loads every `starter_pack/*.yaml`). Mirror
`persistence_sudoers.yaml`. Each: `event.module == "persistence_snapshotter" AND event.action
== "persistence_added" AND persistence.kind == "<kind>"`. No `first_seen` clause (engine drops
those globally). The DSL resolves `persistence.kind` / `persistence.name` /
`persistence.source_path` / `persistence.details` (path resolution walks the typed
`event.persistence` block).

| File | id | kind | severity | short |
| --- | --- | --- | --- | --- |
| `persistence_new_cron.yaml` | `persistence.new_cron` | `cron` | medium | `new cron persistence: {persistence.name}` |
| `persistence_new_systemd_timer.yaml` | `persistence.new_systemd_timer` | `timer` | medium | `new systemd timer: {persistence.name}` |
| `persistence_autostart_changed.yaml` | `persistence.autostart_changed` | `autostart` | medium | `new autostart entry: {persistence.name}` |
| `persistence_authorized_keys_changed.yaml` | `persistence.authorized_keys_changed` | `authorized_key` | high | `new SSH authorized_key: {persistence.name}` |

Each carries `category: persistence`, a `why`, `false_positives` (e.g. "you installed
software that registers a timer/autostart", "you added your own SSH key"), a `detail`
templated with `{persistence.source_path}` + `{persistence.details}`, and `labels:
[persistence, <kind>]`. (The collector's `kind` is `timer` for both system and user timers, so
one rule covers both scopes; parent §1166's separate `new_systemd_user_timer` id is collapsed
to `new_systemd_timer`.)

## 3. Testing (TDD)

- **`build_event`** — `build_event(..., first_seen=True)` yields `event.first_seen is True`;
  default is `False` (existing callers unaffected).
- **worker** — first `step()` emits `persistence_added` with `first_seen=True`; after seeding,
  a later genuine-new entry emits `first_seen=False`; a host with an empty first poll (no
  entries) still flips `_seeded`, so the next poll's new entry is `first_seen=False` (the
  zero-persistence edge).
- **rule engine** — `process(event_with_first_seen_True)` returns `[]` and does not grow the
  correlation history; a normal event still evaluates.
- **rules** — load the 4 YAML files; each fires on a matching non-baseline `persistence_added`
  of its kind and produces an alert with the expected `id` + `severity`; a different kind does
  not match; a `first_seen=True` event yields no alert end-to-end (engine-level).

## 4. Out of scope

- Alerting on `persistence_removed` (a mechanism disappearing).
- The deferred-while-daemon-down gap (see §5).
- Per-entry allowlisting UI (the file-based allowlist already applies to these alerts via the
  normal `is_suppressed` path).
- The larger deferred Cases/evidence work; anomaly_detector / first-sighting statistics.

## 5. Known limitation

Persistence planted while the daemon is **down** reappears on restart as a baseline
(`first_seen=True`) event and is therefore suppressed — no alert fires. The Persistence panel's
baseline-diff still surfaces it visually (capture a baseline, compare after), so it is not
invisible; it just doesn't alert. Acceptable for a single-user host that is normally running;
closing it fully needs persistent first-sighting state (the deferred `anomaly_detector`).
