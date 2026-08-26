# Anomaly checkpointing gaps — design

Date: 2026-08-26
Parent: anomaly detector spec (`2026-08-20-anomaly-detector-design.md`); deferred items
from PR #142 ("entity dicts in checkpoints") and PR #145 ("no checkpointing of resource
baselines — ~25 min warm-up after restart").
Status: **autonomously drafted, NOT human-reviewed.** Small internal-persistence slice;
no concilium (no data destruction, no new attack surface — extends the existing
checkpoint mechanism).

## 1. Goal

Close the two checkpoint gaps so a daemon restart costs the anomaly detector no
detection coverage:

1. **Resource baselines survive restart.** Today `ResourceSampler` state is purely
   in-memory: every restart forgets all per-unit CPU/RSS baselines and the sustained-
   deviation rule is blind for ~25 minutes (`min_samples` warm-up). A restart is
   exactly when an attacker would want a blind monitor.
2. **Entity dicts survive restart.** `StatsEngine.load_row` admits restored entities
   with an empty dict; an alert that fires between restart and the entity's first
   fresh observation renders without its context fields.

## 2. Design

Both reuse the existing `metric_baseline` table (PK `metric_kind, entity_key,
window_name`, `state_json`, `updated_at`) and the existing checkpoint/load cycle in
`AnomalyDetector` (`checkpoint()` every `checkpoint_interval_s` + final flush on stop;
`load_checkpoints()` at start).

### 2.1 Resource baselines

- `ResourceSampler.checkpoint_rows() -> list[tuple[str, str, str, str]]`: one row per
  (entity, metric): `(f"resource.{metric}", entity_key, "1h",
  ws.serialize_window("1h"))`. Only the 1h ring is checkpointed — it is the only ring
  `_observe` ever reads (the 24h/7d rings accumulate unused by design).
- `ResourceSampler.load_row(metric_kind, entity_key, window_name, blob) -> bool`:
  strips the `resource.` prefix, creates the `_EntityState` if absent, restores the 1h
  window via the existing `WindowedStats.load_window`. NOT restored, deliberately:
  `pid`/`prev_ticks`/`prev_t` (stale after restart — the first sample re-resolves and
  re-primes them; the existing None-handling already skips the first delta) and
  `streaks` (reset to 0 — conservative: a genuine sustained deviation re-accumulates
  within `sustained_ticks` samples rather than firing off a half-stale streak).
- **Staleness cutoff:** at load, rows with `metric_kind LIKE 'resource.%'` whose
  `updated_at` is older than 24 h (`_RESOURCE_CHECKPOINT_MAX_AGE_S = 86400`, module
  constant) are skipped AND deleted — a days-old resource profile misrepresents the
  unit and dead units' rows would otherwise live forever. Engine/beacon rows keep
  their existing no-cutoff behavior.
- `AnomalyDetector.checkpoint()` appends `self._sampler.checkpoint_rows()` to the
  UPSERT batch; `load_checkpoints()` dispatches `resource.*` rows to the sampler (all
  other rows keep their current engine→beacon dispatch). The `resource.` prefix
  cannot collide: engine metric kinds are event-derived names and beacon uses its own
  fixed kind, neither starts with `resource.` (verified at implementation time —
  assert in a test).

## 2.2 Entity dicts

- `StatsEngine.checkpoint_rows()` emits one extra row per entity:
  `(metric_kind, entity_key, "entity", json.dumps(entity_dict))` — skipped when the
  dict is empty (no row, no noise).
- `StatsEngine.load_row` handles `window_name == "entity"`: parse-or-reject (same
  never-fail contract as `load_window`), store into `self._entities[key]`. Ordering
  independence: an "entity" row may arrive before or after the entity's window rows —
  both orders must restore correctly (`_admit` if absent, merge if present).
- The existing "heal on next observe" behavior stays — the checkpoint row just closes
  the window between restart and first observation.

## 3. Non-goals

Streak persistence (deliberately reset); 24h/7d resource rings (never read);
checkpointing `pid` resolution; any schema change (the table fits as-is); retention of
`metric_baseline` rows generally (the 24 h cutoff covers only `resource.*`).

## 4. Testing

TDD. Sampler: checkpoint→fresh-sampler→load round-trip restores the 1h ring (mean
preserved, `min_samples` immediately satisfied → sustained rule live on first
post-restart breach); streaks and pid state reset; stale row (25 h) skipped and
deleted; corrupt blob rejected without state change. Engine: entity row round-trip
(alert context present after reload before any observe); empty dict → no row; both
load orders; corrupt entity blob rejected. Detector: `checkpoint()` writes and
`load_checkpoints()` restores all three sources in one cycle; prefix-collision
assertion.

## 5. Delivery

Single PR: `entity_baseline.py` + `stats.py` + `detector.py` + tests.
