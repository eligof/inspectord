# Anomaly detector design — statistical, first-sighting, beaconing, entity baselines

**Date:** 2026-08-20
**Status:** Approved
**Implements:** §12 of `2026-05-24-local-inspection-design.md` (all four sub-features), plus
§20.6 (self-anomaly).
**Amends:** §12.2 of the main spec — the first-sighting marker is
`baseline.first_sighting`, **not** `Event.first_seen` (see §3 below).

## 1. Goals and scope

Build the `anomaly_detector` described in main-spec §12: the layer that makes the product
more than "rules + state diffs."

- **12.1 Statistical anomaly** — rolling mean/stddev per `(metric_kind, entity_key)` over
  1 h / 24 h / 7 d windows; z-score threshold alerts.
- **12.2 First-sighting** — persistent `first_seen` table; mark the first occurrence of an
  entity within a category.
- **12.3 Temporal pattern (beaconing)** — low-variance inter-arrival times on repeated
  outbound connections to the same `(dst.ip, dst.port)` from the same process.
- **12.4 Per-entity behavioural baselines** — CPU/RAM baselines for long-lived processes;
  sustained large deviation fires. Includes inspectord itself (§20.6 self-anomaly).

Out of scope: notification-policy changes (existing notifier/allowlist pipeline is reused
unchanged), new collectors, web UI panels (anomaly alerts surface through the existing
Alerts panel; a dedicated visualization can come later).

## 2. Architecture

The detector is an **in-process library**, like the rule engine — not a worker
subprocess. It has two halves with different latency requirements:

1. **First-sighting** runs **synchronously** in the supervisor's `_dispatch` path,
   because its output is a marker stamped *onto the event itself*, which must happen
   before the rule engine sees the event and before the event is published/persisted.
   It is O(1): an in-memory seen-set lookup, no I/O on the hot path.
2. **Everything statistical** (12.1, 12.3, 12.4) runs **asynchronously** on a dedicated
   thread fed by its own router subscription, because it aggregates over time windows and
   its outputs are *new* events, so ordering against the triggering event doesn't matter.

```
worker fan-out thread:
  enrich(ev) ──► first_sighting.observe(ev)   # may stamp baseline.first_sighting
             ──► rule_engine.process(ev)      # first-sighting rules match the stamp
             ──► router.publish(ev)           # store, IPC, … and the anomaly subscription

anomaly detector thread (tick = 60 s):
  drain subscription ─► per-minute buckets ─► windowed stats / beacon state
  on threshold breach ─► build signal Event ─► supervisor._dispatch(signal)
                                               └► starter-pack anomaly.* rule ─► Alert
```

### 2.1 Signals, not direct alerts

The detector never builds `Alert` objects. On a threshold breach it emits a normal
`Event` with `kind=signal`, `category=["anomaly"]`, `module="anomaly_detector"`, carrying
its measurements in the `baseline` field (e.g. `baseline.deviation`,
`baseline.metric_kind`, `baseline.window`). The signal is re-injected through
`_dispatch`, where declarative starter-pack rules (`anomaly.*`, main-spec §22) convert it
into an alert through the **existing** allowlist → dedup → evidence → notifier pipeline.

Why: the user tunes anomaly alerting exactly like rule alerting (allowlist entries,
rule YAML), signals are persisted/journaled/huntable like any event, and the detector
stays purely statistical.

Feedback-loop guards:

- The detector's router subscription filter **excludes `module == "anomaly_detector"`**,
  so its own signals never feed its aggregators.
- Self-anomaly (§20.6) uses a separate rule id (`monitor_health_anomaly`) and rule class.

### 2.2 Warm-up silence (main-spec §21.4)

No signal is emitted for an entity until its baseline has `min_samples` (default 50)
observations. During warm-up the detector only accumulates. First-sighting markers are
stamped from day one, but the initial snapshot catch-up flood (events with
`Event.first_seen=True`) is already skipped by the rule engine, so catch-up **populates**
the seen-set and `first_seen` table without producing a single alert.

### 2.3 Package layout

```
inspectord/anomaly/
├── __init__.py
├── first_sighting.py   # FirstSightingTracker: sync observe(), async flush
├── detector.py         # AnomalyDetector: subscription drain, tick loop, checkpointing
├── stats.py            # WindowedStats: ring buffers, mean/std, z-score
├── metrics.py          # Event → (metric_kind, entity_key, increment) extraction
├── beacon.py           # BeaconTracker: inter-arrival ring per (proc, dst ip, dst port)
└── entity_baseline.py  # ResourceSampler: /proc CPU/RAM baselines, sustained deviation
```

## 3. First-sighting (12.2) — and the `first_seen` flag conflict

Main-spec 12.2 says the detector sets `event.first_seen=true`. That flag **already
means something else** in the implementation: snapshot collectors re-emit existing state
on startup with `first_seen=True`, and the rule engine skips those events (baseline
catch-up is not a detection). Reusing it would make every catch-up event look like a
sighting and every sighting invisible to rules.

**Resolution (this spec amends main-spec 12.2):** `Event.first_seen` keeps its catch-up
meaning. The first-sighting marker is `baseline.first_sighting = true`, written into the
event's existing `baseline` dict — the field main-spec §4.2 already reserves for the
anomaly detector.

Mechanics:

- `FirstSightingTracker` loads the `first_seen` table into an in-memory set of
  `(category, entity_kind, entity_key)` at startup.
- `observe(ev)` derives zero or more sighting keys from the event (per the extraction
  table below), and for each miss: adds to the set, stamps
  `ev.baseline["first_sighting"] = true`, and appends a pending row to a queue.
- The detector thread flushes pending rows to the `first_seen` table in batches each
  tick. The hot path never touches the database. A crash before flush loses pending
  rows; the entity is re-marked as first-sighted on the next occurrence and the alert
  dedup absorbs the duplicate.

Sighting keys extracted (the five starter cases from main-spec 12.2):

| Trigger event | category | entity_kind | entity_key | rule severity |
|---|---|---|---|---|
| process exec | `process` | `binary` | executable path (hash when available) | low |
| outbound connection | `network` | `proc_dest` | `process.name → dst.ip:dst.port` | low |
| successful login | `authentication` | `login_ip` | source IP | low |
| kernel module load | `driver` | `kmod` | module name | medium |
| SUID file appears | `file` | `suid` | file path | medium |

Each has a matching starter-pack YAML rule keying on `baseline.first_sighting == true`
plus the category (`anomaly.first_*` rule ids, main-spec §22). Severities are chosen
against the notifier's routing (low/info = log-only, medium+ = desktop popup): the
inherently chatty sightings (every new binary, dest, login IP on a young install) ship
at **low** so they satisfy §21.4's "log but do not notify" without any notifier changes,
while the rare, high-signal sightings (first kmod load, new SUID file) ship at
**medium** and do notify.

## 4. Statistical anomaly (12.1)

### 4.1 Metrics

`metrics.py` maps each drained event to zero or more `(metric_kind, entity_key)`
counters, incremented into the **current minute bucket**:

| metric_kind | entity_key | fed by |
|---|---|---|
| `events_per_min` | `process.name:category` | every process-attributed event |
| `egress_bytes_per_min` | `process.name` | outbound connection events carrying byte counts |
| `new_conn_per_min` | `process.name` | outbound connection events |
| `logins_per_min` | `user.name` | authentication success events |
| `sudo_per_min` | `user.name` | sudo events |
| `file_writes_per_min` | parent directory | FIM write events |

### 4.2 Windows and storage shape

On each tick (60 s) the closing minute bucket is appended into three ring buffers per
`(metric_kind, entity_key)`:

| window | buckets | bucket width |
|---|---|---|
| 1 h | 60 | 1 min |
| 24 h | 288 | 5 min (minute values summed) |
| 7 d | 672 | 15 min |

≈ 1 020 floats (~8 KB) per entity-metric — a deliberate coarsening of "sliding window"
to respect the <2 % idle CPU / RAM budget; a naive 7-day minute-resolution ring would be
10 080 samples.

Mean/std computed over the ring at evaluation time. Signal emitted when
`|z| ≥ z_threshold` (default 3.0) **and** the ring holds ≥ `min_samples` (default 50)
buckets, for any window. The signal carries `baseline.deviation` (the z-score),
`baseline.metric_kind`, `baseline.window`, `baseline.mean`, `baseline.stddev`, and the
observed value.

### 4.3 Memory bound

Per metric_kind, at most `max_entities_per_metric` (default 512) entities are tracked,
LRU-evicted. Eviction of an active entity merely restarts its warm-up.

### 4.4 Checkpointing

Live state is in-memory. Every `checkpoint_interval_s` (default 300 s) and on shutdown,
each entity-metric's ring state is serialized to `metric_baseline.state_json`. On
startup the table is loaded back; a row that fails to parse or has an unknown shape is
discarded (that entity warms up fresh) — reload must never fail startup. Restart
therefore does **not** reset the 50-sample warm-up.

## 5. Beaconing (12.3)

`BeaconTracker` keeps, per `(process.name, dst.ip, dst.port)`, a ring of the last 32
inter-arrival times of outbound connections. On each new connection it evaluates:

- count ≥ `beacon_min_events` (default 12), and
- mean interval within [`beacon_min_interval_s`, `beacon_max_interval_s`]
  (defaults 5 s … 1 h), and
- coefficient of variation (std/mean) < `beacon_max_cv` (default 0.1)

→ emit a beacon signal with the interval statistics in `baseline`; the
`anomaly.beacon_signature` starter rule raises a medium-severity alert whose `rule.why`
explains the interval, variance, and why low-variance periodic egress is a C2 indicator.
Beacon state checkpoints into the same `metric_baseline` table
(`window_name = 'beacon'`). Tracked-key cap and LRU as in 4.3.

## 6. Per-entity behavioural baselines (12.4) + self-anomaly (§20.6)

No collector emits resource usage, so the detector samples it directly — cheap reads of
`/proc/<pid>/stat` and `/proc/<pid>/status` on a slower tick (`resource_tick_s`,
default 30 s). Sampled entities:

- main PIDs of running systemd services (from the `service_state` table), and
- inspectord's own process (§20.6).

CPU % and RSS feed the same `WindowedStats` machinery. The firing condition is the
main-spec's sustained rule, not a z-score: value > `sustained_factor` (default 5.0) ×
baseline mean for `sustained_ticks` (default 6, i.e. 3 min) consecutive samples →
signal. Transient spikes never fire. inspectord's own signal uses the dedicated
`monitor_health_anomaly` rule id in a separate rule class so self-anomaly can never
feed back into ordinary anomaly handling.

A PID that disappears mid-sampling (service restart, race between listing and reading
`/proc`) is skipped silently; its baseline is retained and resumes on the next sample.

## 7. Data model — migration `0010_anomaly.sql`

```sql
CREATE TABLE IF NOT EXISTS first_seen (
    category      TEXT NOT NULL,
    entity_kind   TEXT NOT NULL,
    entity_key    TEXT NOT NULL,
    first_seen_at TIMESTAMP NOT NULL,
    event_id      TEXT NOT NULL,
    PRIMARY KEY (category, entity_kind, entity_key)
);

-- Checkpoint of in-memory rolling state; never the source of truth at runtime.
CREATE TABLE IF NOT EXISTS metric_baseline (
    metric_kind  TEXT NOT NULL,
    entity_key   TEXT NOT NULL,
    window_name  TEXT NOT NULL,   -- '1h' | '24h' | '7d' | 'beacon'
    state_json   TEXT NOT NULL,
    updated_at   TIMESTAMP NOT NULL,
    PRIMARY KEY (metric_kind, entity_key, window_name)
);
```

## 8. Configuration

`AnomalyConfig`, a new section on `DaemonConfig` (in-process component, not a
`WorkerSpec`):

```python
class AnomalyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    tick_s: float = 60.0
    z_threshold: float = 3.0
    min_samples: int = 50
    checkpoint_interval_s: float = 300.0
    max_entities_per_metric: int = 512
    # beaconing
    beacon_min_events: int = 12
    beacon_min_interval_s: float = 5.0
    beacon_max_interval_s: float = 3600.0
    beacon_max_cv: float = 0.1
    # entity/resource baselines
    resource_tick_s: float = 30.0
    sustained_factor: float = 5.0
    sustained_ticks: int = 6
```

`dev_config()` includes defaults. `enabled = False` skips the first-sighting stage and
never starts the detector thread.

## 9. Error handling

- **Hot path:** `observe()` runs inside `_dispatch`'s existing alert-path guard; a raise
  is logged and the event still publishes. It performs no I/O.
- **Detector thread:** each tick body is wrapped; one bad tick logs and the loop
  continues. The thread follows the `_drain` loop pattern (stop event,
  `get_nowait`/sleep).
- **Checkpoint write failure:** log, keep in-memory state, retry next interval.
- **Checkpoint read failure:** discard the offending row, warm up fresh; never fail
  startup.
- **Router pressure:** the anomaly subscription uses `drop_oldest_non_critical`,
  queue size 4096 — a lost sample slightly degrades a baseline; it never blocks
  publishers.
- **DB writes** (first_seen flush, checkpoints) happen only on the detector thread,
  batched per tick, via its own `Database` handle — the same pattern the dedup engine
  already uses off the drain thread.

## 10. Testing

TDD throughout; all pure-Python unit tests plus one supervisor-level integration test
per PR (via `_inject_for_test`).

- **stats:** ring rollover across bucket widths; z-score math; warm-up gate (49 samples
  silent, 50th can fire); checkpoint round-trip; corrupt `state_json` discarded; LRU
  eviction at the entity cap.
- **first-sighting:** miss stamps `baseline.first_sighting` and queues a row; hit does
  neither; catch-up events (`Event.first_seen=True`) populate the seen-set without
  alerts; batch flush; reload from table on restart.
- **beacon:** regular 60 s ± 2 s intervals fire; jittered intervals don't; below
  `beacon_min_events` doesn't; interval bounds respected.
- **entity baseline:** fake `/proc` fixture; sustained 5× deviation fires after
  `sustained_ticks`, a transient spike doesn't; self-anomaly uses
  `monitor_health_anomaly`; vanished PID skipped without error.
- **integration:** synthetic event burst through `_inject_for_test` produces an anomaly
  alert row via a starter rule; an allowlist entry suppresses it.

## 11. Delivery — four sequential PRs

All pure Python (no eBPF, so the two-PR native/worker split does not apply).

| PR | Content |
|---|---|
| 1 | `anomaly/` package skeleton, migration 0010, `FirstSightingTracker` + supervisor wiring, `AnomalyConfig`, five first-sighting starter rules, main-spec §12.2 amendment note |
| 2 | `stats.py` + `metrics.py`, `AnomalyDetector` thread + tick, checkpoint/reload, statistical `anomaly.*` starter rules (egress spike, event-rate spike, sudo/login frequency) |
| 3 | `beacon.py` + `anomaly.beacon_signature` rule |
| 4 | `entity_baseline.py`, self-anomaly (`monitor_health_anomaly`), sustained-deviation rules |

Each PR: branch → subagent-driven development → green CI (`lint-and-test`, CodeQL,
cargo-audit, dependency-review) → squash-merge.
