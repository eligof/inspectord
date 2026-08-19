# scanner_runner — design

| Field | Value |
| --- | --- |
| Date | 2026-08-19 |
| Status | Drafted autonomously; **not yet human-reviewed**. Every decision below is recorded with its rationale so it can be overturned cheaply. |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Parent refs | §5.1 (worker row), §4.3 (parsers), §21 (`av.*` rules), §22.1 (profiles), §24 (CLI), §30.6/§30.13 (dependencies), §31 (Phase 3 roadmap), §18 (egress) |
| Phase | 3 (first slice) |

## 1. Purpose

`scanner_runner` runs the on-disk scanners — AIDE, rkhunter, YARA — on a schedule, parses
their output, and emits normalized Events. The `av.*` starter rules turn those events into
alerts. It is the first Phase 3 worker and the first worker in the project that drives a
subprocess taking **minutes** rather than milliseconds.

ClamAV is explicitly **not** in scope: parent §31 puts only "rkhunter, AIDE, YARA" in Phase 3
and lists the ClamAV manifest as optional. The `clamav_parser` named in §4.3 is deferred.

## 2. What makes this different from every worker shipped so far

Every existing collector either polls cheaply (milliseconds) or streams a long-lived
subprocess. A scanner run is a third shape: **one expensive, fallible, minutes-long job that
must not block the worker's liveness and must not survive the worker's death.** Three
foundations the parent spec assumes are missing today, and this design must not pretend
otherwise:

1. **The supervisor never restarts a dead worker.** Parent §3.2 says it restarts with
   exponential backoff; `supervisor.py` has no such code. §5.1's "per-scan retry" therefore
   cannot lean on it — retry must live inside the worker.
2. **There is no IPC→worker channel.** All IPC handlers talk only to DuckDB; a running worker
   is unreachable. So `inspectorctl scanners run <name>` and `scanners schedule set` (parent
   §24) **cannot be implemented in this slice** — see §5.
3. **`Worker.step()` is synchronous and shutdown budgets 5 seconds for all workers combined.**
   A scan inside `step()` would stop heartbeats for minutes and get SIGKILLed on shutdown,
   orphaning the scanner process.

## 3. Locked decisions

| # | Decision | Rationale |
| --- | --- | --- |
| 1 | **Contract `Worker` shape** (stdin JSON config), not the recent source-worker shape. | The supervisor passes no argv to source workers, so that shape is unconfigurable — and this worker's whole behavior is configuration (which scanners, how often, what paths). |
| 2 | **The scan runs in a worker-owned thread**; `step()` starts a run if one is due and otherwise polls the running one. | Satisfies §5.1's "never blocks main loop" and keeps the 10-second heartbeat alive during a 10-minute scan. |
| 3 | **The scanner subprocess gets its own process group** (`start_new_session=True`) and `teardown()` kills the group. | Without this a SIGKILLed worker orphans a running `aide --check`. Nothing in the repo kills a grandchild today; this worker must not inherit that gap. |
| 4 | **Interval scheduling in v1, not cron.** Per-scanner `interval_s` plus a startup delay, in the worker's config. | Parent §24 commits to `scanners schedule set <name> <cron>`, but that CLI needs the IPC→worker channel that does not exist, and cron parsing would add a dependency to a project that has kept them minimal. Shipping interval scheduling now and cron with the control channel later is strictly better than shipping an unreachable CLI. **Recorded as a deliberate deviation from §24.** |
| 5 | **Scheduled runs only in v1; no on-demand.** | Same missing control channel. See §5. |
| 6 | **Findings are Events; the rule engine makes alerts.** No scanner table in this slice. | Matches §21's `av.*` rule ids and the project's "workers emit events, rules decide" invariant. The materialized `scan_run` state table the Antivirus panel needs is a later slice, so the panel and the collector stay independently reviewable. |
| 7 | **Severity is assigned by rules, not by the worker.** The worker emits findings at `low` and lifecycle events at `info`. | Keeps tuning in YAML rule files the user can edit, exactly like every other collector. The scanner's own severity is preserved as data (§4.2) so a rule can key on it. |
| 8 | **Scanner signature/database updates are never performed.** No `rkhunter --update`, no `freshclam`, ever — not even opt-in — in this slice. | Parent §18.1: "No data leaves the host. Every egress is explicit, opt-in, and enumerated here" — and §18.2's egress table does not list scanner updates at all. AIDE's database is ours and local (§30.6) and YARA rules are bundled, so all three Phase 3 scanners run fully offline. rkhunter's bundled checks still work with a stale mirror db; the staleness is surfaced (§4.3) rather than silently fixed by reaching out to the network. Adding an opt-in updater later requires amending §18.2 first. |
| 9 | **Quarantine is out of scope.** | It is a destructive, privileged, reversible action needing a metadata table (original path, mode, owner), an `audit_log`, and a polkit gate — none of which exist. It belongs with the action executor, not the scanner. |
| 10 | **Exit codes are interpreted per scanner, never as a boolean.** | AIDE's exit status is a bitmask where non-zero means *differences found*, and rkhunter returns non-zero *when it warns*. The repo-wide `returncode == 0` convention is simply wrong for both, and reporting a successful detection as a failed scan would be the worst possible bug in a security scanner. |
| 11 | **A failed scan is always reported, never silent.** | The house convention for a failed capture is to emit nothing (`firewall_inspector`, `services_monitor`). For a scanner that is unacceptable: a scan that silently never runs looks identical to a clean machine. Failures emit `scan_completed` with `outcome="failure"`. |
| 12 | **Findings per run are capped** (default 500) and truncation is itself an event. | The router subscription is 4096 deep with `drop_oldest_non_critical`, and a first-run AIDE diff can produce thousands of findings. Silent drops would be indistinguishable from a parse bug in the logs. |
| 13 | **rkhunter is read from its stdout**, not its log file. | Avoids requiring the `/etc/rkhunter.conf.d/inspectord.conf` drop-in (§30.6) before the worker can do anything. `--report-warnings-only` makes stdout the exact finding set. |
| 14 | **A missing scanner binary emits `scan_skipped`, once per due cycle.** | Nothing in the repo gates workers on dependencies, and `dep_state` is only written by the plan-apply path. Silently skipping would mean the user believes AIDE runs nightly when the binary was never installed. This sets the precedent deliberately. |
| 15 | **Profile: `standard`.** | Parent §5.1 says "both", §22.1 says `standard` only. Resolved toward §22.1: multi-minute scans do not belong in the minimal profile. (Profiles are unenforced today, so this only sets `required_when.profiles` in manifests.) |
| 16 | **The Hunt panel is a separate deliverable**, sharing only the phase. | It is a query compiler with its own grammar decisions; bundling it would make both unreviewable. |

## 4. Design

### 4.1 Scanner adapters

One adapter per scanner, each a small module under
`inspectord/workers/scanner_runner/scanners/`, exposing:

```python
class ScannerAdapter(Protocol):
    name: str                       # "aide" | "rkhunter" | "yara"
    binary: str                     # probed with shutil.which before each run
    def argv(self, config: dict[str, Any]) -> list[str]: ...
    def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome: ...  # decision 10
    def parse(self, stdout: str, stderr: str) -> list[Finding]: ...
```

`ScanOutcome` is one of `clean` / `findings` / `failure`, decided per scanner:

- **AIDE** — `aide --config <ours> --check`. Exit status is a bitmask: 0 = no differences;
  the low bits mean new/removed/changed entries (all *findings*, not failure); the high error
  bits mean a real error (write error, config error). The database lives under
  `/var/lib/inspectord/aide/` per §30.6, and we ship the config.
- **rkhunter** — `rkhunter --check --skip-keypress --nocolors --report-warnings-only`.
  Exit 0 = no warnings, 1 = warnings found (*findings*), 2 = error.
- **YARA** — `yara -r -w <rules-dir> <target>` over the bundled rulesets in
  `/var/lib/inspectord/yara/` (§30.6). Exit 0 with no output = clean; matches print to stdout;
  non-zero = failure.

Exact bit values and flags are to be confirmed against the installed tools' man pages when
each adapter is written — the table tests in §8 are where that gets pinned down.

Parsers follow the rule stated in `inspectord/parsers/base.py`: **never raise on unparseable
input** — an unrecognized line is skipped, not fatal. Scanner output is untrusted input; it
embeds attacker-controllable file paths.

### 4.2 Events

Three lifecycle actions plus one finding action, all `module="scanner_runner"`:

| action | kind | severity | when |
| --- | --- | --- | --- |
| `scan_started` | `event` | `info` | a run begins |
| `scan_completed` | `event` | `info` | a run ends; carries `outcome` (`success`/`failure`), duration, finding count, truncation flag |
| `scan_skipped` | `event` | `info` | the scanner binary is absent, or a run is already in flight |
| `scan_finding` | `event` | `low` | one parsed finding |

A finding event:

```python
build_event(
    module="scanner_runner",
    action="scan_finding",
    category=["file"],          # "process" for rkhunter checks that are not file-scoped
    type_=["info"],
    severity="low",             # decision 7 — rules assign the real severity
    file={"path": "/usr/bin/example", "hash": {"sha256": "<hex>"}},   # when the scanner gives one
    threat={
        "indicator": {
            "type": "yara_rule",        # "rkhunter_test" | "aide_change" | "yara_rule"
            "value": "SUSP_Example_Rule",
            "source": "yara",           # the scanner, rule-matchable
            "severity": "high",         # the SCANNER's own severity, preserved as data
        }
    },
    raw={"scanner": "yara", "run_id": "<uuid7>", "line": "<the raw output line>"},
)
```

`run_id` correlates a finding with its `scan_started`/`scan_completed` pair. It lives in `raw`
because the Event schema has no scan block, and `labels` is invisible to the YAML rule engine
(`yaml_loader._resolve_path` cannot walk a list).

**`build_event` gains a `threat=` keyword** — it currently cannot set `threat` at all, so the
alternative is constructing `Event(...)` by hand in this one worker, diverging from every
sibling. The change is additive and defaults to `None`.

### 4.3 Staleness is surfaced, not silently tolerated

Because decision 8 forbids updating scanner databases, `scan_completed` carries the age of the
scanner's own data where the scanner exposes it (e.g. the AIDE database's mtime). A later rule
can then alert on "AIDE database older than N days" with no network access. Reporting staleness
is the honest alternative to fixing it behind the user's back.

### 4.4 Scheduling and single-flight

Config (contract worker, delivered on stdin):

```json
{
  "interval_s": 60,
  "startup_delay_s": 120,
  "max_findings_per_run": 500,
  "max_output_bytes": 8388608,
  "scanners": {
    "aide":     {"enabled": true,  "interval_s": 86400, "timeout_s": 3600},
    "rkhunter": {"enabled": true,  "interval_s": 86400, "timeout_s": 1800},
    "yara":     {"enabled": false, "interval_s": 86400, "timeout_s": 1800, "targets": ["/home", "/tmp"]}
  }
}
```

The top-level `interval_s` is the worker's own tick (how often it checks whether anything is
due), deliberately far shorter than any scan interval. `startup_delay_s` keeps a heavy scan off
the boot path — parent §27.4 wants heavy workers deferred and nothing implements it, so the
worker defers itself.

**Single-flight**: at most one scan runs at a time across all scanners. A scanner that is due
while another run is in flight waits for the next tick, and that is a `scan_skipped` event with
a reason rather than silence. Accepted v1 limitation: a daemon restart mid-scan loses the
in-flight marker, since it lives in memory — the next tick simply starts a fresh run.

**Retry** (§5.1's "per-scan retry"): one retry after a short backoff on `failure`, then give up
until the next scheduled slot. Retries are bounded by the same per-scan timeout.

### 4.5 Timeouts and cleanup

Each scanner has a `timeout_s`. On timeout the process **group** is terminated, then killed,
and the run reports `outcome="failure"` with a `timeout` reason. `teardown()` does the same for
a shutdown mid-scan. This is the mechanism that makes decision 3 real.

## 5. Deliberate deviations from the parent spec

Recorded plainly so a reviewer can reverse them:

1. **No `inspectorctl scanners run` / `scanners schedule set`** (§24). Both need an IPC→worker
   control channel that does not exist. Building one is a daemon-architecture change deserving
   its own design — routing commands through a DuckDB table polled by workers is the option
   that fits the current architecture best, but it should be chosen deliberately, not smuggled
   in under a scanner PR.
2. **Interval scheduling instead of cron** (§24), for the same reason plus dependency
   minimalism.
3. **Profile is `standard`, not "both"** (§5.1 vs §22.1) — see decision 15.
4. **On-demand runs do not "propose a pending action"** (§2.2), because `pending_actions` is a
   Phase 4 table that does not exist.
5. **Scanner database updates are not performed at all**, where §30.6 implies rkhunter's mirror
   db is maintained. Amending §18.2's egress table is a prerequisite for ever changing this.

## 6. Slices

Each is independently useful and separately reviewable:

- **PR1 — framework + AIDE.** The threaded runner, process-group cleanup, timeout handling,
  single-flight, the adapter Protocol, the AIDE adapter and parser, lifecycle + finding events,
  `build_event(threat=...)`, dev-config wiring. AIDE first because its database is ours, so it
  is the one scanner fully deterministic under test.
- **PR2 — rkhunter + YARA adapters**, plus the `rkhunter` dependency manifest that §31 already
  owes (Phase 2 listed it; it was never added).
- **PR3 — the `av.*` starter rules** (§21): `av.rkhunter_warning_or_worse`,
  `av.yara_high_confidence_hit`, `av.aide_change_outside_pkgmgr`. The AIDE rule needs
  package-manager correlation, so it may reduce to "change outside a pacman transaction window"
  in v1 — decide when writing it.
- **Later, each needing its own design**: the `scan_run` state table + Antivirus panel; the
  IPC→worker control channel (which unlocks on-demand runs and cron); quarantine; Hunt.

## 7. Out of scope

ClamAV; quarantine; the Hunt panel; on-demand runs; cron schedules; the Antivirus panel;
scanner database updates of any kind; `pending_actions`; supervisor restart/backoff (a real gap
— parent §3.2 describes behavior that does not exist — but it is a supervisor concern, not a
scanner one, and this worker is written to survive its absence).

## 8. Testing

Per repo `CLAUDE.md`, TDD throughout:

- Adapter parsers are pure functions over captured scanner-output fixtures — no subprocess, no
  root. Every parser gets a malformed-input test asserting it returns the findings parsed so far
  rather than raising.
- `interpret_outcome` gets a table test per scanner, explicitly covering the case that matters
  most: **a non-zero exit meaning "findings", not "failure"**.
- The threaded runner is tested with a fake adapter whose "scan" is a controllable sleep,
  covering: a run completing, a run timing out and being killed, `teardown()` during a run,
  single-flight rejection, and the finding cap with its truncation event.
- Process-group cleanup is tested by starting a real `sleep` subprocess through the runner and
  asserting the group is gone after `teardown()`.
- No root-only test is needed for PR1 — nothing here touches eBPF.
