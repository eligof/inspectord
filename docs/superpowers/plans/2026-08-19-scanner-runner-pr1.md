# scanner_runner — framework + AIDE (PR1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first Phase 3 worker: a contract-shaped `scanner_runner` that runs an on-disk
scanner in a worker-owned thread, kills it by process group on timeout and on shutdown, and turns
its output into normalized Events. PR1 carries the framework plus the **AIDE** adapter only.

**Architecture:** A `Worker` subclass (stdin JSON config, NDJSON on stdout) whose `step()` is a
tick, not a scan. Each tick either starts a due scan in a daemon thread or polls the in-flight one.
Exactly one scan runs at a time (single-flight); a scanner that is due while a run is in flight
emits `scan_skipped`. The subprocess is spawned with `start_new_session=True` so it owns its
process group, and every kill path (`timeout`, `teardown`) signals that **group** — a SIGKILLed
worker must not orphan a running `aide --check`. Scanner-specific knowledge lives entirely in
adapters under `scanners/`, behind a three-method Protocol (`argv` / `interpret_exit` / `parse`).

**Tech Stack:** Python 3.14 stdlib only (`subprocess`, `threading`, `os`, `signal`, `shutil`),
pydantic `Event` (`inspectord/schemas/event.py`), `build_event` (`inspectord/parsers/base.py`),
`Worker` (`inspectord/workers/contract.py`), pytest. **No new third-party dependencies.**

**Spec:** `docs/superpowers/specs/2026-08-19-scanner-runner-design.md` — §3 decisions 1–3, 6, 7,
10–12, 14; §4.1 (adapters), §4.2 (events), §4.4 (scheduling/single-flight), §4.5 (timeouts and
cleanup), §6 (PR1 line), §8 (testing).

**Explicitly NOT in this PR:** rkhunter, YARA, ClamAV, the `av.*` rules, quarantine, on-demand
runs, cron, any state table or migration, any panel or CLI command.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/parsers/base.py` | Add an additive `threat: dict[str, Any] \| None = None` keyword to `build_event`, passed straight through to `Event.threat`. No existing behavior changes. |
| `inspectord/workers/scanner_runner/__init__.py` | Package docstring only (mirrors sibling workers). |
| `inspectord/workers/scanner_runner/scanners/__init__.py` | Package docstring + `default_adapters()` registry (PR1: AIDE only). |
| `inspectord/workers/scanner_runner/scanners/base.py` | `ScanOutcome` (`clean`/`findings`/`failure`), the `Finding` dataclass, the `ScannerAdapter` Protocol (spec §4.1). |
| `inspectord/workers/scanner_runner/scanners/aide.py` | `AideAdapter`: `argv()`, `interpret_exit()` (the bitmask — decision 10), `parse()` over `aide --check` report output. |
| `inspectord/workers/scanner_runner/runner.py` | `signal_process_group()` / `kill_process_group()`, `_ScanJob` (the threaded subprocess), `ScannerRunnerWorker`. |
| `inspectord/workers/scanner_runner/__main__.py` | `main()`: read config from stdin, run the worker. |
| `inspectord/config.py` | `scanner_runner` `WorkerSpec` in the dev-config worker list, **with `aide.enabled = false`**. |
| `packaging/config.example.toml` | Matching `[[workers]]` block (kept in lockstep by `tests/test_config_example.py::test_example_config_worker_names_match_dev_config`). |
| `tests/parsers/test_base.py` | New tests for the `threat=` keyword (present, absent, and the existing default). |
| `tests/workers/test_scanner_runner_aide_adapter.py` | `argv`, the `interpret_exit` **table test**, report parsing, malformed-input tests. |
| `tests/workers/test_scanner_runner_runner.py` | The threaded runner against a fake adapter: completion, timeout+kill, `teardown()` mid-run, single-flight rejection, missing binary, finding cap + truncation, retry, startup delay. |
| `tests/workers/test_scanner_runner_process_group.py` | Real-subprocess test: a `sleep` started through the runner, group gone after `teardown()`. |
| `tests/test_dev_config_scanner_runner.py` | Dev-config presence + the conservative `enabled: false` default. |

---

## The AIDE exit bitmask (decision 10 — the thing to get right)

AIDE is **not installed on this machine** (`which aide` → not found, `man aide` → no entry), so the
values below come from the documented `EXIT STATUS` section of the AIDE manual for the 0.16–0.18
series (the dependency manifest `inspectord/dependencies/manifest_files/aide.yaml` pins
`minimum_version: "0.18"`), not from the installed binary. **This must be re-verified against a
real `man aide` before PR1 merges.**

| status | meaning | `ScanOutcome` |
| --- | --- | --- |
| `0` | no differences | `clean` |
| `1` | new entries detected | `findings` |
| `2` | removed entries detected | `findings` |
| `4` | changed entries detected | `findings` |
| `3`, `5`, `6`, `7` | the above ORed together | `findings` |
| `14` | write error | `failure` |
| `15` | invalid argument | `failure` |
| `16` | unimplemented function | `failure` |
| `17` | invalid config line | `failure` |
| `18` | IO error | `failure` |
| `19` | version mismatch | `failure` |
| anything else (`8`–`13`, `≥20`, negative/signal codes) | unknown | `failure` |

The implementation is written as `0 → clean`, `1 <= code <= 7 → findings`, **everything else →
`failure`** rather than as an enumeration of the error codes. That way a future AIDE that adds a
new error code is reported as a failure (safe) instead of being silently treated as clean, and the
low-bit range — the part that must never be misread as a failure — is exact.

---

### Task 1: `build_event(threat=...)`

**Files:**
- Modify: `inspectord/parsers/base.py`
- Test: `tests/parsers/test_base.py`

- [ ] **Step 1: Write the failing tests** in `tests/parsers/test_base.py`:

```python
def test_build_event_accepts_threat() -> None:
    ev = build_event(
        module="scanner_runner",
        action="scan_finding",
        category=["file"],
        type_=["info"],
        severity="low",
        threat={"indicator": {"type": "aide_change", "value": "changed"}},
    )
    assert ev.threat == {"indicator": {"type": "aide_change", "value": "changed"}}


def test_build_event_threat_defaults_to_none() -> None:
    ev = build_event(module="m", action="a", category=["host"], type_=["info"], severity="info")
    assert ev.threat is None
```

- [ ] **Step 2: Run; expect FAIL** (`TypeError: unexpected keyword argument 'threat'`).
- [ ] **Step 3: Add the keyword** — one parameter in the signature (next to `persistence`) and one
      `threat=threat,` line in the `Event(...)` call. Nothing else changes.
- [ ] **Step 4: Run `tests/parsers/`; expect PASS.**
- [ ] **Step 5: Commit** — `feat(parsers): build_event(threat=...) passthrough`

---

### Task 2: adapter Protocol + types (`scanners/base.py`)

**Files:**
- Create: `inspectord/workers/scanner_runner/__init__.py`
- Create: `inspectord/workers/scanner_runner/scanners/__init__.py`
- Create: `inspectord/workers/scanner_runner/scanners/base.py`

Types, per spec §4.1 / §4.2:

```python
class ScanOutcome(StrEnum):
    clean = "clean"
    findings = "findings"
    failure = "failure"


@dataclass(frozen=True)
class Finding:
    """One normalized scanner finding. Maps 1:1 onto a `scan_finding` Event."""

    indicator_type: str                 # "aide_change" | "rkhunter_test" | "yara_rule"
    indicator_value: str                # the scanner-specific identifier
    raw_line: str                       # the output line this came from
    category: str = "file"              # ECS event.category ("process" for non-file findings)
    path: str | None = None             # -> file.path
    hashes: dict[str, str] | None = None  # -> file.hash
    severity: str | None = None         # the SCANNER's own severity, preserved as data (dec. 7)
    message: str | None = None


class ScannerAdapter(Protocol):
    name: str
    binary: str
    def argv(self, config: Mapping[str, Any]) -> list[str]: ...
    def interpret_exit(self, code: int) -> ScanOutcome: ...
    def parse(self, stdout: str, stderr: str) -> list[Finding]: ...
```

`severity` is `str | None` because AIDE emits no severity of its own; the runner omits the key from
`threat.indicator` when it is `None` rather than inventing one.

- [ ] **Step 1:** write the three files (the `scanners/__init__.py` registry stays empty until Task 3).
- [ ] **Step 2:** `.venv/bin/mypy inspectord`; expect clean. (Committed with Task 3.)

---

### Task 3: the AIDE adapter

**Files:**
- Create: `inspectord/workers/scanner_runner/scanners/aide.py`
- Modify: `inspectord/workers/scanner_runner/scanners/__init__.py` (`default_adapters()`)
- Test: `tests/workers/test_scanner_runner_aide_adapter.py`

- [ ] **Step 1: Write the failing tests.**

The `interpret_exit` **table test** is the centerpiece (decision 10) — it must contain at least one
non-zero code mapping to `findings`:

```python
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0, ScanOutcome.clean),
        (1, ScanOutcome.findings),   # new entries
        (2, ScanOutcome.findings),   # removed entries
        (3, ScanOutcome.findings),   # new | removed
        (4, ScanOutcome.findings),   # changed entries
        (5, ScanOutcome.findings),
        (6, ScanOutcome.findings),
        (7, ScanOutcome.findings),   # new | removed | changed
        (14, ScanOutcome.failure),   # write error
        (15, ScanOutcome.failure),
        (16, ScanOutcome.failure),
        (17, ScanOutcome.failure),
        (18, ScanOutcome.failure),
        (19, ScanOutcome.failure),
        (8, ScanOutcome.failure),    # undocumented -> failure, never clean
        (255, ScanOutcome.failure),
        (-9, ScanOutcome.failure),   # killed by a signal
    ],
)
def test_interpret_exit(code, expected): ...


def test_nonzero_exit_is_findings_not_failure() -> None:
    """The bug this test exists to prevent: reporting a real detection as a broken scan."""
    assert AideAdapter().interpret_exit(4) is ScanOutcome.findings
```

Plus: `argv` uses the inspectord-owned config path and never a shell string; the report parser over
a captured-shape fixture yields added/removed/changed findings with the right paths; the legacy
`added: /path` form parses; and the malformed-input tests:

```python
def test_parse_malformed_returns_findings_so_far() -> None:
    text = ADDED_SECTION + "\n\x00\xff garbage not a line\n" + "f++++++++++++++++: /etc/second\n"
    findings = AideAdapter().parse(text, "")
    assert [f.path for f in findings] == ["/etc/first", "/etc/second"]


def test_parse_empty_and_binary_never_raise() -> None:
    for text in ("", "\n\n\n", "\x00\x01\x02", "Summary:\n  Total number of entries:\t12345\n"):
        assert AideAdapter().parse(text, "") == []
```

- [ ] **Step 2: Run; expect FAIL** (`ModuleNotFoundError`).

- [ ] **Step 3: Write the adapter.**

```python
_CONFIG_PATH = "/var/lib/inspectord/aide/aide.conf"   # spec §30.6 — the database is ours

class AideAdapter:
    name = "aide"
    binary = "aide"

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        config_path = str(config.get("config_path") or _CONFIG_PATH)
        return [self.binary, "--config", config_path, "--check"]

    def interpret_exit(self, code: int) -> ScanOutcome:
        if code == 0:
            return ScanOutcome.clean
        if 1 <= code <= 7:      # bitmask: 1 new | 2 removed | 4 changed
            return ScanOutcome.findings
        return ScanOutcome.failure
```

`parse()` walks the report line by line with a small state machine:

- A line whose stripped, lowercased form is `added entries:` / `removed entries:` / `changed
  entries:` (or the older `... files:`) opens that section.
- Any other line ending in `:` that is a known terminator (`detailed information about changes:`,
  `summary:`, `the attributes of the (uncompressed) database:`) closes the current section, so the
  per-file detail block is never double-counted.
- Inside a section, a line matching `^(?P<attrs>\S[^:]*):\s+(?P<path>/.*\S)\s*$` is one finding.
  Requiring the path to start with `/` is what keeps `  Total number of entries:\t123` out.
- Anywhere, the legacy `^(added|removed|changed):\s+(?P<path>/.*\S)\s*$` form is one finding.
- Everything else is skipped. Nothing raises: the whole per-line body is defensive, and
  `stdout`/`stderr` are treated as untrusted (they embed attacker-controllable file paths).

Each finding becomes:

```python
Finding(
    indicator_type="aide_change",
    indicator_value=change,        # "added" | "removed" | "changed"
    raw_line=line,
    category="file",
    path=path,
    severity=None,                 # AIDE has no severity of its own
    message=f"AIDE: {change} {path}",
)
```

`indicator_value` is the change kind rather than the path: the path already lives in `file.path`,
and a rule keying on `threat.indicator.value == "changed"` is the useful predicate. Recorded here
because it is a choice the spec left open.

- [ ] **Step 4:** add `default_adapters()` to `scanners/__init__.py` returning `[AideAdapter()]`.
- [ ] **Step 5: Run the adapter tests; expect PASS.**
- [ ] **Step 6: Gates; commit** — `feat(scanner_runner): ScannerAdapter protocol + AIDE adapter`

---

### Task 4: the threaded runner

**Files:**
- Create: `inspectord/workers/scanner_runner/runner.py`
- Create: `inspectord/workers/scanner_runner/__main__.py`
- Test: `tests/workers/test_scanner_runner_runner.py`

**Process-group discipline (decision 3 — the most important property in this PR).**

```python
def _pgid_of(proc) -> int | None:
    """The process's group id. With start_new_session=True this is its own pid."""

def signal_process_group(proc, sig) -> None:
    """Send *sig* to the whole group; fall back to the process alone. NEVER raises."""

def kill_process_group(proc, *, grace_s: float = 5.0) -> None:
    """terminate -> wait -> kill -> wait, on the GROUP. NEVER raises.

    Called only from the thread that owns *proc* (so it never races communicate()).
    """
```

Every syscall is individually wrapped: by the time we kill, the process may already be gone
(`ProcessLookupError`), reaped, or never have started.

**`_ScanJob`** owns one subprocess in one daemon thread:

- `start()` spawns the thread; the thread calls `spawn(argv)` → `subprocess.Popen(..., stdin=DEVNULL,
  stdout=PIPE, stderr=PIPE, text=True, errors="replace", start_new_session=True)`.
- Immediately after spawning it re-checks the cancel flag (closing the teardown-before-spawn race)
  and kills the group if set.
- `proc.communicate(timeout=timeout_s)`; on `TimeoutExpired` it sets `timed_out`, calls
  `kill_process_group(proc)`, then drains with a short second `communicate()`.
- A spawn failure (`FileNotFoundError`, `PermissionError`, …) is captured as `error=repr(exc)`, not
  raised — the worker must report a failed scan, never die (decision 11).
- `cancel(grace_s)`: set the flag, SIGTERM the group, `thread.join(grace)`, and if still alive
  SIGKILL the group and join again. The **thread** is what we wait on, so only the job thread ever
  touches `proc.communicate()`/`proc.wait()` — no cross-thread wait race.

**`ScannerRunnerWorker(Worker)`** — config (spec §4.4), all with defaults:

| key | default | meaning |
| --- | --- | --- |
| `interval_s` | `60.0` | the worker's own tick, via `step_interval_s()` |
| `startup_delay_s` | `120.0` | nothing is eligible before this (spec §4.4 / parent §27.4) |
| `max_findings_per_run` | `500` | decision 12 |
| `retry_backoff_s` | `60.0` | the single retry after a failure |
| `scanners.<name>.enabled` | `False` | per-scanner |
| `scanners.<name>.interval_s` | `86400.0` | per-scanner schedule |
| `scanners.<name>.timeout_s` | `3600.0` | per-scanner kill deadline |

`step()`:

1. If a run is in flight and its job is done → finish it (emit findings + `scan_completed`), clear
   the slot, and reschedule (`retry_backoff_s` for the first failure, otherwise `interval_s`).
2. Walk the due, enabled scanners in name order.
   - If a run is (still) in flight → `scan_skipped` with `reason="run_in_flight"`, **once per due
     window** (a `_skip_notified` set, cleared when that scanner actually starts). Without the
     suppression a 60-second tick under a one-hour scan would emit 60 identical events. The
     scanner keeps its due time, so it starts on the first free tick.
   - Else if `shutil.which(adapter.binary) is None` → `scan_skipped` with
     `reason="binary_not_found"` (decision 14) and the slot is **consumed**
     (`next_due = now + interval_s`), which is what "once per due cycle" means.
   - Else start the run: `scan_started`, then the job.
3. `teardown()` cancels any in-flight job (killing the group) and emits a `scan_completed` with
   `outcome="failure"`, `reason="shutdown"`, so a scan interrupted by shutdown is never silent.

Findings are capped at `max_findings_per_run`; the surplus is dropped and `scan_completed` carries
`truncated: true` plus `findings_dropped`.

Events, per spec §4.2 (`module="scanner_runner"`, `kind="event"`):

| action | category | type | severity | `outcome` | key `raw` fields |
| --- | --- | --- | --- | --- | --- |
| `scan_started` | `["process"]` | `["start"]` | `info` | — | `scanner`, `run_id`, `argv` |
| `scan_completed` | `["process"]` | `["end"]` | `info` | `success`/`failure` | `scanner`, `run_id`, `scan_outcome`, `exit_code`, `duration_s`, `finding_count`, `findings_dropped`, `truncated`, `reason` |
| `scan_skipped` | `["process"]` | `["info"]` | `info` | — | `scanner`, `reason`, `binary` |
| `scan_finding` | from the `Finding` | `["info"]` | `low` | — | `scanner`, `run_id`, `line` |

`scan_finding` also sets `file={"path": ..., "hash": {...}}` when the finding has one, and
`threat={"indicator": {"type", "value", "source": <scanner>, "severity": <scanner's own>}}` with
`severity` omitted when the scanner does not provide one.

- [ ] **Step 1: Write the failing tests** in `tests/workers/test_scanner_runner_runner.py`, using a
      `FakeAdapter` whose `argv()` is a controllable **real** `sh -c 'sleep N; ...'` (fast, no root,
      and it exercises the real spawn/kill path), plus a `spawn` injection point for the
      spawn-failure case:

  - `test_run_completes_and_emits_lifecycle_and_findings` — `scan_started`, N `scan_finding`,
    `scan_completed` with `outcome="success"`, matching `run_id` on all of them.
  - `test_clean_run_emits_no_findings`
  - `test_startup_delay_defers_the_first_scan`
  - `test_run_timing_out_is_killed_and_reported_failure` — `scan_completed` `outcome="failure"`,
    `raw.reason == "timeout"`, and the process is gone.
  - `test_teardown_during_a_run_kills_it_and_reports_failure` — `raw.reason == "shutdown"`.
  - `test_single_flight_rejects_a_second_due_scanner` — `scan_skipped`, `reason="run_in_flight"`,
    emitted once, and the loser runs on a later tick.
  - `test_missing_binary_emits_scan_skipped` — `reason="binary_not_found"`, and the slot is consumed.
  - `test_finding_cap_truncates_and_flags` — `max_findings_per_run=3`, 10 findings ⇒ 3
    `scan_finding` events and `scan_completed` with `truncated is True`, `findings_dropped == 7`.
  - `test_failure_retries_once_then_waits_for_the_next_slot`
  - `test_spawn_failure_is_reported_not_raised`
  - `test_disabled_scanner_never_runs`

- [ ] **Step 2: Run; expect FAIL** (`ModuleNotFoundError`).
- [ ] **Step 3: Write `runner.py` and `__main__.py`.**
- [ ] **Step 4: Run the runner tests; expect PASS.**
- [ ] **Step 5: Gates; commit** — `feat(scanner_runner): threaded single-flight scan runner`

---

### Task 5: the real process-group test

**Files:**
- Test: `tests/workers/test_scanner_runner_process_group.py`

Decision 3 deserves a test that does not mock anything (spec §8).

- [ ] **Step 1: Write it.** An adapter whose `argv()` is `["sh", "-c", "sleep 300 & sleep 300"]` —
      the backgrounded child is a **grandchild** in the same new session, so killing only the direct
      child would leave it running and prove nothing. Start it through the runner, capture the
      group id, call `teardown()`, then assert with `os.killpg(pgid, 0)` that the group is gone
      (`ProcessLookupError`), polling briefly for the reap.
- [ ] **Step 2:** the same assertion for the **timeout** path (`timeout_s=0.3`).
- [ ] **Step 3: Run; expect PASS. Commit** — `test(scanner_runner): real process-group cleanup`

---

### Task 6: dev-config + example-config wiring

**Files:**
- Modify: `inspectord/config.py`
- Modify: `packaging/config.example.toml`
- Test: `tests/test_dev_config_scanner_runner.py`

`tests/test_config_example.py::test_example_config_worker_names_match_dev_config` asserts the two
worker-name sets are equal, so both files MUST change together.

**Conservative default (required):** this is the first multi-minute worker in the project, so it
ships with `aide.enabled = false`. The worker starts, ticks cheaply, and never scans until the
operator opts in. A long interval alone is not enough — `aide` is not installed on a stock
developer box, so an enabled scanner would emit a `scan_skipped` on every developer run for a scan
that was never going to happen. `startup_delay_s` is 300 and `interval_s` (per scanner) 86400.

```python
{
    "name": "scanner_runner",
    "module": "inspectord.workers.scanner_runner",
    "config": {
        "interval_s": 60.0,
        "startup_delay_s": 300.0,
        "max_findings_per_run": 500,
        # Disabled by default: a scan takes minutes. Opt in per host.
        "scanners": {"aide": {"enabled": False, "interval_s": 86400.0, "timeout_s": 3600.0}},
    },
},
```

- [ ] **Step 1: Write the failing presence test** (worker present; `aide.enabled` is `False`).
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Add the `config.py` entry and the matching TOML block.**
- [ ] **Step 4: Run `tests/test_dev_config_scanner_runner.py` and `tests/test_config_example.py`; expect PASS.**
- [ ] **Step 5: Commit** — `feat(config): register the scanner_runner worker (disabled)`

---

### Task 7: full gates

- [ ] **Step 1:**

```sh
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q && \
.venv/bin/ruff check inspectord tests && \
.venv/bin/ruff format --check inspectord tests && \
.venv/bin/mypy inspectord
```

Expected: exit 0 from each; mypy prints `Success: no issues found`.

- [ ] **Step 2:** report. Do not push, do not open a PR, do not merge.

---

## Self-Review notes

- **Spec coverage:** §6's PR1 line maps to Task 1 (`build_event(threat=...)`), Tasks 2–3 (adapter
  Protocol + AIDE), Task 4 (threaded runner, timeouts, single-flight, lifecycle + finding events),
  Task 5 (process-group cleanup), Task 6 (dev-config wiring).
- **Deliberately deferred from the design, with reasons:**
  - **§4.3 scanner-data staleness** (`scan_completed` carrying the AIDE database's mtime age) is
    *not* in this PR. The adapter surface this PR was scoped to is exactly `argv` / `interpret_exit`
    / `parse`; adding a fourth method changes the Protocol every later adapter implements, and the
    staleness field has no consumer until the `av.*` rules (PR3). Flagged for the reviewer.
  - Retry uses a fixed `retry_backoff_s`, not exponential backoff — §4.4 says "one retry after a
    short backoff", and one retry has no backoff curve to speak of.
- **`interpret_exit` is range-based, not an enumeration** — see the bitmask table above. This is the
  single most consequential line in the PR and it fails toward `failure`, never toward `clean`.
- **AIDE is not installed on this machine**, so the bitmask is implemented from the documented
  `EXIT STATUS` section rather than verified against `man aide`. Called out in the plan, in the
  adapter's docstring, and in the final report.
- **Two-file wiring:** `config.py` and `config.example.toml` change in the same commit because
  `test_config_example.py` asserts set equality.
- **Threading discipline:** only the job thread calls `communicate()`/`wait()`; other threads only
  *send signals* and `join()` the thread. That is what keeps `teardown()` from racing the scan.
