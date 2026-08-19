# Supervisor worker restart with exponential backoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make spec §3.2 (“a crashed worker doesn't take down the system; the supervisor restarts it with exponential backoff”) true. Today `Supervisor.start()` spawns each worker exactly once and nothing ever polls the children — a collector that crashes stays dead, silently, until the whole daemon restarts. That is a monitoring blind spot with no signal at all.

**Architecture:** One daemon monitor thread owned by the supervisor, started last by `start()`, polling every `poll_interval_s` (~1 s). Per tick it walks `self._procs`; `proc.poll()` returning non-`None` means the child died. A dead worker gets a `worker_died` event, its reader threads joined and pipes closed, then a respawn scheduled `backoff(attempt)` seconds out (1 s doubling to a 60 s cap). Respawn replaces the `_WorkerProc` **in place** in `self._procs` (fresh pipes, fresh reader threads) and emits `worker_restarted`. Consecutive-restart bookkeeping lives on the `_WorkerProc` and is carried across respawns; it resets once a restarted worker has been alive for `restart_healthy_after_s` (60 s). After `restart_max_attempts` (8) consecutive restarts that never reached the healthy threshold, the worker is left dead, marked `exhausted`, and `worker_restart_exhausted` (severity high) is emitted — the event that says a collector is permanently down.

All three events go through the *same* dispatch path worker events take (enrich → rule engine → evidence → alert listeners → router publish), factored out of the duplicated bodies of `_read_stdout` / `_inject_for_test` into `_dispatch`. `RouterFull` is caught and logged there so the monitor thread can never die on a saturated router.

**Shutdown ordering is load-bearing:** `stop()` sets `self._stop` and **joins the monitor thread before terminating any worker**, so the monitor cannot helpfully restart everything mid-shutdown. The monitor loop waits on `self._stop.wait(interval)` (not `sleep`), so the join returns promptly, and it re-checks `self._stop` inside the per-worker loop before respawning.

**Tech Stack:** Python 3.14, stdlib `threading`/`subprocess`, pydantic `Event` schema, `build_event` (`inspectord/parsers/base.py`), YAML rule loader, pytest.

**Spec:** `docs/superpowers/specs/2026-05-24-local-inspection-design.md` §3.2 (“Workers are isolated processes … the supervisor restarts it with exponential backoff”), §3.4 (worker table: “Restart with backoff”).

---

## Tunables

Module constants in `inspectord/supervisor.py`, each overridable via a keyword-only
`Supervisor.__init__` parameter so tests never wait real seconds:

| Constant | Default | Meaning |
| --- | --- | --- |
| `MONITOR_POLL_INTERVAL_S` | `1.0` | how often the monitor polls the children |
| `RESTART_BASE_DELAY_S` | `1.0` | delay before the 1st restart |
| `RESTART_MAX_DELAY_S` | `60.0` | backoff cap |
| `RESTART_HEALTHY_AFTER_S` | `60.0` | uptime that resets the consecutive-restart counter |
| `RESTART_MAX_ATTEMPTS` | `8` | consecutive restarts before giving up |

`backoff_delay(attempt, base, cap) = min(base * 2 ** (attempt - 1), cap)` — a module-level
pure function so the growth curve is unit-testable without any sleeping.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/supervisor.py` | `backoff_delay`, restart bookkeeping on `_WorkerProc`, `_monitor` / `_monitor_tick` / `_handle_dead_worker` / `_respawn`, `_dispatch` refactor, `_emit_supervisor_event`, monitor-aware `stop()`. |
| `inspectord/rules/starter_pack/daemon_worker_restart_exhausted.yaml` | `daemon.worker_restart_exhausted` — high — fires on the exhausted event. |
| `tests/test_supervisor_restart.py` | The restart behaviour suite (real `Supervisor`, real child processes). |
| `tests/rules/starter_pack/test_daemon_worker_restart_exhausted.py` | Rule fires / does-not-fire matrix. |

**Event contract** (all `module="supervisor"`, `category=["process"]`):

| action | severity | type | `raw` fields |
| --- | --- | --- | --- |
| `worker_died` | `medium` | `["end"]` | `worker`, `exit_code`, `signal` (int if `exit_code < 0`, else `None`), `restarts` (restarts so far) |
| `worker_restarted` | `info` | `["start"]` | `worker`, `attempt`, `backoff_s` |
| `worker_restart_exhausted` | `high` | `["error"]` | `worker`, `attempts` |

Worker identity lives in `raw.worker` rather than `process`/`service` deliberately: the
enrichers would try to resolve a `process.pid` that is by definition gone, and
`state/projector.py` ignores `module == "supervisor"` so nothing is projected.

---

### Task 1: backoff curve + tunables

**Files:**
- Modify: `inspectord/supervisor.py`
- Test: `tests/test_supervisor_restart.py`

- [ ] **Step 1:** Write failing tests for `backoff_delay`: 1, 2, 4, 8, 16, 32 then capped at 60 for
  attempts 7+; `attempt <= 1` returns the base; a custom base/cap is honoured.
- [ ] **Step 2:** Run; expect `ImportError`.
- [ ] **Step 3:** Add the five module constants, the `backoff_delay` function, and the
  keyword-only `Supervisor.__init__` overrides (stored on `self`).
- [ ] **Step 4:** Run; expect PASS. Commit — `feat(supervisor): restart backoff tunables`.

---

### Task 2: the monitor thread — detect, restart, exhaust

**Files:**
- Modify: `inspectord/supervisor.py`
- Test: `tests/test_supervisor_restart.py`

Test rig: two throwaway worker modules written into `tmp_path` (`PYTHONPATH` is prepended
with `tmp_path` via `monkeypatch.setenv` so `python -m <name>` finds them) —
one that reads its config line and exits with a chosen code, one that dies by `SIGKILL`,
one that lives for a chosen number of seconds first. `cfg.workers` is replaced with a single
`WorkerSpec` pointing at the helper, and the tunables are shrunk to milliseconds.

- [ ] **Step 1:** Write the failing tests:
  - `test_dead_worker_is_restarted` — the `_WorkerProc` in `sup._procs` ends up holding a
    *different* pid, exactly one entry for that worker name, and the old reader threads are dead.
  - `test_restart_attempts_are_exhausted_and_worker_left_dead` — with `restart_max_attempts=3`:
    exactly 3 `worker_restarted` events, exactly one `worker_restart_exhausted`, and no further
    restarts after a grace period.
  - `test_backoff_resets_after_healthy_uptime` — a worker that lives past
    `restart_healthy_after_s` before dying keeps reporting `attempt == 1`.
  - `test_events_carry_expected_fields` — `worker_died` (`exit_code`, `signal is None`,
    `restarts`), `worker_restarted` (`attempt`, `backoff_s`), `worker_restart_exhausted`
    (`attempts`).
  - `test_worker_killed_by_signal_reports_signal` — `SIGKILL` → `exit_code == -9`, `signal == 9`.
- [ ] **Step 2:** Run; expect FAIL (workers never restart).
- [ ] **Step 3:** Implement:
  - `_WorkerProc` gains `started_at`, `restarts`, `restart_at`, `exhausted`, `died_reported`.
  - `_spawn_worker` split into `_start_worker_proc(spec) -> _WorkerProc` (Popen + config write +
    reader threads) and the appending caller; `_respawn(index, old)` replaces
    `self._procs[index]` under `self._procs_lock`, carrying `restarts` forward.
  - `_monitor()` loops on `while not self._stop.wait(self._poll_interval_s)`, calling
    `_monitor_tick()` inside a `try/except Exception` that only logs, so the thread cannot die.
  - `_monitor_tick()`: skip `exhausted`; live worker past the healthy threshold resets
    `restarts`; dead worker → `_handle_dead_worker` (emit `worker_died` once, join reader
    threads, close pipes) → exhaust or schedule → respawn when `restart_at` elapses.
- [ ] **Step 4:** Run the suite; expect PASS. Commit — `feat(supervisor): restart dead workers with exponential backoff`.

---

### Task 3: shutdown ordering

**Files:**
- Modify: `inspectord/supervisor.py`
- Test: `tests/test_supervisor_restart.py`

- [ ] **Step 1:** Write `test_stop_during_restart_window_does_not_resurrect` — a long base delay
  parks the worker in its restart window; after `worker_died` is observed, `stop()` must
  return well inside its budget, the monitor thread must be dead, and the `_WorkerProc` must
  still hold the same dead pid. Plus `test_stop_is_idempotent_without_start`.
- [ ] **Step 2:** Run; expect FAIL (monitor restarts the worker during shutdown).
- [ ] **Step 3:** `stop()` computes its deadline, sets `self._stop`, joins `self._monitor_thread`
  first, then terminates workers as before.
- [ ] **Step 4:** Run; expect PASS. Commit — `fix(supervisor): stop the monitor before terminating workers`.

---

### Task 4: the starter-pack rule

**Files:**
- Create: `inspectord/rules/starter_pack/daemon_worker_restart_exhausted.yaml`
- Test: `tests/rules/starter_pack/test_daemon_worker_restart_exhausted.py`

- [ ] **Step 1:** Failing tests — fires at severity `high` on the exhausted event; does not fire
  on `worker_died` / `worker_restarted`; does not fire for another module.
- [ ] **Step 2:** Run; expect FAIL (missing YAML).
- [ ] **Step 3:** Write the rule (id `daemon.worker_restart_exhausted`, severity high,
  category `process`). `why` states plainly that the collector is permanently down and its
  telemetry is missing until the daemon is restarted; `false_positives` names the honest ones —
  a worker whose dependency was uninstalled will crash-loop and exhaust, and a machine
  suspended across the restart window can burn attempts without a real fault.
- [ ] **Step 4:** Run; expect PASS. Commit — `feat(rules): daemon.worker_restart_exhausted`.

---

### Task 5: gates + flake loop

- [ ] **Step 1:** `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`,
  `.venv/bin/ruff check inspectord tests`, `.venv/bin/ruff format --check inspectord tests`,
  `.venv/bin/mypy inspectord` — all exit 0.
- [ ] **Step 2:** Run the new supervisor suite 10× in a loop; report the failure count. A flaky
  test in the supervisor is worse than no test.
- [ ] **Step 3:** Report. Do not push, do not open a PR.

---

## Self-Review notes

- **No worker-contract change.** Workers are untouched; the restart is entirely supervisor-side.
- **`_read_stdout` still fans out alerts on the worker thread** — the `_dispatch` refactor moves
  the body, not the thread it runs on. This is load-bearing elsewhere.
- **No stale `_WorkerProc`**: respawn replaces the list entry in place, so `sup._procs` stays
  one entry per spec and the existing `test_supervisor_starts_log_tailer_and_fim_watcher`
  assertion (a set of `wp.spec.name`) keeps passing.
- **Reader-thread hygiene**: threads are joined and pipes closed on death, before the new
  process is created, so no double-read and no fd leak.
- **Known pre-existing debt (not fixed here)**: `Database` documents itself as not thread-safe
  yet is already written from every worker reader thread; the monitor adds one more writer.
  Out of scope for this change, flagged for the reviewer.
