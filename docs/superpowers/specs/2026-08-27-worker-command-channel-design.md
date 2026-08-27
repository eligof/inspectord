# Worker command channel — design

Date: 2026-08-27 (v2 — concilium 3-lens review, unanimous REVISE: 1 BLOCKING +
9 MAJOR + ~12 MINOR findings folded)
Parent: `2026-05-24-local-inspection-design.md` §24; scanner-runner spec's deferral.
Status: **autonomously drafted, NOT human-reviewed** (concilium-reviewed in-session).
Core daemon architecture — §4's trigger-only/at-most-once semantics and the §9
deliberate deviations are the parts most worth a human look.

## 1. Goal

A small, audited request path from IPC clients to a running worker: "do X now".
Transport is the worker's stdin pipe — which the supervisor **currently closes after
the config line** (`_start_worker_proc`, supervisor.py:492); PR1 keeps it open for
ALL workers (workers that never read past line 1 are unaffected — regression-tested,
including that no worker relies on post-config EOF), and `_reap`'s close becomes the
incarnation-end of the channel.

## 2. Scope

### In (v1)

- Contract: opt-in `handle_command` + stdin reader thread + wake event (§4).
- Supervisor: `send_worker_command` with per-incarnation correlation (§5).
- IPC: `run_worker_command` (mutates=True, every attempt audited) (§6).
- Consumers: `vuln_scanner rescan`, `scanner_runner run_scanner {name}` (§7).
- PR2: panel "Run now"/"Rescan now" buttons.

### Out (deliberate)

| Cut | Why |
| --- | --- |
| Result payloads in responses | Commands are triggers; results flow as ordinary events. A synchronous result path would duplicate the pipeline and hold IPC threads through multi-second scans. |
| Fire-and-forget (no response wait) | Rejected: `run_scanner` validation lives in the worker (disabled scanners, config drift) and a wedged stdin reader is invisible without a correlated timeout; daemon-side duplication of worker config would drift. |
| Guaranteed delivery / cross-restart queueing | At-most-once, in-memory. A lost trigger is re-clickable; scheduled runs remain the backbone. |
| Worker-initiated or worker→worker commands | No use case; strictly daemon→worker. |
| Generic exec/args-carrying-paths commands | Closed per-worker command sets; the channel never carries code or paths. |
| CLI `inspectorctl scanners run` | Thin client over the same IPC method, any time after PR1. |

## 3. Wire format & robustness

Command line (NDJSON on stdin, after config):
`{"command": "<^[a-z_]{1,64}$>", "args": {<object, ≤4 KiB serialized>},
"request_id": "<uuid4 hex>"}`

Response: a `command_result` event on stdout (module=<worker>, kind=state,
`raw = {request_id, status: "accepted"|"rejected", detail: str}`).

Worker-side robustness: read-side line cap 64 KiB (an over-long line is drained to
the next newline, logged, dropped — never parsed, never answered); malformed line
with recoverable request_id → `rejected`; without → logged + dropped; rejected-
response emission is bounded (≤ 30/min, excess logged only) so a broken supervisor
flooding stdin cannot turn into an event flood. The reader thread exits on EOF
(readline → `b""`) — no busy-spin (tested by closing the write end).

## 4. Contract-side semantics

- `Worker.run()` starts a daemon stdin reader thread ONLY when the subclass
  overrides `handle_command` (default: no thread, no stdin reads — existing workers
  byte-identical in behavior).
- **Buffer-steal hazard (folded finding):** the config read and the reader thread
  MUST share the same stream object — `read_config_from_stdin` switches to
  `sys.stdin.buffer.readline()` and hands that same buffered object to the thread;
  otherwise a command written between spawn and config-read is stranded in the text
  wrapper's decode buffer and silently lost. Tested: a command line written before
  the config read is still delivered.
- `handle_command(command, args) -> dict` runs on the reader thread; fast,
  non-blocking; flips `threading.Event`s / locked structures for the step loop.
- **The BASE CLASS alone emits `command_result`** via `build_event`: status coerced
  to the accepted/rejected enum, detail coerced to `str`, the emit wrapped in the
  same never-die guard as the handler (a consumer returning garbage can never
  produce a schema-invalid event — which the supervisor would drop, turning an
  accepted command into a silent timeout — nor kill the reader thread).
- **Wake event:** accepting a command sets a wake `threading.Event`; `run()` waits
  on stop-or-wake instead of plain `_stop.wait(interval)`, so "Run now" acts on the
  next loop iteration, not up to `step_interval_s` later.
- Cross-thread stdout: safe because `emit_event` performs ONE `write()` per
  complete line (BufferedWriter serializes calls) — stated as a load-bearing
  invariant and stress-tested (concurrent step-loop + command_result emission,
  every line parses).
- Trigger-only, at-most-once: `accepted` means "will run at the next loop
  iteration", never "done"; a restart between accept and execution loses the
  trigger.

## 5. Supervisor side

`Supervisor.send_worker_command(worker_name, command, args, *, timeout_s=10.0) -> dict`

- Lock discipline (folded finding): `_procs_lock` held ONLY for the name→wp lookup;
  the per-worker stdin lock (on `_WorkerProc`) ONLY for serialize+write+flush; the
  response wait holds NO supervisor lock (tested: a slow command does not delay a
  monitor tick).
- **Pending map lives on `_WorkerProc`** — per-incarnation, keyed by request_id;
  fulfillment identity is THE PIPE: `_read_stdout(wp)` consults only `wp`'s own
  pending map, so a hostile or buggy worker can never fulfill another worker's
  requests, and a respawned incarnation structurally starts empty.
- Write failures of every shape (`BrokenPipeError`, `ValueError` on a reaped/closed
  file, `OSError`) → `worker_unavailable`; the monitor owns recovery.
- Death: `_handle_dead_worker` (after `_reap`, before any respawn) fulfills all of
  that incarnation's pending entries with `worker_died` — accepting the ≤1 s
  monitor-poll latency.
- Shutdown: `stop()` fulfills every pending entry with
  `worker_unavailable/shutting_down` immediately after setting `_stop`, and
  `send_worker_command` fast-fails once `_stop` is set (tested: stop() with a
  command in flight returns within the stop budget).
- Timeout → `{"status": "timeout"}` (command may still run); **the pending entry is
  removed in a `finally` whatever the outcome** — a wedged worker cannot wedge the
  channel. A late `command_result` for an unknown request_id is dispatched as an
  ordinary event and logged, never fulfills. The ≤32-per-worker in-flight cap stays
  as an assert-grade bound (unreachable in single-user practice — documented as
  such).
- `command_result` events are also dispatched normally (history in
  events_enriched).

## 6. IPC + audit

- `run_worker_command` (mutates=True): `{worker, command, args?}`; §3 caps + a
  daemon-side allowlist `{("vuln_scanner","rescan"), ("scanner_runner",
  "run_scanner")}` enforced BEFORE anything touches a pipe.
- **Every attempt is audited, including allowlist/caps rejections** — rejected
  attempts are the probe signature of a compromised session and are the most
  security-interesting rows. Action `worker_command_sent`, target `worker:<name>`,
  details `{"command", "args" (cap-validated, or truncated repr for cap-rejects),
  "status": <result|rejected+reason>}`.
- Coarse rate limit: 12 attempts/min sliding window per method; excess →
  client-facing error, audited once per window (bounds attacker-drivable growth of
  the append-only audit_log).
- Display safety: `args` and worker-authored `detail` are untrusted on every
  surface — HTML autoescape (house standard) and sanitize-style control-char
  stripping for any CLI rendering. PR2 includes a hostile-detail escape test.
- Threat posture note: the 0660 socket already trusts the single user's session;
  this method adds "trigger a scan" to what that session can do — bounded by the
  allowlist and rate limit, recorded here for the human reviewer.

## 7. Consumers (v1)

- **vuln_scanner `rescan`**: sets `_rescan_requested` + wake. The next poll is
  unconditionally due — it **bypasses `FILE_TRIGGER_MIN_INTERVAL_S`** (that guard
  absorbs mid-`mv` mtime flapping, not human clicks; the realistic sequence
  "file refreshed → auto scan → user clicks Rescan" would otherwise accept then
  silently defer 5 minutes) and does not touch the file-trigger bookkeeping.
  Natural bound: one scan per poll tick. The `db.lck` guard still applies.
- **scanner_runner `run_scanner {name}`**: name must be a configured scanner —
  unknown → `rejected/unknown_scanner`; disabled → `rejected/scanner_disabled`
  (honest, not silently swallowed). The run-next entry **survives `_reschedule`**
  (a completion re-basing `next_due` must not clobber a queued trigger for the
  running scanner) and is removed only when `_start_run` actually launches that
  scanner; single-flight respected (`accepted`, detail "queued behind current
  run"). **A triggered run does not consume the scheduled slot** — the scheduled
  cadence continues from its original anchor, so triggering cannot push the next
  scheduled scan a full interval away (anti-forensics nudge otherwise).

## 8. Testing

TDD. Contract: no-override workers start no thread and never read stdin; workers
survive open-stdin (no EOF reliance — regression across the existing worker suite);
early-command buffer-steal case; EOF thread exit without spin; malformed/oversized
lines; handler exception → rejected + live thread; unserializable detail → valid
event + live thread; wake-event latency; concurrent-emission stress. Supervisor:
end-to-end with a stub worker; timeout removes pending (33rd command after 32
timeouts is not busy); death fulfillment per incarnation; respawn starts empty;
stale-incarnation send during the backoff window → worker_unavailable; stop() budget
test; lock-free-wait monitor-tick test; cross-worker fulfillment impossible. IPC:
allowlist/caps rejections audited with reasons, rate limit, registration. Consumers:
rescan bypasses the 300 s guard but respects poll cadence + db.lck; run_scanner
unknown/disabled/single-flight/survives-reschedule/does-not-consume-slot. PR2:
buttons POST → IPC → 303, hostile detail escaped, daemon-down state.

## 9. Deliberate deviations (recorded for the human)

1. Parent §2.2 wants on-demand runs proposed as pending actions; this design
   executes immediately behind an audit row (single-user console: the clicker IS
   the approver) — inheriting and making permanent the scanner-runner spec's
   recorded deviation.
2. Parent §24's CLI form arrives later as a thin client; the IPC method is the
   contract.

## 10. Delivery

PR1: contract + supervisor + IPC + both consumers + tests.
PR2: panel buttons.
