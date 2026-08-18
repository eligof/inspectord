# process_collector syscall tracepoints (ptrace / kernel-module / raw-socket) — design

| Field | Value |
| --- | --- |
| Date | 2026-07-15 |
| Status | Approved (brainstorming + concilium REVISE→revised 2026-07-15) — ready for implementation plan (ptrace slice first) |
| Spec section refs | §5 (`process_collector` worker row), §21 (Starter rule pack, `proc.*` rule ids), v0.3.0 changelog (deferred tracepoints) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Related | `outbound_connection_tracker` slices (PRs #84/#86) — the 2-PR native/worker template these mirror |

## 1. Purpose & context

The parent spec's `process_collector` row (§5) lists eBPF tracepoints `sched_process_exec`,
`sched_process_exit`, `sys_enter_execve`, `sys_enter_ptrace`, `sys_enter_finit_module`, and
raw-socket creation. The first two shipped in Phase 2 v1; `sys_enter_execve` is **subsumed
by the shipped `sched_process_exec` tracepoint** (same signal, better vantage) and will not
be implemented separately. This design covers the remaining three.

What they detect:

| Syscall(s) | Threat | Rule (parent spec §21) |
| --- | --- | --- |
| `ptrace` | Process injection: attaching to and writing into another process's memory/registers. | `proc.ptrace_injection` (new id, this spec) |
| `finit_module` + `init_module` | Kernel-module (LKM rootkit) loading, with the *initiating process* attached. | `proc.kernel_module_loaded_unknown` |
| `socket(SOCK_RAW / AF_PACKET)` | Packet sniffers / crafted-packet tools. | `proc.raw_socket_unprivileged` |

### Design decisions (locked during brainstorming + concilium 2026-07-15)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Delivery slicing | **Per-syscall: 3 native+worker PR pairs (6 PRs)**; ptrace first | Each PR stays the size of the IPv6-connect slice; the first pair proves out the new attach mechanism. Follows the repo's 2-PR native/worker convention for eBPF collectors (CLAUDE.md). |
| Spec scope | **One shared design doc** (this file) covering the mechanism + all 3 detections | The syscall-tracepoint substrate is designed once; per-slice plans reference this spec. |
| ptrace filtering | **In-BPF: injection-relevant requests, cross-process only** | High-signal *relative to full ptrace traffic* — the read/step/cont firehose is dropped at the source. Debugger/crash-reporter attaches still emit (by design; see the alerting split below). |
| ptrace alerting | **Severity split: attach-family alerts at medium; write-family emits events only** | The user is a developer who debugs daily; per-attach popups must stay rare and meaningful, and rr/legacy-tooling write storms must not become popup streams. Every realistic injection flow includes an attach (or a TRACEME'd child then written to — the write event is still recorded). Concilium 2026-07-15. |
| kernel-module coverage | **Both `finit_module` and `init_module`** in the module slice | `init_module(2)` loads from memory with no fd — the classic fd-avoidant rootkit path; tracing only finit would leave a trivial bypass. Concilium 2026-07-15. |
| Detection rules | **Each worker PR ships its starter-pack rule** | Signal is actionable end-to-end on merge (mirrors how connect-tracker rules landed; unlike the persistence slice, no baseline-flood concern exists here — these are live-action events, not snapshot inventory). |

## 2. Shared mechanism: ftrace syscall tracepoints

A **new program category** in `inspectord_native_bpf` alongside the existing
`#[btf_tracepoint]` readers: aya `#[tracepoint]` programs attached to
`syscalls:sys_enter_<name>`.

- **Userspace attach**: aya's `TracePoint` program — `prog.load()` then
  `prog.attach("syscalls", "sys_enter_ptrace")`. (Verified available in aya 0.13.1;
  `TracePointContext::read_at` verified in aya-ebpf 0.1.1.)
- **Argument access**: ftrace syscall-enter tracepoints have a buffer layout that is
  **stable in practice on x86_64** (tracefs event formats are not formally stable kernel
  ABI) — 8-byte common header, `__syscall_nr: i32` at offset 8, then the syscall args as
  `u64` slots at **`16 + 8*i`**. Programs read args with
  `TracePointContext::read_at::<u64>(16 + 8*i)`. The authoritative per-kernel reference
  is `/sys/kernel/tracing/events/syscalls/sys_enter_<name>/format` — cite it when
  debugging rather than assuming the layout.
- **Runtime dependencies** (beyond what the BTF-tracepoint path needs): the kernel must
  have `CONFIG_FTRACE_SYSCALLS=y` (verified =y on the target CachyOS kernel), tracefs
  must be readable (aya resolves the event id there; workers run euid-0), and attach uses
  `perf_event_open` (in systemd's `@debug` syscall group, not `@system-service` —
  relevant only if the parent §17.2 hardening directives are ever applied to the unit).
  On attach failure the stream constructor raises and the worker exits at startup —
  acceptable under the existing no-restart supervisor (recorded tech debt), but the exit
  must log a distinct message naming the missing tracepoint.
- **No BTF offsets needed**: unlike the task_struct/sock_common readers, these programs
  never dereference kernel structs, so they do **not** touch the `OFFSETS` map. Their
  loaders use a lean `load_bpf()` helper (`Ebpf::load(PROGRAM_BYTES)` + attach + take
  ring) instead of `load_and_populate_offsets()`. The syscall programs live in the same
  single embedded ELF as the existing programs (established one-ELF-multiple-programs
  architecture); each worker process loads its own `Ebpf` instance and attaches only its
  own program, exactly as today.
- **Map footprint (accepted constraint)**: every worker's `Ebpf::load()` instantiates
  *all* maps in the shared ELF, so per-worker ring-buffer memory grows with total program
  count (O(n²) across the fleet). To keep this bounded, the three new rare-event rings
  are sized **64 KiB** (not 256 KiB — that size was chosen for exec/exit volume). After
  all three slices: 7 eBPF workers × (4×256 KiB + 3×64 KiB) ≈ 8.5 MiB kernel memory,
  mostly unused — accepted for convention consistency; splitting the ELF is future debt
  if program count keeps growing. The three new Python worker processes cost roughly
  40–60 MB RSS total, accepted against the standard profile's <500 MB budget (parent
  §22.1) for the same reason.
- **In-BPF filtering**: each program is a simple straight-line filter (verifier-friendly,
  same discipline as the split IPv4/IPv6 connect programs) that drops uninteresting calls
  *before* reserving a ring-buffer slot. Note the program still *runs* on every syscall
  entry system-wide (~50–100 ns per filtered invocation); an active `strace` of a
  syscall-heavy process drives high filtered-invocation rates. Accepted: this occurs only
  while the user is actively tracing, not at idle, so the <5 % idle-CPU budget is
  unaffected.
- **Per-syscall plumbing**, mirroring the `process_collector_exit` precedent exactly:
  own ring-buffer map → own `Loaded*Program` in `loader.rs` → own PyO3 `Process*Stream`
  class in `lib.rs` → own worker package under `inspectord/workers/` → own entry in
  `config.py`'s dev config worker list.
- **Capabilities**: no systemd unit change; CAP_BPF + CAP_PERFMON already granted to the
  collector workers (parent spec §975).
- **Timestamps**: records carry `bpf_ktime_get_ns()`; workers convert via the
  `_wall_offset_ns` scheme already used by `ProcessCollectorWorker`.

Everything below §3 that says "record mirrored in both records.rs files" means:
`crates/inspectord_native_bpf/src/records.rs` (BPF side, `zeroed()`) and
`crates/inspectord_native/src/records.rs` (userspace side, `from_bytes()` + decode
helpers + unit tests), layouts byte-identical, like `ConnectRecord`.

## 3. ptrace slice — implemented first

### 3.1 PR1 (native)

**Record** (mirrored in both records.rs files):

```rust
#[repr(C)]
pub struct PtraceRecord {
    pub timestamp_ns: u64,
    pub pid: u32,        // caller (tgid, upper half of bpf_get_current_pid_tgid())
    pub uid: u32,
    pub request: i32,    // raw ptrace request value (validated set only; see filter)
    pub target_pid: i32, // syscall arg 1, caller-pid-namespace-relative TID
    pub comm: [u8; COMM_LEN],
}
```

(8+4+4+4+4+16 = 40 bytes, naturally aligned, no implicit padding.)

Userspace decode helpers: `comm_str()` (as elsewhere) and `request_str()` mapping the
seven emitted request values to `"PTRACE_ATTACH"` etc. Unknown values render as
`PTRACE_<decimal i32>` (e.g. `0x4207` → `PTRACE_16903`, `-1` → `PTRACE_-1`). Unit tested
like `ConnectRecord6`.

**BPF program** `ptrace_syscall` (`#[tracepoint]`, attached to `syscalls:sys_enter_ptrace`):

1. Read `request` from arg 0 (offset 16) and `target_pid` from arg 1 (offset 24), both as
   `u64`.
2. **Emit only if** the **full u64** `request` equals one of
   `{PTRACE_POKETEXT=4, PTRACE_POKEDATA=5, PTRACE_POKEUSR=6, PTRACE_SETREGS=13,
   PTRACE_ATTACH=16, PTRACE_SETREGSET=0x4205, PTRACE_SEIZE=0x4206}` **and** the
   cross-process check passes (below). Comparing the full u64 means values with garbage
   high bits (e.g. `0x1_0000_0010`) never alias to `PTRACE_ATTACH`; only after the match
   is `request` stored as `i32`.
3. **Cross-process check**: caller pid = TGID (upper 32 bits of
   `bpf_get_current_pid_tgid()`); **drop when `(target_pid as u32) == tgid`**;
   negative/huge target values never match the drop condition and are emitted. Caveats,
   accepted: (a) same-process *sibling-thread* attaches still emit — the kernel EPERMs
   them anyway, and another process's TID can never equal the caller's TGID within a
   namespace, so the cheap comparison has no false negatives; (b) ptrace's target is a
   TID in the **caller's pid namespace**, so for namespaced callers (flatpak/bwrap/
   docker) `target_pid` is not a host pid — worker and rule text must not present it as
   one.
4. Reserve a slot in a new `PTRACE_EVENTS` ring buffer (**64 KiB** — rare events; see
   §2 map-footprint note), fill caller pid/uid/comm from helpers, submit with
   `BPF_RB_FORCE_WAKEUP`.

**Loader/PyO3**: `LoadedPtraceProgram` (lean load — no OFFSETS population) +
`ProcessPtraceStream` pyclass (keeping the existing `Process*Stream` prefix) whose
`poll(timeout_ms)` returns dicts
`{timestamp_ns, pid, uid, comm, request, request_name, target_pid}`. Registered in the
`_native` module. As part of this PR, generalize `LoadError::MissingProgram` /
`LoadError::MissingMap` to carry the program/map name
(`MissingProgram(String)` / `MissingMap(String)`, message `"BPF program {0} not found in
object"`) — the current variants hardcode `process_exec`/`EVENTS` in their messages and
would mislead for the new programs; `take_ring()` and the attach helper already receive
the name.

**Root-only tests** in `tests/test_native_loader.py` (skipped as non-root): beyond
attach/detach, a **functional filter test** — fork a child, `PTRACE_ATTACH` to it, and
assert a record with `request_name == "PTRACE_ATTACH"` and the child's pid appears in
`poll()`; then have a child issue an out-of-set request (`PTRACE_TRACEME`) and assert no
record is emitted. (Trivially constructable in-process, unlike the connect programs; this
is the only test at any level that exercises the in-BPF filter — the one genuinely new
logic in this design.)

### 3.2 PR2 (worker + rule)

**Worker** `inspectord/workers/process_collector_ptrace/` mirroring
`process_collector/__main__.py` (stream-factory + sink injection, `_wall_offset_ns`).
Event shape per record:

```python
build_event(
    module="process_collector_ptrace",
    action="ptrace_call",
    category=["process"],
    type_=["access"],
    severity="info",
    ts=<converted timestamp>,
    host={"name": hostname},
    user={"id": str(uid)},
    process={
        "pid": pid,
        "name": comm,
        "ptrace_request": request_name,   # e.g. "PTRACE_ATTACH"
        "target_pid": target_pid,          # flat, for rule expressions
        "target": {"pid": target_pid},     # nested, ECS-style
    },
    raw={"source": "ebpf:sys_enter_ptrace", "request": request},
)
```

One `action="ptrace_call"` (verb phrase, consistent with `process_start` /
`raw_socket_created`) for all seven request kinds; the request name is data, not action.
`target_pid` is namespace-relative (§3.1 caveat b) — templates say "pid … (as seen by the
caller)" rather than asserting a host pid.

**Wiring**: `config.py` dev-config worker entry `process_collector_ptrace` (empty config),
placed after `process_collector_exit`.

**Rule** `inspectord/rules/starter_pack/proc_ptrace_injection.yaml` — per the locked
severity split, the rule matches **only the attach family**; write-family events
(POKE*/SETREGS/SETREGSET) remain events-only (dashboard/evidence, no alert):

```yaml
version: 1.0.0
id: proc.ptrace_injection
name: "cross-process ptrace attach"
severity: medium
category: process
why: |
  A process attached to another process via ptrace. Debuggers do this
  legitimately, but it is also a common process-injection primitive on
  Linux — an attacker attaches, then writes memory or registers.
false_positives:
  - "You were debugging with gdb/strace/lldb/rr (attach to a running process)."
  - "A crash reporter attached to a crashing process (Chromium/Electron crashpad, coredump helpers)."
  - "An IDE-embedded debugger (VS Code, JetBrains) attached to a process."
detect:
  any_of:
    - event.module == "process_collector_ptrace" AND event.action == "ptrace_call" AND process.ptrace_request == "PTRACE_ATTACH"
    - event.module == "process_collector_ptrace" AND event.action == "ptrace_call" AND process.ptrace_request == "PTRACE_SEIZE"
short: "ptrace {process.ptrace_request} from {process.name} to pid {process.target_pid}"
detail: "{process.name} (pid {process.pid}, uid {user.id}) issued {process.ptrace_request} against pid {process.target_pid} (as seen by the caller)."
labels: [process, injection, ptrace]
```

Note: gdb ≥ 12 writes tracee memory via `/proc/<pid>/mem`, not `PTRACE_POKE*`, so the
recurring benign sources are attach events plus rr/legacy tooling write bursts — the
split keeps the former rare-but-alerting and the latter silent-but-recorded.

**Tests**: worker unit tests with a fake stream factory (event shape, timestamp
conversion, request-name passthrough) + rule tests: fires on ATTACH and SEIZE, does
**not** fire on POKETEXT/SETREGSET events (mirroring the persistence rule tests).

## 4. kernel-module slice — design level (own plan later)

Covers **both** module-load syscalls (locked decision, §1):

- `sys_enter_finit_module(int fd, const char *param_values, int flags)`
- `sys_enter_init_module(void *umod, unsigned long len, const char *uargs)` — loads a
  module image directly from memory with **no fd**; tracing only finit would leave the
  fd-avoidant rootkit loader path invisible.

Design sketch: two near-identical BPF programs feeding **one** ring buffer / one record
type (a `variant` field distinguishes them; the fd field is meaningful only for finit),
one worker, one rule.

- **Record**: caller pid/uid/comm + `variant` + `fd: i32` (finit only) + `flags: i32`
  (finit only) + bounded `params` string (arg 1 for finit, arg 2 for init; read via
  `bpf_probe_read_user`, cap ~128 bytes). Params are length-bounded and stored locally
  only — no egress, per the privacy-first stance.
- **Filter**: none — module loads are rare; emit every call.
- **Relationship to `kmod_watcher`**: complementary, not redundant. The pure-Python
  watcher polls loaded-module *state* (what is loaded now); these tracepoints capture the
  *initiating process* in real time (who loaded it), including failed attempts.
- **Worker** emits `action="module_load_attempt"` from a
  `process_collector_module_load` worker (named in full to keep it distinct
  from the existing pure-Python `kmod_watcher`).
- **Rules — reworked 2026-08-18.** The parent spec's `proc.kernel_module_loaded_unknown`
  presupposed a module *name* to judge as unknown, and this slice deliberately
  does not collect one (see the resolved questions above). "Unknown" therefore
  keys off the **loader**, not the module, and the slice ships two rules:

  1. `proc.kernel_module_from_memory` — **high** — fires on `variant ==
     "init_module"`. Since kernel 3.8 every normal loader (kmod/modprobe,
     systemd-udevd, dracut) uses `finit_module` with a file descriptor; loading
     a module image straight from anonymous memory is the fd-avoidant path a
     rootkit loader picks precisely to avoid leaving a file. It is rare enough
     on a desktop that a high-severity alert stays quiet.
  2. `proc.kernel_module_loaded_unknown` — **medium** — fires on `variant ==
     "finit_module"` when `process.name` is `NOT IN` the known-loader list
     (`modprobe`, `insmod`, `kmod`, `systemd-udevd`, `systemd`, `dracut`,
     `mkinitcpio`). Keeps the id promised by parent §21 while resting only on
     data this collector actually has.

  Both are evaluated per-event with no correlation window; joining these events
  to `kmod_watcher`'s `kmod_loaded` (which carries the module name) is left to
  the analyst reading the Cases timeline in v1, not automated.
- **Resolved 2026-08-18** (the two open questions this slice's plan had to settle):

  1. **Module name: not resolved in v1.** The record carries *who loaded a module*, not
     *which module*. `finit_module` gives an fd and `init_module` gives an anonymous
     memory image, so any name would come from the worker racing to read
     `/proc/<pid>/fd/<fd>` before the caller exits or the fd is reused. In a security
     tool a *wrong* attribution is worse than a missing one, and the name is already
     available from the other side: `kmod_watcher` emits `kmod_loaded` with
     `raw.module_name` (verified in `inspectord/workers/kmod_watcher/__main__.py`). The
     two signals are joined by time proximity in the rule engine — which is exactly the
     complementary split described above — rather than by a racy fd read. Revisit only
     if correlation proves too lossy in practice.
  2. **Params string: cut from v1.** No detection rule consumes it, presence-of-load plus
     caller attribution is what the rule fires on, and reading a userspace string in-BPF
     (`bpf_probe_read_user` into a bounded buffer) adds verifier surface and a per-event
     copy for evidence value nothing currently reads. The record therefore drops the
     `params` field; it stays a documented extension point if a future rule needs module
     arguments.

  Net effect on the §4 record: caller pid/uid/comm + `variant` + `fd` + `flags`, no
  `params`.

## 5. raw-socket slice — design level (own plan later)

`sys_enter_socket(int family, int type, int protocol)`.

- **Record**: caller pid/uid/comm + `family: i32` + `type: i32` + `protocol: i32`.
- **Filter (in-BPF)**: emit when `family == AF_PACKET (17)`, **or**
  (`family ∈ {AF_INET=2, AF_INET6=10}` **and** `(type & 0xf) == SOCK_RAW (3)`) — the
  `0xf` mask strips the `SOCK_NONBLOCK`/`SOCK_CLOEXEC` flag bits. The family scope is
  **required**: `AF_NETLINK` sockets are conventionally `SOCK_RAW`, need no CAP_NET_RAW,
  and are created constantly by unprivileged desktop processes (iproute2, sd-netlink/
  systemd, NetworkManager, libnl consumers); `AF_UNIX` `SOCK_RAW` is silently remapped by
  the kernel. An unscoped type-only filter would flood benign events and alerts.
- **Worker** emits `action="raw_socket_created"`; rule `proc.raw_socket_unprivileged`
  (parent §21) fires when `user.id != "0"`. **The uid gate is a proxy, stated honestly:**
  inet/packet raw sockets fail with EPERM only for callers *without* CAP_NET_RAW —
  non-root processes holding CAP_NET_RAW via file/ambient caps (`mtr`, `dumpcap`, some
  `ping` builds) succeed *and* match the rule (list them in the rule's
  `false_positives`), while a root-run sniffer — the higher-privilege threat — produces
  events but no alert. Both the FP and the root-sniffer alerting blind spot are
  **accepted in v1**; the tracepoint fires at sys_enter, so the record carries no
  outcome/capability signal to distinguish these. **Open question for that slice's
  plan**: whether to add an outcome/capability signal (e.g. a sys_exit pairing or
  CAP_NET_RAW check) — mirroring §4's open-question pattern.

## 6. Testing & gates

TDD throughout, per repo CLAUDE.md:

- Rust: `cargo test -p inspectord-native --lib` — record layout roundtrip + decode-helper
  tests (compiles the BPF crate via build.rs, catching compile-time type errors; verifier
  acceptance is checked only by the root-only smoke tests, since the verifier runs at
  load time).
- Python: `pytest -m "not integration and not ebpf_load"` — worker event-shape tests
  (fake stream), rule-fires and rule-does-not-fire tests.
- Root-only: verifier smoke tests in `tests/test_native_loader.py` (attach + detach each
  new program) **plus the §3.1 functional filter test** (fork + PTRACE_ATTACH → record
  appears; out-of-set request → no record), run manually via sudo.
- CI gates all green before merge: lint-and-test, CodeQL, cargo-audit, dependency-review.
- Built via subagent-driven-development; native PRs first, worker PRs after
  (repo CLAUDE.md 2-PR convention).

## 7. Out of scope

- ptrace read/step/cont/PEEK events (dropped in-BPF by design).
- **Known injection blind spots**: `process_vm_writev(2)` and writes to
  `/proc/<pid>/mem` are injection paths that never enter `sys_enter_ptrace` and are not
  observed by this collector (modern gdb itself writes tracee memory via
  `/proc/<pid>/mem`); a future write-side collector or LSM hook would be needed.
- Alerting on write-family ptrace requests (events only in v1; see the §1 severity-split
  decision).
- Module-name resolution from fd/image, and the params-string question (deferred to the
  kernel-module slice plan, §4).
- Anomaly/first-seen scoring, the `anomaly_detector` worker.
- Enrichment (e.g. flagging when the ptrace *target* is a privileged/security process).
- auditd fallback path (parent spec `minimal` profile) — unchanged.
- Alerting on privileged (root/CAP_NET_RAW) raw-socket creation (events only in v1; see
  §5 accepted blind spot).
- An outcome/capability signal for raw-socket events (open question for that slice's
  plan, §5).
