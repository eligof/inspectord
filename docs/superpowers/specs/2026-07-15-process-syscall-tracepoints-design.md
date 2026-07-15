# process_collector syscall tracepoints (ptrace / finit_module / raw-socket) — design

| Field | Value |
| --- | --- |
| Date | 2026-07-15 |
| Status | Approved (brainstorming) — ready for implementation plan (ptrace slice first) |
| Spec section refs | §5 (`process_collector` worker row), §1167 (`proc.*` rule ids), v0.3.0 changelog (deferred tracepoints) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Related | `outbound_connection_tracker` slices (PRs #84/#86) — the 2-PR native/worker template these mirror |

## 1. Purpose & context

The parent spec's `process_collector` row (§5) lists eBPF tracepoints `sched_process_exec`,
`sched_process_exit`, `sys_enter_ptrace`, `sys_enter_finit_module`, and raw-socket creation.
The first two shipped in Phase 2 v1; the remaining three were explicitly deferred in the
v0.3.0 changelog. This design covers all three.

What they detect:

| Syscall | Threat | Rule (parent spec §1167) |
| --- | --- | --- |
| `ptrace` | Process injection: attaching to and writing into another process's memory/registers. | `proc.ptrace_injection` (new id, this spec) |
| `finit_module` | Kernel-module (LKM rootkit) loading, with the *initiating process* attached. | `proc.kernel_module_loaded_unknown` |
| `socket(SOCK_RAW / AF_PACKET)` | Packet sniffers / crafted-packet tools. | `proc.raw_socket_unprivileged` |

### Design decisions (locked during brainstorming 2026-07-15)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Delivery slicing | **Per-syscall: 3 native+worker PR pairs (6 PRs)**; ptrace first | Each PR stays the size of the IPv6-connect slice; the first pair proves out the new attach mechanism. Follows the repo's 2-PR native/worker convention for eBPF collectors (CLAUDE.md). |
| Spec scope | **One shared design doc** (this file) covering the mechanism + all 3 detections | The syscall-tracepoint substrate is designed once; per-slice plans reference this spec. |
| ptrace filtering | **In-BPF: injection-relevant requests, cross-process only** | gdb/strace read/step/cont noise is dropped at the source; ring buffer and router see only high-signal events. |
| Detection rules | **Each worker PR ships its starter-pack rule** | Signal is actionable end-to-end on merge (mirrors how connect-tracker rules landed; unlike the persistence slice, no baseline-flood concern exists here — these are live-action events, not snapshot inventory). |

## 2. Shared mechanism: ftrace syscall tracepoints

A **new program category** in `inspectord_native_bpf` alongside the existing
`#[btf_tracepoint]` readers: aya `#[tracepoint]` programs attached to
`syscalls:sys_enter_<name>`.

- **Userspace attach**: aya's `TracePoint` program — `prog.load()` then
  `prog.attach("syscalls", "sys_enter_ptrace")`. (Verified available in aya 0.13.1;
  `TracePointContext::read_at` verified in aya-ebpf 0.1.1.)
- **Argument access**: ftrace syscall-enter tracepoints have an ABI-stable buffer layout —
  8-byte common header, `__syscall_nr: i32` at offset 8, then the syscall args as `u64`
  slots at **`16 + 8*i`**. Programs read args with
  `TracePointContext::read_at::<u64>(16 + 8*i)`.
- **No BTF offsets needed**: unlike the task_struct/sock_common readers, these programs
  never dereference kernel structs, so they do **not** touch the `OFFSETS` map. Their
  loaders use a lean `load_bpf()` helper (`Ebpf::load(PROGRAM_BYTES)` + attach + take
  ring) instead of `load_and_populate_offsets()`. The syscall programs live in the same
  single embedded ELF as the existing programs (established one-ELF-multiple-programs
  architecture); each worker process loads its own `Ebpf` instance and attaches only its
  own program, exactly as today.
- **In-BPF filtering**: each program is a simple straight-line filter (verifier-friendly,
  same discipline as the split IPv4/IPv6 connect programs) that drops uninteresting calls
  *before* reserving a ring-buffer slot.
- **Per-syscall plumbing**, mirroring the `process_collector_exit` precedent exactly:
  own ring-buffer map → own `Loaded*Program` in `loader.rs` → own PyO3 `*Stream` class in
  `lib.rs` → own worker package under `inspectord/workers/` → own entry in `config.py`'s
  dev config worker list.
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
    pub pid: u32,        // caller (tgid)
    pub uid: u32,
    pub request: i32,    // raw ptrace request value
    pub target_pid: i32, // syscall arg 1
    pub comm: [u8; COMM_LEN],
}
```

Userspace decode helpers: `comm_str()` (as elsewhere) and `request_str()` mapping the six
emitted request values to `"PTRACE_ATTACH"` etc. (unknown values → `"PTRACE_<n>"`), unit
tested like `ConnectRecord6`.

**BPF program** `ptrace_syscall` (`#[tracepoint]`, attached to `syscalls:sys_enter_ptrace`):

1. Read `request` from arg 0 (offset 16) and `target_pid` from arg 1 (offset 24).
2. **Emit only if** `request ∈ {PTRACE_POKETEXT=4, PTRACE_POKEDATA=5, PTRACE_POKEUSR=6,
   PTRACE_SETREGS=13, PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206}` **and**
   `target_pid != caller pid` (self-ptrace is anti-debugging noise, not injection).
3. Reserve a slot in a new `PTRACE_EVENTS` ring buffer (262 144 bytes, matching the
   others), fill caller pid/uid/comm from helpers, submit with `BPF_RB_FORCE_WAKEUP`.

**Loader/PyO3**: `LoadedPtraceProgram` (lean load — no OFFSETS population) + `PtraceStream`
pyclass whose `poll(timeout_ms)` returns dicts
`{timestamp_ns, pid, uid, comm, request, request_name, target_pid}`. Registered in the
`_native` module. Root-only verifier smoke test in `tests/test_native_loader.py`
(skipped as non-root), like the existing streams.

### 3.2 PR2 (worker + rule)

**Worker** `inspectord/workers/process_collector_ptrace/` mirroring
`process_collector/__main__.py` (stream-factory + sink injection, `_wall_offset_ns`).
Event shape per record:

```python
build_event(
    module="process_collector_ptrace",
    action="ptrace",
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

One `action="ptrace"` for all six request kinds; the request name is data, not action.

**Wiring**: `config.py` dev-config worker entry `process_collector_ptrace` (empty config),
placed after `process_collector_exit`.

**Rule** `inspectord/rules/starter_pack/proc_ptrace_injection.yaml`:

```yaml
version: 1.0.0
id: proc.ptrace_injection
name: "cross-process ptrace (injection pattern)"
severity: medium
category: process
why: |
  A process attached to (or wrote into the memory/registers of) another process
  via ptrace. Debuggers do this legitimately, but it is also the primary
  process-injection primitive on Linux.
false_positives:
  - "You were debugging with gdb/strace/lldb (attach to a running process)."
  - "A crash reporter or profiler attached to a process."
detect:
  any_of:
    - event.module == "process_collector_ptrace" AND event.action == "ptrace"
short: "ptrace {process.ptrace_request} from {process.name} to pid {process.target_pid}"
detail: "{process.name} (pid {process.pid}, uid {user.id}) issued {process.ptrace_request} against pid {process.target_pid}."
labels: [process, injection, ptrace]
```

**Tests**: worker unit tests with a fake stream factory (event shape, timestamp
conversion, request-name passthrough) + a rule-fires test mirroring the persistence
rule tests.

## 4. finit_module slice — design level (own plan later)

`sys_enter_finit_module(int fd, const char *param_values, int flags)`.

- **Record**: caller pid/uid/comm + `fd: i32` + `flags: i32` + bounded `params` string
  (read via `bpf_probe_read_user` from arg 1; cap ~128 bytes).
- **Filter**: none — module loads are rare; emit every call.
- **Relationship to `kmod_watcher`**: complementary, not redundant. The pure-Python
  watcher polls loaded-module *state* (what is loaded now); this tracepoint captures the
  *initiating process* in real time (who loaded it), including failed attempts.
- **Worker** emits `action="module_load_attempt"`; rule
  `proc.kernel_module_loaded_unknown` (§1167).
- **Open question for that slice's plan**: module *name* resolution — the syscall gives an
  fd, not a name. Best-effort userspace resolution (e.g. the worker reading
  `/proc/<pid>/fd/<fd>` before the process exits) is racy; decide at plan time whether to
  ship name-less v1 (correlate with `kmod_watcher` via rules) or attempt resolution.

## 5. raw-socket slice — design level (own plan later)

`sys_enter_socket(int family, int type, int protocol)`.

- **Record**: caller pid/uid/comm + `family: i32` + `type: i32` + `protocol: i32`.
- **Filter (in-BPF)**: emit when `(type & 0xf) == SOCK_RAW (3)` — masking out
  `SOCK_NONBLOCK`/`SOCK_CLOEXEC` flag bits — **or** `family == AF_PACKET (17)`.
- **Worker** emits `action="raw_socket_created"`; rule `proc.raw_socket_unprivileged`
  (§1167) fires when `user.id != "0"` (unprivileged callers get EPERM without
  CAP_NET_RAW, but the *attempt* is the signal; root/CAP_NET_RAW callers are surfaced as
  events without alerting in v1).

## 6. Testing & gates

TDD throughout, per repo CLAUDE.md:

- Rust: `cargo test -p inspectord-native --lib` — record layout roundtrip + decode-helper
  tests (compiles the BPF crate via build.rs, catching verifier-relevant type errors).
- Python: `pytest -m "not integration and not ebpf_load"` — worker event-shape tests
  (fake stream), rule-fires tests.
- Root-only: verifier smoke tests in `tests/test_native_loader.py` (attach + detach each
  new program), run manually via sudo.
- CI gates all green before merge: lint-and-test, CodeQL, cargo-audit, dependency-review.
- Built via subagent-driven-development; native PRs first, worker PRs after
  (repo CLAUDE.md 2-PR convention).

## 7. Out of scope

- ptrace read/step/cont/PEEK events (dropped in-BPF by design).
- Module-name resolution from fd (open question deferred to the finit_module plan).
- Anomaly/first-seen scoring, the `anomaly_detector` worker.
- Enrichment (e.g. flagging when the ptrace *target* is a privileged/security process).
- auditd fallback path (parent spec `minimal` profile) — unchanged.
- Alerting on privileged raw-socket creation (events only in v1).
