# ptrace tracepoint — native slice (PR1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `sys_enter_ptrace` eBPF tracepoint program to the native crate — a `PtraceRecord`, a filtering BPF program, a lean loader, and a `ProcessPtraceStream` PyO3 class — so the Python worker (PR2) can stream cross-process ptrace-injection events.

**Architecture:** Introduces a *new program category* alongside the existing `#[btf_tracepoint]` readers: an aya `#[tracepoint]` program attached to `syscalls:sys_enter_ptrace`. Unlike the task_struct/sock readers, syscall tracepoints read args at fixed ftrace offsets (`16 + 8*i`, each a `u64`) and dereference no kernel structs, so the loader skips the `OFFSETS`/BTF machinery entirely (a lean `load_bpf()` helper). Everything else mirrors the `process_collector_exit` precedent: own ring buffer → own `Loaded*Program` → own `Process*Stream` pyclass.

**Tech Stack:** Rust, aya 0.13.1 (userspace `TracePoint` program) + aya-ebpf 0.1.1 (`#[tracepoint]` macro, `TracePointContext::read_at`), PyO3, maturin. Reference spec: `docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md` (§2 shared mechanism, §3.1 ptrace native).

## Scope (PR1 only)

In: `PtraceRecord` (both records.rs), the `ptrace_syscall` BPF program, `LoadedPtraceProgram`, `ProcessPtraceStream`, the `LoadError` name generalization, unit tests for record decode, and the root-only smoke + functional filter test.

Out (PR2): the Python worker, `config.py` wiring, the `proc.ptrace_injection` rule. Also out: finit/init_module and raw-socket slices (separate specs-sections/plans).

## File map

- **Modify** `crates/inspectord_native_bpf/src/records.rs` — add `PtraceRecord` (BPF side, `zeroed()`).
- **Modify** `crates/inspectord_native_bpf/src/main.rs` — add the `PTRACE_EVENTS` ring map, the ptrace request constants, and the `ptrace_syscall` `#[tracepoint]` program.
- **Modify** `crates/inspectord_native/src/records.rs` — add `PtraceRecord` (userspace, `from_bytes()` + `comm_str()` + `request_str()`) and its unit tests.
- **Modify** `crates/inspectord_native/src/loader.rs` — add `load_bpf()` (lean, no OFFSETS), `LoadedPtraceProgram`, and generalize `LoadError::MissingProgram`/`MissingMap` to carry names.
- **Modify** `crates/inspectord_native/src/lib.rs` — add `ProcessPtraceStream` pyclass + register it.
- **Modify** `tests/test_native_loader.py` — root-only load/close + functional filter test.

## Key constants (single source of truth for this plan)

ptrace request values (x86_64, from `<sys/ptrace.h>` / `<linux/ptrace.h>`):

| Name | Value |
| --- | --- |
| `PTRACE_POKETEXT` | 4 |
| `PTRACE_POKEDATA` | 5 |
| `PTRACE_POKEUSR` | 6 |
| `PTRACE_SETREGS` | 13 |
| `PTRACE_ATTACH` | 16 |
| `PTRACE_SETREGSET` | 0x4205 |
| `PTRACE_SEIZE` | 0x4206 |

ftrace `sys_enter_ptrace` arg offsets: `request` at 16 (arg 0), `pid` at 24 (arg 1), read as `u64`.

---

### Task 1: `PtraceRecord` on both sides + userspace decode helpers (TDD)

This task is pure userspace Rust (no eBPF, no root) — the record struct, its byte-copy roundtrip, and the `comm_str`/`request_str` decoders. It stands alone and is fully testable with `cargo test`.

**Files:**
- Modify: `crates/inspectord_native_bpf/src/records.rs`
- Modify: `crates/inspectord_native/src/records.rs`
- Test: inline `#[cfg(test)] mod tests` in `crates/inspectord_native/src/records.rs`

- [ ] **Step 1: Write the failing tests** (append to the existing `#[cfg(test)] mod tests` in `crates/inspectord_native/src/records.rs`)

```rust
    fn sample_ptrace() -> PtraceRecord {
        let mut comm = [0u8; COMM_LEN];
        comm[..4].copy_from_slice(b"gdb\0");
        PtraceRecord {
            timestamp_ns: 999,
            pid: 1234,
            uid: 1000,
            request: 16, // PTRACE_ATTACH
            target_pid: 5678,
            comm,
        }
    }

    #[test]
    fn ptrace_from_bytes_roundtrips_the_c_layout() {
        let r = sample_ptrace();
        let mut buf = vec![0u8; std::mem::size_of::<PtraceRecord>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &r as *const PtraceRecord as *const u8,
                buf.as_mut_ptr(),
                buf.len(),
            );
        }
        let parsed = PtraceRecord::from_bytes(&buf);
        assert_eq!(parsed.timestamp_ns, 999);
        assert_eq!(parsed.pid, 1234);
        assert_eq!(parsed.uid, 1000);
        assert_eq!(parsed.request, 16);
        assert_eq!(parsed.target_pid, 5678);
        assert_eq!(parsed.comm_str(), "gdb");
    }

    #[test]
    fn ptrace_request_str_maps_known_values() {
        let mut r = sample_ptrace();
        for (val, name) in [
            (4, "PTRACE_POKETEXT"),
            (5, "PTRACE_POKEDATA"),
            (6, "PTRACE_POKEUSR"),
            (13, "PTRACE_SETREGS"),
            (16, "PTRACE_ATTACH"),
            (0x4205, "PTRACE_SETREGSET"),
            (0x4206, "PTRACE_SEIZE"),
        ] {
            r.request = val;
            assert_eq!(r.request_str(), name);
        }
    }

    #[test]
    fn ptrace_request_str_renders_unknown_as_decimal() {
        let mut r = sample_ptrace();
        r.request = 0x4207;
        assert_eq!(r.request_str(), "PTRACE_16903");
        r.request = -1;
        assert_eq!(r.request_str(), "PTRACE_-1");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Set the Rust env first (the toolchain is not on PATH by default):
```sh
export CARGO_HOME=/home/eli/.cache/puccinialin/cargo RUSTUP_HOME=/home/eli/.cache/puccinialin/rustup
export PATH="/home/eli/.cache/puccinialin/cargo/bin:$HOME/.cargo/bin:$PATH"
```
Run: `cargo test -p inspectord-native --lib records::tests::ptrace`
Expected: FAIL — `cannot find type PtraceRecord in this scope`.

- [ ] **Step 3: Add `PtraceRecord` to the BPF-side records** (`crates/inspectord_native_bpf/src/records.rs`, after `ProcessExitRecord`)

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub request: i32,
    pub target_pid: i32,
    pub comm: [u8; COMM_LEN],
}

impl PtraceRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            request: 0,
            target_pid: 0,
            comm: [0; COMM_LEN],
        }
    }
}
```

- [ ] **Step 4: Add `PtraceRecord` + decoders to the userspace records** (`crates/inspectord_native/src/records.rs`, after `ProcessExitRecord`)

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    /// Raw ptrace request; only the validated injection-relevant set is ever
    /// emitted (see the BPF program). Decoded by `request_str`.
    pub request: i32,
    /// ptrace's target pid argument — a TID in the *caller's* pid namespace,
    /// so not necessarily a host pid for namespaced callers.
    pub target_pid: i32,
    pub comm: [u8; COMM_LEN],
}

impl PtraceRecord {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());
        let mut out = Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            request: 0,
            target_pid: 0,
            comm: [0; COMM_LEN],
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut out as *mut Self as *mut u8,
                std::mem::size_of::<Self>(),
            );
        }
        out
    }

    pub fn comm_str(&self) -> String {
        let n = self.comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
        String::from_utf8_lossy(&self.comm[..n]).into_owned()
    }

    /// Human-readable ptrace request name. Known injection-relevant values map
    /// to their PTRACE_* constant; anything else renders as `PTRACE_<decimal>`.
    pub fn request_str(&self) -> String {
        match self.request {
            4 => "PTRACE_POKETEXT".to_string(),
            5 => "PTRACE_POKEDATA".to_string(),
            6 => "PTRACE_POKEUSR".to_string(),
            13 => "PTRACE_SETREGS".to_string(),
            16 => "PTRACE_ATTACH".to_string(),
            0x4205 => "PTRACE_SETREGSET".to_string(),
            0x4206 => "PTRACE_SEIZE".to_string(),
            other => format!("PTRACE_{other}"),
        }
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p inspectord-native --lib records::tests::ptrace`
Expected: PASS (3 ptrace tests). This compiles the BPF crate via build.rs too, so a layout/type error in either records.rs surfaces here.

- [ ] **Step 6: Commit**

```bash
git add crates/inspectord_native_bpf/src/records.rs crates/inspectord_native/src/records.rs
git commit -m "feat(native): PtraceRecord + request_str/comm_str decoders

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: the `ptrace_syscall` BPF program

Adds the ring-buffer map, request constants, and the filtering tracepoint program. This is `#![no_std]` eBPF code — it is validated by the kernel verifier only at load time (Task 4's root-only test), so here we only confirm it *compiles* to `bpfel-unknown-none`.

**Files:**
- Modify: `crates/inspectord_native_bpf/src/main.rs`

- [ ] **Step 1: Add the `PTRACE_EVENTS` ring-buffer map** (after the `CONNECT6_EVENTS` map, ~line 34)

64 KiB — rare events; see spec §2 map-footprint note.

```rust
#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(65_536, 0);
```

- [ ] **Step 2: Add the ptrace request constants** (near the existing `AF_INET`/`TCP_*` consts, ~line 69)

```rust
// Injection-relevant ptrace requests (x86_64). Read/step/cont/PEEK are
// intentionally excluded — they are the debugger firehose, not injection.
const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_POKEUSR: u64 = 6;
const PTRACE_SETREGS: u64 = 13;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SETREGSET: u64 = 0x4205;
const PTRACE_SEIZE: u64 = 0x4206;
```

- [ ] **Step 2b: Add the `TracePointContext` import** (extend the existing `use aya_ebpf::{... programs::BtfTracePointContext};` block)

Change the `programs` import line to:
```rust
    programs::{BtfTracePointContext, TracePointContext},
```
and add `tracepoint` to the `macros` import (alongside `btf_tracepoint`, `map`):
```rust
    macros::{btf_tracepoint, map, tracepoint},
```

- [ ] **Step 3: Add the `ptrace_syscall` program** (after `try_outbound_connection6`, before the `panic` handler)

```rust
#[tracepoint]
pub fn ptrace_syscall(ctx: TracePointContext) -> i32 {
    let _ = try_ptrace_syscall(ctx);
    0
}

fn try_ptrace_syscall(ctx: TracePointContext) -> Result<(), i64> {
    // ftrace sys_enter layout (stable in practice on x86_64): 8-byte common
    // header, __syscall_nr at 8, then u64 syscall args at 16 + 8*i.
    //   arg 0 = request  @ offset 16
    //   arg 1 = pid      @ offset 24
    let request: u64 = unsafe { ctx.read_at(16).map_err(|_| -1_i64)? };
    let target_pid: u64 = unsafe { ctx.read_at(24).map_err(|_| -1_i64)? };

    // Compare the FULL u64 so a value with garbage high bits can never alias
    // a real request (e.g. 0x1_0000_0010 must not look like PTRACE_ATTACH).
    let interesting = matches!(
        request,
        PTRACE_POKETEXT
            | PTRACE_POKEDATA
            | PTRACE_POKEUSR
            | PTRACE_SETREGS
            | PTRACE_ATTACH
            | PTRACE_SETREGSET
            | PTRACE_SEIZE
    );
    if !interesting {
        return Err(0);
    }

    // Cross-process only. caller = TGID (upper 32 bits of pid_tgid); drop when
    // the target TID equals it (same-process). Another process's TID can never
    // equal our TGID within a namespace, so this has no false negatives; a
    // sibling-thread self-attach still emits (the kernel EPERMs it anyway).
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if target_pid as u32 == tgid {
        return Err(0);
    }

    let mut entry = PTRACE_EVENTS.reserve::<PtraceRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();
    unsafe {
        record_ptr.write(PtraceRecord::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*record_ptr).pid = tgid;
        let uid_gid = bpf_get_current_uid_gid();
        (*record_ptr).uid = uid_gid as u32;
        (*record_ptr).request = request as i32;
        (*record_ptr).target_pid = target_pid as i32;
        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }
    }
    entry.submit(2u64); // BPF_RB_FORCE_WAKEUP
    Ok(())
}
```

- [ ] **Step 4: Add `PtraceRecord` to the records import** (extend the existing `use records::{...}` block in main.rs to include `PtraceRecord`)

```rust
use records::{
    ConnectRecord, ConnectRecord6, ProcessExecRecord, ProcessExitRecord, PtraceRecord, CMDLINE_LEN,
    COMM_LEN,
};
```

- [ ] **Step 5: Compile the BPF crate**

Run (with the Rust env exported as in Task 1 Step 2):
`cargo test -p inspectord-native --lib records::tests::ptrace`
Expected: PASS — this triggers build.rs which compiles `inspectord_native_bpf` to `bpfel-unknown-none`. A compile error in the BPF program fails the build here. (Verifier acceptance is checked in Task 4.)

- [ ] **Step 6: Commit**

```bash
git add crates/inspectord_native_bpf/src/main.rs
git commit -m "feat(native): ptrace_syscall tracepoint program (cross-process, filtered)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `LoadError` name generalization + `load_bpf()` + `LoadedPtraceProgram`

Generalizes the two hardcoded-message `LoadError` variants to carry names, adds a lean loader path (no OFFSETS population — syscall tracepoints need no BTF), and the `LoadedPtraceProgram` that attaches `syscalls:sys_enter_ptrace` and drains `PTRACE_EVENTS`.

**Files:**
- Modify: `crates/inspectord_native/src/loader.rs`

- [ ] **Step 1: Generalize `LoadError::MissingProgram` and `MissingMap`** — change the enum variants (bottom of loader.rs)

Replace:
```rust
    #[error("BPF program 'process_exec' not found in object")]
    MissingProgram,
    #[error("BPF map 'EVENTS' not found in object")]
    MissingMap,
```
with:
```rust
    #[error("BPF program '{0}' not found in object")]
    MissingProgram(String),
    #[error("BPF map '{0}' not found in object")]
    MissingMap(String),
```

- [ ] **Step 2: Update the two existing helpers that raise these variants**

In `attach_btf_tracepoint`, change:
```rust
        .ok_or(LoadError::MissingProgram)?
```
to:
```rust
        .ok_or_else(|| LoadError::MissingProgram(program_name.to_string()))?
```

In `take_ring`, change:
```rust
    let map = bpf.take_map(name).ok_or(LoadError::MissingMap)?;
```
to:
```rust
    let map = bpf
        .take_map(name)
        .ok_or_else(|| LoadError::MissingMap(name.to_string()))?;
```

- [ ] **Step 3: Add the lean `load_bpf()` helper** (after `load_and_populate_offsets`)

Syscall tracepoints dereference no kernel structs, so this skips OFFSETS entirely.

```rust
/// Lean load path for syscall tracepoint programs: they read args at fixed
/// ftrace offsets and never dereference kernel structs, so — unlike
/// `load_and_populate_offsets` — they need no BTF-resolved OFFSETS map. The
/// returned `Ebpf` is loaded but unattached.
fn load_bpf() -> Result<(Ebpf, Btf), LoadError> {
    let bpf = Ebpf::load(PROGRAM_BYTES).map_err(LoadError::Load)?;
    let btf = Btf::from_sys_fs().map_err(LoadError::AyaBtf)?;
    Ok((bpf, btf))
}
```

- [ ] **Step 4: Add a syscall-tracepoint attach helper** (after `attach_btf_tracepoint`)

The existing `attach_btf_tracepoint` uses `BtfTracePoint`; syscall tracepoints use aya's plain `TracePoint` with a (category, name) pair.

```rust
fn attach_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<(), LoadError> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| LoadError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(LoadError::Program)?;
    program.load().map_err(LoadError::Program)?;
    program.attach(category, name).map_err(LoadError::Program)?;
    Ok(())
}
```

- [ ] **Step 5: Add the `TracePoint` + `PtraceRecord` imports** (top of loader.rs)

Extend the `use aya::{... programs::BtfTracePoint ...}` block so `programs` imports both:
```rust
    programs::{BtfTracePoint, TracePoint},
```
Extend the records import:
```rust
use crate::records::{ConnectRecord, ConnectRecord6, ProcessExecRecord, ProcessExitRecord, PtraceRecord};
```

- [ ] **Step 6: Add `LoadedPtraceProgram`** (struct near the other `Loaded*` structs, impl after `LoadedConnect6Program`)

Struct:
```rust
pub struct LoadedPtraceProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}
```

Impl:
```rust
impl LoadedPtraceProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let (mut bpf, _btf) = load_bpf()?;
        attach_tracepoint(&mut bpf, "ptrace_syscall", "syscalls", "sys_enter_ptrace")?;
        let ring = take_ring(&mut bpf, "PTRACE_EVENTS")?;
        Ok(Self { _bpf: bpf, ring })
    }

    fn drain(&mut self) -> Vec<PtraceRecord> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<PtraceRecord>() {
                out.push(PtraceRecord::from_bytes(&item));
            }
        }
        out
    }

    /// Blocks for up to `timeout` waiting for at least one record, then
    /// drains everything available. Returns empty Vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Vec<PtraceRecord> {
        if !poll_ring(&self.ring, timeout) {
            return Vec::new();
        }
        self.drain()
    }
}
```

- [ ] **Step 7: Compile**

Run (Rust env exported): `cargo build -p inspectord-native`
Expected: SUCCESS. If the `TracePoint` import path is wrong, the error names it — the correct path is `aya::programs::TracePoint` (verified in aya 0.13.1).

- [ ] **Step 8: Run the full native lib test suite + clippy + fmt**

```sh
cargo test -p inspectord-native --lib
cargo clippy -p inspectord-native --lib
cargo fmt --all -- --check
```
Expected: all pass (the generalized `LoadError` variants compile everywhere they're used; existing tests unaffected).

- [ ] **Step 9: Commit**

```bash
git add crates/inspectord_native/src/loader.rs
git commit -m "feat(native): LoadedPtraceProgram + lean load_bpf; name LoadError variants

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: `ProcessPtraceStream` PyO3 class + registration

Exposes the loader to Python as a stream mirroring `ProcessConnectStream`, returning one dict per record including the decoded `request_name`.

**Files:**
- Modify: `crates/inspectord_native/src/lib.rs`

- [ ] **Step 1: Add the import** (extend the `use loader::{...}` line)

```rust
use loader::{
    LoadedConnect6Program, LoadedConnectProgram, LoadedExitProgram, LoadedProgram,
    LoadedPtraceProgram,
};
```

- [ ] **Step 2: Add the `ProcessPtraceStream` pyclass** (after `ProcessConnectStream6`)

```rust
#[pyclass(unsendable)]
struct ProcessPtraceStream {
    program: Option<LoadedPtraceProgram>,
}

#[pymethods]
impl ProcessPtraceStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedPtraceProgram::load_and_attach()
            .map_err(|e| PyOSError::new_err(format!("eBPF load failed: {e}")))?;
        Ok(Self {
            program: Some(program),
        })
    }

    /// Block for up to `timeout_ms` ms, then return all currently-available
    /// cross-process ptrace records as a list of dicts. Only the
    /// injection-relevant request set is emitted (filtered in-BPF).
    fn poll<'py>(&mut self, py: Python<'py>, timeout_ms: u64) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let program = self
            .program
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("stream is closed"))?;
        let records = program.poll(Duration::from_millis(timeout_ms));
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let dict = PyDict::new(py);
            dict.set_item("timestamp_ns", record.timestamp_ns)?;
            dict.set_item("pid", record.pid)?;
            dict.set_item("uid", record.uid)?;
            dict.set_item("comm", record.comm_str())?;
            dict.set_item("request", record.request)?;
            dict.set_item("request_name", record.request_str())?;
            dict.set_item("target_pid", record.target_pid)?;
            out.push(dict);
        }
        Ok(out)
    }

    fn close(&mut self) {
        self.program.take();
    }

    fn __enter__<'py>(slf: PyRef<'py, Self>) -> PyRef<'py, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        self.close();
        false
    }
}
```

- [ ] **Step 3: Register the class in the module** (in `fn _native`, after the `ProcessConnectStream6` line)

```rust
    m.add_class::<ProcessPtraceStream>()?;
```

- [ ] **Step 4: Build the extension into the venv**

Run: `.venv/bin/maturin develop`
Expected: builds and installs; `ProcessPtraceStream` becomes importable from `inspectord._native`.

- [ ] **Step 5: Verify the class is importable** (non-root — construction needs root, but the symbol must exist)

Run: `.venv/bin/python -c "from inspectord._native import ProcessPtraceStream; print('ok')"`
Expected: prints `ok`.

- [ ] **Step 6: Commit**

```bash
git add crates/inspectord_native/src/lib.rs
git commit -m "feat(native): ProcessPtraceStream PyO3 class

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: root-only smoke + functional filter test

The only test that exercises the in-BPF filter — the genuinely new logic. Skipped as non-root in CI; run manually via sudo. Uses Python's `ctypes` to issue a real `PTRACE_ATTACH` to a forked child, and a child that calls `PTRACE_TRACEME` (an out-of-set request) to confirm it is dropped.

**Files:**
- Modify: `tests/test_native_loader.py`

- [ ] **Step 1: Add the load/close smoke test + the functional filter test**

```python
import ctypes  # add to imports at top of file
import time

from inspectord._native import ProcessPtraceStream  # add to the existing import line


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_ptrace_stream_loads_and_closes() -> None:
    """The ptrace_syscall program passes the verifier and attaches."""
    stream = ProcessPtraceStream()
    try:
        assert stream is not None
    finally:
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_ptrace_stream_captures_attach_but_not_out_of_set() -> None:
    """A real cross-process PTRACE_ATTACH is captured; a subsequent out-of-set
    request (PTRACE_PEEKTEXT) on the same child is dropped by the in-BPF filter.

    Note: the child must NOT call PTRACE_TRACEME — that would make this process
    its tracer implicitly, and the later PTRACE_ATTACH would then fail EPERM
    (already traced). The child just sleeps; the parent drives all ptrace calls.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    PTRACE_PEEKTEXT = 1  # out of the emitted set
    PTRACE_CONT = 7  # out of the emitted set (used to resume before cleanup)
    PTRACE_ATTACH = 16  # in the emitted set
    PTRACE_DETACH = 17

    stream = ProcessPtraceStream()
    child = os.fork()
    if child == 0:  # child: just live long enough to be attached to
        time.sleep(5)
        os._exit(0)
    try:
        time.sleep(0.2)
        stream.poll(200)  # drain anything unrelated produced so far

        # Cross-process, in-set → must be captured.
        rc = libc.ptrace(PTRACE_ATTACH, child, 0, 0)
        assert rc == 0, f"PTRACE_ATTACH failed: errno {ctypes.get_errno()}"
        os.waitpid(child, 0)  # wait for the attach-stop

        # Cross-process but OUT of set → must be dropped. The syscall enters
        # (and thus fires the tracepoint) regardless of success, so a null addr
        # is fine — we only need sys_enter_ptrace to run with request=1.
        libc.ptrace(PTRACE_PEEKTEXT, child, 0, 0)

        records: list[dict] = []
        for _ in range(10):
            batch = stream.poll(200)
            records.extend(batch)
            if any(r["request_name"] == "PTRACE_ATTACH" for r in records):
                break

        attach_records = [r for r in records if r["request_name"] == "PTRACE_ATTACH"]
        assert attach_records, f"no PTRACE_ATTACH record captured; got {records}"
        assert attach_records[0]["target_pid"] == child
        # The out-of-set PEEKTEXT (request 1) must never appear.
        assert all(r["request"] != PTRACE_PEEKTEXT for r in records), records
    finally:
        # Resume + detach + reap; ignore errors if the child is already gone.
        try:
            libc.ptrace(PTRACE_CONT, child, 0, 0)
            libc.ptrace(PTRACE_DETACH, child, 0, 0)
            os.kill(child, 9)
            os.waitpid(child, 0)
        except (ProcessLookupError, ChildProcessError):
            pass
        stream.close()
```

- [ ] **Step 2: Verify the non-root skip works** (so CI stays green)

Run: `.venv/bin/python -m pytest tests/test_native_loader.py -v`
Expected: the ptrace tests report SKIPPED (`needs CAP_BPF (run as root)`) when run as a normal user; no failures.

- [ ] **Step 3: Run the functional test as root** (manual verification — this is the concilium-required check)

Run: `sudo .venv/bin/python -m pytest tests/test_native_loader.py -k ptrace -v`
Expected: `test_process_ptrace_stream_loads_and_closes` PASS and `test_ptrace_stream_captures_cross_process_attach` PASS — proving the ftrace arg offsets, the request filter, and the cross-process check all work end-to-end on this kernel.

- [ ] **Step 4: Commit**

```bash
git add tests/test_native_loader.py
git commit -m "test(native): root-only ptrace load + functional filter test

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: full gate sweep + PR

- [ ] **Step 1: Run every gate** (Rust env exported for the cargo ones)

```sh
cargo test -p inspectord-native --lib
cargo fmt --all -- --check
cargo clippy -p inspectord-native --lib
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q
.venv/bin/ruff check inspectord inspectorctl tests
.venv/bin/ruff format --check inspectord inspectorctl tests
.venv/bin/mypy inspectord
```
Expected: all green. (The new tests are Rust-side + a root-only Python test that skips; the Python suite should be unaffected.)

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin ptrace-tracepoint-native
gh pr create --title "feat(process): sys_enter_ptrace eBPF tracepoint + ProcessPtraceStream (ptrace native PR1)" --body "$(cat <<'EOF'
Native slice (PR1) of the process syscall-tracepoints program. Spec:
`docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md`
(brainstormed + concilium-reviewed REVISE→revised).

Adds the first *syscall* tracepoint (vs the existing BTF kernel tracepoints):
- `PtraceRecord` (both records.rs) + `request_str`/`comm_str` decoders.
- `ptrace_syscall` `#[tracepoint]` BPF program on `syscalls:sys_enter_ptrace`
  — filters in-BPF to 7 injection-relevant requests (incl. SETREGSET),
  cross-process only, full-u64 request compare + TGID-vs-TID drop rule.
- Lean `load_bpf()` (no OFFSETS/BTF — syscall tracepoints read fixed ftrace
  arg offsets, dereference no kernel structs) + `LoadedPtraceProgram`.
- `ProcessPtraceStream` PyO3 class.
- `LoadError::MissingProgram`/`MissingMap` generalized to carry names.
- Root-only smoke + **functional filter test** (fork + PTRACE_ATTACH →
  record; out-of-set TRACEME → no record) — verified locally via sudo.

The Python worker + `config.py` wiring + `proc.ptrace_injection` rule land
in PR2.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Watch CI**

Run: `gh pr checks --watch`
Expected: lint-and-test, CodeQL, cargo-audit, dependency-review all green.

- [ ] **Step 4: Merge**

```bash
gh pr merge --squash --delete-branch
```

---

## Self-review notes

- **Spec coverage (§3.1):** PtraceRecord ✓ (Task 1); 7-request full-u64 filter + cross-process TGID/TID rule ✓ (Task 2); 64 KiB ring ✓ (Task 2 Step 1); lean `load_bpf` no-OFFSETS ✓ (Task 3); `ProcessPtraceStream` with `request_name` ✓ (Task 4); `LoadError` name generalization ✓ (Task 3); root-only functional filter test ✓ (Task 5); build.rs "compile-time only, verifier at load" wording reflected in Task 2 Step 5 / Task 5 Step 3. `request_str` unknown → `PTRACE_<decimal>` incl. negative ✓ (Task 1 tests).
- **Deferred to PR2 (correctly out of this plan):** worker, config.py, rule. Deferred to other slices: init/finit_module, raw-socket.
- **Type consistency:** `PtraceRecord` fields identical across both records.rs and every consumer; `request:i32`/`target_pid:i32` stored, `u64` compared in-BPF; pyclass named `ProcessPtraceStream`, program named `ptrace_syscall`, map `PTRACE_EVENTS`, ring 64 KiB — consistent across Tasks 2–5.
- **Assumption to watch at execution:** the exact aya `programs` import may need `BtfTracePoint` and `TracePoint` on separate `use` lines if the existing block is structured differently — the engineer adjusts to match the file; the type paths (`aya::programs::TracePoint`, `aya_ebpf::programs::TracePointContext`, `aya_ebpf::macros::tracepoint`) are verified present in the pinned versions.
