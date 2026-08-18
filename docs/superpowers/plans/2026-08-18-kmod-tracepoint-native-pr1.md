# kernel-module tracepoint native slice (PR1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture every kernel-module load attempt with the *initiating process* attached, by attaching two ftrace syscall tracepoints (`sys_enter_finit_module` and `sys_enter_init_module`) that feed one ring buffer, and expose them to Python as a `ProcessModuleLoadStream` PyO3 class.

**Architecture:** Two `#[tracepoint]` BPF programs write a shared `ModuleLoadRecord` into one new `MODULE_EVENTS` ring buffer (64 KiB); a `variant` field says which syscall produced the record. Neither program dereferences kernel structs, so — like the ptrace program — they need no BTF offsets and use the lean `load_bpf()` path. One `LoadedModuleLoadProgram` attaches both programs and owns the single ring. This is the native half of the 2-PR eBPF split; the Python worker and the `proc.kernel_module_loaded_unknown` rule follow in PR2.

**Tech Stack:** Rust, aya / aya-ebpf, PyO3 (`crates/inspectord_native`, `crates/inspectord_native_bpf`), pytest for the root-only load tests.

**Spec:** `docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md` §2 (shared syscall-tracepoint mechanism), §4 (this slice, including the resolved open questions), §6 (testing), §7 (out of scope).

**Template:** the ptrace slice, merged as #116 (native) and #118 (worker). Every piece below has a direct counterpart there — read `ptrace_syscall` in `crates/inspectord_native_bpf/src/main.rs`, `PtraceRecord` in both `records.rs` files, `LoadedPtraceProgram` in `crates/inspectord_native/src/loader.rs`, and `ProcessPtraceStream` in `crates/inspectord_native/src/lib.rs` before starting.

**Two design decisions already locked (spec §4, resolved 2026-08-18) — do not revisit:**
1. **No module-name resolution.** The record carries who loaded a module, not which one. `kmod_watcher` already reports the name; the two are joined by time proximity in the rule engine, not by a racy `/proc/<pid>/fd/<fd>` read.
2. **No params string.** The `params`/`uargs` userspace string is not captured. No rule consumes it, and reading it in-BPF adds verifier surface for unused evidence.

---

## Build & test commands

Rust toolchain is **not on PATH by default**. Every Rust command in this plan must be run after:

```sh
export CARGO_HOME=/home/eli/.cache/puccinialin/cargo RUSTUP_HOME=/home/eli/.cache/puccinialin/rustup
export PATH="/home/eli/.cache/puccinialin/cargo/bin:$HOME/.cargo/bin:$PATH"
```

- Rust tests (also compiles the BPF crate via build.rs): `cargo test -p inspectord-native --lib`
- Rust gates: `cargo fmt --all -- --check` · `cargo clippy -p inspectord-native --lib`
- Rebuild the Python extension after Rust changes: `.venv/bin/maturin develop`
- Python gates: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` · `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests` · `.venv/bin/mypy inspectord`
- Root-only eBPF tests: `sudo .venv/bin/python -m pytest -m ebpf_load <path>` (a NOPASSWD sudoers rule covers exactly `.venv/bin/python -m pytest *`; no other sudo command will work)

---

## File Structure

| File | Change |
| --- | --- |
| `crates/inspectord_native_bpf/src/records.rs` | Add `ModuleLoadRecord` (BPF-side mirror, `zeroed()`). |
| `crates/inspectord_native_bpf/src/main.rs` | Add the `MODULE_EVENTS` ring buffer, the variant constants, and the two `#[tracepoint]` programs `finit_module_syscall` / `init_module_syscall`. |
| `crates/inspectord_native/src/records.rs` | Add the userspace `ModuleLoadRecord` mirror + `from_bytes` + `comm_str` + `variant_str`, and unit tests. |
| `crates/inspectord_native/src/loader.rs` | Add `LoadedModuleLoadProgram` (attaches both tracepoints, owns the one ring). |
| `crates/inspectord_native/src/lib.rs` | Add the `ProcessModuleLoadStream` pyclass and register it in the module. |
| `tests/test_native_loader.py` | Add the root-only load test and the root-only functional test. |

---

### Task 1: `ModuleLoadRecord` in both crates + decoders

**Files:**
- Modify: `crates/inspectord_native_bpf/src/records.rs`
- Modify: `crates/inspectord_native/src/records.rs` (add tests in its existing `#[cfg(test)] mod tests`)

**The layout** (identical in both files, byte-for-byte, 48 bytes, no implicit padding — field order is chosen so every field is naturally aligned):

| offset | field | type |
| --- | --- | --- |
| 0 | `timestamp_ns` | `u64` |
| 8 | `pid` | `u32` |
| 12 | `uid` | `u32` |
| 16 | `variant` | `u32` |
| 20 | `fd` | `i32` |
| 24 | `flags` | `i32` |
| 28 | `_padding` | `[u8; 4]` |
| 32 | `comm` | `[u8; COMM_LEN]` |

- [ ] **Step 1: Write the failing tests**

In `crates/inspectord_native/src/records.rs`, inside the existing `#[cfg(test)] mod tests`, add (mirroring the existing `sample_ptrace` / `ptrace_from_bytes_roundtrips_the_c_layout` tests):

```rust
    fn sample_module_load() -> ModuleLoadRecord {
        let mut comm = [0u8; COMM_LEN];
        comm[..6].copy_from_slice(b"insmod");
        ModuleLoadRecord {
            timestamp_ns: 42,
            pid: 4321,
            uid: 0,
            variant: 0,
            fd: 3,
            flags: 0,
            _padding: [0; 4],
            comm,
        }
    }

    #[test]
    fn module_load_record_is_48_bytes() {
        // The BPF and userspace structs are transmuted across the ring buffer,
        // so the size must stay pinned; a silent layout change would decode
        // garbage rather than fail loudly.
        assert_eq!(std::mem::size_of::<ModuleLoadRecord>(), 48);
    }

    #[test]
    fn module_load_from_bytes_roundtrips_the_c_layout() {
        let record = sample_module_load();
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &record as *const ModuleLoadRecord as *const u8,
                std::mem::size_of::<ModuleLoadRecord>(),
            )
        };
        let decoded = ModuleLoadRecord::from_bytes(bytes);
        assert_eq!(decoded.timestamp_ns, 42);
        assert_eq!(decoded.pid, 4321);
        assert_eq!(decoded.uid, 0);
        assert_eq!(decoded.variant, 0);
        assert_eq!(decoded.fd, 3);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.comm_str(), "insmod");
    }

    #[test]
    fn module_load_variant_str_maps_both_syscalls() {
        let mut record = sample_module_load();
        assert_eq!(record.variant_str(), "finit_module");
        record.variant = 1;
        assert_eq!(record.variant_str(), "init_module");
    }

    #[test]
    fn module_load_variant_str_renders_unknown_numerically() {
        let mut record = sample_module_load();
        record.variant = 7;
        assert_eq!(record.variant_str(), "module_load_7");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p inspectord-native --lib`
Expected: compile error — `cannot find type ModuleLoadRecord in this scope`.

- [ ] **Step 3: Add the BPF-side record**

In `crates/inspectord_native_bpf/src/records.rs`, after `PtraceRecord`:

```rust
/// One kernel-module load attempt, from either `finit_module` (variant 0,
/// which passes an fd) or `init_module` (variant 1, which passes an anonymous
/// memory image and therefore has no fd or flags). Emitted for every call,
/// successful or not — sys_enter fires before the kernel's permission checks.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleLoadRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    /// 0 = finit_module, 1 = init_module.
    pub variant: u32,
    /// finit_module's fd argument; -1 for init_module, which has none.
    pub fd: i32,
    /// finit_module's flags argument; 0 for init_module, which has none.
    pub flags: i32,
    pub _padding: [u8; 4],
    pub comm: [u8; COMM_LEN],
}

impl ModuleLoadRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            variant: 0,
            fd: -1,
            flags: 0,
            _padding: [0; 4],
            comm: [0; COMM_LEN],
        }
    }
}
```

- [ ] **Step 4: Add the userspace record + decoders**

In `crates/inspectord_native/src/records.rs`, after the `PtraceRecord` block, add the identical struct definition (same doc comments, same field order) plus:

```rust
impl ModuleLoadRecord {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());
        let mut out = Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            variant: 0,
            fd: -1,
            flags: 0,
            _padding: [0; 4],
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

    /// Which syscall produced this record. Keep in sync with the `variant`
    /// values written by the BPF programs in inspectord_native_bpf/src/main.rs.
    pub fn variant_str(&self) -> String {
        match self.variant {
            0 => "finit_module".to_string(),
            1 => "init_module".to_string(),
            other => format!("module_load_{other}"),
        }
    }
}
```

Follow the file's existing convention for imports/exports — `ModuleLoadRecord` must be importable exactly the way `PtraceRecord` is.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p inspectord-native --lib`
Expected: PASS, with 4 more tests than before (the suite currently reports 15 passed; expect 19).

- [ ] **Step 6: Run the Rust gates**

Run: `cargo fmt --all -- --check` then `cargo clippy -p inspectord-native --lib`
Expected: no output from fmt; no warnings from clippy.

- [ ] **Step 7: Commit**

```bash
git add crates/inspectord_native_bpf/src/records.rs crates/inspectord_native/src/records.rs
git commit -m "feat(native): ModuleLoadRecord + variant/comm decoders

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: the two BPF tracepoint programs

**Files:**
- Modify: `crates/inspectord_native_bpf/src/main.rs`

There is no unit test at this layer — the BPF crate is `no_std` and only compiles; verifier acceptance happens at load time and is covered by Task 4's root-only test. `cargo test -p inspectord-native --lib` still compiles this crate via build.rs, so a type error fails there.

- [ ] **Step 1: Add the ring buffer**

After the existing `PTRACE_EVENTS` map declaration:

```rust
#[map]
static MODULE_EVENTS: RingBuf = RingBuf::with_byte_size(65_536, 0);
```

64 KiB, matching `PTRACE_EVENTS` — module loads are rare, and per spec §2 every worker's `Ebpf::load()` instantiates all maps in the shared ELF, so rings for rare events stay small.

- [ ] **Step 2: Add the variant constants**

Next to the existing `PTRACE_*` constants:

```rust
// Which module-load syscall produced a record. Keep in sync with
// ModuleLoadRecord::variant_str in the userspace crate.
const MODULE_VARIANT_FINIT: u32 = 0;
const MODULE_VARIANT_INIT: u32 = 1;
```

Also add `ModuleLoadRecord` to the existing `use records::{...}` list.

- [ ] **Step 3: Write the finit_module program**

Append after `try_ptrace_syscall`:

```rust
#[tracepoint]
pub fn finit_module_syscall(ctx: TracePointContext) -> i32 {
    let _ = try_finit_module_syscall(ctx);
    0
}

fn try_finit_module_syscall(ctx: TracePointContext) -> Result<(), i64> {
    // sys_enter_finit_module(int fd, const char *param_values, int flags).
    // ftrace sys_enter layout: 8-byte common header, __syscall_nr at 8, then
    // u64 syscall args at 16 + 8*i.
    //   arg 0 = fd     @ 16
    //   arg 1 = params @ 24 (deliberately not captured — spec section 4)
    //   arg 2 = flags  @ 32
    let fd: u64 = unsafe { ctx.read_at(16).map_err(|_| -1_i64)? };
    let flags: u64 = unsafe { ctx.read_at(32).map_err(|_| -1_i64)? };

    // No filter: module loads are rare, and every attempt is interesting —
    // including the ones the kernel is about to reject.
    let mut entry = MODULE_EVENTS.reserve::<ModuleLoadRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();
    unsafe {
        record_ptr.write(ModuleLoadRecord::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*record_ptr).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*record_ptr).uid = bpf_get_current_uid_gid() as u32;
        (*record_ptr).variant = MODULE_VARIANT_FINIT;
        (*record_ptr).fd = fd as i32;
        (*record_ptr).flags = flags as i32;
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

- [ ] **Step 4: Write the init_module program**

```rust
#[tracepoint]
pub fn init_module_syscall(ctx: TracePointContext) -> i32 {
    let _ = try_init_module_syscall(ctx);
    0
}

fn try_init_module_syscall(ctx: TracePointContext) -> Result<(), i64> {
    // sys_enter_init_module(void *umod, unsigned long len, const char *uargs).
    // The module image is an anonymous userspace buffer: there is no fd and no
    // path, which is exactly why this fd-avoidant loader path is traced at all.
    // None of its three arguments are captured (spec section 4: no params
    // string), so the record carries caller attribution only.
    let mut entry = MODULE_EVENTS.reserve::<ModuleLoadRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();
    unsafe {
        record_ptr.write(ModuleLoadRecord::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*record_ptr).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*record_ptr).uid = bpf_get_current_uid_gid() as u32;
        (*record_ptr).variant = MODULE_VARIANT_INIT;
        // fd stays -1 and flags stays 0 from zeroed() — init_module has neither.
        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }
    }
    entry.submit(2u64);
    Ok(())
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo test -p inspectord-native --lib`
Expected: PASS (build.rs compiles the BPF crate; a type error here fails the run).

- [ ] **Step 6: Run the Rust gates and commit**

```bash
cargo fmt --all -- --check && cargo clippy -p inspectord-native --lib
git add crates/inspectord_native_bpf/src/main.rs
git commit -m "feat(native): finit_module + init_module tracepoint programs

Both feed one MODULE_EVENTS ring; a variant field distinguishes them. No
filter — module loads are rare and every attempt matters, including rejected
ones. Neither program dereferences kernel structs, so no BTF offsets.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `LoadedModuleLoadProgram` + `ProcessModuleLoadStream`

**Files:**
- Modify: `crates/inspectord_native/src/loader.rs`
- Modify: `crates/inspectord_native/src/lib.rs`

- [ ] **Step 1: Add the loader struct**

In `loader.rs`, declare the struct beside `LoadedPtraceProgram` (same shape: `_bpf: Ebpf`, `ring: RingBuf<MapData>`) and add:

```rust
impl LoadedModuleLoadProgram {
    /// Attaches BOTH module-load syscalls. init_module is the fd-avoidant
    /// path a rootkit loader would prefer, so attaching only finit would leave
    /// a trivial bypass; one ring buffer serves both programs.
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let (mut bpf, _btf) = load_bpf()?;
        attach_tracepoint(
            &mut bpf,
            "finit_module_syscall",
            "syscalls",
            "sys_enter_finit_module",
        )?;
        attach_tracepoint(
            &mut bpf,
            "init_module_syscall",
            "syscalls",
            "sys_enter_init_module",
        )?;
        let ring = take_ring(&mut bpf, "MODULE_EVENTS")?;
        Ok(Self { _bpf: bpf, ring })
    }

    fn drain(&mut self) -> Vec<ModuleLoadRecord> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<ModuleLoadRecord>() {
                out.push(ModuleLoadRecord::from_bytes(&item));
            }
        }
        out
    }

    /// Blocks for up to `timeout` waiting for at least one record, then
    /// drains everything available. Returns empty Vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Vec<ModuleLoadRecord> {
        if !poll_ring(&self.ring, timeout) {
            return Vec::new();
        }
        self.drain()
    }
}
```

Add `ModuleLoadRecord` to the `use crate::records::{...}` list at the top of the file.

- [ ] **Step 2: Add the pyclass**

In `lib.rs`, mirroring `ProcessPtraceStream` exactly (`#[pyclass(unsendable)]`, `new`, `poll`, `close`, `__enter__`, `__exit__`):

```rust
#[pyclass(unsendable)]
struct ProcessModuleLoadStream {
    program: Option<LoadedModuleLoadProgram>,
}

#[pymethods]
impl ProcessModuleLoadStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedModuleLoadProgram::load_and_attach()
            .map_err(|e| PyOSError::new_err(format!("eBPF load failed: {e}")))?;
        Ok(Self {
            program: Some(program),
        })
    }

    /// Block for up to `timeout_ms` ms, then return all currently-available
    /// kernel-module load attempts as a list of dicts. Every call is emitted,
    /// including ones the kernel rejects — the tracepoint is at syscall entry.
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
            dict.set_item("variant", record.variant)?;
            dict.set_item("variant_name", record.variant_str())?;
            dict.set_item("fd", record.fd)?;
            dict.set_item("flags", record.flags)?;
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

Register it in the `#[pymodule] fn _native` body: `m.add_class::<ProcessModuleLoadStream>()?;`, and add `LoadedModuleLoadProgram` to the `use loader::{...}` import list.

- [ ] **Step 3: Build and verify the class is importable**

Run:
```sh
cargo test -p inspectord-native --lib && .venv/bin/maturin develop && \
.venv/bin/python -c "from inspectord._native import ProcessModuleLoadStream; print(ProcessModuleLoadStream)"
```
Expected: the class prints. (Constructing it needs root; that is Task 4.)

- [ ] **Step 4: Run the Rust gates and commit**

```bash
cargo fmt --all -- --check && cargo clippy -p inspectord-native --lib
git add crates/inspectord_native/src/loader.rs crates/inspectord_native/src/lib.rs
git commit -m "feat(native): LoadedModuleLoadProgram + ProcessModuleLoadStream

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: root-only load + functional tests

**Files:**
- Modify: `tests/test_native_loader.py`

The functional test does **not** load a real kernel module. `sys_enter_*` fires at syscall entry, before the kernel validates the fd or the image, so calling `finit_module` with a deliberately invalid fd produces a record and then fails with `EBADF` — nothing is loaded, and the test is safe to run repeatedly. Same for `init_module` with a NULL image.

x86_64 syscall numbers: `init_module` = 175, `finit_module` = 313.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_native_loader.py` (and add `ProcessModuleLoadStream` to the existing `from inspectord._native import (...)`):

```python
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_module_load_stream_loads_and_closes() -> None:
    """Both module-load programs pass the verifier and attach."""
    stream = ProcessModuleLoadStream()
    try:
        assert stream is not None
    finally:
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_module_load_stream_captures_both_syscall_variants() -> None:
    """A failing finit_module and a failing init_module are both recorded.

    sys_enter fires before the kernel validates the fd or the image, so
    deliberately invalid arguments still produce records — no module is ever
    loaded by this test.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    sys_init_module = 175
    sys_finit_module = 313

    stream = ProcessModuleLoadStream()
    try:
        time.sleep(0.2)
        stream.poll(200)  # drain anything unrelated

        # Invalid fd -> EBADF, but the tracepoint has already fired.
        libc.syscall(sys_finit_module, -1, b"", 0)
        # NULL image -> EFAULT, likewise after the tracepoint fired.
        libc.syscall(sys_init_module, None, 0, b"")

        records: list[dict] = []
        for _ in range(10):
            records.extend(stream.poll(200))
            names = {r["variant_name"] for r in records if r["pid"] == os.getpid()}
            if {"finit_module", "init_module"} <= names:
                break

        mine = [r for r in records if r["pid"] == os.getpid()]
        finits = [r for r in mine if r["variant_name"] == "finit_module"]
        inits = [r for r in mine if r["variant_name"] == "init_module"]
        assert finits, f"no finit_module record captured; got {records}"
        assert inits, f"no init_module record captured; got {records}"
        assert finits[0]["fd"] == -1
        assert inits[0]["fd"] == -1  # init_module has no fd
        assert finits[0]["uid"] == 0
    finally:
        stream.close()
```

- [ ] **Step 2: Run as root**

Run: `sudo .venv/bin/python -m pytest tests/test_native_loader.py -k module_load -v`
Expected: PASS once Tasks 1-3 are complete. If it fails, read the message before changing anything — a verifier rejection, a missing tracepoint, and a wrong argument offset all look different. The authoritative reference for the argument layout is
`/sys/kernel/tracing/events/syscalls/sys_enter_finit_module/format`.

- [ ] **Step 3: Run the full root-only set**

Run: `sudo .venv/bin/python -m pytest tests/test_native_loader.py -v`
Expected: all tests pass, including the pre-existing exec/connect6/ptrace ones — the new programs must not break the shared ELF.

- [ ] **Step 4: Run every gate**

```sh
cargo fmt --all -- --check && cargo clippy -p inspectord-native --lib && cargo test -p inspectord-native --lib
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q
.venv/bin/ruff check inspectord tests && .venv/bin/ruff format --check inspectord tests && .venv/bin/mypy inspectord
```
Expected: all clean.

- [ ] **Step 5: Commit**

```bash
git add tests/test_native_loader.py
git commit -m "test(native): root-only module-load verifier + functional test

Both syscall variants are exercised with deliberately invalid arguments, so
the tracepoints fire without any module ever being loaded.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: PR

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin kmod-tracepoint-native
gh pr create --base main --head kmod-tracepoint-native \
  --title "feat(native): finit_module + init_module tracepoints + ProcessModuleLoadStream (PR1)" \
  --body "<mechanism, the two locked decisions, the root-only test output>"
```

- [ ] **Step 2: Watch CI, then squash-merge**

```bash
gh pr checks <N> --watch
gh pr merge <N> --squash --delete-branch
```

---

## Self-Review notes

- **Spec coverage:** §4's record (caller pid/uid/comm + variant + fd + flags, no params) → Task 1; both syscalls traced with no filter → Task 2; the one-ring/one-loader design → Task 3; §6's Rust roundtrip tests and root-only verifier tests → Tasks 1 and 4. §4's resolved decisions are honored: no name resolution anywhere, no params capture.
- **Out of scope (§7):** no worker, no rule, no name resolution, no anomaly scoring — those are PR2 and later.
- **Type consistency:** `ModuleLoadRecord`'s field names and order are identical in both crates and in the pyclass dict keys; the `variant` values 0/1 are defined once as constants in the BPF crate and decoded by `variant_str` in the userspace crate, with a comment in each pointing at the other.
