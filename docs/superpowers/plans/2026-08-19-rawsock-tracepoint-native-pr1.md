# raw-socket tracepoint native slice (PR1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture raw-socket creation — the packet-sniffer / crafted-packet primitive — with the creating process attached, by attaching the `syscalls:sys_enter_socket` ftrace tracepoint, and expose it to Python as a `ProcessRawSocketStream` PyO3 class.

**Architecture:** One `#[tracepoint]` BPF program `socket_syscall` writes a `RawSocketRecord` into a new `RAWSOCK_EVENTS` ring buffer (64 KiB). It never dereferences kernel structs, so — like the ptrace and module-load programs — it needs no BTF offsets and uses the lean `load_bpf()` path. One `LoadedRawSocketProgram` attaches the program and owns the ring; one `ProcessRawSocketStream` pyclass exposes `poll()`. This is the native half of the 2-PR eBPF split and the third and final slice of the syscall-tracepoint spec; the Python worker and the `proc.raw_socket_unprivileged` rule follow in PR2.

**Tech Stack:** Rust, aya / aya-ebpf, PyO3 (`crates/inspectord_native`, `crates/inspectord_native_bpf`), pytest for the root-only load tests.

**Spec:** `docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md` §2 (shared syscall-tracepoint mechanism), §5 (this slice, including the filter and the resolved open question), §6 (testing), §7 (out of scope).

**Template:** the ptrace slice (#116 native / #118 worker) and the kernel-module slice (#119 native / #120 worker). Every piece below has a direct counterpart — read `ptrace_syscall` and `finit_module_syscall` in `crates/inspectord_native_bpf/src/main.rs`, `PtraceRecord` / `ModuleLoadRecord` in both `records.rs` files, `LoadedPtraceProgram` / `LoadedModuleLoadProgram` in `crates/inspectord_native/src/loader.rs`, and `ProcessPtraceStream` / `ProcessModuleLoadStream` in `crates/inspectord_native/src/lib.rs` before starting.

**Two things already locked (spec §5) — do not revisit:**

1. **The filter is family-scoped and must not be widened.** Emit when `family == AF_PACKET (17)`, **or** (`family ∈ {AF_INET=2, AF_INET6=10}` **and** `(type & 0xf) == SOCK_RAW (3)`). `AF_NETLINK` sockets are conventionally `SOCK_RAW`, need no CAP_NET_RAW, and are created constantly by ordinary desktop processes (iproute2, sd-netlink/systemd, NetworkManager, libnl consumers) — an unscoped type-only filter would flood the stream. `AF_UNIX SOCK_RAW` is silently remapped by the kernel. The `0xf` mask strips `SOCK_NONBLOCK`/`SOCK_CLOEXEC`; the record stores the **unmasked** `type` so the worker keeps the flags as evidence.
2. **No outcome or capability signal in v1** (resolved 2026-08-19). No `sys_exit_socket` pairing (needs per-thread state that leaks on task death) and no in-BPF CAP_NET_RAW read (needs BTF struct offsets, which this whole tracepoint family exists to avoid). The uid-proxy blind spots are accepted and belong in PR2's rule `false_positives`, not here.

---

## Build & test commands

Rust toolchain is **not on PATH by default**. Every Rust command in this plan must be run after:

```sh
export CARGO_HOME=/home/eli/.cache/puccinialin/cargo RUSTUP_HOME=/home/eli/.cache/puccinialin/rustup
export PATH="/home/eli/.cache/puccinialin/cargo/bin:$HOME/.cargo/bin:$PATH"
```

- Rust tests (also compiles the BPF crate via build.rs): `cargo test -p inspectord-native --lib`
- Rust gates: `cargo fmt --all -- --check` · `cargo clippy -p inspectord-native --lib`
- CI builds the BPF crate with `-D warnings`; check locally with
  `cd crates/inspectord_native_bpf && RUSTFLAGS="-D warnings" cargo build --release --target bpfel-unknown-none`
- Rebuild the Python extension after Rust changes: `.venv/bin/maturin develop`
- Python gates: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` · `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests` · `.venv/bin/mypy inspectord`
- Root-only eBPF tests: `sudo .venv/bin/python -m pytest tests/test_native_loader.py -v` (a NOPASSWD sudoers rule covers exactly `.venv/bin/python -m pytest *`; no other sudo command will work)

---

## File Structure

| File | Change |
| --- | --- |
| `crates/inspectord_native_bpf/src/records.rs` | Add `RawSocketRecord` (BPF-side mirror, `zeroed()`). |
| `crates/inspectord_native_bpf/src/main.rs` | Add the `RAWSOCK_EVENTS` ring buffer, the socket-domain/type constants, and the `socket_syscall` `#[tracepoint]` program with its filter. |
| `crates/inspectord_native/src/records.rs` | Add the userspace `RawSocketRecord` mirror + `from_bytes` + `comm_str` + `family_str`, and unit tests. |
| `crates/inspectord_native/src/loader.rs` | Add `LoadedRawSocketProgram` (attaches the tracepoint, holds the per-CPU perf-event fds, owns the ring). |
| `crates/inspectord_native/src/lib.rs` | Add the `ProcessRawSocketStream` pyclass and register it in the module. |
| `tests/test_native_loader.py` | Add the root-only load test and the root-only functional filter test. |

---

### Task 1: `RawSocketRecord` in both crates + decoders

**Files:**
- Modify: `crates/inspectord_native_bpf/src/records.rs`
- Modify: `crates/inspectord_native/src/records.rs` (add tests in its existing `#[cfg(test)] mod tests`)

**The layout** (identical in both files, byte-for-byte, 48 bytes, no implicit padding — field order is chosen so every field is naturally aligned):

| offset | field | type |
| --- | --- | --- |
| 0 | `timestamp_ns` | `u64` |
| 8 | `pid` | `u32` |
| 12 | `uid` | `u32` |
| 16 | `family` | `i32` |
| 20 | `type_` | `i32` |
| 24 | `protocol` | `i32` |
| 28 | `_padding` | `[u8; 4]` |
| 32 | `comm` | `[u8; COMM_LEN]` |

- [ ] **Step 1: Write the failing tests**

In `crates/inspectord_native/src/records.rs`, inside the existing `#[cfg(test)] mod tests`, append (mirroring `sample_module_load` / `module_load_record_is_48_bytes`):

```rust
    fn sample_raw_socket() -> RawSocketRecord {
        let mut comm = [0u8; COMM_LEN];
        comm[..7].copy_from_slice(b"tcpdump");
        RawSocketRecord {
            timestamp_ns: 42,
            pid: 4321,
            uid: 0,
            family: 17,
            type_: 3,
            protocol: 768,
            _padding: [0; 4],
            comm,
        }
    }

    #[test]
    fn raw_socket_record_is_48_bytes() {
        // The BPF and userspace structs are transmuted across the ring buffer,
        // so the size must stay pinned; a silent layout change would decode
        // garbage rather than fail loudly.
        assert_eq!(std::mem::size_of::<RawSocketRecord>(), 48);
    }

    #[test]
    fn raw_socket_from_bytes_roundtrips_the_c_layout() {
        let record = sample_raw_socket();
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &record as *const RawSocketRecord as *const u8,
                std::mem::size_of::<RawSocketRecord>(),
            )
        };
        let decoded = RawSocketRecord::from_bytes(bytes);
        assert_eq!(decoded.timestamp_ns, 42);
        assert_eq!(decoded.pid, 4321);
        assert_eq!(decoded.uid, 0);
        assert_eq!(decoded.family, 17);
        assert_eq!(decoded.type_, 3);
        assert_eq!(decoded.protocol, 768);
        assert_eq!(decoded.comm_str(), "tcpdump");
    }

    #[test]
    fn raw_socket_family_str_maps_the_emitted_families() {
        let mut record = sample_raw_socket();
        assert_eq!(record.family_str(), "AF_PACKET");
        record.family = 2;
        assert_eq!(record.family_str(), "AF_INET");
        record.family = 10;
        assert_eq!(record.family_str(), "AF_INET6");
    }

    #[test]
    fn raw_socket_family_str_renders_unknown_numerically() {
        let mut record = sample_raw_socket();
        record.family = 16;
        assert_eq!(record.family_str(), "AF_16");
        record.family = -1;
        assert_eq!(record.family_str(), "AF_-1");
    }

    #[test]
    fn raw_socket_type_keeps_the_socket_flags() {
        // The BPF filter masks with 0xf to recognise SOCK_RAW, but the record
        // stores the type as passed so SOCK_NONBLOCK/SOCK_CLOEXEC survive as
        // evidence. 0x80803 = SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC.
        let mut record = sample_raw_socket();
        record.type_ = 0x8_0803;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &record as *const RawSocketRecord as *const u8,
                std::mem::size_of::<RawSocketRecord>(),
            )
        };
        assert_eq!(RawSocketRecord::from_bytes(bytes).type_, 0x8_0803);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p inspectord-native --lib`
Expected: compile error — `cannot find type RawSocketRecord in this scope`.

- [ ] **Step 3: Add the BPF-side record**

In `crates/inspectord_native_bpf/src/records.rs`, after `ModuleLoadRecord`:

```rust
/// One raw-socket creation, from `sys_enter_socket`. Only the family-scoped
/// raw sockets pass the in-BPF filter (AF_PACKET of any type, or AF_INET /
/// AF_INET6 with SOCK_RAW) — see the filter in main.rs. Emitted at syscall
/// entry, so a call the kernel is about to reject with EPERM is recorded too.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawSocketRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    /// socket(2)'s domain argument: AF_PACKET / AF_INET / AF_INET6.
    pub family: i32,
    /// socket(2)'s type argument **as passed**, flag bits included. The filter
    /// masks with 0xf to test for SOCK_RAW; the record keeps the flags.
    pub type_: i32,
    /// socket(2)'s protocol argument (e.g. ETH_P_ALL = 0x0003 for a sniffer,
    /// byte-swapped by the caller via htons, so typically 768 on little-endian).
    pub protocol: i32,
    pub _padding: [u8; 4],
    pub comm: [u8; COMM_LEN],
}

impl RawSocketRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            family: 0,
            type_: 0,
            protocol: 0,
            _padding: [0; 4],
            comm: [0; COMM_LEN],
        }
    }
}
```

- [ ] **Step 4: Add the userspace record + decoders**

In `crates/inspectord_native/src/records.rs`, after the `ModuleLoadRecord` block, add the identical struct definition (same doc comments, same field order) plus:

```rust
impl RawSocketRecord {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());
        let mut out = Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            family: 0,
            type_: 0,
            protocol: 0,
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

    /// Human-readable address family. Only the three families the BPF filter
    /// emits are named; anything else renders as `AF_<decimal>` so an
    /// unexpected value is visible rather than silently mislabelled.
    pub fn family_str(&self) -> String {
        match self.family {
            2 => "AF_INET".to_string(),
            10 => "AF_INET6".to_string(),
            17 => "AF_PACKET".to_string(),
            other => format!("AF_{other}"),
        }
    }
}
```

Follow the file's existing convention for imports/exports — `RawSocketRecord` must be importable exactly the way `ModuleLoadRecord` is.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p inspectord-native --lib`
Expected: PASS with 5 more tests than before (the suite currently reports 19 passed; expect 24).

- [ ] **Step 6: Run the Rust gates**

Run: `cargo fmt --all -- --check` then `cargo clippy -p inspectord-native --lib`
Expected: no output from fmt; no warnings from clippy.

- [ ] **Step 7: Commit**

```bash
git add crates/inspectord_native_bpf/src/records.rs crates/inspectord_native/src/records.rs
git commit -m "feat(native): RawSocketRecord + family/comm decoders

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: the `socket_syscall` BPF program

**Files:**
- Modify: `crates/inspectord_native_bpf/src/main.rs`

There is no unit test at this layer — the BPF crate is `no_std` and only compiles; verifier acceptance happens at load time and is covered by Task 4's root-only test. `cargo test -p inspectord-native --lib` still compiles this crate via build.rs, so a type error fails there.

- [ ] **Step 1: Add the ring buffer**

After the existing `MODULE_EVENTS` map declaration:

```rust
#[map]
static RAWSOCK_EVENTS: RingBuf = RingBuf::with_byte_size(65_536, 0);
```

64 KiB, matching `PTRACE_EVENTS` / `MODULE_EVENTS` — raw-socket creation is rare, and per spec §2 every worker's `Ebpf::load()` instantiates all maps in the shared ELF, so rings for rare events stay small.

- [ ] **Step 2: Add the socket constants**

Next to the existing `MODULE_VARIANT_*` constants. Note the file already has `AF_INET: u16` / `AF_INET6: u16` for the `sock_common` readers, which are a different type and a different concept (kernel struct field vs. syscall argument), hence the distinct `SOCKET_AF_*` names:

```rust
// socket(2) domain/type values, as the syscall's `int` arguments. Named
// apart from the AF_INET/AF_INET6 u16 constants above, which decode
// sock_common.skc_family rather than a syscall argument.
const SOCKET_AF_INET: i32 = 2;
const SOCKET_AF_INET6: i32 = 10;
const SOCKET_AF_PACKET: i32 = 17;
const SOCK_RAW: i32 = 3;
/// socket(2)'s type argument carries SOCK_NONBLOCK/SOCK_CLOEXEC in its high
/// bits; the base type is the low nibble.
const SOCK_TYPE_MASK: i32 = 0xf;
```

Also add `RawSocketRecord` to the existing `use records::{...}` list.

- [ ] **Step 3: Write the program**

Append after `try_init_module_syscall`:

```rust
#[tracepoint]
pub fn socket_syscall(ctx: TracePointContext) -> i32 {
    let _ = try_socket_syscall(ctx);
    0
}

fn try_socket_syscall(ctx: TracePointContext) -> Result<(), i64> {
    // sys_enter_socket(int family, int type, int protocol).
    // ftrace sys_enter layout: 8-byte common header, __syscall_nr at 8, then
    // u64 syscall args at 16 + 8*i.
    //   arg 0 = family   @ 16
    //   arg 1 = type     @ 24
    //   arg 2 = protocol @ 32
    //
    // Read as u64 and truncate to i32, which is exactly what the kernel's
    // SYSCALL_DEFINE3(socket, int, int, int) does with the register values —
    // so our view of the arguments cannot diverge from the kernel's. (The
    // ptrace program compares the full u64 instead, because ptrace's request
    // argument is a `long` there and is *not* truncated.)
    let family: u64 = unsafe { ctx.read_at(16).map_err(|_| -1_i64)? };
    let sock_type: u64 = unsafe { ctx.read_at(24).map_err(|_| -1_i64)? };
    let family = family as i32;
    let sock_type = sock_type as i32;

    // Filter BEFORE reserving a ring slot (spec section 5). Emit AF_PACKET of
    // any type — the packet-sniffer domain, CAP_NET_RAW-gated in full — plus
    // inet/inet6 SOCK_RAW, the crafted-packet path.
    //
    // The family scope is load-bearing, not a nicety: AF_NETLINK sockets are
    // conventionally SOCK_RAW, need no CAP_NET_RAW, and are opened constantly
    // by ordinary desktop software (iproute2, sd-netlink/systemd,
    // NetworkManager, libnl), so a type-only filter would flood this stream.
    // AF_UNIX SOCK_RAW is silently remapped by the kernel and is likewise not
    // a raw socket in any meaningful sense.
    let is_raw_inet = (family == SOCKET_AF_INET || family == SOCKET_AF_INET6)
        && (sock_type & SOCK_TYPE_MASK) == SOCK_RAW;
    if family != SOCKET_AF_PACKET && !is_raw_inet {
        return Err(0);
    }

    let protocol: u64 = unsafe { ctx.read_at(32).map_err(|_| -1_i64)? };

    let mut entry = RAWSOCK_EVENTS.reserve::<RawSocketRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();
    unsafe {
        record_ptr.write(RawSocketRecord::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*record_ptr).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*record_ptr).uid = bpf_get_current_uid_gid() as u32;
        (*record_ptr).family = family;
        // Unmasked on purpose: the mask is only how SOCK_RAW is recognised,
        // while SOCK_NONBLOCK/SOCK_CLOEXEC are evidence worth keeping.
        (*record_ptr).type_ = sock_type;
        (*record_ptr).protocol = protocol as i32;
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

- [ ] **Step 4: Verify it compiles, including under CI's `-D warnings`**

Run:
```sh
cargo test -p inspectord-native --lib
cd crates/inspectord_native_bpf && RUSTFLAGS="-D warnings" cargo build --release --target bpfel-unknown-none
```
Expected: both clean. (CI builds the BPF crate with `-D warnings`, so an unused variable here breaks the build even though local builds tolerate it.)

- [ ] **Step 5: Run the Rust gates and commit**

```bash
cargo fmt --all -- --check && cargo clippy -p inspectord-native --lib
git add crates/inspectord_native_bpf/src/main.rs
git commit -m "feat(native): socket_syscall tracepoint program + RAWSOCK_EVENTS ring

Filters in-BPF to AF_PACKET, or AF_INET/AF_INET6 with SOCK_RAW, before
reserving a ring slot. The family scope keeps the constant AF_NETLINK
SOCK_RAW traffic of ordinary desktop software out of the stream.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `LoadedRawSocketProgram` + `ProcessRawSocketStream`

**Files:**
- Modify: `crates/inspectord_native/src/loader.rs`
- Modify: `crates/inspectord_native/src/lib.rs`

- [ ] **Step 1: Add the loader struct**

In `loader.rs`, declare the struct beside `LoadedModuleLoadProgram` (same shape: `_bpf: Ebpf`, `ring: RingBuf<MapData>`, `_cpu_events: Vec<OwnedFd>` — `attach_tracepoint` returns the per-CPU perf-event fds and **the program must hold them for its lifetime**), and add:

```rust
impl LoadedRawSocketProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let (mut bpf, _btf) = load_bpf()?;
        let cpu_events =
            attach_tracepoint(&mut bpf, "socket_syscall", "syscalls", "sys_enter_socket")?;
        let ring = take_ring(&mut bpf, "RAWSOCK_EVENTS")?;
        Ok(Self {
            _bpf: bpf,
            ring,
            _cpu_events: cpu_events,
        })
    }

    fn drain(&mut self) -> Vec<RawSocketRecord> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<RawSocketRecord>() {
                out.push(RawSocketRecord::from_bytes(&item));
            }
        }
        out
    }

    /// Blocks for up to `timeout` waiting for at least one record, then
    /// drains everything available. Returns empty Vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Vec<RawSocketRecord> {
        if !poll_ring(&self.ring, timeout) {
            return Vec::new();
        }
        self.drain()
    }
}
```

Add `RawSocketRecord` to the `use crate::records::{...}` list at the top of the file.

- [ ] **Step 2: Add the pyclass**

In `lib.rs`, mirroring `ProcessModuleLoadStream` exactly (`#[pyclass(unsendable)]`, `new`, `poll`, `close`, `__enter__`, `__exit__`):

```rust
#[pyclass(unsendable)]
struct ProcessRawSocketStream {
    program: Option<LoadedRawSocketProgram>,
}

#[pymethods]
impl ProcessRawSocketStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedRawSocketProgram::load_and_attach()
            .map_err(|e| PyOSError::new_err(format!("eBPF load failed: {e}")))?;
        Ok(Self {
            program: Some(program),
        })
    }

    /// Block for up to `timeout_ms` ms, then return all currently-available
    /// raw-socket creations as a list of dicts. Only AF_PACKET sockets and
    /// AF_INET/AF_INET6 SOCK_RAW sockets are emitted; the call is recorded at
    /// syscall entry, so one the kernel rejects with EPERM appears too.
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
            dict.set_item("family", record.family)?;
            dict.set_item("family_name", record.family_str())?;
            dict.set_item("type", record.type_)?;
            dict.set_item("protocol", record.protocol)?;
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

Register it in the `#[pymodule] fn _native` body: `m.add_class::<ProcessRawSocketStream>()?;`, and add `LoadedRawSocketProgram` to the `use loader::{...}` import list.

- [ ] **Step 3: Build and verify the class is importable**

Run:
```sh
cargo test -p inspectord-native --lib && .venv/bin/maturin develop && \
.venv/bin/python -c "from inspectord._native import ProcessRawSocketStream; print(ProcessRawSocketStream)"
```
Expected: the class prints. (Constructing it needs root; that is Task 4.)

- [ ] **Step 4: Run the Rust gates and commit**

```bash
cargo fmt --all -- --check && cargo clippy -p inspectord-native --lib
git add crates/inspectord_native/src/loader.rs crates/inspectord_native/src/lib.rs
git commit -m "feat(native): LoadedRawSocketProgram + ProcessRawSocketStream

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: root-only load + functional filter tests

**Files:**
- Modify: `tests/test_native_loader.py`

The functional test is the only test at any level that exercises the in-BPF filter — the one genuinely new piece of logic in this slice — and its most valuable assertion is the **negative** one for `AF_NETLINK SOCK_RAW`, the flood the family scope exists to prevent.

**CPU pinning: not needed here** (unlike `test_module_load_stream_captures_both_syscall_variants`). That test pins off CPU 0 because `sys_enter_finit_module` / `sys_enter_init_module` are *faultable* tracepoints — they copy a userspace string argument, and their kernel handler returns early on any CPU with no registered perf event. `sys_enter_socket` takes three scalar `int`s, copies nothing from userspace, and is therefore a plain tracepoint whose BPF program runs on every CPU as soon as it is attached — exactly like `sys_enter_ptrace`, whose functional test also does not pin. Keeping the test unpinned matches the ptrace precedent and avoids implying a dependency that does not exist.

**Ordering matters**: create the two sockets that must be filtered out **first**, and the AF_PACKET socket that must be captured **last**. Then poll until the AF_PACKET record arrives — at which point all three syscalls have provably already fired, so "no record for the other two" is a real assertion rather than a race.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_native_loader.py` (and add `ProcessRawSocketStream` to the existing `from inspectord._native import (...)`):

```python
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_raw_socket_stream_loads_and_closes() -> None:
    """The socket_syscall program passes the verifier and attaches."""
    stream = ProcessRawSocketStream()
    try:
        assert stream is not None
    finally:
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_raw_socket_stream_captures_af_packet_but_filters_the_rest() -> None:
    """AF_PACKET is captured; a plain TCP socket and an AF_NETLINK SOCK_RAW
    socket are dropped by the in-BPF family scope.

    The AF_NETLINK case is the point of the family scope: netlink sockets are
    conventionally SOCK_RAW, need no CAP_NET_RAW, and are opened constantly by
    ordinary desktop software, so a type-only filter would flood the stream.

    The two sockets that must be filtered out are created first and the
    AF_PACKET one last, so that once its record arrives the other two syscalls
    have provably already run — making their absence an assertion, not a race.

    No CPU pinning here (unlike the module-load test): sys_enter_socket takes
    three scalar ints, copies nothing from userspace, and so is not one of the
    faultable tracepoints whose handler is gated on a per-CPU perf event.
    """
    af_netlink = 16  # socket.AF_NETLINK exists but keep the number explicit
    netlink_route = 0

    stream = ProcessRawSocketStream()
    tcp_sock = None
    netlink_sock = None
    packet_sock = None
    try:
        time.sleep(0.2)
        stream.poll(200)  # drain anything unrelated

        # Must NOT be captured: ordinary TCP socket.
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        # Must NOT be captured: netlink is SOCK_RAW by convention.
        netlink_sock = socket.socket(af_netlink, socket.SOCK_RAW, netlink_route)
        # Must be captured: the packet-sniffer socket.
        packet_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)

        records: list[dict] = []
        for _ in range(10):
            records.extend(stream.poll(200))
            if any(
                r["pid"] == os.getpid() and r["family_name"] == "AF_PACKET" for r in records
            ):
                break

        mine = [r for r in records if r["pid"] == os.getpid()]
        packets = [r for r in mine if r["family_name"] == "AF_PACKET"]
        assert packets, f"no AF_PACKET record captured; got {records}"
        assert packets[0]["comm"], "record carries no comm"
        assert packets[0]["uid"] == 0
        # SOCK_RAW, unmasked (Python passes no SOCK_NONBLOCK/SOCK_CLOEXEC).
        assert packets[0]["type"] == socket.SOCK_RAW

        # The whole reason the filter is family-scoped.
        assert not [r for r in mine if r["family"] == af_netlink], (
            f"AF_NETLINK SOCK_RAW leaked past the family scope: {mine}"
        )
        # A plain AF_INET SOCK_STREAM socket is not raw and must not appear.
        assert not [r for r in mine if r["family_name"] == "AF_INET"], (
            f"non-raw AF_INET socket leaked past the type check: {mine}"
        )
    finally:
        for sock in (tcp_sock, netlink_sock, packet_sock):
            if sock is not None:
                sock.close()
        stream.close()
```

Add `import socket` to the module's imports.

- [ ] **Step 2: Run as root**

Run: `sudo .venv/bin/python -m pytest tests/test_native_loader.py -k raw_socket -v`
Expected: PASS once Tasks 1-3 are complete. If it fails, read the message before changing anything — a verifier rejection, a missing tracepoint, and a wrong argument offset all look different. The authoritative reference for the argument layout is
`/sys/kernel/tracing/events/syscalls/sys_enter_socket/format`.

- [ ] **Step 3: Run the full root-only set**

Run: `sudo .venv/bin/python -m pytest tests/test_native_loader.py -v`
Expected: all tests pass, including the pre-existing exec/connect6/ptrace/module-load ones — the new program must not break the shared ELF.

- [ ] **Step 4: Run every gate**

```sh
cargo fmt --all -- --check && cargo clippy -p inspectord-native --lib && cargo test -p inspectord-native --lib
cd crates/inspectord_native_bpf && RUSTFLAGS="-D warnings" cargo build --release --target bpfel-unknown-none
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q
.venv/bin/ruff check inspectord tests && .venv/bin/ruff format --check inspectord tests && .venv/bin/mypy inspectord
```
Expected: all clean.

- [ ] **Step 5: Commit**

```bash
git add tests/test_native_loader.py
git commit -m "test(native): root-only raw-socket verifier + functional filter test

Asserts AF_PACKET is captured while a plain TCP socket and an AF_NETLINK
SOCK_RAW socket are not — the netlink case being the flood the family scope
exists to prevent.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: PR

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin rawsock-tracepoint-native
gh pr create --base main --head rawsock-tracepoint-native \
  --title "feat(native): sys_enter_socket tracepoint + ProcessRawSocketStream (PR1)" \
  --body "<mechanism, the family-scoped filter and why, the root-only test output>"
```

- [ ] **Step 2: Watch CI, then squash-merge**

```bash
gh pr checks <N> --watch
gh pr merge <N> --squash --delete-branch
```

---

## Self-Review notes

- **Spec coverage:** §5's record (caller pid/uid/comm + family + type + protocol) → Task 1; the exact family-scoped filter, applied before the ring reserve → Task 2; the per-syscall plumbing of §2 (own ring → own `Loaded*Program` → own `Process*Stream`) → Task 3; §6's Rust roundtrip tests plus the root-only verifier and functional tests → Tasks 1 and 4.
- **Out of scope (§7):** no worker, no `proc.raw_socket_unprivileged` rule, no outcome/capability signal, no anomaly scoring — those are PR2 and later.
- **Type consistency:** `RawSocketRecord`'s field names and order are identical in both crates; the three family values are constants in the BPF crate and decoded by `family_str` in the userspace crate, with a comment in each pointing at the other. The pyclass exposes `type_` as the dict key `type` (Python has no keyword clash there) — PR2's worker must use that key.
- **Deliberate deviation from the ptrace program:** `socket_syscall` truncates its arguments to `i32` before comparing, where `ptrace_syscall` compares the full `u64`. This is not an inconsistency: ptrace's `request` is a `long` that the kernel does not truncate, whereas socket's three arguments are `int`s that the kernel does. Mirroring the kernel's own truncation keeps the filter from being bypassable by a caller who sets garbage high bits.
