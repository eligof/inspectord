//! Loads the embedded BPF object into the kernel, attaches the
//! process_exec / process_exit tracepoint programs, and reads records from
//! their ring buffers. Each `LoadedProgram` / `LoadedExitProgram` is meant
//! to live in its own worker process — it owns its `Ebpf` instance and
//! populates its own copy of the OFFSETS map at load time.

use aya::{
    include_bytes_aligned,
    maps::{ring_buf::RingBuf, Array, MapData},
    programs::{BtfTracePoint, TracePoint},
    Btf, Ebpf,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use crate::btf_offsets::{BtfError, KernelOffsets};
use crate::records::{
    ConnectRecord, ConnectRecord6, ModuleLoadRecord, ProcessExecRecord, ProcessExitRecord,
    PtraceRecord,
};

// `include_bytes!` only guarantees byte alignment, but aya's ELF parser
// requires the program bytes to be aligned to the ELF header struct.
// `aya::include_bytes_aligned!` wraps the bytes in a 32-byte-aligned struct.
const PROGRAM_BYTES: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/inspectord-bpf"));

pub struct LoadedProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

pub struct LoadedExitProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

pub struct LoadedConnectProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

pub struct LoadedConnect6Program {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

pub struct LoadedPtraceProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

pub struct LoadedModuleLoadProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
    /// Held open for the life of the program; see
    /// `enable_tracepoint_on_all_cpus`.
    _cpu_events: Vec<OwnedFd>,
}

/// Load the embedded BPF object and populate the OFFSETS array map from
/// `/sys/kernel/btf/vmlinux`. The returned `Ebpf` is loaded but has no
/// attached programs yet — the caller picks which tracepoint(s) to attach
/// and which ring-buffer map to take.
fn load_and_populate_offsets() -> Result<(Ebpf, Btf), LoadError> {
    let mut bpf = Ebpf::load(PROGRAM_BYTES).map_err(LoadError::Load)?;

    // Resolve current-kernel struct offsets from BTF and pass them to the
    // BPF program. Order matters: programs are loaded but not yet attached,
    // so they can't fire with zero offsets before we populate.
    let offsets = KernelOffsets::from_sys_fs().map_err(LoadError::BtfResolve)?;
    let offsets_map = bpf.map_mut("OFFSETS").ok_or(LoadError::MissingOffsetsMap)?;
    let mut offsets_arr: Array<_, u32> =
        Array::try_from(offsets_map).map_err(|e| LoadError::MapKind(format!("{e:?}")))?;
    for (idx, value) in [
        (0u32, offsets.task_real_parent),
        (1, offsets.task_tgid),
        (2, offsets.task_mm),
        (3, offsets.mm_arg_start),
        (4, offsets.task_exit_code),
        (5, offsets.sock_family),
        (6, offsets.sock_dport),
        (7, offsets.sock_num),
        // sock_common.skc_daddr legitimately lives at offset 0; we still
        // write it so the loader's BPF-side "populated" sentinel is family.
        (8, offsets.sock_daddr),
        (9, offsets.sock_rcv_saddr),
        (10, offsets.sock_v6_daddr),
        (11, offsets.sock_v6_rcv_saddr),
    ] {
        offsets_arr
            .set(idx, value, 0)
            .map_err(|e| LoadError::MapWrite(format!("{e:?}")))?;
    }

    let btf = Btf::from_sys_fs().map_err(LoadError::AyaBtf)?;
    Ok((bpf, btf))
}

/// Lean load path for syscall tracepoint programs: they read args at fixed
/// ftrace offsets and never dereference kernel structs, so — unlike
/// `load_and_populate_offsets` — they need no BTF-resolved OFFSETS map. The
/// returned `Ebpf` is loaded but unattached.
fn load_bpf() -> Result<(Ebpf, Btf), LoadError> {
    let bpf = Ebpf::load(PROGRAM_BYTES).map_err(LoadError::Load)?;
    let btf = Btf::from_sys_fs().map_err(LoadError::AyaBtf)?;
    Ok((bpf, btf))
}

fn attach_btf_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    tracepoint: &str,
    btf: &Btf,
) -> Result<(), LoadError> {
    let program: &mut BtfTracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| LoadError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(LoadError::Program)?;
    program.load(tracepoint, btf).map_err(LoadError::Program)?;
    program.attach().map_err(LoadError::Program)?;
    Ok(())
}

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

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;

/// `perf_event_attr`, zeroed except for the three fields a tracepoint event
/// needs. Sized at 128 bytes (PERF_ATTR_SIZE_VER7): older kernels check that
/// the trailing bytes they don't know about are zero, newer ones zero-fill
/// the fields we don't supply.
#[repr(C)]
#[derive(Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    rest: [u64; 14],
}

/// Opens one plain tracepoint perf event per online CPU and returns the fds,
/// which the caller must keep open for as long as the BPF program is attached.
///
/// Why: `TracePoint::attach` opens a single perf event with `pid = -1, cpu = 0`.
/// For most syscall tracepoints that is enough, because the kernel's perf
/// handler runs the tracepoint's BPF program array on any CPU as soon as one
/// program is attached. The faultable syscall tracepoints that copy their
/// userspace string argument — `sys_enter_finit_module` and
/// `sys_enter_init_module` among them — instead return early on any CPU whose
/// per-CPU perf-event list for that tracepoint is empty, so a CPU-0-only event
/// silently limits the collector to module loads that happen to run on CPU 0.
/// Registering an event on every CPU un-gates the handler everywhere. These
/// events carry no BPF program and are never mmap'd, so the program stays
/// attached exactly once and each syscall still produces exactly one record.
fn enable_tracepoint_on_all_cpus(category: &str, name: &str) -> Result<Vec<OwnedFd>, LoadError> {
    let tracefs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .find(|dir| Path::new(dir).join("events").is_dir())
        .ok_or_else(|| LoadError::PerfEvent("tracefs is not mounted".to_string()))?;
    let id_path = format!("{tracefs}/events/{category}/{name}/id");
    let id: u64 = std::fs::read_to_string(&id_path)
        .map_err(|e| LoadError::PerfEvent(format!("read {id_path}: {e}")))?
        .trim()
        .parse()
        .map_err(|e| LoadError::PerfEvent(format!("parse {id_path}: {e}")))?;

    let cpus = aya::util::online_cpus()
        .map_err(|(path, e)| LoadError::PerfEvent(format!("read {path}: {e}")))?;
    let mut fds = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let attr = PerfEventAttr {
            type_: PERF_TYPE_TRACEPOINT,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            config: id,
            rest: [0; 14],
        };
        // SAFETY: `attr` outlives the call and is sized by its own `size`
        // field; the kernel only reads from it.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr,
                -1_i32, // pid: any process
                cpu as i32,
                -1_i32, // group_fd
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(LoadError::PerfEvent(format!(
                "perf_event_open({category}:{name}) on cpu {cpu}: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: perf_event_open returned a fresh, owned fd.
        fds.push(unsafe { OwnedFd::from_raw_fd(fd as i32) });
    }
    Ok(fds)
}

fn take_ring(bpf: &mut Ebpf, name: &str) -> Result<RingBuf<MapData>, LoadError> {
    let map = bpf
        .take_map(name)
        .ok_or_else(|| LoadError::MissingMap(name.to_string()))?;
    RingBuf::try_from(map).map_err(|e| LoadError::MapKind(format!("{e:?}")))
}

fn poll_ring(ring: &RingBuf<MapData>, timeout: Duration) -> bool {
    use libc::{poll, pollfd, POLLIN};
    let mut fds = [pollfd {
        fd: ring.as_raw_fd(),
        events: POLLIN,
        revents: 0,
    }];
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    unsafe { poll(fds.as_mut_ptr(), 1, timeout_ms) > 0 }
}

impl LoadedProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let (mut bpf, btf) = load_and_populate_offsets()?;
        attach_btf_tracepoint(&mut bpf, "process_exec", "sched_process_exec", &btf)?;
        let ring = take_ring(&mut bpf, "EVENTS")?;
        Ok(Self { _bpf: bpf, ring })
    }

    fn drain(&mut self) -> Vec<ProcessExecRecord> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<ProcessExecRecord>() {
                out.push(ProcessExecRecord::from_bytes(&item));
            }
        }
        out
    }

    /// Blocks for up to `timeout` waiting for at least one record, then
    /// drains everything available. Returns empty Vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Vec<ProcessExecRecord> {
        if !poll_ring(&self.ring, timeout) {
            return Vec::new();
        }
        self.drain()
    }
}

impl LoadedExitProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let (mut bpf, btf) = load_and_populate_offsets()?;
        attach_btf_tracepoint(&mut bpf, "process_exit", "sched_process_exit", &btf)?;
        let ring = take_ring(&mut bpf, "EXIT_EVENTS")?;
        Ok(Self { _bpf: bpf, ring })
    }

    fn drain(&mut self) -> Vec<ProcessExitRecord> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<ProcessExitRecord>() {
                out.push(ProcessExitRecord::from_bytes(&item));
            }
        }
        out
    }

    /// Blocks for up to `timeout` waiting for at least one record, then
    /// drains everything available. Returns empty Vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Vec<ProcessExitRecord> {
        if !poll_ring(&self.ring, timeout) {
            return Vec::new();
        }
        self.drain()
    }
}

impl LoadedConnectProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let (mut bpf, btf) = load_and_populate_offsets()?;
        attach_btf_tracepoint(&mut bpf, "outbound_connection", "inet_sock_set_state", &btf)?;
        let ring = take_ring(&mut bpf, "CONNECT_EVENTS")?;
        Ok(Self { _bpf: bpf, ring })
    }

    fn drain(&mut self) -> Vec<ConnectRecord> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<ConnectRecord>() {
                out.push(ConnectRecord::from_bytes(&item));
            }
        }
        out
    }

    /// Blocks for up to `timeout` waiting for at least one record, then
    /// drains everything available. Returns empty Vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Vec<ConnectRecord> {
        if !poll_ring(&self.ring, timeout) {
            return Vec::new();
        }
        self.drain()
    }
}

impl LoadedConnect6Program {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let (mut bpf, btf) = load_and_populate_offsets()?;
        attach_btf_tracepoint(
            &mut bpf,
            "outbound_connection6",
            "inet_sock_set_state",
            &btf,
        )?;
        let ring = take_ring(&mut bpf, "CONNECT6_EVENTS")?;
        Ok(Self { _bpf: bpf, ring })
    }

    fn drain(&mut self) -> Vec<ConnectRecord6> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<ConnectRecord6>() {
                out.push(ConnectRecord6::from_bytes(&item));
            }
        }
        out
    }

    /// Blocks for up to `timeout` waiting for at least one record, then
    /// drains everything available. Returns empty Vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Vec<ConnectRecord6> {
        if !poll_ring(&self.ring, timeout) {
            return Vec::new();
        }
        self.drain()
    }
}

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
        // Both tracepoints need a perf event on every CPU, not just CPU 0.
        let mut cpu_events = enable_tracepoint_on_all_cpus("syscalls", "sys_enter_finit_module")?;
        cpu_events.extend(enable_tracepoint_on_all_cpus(
            "syscalls",
            "sys_enter_init_module",
        )?);
        let ring = take_ring(&mut bpf, "MODULE_EVENTS")?;
        Ok(Self {
            _bpf: bpf,
            ring,
            _cpu_events: cpu_events,
        })
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

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("aya load error: {0}")]
    Load(#[from] aya::EbpfError),
    #[error("aya program error: {0}")]
    Program(#[from] aya::programs::ProgramError),
    #[error("BPF program '{0}' not found in object")]
    MissingProgram(String),
    #[error("BPF map '{0}' not found in object")]
    MissingMap(String),
    #[error("BPF map 'OFFSETS' not found in object")]
    MissingOffsetsMap,
    #[error("map kind mismatch: {0}")]
    MapKind(String),
    #[error("map write failed: {0}")]
    MapWrite(String),
    #[error("kernel BTF resolution failed: {0}")]
    BtfResolve(#[from] BtfError),
    #[error("aya BTF error: {0}")]
    AyaBtf(#[from] aya::BtfError),
    #[error("tracepoint perf event setup failed: {0}")]
    PerfEvent(String),
}
