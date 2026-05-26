//! Loads the embedded BPF object into the kernel, attaches the
//! `process_exec` tracepoint program, and reads records from the
//! ring buffer.

use aya::{
    include_bytes_aligned,
    maps::{ring_buf::RingBuf, Array, MapData},
    programs::TracePoint,
    Ebpf,
};
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::btf_offsets::{BtfError, KernelOffsets};
use crate::records::ProcessExecRecord;

// `include_bytes!` only guarantees byte alignment, but aya's ELF parser
// requires the program bytes to be aligned to the ELF header struct.
// `aya::include_bytes_aligned!` wraps the bytes in a 32-byte-aligned struct.
const PROGRAM_BYTES: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/inspectord-bpf"));

pub struct LoadedProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

impl LoadedProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let mut bpf = Ebpf::load(PROGRAM_BYTES).map_err(LoadError::Load)?;

        // Resolve current-kernel struct offsets from BTF and pass them to
        // the BPF program via the OFFSETS array map. Order matters: the
        // program is loaded but not yet attached, so it can't fire with
        // zero offsets before we populate.
        let offsets = KernelOffsets::from_sys_fs().map_err(LoadError::BtfResolve)?;
        let offsets_map = bpf.map_mut("OFFSETS").ok_or(LoadError::MissingOffsetsMap)?;
        let mut offsets_arr: Array<_, u32> =
            Array::try_from(offsets_map).map_err(|e| LoadError::MapKind(format!("{e:?}")))?;
        for (idx, value) in [
            (0u32, offsets.task_real_parent),
            (1, offsets.task_tgid),
            (2, offsets.task_mm),
            (3, offsets.mm_arg_start),
        ] {
            offsets_arr
                .set(idx, value, 0)
                .map_err(|e| LoadError::MapWrite(format!("{e:?}")))?;
        }

        let program: &mut TracePoint = bpf
            .program_mut("process_exec")
            .ok_or(LoadError::MissingProgram)?
            .try_into()
            .map_err(LoadError::Program)?;
        program.load().map_err(LoadError::Program)?;
        program
            .attach("sched", "sched_process_exec")
            .map_err(LoadError::Program)?;

        let map = bpf.take_map("EVENTS").ok_or(LoadError::MissingMap)?;
        let ring = RingBuf::try_from(map).map_err(|e| LoadError::MapKind(format!("{e:?}")))?;

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
        use libc::{poll, pollfd, POLLIN};
        let mut fds = [pollfd {
            fd: self.ring.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        }];
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { poll(fds.as_mut_ptr(), 1, timeout_ms) };
        if rc <= 0 {
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
    #[error("BPF program 'process_exec' not found in object")]
    MissingProgram,
    #[error("BPF map 'EVENTS' not found in object")]
    MissingMap,
    #[error("BPF map 'OFFSETS' not found in object")]
    MissingOffsetsMap,
    #[error("map kind mismatch: {0}")]
    MapKind(String),
    #[error("map write failed: {0}")]
    MapWrite(String),
    #[error("kernel BTF resolution failed: {0}")]
    BtfResolve(#[from] BtfError),
}
