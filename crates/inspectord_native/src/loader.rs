//! Loads the embedded BPF object into the kernel and attaches the
//! `process_exec` tracepoint program. Dropping the LoadedProgram
//! unloads everything from the kernel.

use aya::{programs::TracePoint, Ebpf};
use std::sync::Mutex;

/// BPF object emitted by the build script. Embedded at compile time so
/// the wheel ships with the program pre-compiled.
const PROGRAM_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/inspectord-bpf"));

pub struct LoadedProgram {
    _inner: Mutex<Ebpf>,
}

impl LoadedProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let mut bpf = Ebpf::load(PROGRAM_BYTES).map_err(LoadError::Load)?;
        let program: &mut TracePoint = bpf
            .program_mut("process_exec")
            .ok_or(LoadError::MissingProgram)?
            .try_into()
            .map_err(LoadError::Program)?;
        program.load().map_err(LoadError::Program)?;
        program
            .attach("sched", "sched_process_exec")
            .map_err(LoadError::Program)?;
        Ok(Self {
            _inner: Mutex::new(bpf),
        })
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
}
