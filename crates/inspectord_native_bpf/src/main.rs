//! inspectord process_collector tracepoint program (Phase 2 v1).
//!
//! No-op stub: attaches to sched_process_exec and returns 0.
//! Ring-buffer emission lands in subsequent PRs.

#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn process_exec(_ctx: TracePointContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
