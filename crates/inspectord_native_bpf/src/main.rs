//! inspectord process_collector tracepoint program (Phase 2 v1).
//!
//! Writes a ProcessExecRecord to the EVENTS ring buffer for every hit.

#![no_std]
#![no_main]

mod records;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use records::{ProcessExecRecord, COMM_LEN};

/// Ring buffer used to ship records to userspace.
/// 256 KiB = enough headroom for bursty fork-bombs.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[tracepoint]
pub fn process_exec(_ctx: TracePointContext) -> u32 {
    let _ = try_process_exec();
    0
}

fn try_process_exec() -> Result<(), i64> {
    // BPF_RB_FORCE_WAKEUP = 2; wake userspace consumer immediately.
    const BPF_RB_FORCE_WAKEUP: u64 = 2;

    let mut entry = EVENTS.reserve::<ProcessExecRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();

    unsafe {
        record_ptr.write(ProcessExecRecord::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*record_ptr).pid = (pid_tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        (*record_ptr).uid = uid_gid as u32;
        (*record_ptr).gid = (uid_gid >> 32) as u32;

        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }
    }

    entry.submit(BPF_RB_FORCE_WAKEUP);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
