//! inspectord process_collector tracepoint program (Phase 2 v1).
//!
//! Writes a ProcessExecRecord (with cmdline + ppid) to the EVENTS ring buffer.

#![no_std]
#![no_main]

mod records;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel_buf,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use records::{ProcessExecRecord, CMDLINE_LEN, COMM_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// Hard-coded task_struct offsets for CachyOS kernel 7.0.10-1-cachyos-bore (x86_64).
// A follow-up Phase 2 slice will replace these with CO-RE BTF relocations.
// To re-derive on a different kernel:
//   pahole -C task_struct /sys/kernel/btf/vmlinux | grep -E 'real_parent|tgid|mm;'
//   pahole -C mm_struct  /sys/kernel/btf/vmlinux | grep arg_start
const TASK_REAL_PARENT_OFFSET: usize = 2880;
const TASK_TGID_OFFSET: usize = 2868;
const TASK_MM_OFFSET: usize = 2744;
const MM_ARG_START_OFFSET: usize = 696;

#[tracepoint]
pub fn process_exec(_ctx: TracePointContext) -> u32 {
    let _ = try_process_exec();
    0
}

fn try_process_exec() -> Result<(), i64> {
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

        let task = bpf_get_current_task() as *const u8;
        if !task.is_null() {
            // Read real_parent pointer from task_struct.
            let mut real_parent_bytes = [0u8; 8];
            if bpf_probe_read_kernel_buf(task.add(TASK_REAL_PARENT_OFFSET), &mut real_parent_bytes)
                .is_ok()
            {
                let real_parent = usize::from_ne_bytes(real_parent_bytes) as *const u8;
                if !real_parent.is_null() {
                    // Read tgid (u32) from real_parent task_struct.
                    let mut tgid_bytes = [0u8; 4];
                    if bpf_probe_read_kernel_buf(real_parent.add(TASK_TGID_OFFSET), &mut tgid_bytes)
                        .is_ok()
                    {
                        (*record_ptr).ppid = u32::from_ne_bytes(tgid_bytes);
                    }
                }
            }

            // Read mm pointer from task_struct.
            let mut mm_bytes = [0u8; 8];
            if bpf_probe_read_kernel_buf(task.add(TASK_MM_OFFSET), &mut mm_bytes).is_ok() {
                let mm = usize::from_ne_bytes(mm_bytes) as *const u8;
                if !mm.is_null() {
                    // Read arg_start (u64) from mm_struct.
                    let mut arg_start_bytes = [0u8; 8];
                    if bpf_probe_read_kernel_buf(mm.add(MM_ARG_START_OFFSET), &mut arg_start_bytes)
                        .is_ok()
                    {
                        let arg_start = u64::from_ne_bytes(arg_start_bytes);
                        if arg_start != 0 {
                            let dst = &mut (*record_ptr).cmdline;
                            if let Ok(bytes) =
                                bpf_probe_read_user_str_bytes(arg_start as *const u8, dst)
                            {
                                (*record_ptr).cmdline_len =
                                    (bytes.len() as u16).min(CMDLINE_LEN as u16);
                            }
                        }
                    }
                }
            }
        }
    }

    entry.submit(2u64); // BPF_RB_FORCE_WAKEUP
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
