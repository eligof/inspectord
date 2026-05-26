//! inspectord process_collector tracepoint program (Phase 2 v1).
//!
//! Writes a ProcessExecRecord (with cmdline + ppid) to the EVENTS ring buffer.

#![no_std]
#![no_main]

mod records;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel_buf, gen::bpf_probe_read_user as raw_probe_read_user,
    },
    macros::{btf_tracepoint, map},
    maps::{Array, RingBuf},
    programs::BtfTracePointContext,
};

use records::{ProcessExecRecord, ProcessExitRecord, CMDLINE_LEN, COMM_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// Per-kernel struct field offsets, populated by the userspace loader at
// startup from /sys/kernel/btf/vmlinux. Avoids the previous habit of
// silently breaking on every CONFIG-driven kernel rebuild.
//
// Index layout — must match KernelOffsets in the userspace crate:
//   0 = task_struct.real_parent
//   1 = task_struct.tgid
//   2 = task_struct.mm
//   3 = mm_struct.arg_start   (arg_end is +8 by ABI; not stored)
//   4 = task_struct.exit_code
#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(5, 0);

const OFF_TASK_REAL_PARENT: u32 = 0;
const OFF_TASK_TGID: u32 = 1;
const OFF_TASK_MM: u32 = 2;
const OFF_MM_ARG_START: u32 = 3;
const OFF_TASK_EXIT_CODE: u32 = 4;

#[btf_tracepoint]
pub fn process_exec(ctx: BtfTracePointContext) -> i32 {
    let _ = try_process_exec(ctx);
    0
}

fn try_process_exec(ctx: BtfTracePointContext) -> Result<(), i64> {
    // Bail before reserving a ring-buffer slot if the loader never populated
    // the offsets map — emitting events with garbage ppid/cmdline is worse
    // than dropping them.
    let real_parent_off = *OFFSETS.get(OFF_TASK_REAL_PARENT).ok_or(-1_i64)? as usize;
    let tgid_off = *OFFSETS.get(OFF_TASK_TGID).ok_or(-1_i64)? as usize;
    let mm_off = *OFFSETS.get(OFF_TASK_MM).ok_or(-1_i64)? as usize;
    let arg_start_off = *OFFSETS.get(OFF_MM_ARG_START).ok_or(-1_i64)? as usize;
    if real_parent_off == 0 || tgid_off == 0 || mm_off == 0 || arg_start_off == 0 {
        return Err(-1);
    }
    let arg_end_off = arg_start_off + 8;

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

        // sched_process_exec's first BTF argument is the new task_struct
        // pointer (kernel signature:
        // `void(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)`).
        // Using it directly avoids an extra bpf_get_current_task helper call
        // and is more explicit about which task we mean.
        let task: *const u8 = ctx.arg(0);
        if !task.is_null() {
            // Read real_parent pointer from task_struct.
            let mut real_parent_bytes = [0u8; 8];
            if bpf_probe_read_kernel_buf(task.add(real_parent_off), &mut real_parent_bytes).is_ok()
            {
                let real_parent = usize::from_ne_bytes(real_parent_bytes) as *const u8;
                if !real_parent.is_null() {
                    // Read tgid (u32) from real_parent task_struct.
                    let mut tgid_bytes = [0u8; 4];
                    if bpf_probe_read_kernel_buf(real_parent.add(tgid_off), &mut tgid_bytes).is_ok()
                    {
                        (*record_ptr).ppid = u32::from_ne_bytes(tgid_bytes);
                    }
                }
            }

            // Read mm pointer from task_struct.
            let mut mm_bytes = [0u8; 8];
            if bpf_probe_read_kernel_buf(task.add(mm_off), &mut mm_bytes).is_ok() {
                let mm = usize::from_ne_bytes(mm_bytes) as *const u8;
                if !mm.is_null() {
                    // Read both arg_start + arg_end so we capture all
                    // NUL-separated argv elements. bpf_probe_read_user_str_bytes
                    // would stop at the first NUL (= argv[0] only), which
                    // is useless for LOLBin patterns whose suspicious string
                    // lives in argv[2] of an outer `bash -c '...'`.
                    let mut arg_start_bytes = [0u8; 8];
                    let mut arg_end_bytes = [0u8; 8];
                    let s_ok =
                        bpf_probe_read_kernel_buf(mm.add(arg_start_off), &mut arg_start_bytes)
                            .is_ok();
                    let e_ok =
                        bpf_probe_read_kernel_buf(mm.add(arg_end_off), &mut arg_end_bytes).is_ok();
                    if s_ok && e_ok {
                        let arg_start = u64::from_ne_bytes(arg_start_bytes);
                        let arg_end = u64::from_ne_bytes(arg_end_bytes);
                        if arg_start != 0 && arg_end > arg_start {
                            // Read only `argv_len` bytes, capped at CMDLINE_LEN.
                            // Reading further would cross arg_end into envp or
                            // potentially unmapped pages, causing the helper
                            // to -EFAULT and write nothing.
                            let argv_len = (arg_end - arg_start).min(CMDLINE_LEN as u64) as u32;
                            let dst = (*record_ptr).cmdline.as_mut_ptr();
                            let ret =
                                raw_probe_read_user(dst as *mut _, argv_len, arg_start as *const _);
                            if ret >= 0 {
                                (*record_ptr).cmdline_len = argv_len as u16;
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

#[btf_tracepoint]
pub fn process_exit(ctx: BtfTracePointContext) -> i32 {
    let _ = try_process_exit(ctx);
    0
}

fn try_process_exit(ctx: BtfTracePointContext) -> Result<(), i64> {
    let exit_code_off = *OFFSETS.get(OFF_TASK_EXIT_CODE).ok_or(-1_i64)? as usize;
    if exit_code_off == 0 {
        return Err(-1);
    }

    let mut entry = EXIT_EVENTS.reserve::<ProcessExitRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();

    unsafe {
        record_ptr.write(ProcessExitRecord::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*record_ptr).pid = (pid_tgid >> 32) as u32;

        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }

        // sched_process_exit's first BTF argument is the exiting task_struct
        // pointer (kernel signature: `void(struct task_struct *p)`).
        let task: *const u8 = ctx.arg(0);
        if !task.is_null() {
            let mut exit_code_bytes = [0u8; 4];
            if bpf_probe_read_kernel_buf(task.add(exit_code_off), &mut exit_code_bytes).is_ok() {
                (*record_ptr).exit_code = i32::from_ne_bytes(exit_code_bytes);
            }
        }
    }

    entry.submit(2u64);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
