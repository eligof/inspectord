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
    macros::{btf_tracepoint, map, tracepoint},
    maps::{Array, RingBuf},
    programs::{BtfTracePointContext, TracePointContext},
};

use records::{
    ConnectRecord, ConnectRecord6, ProcessExecRecord, ProcessExitRecord, PtraceRecord, CMDLINE_LEN,
    COMM_LEN,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[map]
static CONNECT6_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(65_536, 0);

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
//   5 = sock_common.skc_family
//   6 = sock_common.skc_dport
//   7 = sock_common.skc_num
//   8 = sock_common.skc_daddr     (typically 0)
//   9 = sock_common.skc_rcv_saddr
//  10 = sock_common.skc_v6_daddr
//  11 = sock_common.skc_v6_rcv_saddr
#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(12, 0);

const OFF_TASK_REAL_PARENT: u32 = 0;
const OFF_TASK_TGID: u32 = 1;
const OFF_TASK_MM: u32 = 2;
const OFF_MM_ARG_START: u32 = 3;
const OFF_TASK_EXIT_CODE: u32 = 4;
const OFF_SOCK_FAMILY: u32 = 5;
const OFF_SOCK_DPORT: u32 = 6;
const OFF_SOCK_NUM: u32 = 7;
const OFF_SOCK_DADDR: u32 = 8;
const OFF_SOCK_RCV_SADDR: u32 = 9;
const OFF_SOCK_V6_DADDR: u32 = 10;
const OFF_SOCK_V6_RCV_SADDR: u32 = 11;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;

// Injection-relevant ptrace requests (x86_64). Read/step/cont/PEEK are
// intentionally excluded — they are the debugger firehose, not injection.
const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_POKEUSR: u64 = 6;
const PTRACE_SETREGS: u64 = 13;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SETREGSET: u64 = 0x4205;
const PTRACE_SEIZE: u64 = 0x4206;

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

#[btf_tracepoint]
pub fn outbound_connection(ctx: BtfTracePointContext) -> i32 {
    let _ = try_outbound_connection(ctx);
    0
}

fn try_outbound_connection(ctx: BtfTracePointContext) -> Result<(), i64> {
    // inet_sock_set_state(const struct sock *sk, int oldstate, int newstate)
    let oldstate: i32 = unsafe { ctx.arg(1) };
    let newstate: i32 = unsafe { ctx.arg(2) };
    if oldstate != TCP_SYN_SENT || newstate != TCP_ESTABLISHED {
        return Err(0);
    }

    let sk: *const u8 = unsafe { ctx.arg(0) };
    if sk.is_null() {
        return Err(-1);
    }

    let family_off = *OFFSETS.get(OFF_SOCK_FAMILY).ok_or(-1_i64)? as usize;
    let dport_off = *OFFSETS.get(OFF_SOCK_DPORT).ok_or(-1_i64)? as usize;
    let num_off = *OFFSETS.get(OFF_SOCK_NUM).ok_or(-1_i64)? as usize;
    let daddr_off = *OFFSETS.get(OFF_SOCK_DADDR).ok_or(-1_i64)? as usize;
    let rcv_saddr_off = *OFFSETS.get(OFF_SOCK_RCV_SADDR).ok_or(-1_i64)? as usize;
    // family is the only offset that can never legitimately be zero in
    // sock_common; treat zero as "loader didn't populate".
    if family_off == 0 {
        return Err(-1);
    }

    let mut family_bytes = [0u8; 2];
    if unsafe { bpf_probe_read_kernel_buf(sk.add(family_off), &mut family_bytes) }.is_err() {
        return Err(-1);
    }
    let family = u16::from_ne_bytes(family_bytes);
    if family != AF_INET {
        return Err(0);
    }

    let mut entry = CONNECT_EVENTS.reserve::<ConnectRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();

    unsafe {
        record_ptr.write(ConnectRecord::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*record_ptr).pid = (pid_tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        (*record_ptr).uid = uid_gid as u32;
        (*record_ptr).family = family;

        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }

        let mut dport_bytes = [0u8; 2];
        if bpf_probe_read_kernel_buf(sk.add(dport_off), &mut dport_bytes).is_ok() {
            (*record_ptr).dport_be = u16::from_ne_bytes(dport_bytes);
        }
        let mut num_bytes = [0u8; 2];
        if bpf_probe_read_kernel_buf(sk.add(num_off), &mut num_bytes).is_ok() {
            (*record_ptr).sport = u16::from_ne_bytes(num_bytes);
        }
        let mut daddr_bytes = [0u8; 4];
        if bpf_probe_read_kernel_buf(sk.add(daddr_off), &mut daddr_bytes).is_ok() {
            (*record_ptr).daddr_be = u32::from_ne_bytes(daddr_bytes);
        }
        let mut saddr_bytes = [0u8; 4];
        if bpf_probe_read_kernel_buf(sk.add(rcv_saddr_off), &mut saddr_bytes).is_ok() {
            (*record_ptr).saddr_be = u32::from_ne_bytes(saddr_bytes);
        }
    }

    entry.submit(2u64);
    Ok(())
}

#[btf_tracepoint]
pub fn outbound_connection6(ctx: BtfTracePointContext) -> i32 {
    let _ = try_outbound_connection6(ctx);
    0
}

fn try_outbound_connection6(ctx: BtfTracePointContext) -> Result<(), i64> {
    // Same tracepoint as the IPv4 path. Both programs fire on every
    // inet_sock_set_state; each keeps only its own address family so the
    // verifier sees two simple programs instead of one branchy one.
    let oldstate: i32 = unsafe { ctx.arg(1) };
    let newstate: i32 = unsafe { ctx.arg(2) };
    if oldstate != TCP_SYN_SENT || newstate != TCP_ESTABLISHED {
        return Err(0);
    }

    let sk: *const u8 = unsafe { ctx.arg(0) };
    if sk.is_null() {
        return Err(-1);
    }

    let family_off = *OFFSETS.get(OFF_SOCK_FAMILY).ok_or(-1_i64)? as usize;
    let dport_off = *OFFSETS.get(OFF_SOCK_DPORT).ok_or(-1_i64)? as usize;
    let num_off = *OFFSETS.get(OFF_SOCK_NUM).ok_or(-1_i64)? as usize;
    let v6_daddr_off = *OFFSETS.get(OFF_SOCK_V6_DADDR).ok_or(-1_i64)? as usize;
    let v6_saddr_off = *OFFSETS.get(OFF_SOCK_V6_RCV_SADDR).ok_or(-1_i64)? as usize;
    // family and the v6 address fields all live past offset 0 in sock_common,
    // so zero means the loader never populated the map.
    if family_off == 0 || v6_daddr_off == 0 || v6_saddr_off == 0 {
        return Err(-1);
    }

    let mut family_bytes = [0u8; 2];
    if unsafe { bpf_probe_read_kernel_buf(sk.add(family_off), &mut family_bytes) }.is_err() {
        return Err(-1);
    }
    let family = u16::from_ne_bytes(family_bytes);
    if family != AF_INET6 {
        return Err(0);
    }

    let mut entry = CONNECT6_EVENTS.reserve::<ConnectRecord6>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();

    unsafe {
        record_ptr.write(ConnectRecord6::zeroed());
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*record_ptr).pid = (pid_tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        (*record_ptr).uid = uid_gid as u32;
        (*record_ptr).family = family;

        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }

        let mut dport_bytes = [0u8; 2];
        if bpf_probe_read_kernel_buf(sk.add(dport_off), &mut dport_bytes).is_ok() {
            (*record_ptr).dport_be = u16::from_ne_bytes(dport_bytes);
        }
        let mut num_bytes = [0u8; 2];
        if bpf_probe_read_kernel_buf(sk.add(num_off), &mut num_bytes).is_ok() {
            (*record_ptr).sport = u16::from_ne_bytes(num_bytes);
        }
        let _ = bpf_probe_read_kernel_buf(sk.add(v6_saddr_off), &mut (*record_ptr).saddr);
        let _ = bpf_probe_read_kernel_buf(sk.add(v6_daddr_off), &mut (*record_ptr).daddr);
    }

    entry.submit(2u64);
    Ok(())
}

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

    // Compare the FULL u64 so a value with garbage high bits can never alias
    // a real request (e.g. 0x1_0000_0010 must not look like PTRACE_ATTACH).
    // Filter on request first — the excluded read/step/cont requests are the
    // overwhelming majority, so we skip the second probe-read on that hot path.
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
    let target_pid: u64 = unsafe { ctx.read_at(24).map_err(|_| -1_i64)? };

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
