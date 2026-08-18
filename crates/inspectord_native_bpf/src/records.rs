//! On-the-wire record schemas shared between the BPF programs and the
//! userspace loader. C-compatible layout so we can transmute ring-buffer
//! byte slices on the userspace side.

#![allow(dead_code)]

pub const COMM_LEN: usize = 16;
pub const CMDLINE_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; COMM_LEN],
    pub cmdline_len: u16,
    pub _padding: [u8; 2],
    pub cmdline: [u8; CMDLINE_LEN],
}

impl ProcessExecRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0; COMM_LEN],
            cmdline_len: 0,
            _padding: [0; 2],
            cmdline: [0; CMDLINE_LEN],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    /// Kernel's task->exit_code. Encodes either an exit status (low byte
    /// 0, high byte = status >> 8) or a fatal signal (low byte = signum,
    /// high byte = core flag). Decoded on the userspace side.
    pub exit_code: i32,
    pub comm: [u8; COMM_LEN],
    pub _padding: [u8; 4],
}

impl ProcessExitRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            exit_code: 0,
            comm: [0; COMM_LEN],
            _padding: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    /// Raw ptrace request; only the validated injection-relevant set is
    /// emitted (see the PTRACE_* filter in main.rs).
    pub request: i32,
    /// ptrace's target pid arg — a TID in the caller's pid namespace.
    pub target_pid: i32,
    pub comm: [u8; COMM_LEN],
}

impl PtraceRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            request: 0,
            target_pid: 0,
            comm: [0; COMM_LEN],
        }
    }
}

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub family: u16,
    pub sport: u16,
    /// Destination port in network byte order (as the kernel stores
    /// `sock_common.skc_dport`). Decoded on the userspace side.
    pub dport_be: u16,
    pub _padding: [u8; 2],
    /// Source IPv4 in network byte order (kernel `skc_rcv_saddr`).
    pub saddr_be: u32,
    /// Destination IPv4 in network byte order (kernel `skc_daddr`).
    pub daddr_be: u32,
}

impl ConnectRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            comm: [0; COMM_LEN],
            family: 0,
            sport: 0,
            dport_be: 0,
            _padding: [0; 2],
            saddr_be: 0,
            daddr_be: 0,
        }
    }
}

/// IPv6 sibling of `ConnectRecord`: 16-byte `in6_addr` source/destination
/// in place of the 4-byte IPv4 addresses. Same leading fields so the
/// userspace decode stays a straight mirror.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectRecord6 {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub family: u16,
    pub sport: u16,
    /// Destination port in network byte order (kernel `skc_dport`).
    pub dport_be: u16,
    pub _padding: [u8; 2],
    /// Source IPv6 in network byte order (kernel `skc_v6_rcv_saddr`).
    pub saddr: [u8; 16],
    /// Destination IPv6 in network byte order (kernel `skc_v6_daddr`).
    pub daddr: [u8; 16],
}

impl ConnectRecord6 {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            comm: [0; COMM_LEN],
            family: 0,
            sport: 0,
            dport_be: 0,
            _padding: [0; 2],
            saddr: [0; 16],
            daddr: [0; 16],
        }
    }
}
