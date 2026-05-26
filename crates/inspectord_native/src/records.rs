//! Mirror of crates/inspectord_native_bpf/src/records.rs.
//!
//! Userspace reads ring-buffer bytes through this struct via memcpy.
//! Layout MUST match the BPF crate's record exactly.

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
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());
        let mut out = Self {
            timestamp_ns: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0; COMM_LEN],
            cmdline_len: 0,
            _padding: [0; 2],
            cmdline: [0; CMDLINE_LEN],
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

    pub fn cmdline_str(&self) -> String {
        let n = (self.cmdline_len as usize).min(CMDLINE_LEN);
        // argv elements are NUL-separated; replace NULs with spaces for display.
        let bytes: Vec<u8> = self.cmdline[..n]
            .iter()
            .map(|&b| if b == 0 { b' ' } else { b })
            .collect();
        String::from_utf8_lossy(&bytes).trim().to_string()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    /// task->exit_code: low byte is the signal that killed (0 if normal),
    /// the second byte is the wait-style exit status (`status >> 8`).
    pub exit_code: i32,
    pub comm: [u8; COMM_LEN],
    pub _padding: [u8; 4],
}

impl ProcessExitRecord {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());
        let mut out = Self {
            timestamp_ns: 0,
            pid: 0,
            exit_code: 0,
            comm: [0; COMM_LEN],
            _padding: [0; 4],
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

    /// Exit status from a normal exit (None if the task was killed by a
    /// signal).
    pub fn exit_status(&self) -> Option<i32> {
        let signal = self.exit_code & 0x7f;
        if signal == 0 {
            Some((self.exit_code >> 8) & 0xff)
        } else {
            None
        }
    }

    /// Signal number that killed the task, if any.
    pub fn killed_by_signal(&self) -> Option<i32> {
        let signal = self.exit_code & 0x7f;
        if signal != 0 {
            Some(signal)
        } else {
            None
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
    pub dport_be: u16,
    pub _padding: [u8; 2],
    pub saddr_be: u32,
    pub daddr_be: u32,
}

impl ConnectRecord {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());
        let mut out = Self {
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

    /// IPv4 source address as dotted-quad. Returns "" for non-AF_INET.
    pub fn saddr_str(&self) -> String {
        ipv4_dotted(self.saddr_be)
    }

    /// IPv4 destination address as dotted-quad. Returns "" for non-AF_INET.
    pub fn daddr_str(&self) -> String {
        ipv4_dotted(self.daddr_be)
    }

    pub fn dport(&self) -> u16 {
        u16::from_be(self.dport_be)
    }

    /// True for IPv4 loopback (127.0.0.0/8) on either endpoint.
    pub fn is_loopback(&self) -> bool {
        is_ipv4_loopback(self.saddr_be) || is_ipv4_loopback(self.daddr_be)
    }
}

fn ipv4_dotted(addr_be: u32) -> String {
    let bytes = addr_be.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn is_ipv4_loopback(addr_be: u32) -> bool {
    // First byte of the network-order address is the high octet (127.x.x.x).
    addr_be.to_ne_bytes()[0] == 127
}
