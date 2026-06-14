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

/// IPv6 mirror of `ConnectRecord`. Same leading fields; the 4-byte IPv4
/// addresses are replaced by 16-byte `in6_addr` arrays stored in network
/// byte order exactly as the kernel keeps `sock_common.skc_v6_*`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectRecord6 {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub family: u16,
    pub sport: u16,
    pub dport_be: u16,
    pub _padding: [u8; 2],
    /// Source IPv6 (kernel `skc_v6_rcv_saddr`), network byte order.
    pub saddr: [u8; 16],
    /// Destination IPv6 (kernel `skc_v6_daddr`), network byte order.
    pub daddr: [u8; 16],
}

impl ConnectRecord6 {
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
            saddr: [0; 16],
            daddr: [0; 16],
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

    /// IPv6 source address in IETF-compressed form (e.g. `2001:db8::1`).
    pub fn saddr_str(&self) -> String {
        std::net::Ipv6Addr::from(self.saddr).to_string()
    }

    /// IPv6 destination address in IETF-compressed form.
    pub fn daddr_str(&self) -> String {
        std::net::Ipv6Addr::from(self.daddr).to_string()
    }

    pub fn dport(&self) -> u16 {
        u16::from_be(self.dport_be)
    }

    /// True for IPv6 loopback (`::1`) on either endpoint.
    pub fn is_loopback(&self) -> bool {
        std::net::Ipv6Addr::from(self.saddr).is_loopback()
            || std::net::Ipv6Addr::from(self.daddr).is_loopback()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample6() -> ConnectRecord6 {
        let mut comm = [0u8; COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        ConnectRecord6 {
            timestamp_ns: 123,
            pid: 4242,
            uid: 1000,
            comm,
            family: 10, // AF_INET6
            sport: 51000,
            dport_be: 443u16.to_be(),
            _padding: [0; 2],
            // 2001:db8::1
            saddr: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
            // 2606:2800:220:1:248:1893:25c8:1946
            daddr: [
                0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8,
                0x19, 0x46,
            ],
        }
    }

    #[test]
    fn formats_ipv6_addresses_in_compressed_form() {
        let r = sample6();
        assert_eq!(r.saddr_str(), "2001:db8::1");
        assert_eq!(r.daddr_str(), "2606:2800:220:1:248:1893:25c8:1946");
    }

    #[test]
    fn decodes_dport_from_network_byte_order() {
        assert_eq!(sample6().dport(), 443);
    }

    #[test]
    fn comm_str_stops_at_first_nul() {
        assert_eq!(sample6().comm_str(), "curl");
    }

    #[test]
    fn detects_ipv6_loopback_on_either_endpoint() {
        let loopback = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1
        assert!(!sample6().is_loopback());

        let mut dst_loopback = sample6();
        dst_loopback.daddr = loopback;
        assert!(dst_loopback.is_loopback());

        let mut src_loopback = sample6();
        src_loopback.saddr = loopback;
        assert!(src_loopback.is_loopback());
    }

    #[test]
    fn from_bytes_roundtrips_the_c_layout() {
        let r = sample6();
        let mut buf = vec![0u8; std::mem::size_of::<ConnectRecord6>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &r as *const ConnectRecord6 as *const u8,
                buf.as_mut_ptr(),
                buf.len(),
            );
        }
        let parsed = ConnectRecord6::from_bytes(&buf);
        assert_eq!(parsed.timestamp_ns, 123);
        assert_eq!(parsed.pid, 4242);
        assert_eq!(parsed.uid, 1000);
        assert_eq!(parsed.family, 10);
        assert_eq!(parsed.sport, 51000);
        assert_eq!(parsed.dport(), 443);
        assert_eq!(parsed.comm_str(), "curl");
        assert_eq!(parsed.saddr_str(), "2001:db8::1");
        assert_eq!(parsed.daddr_str(), "2606:2800:220:1:248:1893:25c8:1946");
    }
}
