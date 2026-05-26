//! Minimal BTF (BPF Type Format) parser for resolving kernel struct field
//! offsets at runtime, eliminating hardcoded values that drift across
//! CONFIG-driven kernel rebuilds.
//!
//! Only supports the operations we need: finding a `struct N` by name and
//! returning the byte offset of a named field, including fields nested
//! inside anonymous member structs/unions (e.g. `mm_struct.arg_start`,
//! which sits inside an unnamed wrapper in modern kernels).
//!
//! Reference: <https://www.kernel.org/doc/html/latest/bpf/btf.html>

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// Byte offsets of the `task_struct` and `mm_struct` fields the BPF program
/// reads to extract ppid, the argv buffer, and exit_code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelOffsets {
    pub task_real_parent: u32,
    pub task_tgid: u32,
    pub task_mm: u32,
    pub mm_arg_start: u32,
    pub task_exit_code: u32,
}

impl KernelOffsets {
    /// Resolve every offset from `/sys/kernel/btf/vmlinux`.
    pub fn from_sys_fs() -> Result<Self, BtfError> {
        Self::from_path("/sys/kernel/btf/vmlinux")
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, BtfError> {
        let data = fs::read(path).map_err(BtfError::Io)?;
        Self::from_bytes(&data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, BtfError> {
        let btf = Btf::parse(data)?;
        Ok(Self {
            task_real_parent: btf.field_offset("task_struct", "real_parent")?,
            task_tgid: btf.field_offset("task_struct", "tgid")?,
            task_mm: btf.field_offset("task_struct", "mm")?,
            mm_arg_start: btf.field_offset("mm_struct", "arg_start")?,
            task_exit_code: btf.field_offset("task_struct", "exit_code")?,
        })
    }
}

const BTF_MAGIC_LE: u16 = 0xEB9F;
const BTF_MAGIC_BE: u16 = 0x9FEB;

const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_ENUM64: u32 = 19;

/// Compact metadata for a single BTF type, indexed by type_id.
/// type_id 0 is the implicit "void" entry.
#[derive(Clone)]
struct TypeMeta {
    kind: u32,
    name_off: u32,
    vlen: usize,
    kind_flag: bool,
    /// For STRUCT/UNION: byte range within `types` covering the member array
    /// (vlen * 12 bytes). For other kinds: (0, 0) sentinel.
    members_range: (usize, usize),
}

struct Btf<'a> {
    types: &'a [u8],
    strings: &'a [u8],
    metas: Vec<TypeMeta>,
}

impl<'a> Btf<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, BtfError> {
        if data.len() < 24 {
            return Err(BtfError::Truncated);
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC_LE && magic != BTF_MAGIC_BE {
            return Err(BtfError::InvalidMagic);
        }
        if magic == BTF_MAGIC_BE {
            return Err(BtfError::BigEndianUnsupported);
        }
        let version = data[2];
        if version != 1 {
            return Err(BtfError::UnsupportedVersion(version));
        }
        let hdr_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let type_off = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let type_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        let str_off = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        let str_len = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;

        let types_start = hdr_len.checked_add(type_off).ok_or(BtfError::Truncated)?;
        let types_end = types_start
            .checked_add(type_len)
            .ok_or(BtfError::Truncated)?;
        let strs_start = hdr_len.checked_add(str_off).ok_or(BtfError::Truncated)?;
        let strs_end = strs_start.checked_add(str_len).ok_or(BtfError::Truncated)?;
        if types_end > data.len() || strs_end > data.len() {
            return Err(BtfError::Truncated);
        }

        let types = &data[types_start..types_end];
        let strings = &data[strs_start..strs_end];

        // First pass: build the type-id table so we can resolve nested
        // anonymous struct/union members later.
        let mut metas = vec![TypeMeta {
            kind: 0,
            name_off: 0,
            vlen: 0,
            kind_flag: false,
            members_range: (0, 0),
        }];
        let mut cursor = 0usize;
        while cursor + 12 <= types.len() {
            let name_off = u32::from_le_bytes(types[cursor..cursor + 4].try_into().unwrap());
            let info = u32::from_le_bytes(types[cursor + 4..cursor + 8].try_into().unwrap());
            let _size_or_type =
                u32::from_le_bytes(types[cursor + 8..cursor + 12].try_into().unwrap());
            cursor += 12;

            let kind = (info >> 24) & 0x1F;
            let vlen = (info & 0xFFFF) as usize;
            let kind_flag = info >> 31 == 1;
            let extra = kind_payload_size(kind, vlen)?;
            let payload_start = cursor;
            let payload_end = cursor.checked_add(extra).ok_or(BtfError::Truncated)?;
            if payload_end > types.len() {
                return Err(BtfError::Truncated);
            }

            let members_range = if kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION {
                (payload_start, payload_end)
            } else {
                (0, 0)
            };

            metas.push(TypeMeta {
                kind,
                name_off,
                vlen,
                kind_flag,
                members_range,
            });
            cursor = payload_end;
        }

        Ok(Self {
            types,
            strings,
            metas,
        })
    }

    fn string_at(&self, offset: u32) -> Result<&str, BtfError> {
        let offset = offset as usize;
        if offset >= self.strings.len() {
            return Err(BtfError::Truncated);
        }
        let end = self.strings[offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(BtfError::Truncated)?;
        std::str::from_utf8(&self.strings[offset..offset + end]).map_err(|_| BtfError::Truncated)
    }

    /// Find the byte offset of `field_name` in `struct struct_name`.
    /// Recurses through anonymous (name="") nested struct/union members so
    /// that fields placed inside unnamed wrappers — common in modern
    /// `mm_struct` and `task_struct` — are still locatable.
    fn field_offset(&self, struct_name: &str, field_name: &str) -> Result<u32, BtfError> {
        for (type_id, meta) in self.metas.iter().enumerate().skip(1) {
            if meta.kind == BTF_KIND_STRUCT && self.string_at(meta.name_off)? == struct_name {
                if let Some(off) = self.walk_members(type_id as u32, 0, field_name)? {
                    return Ok(off);
                }
                return Err(BtfError::FieldNotFound {
                    struct_name: struct_name.to_string(),
                    field_name: field_name.to_string(),
                });
            }
        }
        Err(BtfError::StructNotFound(struct_name.to_string()))
    }

    fn walk_members(
        &self,
        type_id: u32,
        base_byte_offset: u32,
        field_name: &str,
    ) -> Result<Option<u32>, BtfError> {
        let meta = self
            .metas
            .get(type_id as usize)
            .ok_or(BtfError::Truncated)?;
        if meta.kind != BTF_KIND_STRUCT && meta.kind != BTF_KIND_UNION {
            return Ok(None);
        }
        let (start, end) = meta.members_range;
        let bytes = &self.types[start..end];

        for i in 0..meta.vlen {
            let base = i * 12;
            let name_off = u32::from_le_bytes(bytes[base..base + 4].try_into().unwrap());
            let member_type_id = u32::from_le_bytes(bytes[base + 4..base + 8].try_into().unwrap());
            let raw_offset = u32::from_le_bytes(bytes[base + 8..base + 12].try_into().unwrap());

            let bit_offset = if meta.kind_flag {
                raw_offset & 0x00FF_FFFF
            } else {
                raw_offset
            };
            let bitfield_size = if meta.kind_flag { raw_offset >> 24 } else { 0 };

            let name = self.string_at(name_off)?;
            if name == field_name {
                if bitfield_size != 0 || bit_offset % 8 != 0 {
                    return Err(BtfError::BitfieldUnsupported);
                }
                let byte_offset = base_byte_offset
                    .checked_add(bit_offset / 8)
                    .ok_or(BtfError::Truncated)?;
                return Ok(Some(byte_offset));
            }

            // Recurse into anonymous struct/union members so we can find
            // fields like mm_struct.arg_start that live inside an unnamed
            // wrapper struct. Skip bitfield-style anonymous slots — wrappers
            // are always byte-aligned in practice.
            if name.is_empty() && bit_offset % 8 == 0 {
                let nested_base = base_byte_offset
                    .checked_add(bit_offset / 8)
                    .ok_or(BtfError::Truncated)?;
                if let Some(off) = self.walk_members(member_type_id, nested_base, field_name)? {
                    return Ok(Some(off));
                }
            }
        }
        Ok(None)
    }
}

fn kind_payload_size(kind: u32, vlen: usize) -> Result<usize, BtfError> {
    Ok(match kind {
        0 => 0,                          // VOID
        BTF_KIND_INT => 4,               // INT: extra u32
        2 => 0,                          // PTR
        BTF_KIND_ARRAY => 12,            // ARRAY: { type, index_type, nelems }
        BTF_KIND_STRUCT => vlen * 12,    // STRUCT: vlen 12-byte members
        BTF_KIND_UNION => vlen * 12,     // UNION: same shape
        BTF_KIND_ENUM => vlen * 8,       // ENUM: vlen 8-byte entries
        7 => 0,                          // FWD
        8 => 0,                          // TYPEDEF
        9 => 0,                          // VOLATILE
        10 => 0,                         // CONST
        11 => 0,                         // RESTRICT
        12 => 0,                         // FUNC
        BTF_KIND_FUNC_PROTO => vlen * 8, // FUNC_PROTO: vlen 8-byte params
        BTF_KIND_VAR => 4,               // VAR: extra u32 (linkage)
        BTF_KIND_DATASEC => vlen * 12,   // DATASEC: vlen 12-byte entries
        16 => 0,                         // FLOAT
        BTF_KIND_DECL_TAG => 4,          // DECL_TAG: extra u32
        18 => 0,                         // TYPE_TAG
        BTF_KIND_ENUM64 => vlen * 12,    // ENUM64: 12-byte entries
        other => return Err(BtfError::UnknownKind(other)),
    })
}

#[derive(Debug)]
pub enum BtfError {
    Io(io::Error),
    InvalidMagic,
    BigEndianUnsupported,
    UnsupportedVersion(u8),
    Truncated,
    UnknownKind(u32),
    StructNotFound(String),
    FieldNotFound {
        struct_name: String,
        field_name: String,
    },
    BitfieldUnsupported,
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BtfError::Io(e) => write!(f, "BTF I/O error: {e}"),
            BtfError::InvalidMagic => write!(f, "not a BTF blob (bad magic)"),
            BtfError::BigEndianUnsupported => write!(f, "big-endian BTF not supported"),
            BtfError::UnsupportedVersion(v) => write!(f, "unsupported BTF version: {v}"),
            BtfError::Truncated => write!(f, "BTF blob is truncated or malformed"),
            BtfError::UnknownKind(k) => write!(f, "BTF type kind {k} not handled"),
            BtfError::StructNotFound(n) => write!(f, "struct '{n}' not found in BTF"),
            BtfError::FieldNotFound {
                struct_name,
                field_name,
            } => write!(
                f,
                "field '{field_name}' not found in struct '{struct_name}'"
            ),
            BtfError::BitfieldUnsupported => write!(f, "bitfield member not supported"),
        }
    }
}

impl std::error::Error for BtfError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny BTF blob builder so the parser tests don't require the kernel.
    struct BtfBuilder {
        strings: Vec<u8>,
        types: Vec<u8>,
    }

    impl BtfBuilder {
        fn new() -> Self {
            Self {
                strings: vec![0],
                types: Vec::new(),
            }
        }

        fn intern(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        /// Append an INT type "u32" so member type_ids resolve to something.
        fn add_u32_int(&mut self) {
            let n = self.intern("u32");
            self.types.extend_from_slice(&n.to_le_bytes());
            let info = BTF_KIND_INT << 24;
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&4u32.to_le_bytes());
            self.types.extend_from_slice(&0u32.to_le_bytes());
        }

        /// Append a STRUCT type with the given members (name, type_id, bit_offset).
        fn add_struct(&mut self, name: &str, total_size: u32, members: &[(&str, u32, u32)]) {
            let n = self.intern(name);
            self.types.extend_from_slice(&n.to_le_bytes());
            let info = (BTF_KIND_STRUCT << 24) | (members.len() as u32 & 0xFFFF);
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&total_size.to_le_bytes());
            for (mname, type_id, bit_off) in members {
                let mn = self.intern(mname);
                self.types.extend_from_slice(&mn.to_le_bytes());
                self.types.extend_from_slice(&type_id.to_le_bytes());
                self.types.extend_from_slice(&bit_off.to_le_bytes());
            }
        }

        fn finish(self) -> Vec<u8> {
            let mut header = Vec::with_capacity(24);
            header.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes());
            header.push(1); // version
            header.push(0); // flags
            header.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
            header.extend_from_slice(&0u32.to_le_bytes()); // type_off
            header.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // type_len
            header.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            header.extend_from_slice(&(self.strings.len() as u32).to_le_bytes()); // str_len
            let mut blob = header;
            blob.extend_from_slice(&self.types);
            blob.extend_from_slice(&self.strings);
            blob
        }
    }

    #[test]
    fn finds_top_level_field() {
        let mut b = BtfBuilder::new();
        b.add_u32_int(); // type_id 1
        b.add_struct("dummy", 8, &[("first", 1, 0), ("second", 1, 32)]);
        let blob = b.finish();
        let btf = Btf::parse(&blob).unwrap();
        assert_eq!(btf.field_offset("dummy", "first").unwrap(), 0);
        assert_eq!(btf.field_offset("dummy", "second").unwrap(), 4);
    }

    #[test]
    fn recurses_into_anonymous_nested_struct() {
        // outer { _: inner { value @ bit 32 } @ bit 64 }
        // Expected byte offset for "value" = (64 + 32) / 8 = 12.
        let mut b = BtfBuilder::new();
        b.add_u32_int(); // type_id 1
                         // type_id 2: inner struct with one named member "value" at bit 32
        b.add_struct("inner", 8, &[("value", 1, 32)]);
        // type_id 3: outer struct with one anonymous member of type_id 2 at bit 64
        b.add_struct("outer", 16, &[("", 2, 64)]);
        let blob = b.finish();
        let btf = Btf::parse(&blob).unwrap();
        assert_eq!(btf.field_offset("outer", "value").unwrap(), 12);
    }

    #[test]
    fn returns_struct_not_found() {
        let mut b = BtfBuilder::new();
        b.add_u32_int();
        b.add_struct("dummy", 4, &[("first", 1, 0)]);
        let blob = b.finish();
        let btf = Btf::parse(&blob).unwrap();
        assert!(matches!(
            btf.field_offset("nope", "first"),
            Err(BtfError::StructNotFound(s)) if s == "nope"
        ));
    }

    #[test]
    fn returns_field_not_found() {
        let mut b = BtfBuilder::new();
        b.add_u32_int();
        b.add_struct("dummy", 4, &[("first", 1, 0)]);
        let blob = b.finish();
        let btf = Btf::parse(&blob).unwrap();
        assert!(matches!(
            btf.field_offset("dummy", "missing"),
            Err(BtfError::FieldNotFound { .. })
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = BtfBuilder::new();
        b.add_u32_int();
        b.add_struct("dummy", 4, &[("first", 1, 0)]);
        let mut blob = b.finish();
        blob[0] = 0;
        blob[1] = 0;
        assert!(matches!(Btf::parse(&blob), Err(BtfError::InvalidMagic)));
    }

    /// Integration check against the running kernel's BTF, when available.
    /// Skipped in environments without /sys/kernel/btf/vmlinux (CI containers).
    #[test]
    fn reads_real_kernel_offsets_when_available() {
        if !Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let offsets = KernelOffsets::from_sys_fs().expect("read kernel BTF");
        eprintln!("kernel offsets: {offsets:?}");
        for v in [
            offsets.task_real_parent,
            offsets.task_tgid,
            offsets.task_mm,
            offsets.mm_arg_start,
            offsets.task_exit_code,
        ] {
            assert!(v > 0, "offset is zero: {offsets:?}");
            assert!(v < 65_536, "offset suspiciously large: {offsets:?}");
        }
    }
}
