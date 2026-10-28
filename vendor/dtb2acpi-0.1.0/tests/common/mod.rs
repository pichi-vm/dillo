// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test-side ACPI verifier.
//!
//! A small re-decoder that walks emitted bytes and exposes the
//! cross-table chain (RSDP → XSDT → tables; FADT → DSDT) as Rust
//! structs. Independent of `dtb2acpi`'s emit code path so a bug on
//! one side can't mask a bug on the other.

#![allow(dead_code)]

use std::collections::BTreeMap;

use dtb2acpi::{AcpiBuffer, OemIdentity};

/// Test-side helper: treat the buffer's own host address as a GPA.
/// Sound for in-process tests where the buffer's allocation is what
/// the verifier will read; not meaningful in any other context.
pub(crate) fn buf_gpa<const N: usize>(buf: &AcpiBuffer<N>) -> u64 {
    buf.as_ref().as_ptr().addr() as u64
}

/// Default OEM identity used across the test suite. The crate itself
/// ships no defaults — each test passes this constant to `extract`.
pub(crate) const TEST_OEM: OemIdentity = OemIdentity {
    oem_id: *b"TEST00",
    oem_table_id: *b"TESTTBL0",
    oem_revision: 1,
    creator_id: *b"TEST",
    creator_revision: 1,
};

/// A re-decoded ACPI layout — what the verifier sees after walking
/// the bytes `AcpiBuffer::populate` produced.
#[derive(Debug)]
pub(crate) struct Decoded {
    pub rsdp: Rsdp,
    pub xsdt: Xsdt,
    /// Tables indexed by their 4-byte signature, populated by following
    /// every XSDT entry.
    pub tables: BTreeMap<[u8; 4], TableHeader>,
    /// FADT-specific fields we care about for the cross-check.
    pub fadt: Fadt,
    /// DSDT-specific fields we care about.
    pub dsdt: Dsdt,
    /// All MADT entries, in order, with their (type, length) and
    /// the raw entry bytes.
    pub madt_entries: Vec<(u8, u8, Vec<u8>)>,
    /// MCFG allocations (base, segment, bus_start, bus_end), if MCFG present.
    pub mcfg_allocations: Vec<(u64, u16, u8, u8)>,
    /// SRAT entries (type, raw body), if SRAT present.
    pub srat_entries: Vec<(u8, Vec<u8>)>,
    /// SLIT raw matrix bytes (n*n), if SLIT present. Number of
    /// localities is implied by `sqrt(matrix.len())`.
    pub slit_matrix: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub revision: u8,
    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
}

#[derive(Debug)]
pub(crate) struct Xsdt {
    pub header: TableHeader,
    pub entries: Vec<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct TableHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    /// Byte offset within the layout buffer where the header begins.
    pub offset_in_buf: usize,
}

#[derive(Debug)]
pub(crate) struct Fadt {
    pub flags: u32,
    pub iapc_boot_arch: u16,
    /// Legacy 32-bit DSDT pointer at FADT offset 40..44. Must be zero
    /// whenever the DSDT lives above 4 GiB (the 64-bit `x_dsdt` is
    /// then the only authoritative pointer).
    pub dsdt_legacy: u32,
    pub x_dsdt: u64,
    pub sleep_control_addr: u64,
    pub sleep_status_addr: u64,
    pub reset_addr: u64,
    pub reset_value: u8,
    pub fadt_minor_version: u8,
}

#[derive(Debug)]
pub(crate) struct Dsdt {
    pub header: TableHeader,
}

const HW_REDUCED_ACPI: u32 = 1 << 20;

impl Decoded {
    pub(crate) fn hw_reduced(&self) -> bool {
        self.fadt.flags & HW_REDUCED_ACPI != 0
    }
}

/// Walk `buf` as emitted ACPI bytes. The buffer's starting address
/// is taken as the layout's base GPA — tests pass [`buf_gpa`] to
/// `populate`, so the RSDP lives at `buf.as_ptr()`.
///
/// Panics on any structural error — tests that want to inspect a
/// failure can call [`try_decode`] directly.
pub(crate) fn decode(buf: impl AsRef<[u8]>) -> Decoded {
    try_decode(buf).expect("decode")
}

/// As [`decode`] but with an explicit `base_gpa` — for tests that
/// pass a synthetic GPA (e.g. above 4 GiB) to `populate` instead of
/// the buffer's own address.
pub(crate) fn decode_at_base(buf: impl AsRef<[u8]>, base_gpa: u64) -> Decoded {
    try_decode_at_base(buf, base_gpa).expect("decode")
}

pub(crate) fn try_decode(buf: impl AsRef<[u8]>) -> Result<Decoded, String> {
    let base_gpa = buf.as_ref().as_ptr() as u64;
    try_decode_at_base(buf, base_gpa)
}

pub(crate) fn try_decode_at_base(buf: impl AsRef<[u8]>, base_gpa: u64) -> Result<Decoded, String> {
    let buf = buf.as_ref();
    let rsdp_gpa = base_gpa; // RSDP is laid out first

    let to_off = |gpa: u64| -> Result<usize, String> {
        gpa.checked_sub(base_gpa)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| format!("gpa {gpa:#x} < base {base_gpa:#x}"))
    };

    // --- RSDP ---
    let rsdp_off = to_off(rsdp_gpa)?;
    let rsdp_bytes = buf
        .get(rsdp_off..rsdp_off + 36)
        .ok_or("RSDP out of bounds")?;
    if &rsdp_bytes[..8] != b"RSD PTR " {
        return Err(format!("bad RSDP sig: {:?}", &rsdp_bytes[..8]));
    }
    let short_sum: u8 = rsdp_bytes[..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    if short_sum != 0 {
        return Err(format!("RSDP short checksum != 0: {short_sum}"));
    }
    let ext_sum: u8 = rsdp_bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    if ext_sum != 0 {
        return Err(format!("RSDP extended checksum != 0: {ext_sum}"));
    }
    let rsdp = Rsdp {
        signature: rsdp_bytes[..8].try_into().unwrap(),
        checksum: rsdp_bytes[8],
        revision: rsdp_bytes[15],
        length: u32::from_le_bytes(rsdp_bytes[20..24].try_into().unwrap()),
        xsdt_address: u64::from_le_bytes(rsdp_bytes[24..32].try_into().unwrap()),
        extended_checksum: rsdp_bytes[32],
    };
    if rsdp.revision != 2 {
        return Err(format!("RSDP revision != 2: {}", rsdp.revision));
    }

    // --- XSDT ---
    let xsdt_off = to_off(rsdp.xsdt_address)?;
    let xsdt_header = decode_sdt_header(buf, xsdt_off)?;
    if xsdt_header.signature != *b"XSDT" {
        return Err(format!("bad XSDT sig: {:?}", xsdt_header.signature));
    }
    verify_checksum(buf, xsdt_off, xsdt_header.length as usize, "XSDT")?;
    let body_start = xsdt_off + 36;
    let body_end = xsdt_off + xsdt_header.length as usize;
    if !(body_end - body_start).is_multiple_of(8) {
        return Err("XSDT body not u64-aligned".into());
    }
    let mut entries = Vec::new();
    for chunk in buf[body_start..body_end].as_chunks::<8>().0 {
        entries.push(u64::from_le_bytes(*chunk));
    }
    let xsdt = Xsdt {
        header: xsdt_header.clone(),
        entries,
    };

    // --- Follow each XSDT entry ---
    let mut tables = BTreeMap::new();
    tables.insert(*b"XSDT", xsdt_header);
    for &gpa in &xsdt.entries {
        let off = to_off(gpa)?;
        let h = decode_sdt_header(buf, off)?;
        verify_checksum(
            buf,
            off,
            h.length as usize,
            std::str::from_utf8(&h.signature).unwrap_or("???"),
        )?;
        tables.insert(h.signature, h);
    }

    // --- FADT ---
    let fadt_header = tables.get(b"FACP").ok_or("FADT (FACP) missing")?.clone();
    let fadt = decode_fadt(buf, fadt_header.offset_in_buf)?;

    // --- DSDT via FADT.X_DSDT ---
    let dsdt_off = to_off(fadt.x_dsdt)?;
    let dsdt_header = decode_sdt_header(buf, dsdt_off)?;
    if dsdt_header.signature != *b"DSDT" {
        return Err(format!("bad DSDT sig: {:?}", dsdt_header.signature));
    }
    verify_checksum(buf, dsdt_off, dsdt_header.length as usize, "DSDT")?;
    let dsdt = Dsdt {
        header: dsdt_header,
    };

    // --- MADT entries ---
    let mut madt_entries = Vec::new();
    if let Some(h) = tables.get(b"APIC") {
        let body_start = h.offset_in_buf + 44; // SDT header + 4 + 4
        let body_end = h.offset_in_buf + h.length as usize;
        let mut pos = body_start;
        while pos + 2 <= body_end {
            let typ = buf[pos];
            let len = buf[pos + 1];
            if len < 2 {
                return Err(format!("MADT entry at {pos} has length {len}"));
            }
            let end = pos + len as usize;
            if end > body_end {
                return Err("MADT entry overruns table".into());
            }
            madt_entries.push((typ, len, buf[pos..end].to_vec()));
            pos = end;
        }
    }

    // --- MCFG allocations ---
    let mut mcfg_allocations = Vec::new();
    if let Some(h) = tables.get(b"MCFG") {
        let body_start = h.offset_in_buf + 44; // SDT header + 8
        let body_end = h.offset_in_buf + h.length as usize;
        for chunk in buf[body_start..body_end].as_chunks::<16>().0 {
            let base = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            let seg = u16::from_le_bytes(chunk[8..10].try_into().unwrap());
            let bs = chunk[10];
            let be = chunk[11];
            mcfg_allocations.push((base, seg, bs, be));
        }
    }

    // --- SRAT entries ---
    let mut srat_entries = Vec::new();
    if let Some(h) = tables.get(b"SRAT") {
        let body_start = h.offset_in_buf + 48; // SDT header + 4 + 8
        let body_end = h.offset_in_buf + h.length as usize;
        let mut pos = body_start;
        while pos + 2 <= body_end {
            let typ = buf[pos];
            let len = buf[pos + 1];
            if len < 2 {
                return Err("SRAT entry length < 2".into());
            }
            let end = pos + len as usize;
            if end > body_end {
                return Err("SRAT entry overruns table".into());
            }
            srat_entries.push((typ, buf[pos + 2..end].to_vec()));
            pos = end;
        }
    }

    // --- SLIT matrix ---
    let slit_matrix = tables.get(b"SLIT").map(|h| {
        let body_start = h.offset_in_buf + 44; // SDT header + 8
        let body_end = h.offset_in_buf + h.length as usize;
        buf[body_start..body_end].to_vec()
    });

    Ok(Decoded {
        rsdp,
        xsdt,
        tables,
        fadt,
        dsdt,
        madt_entries,
        mcfg_allocations,
        srat_entries,
        slit_matrix,
    })
}

fn decode_sdt_header(buf: &[u8], off: usize) -> Result<TableHeader, String> {
    let h = buf
        .get(off..off + 36)
        .ok_or_else(|| format!("SDT header at {off:#x} out of bounds"))?;
    Ok(TableHeader {
        signature: h[..4].try_into().unwrap(),
        length: u32::from_le_bytes(h[4..8].try_into().unwrap()),
        revision: h[8],
        checksum: h[9],
        offset_in_buf: off,
    })
}

fn verify_checksum(buf: &[u8], off: usize, length: usize, name: &str) -> Result<(), String> {
    let end = off + length;
    let sum: u8 = buf[off..end].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    if sum != 0 {
        return Err(format!("{name} checksum != 0: sum={sum}"));
    }
    Ok(())
}

fn decode_fadt(buf: &[u8], off: usize) -> Result<Fadt, String> {
    let f = buf.get(off..off + 276).ok_or("FADT too small")?;
    Ok(Fadt {
        flags: u32::from_le_bytes(f[112..116].try_into().unwrap()),
        // IAPC_BOOT_ARCH is a u16 immediately before `reserved_2` at
        // FADT offset 109..111 (see ACPI 6.5 §5.2.9, Table 5.9).
        iapc_boot_arch: u16::from_le_bytes(f[109..111].try_into().unwrap()),
        dsdt_legacy: u32::from_le_bytes(f[40..44].try_into().unwrap()),
        x_dsdt: u64::from_le_bytes(f[140..148].try_into().unwrap()),
        sleep_control_addr: u64::from_le_bytes(f[244 + 4..244 + 12].try_into().unwrap()),
        sleep_status_addr: u64::from_le_bytes(f[256 + 4..256 + 12].try_into().unwrap()),
        reset_addr: u64::from_le_bytes(f[116 + 4..116 + 12].try_into().unwrap()),
        reset_value: f[128],
        fadt_minor_version: f[131],
    })
}
