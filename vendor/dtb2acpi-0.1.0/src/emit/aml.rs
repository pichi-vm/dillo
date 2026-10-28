// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Minimal AML emission helpers for DSDT bodies.
//!
//! Covers the subset of AML this crate actually produces:
//! - 2-byte PkgLength encoding (sufficient for every name-scope this
//!   crate generates — bodies stay well under 4 KiB)
//! - Single-segment NameStrings (e.g. `"PCI0"`, `"_HID"`)
//! - `DefName` and `DefDevice` constructors
//! - Constant data prefixes (Byte/Word/DWord)
//! - EISAID compression for `_HID` / `_CID`
//! - Resource template descriptors: `WordBusNumber`, `DWordMemory`,
//!   `EndTag`
//!
//! All emitters write into a caller-supplied `&mut [u8]` at a
//! caller-tracked offset and return the new offset (or
//! `DtbError::Internal` on slot bounds — unreachable on a
//! count-validated slot).
//!
//! ACPI references throughout are to ACPI 6.5.

use crate::error::DtbError;

// ── AML opcodes (ACPI §20.2.5) ────────────────────────────────────────
pub(crate) const NAME_OP: u8 = 0x08;
pub(crate) const BYTE_PREFIX: u8 = 0x0A;
pub(crate) const WORD_PREFIX: u8 = 0x0B;
pub(crate) const DWORD_PREFIX: u8 = 0x0C;
pub(crate) const STRING_PREFIX: u8 = 0x0D;
pub(crate) const BUFFER_OP: u8 = 0x11;
pub(crate) const PACKAGE_OP: u8 = 0x12;
pub(crate) const EXT_OP_PREFIX: u8 = 0x5B;
pub(crate) const DEVICE_OP: u8 = 0x82;

// ── Large resource descriptor tags (ACPI §6.4.3) ─────────────────────
pub(crate) const TAG_DWORD_ADDRESS_SPACE: u8 = 0x87;
pub(crate) const TAG_WORD_ADDRESS_SPACE: u8 = 0x88;
pub(crate) const TAG_EXTENDED_INTERRUPT: u8 = 0x89;
pub(crate) const TAG_QWORD_ADDRESS_SPACE: u8 = 0x8A;

// ── Small resource descriptor tags (ACPI §6.4.2) ─────────────────────
// Encoded as `(tag << 3) | length`.
// EndTag (§6.4.2.9): tag=0x0F, length=1 (the checksum byte) → 0x79.
pub(crate) const TAG_END: u8 = 0x79;

// ── Address space resource types (ACPI §6.4.3.5.x) ───────────────────
pub(crate) const RES_TYPE_MEMORY: u8 = 0;
pub(crate) const RES_TYPE_BUS_NUMBER: u8 = 2;

/// `_CRS` General Flags: Producer/Consumer | Decode | MinFixed | MaxFixed
/// MaxFixed=1, MinFixed=1, ProducerConsumer=0 (consumer), Decode=0
/// (positive). The PCI host bridge produces all four; the values come
/// from §6.4.3.5.1 Table 6.36.
pub(crate) const GENFLAGS_FIXED_RANGE: u8 = 0b0000_1100;

/// Memory-range Type-Specific Flags: ReadWrite | Cacheable=NotCacheable.
/// For PCI BAR windows we expose non-cacheable read-write memory; the
/// guest's PCI driver claims its own cacheability per device.
pub(crate) const MEMFLAGS_READWRITE: u8 = 0b0000_0001;

/// Write a 2-byte PkgLength encoding `value`. ACPI §20.2.4: high two
/// bits of byte 0 = 01 (2-byte form), low 4 bits = low nibble of value,
/// byte 1 = high 8 bits. Max value 4095 — every name scope this crate
/// emits is well under that.
pub(crate) fn write_pkg_length(
    slot: &mut [u8],
    pos: usize,
    value: usize,
) -> Result<usize, DtbError> {
    if value > 0x0FFF {
        return Err(DtbError::Internal);
    }
    let b0 = 0x40u8 | u8::try_from(value & 0x0F).map_err(|_| DtbError::Internal)?;
    let b1 = u8::try_from((value >> 4) & 0xFF).map_err(|_| DtbError::Internal)?;
    write_bytes(slot, pos, &[b0, b1])
}

/// Constant byte cost of a 2-byte PkgLength.
pub(crate) const PKG_LENGTH_BYTES: usize = 2;

/// Write a 4-byte NameString segment (no scope prefix, no multi-name).
/// ACPI §20.2.2: bare NameSeg is 4 ASCII chars, padded with `_` if
/// shorter. The caller is responsible for not passing names that
/// require root (`\`), parent (`^`), or DualName/MultiName prefixes.
pub(crate) fn write_name_seg(
    slot: &mut [u8],
    pos: usize,
    name: &[u8; 4],
) -> Result<usize, DtbError> {
    write_bytes(slot, pos, name)
}

/// Write the AML `Device(<name>)` header: ExtOpPrefix + DeviceOp +
/// 2-byte PkgLength + 4-byte NameSeg. `total_bytes` is the complete
/// device size (including the 2-byte DeviceOp prefix); the PkgLength
/// covers everything after the prefix.
pub(crate) fn write_device_header(
    slot: &mut [u8],
    pos: usize,
    name: &[u8; 4],
    total_bytes: usize,
) -> Result<usize, DtbError> {
    let pos = write_bytes(slot, pos, &[EXT_OP_PREFIX, DEVICE_OP])?;
    let pkg_value = total_bytes.checked_sub(2).ok_or(DtbError::Internal)?;
    let pos = write_pkg_length(slot, pos, pkg_value)?;
    write_name_seg(slot, pos, name)
}

/// Build a NameSeg from a 3-byte prefix and a hex index (`0`–`9`,
/// `A`–`Z`): e.g. `name_seg_indexed(b"PCI", 0)` → `b"PCI0"`,
/// `name_seg_indexed(b"MBR", 10)` → `b"MBRA"`.
pub(crate) fn name_seg_indexed(prefix: &[u8; 3], index: u8) -> [u8; 4] {
    let suffix = if index < 10 {
        b'0'.saturating_add(index)
    } else {
        b'A'.saturating_add(index.saturating_sub(10))
    };
    [prefix[0], prefix[1], prefix[2], suffix]
}

/// `Name(<name>, <ByteConst>)` — 7 bytes total.
pub(crate) fn write_name_byte(
    slot: &mut [u8],
    pos: usize,
    name: &[u8; 4],
    value: u8,
) -> Result<usize, DtbError> {
    let pos = write_bytes(slot, pos, &[NAME_OP])?;
    let pos = write_name_seg(slot, pos, name)?;
    write_bytes(slot, pos, &[BYTE_PREFIX, value])
}

/// `Name(<name>, <DWordConst>)` — 10 bytes total.
pub(crate) fn write_name_dword(
    slot: &mut [u8],
    pos: usize,
    name: &[u8; 4],
    value: u32,
) -> Result<usize, DtbError> {
    let pos = write_bytes(slot, pos, &[NAME_OP])?;
    let pos = write_name_seg(slot, pos, name)?;
    let pos = write_bytes(slot, pos, &[DWORD_PREFIX])?;
    write_bytes(slot, pos, &value.to_le_bytes())
}

/// `Name(<name>, "<value>")`.
pub(crate) fn write_name_string(
    slot: &mut [u8],
    pos: usize,
    name: &[u8; 4],
    value: &[u8],
) -> Result<usize, DtbError> {
    let pos = write_bytes(slot, pos, &[NAME_OP])?;
    let pos = write_name_seg(slot, pos, name)?;
    write_string(slot, pos, value)
}

/// AML StringPrefix followed by a NUL-terminated byte string.
pub(crate) fn write_string(slot: &mut [u8], pos: usize, value: &[u8]) -> Result<usize, DtbError> {
    let pos = write_bytes(slot, pos, &[STRING_PREFIX])?;
    let pos = write_bytes(slot, pos, value)?;
    write_bytes(slot, pos, &[0])
}

/// Constant byte cost of an AML string for an ASCII byte slice.
pub(crate) const fn string_bytes(value_len: usize) -> usize {
    value_len.saturating_add(2)
}

/// `Buffer() { <bytes> }` for byte arrays of length <= 255.
pub(crate) fn write_byte_buffer(
    slot: &mut [u8],
    pos: usize,
    bytes: &[u8],
) -> Result<usize, DtbError> {
    let len = u8::try_from(bytes.len()).map_err(|_| DtbError::Internal)?;
    let pos = write_bytes(slot, pos, &[BUFFER_OP])?;
    let pkg = PKG_LENGTH_BYTES
        .checked_add(2)
        .and_then(|v| v.checked_add(bytes.len()))
        .ok_or(DtbError::Internal)?;
    let pos = write_pkg_length(slot, pos, pkg)?;
    let pos = write_bytes(slot, pos, &[BYTE_PREFIX, len])?;
    write_bytes(slot, pos, bytes)
}

/// Constant byte cost of [`write_byte_buffer`] for length <= 255.
pub(crate) const fn byte_buffer_bytes(value_len: usize) -> usize {
    value_len.saturating_add(PKG_LENGTH_BYTES).saturating_add(3)
}

/// Compute the 32-bit EISAID encoding of a 7-character PNP ID like
/// `b"PNP0A08"`. ACPI §5.7.2.1: first three letters compressed into
/// bytes 0-1 (5 bits each, biased by `@`), last four hex digits in
/// bytes 2-3 (4 bits each), all stored little-endian.
// Provably-safe bit-packing: every term is masked/shifted within u32 and
// the inputs are spec-bounded ASCII (`@`..`_` letters, `0`..`F` hex). All
// arithmetic is const-evaluated, so any overflow is a compile error, not a
// runtime hazard — checked ops would only obscure the EISAID encoding.
#[allow(clippy::arithmetic_side_effects, clippy::as_conversions)]
pub(crate) const fn eisaid(s: &[u8; 7]) -> u32 {
    let c0 = (s[0] - b'@') as u32;
    let c1 = (s[1] - b'@') as u32;
    let c2 = (s[2] - b'@') as u32;
    let h0 = hex_digit(s[3]) as u32;
    let h1 = hex_digit(s[4]) as u32;
    let h2 = hex_digit(s[5]) as u32;
    let h3 = hex_digit(s[6]) as u32;
    let b0 = (c0 << 2) | (c1 >> 3);
    let b1 = ((c1 & 0x07) << 5) | c2;
    let b2 = (h0 << 4) | h1;
    let b3 = (h2 << 4) | h3;
    (b0) | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

// Match guards bound `c` to the subtracted range, so both subtractions are
// provably non-negative and `+ 10` stays within a nibble; const-evaluated.
#[allow(clippy::arithmetic_side_effects)]
const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        // EISAID hex digits are always 0-9 / A-F by spec; any other
        // input is a programming error. Return 0 — the resulting
        // EISAID won't match anything the OS recognises and tests
        // will catch it.
        _ => 0,
    }
}

/// Write the bytes of a `WordBusNumber` resource descriptor (16 bytes).
/// ACPI §6.4.3.5.3. Single fixed bus-number range with min ≤ max.
pub(crate) fn write_word_bus_number(
    slot: &mut [u8],
    pos: usize,
    bus_min: u8,
    bus_max: u8,
) -> Result<usize, DtbError> {
    let len = u16::from(bus_max.saturating_sub(bus_min).saturating_add(1));
    let mut buf = [0u8; 16];
    buf[0] = TAG_WORD_ADDRESS_SPACE;
    // 2-byte length field = 13 (the standard form, no ResourceSource).
    buf[1] = 0x0D;
    buf[2] = 0x00;
    buf[3] = RES_TYPE_BUS_NUMBER;
    buf[4] = GENFLAGS_FIXED_RANGE;
    buf[5] = 0; // Type-specific flags = 0 for bus numbers
    // Granularity = 0, Min = bus_min, Max = bus_max, Translation = 0, Len.
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    buf[8..10].copy_from_slice(&u16::from(bus_min).to_le_bytes());
    buf[10..12].copy_from_slice(&u16::from(bus_max).to_le_bytes());
    buf[12..14].copy_from_slice(&0u16.to_le_bytes());
    buf[14..16].copy_from_slice(&len.to_le_bytes());
    write_bytes(slot, pos, &buf)
}

/// Constant byte cost of a `WordBusNumber` descriptor.
pub(crate) const WORD_BUS_NUMBER_BYTES: usize = 16;

/// Write a `DWordMemory` resource descriptor for a 32-bit MMIO window
/// (26 bytes). ACPI §6.4.3.5.2.
pub(crate) fn write_dword_memory(
    slot: &mut [u8],
    pos: usize,
    base: u32,
    size: u32,
) -> Result<usize, DtbError> {
    let max = base
        .checked_add(size)
        .ok_or(DtbError::Internal)?
        .saturating_sub(1);
    let mut buf = [0u8; 26];
    buf[0] = TAG_DWORD_ADDRESS_SPACE;
    buf[1] = 0x17; // length field = 23
    buf[2] = 0x00;
    buf[3] = RES_TYPE_MEMORY;
    buf[4] = GENFLAGS_FIXED_RANGE;
    buf[5] = MEMFLAGS_READWRITE;
    buf[6..10].copy_from_slice(&0u32.to_le_bytes()); // granularity
    buf[10..14].copy_from_slice(&base.to_le_bytes()); // min
    buf[14..18].copy_from_slice(&max.to_le_bytes()); // max
    buf[18..22].copy_from_slice(&0u32.to_le_bytes()); // translation
    buf[22..26].copy_from_slice(&size.to_le_bytes()); // length
    write_bytes(slot, pos, &buf)
}

/// Constant byte cost of a `DWordMemory` descriptor.
pub(crate) const DWORD_MEMORY_BYTES: usize = 26;

/// Write a `QWordMemory` resource descriptor for a 64-bit MMIO window
/// (46 bytes). ACPI §6.4.3.5.1. Same shape as `DWordMemory` but every
/// address field is a 64-bit little-endian quantity — the descriptor
/// the 64-bit-only PCIe BAR window (device-model §4) needs.
pub(crate) fn write_qword_memory(
    slot: &mut [u8],
    pos: usize,
    base: u64,
    size: u64,
) -> Result<usize, DtbError> {
    let max = base
        .checked_add(size)
        .ok_or(DtbError::Internal)?
        .saturating_sub(1);
    let mut buf = [0u8; 46];
    buf[0] = TAG_QWORD_ADDRESS_SPACE;
    buf[1] = 0x2B; // length field = 43
    buf[2] = 0x00;
    buf[3] = RES_TYPE_MEMORY;
    buf[4] = GENFLAGS_FIXED_RANGE;
    buf[5] = MEMFLAGS_READWRITE;
    buf[6..14].copy_from_slice(&0u64.to_le_bytes()); // granularity
    buf[14..22].copy_from_slice(&base.to_le_bytes()); // min
    buf[22..30].copy_from_slice(&max.to_le_bytes()); // max
    buf[30..38].copy_from_slice(&0u64.to_le_bytes()); // translation
    buf[38..46].copy_from_slice(&size.to_le_bytes()); // length
    write_bytes(slot, pos, &buf)
}

/// Constant byte cost of a `QWordMemory` descriptor.
pub(crate) const QWORD_MEMORY_BYTES: usize = 46;

/// Write an `ExtendedInterrupt` resource descriptor for one GSI (9 bytes).
/// ACPI §6.4.3.6. The trigger/polarity is derived from the devicetree
/// interrupt `sense` (IRQ_TYPE_*), not hardcoded: a VMM that delivers the line
/// edge-triggered (the dillo KVM irqfd route) needs the descriptor to say
/// edge, or an interrupt-driven consumer (e.g. `ttyS0`) stalls after the first
/// FIFO drains. Flag bits: bit0 ResourceConsumer, bit1 Edge(1)/Level(0),
/// bit2 ActiveLow(1)/High(0).
pub(crate) fn write_extended_interrupt(
    slot: &mut [u8],
    pos: usize,
    gsi: u32,
    sense: u32,
) -> Result<usize, DtbError> {
    let trigger_polarity: u8 = match sense {
        2 => 0b110, // EDGE_FALLING: edge,  active-low
        4 => 0b000, // LEVEL_HIGH  : level, active-high
        8 => 0b100, // LEVEL_LOW   : level, active-low
        _ => 0b010, // EDGE_RISING (1) / default: edge, active-high
    };
    let mut buf = [0u8; EXTENDED_INTERRUPT_BYTES];
    buf[0] = TAG_EXTENDED_INTERRUPT;
    buf[1] = 0x06; // length field = 6: flags + count + one u32 interrupt
    buf[2] = 0x00;
    buf[3] = 0b0000_0001 | trigger_polarity; // ResourceConsumer + trigger/polarity
    buf[4] = 1; // interrupt table length
    buf[5..9].copy_from_slice(&gsi.to_le_bytes());
    write_bytes(slot, pos, &buf)
}

/// Constant byte cost of a one-entry `ExtendedInterrupt` descriptor.
pub(crate) const EXTENDED_INTERRUPT_BYTES: usize = 9;

/// Write an `EndTag` (small descriptor, 2 bytes). Checksum byte 0 means
/// "don't verify" — the kernel accepts this and most firmware uses it.
pub(crate) fn write_end_tag(slot: &mut [u8], pos: usize) -> Result<usize, DtbError> {
    write_bytes(slot, pos, &[TAG_END, 0])
}

pub(crate) const END_TAG_BYTES: usize = 2;

/// Byte cost of the `Name(_CRS, Buffer(…))` wrapper around resource
/// descriptors: NameOp(1) + `_CRS`(4) + BufferOp(1) + PkgLength(2) +
/// WordPrefix+u16(3) = 11 bytes.
pub(crate) const CRS_WRAPPER_BYTES: usize = 1 + 4 + 1 + PKG_LENGTH_BYTES + 3;

/// Write the `Name(_CRS, Buffer(<descriptors>))` preamble: NameOp +
/// `_CRS` + BufferOp + PkgLength + WordPrefix + buffer-size u16.
/// `descriptor_bytes` is the total byte count of the resource
/// descriptors that will follow (the caller writes those next).
pub(crate) fn write_crs_buffer_header(
    slot: &mut [u8],
    pos: usize,
    descriptor_bytes: usize,
) -> Result<usize, DtbError> {
    let buffer_size = u16::try_from(descriptor_bytes).map_err(|_| DtbError::Internal)?;
    let buf_pkg_value = PKG_LENGTH_BYTES
        .checked_add(3)
        .and_then(|v| v.checked_add(descriptor_bytes))
        .ok_or(DtbError::Internal)?;
    let pos = write_bytes(slot, pos, &[NAME_OP])?;
    let pos = write_name_seg(slot, pos, b"_CRS")?;
    let pos = write_bytes(slot, pos, &[BUFFER_OP])?;
    let pos = write_pkg_length(slot, pos, buf_pkg_value)?;
    let pos = write_bytes(slot, pos, &[WORD_PREFIX])?;
    write_bytes(slot, pos, &buffer_size.to_le_bytes())
}

/// Append `bytes` at `pos`, returning the new position.
pub(crate) fn write_bytes(slot: &mut [u8], pos: usize, bytes: &[u8]) -> Result<usize, DtbError> {
    let end = pos.checked_add(bytes.len()).ok_or(DtbError::Internal)?;
    let dst = slot.get_mut(pos..end).ok_or(DtbError::Internal)?;
    dst.copy_from_slice(bytes);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eisaid_known_values() {
        // Verified against the canonical encodings in ACPI 6.5 §5.7.2.1
        // and against Linux's PNPID_FOR_NUMBER definitions.
        assert_eq!(eisaid(b"PNP0A03"), 0x030A_D041);
        assert_eq!(eisaid(b"PNP0A08"), 0x080A_D041);
    }

    #[test]
    fn pkg_length_roundtrip() {
        let mut buf = [0u8; 2];
        let _ = write_pkg_length(&mut buf, 0, 0x102).expect("encode");
        // 0x102 = 4-bit-low 0x2, high 8-bit 0x10
        assert_eq!(buf, [0x40 | 0x02, 0x10]);
    }

    #[test]
    fn end_tag_layout() {
        let mut buf = [0u8; 2];
        let n = write_end_tag(&mut buf, 0).expect("end tag");
        assert_eq!(n, END_TAG_BYTES);
        assert_eq!(buf, [0x79, 0x00]);
    }

    #[test]
    fn word_bus_number_min_max_match_input() {
        let mut buf = [0u8; WORD_BUS_NUMBER_BYTES];
        let n = write_word_bus_number(&mut buf, 0, 0, 0).expect("write");
        assert_eq!(n, WORD_BUS_NUMBER_BYTES);
        assert_eq!(buf[0], TAG_WORD_ADDRESS_SPACE);
        assert_eq!(buf[3], RES_TYPE_BUS_NUMBER);
        assert_eq!(u16::from_le_bytes([buf[8], buf[9]]), 0); // min
        assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 0); // max
        assert_eq!(u16::from_le_bytes([buf[14], buf[15]]), 1); // length
    }

    #[test]
    fn dword_memory_min_max_and_length() {
        let mut buf = [0u8; DWORD_MEMORY_BYTES];
        let n = write_dword_memory(&mut buf, 0, 0xC000_0000, 0x1000_0000).expect("write");
        assert_eq!(n, DWORD_MEMORY_BYTES);
        assert_eq!(buf[0], TAG_DWORD_ADDRESS_SPACE);
        assert_eq!(buf[3], RES_TYPE_MEMORY);
        assert_eq!(
            u32::from_le_bytes(buf[10..14].try_into().unwrap()),
            0xC000_0000
        );
        assert_eq!(
            u32::from_le_bytes(buf[14..18].try_into().unwrap()),
            0xCFFF_FFFF
        );
        assert_eq!(
            u32::from_le_bytes(buf[22..26].try_into().unwrap()),
            0x1000_0000
        );
    }

    #[test]
    fn qword_memory_min_max_and_length() {
        // The conformant arma 64-bit BAR window: 128 GiB at 32 GiB
        // (device-model §4 default). Pins the tag, the length byte, and
        // the 64-bit min/max/length fields.
        let base: u64 = 0x0000_0008_0000_0000; // 32 GiB
        let size: u64 = 0x0000_0020_0000_0000; // 128 GiB
        let mut buf = [0u8; QWORD_MEMORY_BYTES];
        let n = write_qword_memory(&mut buf, 0, base, size).expect("write");
        assert_eq!(n, QWORD_MEMORY_BYTES);
        assert_eq!(buf[0], TAG_QWORD_ADDRESS_SPACE);
        assert_eq!(buf[1], 0x2B, "QWordMemory length field = 43");
        assert_eq!(buf[3], RES_TYPE_MEMORY);
        assert_eq!(u64::from_le_bytes(buf[14..22].try_into().unwrap()), base);
        assert_eq!(
            u64::from_le_bytes(buf[22..30].try_into().unwrap()),
            base + size - 1
        );
        assert_eq!(u64::from_le_bytes(buf[38..46].try_into().unwrap()), size);
    }
}
