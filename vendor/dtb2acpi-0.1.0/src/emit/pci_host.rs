// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! DSDT `Device(PCI<n>)` emitter — one per `pci-host-ecam-generic`
//! root child.
//!
//! Linux's `acpi_pci_root_add` registers a PCI root bus only for ACPI
//! namespace devices whose `_HID` (or `_CID`) matches `PNP0A08`
//! (PCIe) or `PNP0A03` (legacy PCI). Without such a device the kernel
//! never enumerates the bus — even when MCFG is valid and the ECAM
//! window is reserved — and falls through to legacy CF8/CFC port-IO
//! that dillo does not (and per DT-binding policy, will not) emulate.
//!
//! Per host-bridge device shape (one per ECAM):
//!
//! ```aml
//! Device(PCI<n>) {
//!     Name(_HID, EISAID("PNP0A08"))
//!     Name(_CID, EISAID("PNP0A03"))
//!     Name(_SEG, <segment>)
//!     Name(_UID, <segment>)
//!     Name(_BBN, <bus_start>)
//!     Name(_CRS, ResourceTemplate() {
//!         WordBusNumber(<bus_start>..<bus_end>)
//!         DWordMemory(<mmio_base>..<mmio_base+size-1>)+   // per Mem32 range
//!         EndTag
//!     })
//! }
//! ```
//!
//! The segment number is the host-bridge's 0-based index in
//! `root.children()` order, matching MCFG's segment assignment in
//! [`crate::emit::mcfg`]. Both 32-bit (`phys.hi` space code `0x02`,
//! `DWordMemory`) and 64-bit (`0x03`, `QWordMemory`) memory ranges are
//! exposed in `_CRS`; I/O windows (`0x01`) are skipped — the modern
//! profile drops the PCI I/O-port window, and the spec design is that
//! anything not in `_CRS` simply isn't part of this root's resources.
//! The conformant arma DTB declares a single 64-bit window
//! (device-model §4), so the QWord path is the load-bearing one.
//!
//! Pure translation: cell-level errors during emit's re-walk surface as
//! `DtbError::Internal`, defense-in-depth on a count-validated tree.

use devtree::TreeView;

use super::aml;
use crate::dtb::DtbNode;
use crate::error::DtbError;

/// Fixed body bytes per Device(PCI<n>) before `_CRS`:
/// `_HID` + `_CID` (DWord-valued names) + `_SEG` + `_UID` + `_BBN`
/// (Byte-valued names).
const FIXED_NAMES_BYTES: usize = (1 + 4 + 1 + 4) * 2  // _HID, _CID
    + (1 + 4 + 1 + 1) * 3; // _SEG, _UID, _BBN

/// Memory-window counts a host bridge advertises in `_CRS`, split by
/// descriptor width: 32-bit (`DWordMemory`) and 64-bit (`QWordMemory`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MemWindows {
    mem32: usize,
    mem64: usize,
}

/// Total bytes one Device(PCI<n>) AML occupies given the memory windows
/// it advertises in `_CRS`.
const fn host_bridge_aml_bytes(w: MemWindows) -> usize {
    let descriptors = aml::WORD_BUS_NUMBER_BYTES
        .saturating_add(aml::DWORD_MEMORY_BYTES.saturating_mul(w.mem32))
        .saturating_add(aml::QWORD_MEMORY_BYTES.saturating_mul(w.mem64))
        .saturating_add(aml::END_TAG_BYTES);
    let crs = aml::CRS_WRAPPER_BYTES.saturating_add(descriptors);
    let body = FIXED_NAMES_BYTES.saturating_add(crs);
    // DeviceOp(2) + PkgLength(2) + NameSeg(4) + body
    body.saturating_add(aml::PKG_LENGTH_BYTES).saturating_add(6)
}

/// Sum AML bytes for every PCI host bridge the tree declares. Walked
/// during count to size the DSDT slot.
pub(crate) fn dsdt_total_bytes<T: TreeView>(tree: &T) -> Result<usize, DtbError> {
    let root = DtbNode::root_of(tree.root());
    let mut total = 0usize;
    for child in root.children()? {
        if !child.has_compatible("pci-host-ecam-generic")? {
            continue;
        }
        let windows = count_windows(&child)?;
        total = total
            .checked_add(host_bridge_aml_bytes(windows))
            .ok_or(DtbError::Internal)?;
    }
    Ok(total)
}

fn count_windows<N: devtree::NodeView + Copy>(node: &DtbNode<N>) -> Result<MemWindows, DtbError> {
    let Some(ranges) = node.pci_ranges()? else {
        return Ok(MemWindows::default());
    };
    let mut w = MemWindows::default();
    for r in ranges {
        match r.space_code {
            0x02 => w.mem32 = w.mem32.checked_add(1).ok_or(DtbError::Internal)?,
            0x03 => w.mem64 = w.mem64.checked_add(1).ok_or(DtbError::Internal)?,
            _ => {}
        }
    }
    Ok(w)
}

/// Emit one `Device(PCI<seg>)` block per `pci-host-ecam-generic` root
/// child into `slot` starting at `pos`. Returns the new write position.
pub(crate) fn emit<T: TreeView>(slot: &mut [u8], pos: usize, tree: &T) -> Result<usize, DtbError> {
    let root = DtbNode::root_of(tree.root());
    let mut cursor = pos;
    let mut segment: u8 = 0;
    for child in root.children()? {
        if !child.has_compatible("pci-host-ecam-generic")? {
            continue;
        }
        cursor = write_one_device(slot, cursor, &child, segment)?;
        segment = segment.checked_add(1).ok_or(DtbError::Internal)?;
    }
    Ok(cursor)
}

fn write_one_device<N: devtree::NodeView + Copy>(
    slot: &mut [u8],
    pos: usize,
    node: &DtbNode<N>,
    segment: u8,
) -> Result<usize, DtbError> {
    let (bus_start, bus_end) = node.decode_pci_bus_range()?;
    let windows = count_windows(node)?;
    let total = host_bridge_aml_bytes(windows);

    let pos = aml::write_device_header(slot, pos, &aml::name_seg_indexed(b"PCI", segment), total)?;

    // ─── Body ──────────────────────────────────────────────────────
    let pos = aml::write_name_dword(slot, pos, b"_HID", aml::eisaid(b"PNP0A08"))?;
    let pos = aml::write_name_dword(slot, pos, b"_CID", aml::eisaid(b"PNP0A03"))?;
    let pos = aml::write_name_byte(slot, pos, b"_SEG", segment)?;
    let pos = aml::write_name_byte(slot, pos, b"_UID", segment)?;
    let pos = aml::write_name_byte(slot, pos, b"_BBN", bus_start)?;

    // ─── _CRS = Buffer(<descriptors>) ──────────────────────────────
    let descriptors_bytes = aml::WORD_BUS_NUMBER_BYTES
        .checked_add(
            aml::DWORD_MEMORY_BYTES
                .checked_mul(windows.mem32)
                .ok_or(DtbError::Internal)?,
        )
        .and_then(|v| v.checked_add(aml::QWORD_MEMORY_BYTES.checked_mul(windows.mem64)?))
        .and_then(|v| v.checked_add(aml::END_TAG_BYTES))
        .ok_or(DtbError::Internal)?;
    let pos = aml::write_crs_buffer_header(slot, pos, descriptors_bytes)?;

    // ─── Resource descriptors ──────────────────────────────────────
    let pos = aml::write_word_bus_number(slot, pos, bus_start, bus_end)?;
    let mut cursor = pos;
    if let Some(ranges) = node.pci_ranges()? {
        for r in ranges {
            match r.space_code {
                0x02 => {
                    let base = u32::try_from(r.parent_addr).map_err(|_| DtbError::Internal)?;
                    let size = u32::try_from(r.size).map_err(|_| DtbError::Internal)?;
                    cursor = aml::write_dword_memory(slot, cursor, base, size)?;
                }
                0x03 => {
                    cursor = aml::write_qword_memory(slot, cursor, r.parent_addr, r.size)?;
                }
                _ => continue,
            }
        }
    }
    aml::write_end_tag(slot, cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_name_seg_first_few() {
        assert_eq!(aml::name_seg_indexed(b"PCI", 0), *b"PCI0");
        assert_eq!(aml::name_seg_indexed(b"PCI", 9), *b"PCI9");
        assert_eq!(aml::name_seg_indexed(b"PCI", 10), *b"PCIA");
    }

    #[test]
    fn host_bridge_aml_bytes_one_mem32() {
        // DeviceOp(2) + PkgLength(2) + Name(4) + body(FIXED + CRS)
        // FIXED = (10*2) + (7*3) = 41
        // CRS wrapper = 11
        // CRS descriptors = WordBusNumber(16) + DWordMemory(26) + EndTag(2) = 44
        // CRS total = 11 + 44 = 55
        // body = 41 + 55 = 96
        // total = 2 + 2 + 4 + 96 = 104
        assert_eq!(
            host_bridge_aml_bytes(MemWindows { mem32: 1, mem64: 0 }),
            104
        );
    }

    #[test]
    fn host_bridge_aml_bytes_two_mem32() {
        // +26 for the extra DWordMemory
        assert_eq!(
            host_bridge_aml_bytes(MemWindows { mem32: 2, mem64: 0 }),
            130
        );
    }

    #[test]
    fn host_bridge_aml_bytes_zero_windows() {
        // Edge: a host bridge with no MMIO range still emits the
        // device + WordBusNumber + EndTag.
        // CRS descriptors = 16 + 2 = 18; CRS total = 11 + 18 = 29
        // body = 41 + 29 = 70; total = 2 + 2 + 4 + 70 = 78.
        assert_eq!(host_bridge_aml_bytes(MemWindows::default()), 78);
    }

    #[test]
    fn host_bridge_aml_bytes_one_mem64() {
        // Like one_mem32 but the descriptor is a QWordMemory (46 bytes)
        // instead of a DWordMemory (26): +20 over the 104 baseline.
        // CRS descriptors = 16 + 46 + 2 = 64; CRS total = 11 + 64 = 75
        // body = 41 + 75 = 116; total = 2 + 2 + 4 + 116 = 124.
        assert_eq!(
            host_bridge_aml_bytes(MemWindows { mem32: 0, mem64: 1 }),
            124
        );
    }
}
