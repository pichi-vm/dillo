// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Multiple APIC Description Table.
//!
//! ACPI 6.5 §5.2.12. Header is SDT header + 4-byte LAPIC address +
//! 4-byte flags (44 bytes); body is a variable-length sequence of
//! entries.
//!
//! Entry types we emit, chosen per-vCPU by APIC ID / processor UID:
//!
//! - Type 0 — Processor Local APIC (8 bytes) per vCPU with APIC ID ≤254
//! - Type 1 — I/O APIC (12 bytes) per IOAPIC
//! - Type 4 — Local APIC NMI (6 bytes) per vCPU with UID ≤254
//! - Type 9 — Processor Local x2APIC (16 bytes) per vCPU with APIC ID ≥255
//! - Type 10 — Local x2APIC NMI (12 bytes) per vCPU with UID ≥255
//!
//! NMI entries are emitted with LINT1 / edge / active-high — the
//! hardware-fixed wiring for x86 LAPIC NMI delivery.

use devtree::TreeView;
use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::flag_type;
use super::sdt::SdtHeader;
use super::set_sdt_checksum;
use super::write_entry;
use crate::count::{CpuCache, DtStatus, IOAPIC_GSI_STRIDE};
use crate::dtb::DtbNode;
use crate::error::{DtbError, Site};
use crate::oem::OemIdentity;

// Note on Type 0/9 selection: `processor_id` (the sequential UID) is
// packed into Type 0's u8 `processor_id` field, so a vCPU forced to
// Type 0 by a small APIC ID still has to fit its UID into a u8. The
// switch therefore considers BOTH axes — if either exceeds
// `XAPIC_ID_MAX`, fall back to Type 9 (x2APIC). Sizing and emit must
// use the same predicate.

/// MADT revision per ACPI 6.5.
pub(crate) const REVISION: u8 = 5;

/// Entry type identifiers per ACPI 6.5 §5.2.12 Table 5.20.
pub(crate) mod entry_type {
    pub(crate) const LOCAL_APIC: u8 = 0;
    pub(crate) const IO_APIC: u8 = 1;
    pub(crate) const LOCAL_APIC_NMI: u8 = 4;
    pub(crate) const PROCESSOR_LOCAL_X2APIC: u8 = 9;
    pub(crate) const LOCAL_X2APIC_NMI: u8 = 10;
}

/// Maximum value representable in the 1-byte Type 0 `apic_id` and
/// Type 4 `processor_id` fields. `0xFF` is reserved for broadcast.
pub(crate) const XAPIC_ID_MAX: u32 = 254;

flag_type! {
    /// MADT processor flag bits, shared between Type 0 (LAPIC,
    /// §5.2.12.2 Table 5.21) and Type 9 (x2APIC, §5.2.12.12) — both
    /// use the same Enabled + OnlineCapable encoding.
    pub(crate) struct LapicFlags: U32 as u32 {
        /// Bit 0 — processor is ready for use.
        const ENABLED = 1 << 0;
        /// Bit 1 — when [`Self::ENABLED`] is clear, indicates the
        /// processor can be brought online at runtime (hot-online
        /// capable).
        const ONLINE_CAPABLE = 1 << 1;
    }
}

flag_type! {
    /// MPS INTI Flags for the LAPIC NMI source entries (Type 4 +
    /// Type 10). Bits 0–1 polarity, bits 2–3 trigger mode.
    pub(crate) struct NmiFlags: U16 as u16 {
        /// `0x0005` — active-high + edge-triggered. The universal x86
        /// LAPIC NMI wiring (LINT1, this polarity/trigger). Every
        /// Intel/AMD LAPIC since the P6 ships this way; every commodity
        /// VMM emulates it; every x86 OS assumes it at boot. DT has no
        /// binding to express alternative wiring, and an x86 platform
        /// that varied from this would not boot a stock OS regardless
        /// of what its ACPI tables claimed.
        const EDGE_HIGH = 0x0005;
    }
}

/// MADT header — SDT header + LAPIC base + flags.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct MadtHeader {
    pub header: SdtHeader,
    pub local_apic_address: U32,
    /// MADT header flag bits per ACPI 6.5 §5.2.12 Table 5.19. The
    /// only defined bit is PCAT_COMPAT (bit 0, legacy 8259 PIC
    /// present), which is always clear for HW-Reduced ACPI guests —
    /// so we write zero.
    pub flags: U32,
}

impl MadtHeader {
    pub(crate) const SIZE: usize = 44;

    /// Total MADT byte cost: header + per-vCPU entries (LAPIC + NMI,
    /// pre-summed by [`crate::count::run`]) + IOAPIC entries.
    pub(crate) fn total_size(
        ioapic_count: u32,
        vcpu_entries_bytes: usize,
    ) -> Result<usize, DtbError> {
        let ioapics_bytes = usize::try_from(ioapic_count)
            .ok()
            .and_then(|n| n.checked_mul(IoApicEntry::SIZE))
            .ok_or(DtbError::Internal)?;
        Self::SIZE
            .checked_add(vcpu_entries_bytes)
            .and_then(|s| s.checked_add(ioapics_bytes))
            .ok_or(DtbError::Internal)
    }
}

/// Processor Local APIC entry (Type 0).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct LocalApicEntry {
    pub entry_type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: LapicFlags,
}

impl LocalApicEntry {
    pub(crate) const SIZE: usize = 8;
    const LENGTH: u8 = 8;

    /// Build a Type 0 entry. Caller has already narrowed both ids to
    /// u8 after the [`XAPIC_ID_MAX`] dispatch.
    pub(crate) const fn new(processor_id: u8, apic_id: u8, flags: LapicFlags) -> Self {
        Self {
            entry_type: entry_type::LOCAL_APIC,
            length: Self::LENGTH,
            processor_id,
            apic_id,
            flags,
        }
    }
}

/// Translate a [`DtStatus`] (cpu node) into the ACPI MADT processor
/// flag pair shared by Type 0 (LAPIC) and Type 9 (x2APIC) — both use
/// the same Enabled + OnlineCapable encoding per ACPI 6.5 §5.2.12.2
/// / §5.2.12.12.
///
/// - `Okay`     → `Enabled = 1`
/// - `Disabled` → `OnlineCapable = 1` (cpu is quiescent + hot-onlineable;
///   on x86 brought up via INIT/SIPI)
/// - `Reserved` → both 0 (lossy: DT says "operational but firmware-owned",
///   ACPI has no equivalent — both 0 == "OSPM ignores", which gives the
///   right OS-visible effect even though the spec semantic differs.
///   Omitting the entry entirely would be slightly more faithful but
///   breaks the walk-position-equals-UID invariant and adds status-aware
///   byte accounting; the OS-visible behavior is identical either way.)
/// - `Fail`     → both 0 ("cpu doesn't exist or is broken" — OSPM ignores)
impl From<DtStatus> for LapicFlags {
    fn from(status: DtStatus) -> Self {
        match status {
            DtStatus::Okay => Self::ENABLED,
            DtStatus::Disabled => Self::ONLINE_CAPABLE,
            DtStatus::Reserved | DtStatus::Fail => Self::empty(),
        }
    }
}

/// Processor Local x2APIC entry (Type 9). ACPI 6.5 §5.2.12.12.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct LocalX2ApicEntry {
    pub entry_type: u8,
    pub length: u8,
    pub reserved: [u8; 2],
    pub x2apic_id: U32,
    pub flags: LapicFlags,
    pub uid: U32,
}

impl LocalX2ApicEntry {
    pub(crate) const SIZE: usize = 16;
    const LENGTH: u8 = 16;

    /// Build a Type 9 entry. Both ids are full u32 on-wire — no
    /// narrowing needed.
    pub(crate) fn new(processor_id: u32, apic_id: u32, flags: LapicFlags) -> Self {
        Self {
            entry_type: entry_type::PROCESSOR_LOCAL_X2APIC,
            length: Self::LENGTH,
            reserved: [0; 2],
            x2apic_id: U32::new(apic_id),
            flags,
            uid: U32::new(processor_id),
        }
    }
}

/// I/O APIC entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct IoApicEntry {
    pub entry_type: u8,
    pub length: u8,
    pub io_apic_id: u8,
    pub reserved: u8,
    pub io_apic_address: U32,
    pub global_system_interrupt_base: U32,
}

impl IoApicEntry {
    pub(crate) const SIZE: usize = 12;
    const LENGTH: u8 = 12;

    /// Build an IOAPIC entry. `io_apic_id` is the caller's
    /// sequentially-assigned u8; `address` and `gsi_base` are both
    /// full u32 on-wire.
    pub(crate) fn new(io_apic_id: u8, address: u32, gsi_base: u32) -> Self {
        Self {
            entry_type: entry_type::IO_APIC,
            length: Self::LENGTH,
            io_apic_id,
            reserved: 0,
            io_apic_address: U32::new(address),
            global_system_interrupt_base: U32::new(gsi_base),
        }
    }
}

/// Local APIC NMI entry (Type 4).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct LocalApicNmiEntry {
    pub entry_type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub flags: NmiFlags,
    pub lint: u8,
}

impl LocalApicNmiEntry {
    pub(crate) const SIZE: usize = 6;
    const LENGTH: u8 = 6;
    /// LINT1 — the canonical x86 NMI pin. Same rationale as
    /// [`NmiFlags::EDGE_HIGH`]: hardware-, hypervisor-, and OS-
    /// universal; DT doesn't express it; not a configuration knob.
    pub(crate) const LINT_NMI: u8 = 1;

    /// Build a Type 4 entry. Caller has already narrowed `processor_id`
    /// to u8 after the [`XAPIC_ID_MAX`] dispatch. Flags + lint are
    /// fixed by the x86-universal wiring (see [`NmiFlags::EDGE_HIGH`]
    /// / [`Self::LINT_NMI`]).
    pub(crate) const fn new(processor_id: u8) -> Self {
        Self {
            entry_type: entry_type::LOCAL_APIC_NMI,
            length: Self::LENGTH,
            processor_id,
            flags: NmiFlags::EDGE_HIGH,
            lint: Self::LINT_NMI,
        }
    }
}

/// Local x2APIC NMI entry (Type 10). ACPI 6.5 §5.2.12.13.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct LocalX2ApicNmiEntry {
    pub entry_type: u8,
    pub length: u8,
    pub flags: NmiFlags,
    pub uid: U32,
    pub lint: u8,
    pub reserved: [u8; 3],
}

impl LocalX2ApicNmiEntry {
    pub(crate) const SIZE: usize = 12;
    const LENGTH: u8 = 12;

    /// Build a Type 10 entry. `uid` is full u32 on-wire. Flags + lint
    /// are fixed by the x86-universal wiring (see
    /// [`NmiFlags::EDGE_HIGH`] / [`LocalApicNmiEntry::LINT_NMI`]).
    pub(crate) fn new(uid: u32) -> Self {
        Self {
            entry_type: entry_type::LOCAL_X2APIC_NMI,
            length: Self::LENGTH,
            flags: NmiFlags::EDGE_HIGH,
            uid: U32::new(uid),
            lint: LocalApicNmiEntry::LINT_NMI,
            reserved: [0; 3],
        }
    }
}

/// Byte cost of the LAPIC entry chosen for a vCPU. Type 0 (xAPIC)
/// is only chosen when BOTH `apic_id` and `processor_id` (UID) fit in
/// `XAPIC_ID_MAX`'s `u8`-representable range.
#[inline]
pub(crate) const fn lapic_entry_size_for_apic(apic_id: u32, processor_id: u32) -> usize {
    if apic_id <= XAPIC_ID_MAX && processor_id <= XAPIC_ID_MAX {
        LocalApicEntry::SIZE
    } else {
        LocalX2ApicEntry::SIZE
    }
}

/// Byte cost of the NMI entry chosen for a vCPU with the given UID.
#[inline]
pub(crate) const fn nmi_entry_size_for_uid(uid: u32) -> usize {
    if uid <= XAPIC_ID_MAX {
        LocalApicNmiEntry::SIZE
    } else {
        LocalX2ApicNmiEntry::SIZE
    }
}

/// Emit a complete, checksummed MADT into `slot`.
///
/// The slot length is the source of truth for the SDT `length` field;
/// [`crate::count::run`] sized it exactly.
///
/// Processor UID is the cpu's 0-based index in `cpus.children()`
/// walk order, matching `count::walk_cpus`. UID 0 is the BSP
/// (enforced at count time). NMI source entries (Type 4 / Type 10)
/// reference the same UID space.
pub(crate) fn emit<T: TreeView>(
    slot: &mut [u8],
    oem: &OemIdentity,
    tree: &T,
    lapic_base: u32,
    cpu_cache: &CpuCache,
) -> Result<(), DtbError> {
    let length = super::sdt_length_from_slot(slot)?;
    let header = MadtHeader {
        header: SdtHeader::new(*b"APIC", length, REVISION, oem),
        // `lapic_base` was narrowed to u32 at count time after the
        // `<= u32::MAX` validation; the write here is infallible.
        local_apic_address: U32::new(lapic_base),
        flags: U32::new(0),
    };
    super::write_header(slot, &header)?;

    let mut pos = MadtHeader::SIZE;
    let root = DtbNode::root_of(tree.root());

    // Per-vCPU entries (LAPIC + NMI) — read pre-decoded
    // `(apic_id, status)` out of the cache populated by `count::run`.
    // Bounded by `CPU_CACHE_CAP`; count rejects oversize trees.
    for (processor_id, apic_id, _numa, status) in cpu_cache.entries() {
        pos = emit_lapic_entry(slot, pos, processor_id, apic_id, status)?;
        pos = emit_nmi_entry(slot, pos, processor_id)?;
    }

    // IOAPIC entries after all per-CPU entries (entry order within
    // MADT is not significant per ACPI 6.5 §5.2.12).
    //
    // Re-walk the `intel,ce4100-ioapic` root children using the same
    // filter as count; each node's `reg[0]` base is one IOAPIC entry.
    // IOAPIC id and global_system_interrupt_base are policy choices the
    // DT cannot inform (DT uses phandle references and per-controller
    // local interrupt namespaces, not a flat ID/GSI space): id starts
    // at 0 and increments per IOAPIC; GSI base strides by
    // `IOAPIC_GSI_STRIDE` (the standard 24-pin Intel IOAPIC count). The
    // OS writes the id we assign into the IOAPIC's ID register at boot,
    // so any unique sequence works.
    let mut io_id: u8 = 0;
    let mut gsi_base: u32 = 0;
    for ioapic in root.ioapic_nodes()? {
        let base = ioapic.reg(Site::Intc)?.next().ok_or(DtbError::Internal)?.0;
        let base32 = u32::try_from(base).map_err(|_| DtbError::Internal)?;
        let e = IoApicEntry::new(io_id, base32, gsi_base);
        pos = write_entry(slot, pos, e.as_bytes())?;
        io_id = io_id.checked_add(1).ok_or(DtbError::Internal)?;
        gsi_base = gsi_base
            .checked_add(IOAPIC_GSI_STRIDE)
            .ok_or(DtbError::Internal)?;
    }

    let _ = pos;
    set_sdt_checksum(slot)
}

#[inline]
fn emit_lapic_entry(
    slot: &mut [u8],
    pos: usize,
    processor_id: u32,
    apic_id: u32,
    status: DtStatus,
) -> Result<usize, DtbError> {
    let flags = LapicFlags::from(status);
    if apic_id <= XAPIC_ID_MAX && processor_id <= XAPIC_ID_MAX {
        let proc_u8 = u8::try_from(processor_id).map_err(|_| DtbError::Internal)?;
        let apic_u8 = u8::try_from(apic_id).map_err(|_| DtbError::Internal)?;
        let e = LocalApicEntry::new(proc_u8, apic_u8, flags);
        write_entry(slot, pos, e.as_bytes())
    } else {
        let e = LocalX2ApicEntry::new(processor_id, apic_id, flags);
        write_entry(slot, pos, e.as_bytes())
    }
}

/// Emit the per-processor LAPIC NMI source entry (Type 4 below
/// [`XAPIC_ID_MAX`], Type 10 above). The NMI wiring itself
/// ([`LocalApicNmiEntry::LINT_NMI`] + [`NmiFlags::EDGE_HIGH`])
/// is the x86-universal LINT1 + edge + active-high; see those
/// constants for why this is not a configuration knob.
#[inline]
fn emit_nmi_entry(slot: &mut [u8], pos: usize, processor_id: u32) -> Result<usize, DtbError> {
    if processor_id <= XAPIC_ID_MAX {
        let proc_u8 = u8::try_from(processor_id).map_err(|_| DtbError::Internal)?;
        let e = LocalApicNmiEntry::new(proc_u8);
        write_entry(slot, pos, e.as_bytes())
    } else {
        let e = LocalX2ApicNmiEntry::new(processor_id);
        write_entry(slot, pos, e.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No integration fixture has >254 vCPUs, so the Type 10 NMI branch
    // (LocalX2ApicNmiEntry) is only reachable from this direct unit
    // test. Sized fixtures are impractical to hand-craft.

    #[test]
    fn nmi_size_threshold() {
        assert_eq!(nmi_entry_size_for_uid(0), LocalApicNmiEntry::SIZE);
        assert_eq!(
            nmi_entry_size_for_uid(XAPIC_ID_MAX),
            LocalApicNmiEntry::SIZE
        );
        assert_eq!(
            nmi_entry_size_for_uid(XAPIC_ID_MAX + 1),
            LocalX2ApicNmiEntry::SIZE
        );
        assert_eq!(nmi_entry_size_for_uid(u32::MAX), LocalX2ApicNmiEntry::SIZE);
    }

    #[test]
    fn x2apic_nmi_emit_bytes_match_spec() {
        let uid: u32 = 255;
        let mut buf = [0u8; LocalX2ApicNmiEntry::SIZE];
        let new_pos = emit_nmi_entry(&mut buf, 0, uid).expect("emit");
        assert_eq!(new_pos, LocalX2ApicNmiEntry::SIZE);
        // ACPI 6.5 §5.2.12.13 — Type 10 NMI:
        // type, length, flags(u16 LE), uid(u32 LE), lint, reserved[3].
        assert_eq!(buf[0], entry_type::LOCAL_X2APIC_NMI);
        assert_eq!(buf[1] as usize, LocalX2ApicNmiEntry::SIZE);
        // NmiFlags::EDGE_HIGH is documented as 0x0005 (active-high +
        // edge-triggered) — pin the wire value here.
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x0005);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), uid);
        assert_eq!(buf[8], LocalApicNmiEntry::LINT_NMI);
        assert_eq!(&buf[9..12], &[0u8, 0, 0]);
    }
}
