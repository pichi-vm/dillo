// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! System Resource Affinity Table.
//!
//! ACPI 6.5 §5.2.16. Header is SDT header + 4-byte reserved (set to
//! 1 per ACPI 1.0 compatibility) + 8-byte reserved (48 bytes total).
//! Body is a sequence of affinity entries.
//!
//! Entry types we emit, chosen per-CPU by APIC ID:
//!
//! - Type 0 — Processor Local APIC/SAPIC Affinity (16 bytes) per vCPU with APIC ID ≤254
//! - Type 1 — Memory Affinity (40 bytes) per `/memory@…` region
//! - Type 2 — Processor Local x2APIC Affinity (24 bytes) per vCPU with APIC ID ≥255

use devtree::TreeView;
use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::flag_type;
use super::madt::XAPIC_ID_MAX;
use super::sdt::SdtHeader;
use super::set_sdt_checksum;
use super::write_entry;
use crate::count::{CpuCache, DtStatus, base_name_is};
use crate::dtb::DtbNode;
use crate::error::{DtbError, NumaIncomplete, Site};
use crate::oem::OemIdentity;

/// SRAT revision per ACPI 6.5.
pub(crate) const REVISION: u8 = 3;

pub(crate) mod entry_type {
    pub(crate) const PROCESSOR_LOCAL_APIC: u8 = 0;
    pub(crate) const MEMORY_AFFINITY: u8 = 1;
    pub(crate) const PROCESSOR_LOCAL_X2APIC: u8 = 2;
}

/// SRAT header — SDT header + reserved fields.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct SratHeader {
    pub header: SdtHeader,
    /// Reserved; set to 1 per ACPI 1.0 compatibility.
    pub table_revision: U32,
    pub reserved: U64,
}

impl SratHeader {
    pub(crate) const SIZE: usize = 48;

    /// Total SRAT byte cost: header + per-CPU affinity entries
    /// (pre-summed by [`crate::count::run`]) + memory affinity entries.
    pub(crate) fn total_size(
        memory_region_count: u32,
        cpu_entries_bytes: usize,
    ) -> Result<usize, DtbError> {
        let mem_bytes = usize::try_from(memory_region_count)
            .ok()
            .and_then(|n| n.checked_mul(MemoryAffinity::SIZE))
            .ok_or(DtbError::Internal)?;
        Self::SIZE
            .checked_add(cpu_entries_bytes)
            .and_then(|s| s.checked_add(mem_bytes))
            .ok_or(DtbError::Internal)
    }
}

flag_type! {
    /// SRAT processor affinity flag bits, shared between Type 0
    /// (APIC, §5.2.16.1) and Type 2 (x2APIC, §5.2.16.3) — both use
    /// the same encoding.
    pub(crate) struct CpuAffinityFlags: U32 as u32 {
        /// The entry is meaningful (cleared for missing / firmware-
        /// owned / non-existent CPUs; OSPM ignores entries with
        /// Enabled clear).
        const ENABLED = 1 << 0;
    }
}

flag_type! {
    /// SRAT Memory Affinity flag bits. ACPI 6.5 §5.2.16.2 Table 5.45.
    pub(crate) struct MemoryAffinityFlags: U32 as u32 {
        /// Bit 0 — the region exists and the OS may use it. Cleared
        /// for memory whose DT `status` is not `"okay"`; OSPM ignores
        /// entries whose Enabled is clear.
        const ENABLED = 1 << 0;
        /// Bit 1 — the memory region may be hot-added or hot-removed
        /// at runtime. Driven by the DT spec's `hotpluggable` property
        /// (§3.4, Table 3.3) on the `/memory@…` node — orthogonal to
        /// [`Self::ENABLED`]: a region can be present-and-removable
        /// (Enabled+HotPluggable), or absent-and-addable (HotPluggable
        /// only).
        const HOT_PLUGGABLE = 1 << 1;
    }
}

/// Processor Local APIC/SAPIC Affinity entry (Type 0).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct ProcessorLocalApicAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain_lo: u8,
    pub apic_id: u8,
    pub flags: CpuAffinityFlags,
    pub local_sapic_eid: u8,
    pub proximity_domain_hi: [u8; 3],
    pub clock_domain: U32,
}

impl ProcessorLocalApicAffinity {
    pub(crate) const SIZE: usize = 16;
    const LENGTH: u8 = 16;

    /// Build a Type 0 entry. Caller has already narrowed `apic_id` to
    /// u8 after the [`XAPIC_ID_MAX`] dispatch. Splits the proximity
    /// domain into the awkward (lo: u8, hi: [u8; 3]) wire layout.
    pub(crate) fn new(apic_id: u8, proximity_domain: u32, flags: CpuAffinityFlags) -> Self {
        let pd = proximity_domain.to_le_bytes();
        Self {
            entry_type: entry_type::PROCESSOR_LOCAL_APIC,
            length: Self::LENGTH,
            proximity_domain_lo: pd[0],
            apic_id,
            flags,
            local_sapic_eid: 0,
            proximity_domain_hi: [pd[1], pd[2], pd[3]],
            clock_domain: U32::new(0),
        }
    }
}

/// Processor Local x2APIC Affinity entry (Type 2). ACPI 6.5 §5.2.16.3.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct X2ApicAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub reserved_1: [u8; 2],
    pub proximity_domain: U32,
    pub x2apic_id: U32,
    pub flags: CpuAffinityFlags,
    pub clock_domain: U32,
    pub reserved_2: [u8; 4],
}

impl X2ApicAffinity {
    pub(crate) const SIZE: usize = 24;
    const LENGTH: u8 = 24;

    /// Build a Type 2 entry. Both `apic_id` and `proximity_domain`
    /// are full u32 on-wire — no narrowing or splitting.
    pub(crate) fn new(apic_id: u32, proximity_domain: u32, flags: CpuAffinityFlags) -> Self {
        Self {
            entry_type: entry_type::PROCESSOR_LOCAL_X2APIC,
            length: Self::LENGTH,
            reserved_1: [0; 2],
            proximity_domain: U32::new(proximity_domain),
            x2apic_id: U32::new(apic_id),
            flags,
            clock_domain: U32::new(0),
            reserved_2: [0; 4],
        }
    }
}

/// Memory Affinity entry.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct MemoryAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain: U32,
    pub reserved_1: U16,
    pub base_addr_low: U32,
    pub base_addr_high: U32,
    pub length_low: U32,
    pub length_high: U32,
    pub reserved_2: U32,
    pub flags: MemoryAffinityFlags,
    pub reserved_3: U64,
}

impl MemoryAffinity {
    pub(crate) const SIZE: usize = 40;
    const LENGTH: u8 = 40;

    /// Build a Memory Affinity entry. Splits both `base` and `length`
    /// from u64 into the (lo: U32, hi: U32) wire layout. The
    /// `try_from(...).unwrap_or(0)` fallbacks are provably dead —
    /// each operand is masked to 32 bits first — but satisfy the
    /// no-panic / no-`as`-cast lints without making the constructor
    /// fallible.
    pub(crate) fn new(
        proximity_domain: u32,
        base: u64,
        length: u64,
        flags: MemoryAffinityFlags,
    ) -> Self {
        let base_lo = u32::try_from(base & 0xFFFF_FFFF).unwrap_or(0);
        let base_hi = u32::try_from((base >> 32) & 0xFFFF_FFFF).unwrap_or(0);
        let len_lo = u32::try_from(length & 0xFFFF_FFFF).unwrap_or(0);
        let len_hi = u32::try_from((length >> 32) & 0xFFFF_FFFF).unwrap_or(0);
        Self {
            entry_type: entry_type::MEMORY_AFFINITY,
            length: Self::LENGTH,
            proximity_domain: U32::new(proximity_domain),
            reserved_1: U16::new(0),
            base_addr_low: U32::new(base_lo),
            base_addr_high: U32::new(base_hi),
            length_low: U32::new(len_lo),
            length_high: U32::new(len_hi),
            reserved_2: U32::new(0),
            flags,
            reserved_3: U64::new(0),
        }
    }
}

/// Byte cost of the CPU affinity entry chosen for the given APIC ID.
#[inline]
pub(crate) const fn cpu_affinity_size_for_apic(apic_id: u32) -> usize {
    if apic_id <= XAPIC_ID_MAX {
        ProcessorLocalApicAffinity::SIZE
    } else {
        X2ApicAffinity::SIZE
    }
}

/// Emit a complete, checksummed SRAT into `slot`.
///
/// `slot.len()` is the source of truth for the SDT `length` field;
/// [`crate::count::run`] sized it exactly. Per-CPU and
/// per-memory proximity-domain tags are re-read from the tree —
/// [`crate::count::run`] already enforced completeness, so a missing
/// tag at emit time indicates drift and is surfaced as
/// [`DtbError::PartialNuma`] rather than silently substituting `0`
/// (which would mis-assign affinity).
pub(crate) fn emit<T: TreeView>(
    slot: &mut [u8],
    oem: &OemIdentity,
    tree: &T,
    cpu_cache: &CpuCache,
) -> Result<(), DtbError> {
    let length = super::sdt_length_from_slot(slot)?;
    let header = SratHeader {
        header: SdtHeader::new(*b"SRAT", length, REVISION, oem),
        table_revision: U32::new(1),
        reserved: U64::new(0),
    };
    super::write_header(slot, &header)?;

    let mut pos = SratHeader::SIZE;

    // Per-CPU affinity entries — pre-decoded from the cpu cache
    // populated by `count::run`. Bounded by `CPU_CACHE_CAP`; count
    // rejects oversize trees.
    let root = DtbNode::root_of(tree.root());
    for (_processor_id, apic_id, numa, status) in cpu_cache.entries() {
        let pd = numa.ok_or(DtbError::PartialNuma {
            reason: NumaIncomplete::CpuUntagged,
        })?;
        pos = emit_cpu_affinity(slot, pos, apic_id, pd, status)?;
    }

    // Memory affinity entries — re-walk /memory@* nodes using the
    // same parser as count::run. Like the CPU walk above, a missing
    // `numa-node-id` here means count and emit have drifted; surface
    // it as PartialNuma rather than silently defaulting to 0.
    for child in root.children()? {
        if !base_name_is(child.name(), "memory") {
            continue;
        }
        let pd = child
            .property_u32_opt("numa-node-id")?
            .ok_or(DtbError::PartialNuma {
                reason: NumaIncomplete::MemoryUntagged,
            })?;
        let mem_status = child.decode_status(Site::Memory)?;
        let hotpluggable = child.decode_memory_hotpluggable();
        let flags = MemoryAffinityFlags::for_memory(mem_status, hotpluggable);
        for (base, length) in child.reg(Site::Memory)? {
            let e = MemoryAffinity::new(pd, base, length, flags);
            pos = write_entry(slot, pos, e.as_bytes())?;
        }
    }

    let _ = pos;
    set_sdt_checksum(slot)
}

/// Translate a [`DtStatus`] (cpu node) into the SRAT processor-affinity
/// Enabled bit. SRAT has no OnlineCapable concept — affinity is a
/// static topology property — so `Okay` and `Disabled` (quiescent,
/// hot-onlineable) both set the bit so the OS knows the cpu's NUMA
/// domain when it comes online. `Reserved` and `Fail` clear it: the
/// cpu is either firmware-claimed or non-existent; no usable affinity
/// to report.
impl From<DtStatus> for CpuAffinityFlags {
    fn from(status: DtStatus) -> Self {
        match status {
            DtStatus::Okay | DtStatus::Disabled => Self::ENABLED,
            DtStatus::Reserved | DtStatus::Fail => Self::empty(),
        }
    }
}

impl MemoryAffinityFlags {
    /// Translate a `/memory@…` node's [`DtStatus`] and `hotpluggable`
    /// presence into the SRAT Memory Affinity flag pair (Enabled +
    /// HotPluggable). The two DT properties are independent and map
    /// orthogonally onto the two ACPI bits, per ACPI 6.5 §5.2.16.2:
    ///
    /// | DT `status` | DT `hotpluggable` | Enabled | HotPluggable |
    /// |-------------|-------------------|---------|--------------|
    /// | okay/absent | absent            |    1    |      0       |
    /// | okay/absent | present           |    1    |      1       |
    /// | disabled    | present           |    0    |      1       |
    /// | disabled    | absent            |    0    |      0       |
    /// | reserved    | (either)          |    0    |      0       |
    /// | fail        | (either)          |    0    |      0       |
    ///
    /// `Fail` and `Reserved` clear both bits — `hotpluggable` has no
    /// meaning on a region that doesn't exist (`fail`) or that another
    /// software component owns (`reserved`).
    pub(crate) fn for_memory(status: DtStatus, hotpluggable: bool) -> Self {
        let enabled = matches!(status, DtStatus::Okay);
        let hot = hotpluggable && matches!(status, DtStatus::Okay | DtStatus::Disabled);
        let mut f = Self::empty();
        if enabled {
            f |= Self::ENABLED;
        }
        if hot {
            f |= Self::HOT_PLUGGABLE;
        }
        f
    }
}

#[inline]
fn emit_cpu_affinity(
    slot: &mut [u8],
    pos: usize,
    apic_id: u32,
    proximity_domain: u32,
    status: DtStatus,
) -> Result<usize, DtbError> {
    let flags = CpuAffinityFlags::from(status);
    if apic_id <= XAPIC_ID_MAX {
        let apic_u8 = u8::try_from(apic_id).map_err(|_| DtbError::Internal)?;
        let e = ProcessorLocalApicAffinity::new(apic_u8, proximity_domain, flags);
        write_entry(slot, pos, e.as_bytes())
    } else {
        let e = X2ApicAffinity::new(apic_id, proximity_domain, flags);
        write_entry(slot, pos, e.as_bytes())
    }
}
