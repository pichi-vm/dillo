// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PCI Express Memory-mapped Configuration Space Description.
//!
//! Per the PCI Firmware Specification. Header is SDT header +
//! 8-byte reserved (44 bytes). Body is a packed array of 16-byte
//! allocation entries.
//!
//! Per-ECAM (base, bus_start, bus_end) details are re-derived during
//! emit from `root.children()` filtered by `compatible =
//! "pci-host-ecam-generic"`, using the same parser as [`crate::count::run`].

use devtree::TreeView;
use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::sdt::SdtHeader;
use super::set_sdt_checksum;
use super::write_entry;
use crate::dtb::DtbNode;
use crate::error::{DtbError, Site};
use crate::oem::OemIdentity;

/// MCFG revision per PCI Firmware Spec.
pub(crate) const REVISION: u8 = 1;

/// MCFG header — SDT header + 8-byte reserved.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct McfgHeader {
    pub header: SdtHeader,
    pub reserved: U64,
}

impl McfgHeader {
    pub(crate) const SIZE: usize = 44;

    /// Total MCFG byte cost: header + one allocation entry per ECAM.
    pub(crate) fn total_size(ecam_count: u32) -> Result<usize, DtbError> {
        let regions_bytes = usize::try_from(ecam_count)
            .ok()
            .and_then(|n| n.checked_mul(McfgAllocation::SIZE))
            .ok_or(DtbError::Internal)?;
        Self::SIZE
            .checked_add(regions_bytes)
            .ok_or(DtbError::Internal)
    }
}

/// One ECAM allocation.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct McfgAllocation {
    pub base_address: U64,
    pub segment_group: U16,
    pub bus_start: u8,
    pub bus_end: u8,
    pub reserved: U32,
}

impl McfgAllocation {
    pub(crate) const SIZE: usize = 16;
}

/// Emit a complete, checksummed MCFG into `slot`.
///
/// Walks `root.children()` filtered by `compatible =
/// "pci-host-ecam-generic"` to derive per-ECAM details. Errors from
/// the re-walk are defense-in-depth: [`crate::count::run`] validated
/// the same nodes with the same parser, so they cannot fire on a
/// tree that [`crate::count::run`] accepted.
pub(crate) fn emit<T: TreeView>(
    slot: &mut [u8],
    oem: &OemIdentity,
    tree: &T,
) -> Result<(), DtbError> {
    let length = super::sdt_length_from_slot(slot)?;
    let header = McfgHeader {
        header: SdtHeader::new(*b"MCFG", length, REVISION, oem),
        reserved: U64::new(0),
    };
    super::write_header(slot, &header)?;

    let mut pos = McfgHeader::SIZE;
    let root = DtbNode::root_of(tree.root());
    for child in root.children()? {
        if !child.has_compatible("pci-host-ecam-generic")? {
            continue;
        }
        let base = child
            .reg(Site::PciHost)?
            .next()
            .ok_or(DtbError::MissingProperty {
                site: Site::PciHost,
                property: "reg",
            })?
            .0;
        let (bus_start, bus_end) = child.decode_pci_bus_range()?;
        // PCIe segment 0. Segments solve 256-bus exhaustion and
        // independent-root-complex topologies in physical hardware;
        // HW-Reduced virtio guests don't approach either limit.
        // DT spec doesn't standardize PCI segment numbering, and
        // `linux,pci-domain` is an OS-specific extension (see the
        // "DT binding scope" section in the crate-level docs) we
        // deliberately don't consume. A future multi-segment caller
        // would need a generic binding, not this Linux property.
        let alloc = McfgAllocation {
            base_address: U64::new(base),
            segment_group: U16::new(0),
            bus_start,
            bus_end,
            reserved: U32::new(0),
        };
        pos = write_entry(slot, pos, alloc.as_bytes())?;
    }
    let _ = pos;
    set_sdt_checksum(slot)
}
