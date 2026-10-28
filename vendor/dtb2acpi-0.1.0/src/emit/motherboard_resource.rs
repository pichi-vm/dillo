// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! DSDT motherboard resource emitter.
//!
//! Linux's late ECAM validation accepts an MCFG allocation only when the ECAM
//! range is reserved by firmware, commonly through a `PNP0C02` motherboard
//! resource device. MCFG names the ECAM base; this DSDT device reserves the
//! same DTB-derived `reg` window so an ECAM-only x86 guest does not need legacy
//! CF8/CFC config-space probing.

use devtree::TreeView;

use super::aml;
use crate::dtb::DtbNode;
use crate::error::{DtbError, Site};

/// `_HID` + `_UID`.
const FIXED_NAMES_BYTES: usize = (1 + 4 + 1 + 4) + (1 + 4 + 1 + 1);

const fn motherboard_aml_bytes() -> usize {
    let descriptors = aml::QWORD_MEMORY_BYTES + aml::END_TAG_BYTES;
    let crs = aml::CRS_WRAPPER_BYTES + descriptors;
    let body = FIXED_NAMES_BYTES.saturating_add(crs);
    body.saturating_add(aml::PKG_LENGTH_BYTES).saturating_add(6)
}

pub(crate) fn dsdt_total_bytes<T: TreeView>(tree: &T) -> Result<usize, DtbError> {
    let root = DtbNode::root_of(tree.root());
    let mut total = 0usize;
    for child in root.children()? {
        if !child.has_compatible("pci-host-ecam-generic")? {
            continue;
        }
        total = total
            .checked_add(motherboard_aml_bytes())
            .ok_or(DtbError::Internal)?;
    }
    Ok(total)
}

pub(crate) fn emit<T: TreeView>(slot: &mut [u8], pos: usize, tree: &T) -> Result<usize, DtbError> {
    let root = DtbNode::root_of(tree.root());
    let mut cursor = pos;
    let mut index: u8 = 0;
    for child in root.children()? {
        if !child.has_compatible("pci-host-ecam-generic")? {
            continue;
        }
        let (base, size) = child.reg(Site::PciHost)?.next().ok_or(DtbError::Internal)?;
        cursor = write_one_device(slot, cursor, index, base, size)?;
        index = index.checked_add(1).ok_or(DtbError::Internal)?;
    }
    Ok(cursor)
}

fn write_one_device(
    slot: &mut [u8],
    pos: usize,
    index: u8,
    base: u64,
    size: u64,
) -> Result<usize, DtbError> {
    let total = motherboard_aml_bytes();

    let pos = aml::write_device_header(slot, pos, &aml::name_seg_indexed(b"MBR", index), total)?;

    let pos = aml::write_name_dword(slot, pos, b"_HID", aml::eisaid(b"PNP0C02"))?;
    let pos = aml::write_name_byte(slot, pos, b"_UID", index)?;

    let descriptors_bytes = aml::QWORD_MEMORY_BYTES + aml::END_TAG_BYTES;
    let pos = aml::write_crs_buffer_header(slot, pos, descriptors_bytes)?;
    let pos = aml::write_qword_memory(slot, pos, base, size)?;
    aml::write_end_tag(slot, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motherboard_device_size_is_stable() {
        assert_eq!(motherboard_aml_bytes(), 84);
    }

    #[test]
    fn motherboard_name_first_few() {
        assert_eq!(aml::name_seg_indexed(b"MBR", 0), *b"MBR0");
        assert_eq!(aml::name_seg_indexed(b"MBR", 9), *b"MBR9");
        assert_eq!(aml::name_seg_indexed(b"MBR", 10), *b"MBRA");
    }
}
