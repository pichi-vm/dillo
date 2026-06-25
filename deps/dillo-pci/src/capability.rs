// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Portions derived from Firecracker (https://github.com/firecracker-microvm/firecracker),
// licensed under Apache-2.0 OR BSD-3-Clause.

//! Standard PCI capability IDs used in the capability linked list.

/// PCI Power Management capability ID.
pub const CAP_ID_PM: u8 = 0x01;
/// PCI Vendor-Specific capability ID.
pub const CAP_ID_VENDOR: u8 = 0x09;
/// PCI Express capability ID.
pub const CAP_ID_PCIE: u8 = 0x10;
/// MSI-X capability ID.
pub const CAP_ID_MSIX: u8 = 0x11;
