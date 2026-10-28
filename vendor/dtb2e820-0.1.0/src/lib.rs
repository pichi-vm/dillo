// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `dtb2e820` — translate a flattened devicetree into a Linux x86
//! e820 memory-map entry list.
//!
//! `no_std`, no allocations, `forbid(unsafe_code)`. Caller owns the
//! storage: hand a `&mut [E820Entry]` to the [`ExtractE820`]
//! extension method on `TreeView` and read back the count written.
//!
//! # Usage
//!
//! ```
//! use devtree::Tree;
//! use dtb2e820::{E820Entry, ExtractE820, E820Type};
//!
//! let dtb: &[u8] = include_bytes!("../tests/data/basic.dtb");
//! let tree: Tree<'_> = Tree::parse(dtb).unwrap();
//!
//! // Pre-seed any non-DT entries (e.g. ACPI workspace) at the head,
//! // then hand the rest to extract_e820.
//! let mut buf = [E820Entry::default(); 128];
//! buf[0] = E820Entry { addr: 0x4_0000_0000, size: 0x2000, kind: E820Type::Acpi };
//! let n = tree.extract_e820(&mut buf[1..]).unwrap();
//! for e in &buf[..1 + n] {
//!     let _ = (e.addr, e.size, e.kind);
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use devtree::{NodeView, PropertyView, TreeView};

// === E820Type ===============================================================

/// Linux e820 entry type. Discriminants match Linux's `enum
/// e820_type` (`arch/x86/include/asm/e820/types.h`); the full set
/// is enumerated so callers can construct entries of any standard
/// type, not only the ones this crate emits from DT.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum E820Type {
    /// Invalid — placeholder for an uninitialized buffer slot.
    #[default]
    Invalid = 0,

    /// Usable RAM (Linux's `E820_TYPE_RAM`).
    Usable = 1,

    /// Reserved by the firmware: MMIO holes, BIOS regions, etc.
    Reserved = 2,

    /// ACPI tables — reclaimable by the OS after parsing.
    Acpi = 3,

    /// ACPI Non-Volatile Storage — preserved across S3 sleep.
    AcpiNvs = 4,

    /// Memory marked unusable (e.g. due to detected errors).
    Unusable = 5,

    /// Persistent memory (NVDIMM, byte-addressable storage).
    Pmem = 7,

    /// Legacy persistent RAM marker (`CONFIG_X86_PMEM_LEGACY`).
    Pram = 12,

    /// Reserved RAM the kernel itself carves out of the e820 map
    /// at boot.
    ReservedKern = 128,

    /// Soft-reserved — reserved by default but reclaimable via
    /// admin policy (CXL / EFI memory map translation).
    SoftReserved = 0xefff_ffff,
}

impl E820Type {
    /// Decode a node's `reg` property as a sequence of entries of
    /// this kind, writing into `out`. Returns the count written.
    ///
    /// Assumes `#address-cells = 2 / #size-cells = 2`: every
    /// `(addr, size)` pair is 4 BE `u32` cells. Returns `Ok(0)` if
    /// the node has no `reg`.
    fn append_reg<NV: NodeView>(self, node: &NV, out: &mut [E820Entry]) -> Result<usize, Error> {
        let Some(reg) = node.property("reg") else {
            return Ok(0);
        };

        let mut cells = reg.as_u32s().ok_or(Error::BadRegShape)?;
        let mut n: usize = 0;
        while let Some(entry) = self.entry(&mut cells)? {
            let slot = out.get_mut(n).ok_or(Error::BufferFull)?;
            *slot = entry;
            n += 1;
        }

        Ok(n)
    }

    /// Consume one 4-cell `(addr, size)` group from `cells` and
    /// build an entry of this kind.
    ///
    /// - `Ok(Some(entry))` — full group consumed and decoded.
    /// - `Ok(None)` — iterator exhausted at a group boundary
    ///   (clean end; the caller's loop terminates here).
    /// - `Err(BadRegShape)` — iterator ended partway through a
    ///   group (1, 2, or 3 cells consumed without a 4th).
    fn entry<I: Iterator<Item = u32>>(self, cells: &mut I) -> Result<Option<E820Entry>, Error> {
        let Some(addr_hi) = cells.next() else {
            return Ok(None);
        };

        let addr_lo = cells.next().ok_or(Error::BadRegShape)?;
        let size_hi = cells.next().ok_or(Error::BadRegShape)?;
        let size_lo = cells.next().ok_or(Error::BadRegShape)?;
        let addr = (u64::from(addr_hi) << 32) | u64::from(addr_lo);
        let size = (u64::from(size_hi) << 32) | u64::from(size_lo);
        Ok(Some(E820Entry {
            addr,
            size,
            kind: self,
        }))
    }
}

// === E820Entry ==============================================================

/// One e820 entry. Layout matches Linux's `struct boot_e820_entry`
/// byte-for-byte (`__u64 addr; __u64 size; __u32 type;` packed,
/// little-endian on x86), so `size_of::<E820Entry>()` is 20 and
/// `&[E820Entry]` is the wire stream Linux's boot_params expects.
///
/// This is a write-only producer: build entries via the [`E820Type`]
/// constructors and hand `&[E820Entry]` to the kernel. Because `kind`
/// is an enum, reinterpreting *arbitrary* wire bytes back into an
/// `E820Entry` (a type value outside [`E820Type`]) is undefined
/// behavior — do not transmute untrusted bytes into this type.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct E820Entry {
    /// Base GPA of this region.
    pub addr: u64,

    /// Length in bytes.
    pub size: u64,

    /// Linux e820 type.
    pub kind: E820Type,
}

/// Adds [`extract_e820`](Self::extract_e820) to any [`TreeView`].
pub trait ExtractE820 {
    /// Walk this tree's root children and write classified entries
    /// into `out`, returning the count written:
    ///
    /// | Source                                                    | Type     |
    /// | --------------------------------------------------------- | -------- |
    /// | `/memory@*` `reg`                                         | USABLE   |
    /// | `/reserved-memory/*` `reg`                                | RESERVED |
    /// | Root children with `compatible = "pci-host-ecam-generic"` | RESERVED |
    ///
    /// The PCIe-ECAM rule is load-bearing: Linux's
    /// `pci_mmcfg_check_reserved` rejects the ECAM window unless it
    /// appears as e820 RESERVED, and no PCI devices are enumerated
    /// otherwise.
    ///
    /// # Errors
    ///
    /// - [`Error::BufferFull`] — `out` ran out of slots before every
    ///   entry was written; size it larger and retry.
    /// - [`Error::BadRegShape`] — a `reg` property was malformed (byte
    ///   length not a multiple of 4, or ending partway through an
    ///   `(addr, size)` 4-cell tuple).
    fn extract_e820(&self, out: &mut [E820Entry]) -> Result<usize, Error>;
}

impl<T: TreeView> ExtractE820 for T {
    fn extract_e820(&self, out: &mut [E820Entry]) -> Result<usize, Error> {
        let mut n: usize = 0;
        for child in self.root().children() {
            let name = child.name();
            let seg = name.split_once('@').map_or(name, |(s, _)| s);
            let kind = match seg {
                "memory" => E820Type::Usable,
                "reserved-memory" => {
                    for sub in child.children() {
                        n += E820Type::Reserved.append_reg(&sub, &mut out[n..])?;
                    }
                    continue;
                }
                _ if child.has_compatible("pci-host-ecam-generic") => E820Type::Reserved,
                _ => continue,
            };

            n += kind.append_reg(&child, &mut out[n..])?;
        }
        Ok(n)
    }
}

/// Private extension on `NodeView`: `is_some_and`-style compatible-string
/// check spelled out long-hand because `as_strs` borrows from the property,
/// so `.and_then(|p| p.as_strs())` breaks lifetimes.
trait NodeExt {
    fn has_compatible(&self, target: &str) -> bool;
}

impl<N: NodeView> NodeExt for N {
    fn has_compatible(&self, target: &str) -> bool {
        let Some(prop) = self.property("compatible") else {
            return false;
        };
        let Some(mut strs) = prop.as_strs() else {
            return false;
        };
        strs.any(|s| s == target)
    }
}

// === Error ==================================================================

/// Failures returned by [`E820Type::append_reg`] and
/// [`ExtractE820::extract_e820`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// The output slice is full — caller must size it larger.
    BufferFull,

    /// A `reg` property is malformed: either its byte length isn't a
    /// multiple of 4, or it ends partway through an `(addr, size)`
    /// 4-cell tuple.
    BadRegShape,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferFull => f.write_str("e820 buffer full"),
            Self::BadRegShape => f.write_str("malformed `reg` property"),
        }
    }
}

impl core::error::Error for Error {}
