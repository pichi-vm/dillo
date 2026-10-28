// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Trait-generic DTB walker.
//!
//! [`DtbNode<N>`] wraps a `devtree::NodeView` together with the
//! `#address-cells` / `#size-cells` declared by its parent. This
//! eliminates the per-call threading of cell counts that infested
//! the previous design.
//!
//! Property absence (`Option::None`) is *not* error-conflated with
//! property malformation (`Result::Err`). Decisions about whether
//! absence is OK live with the caller (count helpers), per the
//! "partial binding = error, absent binding = OK if optional" rule.
//!
//! `#address-cells` / `#size-cells` follow FDT v17 defaults (2 and
//! 1 respectively) when absent — but a malformed value propagates as
//! an error rather than silently falling back.

use devtree::{NodeView, PropertyView};

use crate::error::{DtbError, Site};

/// A devicetree node, plus the parent's `#address-cells` and
/// `#size-cells` (which govern how this node's own `reg` is decoded)
/// and its categorical [`Site`] — used to tag every error this node
/// produces, so callers always get site-attributed errors rather than
/// opaque parser-level ones.
#[derive(Clone, Copy)]
pub(crate) struct DtbNode<N: NodeView + Copy> {
    pub node: N,
    pub(crate) parent_addr_cells: u32,
    pub(crate) parent_size_cells: u32,
    pub(crate) site: Site,
}

impl<N: NodeView + Copy> DtbNode<N> {
    /// Wrap the tree's root. The DT spec doesn't give the root a
    /// parent, but we conventionally use the FDT v17 defaults
    /// (2, 1) for any cell-aware reads on the root itself.
    pub(crate) fn root_of(root: N) -> Self {
        Self {
            node: root,
            parent_addr_cells: 2,
            parent_size_cells: 1,
            site: Site::Root,
        }
    }

    /// Look up a direct child by name. The returned `DtbNode` carries
    /// `child_site` for error attribution; its `parent_*_cells` come
    /// from `self`'s own cell declarations.
    ///
    /// # Errors
    /// `MalformedProperty` (with `self.site`) if `#address-cells` or
    /// `#size-cells` on `self` is malformed.
    pub(crate) fn child(&self, name: &str, child_site: Site) -> Result<Option<Self>, DtbError> {
        let Some(child) = self.node.child(name) else {
            return Ok(None);
        };
        let (a, s) = self.own_cells()?;
        Ok(Some(Self {
            node: child,
            parent_addr_cells: a,
            parent_size_cells: s,
            site: child_site,
        }))
    }

    /// Iterate direct children with cells inherited from `self`. Each
    /// child inherits `self.site` — callers needing a different site
    /// per child (e.g. enumerating `/cpus/cpu@N`) should use
    /// [`Self::child`] with an explicit `child_site` instead.
    ///
    /// # Errors
    /// `MalformedProperty` (with `self.site`) if `#address-cells` or
    /// `#size-cells` on `self` is malformed.
    pub(crate) fn children(&self) -> Result<impl Iterator<Item = Self> + '_, DtbError> {
        let (a, s) = self.own_cells()?;
        let parent_site = self.site;
        Ok(self.node.children().map(move |c| Self {
            node: c,
            parent_addr_cells: a,
            parent_size_cells: s,
            site: parent_site,
        }))
    }

    /// Read `#address-cells` and `#size-cells` declared on this node
    /// (for its children's reg decoding). Returns FDT defaults when
    /// absent; tags malformed values with `self.site`.
    fn own_cells(&self) -> Result<(u32, u32), DtbError> {
        let a = self.property_u32_opt("#address-cells")?.unwrap_or(2);
        let s = self.property_u32_opt("#size-cells")?.unwrap_or(1);
        Ok((a, s))
    }

    /// The node's name.
    pub(crate) fn name(&self) -> &str {
        self.node.name()
    }

    /// `true` iff this node's `compatible` lists `want`.
    ///
    /// # Errors
    /// `MalformedProperty` (with `self.site`) if `compatible` exists
    /// but is malformed.
    pub(crate) fn has_compatible(&self, want: &str) -> Result<bool, DtbError> {
        let Some(prop) = self.node.property("compatible") else {
            return Ok(false);
        };
        Ok(prop
            .as_strs()
            .ok_or(DtbError::MalformedProperty {
                site: self.site,
                property: "compatible",
            })?
            .any(|s| s == want))
    }

    /// Iterate this node's `reg` property as `(base, size)` pairs
    /// decoded using `parent_addr_cells` / `parent_size_cells`. The
    /// `site` argument overrides `self.site` for error attribution —
    /// some callers (e.g. `find_lapic`) hold a generic-walk DtbNode but
    /// want to attribute reg errors to a specific binding site.
    ///
    /// # Errors
    /// `MissingProperty` if `reg` is absent.
    /// `UnsupportedAddressCells` / `UnsupportedSizeCells` if cell
    /// counts are outside the x86_64-supported range.
    pub(crate) fn reg(&self, site: Site) -> Result<RegIter<N::Property>, DtbError> {
        let prop = self.node.property("reg").ok_or(DtbError::MissingProperty {
            site,
            property: "reg",
        })?;
        RegIter::new(prop, self.parent_addr_cells, self.parent_size_cells, site)
    }

    /// Read a required single u32 property by name. Errors are tagged
    /// with the caller-supplied `site` (rather than `self.site`) so
    /// shared dtb_node walks can attribute property failures to a
    /// specific binding role.
    ///
    /// # Errors
    /// `MissingProperty` if absent. `MalformedProperty` if present but
    /// not a single u32 cell.
    pub(crate) fn property_u32(&self, name: &'static str, site: Site) -> Result<u32, DtbError> {
        let prop = self.node.property(name).ok_or(DtbError::MissingProperty {
            site,
            property: name,
        })?;
        prop.as_u32().ok_or(DtbError::MalformedProperty {
            site,
            property: name,
        })
    }

    /// Decode a 2-cell `interrupts` property: `<pin, sense>`. Returns
    /// `(gsi, sense)`. Validates that exactly 2 cells are present.
    ///
    /// # Errors
    /// `MissingProperty` if absent. `MalformedProperty` if not exactly
    /// 2 u32 cells.
    pub(crate) fn decode_interrupts_2(&self, site: Site) -> Result<(u32, u32), DtbError> {
        let prop = self
            .node
            .property("interrupts")
            .ok_or(DtbError::MissingProperty {
                site,
                property: "interrupts",
            })?;
        let mut cells = prop.as_u32s().ok_or(DtbError::MalformedProperty {
            site,
            property: "interrupts",
        })?;
        let malformed = || DtbError::MalformedProperty {
            site,
            property: "interrupts",
        };
        let gsi = cells.next().ok_or_else(malformed)?;
        let sense = cells.next().ok_or_else(malformed)?;
        if cells.next().is_some() {
            return Err(malformed());
        }
        Ok((gsi, sense))
    }

    /// Read a u32 property if present.
    ///
    /// # Errors
    /// `MalformedProperty` (with `self.site`) if present but
    /// not a single u32 cell.
    pub(crate) fn property_u32_opt(&self, name: &'static str) -> Result<Option<u32>, DtbError> {
        match self.node.property(name) {
            None => Ok(None),
            Some(p) => Ok(Some(p.as_u32().ok_or(DtbError::MalformedProperty {
                site: self.site,
                property: name,
            })?)),
        }
    }
}

/// Iterator over `(base, size)` pairs from a `reg` property.
///
/// Holds the property by value (it is `Copy`) so the iterator can be
/// returned without a self-referential borrow.
pub(crate) struct RegIter<P: PropertyView> {
    prop: P,
    addr_cells: u32,
    size_cells: u32,
    pos: usize,
}

impl<P: PropertyView> RegIter<P> {
    pub(crate) fn new(
        prop: P,
        addr_cells: u32,
        size_cells: u32,
        site: Site,
    ) -> Result<Self, DtbError> {
        if !matches!(addr_cells, 1..=2) {
            return Err(DtbError::UnsupportedAddressCells {
                site,
                found: addr_cells,
            });
        }
        if !matches!(size_cells, 0..=2) {
            return Err(DtbError::UnsupportedSizeCells {
                site,
                found: size_cells,
            });
        }
        Ok(Self {
            prop,
            addr_cells,
            size_cells,
            pos: 0,
        })
    }
}

impl<P: PropertyView> Iterator for RegIter<P> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.prop.as_ref();
        let base = fold_be_cells(raw, &mut self.pos, self.addr_cells)?;
        let size = fold_be_cells(raw, &mut self.pos, self.size_cells)?;
        Some((base, size))
    }
}

/// Fold the next `n_cells` big-endian u32 cells starting at `*pos`
/// into a u64, advancing `*pos`. Returns `None` if fewer cells are
/// available than requested.
#[inline]
pub(crate) fn fold_be_cells(raw: &[u8], pos: &mut usize, n_cells: u32) -> Option<u64> {
    let mut acc: u64 = 0;
    for _ in 0..n_cells {
        let end = pos.checked_add(4)?;
        let slice = raw.get(*pos..end)?;
        let arr: [u8; 4] = slice.try_into().ok()?;
        acc = (acc << 32) | u64::from(u32::from_be_bytes(arr));
        *pos = end;
    }
    Some(acc)
}

/// Iterate a PCI host bridge's `ranges` property as
/// `(space_code, child_addr, parent_addr, size)` quadruples per the
/// Open Firmware PCI bus binding. Each entry is
/// `3 + parent_addr_cells + 2` cells: phys.hi (space code in the top
/// byte) + phys.mid + phys.lo + cpu.hi + (cpu.mid)? + cpu.lo +
/// size.hi + size.lo.
///
/// The pci node's own `#address-cells = 3` and `#size-cells = 2` are
/// hardcoded by the binding; this iterator assumes both and uses the
/// node's `parent_addr_cells` for the CPU-side width.
pub(crate) struct PciRangesIter<P: PropertyView> {
    prop: P,
    parent_addr_cells: u32,
    pos: usize,
}

/// One decoded PCI `ranges` entry. `space_code` is the top byte of
/// phys.hi: `0x01 = I/O`, `0x02 = 32-bit Mem`, `0x03 = 64-bit Mem`.
/// `parent_addr` is the CPU-side base; `size` is the range length.
/// (The bus-side child address is dropped — every consumer today
/// maps 1:1, so duplicating it just invites confusion.)
#[derive(Debug, Clone, Copy)]
pub(crate) struct PciRange {
    pub space_code: u8,
    pub parent_addr: u64,
    pub size: u64,
}

impl<P: PropertyView> PciRangesIter<P> {
    pub(crate) fn new(prop: P, parent_addr_cells: u32, site: Site) -> Result<Self, DtbError> {
        if !matches!(parent_addr_cells, 1..=2) {
            return Err(DtbError::UnsupportedAddressCells {
                site,
                found: parent_addr_cells,
            });
        }
        Ok(Self {
            prop,
            parent_addr_cells,
            pos: 0,
        })
    }
}

impl<P: PropertyView> Iterator for PciRangesIter<P> {
    type Item = PciRange;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.prop.as_ref();
        // phys.hi is one cell carrying the space code in its top byte.
        let phys_hi = fold_be_cells(raw, &mut self.pos, 1)?;
        // phys.mid:phys.lo — bus-side address, consumed and discarded
        // (1:1 with parent_addr in our flat-mapped layout).
        let _ = fold_be_cells(raw, &mut self.pos, 2)?;
        let parent_addr = fold_be_cells(raw, &mut self.pos, self.parent_addr_cells)?;
        // size.hi:size.lo (pci #size-cells = 2 always).
        let size = fold_be_cells(raw, &mut self.pos, 2)?;
        Some(PciRange {
            space_code: u8::try_from((phys_hi >> 24) & 0x03).ok()?,
            parent_addr,
            size,
        })
    }
}

impl<N: NodeView + Copy> DtbNode<N> {
    /// Iterate this PCI host bridge's `ranges` property. Returns an
    /// empty iterator if the property is absent — the PCI binding
    /// permits a host bridge with no `ranges` (e.g. config-space-only
    /// or test fixtures), and the consumers (count + emit) treat
    /// absent as "no windows".
    ///
    /// # Errors
    /// `UnsupportedAddressCells` if `parent_addr_cells` is outside 1..=2.
    pub(crate) fn pci_ranges(&self) -> Result<Option<PciRangesIter<N::Property>>, DtbError> {
        let Some(prop) = self.node.property("ranges") else {
            return Ok(None);
        };
        Ok(Some(PciRangesIter::new(
            prop,
            self.parent_addr_cells,
            Site::PciHost,
        )?))
    }
}

/// Iterate the cell stream of a `reg` property as raw u32 cells.
/// Useful when callers want cells without the base/size grouping
/// (e.g., for `bus-range` which is two raw u32 cells regardless of
/// parent cell counts).
#[inline]
pub(crate) fn cells_as_u32s(raw: &[u8]) -> impl Iterator<Item = u32> + '_ {
    raw.as_chunks::<4>()
        .0
        .iter()
        .copied()
        .map(u32::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_one_cell() {
        let raw = &[0x00, 0x00, 0x00, 0x42, 0xFF, 0xFF];
        let mut pos = 0;
        assert_eq!(fold_be_cells(raw, &mut pos, 1), Some(0x42));
        assert_eq!(pos, 4);
    }

    #[test]
    fn fold_two_cells() {
        let raw = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut pos = 0;
        assert_eq!(fold_be_cells(raw, &mut pos, 2), Some(0xDEAD_BEEF_CAFE_BABE));
        assert_eq!(pos, 8);
    }

    #[test]
    fn fold_zero_cells_is_zero() {
        let raw: &[u8] = &[];
        let mut pos = 0;
        assert_eq!(fold_be_cells(raw, &mut pos, 0), Some(0));
        assert_eq!(pos, 0);
    }

    #[test]
    fn fold_insufficient_bytes() {
        let raw = &[0x00, 0x00, 0x00];
        let mut pos = 0;
        assert_eq!(fold_be_cells(raw, &mut pos, 1), None);
    }

    // RegIter is now generic over P: PropertyView. End-to-end testing
    // of the iterator happens via the pipeline integration tests with
    // real devtree-parsed properties; the cell-folding primitive is
    // tested directly above via fold_be_cells.

    #[test]
    fn cells_as_u32s_basic() {
        let raw = &[
            0x00, 0x00, 0x00, 0x00, // 0
            0x00, 0x00, 0x00, 0xFF, // 0xFF
        ];
        let v: alloc::vec::Vec<u32> = cells_as_u32s(raw).collect();
        assert_eq!(v, alloc::vec![0u32, 0xFF]);
    }

    // Stub for #[cfg(test)] only — std is available in tests.
    extern crate alloc;
}
