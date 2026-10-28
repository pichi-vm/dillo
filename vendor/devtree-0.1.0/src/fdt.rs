// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Parsed devicetree.
//!
//! [`Tree::parse`] validates everything in one pass: header layout,
//! every token in the structure block, every property's name lookup
//! into the strings block, tree depth, root presence, memory-reservation
//! terminator, reserved-phandle values. After it returns, every walk
//! is **infallible** — iterators yield `T` directly, not `Result<T>`.
//!
//! The trust-boundary discipline pays off here: callers do not have to
//! pepper their walks with `?`, and they can be certain that anything
//! they observe came from a well-formed blob.

use core::num::NonZeroU32;

use crate::cursor::{self, CstrError, align_up_4};
use crate::error::{Error, Limit, MalformedKind};
use crate::header::Header;

pub(crate) const FDT_BEGIN_NODE: u32 = 0x1;
pub(crate) const FDT_END_NODE: u32 = 0x2;
pub(crate) const FDT_PROP: u32 = 0x3;
pub(crate) const FDT_NOP: u32 = 0x4;
pub(crate) const FDT_END: u32 = 0x9;

// Default caps live as literals on Tree's const generic defaults.
// Tests that need to exercise the cap should override the const
// generic (e.g. `Tree::<'_, 4>::parse(...)`) rather than reference a
// shared constant — that decouples the test from the default value.

/// A reserved-memory entry from the FDT memory-reservation block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    /// Physical address of the reserved region, in bytes.
    pub address: u64,
    /// Length of the reserved region, in bytes.
    pub size: u64,
}

/// Parsed flattened devicetree blob. Borrows the underlying bytes.
/// Every walk is infallible — `parse` already validated everything.
///
/// The two const generics bound the parse-time recursion checks:
/// - `DEPTH` — maximum tree depth (default `64`). Real DTBs are 5–10
///   deep; 64 leaves headroom while bounding adversarial stack use.
/// - `MEMRSV_CAP` — maximum memory-reservation entries (default
///   `1024`). Real DTBs carry a handful at most.
///
/// They appear in the type only as a *parse-time contract*; the
/// stored data is identical regardless of the chosen caps. Use the
/// defaults (`let fdt: Tree = Tree::parse(blob)?`) unless you have a
/// specific trust budget that requires otherwise.
#[derive(Debug, Clone, Copy)]
pub struct Tree<'a, const DEPTH: u32 = 64, const MEMRSV_CAP: u32 = 1024> {
    blob: &'a [u8],
    totalsize: u32,
    struct_block: &'a [u8],
    strings_block: &'a [u8],
    // Memrsv entries, sliced from `off_mem_rsvmap` up to (but not
    // including) the `(0,0)` terminator the validator consumed.
    memrsv_block: &'a [u8],
    // Position immediately after the root BEGIN_NODE + name + padding.
    root_body_offset: u32,
    // Empty string in any spec-compliant DTB.
    root_name: &'a str,
    // Computed at parse so the overlay applier can derive its phandle
    // shift without re-walking the base tree. `0` when no phandles.
    max_phandle: u32,
    // Sum of `(prop.name.len() + 1)` over every property token. Used
    // as a strict upper bound on emitted strings-table size during
    // overlay apply (which emits without dedup).
    prop_name_bytes: usize,
    // `/__symbols__` body offset + name, cached at parse so overlay
    // label-target resolution doesn't re-walk root children.
    symbols_root: Option<(u32, &'a str)>,
}

impl<'a, const DEPTH: u32, const MEMRSV_CAP: u32> Tree<'a, DEPTH, MEMRSV_CAP> {
    /// Iterate the root node's children. Yields items borrowing from
    /// the underlying blob (`'a`) rather than from `self`, so the
    /// iterator can outlive a temporary root-node value.
    pub(crate) fn root_children(self) -> ChildIter<'a> {
        ChildIter {
            struct_block: self.struct_block,
            strings_block: self.strings_block,
            pos: self.root_body_offset as usize,
        }
    }

    /// Length of the structure block in bytes.
    pub(crate) fn struct_block_len(&self) -> usize {
        self.struct_block.len()
    }

    /// Sum of `(prop.name.len() + 1)` over every property in this
    /// tree, computed at parse.
    pub(crate) fn prop_name_bytes(&self) -> usize {
        self.prop_name_bytes
    }

    /// Maximum phandle observed at parse, used by the overlay applier
    /// to compute its shift without re-walking the base.
    pub(crate) fn max_phandle(&self) -> u32 {
        self.max_phandle
    }

    /// `/__symbols__` node if the blob carries one, resolved at parse.
    pub(crate) fn symbols(&self) -> Option<Node<'a>> {
        self.symbols_root.map(|(off, name)| Node {
            struct_block: self.struct_block,
            strings_block: self.strings_block,
            body_offset: off,
            name,
        })
    }

    /// Parse a flattened devicetree blob and fully validate it. After
    /// this returns successfully, every subsequent walk is infallible.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] for any header-level or structure-block
    ///   invariant failure (bad magic, version, alignment, bad token,
    ///   malformed string, no root, reserved phandle value, etc.).
    /// - [`Error::LimitExceeded`] for depth or reservation-count
    ///   caps exceeded.
    pub fn parse(blob: &'a [u8]) -> Result<Self, Error> {
        let header = Header::parse(blob)?;

        // Pre-slice the three blocks. Header::parse already validated:
        //   header_size <= memrsv_off + 16 <= struct_off <= struct_off+struct_size <= strings_off <= strings_off+strings_size <= total <= blob.len()
        // Local allow because the lint regime would otherwise force
        // `.get(..).ok_or(unreachable error)` for fully-validated bounds.
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        let (struct_block, strings_block, memrsv_region) = {
            let struct_off = header.off_dt_struct as usize;
            let struct_end = struct_off + header.size_dt_struct as usize;
            let strings_off = header.off_dt_strings as usize;
            let strings_end = strings_off + header.size_dt_strings as usize;
            let memrsv_off = header.off_mem_rsvmap as usize;
            // memrsv region extends from memrsv_off up to struct_off
            // (canonical layout enforced by Header::parse). Bounded
            // walk inside this region locates the (0,0) terminator.
            (
                &blob[struct_off..struct_end],
                &blob[strings_off..strings_end],
                &blob[memrsv_off..struct_off],
            )
        };

        let memrsv_block = validate_memrsv(memrsv_region, MEMRSV_CAP)?;
        let (root_body_offset, root_name, max_phandle, prop_name_bytes) =
            validate_struct(struct_block, strings_block, DEPTH)?;

        // Cache /__symbols__'s body offset for fast lookup at overlay
        // apply time. One pass over root children — cheap.
        let symbols_root = find_child_by_bytes(
            struct_block,
            strings_block,
            root_body_offset as usize,
            b"__symbols__",
        )
        .map(|n| (n.body_offset, n.name));

        Ok(Tree {
            blob,
            totalsize: header.totalsize,
            struct_block,
            strings_block,
            memrsv_block,
            root_body_offset,
            root_name,
            max_phandle,
            prop_name_bytes,
            symbols_root,
        })
    }
}

fn find_phandle_in(node: Node<'_>, ph: NonZeroU32, depth: u32) -> Option<Node<'_>> {
    if depth == 0 {
        return None;
    }
    if node.phandle() == Some(ph) {
        return Some(node);
    }
    let next_depth = depth.saturating_sub(1);
    for child in node.children() {
        if let Some(found) = find_phandle_in(child, ph, next_depth) {
            return Some(found);
        }
    }
    None
}

/// A handle to a node in a parsed FDT. `Copy` — cheap to pass around.
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    pub(crate) struct_block: &'a [u8],
    pub(crate) strings_block: &'a [u8],
    /// Offset into `struct_block` where this node's body begins
    /// (immediately after BEGIN_NODE + name + padding).
    pub(crate) body_offset: u32,
    pub(crate) name: &'a str,
}

/// A property in a parsed FDT — name and raw value bytes.
#[derive(Debug, Clone, Copy)]
pub struct Property<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a [u8],
    pub(crate) value_struct_offset: u32,
}

// Equality is over the observable `(name, value)` only. `value_struct_offset`
// is an internal locator (where the value sits in the blob) used by the
// overlay applier; two properties with the same name and bytes read from
// different positions are equal, matching the semantics of the owned
// representation (`OwnedProperty`).
impl PartialEq for Property<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.value == other.value
    }
}

impl Eq for Property<'_> {}

// ---------------------------------------------------------------------------
// Public read-side traits.
// ---------------------------------------------------------------------------

impl crate::sealed::Sealed for Property<'_> {}
impl crate::sealed::Sealed for Node<'_> {}
impl<const D: u32, const M: u32> crate::sealed::Sealed for Tree<'_, D, M> {}

/// Read-side view of a parsed property's value bytes.
///
/// The raw value bytes are exposed via [`AsRef<[u8]>`]: `prop.as_ref()`.
///
/// Conversion methods (`as_u32`, `as_str`, etc.) return [`Option`] —
/// a length or encoding mismatch is `None`, not an error. Callers
/// that need the specific reason (e.g. for diagnostics) can inspect
/// the raw bytes themselves.
pub trait PropertyView: Copy + AsRef<[u8]> + crate::sealed::Sealed {
    /// Property name.
    fn name(&self) -> &str;
    /// Interpret the value as a single big-endian `u32`. `None` if the
    /// value isn't exactly 4 bytes.
    fn as_u32(&self) -> Option<u32>;
    /// Interpret the value as a single big-endian `u64`. `None` if the
    /// value isn't exactly 8 bytes.
    fn as_u64(&self) -> Option<u64>;
    /// Interpret the value as a single NUL-terminated UTF-8 string.
    /// `None` if the value isn't NUL-terminated, has data after the
    /// first NUL, or contains invalid UTF-8.
    fn as_str(&self) -> Option<&str>;
    /// Iterate the value as a packed array of big-endian `u32` cells.
    /// `None` if the value's length isn't a multiple of 4.
    fn as_u32s(&self) -> Option<impl Iterator<Item = u32> + '_>;
    /// Iterate the value as a NUL-separated list of UTF-8 strings (the
    /// FDT encoding for `stringlist`, e.g. `compatible`). Strict: the
    /// value must end with a NUL byte, every nonempty piece must be
    /// valid UTF-8. `None` on either failure.
    fn as_strs(&self) -> Option<impl Iterator<Item = &str> + '_>;
}

impl AsRef<[u8]> for Property<'_> {
    fn as_ref(&self) -> &[u8] {
        self.value
    }
}

impl PropertyView for Property<'_> {
    fn name(&self) -> &str {
        self.name
    }

    fn as_u32(&self) -> Option<u32> {
        value_as_u32(self.value)
    }

    fn as_u64(&self) -> Option<u64> {
        value_as_u64(self.value)
    }

    fn as_str(&self) -> Option<&str> {
        value_as_str(self.value)
    }

    fn as_u32s(&self) -> Option<impl Iterator<Item = u32> + '_> {
        value_as_u32s(self.value)
    }

    fn as_strs(&self) -> Option<impl Iterator<Item = &str> + '_> {
        value_as_strs(self.value)
    }
}

// Property-value parsers, factored out of the [`PropertyView`] impl so the
// owned representation (`alloc` feature) shares the exact same semantics
// rather than reimplementing them.

/// Big-endian `u32` if `value` is exactly 4 bytes.
pub(crate) fn value_as_u32(value: &[u8]) -> Option<u32> {
    let arr: [u8; 4] = value.try_into().ok()?;
    Some(u32::from_be_bytes(arr))
}

/// Big-endian `u64` if `value` is exactly 8 bytes.
pub(crate) fn value_as_u64(value: &[u8]) -> Option<u64> {
    let arr: [u8; 8] = value.try_into().ok()?;
    Some(u64::from_be_bytes(arr))
}

/// Single NUL-terminated UTF-8 string (no trailing data, valid UTF-8).
pub(crate) fn value_as_str(value: &[u8]) -> Option<&str> {
    let nul = value.iter().position(|&b| b == 0)?;
    if nul.checked_add(1)? != value.len() {
        return None;
    }
    core::str::from_utf8(value.get(..nul)?).ok()
}

/// Packed big-endian `u32` cells; `None` if length isn't a multiple of 4.
pub(crate) fn value_as_u32s(value: &[u8]) -> Option<impl Iterator<Item = u32> + '_> {
    if !value.len().is_multiple_of(4) {
        return None;
    }
    Some(value.chunks_exact(4).map(|c| {
        let arr: [u8; 4] = c.try_into().unwrap_or([0; 4]);
        u32::from_be_bytes(arr)
    }))
}

/// NUL-separated UTF-8 stringlist (FDT `stringlist` encoding). Strict: must
/// end with NUL, every nonempty piece valid UTF-8.
pub(crate) fn value_as_strs(value: &[u8]) -> Option<impl Iterator<Item = &str> + '_> {
    if !value.is_empty() && value.last() != Some(&0) {
        return None;
    }
    let tail = match value.split_last() {
        Some((&0, head)) => head,
        _ => value,
    };
    for piece in tail.split(|&b| b == 0) {
        if piece.is_empty() {
            continue;
        }
        if core::str::from_utf8(piece).is_err() {
            return None;
        }
    }
    Some(
        tail.split(|&b| b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| core::str::from_utf8(p).unwrap_or("")),
    )
}

/// Read-side view of a parsed node.
pub trait NodeView: Copy + crate::sealed::Sealed {
    /// The associated property type yielded by [`NodeView::properties`].
    type Property: PropertyView;

    /// The node's name as it appears in the structure block.
    fn name(&self) -> &str;
    /// Iterate this node's properties.
    fn properties(&self) -> impl Iterator<Item = Self::Property> + '_;
    /// Iterate this node's direct children.
    fn children(&self) -> impl Iterator<Item = Self> + '_;
    /// Look up a property by name. Linear scan.
    fn property(&self, name: &str) -> Option<Self::Property> {
        self.properties().find(|p| p.name() == name)
    }
    /// Look up a property by its position among [`Self::properties`].
    fn property_at(&self, index: usize) -> Option<Self::Property> {
        self.properties().nth(index)
    }
    /// Look up several properties by name in one pass, returning them in the
    /// input order. A single scan over [`Self::properties`] regardless of `N`,
    /// stopping early once every name has been found.
    ///
    /// Names are matched as raw bytes. Note the default impl drives
    /// [`Self::properties`] (which resolves and UTF-8-validates each property
    /// name as it goes); it does not use the raw-byte fast path that the
    /// `Node` override of [`Self::property`] has, so the win over N separate
    /// [`Self::property`] calls is the single traversal, not cheaper matching.
    fn property_subset<const N: usize>(&self, names: [&[u8]; N]) -> [Option<Self::Property>; N] {
        let mut out: [Option<Self::Property>; N] = core::array::from_fn(|_| None);
        let mut remaining = N;
        for prop in self.properties() {
            if remaining == 0 {
                break;
            }
            let pname = prop.name().as_bytes();
            for (slot, needle) in out.iter_mut().zip(names.iter()) {
                if slot.is_none() && pname == *needle {
                    *slot = Some(prop);
                    remaining = remaining.saturating_sub(1);
                    break;
                }
            }
        }
        out
    }
    /// Look up a direct child by name. Linear scan.
    fn child(&self, name: &str) -> Option<Self> {
        self.children().find(|c| c.name() == name)
    }
    /// Look up a direct child by its position among [`Self::children`].
    fn child_at(&self, index: usize) -> Option<Self> {
        self.children().nth(index)
    }
    /// Read this node's phandle, falling back to legacy `linux,phandle`.
    /// `None` if neither property is present or the value isn't a valid
    /// 4-byte u32.
    fn phandle(&self) -> Option<NonZeroU32>;
}

impl<'a> NodeView for Node<'a> {
    type Property = Property<'a>;

    fn name(&self) -> &str {
        self.name
    }

    fn properties(&self) -> impl Iterator<Item = Property<'a>> + '_ {
        PropIter {
            struct_block: self.struct_block,
            strings_block: self.strings_block,
            pos: self.body_offset as usize,
        }
    }

    fn children(&self) -> impl Iterator<Item = Node<'a>> + '_ {
        ChildIter {
            struct_block: self.struct_block,
            strings_block: self.strings_block,
            pos: self.body_offset as usize,
        }
    }

    /// Fast-path override: compares property names as raw bytes;
    /// validates UTF-8 only on the matched name. Same contract as the
    /// default impl.
    fn property(&self, name: &str) -> Option<Property<'a>> {
        find_property_by_bytes(
            self.struct_block,
            self.strings_block,
            self.body_offset as usize,
            name.as_bytes(),
        )
    }

    /// Fast-path override: raw byte-comparison against child names;
    /// validates UTF-8 only on the matched name.
    fn child(&self, name: &str) -> Option<Node<'a>> {
        find_child_by_bytes(
            self.struct_block,
            self.strings_block,
            self.body_offset as usize,
            name.as_bytes(),
        )
    }

    fn phandle(&self) -> Option<NonZeroU32> {
        let p = NodeView::property(self, "phandle")
            .or_else(|| NodeView::property(self, "linux,phandle"))?;
        NonZeroU32::new(p.as_u32()?)
    }
}

/// Walk child BEGIN_NODE tokens, comparing each name as raw bytes;
/// skips matching subtrees on miss. Validates UTF-8 only on the
/// matched node name (parse already proved every name is valid UTF-8).
#[inline]
fn find_child_by_bytes<'a>(
    struct_block: &'a [u8],
    strings_block: &'a [u8],
    body_offset: usize,
    needle: &[u8],
) -> Option<Node<'a>> {
    let mut pos = body_offset;
    loop {
        let tok = cursor::read_u32(struct_block, pos)?;
        let after = pos.checked_add(4)?;
        match tok {
            FDT_NOP => {
                pos = after;
            }
            FDT_PROP => {
                let len = cursor::read_u32(struct_block, after)? as usize;
                let value_end = after.checked_add(8)?.checked_add(len)?;
                pos = align_up_4(value_end);
            }
            FDT_BEGIN_NODE => {
                let name_bytes = cursor::read_cstr_bytes(struct_block, after).ok()?;
                let name_end = after.checked_add(name_bytes.len())?.checked_add(1)?;
                let body_off = align_up_4(name_end);
                if name_bytes == needle {
                    let name = core::str::from_utf8(name_bytes).ok()?;
                    let body_off_u32 = u32::try_from(body_off).ok()?;
                    return Some(Node {
                        struct_block,
                        strings_block,
                        body_offset: body_off_u32,
                        name,
                    });
                }
                pos = skip_subtree(struct_block, body_off)?;
            }
            _ => return None,
        }
    }
}

/// Walk PROP tokens, comparing each name (looked up in the strings
/// block) as raw bytes. Validates UTF-8 only on the matched name.
#[inline]
fn find_property_by_bytes<'a>(
    struct_block: &'a [u8],
    strings_block: &'a [u8],
    body_offset: usize,
    needle: &[u8],
) -> Option<Property<'a>> {
    let mut pos = body_offset;
    loop {
        let tok = cursor::read_u32(struct_block, pos)?;
        let after = pos.checked_add(4)?;
        match tok {
            FDT_NOP => {
                pos = after;
            }
            FDT_PROP => {
                let len = cursor::read_u32(struct_block, after)? as usize;
                let name_off = cursor::read_u32(struct_block, after.checked_add(4)?)?;
                let value_start = after.checked_add(8)?;
                let value_end = value_start.checked_add(len)?;
                let name_bytes = cursor::read_cstr_bytes(strings_block, name_off as usize).ok()?;
                if name_bytes == needle {
                    let value = struct_block.get(value_start..value_end)?;
                    let value_struct_offset = u32::try_from(value_start).ok()?;
                    let name = core::str::from_utf8(name_bytes).ok()?;
                    return Some(Property {
                        name,
                        value,
                        value_struct_offset,
                    });
                }
                pos = align_up_4(value_end);
            }
            _ => return None,
        }
    }
}

/// Read-side view of a parsed devicetree.
///
/// Implemented by every `Tree<'_, D, M>` — the const-generic caps are a
/// parse-time contract that vanishes from the read-side view, so this trait
/// lets code be generic over the whole family without naming (or caring
/// about) the caps — and, with the `alloc` feature, by `&OwnedTree`, so the
/// same generic code accepts the owned representation too.
///
/// `AsRef<[u8]>` is intentionally *not* a supertrait: the concrete zero-copy
/// [`Tree`] exposes its backing blob via `AsRef<[u8]>` (`tree.as_ref()`), but
/// an owned tree has no single canonical blob (it would go stale after a
/// mutation), so byte access belongs to the concrete type, not the view.
pub trait TreeView: Copy + crate::sealed::Sealed {
    /// The associated node type yielded by [`TreeView::root`] etc.
    type Node: NodeView;

    /// The root node. Always present after a successful parse.
    fn root(&self) -> Self::Node;
    /// Look up a node by absolute path (e.g. `"/cpus/cpu@0"`). Returns
    /// `None` for missing nodes *or* paths that don't start with `/`.
    fn find_path(&self, path: &str) -> Option<Self::Node> {
        let rest = path.strip_prefix('/')?;
        let mut node = self.root();
        for segment in rest.split('/').filter(|s| !s.is_empty()) {
            node = node.child(segment)?;
        }
        Some(node)
    }
    /// Look up a node by its `phandle` (or legacy `linux,phandle`)
    /// property. Bounded by the implementation's parse-time depth cap.
    fn find_phandle(&self, ph: NonZeroU32) -> Option<Self::Node>;
    /// Iterate the memory reservation block.
    fn reservations(&self) -> impl Iterator<Item = Reservation> + '_;
}

impl<const D: u32, const M: u32> AsRef<[u8]> for Tree<'_, D, M> {
    #[allow(clippy::indexing_slicing)] // totalsize <= blob.len() enforced by Header::parse
    fn as_ref(&self) -> &[u8] {
        &self.blob[..self.totalsize as usize]
    }
}

impl<'a, const D: u32, const M: u32> TreeView for Tree<'a, D, M> {
    type Node = Node<'a>;

    fn root(&self) -> Node<'a> {
        Node {
            struct_block: self.struct_block,
            strings_block: self.strings_block,
            body_offset: self.root_body_offset,
            name: self.root_name,
        }
    }

    fn find_phandle(&self, ph: NonZeroU32) -> Option<Node<'a>> {
        find_phandle_in(TreeView::root(self), ph, D)
    }

    fn reservations(&self) -> impl Iterator<Item = Reservation> + '_ {
        ReservationIter {
            block: self.memrsv_block,
            pos: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Parse-time validation.
// ---------------------------------------------------------------------------

/// Walk the entire structure block once, validating tokens, alignment,
/// string lookups, tree depth, root presence, and reserved-phandle
/// values. Returns the root node's body offset, name, and the maximum
/// observed phandle value (0 if none).
fn validate_struct<'a>(
    struct_block: &'a [u8],
    strings_block: &'a [u8],
    max_depth: u32,
) -> Result<(u32, &'a str, u32, usize), Error> {
    let mut pos = 0usize;
    let mut max_phandle: u32 = 0;
    let mut prop_name_bytes: usize = 0;
    // Skip leading NOPs.
    let (root_name, root_body_offset) = loop {
        let tok = read_token(struct_block, pos)?;
        match tok {
            TokenAt::Nop { next } => pos = next,
            TokenAt::Begin {
                name,
                body_offset,
                next: _,
            } => break (name, u32_or_tree_overflow(body_offset)?),
            _ => return Err(Error::from(MalformedKind::NoRoot)),
        }
    };

    // Validate the root subtree.
    pos = root_body_offset as usize;
    let mut depth: u32 = 1;
    while depth > 0 {
        let tok = read_token(struct_block, pos)?;
        match tok {
            TokenAt::Begin { next, .. } => {
                depth = depth.checked_add(1).ok_or(Limit::Depth)?;
                if depth > max_depth {
                    return Err(Error::LimitExceeded(Limit::Depth));
                }
                pos = next;
            }
            TokenAt::EndNode { next } => {
                depth = depth.checked_sub(1).ok_or(MalformedKind::BadStructure)?;
                pos = next;
            }
            TokenAt::Prop {
                name_off,
                value,
                next,
            } => {
                let name = lookup_name(strings_block, name_off)?;
                prop_name_bytes = prop_name_bytes
                    .checked_add(name.len())
                    .and_then(|n| n.checked_add(1))
                    .ok_or(MalformedKind::SizeOverflow)?;
                // Phandle reserved-value check applies to `phandle` and
                // `linux,phandle` properties — if present and 4 bytes,
                // value must not be 0 or u32::MAX. Track the max so the
                // overlay layer can compute its shift without a re-walk.
                if (name == "phandle" || name == "linux,phandle") && value.len() == 4 {
                    let arr: [u8; 4] = value.try_into().unwrap_or([0; 4]);
                    let v = u32::from_be_bytes(arr);
                    if v == 0 || v == u32::MAX {
                        return Err(Error::from(MalformedKind::ReservedPhandle));
                    }
                    if v > max_phandle {
                        max_phandle = v;
                    }
                }
                pos = next;
            }
            TokenAt::Nop { next } => pos = next,
            TokenAt::End => return Err(Error::from(MalformedKind::BadStructure)),
        }
    }

    // After the root closes, only NOPs then END are allowed.
    loop {
        let tok = read_token(struct_block, pos)?;
        match tok {
            TokenAt::Nop { next } => pos = next,
            TokenAt::End => break,
            _ => return Err(Error::from(MalformedKind::BadStructure)),
        }
    }

    Ok((root_body_offset, root_name, max_phandle, prop_name_bytes))
}

fn lookup_name(strings_block: &[u8], name_off: u32) -> Result<&str, Error> {
    match cursor::read_cstr(strings_block, name_off as usize) {
        Ok(s) => Ok(s),
        Err(CstrError::OutOfBounds) => Err(MalformedKind::BadNameOffset { name_off }.into()),
        Err(CstrError::BadString) => Err(MalformedKind::BadString { offset: name_off }.into()),
    }
}

fn u32_or_tree_overflow(v: usize) -> Result<u32, Error> {
    u32::try_from(v).map_err(|_| MalformedKind::BadStructure.into())
}

/// One token, plus its starting position-after-parse.
enum TokenAt<'a> {
    Begin {
        name: &'a str,
        body_offset: usize,
        next: usize,
    },
    EndNode {
        next: usize,
    },
    Prop {
        name_off: u32,
        value: &'a [u8],
        next: usize,
    },
    Nop {
        next: usize,
    },
    End,
}

/// Read one token at `pos`. Reports the position immediately after the
/// token in `next`. Returns rich errors with offset context.
fn read_token(struct_block: &[u8], pos: usize) -> Result<TokenAt<'_>, Error> {
    let pos_u32 = u32_or_tree_overflow(pos)?;
    let tok = cursor::read_u32(struct_block, pos).ok_or(MalformedKind::BadStructure)?;
    let after_tok = pos.checked_add(4).ok_or(MalformedKind::BadStructure)?;
    match tok {
        FDT_BEGIN_NODE => {
            let Ok(name) = cursor::read_cstr(struct_block, after_tok) else {
                return Err(Error::from(MalformedKind::BadString { offset: pos_u32 }));
            };
            let name_end = after_tok
                .checked_add(name.len())
                .and_then(|n| n.checked_add(1))
                .ok_or(MalformedKind::BadStructure)?;
            let body_offset = align_up_4(name_end);
            Ok(TokenAt::Begin {
                name,
                body_offset,
                next: body_offset,
            })
        }
        FDT_END_NODE => Ok(TokenAt::EndNode { next: after_tok }),
        FDT_PROP => {
            let len_u32 =
                cursor::read_u32(struct_block, after_tok).ok_or(MalformedKind::BadStructure)?;
            let after_len = after_tok
                .checked_add(4)
                .ok_or(MalformedKind::BadStructure)?;
            let name_off =
                cursor::read_u32(struct_block, after_len).ok_or(MalformedKind::BadStructure)?;
            let after_name_off = after_len
                .checked_add(4)
                .ok_or(MalformedKind::BadStructure)?;
            let len = len_u32 as usize;
            let value_end = after_name_off
                .checked_add(len)
                .ok_or(MalformedKind::BadStructure)?;
            let value = struct_block
                .get(after_name_off..value_end)
                .ok_or(MalformedKind::BadStructure)?;
            Ok(TokenAt::Prop {
                name_off,
                value,
                next: align_up_4(value_end),
            })
        }
        FDT_NOP => Ok(TokenAt::Nop { next: after_tok }),
        FDT_END => Ok(TokenAt::End),
        _ => Err(MalformedKind::BadToken { offset: pos_u32 }.into()),
    }
}

/// Validate the memrsv region: walk pairs of u64s, stop at `(0,0)` or
/// the cap. Returns the slice of *entries only* — the `(0,0)`
/// terminator is consumed by the validator and stripped from the
/// returned slice, so the iterator can yield until the slice is
/// exhausted without re-checking for the terminator.
fn validate_memrsv(region: &[u8], max_entries: u32) -> Result<&[u8], Error> {
    let mut pos = 0usize;
    let mut entries: u32 = 0;
    loop {
        let address =
            cursor::read_u64(region, pos).ok_or(crate::error::MalformedKind::MemRsvUnterminated)?;
        let size_pos = pos
            .checked_add(8)
            .ok_or(crate::error::MalformedKind::Truncated)?;
        let size = cursor::read_u64(region, size_pos)
            .ok_or(crate::error::MalformedKind::MemRsvUnterminated)?;
        if address == 0 && size == 0 {
            // Strip the terminator from the returned slice.
            let block = region
                .get(..pos)
                .ok_or(crate::error::MalformedKind::Truncated)?;
            return Ok(block);
        }
        entries = entries
            .checked_add(1)
            .ok_or(crate::error::MalformedKind::Truncated)?;
        if entries >= max_entries {
            return Err(crate::error::Limit::Reservations.into());
        }
        pos = size_pos
            .checked_add(8)
            .ok_or(crate::error::MalformedKind::Truncated)?;
    }
}

// ---------------------------------------------------------------------------
// Infallible iterators (post-validation).
// ---------------------------------------------------------------------------

/// Skip past a node body (terminating END_NODE consumed). Used by
/// child iteration. Infallible because parse validated structure.
fn skip_subtree(struct_block: &[u8], body_offset: usize) -> Option<usize> {
    let mut pos = body_offset;
    let mut depth: u32 = 1;
    while depth > 0 {
        let tok = read_token_quick(struct_block, pos)?;
        pos = tok.next;
        match tok.kind {
            QuickKind::Begin => depth = depth.saturating_add(1),
            QuickKind::EndNode => depth = depth.saturating_sub(1),
            QuickKind::Prop | QuickKind::Nop => {}
            QuickKind::End => return None,
        }
    }
    Some(pos)
}

struct QuickToken {
    kind: QuickKind,
    next: usize,
}

enum QuickKind {
    Begin,
    EndNode,
    Prop,
    Nop,
    End,
}

/// Lightweight token reader for the infallible iterators. Returns
/// `None` on shapes the validator already rejected, which `parse`
/// excluded — iterators treat `None` as end-of-stream. Node names are
/// read as raw bytes (no UTF-8 re-validation) since this is only used
/// to skip subtrees.
fn read_token_quick(struct_block: &[u8], pos: usize) -> Option<QuickToken> {
    let tok = cursor::read_u32(struct_block, pos)?;
    let after = pos.checked_add(4)?;
    match tok {
        FDT_BEGIN_NODE => {
            let name = cursor::read_cstr_bytes(struct_block, after).ok()?;
            let name_end = after.checked_add(name.len())?.checked_add(1)?;
            Some(QuickToken {
                kind: QuickKind::Begin,
                next: align_up_4(name_end),
            })
        }
        FDT_END_NODE => Some(QuickToken {
            kind: QuickKind::EndNode,
            next: after,
        }),
        FDT_PROP => {
            let len = cursor::read_u32(struct_block, after)? as usize;
            let after_name_off = after.checked_add(8)?;
            let value_end = after_name_off.checked_add(len)?;
            Some(QuickToken {
                kind: QuickKind::Prop,
                next: align_up_4(value_end),
            })
        }
        FDT_NOP => Some(QuickToken {
            kind: QuickKind::Nop,
            next: after,
        }),
        FDT_END => Some(QuickToken {
            kind: QuickKind::End,
            next: after,
        }),
        _ => None,
    }
}

pub(crate) struct PropIter<'a> {
    pub(crate) struct_block: &'a [u8],
    pub(crate) strings_block: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Iterator for PropIter<'a> {
    type Item = Property<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let tok = cursor::read_u32(self.struct_block, self.pos)?;
            let after = self.pos.checked_add(4)?;
            match tok {
                FDT_NOP => {
                    self.pos = after;
                    continue;
                }
                FDT_PROP => {
                    let len = cursor::read_u32(self.struct_block, after)? as usize;
                    let name_off = cursor::read_u32(self.struct_block, after.checked_add(4)?)?;
                    let value_start = after.checked_add(8)?;
                    let value_end = value_start.checked_add(len)?;
                    let value = self.struct_block.get(value_start..value_end)?;
                    let name = cursor::read_cstr(self.strings_block, name_off as usize).ok()?;
                    let value_struct_offset = u32::try_from(value_start).ok()?;
                    self.pos = align_up_4(value_end);
                    return Some(Property {
                        name,
                        value,
                        value_struct_offset,
                    });
                }
                _ => return None, // BEGIN_NODE / END_NODE / END
            }
        }
    }
}

pub(crate) struct ChildIter<'a> {
    pub(crate) struct_block: &'a [u8],
    pub(crate) strings_block: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Iterator for ChildIter<'a> {
    type Item = Node<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let tok = cursor::read_u32(self.struct_block, self.pos)?;
            let after = self.pos.checked_add(4)?;
            match tok {
                FDT_NOP => {
                    self.pos = after;
                    continue;
                }
                FDT_PROP => {
                    // Skip past property.
                    let len = cursor::read_u32(self.struct_block, after)? as usize;
                    let value_end = after.checked_add(8)?.checked_add(len)?;
                    self.pos = align_up_4(value_end);
                    continue;
                }
                FDT_BEGIN_NODE => {
                    let name = cursor::read_cstr(self.struct_block, after).ok()?;
                    let name_end = after.checked_add(name.len())?.checked_add(1)?;
                    let body_offset = align_up_4(name_end);
                    let body_offset_u32 = u32::try_from(body_offset).ok()?;
                    let next = skip_subtree(self.struct_block, body_offset)?;
                    self.pos = next;
                    return Some(Node {
                        struct_block: self.struct_block,
                        strings_block: self.strings_block,
                        body_offset: body_offset_u32,
                        name,
                    });
                }
                _ => return None,
            }
        }
    }
}

struct ReservationIter<'a> {
    block: &'a [u8],
    pos: usize,
}

impl Iterator for ReservationIter<'_> {
    type Item = Reservation;
    fn next(&mut self) -> Option<Self::Item> {
        let address = cursor::read_u64(self.block, self.pos)?;
        let size_pos = self.pos.checked_add(8)?;
        let size = cursor::read_u64(self.block, size_pos)?;
        let next = size_pos.checked_add(8)?;
        self.pos = next;
        Some(Reservation { address, size })
    }
}
