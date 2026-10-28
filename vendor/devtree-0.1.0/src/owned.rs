// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Owned devicetree (the `alloc` feature).
//!
//! [`OwnedTree`] / [`OwnedNode`] / [`OwnedProperty`] are the owned counterpart
//! of the crate's zero-copy types ([`Tree`](crate::Tree) and the nodes and
//! properties its [`NodeView`] / [`PropertyView`] traits yield): the tree is
//! copied out of the borrowed blob so it can be both read and modified freely.
//! [`OwnedTree::materialize`] (a.k.a. `From<&T>`) builds one from any parsed
//! [`TreeView`]; the source blob is not retained.
//!
//! **Reads** mirror the zero-copy vocabulary exactly — `name` / `property` /
//! `properties` / `children` and the `as_*` value accessors — so code that
//! knows the borrowed types reads an owned tree with no new vocabulary, plus a
//! few accessors a flat zero-copy handle can't offer ([`OwnedNode::path`],
//! [`OwnedNode::address_cells`], [`OwnedNode::size_cells`]). They are available
//! both as inherent methods (callable however you hold the value) and through
//! the shared [`NodeView`] / [`PropertyView`] / [`TreeView`] traits, which are
//! implemented on the `&` references (these are `Copy`), so generic
//! `N: NodeView` / `T: TreeView` code accepts borrowed and owned alike.
//!
//! **Modification** comes in matching grids over both node collections, each
//! addressable by name *or* index:
//!
//! - read-mut: [`OwnedNode::property_mut`] / `property_at_mut` /
//!   `properties_mut`, and [`OwnedNode::child_mut`] / `child_at_mut` /
//!   `children_mut`.
//! - remove (returns the owned value): [`OwnedNode::remove_property`] /
//!   `remove_property_at` and [`OwnedNode::remove_child`] / `remove_child_at`,
//!   plus [`OwnedTree::remove_path`] / `remove_phandle`. Pair the `_at` forms
//!   with `properties()` / `children().position(..)` for a predicate match.
//! - construct / insert: build a property with [`OwnedProperty::new`] + the
//!   `with_*` builders (or `set_*` setters — each `set_X` is the write partner
//!   of an `as_X` reader, e.g. [`OwnedProperty::set_u32`] ↔ `as_u32`); build a
//!   node with [`OwnedNode::new`] + [`OwnedNode::with_property`] /
//!   [`OwnedNode::with_child`]; insert-or-replace with
//!   [`OwnedNode::set_property`] / [`OwnedNode::set_child`].
//!
//! Nothing derived is cached in a way that mutation can falsify:
//! `address_cells`/`size_cells` read the live `#*-cells` properties,
//! [`OwnedTree::find_phandle`] / `remove_phandle` walk the live tree, and the
//! one cached field — each node's absolute `path` — is re-derived by
//! [`OwnedNode::set_child`] for the subtree it attaches.
//!
//! [`OwnedTree::encode`] serializes the tree back to flattened-devicetree
//! bytes (the inverse of `materialize`), so a `materialize → modify → encode →
//! Tree::parse` round-trip is closed.

use core::num::NonZeroU32;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::cursor::align_up_4;
use crate::error::{Error, MalformedKind};
use crate::fdt::{
    FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_PROP, value_as_str, value_as_strs, value_as_u32,
    value_as_u32s, value_as_u64,
};
use crate::header::FDT_HEADER_SIZE;
use crate::writer::{build_header, u32_or};
use crate::{NodeView, PropertyView, Reservation, TreeView};

/// An owned property: name plus raw value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProperty {
    name: String,
    bytes: Vec<u8>,
}

impl OwnedProperty {
    /// Property name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Big-endian `u32` if the value is exactly 4 bytes.
    pub fn as_u32(&self) -> Option<u32> {
        value_as_u32(&self.bytes)
    }

    /// Big-endian `u64` if the value is exactly 8 bytes.
    pub fn as_u64(&self) -> Option<u64> {
        value_as_u64(&self.bytes)
    }

    /// Single NUL-terminated UTF-8 string.
    pub fn as_str(&self) -> Option<&str> {
        value_as_str(&self.bytes)
    }

    /// Packed big-endian `u32` cells.
    pub fn as_u32s(&self) -> Option<impl Iterator<Item = u32> + '_> {
        value_as_u32s(&self.bytes)
    }

    /// NUL-separated UTF-8 stringlist (e.g. `compatible`).
    pub fn as_strs(&self) -> Option<impl Iterator<Item = &str> + '_> {
        value_as_strs(&self.bytes)
    }

    // ── construction + value setters ──
    //
    // The `set_*` setters are the write partners of the `as_*` readers: each
    // `set_X(&mut self, X)` is the inverse of `as_X(&self) -> Option<X>`,
    // encoding the FDT layout the reader decodes.

    /// A property with the given name and an empty value. Fill it with a
    /// `set_*` setter, or chain a `with_*` builder.
    pub fn new(name: &str) -> Self {
        OwnedProperty {
            name: name.into(),
            bytes: Vec::new(),
        }
    }

    /// Replace the raw value bytes (write partner of `as_ref`).
    pub fn set_bytes(&mut self, value: Vec<u8>) {
        self.bytes = value;
    }

    /// Set the value to a single big-endian `u32` (write partner of [`Self::as_u32`]).
    pub fn set_u32(&mut self, value: u32) {
        self.bytes = value.to_be_bytes().to_vec();
    }

    /// Set the value to a single big-endian `u64` (write partner of [`Self::as_u64`]).
    pub fn set_u64(&mut self, value: u64) {
        self.bytes = value.to_be_bytes().to_vec();
    }

    /// Set the value to a single NUL-terminated string (write partner of [`Self::as_str`]).
    pub fn set_str(&mut self, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.bytes = bytes;
    }

    /// Set the value to a packed array of big-endian `u32` cells (write partner of [`Self::as_u32s`]).
    pub fn set_u32s(&mut self, values: &[u32]) {
        let mut bytes = Vec::new();
        for v in values {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        self.bytes = bytes;
    }

    /// Set the value to a NUL-separated stringlist (write partner of [`Self::as_strs`]).
    pub fn set_strs(&mut self, values: &[&str]) {
        let mut bytes = Vec::new();
        for s in values {
            bytes.extend_from_slice(s.as_bytes());
            bytes.push(0);
        }
        self.bytes = bytes;
    }

    // ── builder forms (chainable construction), e.g.
    //    `OwnedProperty::new("reg").with_u32(0x1000)` ──

    /// Builder form of [`Self::set_bytes`].
    #[must_use]
    pub fn with_bytes(mut self, value: Vec<u8>) -> Self {
        self.set_bytes(value);
        self
    }

    /// Builder form of [`Self::set_u32`].
    #[must_use]
    pub fn with_u32(mut self, value: u32) -> Self {
        self.set_u32(value);
        self
    }

    /// Builder form of [`Self::set_u64`].
    #[must_use]
    pub fn with_u64(mut self, value: u64) -> Self {
        self.set_u64(value);
        self
    }

    /// Builder form of [`Self::set_str`].
    #[must_use]
    pub fn with_str(mut self, value: &str) -> Self {
        self.set_str(value);
        self
    }

    /// Builder form of [`Self::set_u32s`].
    #[must_use]
    pub fn with_u32s(mut self, values: &[u32]) -> Self {
        self.set_u32s(values);
        self
    }

    /// Builder form of [`Self::set_strs`].
    #[must_use]
    pub fn with_strs(mut self, values: &[&str]) -> Self {
        self.set_strs(values);
        self
    }
}

impl AsRef<[u8]> for OwnedProperty {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// An owned node: name, absolute path, properties, and child nodes — all
/// readable, modifiable, and removable by move.
#[derive(Debug, Clone)]
pub struct OwnedNode {
    name: String,
    path: String,
    props: Vec<OwnedProperty>,
    children: Vec<OwnedNode>,
}

// Structural equality over `(name, properties, children)` only. `path` is a
// denormalized convenience — a node's position in the tree, not part of its
// content — so a detached subtree compares equal to its attached self. This
// mirrors `Property` equality, which excludes its internal value offset.
impl PartialEq for OwnedNode {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.props == other.props && self.children == other.children
    }
}

impl Eq for OwnedNode {}

impl OwnedNode {
    // ── reads (inherent; the shared-trait impls delegate to these shapes) ──

    /// The node's name (the unit name as it appears in the tree).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The node's absolute path from the root (e.g. `"/firmware/psci"`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// This node's `#address-cells` — the cell count governing its **children's**
    /// `reg`, per the DT spec (and libfdt's `fdt_address_cells`) — read live,
    /// defaulting to 2 when absent. So to parse a node's own `reg`, ask its
    /// parent: `parent.address_cells()`. (An [`OwnedNode`] has no back-pointer,
    /// so it can't report its own governing cells; reach the parent by
    /// navigating from the root, e.g. via [`OwnedTree::find_path`].)
    pub fn address_cells(&self) -> u32 {
        self.property("#address-cells")
            .and_then(OwnedProperty::as_u32)
            .unwrap_or(2)
    }

    /// This node's `#size-cells` — governing its **children's** `reg` — read
    /// live, defaulting to 1 when absent.
    pub fn size_cells(&self) -> u32 {
        self.property("#size-cells")
            .and_then(OwnedProperty::as_u32)
            .unwrap_or(1)
    }

    /// Look up a property by name.
    pub fn property(&self, name: &str) -> Option<&OwnedProperty> {
        self.props.iter().find(|p| p.name == name)
    }

    /// Look up a property by its position among [`Self::properties`].
    pub fn property_at(&self, index: usize) -> Option<&OwnedProperty> {
        self.props.get(index)
    }

    /// Iterate this node's properties.
    pub fn properties(&self) -> impl Iterator<Item = &OwnedProperty> + '_ {
        self.props.iter()
    }

    /// Mutable lookup of a property by name.
    pub fn property_mut(&mut self, name: &str) -> Option<&mut OwnedProperty> {
        self.props.iter_mut().find(|p| p.name == name)
    }

    /// Mutable lookup of a property by its position among [`Self::properties`].
    pub fn property_at_mut(&mut self, index: usize) -> Option<&mut OwnedProperty> {
        self.props.get_mut(index)
    }

    /// Iterate this node's properties mutably.
    pub fn properties_mut(&mut self) -> impl Iterator<Item = &mut OwnedProperty> + '_ {
        self.props.iter_mut()
    }

    /// Insert a property, or replace the existing one with the same name,
    /// returning the previous property if one was replaced. The write partner
    /// of [`Self::property`]; build the argument with [`OwnedProperty::new`]
    /// and a `with_*` builder (or a `set_*` setter).
    pub fn set_property(&mut self, prop: OwnedProperty) -> Option<OwnedProperty> {
        if let Some(existing) = self.props.iter_mut().find(|p| p.name == prop.name) {
            Some(core::mem::replace(existing, prop))
        } else {
            self.props.push(prop);
            None
        }
    }

    /// A node with the given name and no properties or children. Build it up
    /// with [`Self::with_property`] / [`Self::with_child`] (or `set_property` /
    /// `set_child`). Its `path` is a placeholder until it is attached to a tree
    /// via [`Self::set_child`], which re-derives it.
    pub fn new(name: &str) -> Self {
        OwnedNode {
            name: name.into(),
            path: name.into(),
            props: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Insert a child, or replace an existing child with the same name,
    /// returning the previous subtree. The write partner of [`Self::child`].
    /// The inserted subtree's `path` is re-derived from this node, so `path()`
    /// stays correct after insertion. (Cells are read live, so they need no
    /// fix-up.)
    pub fn set_child(&mut self, mut child: OwnedNode) -> Option<OwnedNode> {
        child.path = child_path(&self.path, &child.name);
        child.restamp_children();
        if let Some(existing) = self.children.iter_mut().find(|c| c.name == child.name) {
            Some(core::mem::replace(existing, child))
        } else {
            self.children.push(child);
            None
        }
    }

    /// Builder form of [`Self::set_property`].
    #[must_use]
    pub fn with_property(mut self, prop: OwnedProperty) -> Self {
        self.set_property(prop);
        self
    }

    /// Builder form of [`Self::set_child`].
    #[must_use]
    pub fn with_child(mut self, child: OwnedNode) -> Self {
        self.set_child(child);
        self
    }

    /// Look up a direct child by name.
    pub fn child(&self, name: &str) -> Option<&OwnedNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Look up a direct child by its position among [`Self::children`].
    pub fn child_at(&self, index: usize) -> Option<&OwnedNode> {
        self.children.get(index)
    }

    /// Iterate this node's direct children.
    pub fn children(&self) -> impl Iterator<Item = &OwnedNode> + '_ {
        self.children.iter()
    }

    /// Mutable lookup of a direct child by name.
    pub fn child_mut(&mut self, name: &str) -> Option<&mut OwnedNode> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    /// Mutable lookup of a direct child by its position among [`Self::children`].
    pub fn child_at_mut(&mut self, index: usize) -> Option<&mut OwnedNode> {
        self.children.get_mut(index)
    }

    /// Iterate this node's direct children mutably.
    pub fn children_mut(&mut self) -> impl Iterator<Item = &mut OwnedNode> + '_ {
        self.children.iter_mut()
    }

    /// This node's `phandle` (falling back to legacy `linux,phandle`).
    pub fn phandle(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.raw_phandle()?)
    }

    fn raw_phandle(&self) -> Option<u32> {
        let p = self
            .property("phandle")
            .or_else(|| self.property("linux,phandle"))?;
        p.as_u32()
    }

    // ── removals (the consumption verbs) ──

    /// Remove a property by name, returning it. The removal partner of
    /// [`Self::property`]. A second removal of the same name yields `None`.
    pub fn remove_property(&mut self, name: &str) -> Option<OwnedProperty> {
        let idx = self.props.iter().position(|p| p.name == name)?;
        Some(self.props.remove(idx))
    }

    /// Remove a property by its position among [`Self::properties`], returning
    /// it. `None` if the index is out of range. The removal partner of
    /// [`Self::property_at`]; pair it with `properties().position(pred)` to
    /// remove a predicate-matched property without allocating.
    pub fn remove_property_at(&mut self, index: usize) -> Option<OwnedProperty> {
        if index < self.props.len() {
            Some(self.props.remove(index))
        } else {
            None
        }
    }

    /// Remove a direct child by name, returning the removed subtree. The
    /// removal partner of [`Self::child`]; use it when you hold a literal name.
    /// A second removal of the same name yields `None`.
    pub fn remove_child(&mut self, name: &str) -> Option<OwnedNode> {
        let idx = self.children.iter().position(|c| c.name == name)?;
        Some(self.children.remove(idx))
    }

    /// Remove a direct child by its position among [`Self::children`],
    /// returning the removed subtree. `None` if the index is out of range. The
    /// removal partner of [`Self::child_at`]; pair it with
    /// `children().position(pred)` to remove a predicate-matched child (e.g. a
    /// `name` prefix or `compatible`) without allocating — `position` yields a
    /// `Copy` index that ends the immutable borrow before this `&mut` removal,
    /// whereas removing such a match by name would force its `name()` to be
    /// `to_owned()`'d across the borrow.
    pub fn remove_child_at(&mut self, index: usize) -> Option<OwnedNode> {
        if index < self.children.len() {
            Some(self.children.remove(index))
        } else {
            None
        }
    }

    // ── build helpers ──

    fn from_view<N: NodeView>(node: N, path: String) -> Self {
        let props: Vec<OwnedProperty> = node
            .properties()
            .map(|p| OwnedProperty {
                name: p.name().into(),
                bytes: p.as_ref().to_vec(),
            })
            .collect();
        let children: Vec<OwnedNode> = node
            .children()
            .map(|c| {
                let cp = child_path(&path, c.name());
                OwnedNode::from_view(c, cp)
            })
            .collect();
        OwnedNode {
            name: node.name().into(),
            path,
            props,
            children,
        }
    }

    /// Re-derive the paths of this node's whole subtree, assuming this node's
    /// own `path` is already correct. Called after a structural insert so the
    /// stored `path` stays accurate. (Cells are read live, so they need no
    /// fix-up.)
    fn restamp_children(&mut self) {
        let parent_path = self.path.clone();
        for child in &mut self.children {
            child.path = child_path(&parent_path, &child.name);
            child.restamp_children();
        }
    }

    /// Depth-first search for a node carrying `ph` (this node or a descendant).
    fn find_with_phandle(&self, ph: NonZeroU32) -> Option<&OwnedNode> {
        if self.phandle() == Some(ph) {
            return Some(self);
        }
        for c in &self.children {
            if let Some(found) = c.find_with_phandle(ph) {
                return Some(found);
            }
        }
        None
    }

    /// Remove the first descendant carrying `ph`, returning it.
    fn remove_descendant_with_phandle(&mut self, ph: NonZeroU32) -> Option<OwnedNode> {
        if let Some(i) = self.children.iter().position(|c| c.phandle() == Some(ph)) {
            return Some(self.children.remove(i));
        }
        for c in &mut self.children {
            if let Some(found) = c.remove_descendant_with_phandle(ph) {
                return Some(found);
            }
        }
        None
    }

    /// Emit this node's `BEGIN_NODE … END_NODE` span into the structure block,
    /// interning property names into `strings`. Recurses depth-first; emits
    /// properties before child nodes, per the FDT convention.
    fn emit(&self, structure: &mut Vec<u8>, strings: &mut Strings) -> Result<(), Error> {
        push_u32(structure, FDT_BEGIN_NODE);
        structure.extend_from_slice(self.name.as_bytes());
        structure.push(0);
        pad_to_4(structure);
        for p in &self.props {
            push_u32(structure, FDT_PROP);
            push_u32(structure, u32_or(p.bytes.len())?);
            push_u32(structure, strings.intern(&p.name)?);
            structure.extend_from_slice(&p.bytes);
            pad_to_4(structure);
        }
        for c in &self.children {
            c.emit(structure, strings)?;
        }
        push_u32(structure, FDT_END_NODE);
        Ok(())
    }
}

/// The FDT strings block being built: deduplicated NUL-terminated names plus a
/// name → offset index.
struct Strings {
    bytes: Vec<u8>,
    offsets: BTreeMap<String, u32>,
}

impl Strings {
    fn new() -> Self {
        Strings {
            bytes: Vec::new(),
            offsets: BTreeMap::new(),
        }
    }

    /// Offset of `name` in the strings block, appending it (with a NUL) on
    /// first sight. `Err` if the block would exceed `u32`.
    fn intern(&mut self, name: &str) -> Result<u32, Error> {
        if let Some(&off) = self.offsets.get(name) {
            return Ok(off);
        }
        let off = u32_or(self.bytes.len())?;
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        self.offsets.insert(name.into(), off);
        Ok(off)
    }
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Zero-pad `buf` up to the next 4-byte boundary (FDT token alignment).
fn pad_to_4(buf: &mut Vec<u8>) {
    buf.resize(align_up_4(buf.len()), 0);
}

/// Build an absolute child path from a parent path and a child name, without
/// doubling the separator at the root.
fn child_path(parent: &str, name: &str) -> String {
    let mut p = String::new();
    p.push_str(parent);
    if !parent.ends_with('/') {
        p.push('/');
    }
    p.push_str(name);
    p
}

/// An owned devicetree: a root node plus the memory-reservation entries,
/// materialized from a [`TreeView`] and freely modifiable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTree {
    root: OwnedNode,
    reservations: Vec<Reservation>,
}

impl OwnedTree {
    /// Build an owned tree from a root node, with no memory reservations. The
    /// from-scratch constructor (the counterpart of [`Self::materialize`]);
    /// pairs with [`Self::encode`] to assemble a tree and serialize it.
    pub fn new(root: OwnedNode) -> Self {
        OwnedTree {
            root,
            reservations: Vec::new(),
        }
    }

    /// Copy a parsed, validated zero-copy tree into an owned one. The source
    /// blob is not retained.
    pub fn materialize<T: TreeView>(view: &T) -> Self {
        let root = OwnedNode::from_view(view.root(), String::from("/"));
        let reservations = view.reservations().collect();
        OwnedTree { root, reservations }
    }

    /// The root node.
    pub fn root(&self) -> &OwnedNode {
        &self.root
    }

    /// The root node, mutably (the entry point for draining).
    pub fn root_mut(&mut self) -> &mut OwnedNode {
        &mut self.root
    }

    /// The memory-reservation entries.
    pub fn reservations(&self) -> &[Reservation] {
        &self.reservations
    }

    /// Look up a node by absolute path (e.g. `"/cpus/cpu@0"`). `None` for a
    /// missing node or a path that doesn't start with `/`.
    pub fn find_path(&self, path: &str) -> Option<&OwnedNode> {
        let rest = path.strip_prefix('/')?;
        let mut node = &self.root;
        for seg in rest.split('/').filter(|s| !s.is_empty()) {
            node = node.child(seg)?;
        }
        Some(node)
    }

    /// Look up a node by its `phandle` (or legacy `linux,phandle`). Walks the
    /// live tree, so it stays correct after mutation.
    pub fn find_phandle(&self, ph: NonZeroU32) -> Option<&OwnedNode> {
        self.root.find_with_phandle(ph)
    }

    /// Remove a node by absolute path, returning the removed subtree. `None`
    /// for a missing node or a non-`/` path.
    pub fn remove_path(&mut self, path: &str) -> Option<OwnedNode> {
        let rest = path.strip_prefix('/')?;
        let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        let (last, parents) = segs.split_last()?;
        let mut node = &mut self.root;
        for &seg in parents {
            node = node.child_mut(seg)?;
        }
        node.remove_child(last)
    }

    /// Remove a node by its `phandle`, returning the removed subtree. Walks the
    /// live tree. The root cannot be removed, so `remove_phandle` of a phandle
    /// carried by the root yields `None` (whereas [`Self::find_phandle`] matches
    /// it).
    pub fn remove_phandle(&mut self, ph: NonZeroU32) -> Option<OwnedNode> {
        self.root.remove_descendant_with_phandle(ph)
    }

    /// Encode this tree to flattened-devicetree bytes — the structural inverse
    /// of [`Self::materialize`].
    ///
    /// A tree produced by [`Self::materialize`] (or built within the FDT
    /// invariants) re-parses with [`Tree::parse`](crate::Tree::parse). `encode`
    /// performs no structural validation, so a hand-built tree that violates an
    /// invariant — e.g. a reserved `phandle` value (0 or `u32::MAX`) — encodes
    /// here but is rejected at re-parse; validation happens there, not here.
    ///
    /// The header's `boot_cpuid_phys` is emitted as 0: the crate does not carry
    /// it through `parse`/`materialize` (the overlay applier zeroes it too), so
    /// a non-zero boot CPU id does not round-trip.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] reporting `SizeOverflow` if the tree is too large
    /// for the FDT header's 32-bit size/offset fields.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut strings = Strings::new();
        let mut structure: Vec<u8> = Vec::new();
        self.root.emit(&mut structure, &mut strings)?;
        push_u32(&mut structure, FDT_END);

        // Memory-reservation block: entries then the (0, 0) terminator. Each
        // entry is two big-endian u64s, so the block is 8-byte aligned.
        let mut memrsv: Vec<u8> = Vec::new();
        for r in &self.reservations {
            memrsv.extend_from_slice(&r.address.to_be_bytes());
            memrsv.extend_from_slice(&r.size.to_be_bytes());
        }
        memrsv.extend_from_slice(&0u64.to_be_bytes());
        memrsv.extend_from_slice(&0u64.to_be_bytes());

        // Block offsets. The header is 40 bytes (8-aligned); the memrsv block is
        // a whole number of 16-byte entries (8-aligned); the structure block is
        // 4-aligned by construction — so every block starts aligned with no
        // inter-block padding.
        let off_mem_rsvmap = FDT_HEADER_SIZE;
        let off_dt_struct = off_mem_rsvmap
            .checked_add(memrsv.len())
            .ok_or(MalformedKind::SizeOverflow)?;
        let off_dt_strings = off_dt_struct
            .checked_add(structure.len())
            .ok_or(MalformedKind::SizeOverflow)?;
        let totalsize = off_dt_strings
            .checked_add(strings.bytes.len())
            .ok_or(MalformedKind::SizeOverflow)?;

        let header = build_header(
            u32_or(totalsize)?,
            u32_or(off_dt_struct)?,
            u32_or(off_dt_strings)?,
            u32_or(off_mem_rsvmap)?,
            u32_or(structure.len())?,
            u32_or(strings.bytes.len())?,
        );

        let mut out = Vec::with_capacity(totalsize);
        out.extend_from_slice(&header);
        out.extend_from_slice(&memrsv);
        out.extend_from_slice(&structure);
        out.extend_from_slice(&strings.bytes);
        Ok(out)
    }
}

impl<T: TreeView> From<&T> for OwnedTree {
    /// Equivalent to [`OwnedTree::materialize`]; the named method advertises
    /// the copy cost, this is the idiomatic conversion spelling.
    fn from(view: &T) -> Self {
        OwnedTree::materialize(view)
    }
}

// ── shared read-side traits, on the `Copy` references ──
//
// Implementing the existing zero-copy traits on `&OwnedNode` / `&OwnedProperty`
// (both `Copy`) lets generic `N: NodeView` / `P: PropertyView` code accept the
// owned representation with no changes. Mutation/removal stays inherent (a
// `Copy` read handle can't mutate).

impl crate::sealed::Sealed for &OwnedProperty {}
impl crate::sealed::Sealed for &OwnedNode {}
impl crate::sealed::Sealed for &OwnedTree {}

impl PropertyView for &OwnedProperty {
    fn name(&self) -> &str {
        &self.name
    }

    fn as_u32(&self) -> Option<u32> {
        value_as_u32(&self.bytes)
    }

    fn as_u64(&self) -> Option<u64> {
        value_as_u64(&self.bytes)
    }

    fn as_str(&self) -> Option<&str> {
        value_as_str(&self.bytes)
    }

    fn as_u32s(&self) -> Option<impl Iterator<Item = u32> + '_> {
        value_as_u32s(&self.bytes)
    }

    fn as_strs(&self) -> Option<impl Iterator<Item = &str> + '_> {
        value_as_strs(&self.bytes)
    }
}

impl<'a> NodeView for &'a OwnedNode {
    type Property = &'a OwnedProperty;

    fn name(&self) -> &str {
        &self.name
    }

    fn properties(&self) -> impl Iterator<Item = Self::Property> + '_ {
        // Copy the inner `&'a OwnedNode` out so the iterator borrows for `'a`
        // (outliving `&self`), matching the trait's `Item = Self::Property`.
        let inner: &'a OwnedNode = self;
        inner.props.iter()
    }

    fn children(&self) -> impl Iterator<Item = Self> + '_ {
        let inner: &'a OwnedNode = self;
        inner.children.iter()
    }

    fn phandle(&self) -> Option<NonZeroU32> {
        OwnedNode::phandle(self)
    }
}

impl<'a> TreeView for &'a OwnedTree {
    type Node = &'a OwnedNode;

    fn root(&self) -> Self::Node {
        let inner: &'a OwnedTree = self;
        &inner.root
    }

    fn find_phandle(&self, ph: NonZeroU32) -> Option<Self::Node> {
        let inner: &'a OwnedTree = self;
        inner.find_phandle(ph)
    }

    fn reservations(&self) -> impl Iterator<Item = Reservation> + '_ {
        self.reservations.iter().copied()
    }
}
