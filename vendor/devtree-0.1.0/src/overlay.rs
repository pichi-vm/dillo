// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Overlay layer.
//!
//! Two operations:
//!
//! 1. [`Overlay::parse`] turns a DTBO blob into a structural view: a
//!    list of [`Fragment`]s, each carrying its [`Target`] and
//!    the `__overlay__` subnode whose contents are the proposed
//!    changes. Callers can enumerate fragments and walk their
//!    `__overlay__` subtrees to run policy *before* applying.
//!
//! 2. [`OverlayView::apply`] resolves every fragment's target against
//!    a base [`Tree`], computes the phandle shift, and merges the
//!    overlay into a caller-supplied buffer in one pass. Returns the
//!    number of bytes actually written. On `BufferTooSmall { needed }`
//!    the caller can size a new buffer to `needed` and retry.
//!
//! The const-generic caps `FRAGS`, `REWRITES`, `LAYERS` bound the
//! fixed-size internal arrays. The defaults (`16`, `64`, `4`) fit
//! every overlay this crate has seen in the wild; callers with
//! larger overlays can opt into bigger limits:
//!
//! ```ignore
//! let overlay: Overlay<32, 128, 8> = Overlay::parse(blob)?;
//! ```
//!
//! Format limitation — deletion is not supported, and cannot be:
//! `/delete-node/` and `/delete-property/` are DTS source directives
//! that dtc resolves at compile time. The DTBO binary format defines
//! no deletion token.

use crate::cursor::align_up_4;
use crate::error::{Error, Limit, MalformedKind};
use crate::fdt::{
    FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_PROP, Node, NodeView, Property, PropertyView, Tree,
    TreeView,
};
use crate::header::FDT_HEADER_SIZE;
use crate::writer::{WriteCursor, build_header, u32_or};

/// PROP token (4) + len (4) + name_off (4). Derived from the FDT v17
/// wire format, not a tunable.
const PROP_HEADER_SIZE: usize = 12;

/// How a fragment names the base node it patches.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    /// `target-path = "/path"` — literal absolute path into the base.
    Path(&'a str),
    /// `target = <&label>` — the label name from the overlay's
    /// `/__fixups__`. The base must declare this label in
    /// `/__symbols__` at apply time.
    Label(&'a str),
}

/// A single overlay fragment.
#[derive(Debug, Clone, Copy)]
pub struct Fragment<'a> {
    name: &'a str,
    target: Target<'a>,
    overlay_node: Node<'a>,
}

impl<'a> Fragment<'a> {
    /// Fragment node name (e.g. `"fragment@0"`).
    pub fn name(self) -> &'a str {
        self.name
    }
    /// Where this fragment will be applied.
    pub fn target(self) -> Target<'a> {
        self.target
    }
    /// The `__overlay__` subnode — the proposed changes.
    pub fn node(self) -> Node<'a> {
        self.overlay_node
    }
}

/// Parsed DTBO with introspectable fragments.
///
/// Three const generics, all with defaults:
/// - `FRAGS` — max fragments per overlay (16). Real host overlays carry a handful.
/// - `REWRITES` — max `__fixups__` + `__local_fixups__` entries combined (64).
/// - `LAYERS` — max overlay layers at a single node during merge (4).
///
/// # Size
///
/// `Overlay` carries inline arrays sized by the const generics. With
/// the default `FRAGS=16` it weighs roughly 1 KB — large enough that
/// it intentionally does **not** implement `Copy`. Pass it by
/// reference (`&overlay`) on the hot path; `Clone` is available for
/// when you really do need to duplicate it.
#[derive(Debug, Clone)]
pub struct Overlay<'a, const FRAGS: usize = 16, const REWRITES: usize = 64, const LAYERS: usize = 4>
{
    blob: Tree<'a>,
    // `/__fixups__` and `/__local_fixups__`, resolved once at parse so
    // `apply` doesn't pay tree walks per call.
    fixups: Option<Node<'a>>,
    local_fixups: Option<Node<'a>>,
    // True if `/__fixups__` carries any non-`:target:` entry. For the
    // typical pure-plugin overlay this is false, and `build_context`
    // skips the per-apply __fixups__ walk entirely.
    has_rewrite_fixups: bool,
    // Per-fragment overlay-side metadata captured at parse time.
    // Base-side target resolution still happens at apply (since it
    // depends on the base tree).
    cached_frags: [Option<CachedFrag<'a>>; FRAGS],
    cached_frag_count: usize,
}

// Overlay-side fragment metadata captured at parse time.
//
// `Target::Label` carries the label name resolved from `/__fixups__`
// at parse, so apply only needs the base's `/__symbols__` to finish
// resolving it.
#[derive(Debug, Clone, Copy)]
struct CachedFrag<'a> {
    name: &'a str,
    overlay_node: Node<'a>,
    target: Target<'a>,
}

/// Runtime bound on merge-walk recursion depth. Sized to comfortably
/// cover real FDTs (typically 5–10 deep) plus any overlay layering.
const MERGE_DEPTH: u32 = 128;

impl<'a, const FRAGS: usize, const REWRITES: usize, const LAYERS: usize>
    Overlay<'a, FRAGS, REWRITES, LAYERS>
{
    /// Parse a DTBO blob. Walks all fragments once to surface
    /// structural errors at parse time.
    ///
    /// # Errors
    ///
    /// - Header/tree errors from [`Tree::parse`].
    /// - [`Error::Malformed`] for a fragment carrying `__overlay__`
    ///   but missing `target`/`target-path`, or other structural
    ///   malformedness in the DTBO.
    /// - [`Limit::Fragments`] if either the validated fragment count
    ///   or the total root-child scan exceeds the configured cap.
    pub fn parse(overlay_blob: &'a [u8]) -> Result<Self, Error> {
        let blob: Tree<'a> = Tree::parse(overlay_blob)?;

        // Cache metadata-node lookups: apply() needs them every call.
        // Resolving here at parse time turns three per-apply find_path
        // walks into zero.
        let fixups = blob.find_path("/__fixups__");
        let local_fixups = blob.find_path("/__local_fixups__");
        // Decide once whether /__fixups__ holds any phandle-rewrite
        // entries (non-`:target:`). For the typical plugin overlay
        // (target-only fragments, no internal phandle refs) this is
        // false, and build_context can skip the per-call walk.
        let has_rewrite_fixups = if let Some(fx) = fixups {
            let mut any = false;
            'props: for prop in fx.properties() {
                for entry in null_separated_strings(prop.value)? {
                    if !entry.contains(":target:") {
                        any = true;
                        break 'props;
                    }
                }
            }
            any
        } else {
            false
        };

        // Walk root_children once to validate fragment structure AND
        // capture per-fragment overlay-side metadata. Base-side
        // resolution still happens at apply time.
        //
        // Cap unrelated root children at ~4× FRAGS plus headroom —
        // defends against blobs of irrelevant root nodes inflating the
        // scan, while leaving room for the usual `__symbols__` /
        // `__fixups__` / `__local_fixups__` siblings. Exceeding the
        // cap surfaces as `Limit::Fragments` so callers see the same
        // remediation as a fragment-cap overflow.
        let mut cached_frags: [Option<CachedFrag<'a>>; FRAGS] = [None; FRAGS];
        let mut cached_frag_count = 0usize;
        let root_child_cap = FRAGS.saturating_mul(4).saturating_add(16);
        let mut seen = 0usize;
        for child in blob.root_children() {
            seen = seen.checked_add(1).ok_or(Limit::Fragments)?;
            if seen > root_child_cap {
                return Err(Limit::Fragments.into());
            }
            let Some(overlay_node) = child.child("__overlay__") else {
                continue;
            };
            let slot = cached_frags
                .get_mut(cached_frag_count)
                .ok_or(Limit::Fragments)?;
            let target = if let Some(p) = child.property("target-path") {
                Target::Path(parse_target_path_value(p.value, p.value_struct_offset)?)
            } else if child.property("target").is_some() {
                // Resolve the label from /__fixups__ now so build_context
                // doesn't re-walk /__fixups__ per apply() call.
                let label = fixup_label_for_cached(fixups, child.name)?;
                Target::Label(label)
            } else {
                return Err(MalformedKind::BadFragmentStructure.into());
            };
            *slot = Some(CachedFrag {
                name: child.name,
                overlay_node,
                target,
            });
            cached_frag_count = cached_frag_count.checked_add(1).ok_or(Limit::Fragments)?;
        }

        Ok(Self {
            blob,
            fixups,
            local_fixups,
            has_rewrite_fixups,
            cached_frags,
            cached_frag_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Per-apply state.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct ResolvedFragment<'a> {
    target_body_offset: u32,
    overlay_node: Node<'a>,
}

#[derive(Debug, Clone, Copy)]
struct Rewrite {
    value_struct_offset: u32,
    byte_offset: u32,
    kind: RewriteKind,
}

#[derive(Debug, Clone, Copy)]
enum RewriteKind {
    Replace(u32),
    Shift(u32),
}

#[derive(Debug, Clone, Copy)]
struct ApplyCtx<'a, const FRAGS: usize, const REWRITES: usize> {
    fragments: [Option<ResolvedFragment<'a>>; FRAGS],
    frag_count: usize,
    rewrites: [Option<Rewrite>; REWRITES],
    rw_count: usize,
    phandle_shift: u32,
}

impl<'a, const FRAGS: usize, const REWRITES: usize> ApplyCtx<'a, FRAGS, REWRITES> {
    fn fragments_slice(&self) -> &[Option<ResolvedFragment<'a>>] {
        self.fragments.get(..self.frag_count).unwrap_or(&[])
    }
    fn rewrites_slice(&self) -> &[Option<Rewrite>] {
        self.rewrites.get(..self.rw_count).unwrap_or(&[])
    }
}

fn build_context<
    'a,
    'b,
    const FRAGS: usize,
    const REWRITES: usize,
    const LAYERS: usize,
    const D: u32,
    const M: u32,
>(
    overlay: &Overlay<'a, FRAGS, REWRITES, LAYERS>,
    base: &Tree<'b, D, M>,
    overlay_depth: u32,
) -> Result<ApplyCtx<'a, FRAGS, REWRITES>, Error> {
    let overlay_tree = overlay.blob;
    let overlay_fixups = overlay.fixups;
    let overlay_local_fixups = overlay.local_fixups;
    let has_rewrite_fixups = overlay.has_rewrite_fixups;
    let cached_frags = &overlay.cached_frags;
    let cached_frag_count = overlay.cached_frag_count;
    let phandle_shift = compute_phandle_shift(base)?;
    let base_symbols = base.symbols();

    // Pass 1: convert cached overlay-side fragment metadata into
    // resolved fragments. Path-target fragments resolve directly
    // against the base. Label-target fragments use the label captured
    // at Overlay::parse time to look up the base symbol, eliminating
    // the per-apply /__fixups__ walk that earlier versions did.
    //
    // A per-label resolution cache (resolved_by_label) is shared with
    // pass 2 — if the same label is referenced by both a fragment and
    // a phandle rewrite, base is only touched once.
    let mut fragments: [Option<ResolvedFragment<'a>>; FRAGS] = [None; FRAGS];
    let mut resolved_by_label: [Option<(&'a str, u32, Option<core::num::NonZeroU32>)>; FRAGS] =
        [None; FRAGS];
    let mut resolved_count = 0usize;

    for (i, cf) in cached_frags.iter().take(cached_frag_count).enumerate() {
        let Some(cf) = cf else { continue };
        let slot = fragments.get_mut(i).ok_or(Limit::Fragments)?;
        match cf.target {
            Target::Path(path) => {
                let target = base
                    .find_path(path)
                    .ok_or(MalformedKind::UnresolvedTarget)?;
                *slot = Some(ResolvedFragment {
                    target_body_offset: target.body_offset,
                    overlay_node: cf.overlay_node,
                });
            }
            Target::Label(label) => {
                let symbols = base_symbols.as_ref().ok_or(MalformedKind::UnknownSymbol)?;
                let sym_prop = symbols
                    .property(label)
                    .ok_or(MalformedKind::UnknownSymbol)?;
                let path = sym_prop.as_str().ok_or(MalformedKind::UnknownSymbol)?;
                let target = base
                    .find_path(path)
                    .ok_or(MalformedKind::UnresolvedTarget)?;
                let body_off = target.body_offset;
                let ph = target.phandle();
                *slot = Some(ResolvedFragment {
                    target_body_offset: body_off,
                    overlay_node: cf.overlay_node,
                });
                if let Some(rs) = resolved_by_label.get_mut(resolved_count) {
                    *rs = Some((label, body_off, ph));
                    resolved_count = resolved_count.saturating_add(1);
                }
            }
        }
    }

    // Pass 2: walk /__fixups__ once for phandle rewrites only.
    // `:target:` entries that associate fragments with labels are
    // already handled at parse time via CachedFrag::Label, and Pass 1
    // resolved those labels — `resolved_by_label` caches the lookup so
    // a property fixup against the same label doesn't redo it.
    let mut rewrites: [Option<Rewrite>; REWRITES] = [None; REWRITES];
    let mut rw_count = 0usize;

    if has_rewrite_fixups && let Some(fixups) = overlay_fixups {
        for prop in fixups.properties() {
            let label = prop.name;
            let raw = prop.value;
            let entries = null_separated_strings(raw)?;
            let mut resolved: Option<(u32, Option<core::num::NonZeroU32>)> = None;

            for entry in entries {
                if entry.contains(":target:") {
                    continue;
                }
                // Rewrite entry — needs target phandle.
                let (_body_off, ph_opt) = if let Some(r) = &resolved {
                    *r
                } else {
                    // Try the per-label cache populated by pass 1.
                    let cached = resolved_by_label
                        .iter()
                        .take(resolved_count)
                        .flatten()
                        .find(|(l, _, _)| *l == label)
                        .copied();
                    let r = if let Some((_, body, ph)) = cached {
                        (body, ph)
                    } else {
                        let symbols = base_symbols.as_ref().ok_or(MalformedKind::UnknownSymbol)?;
                        let sym_prop = symbols
                            .property(label)
                            .ok_or(MalformedKind::UnknownSymbol)?;
                        let path = sym_prop.as_str().ok_or(MalformedKind::UnknownSymbol)?;
                        let target = base
                            .find_path(path)
                            .ok_or(MalformedKind::UnresolvedTarget)?;
                        (target.body_offset, target.phandle())
                    };
                    resolved = Some(r);
                    r
                };
                let tp = ph_opt.ok_or(MalformedKind::UnresolvedTarget)?.get();
                let (overlay_path, prop_name, byte_offset) = parse_fixup_entry(entry)?;
                let (prop_value_offset, prop_value_len) =
                    locate_overlay_property(overlay_tree, overlay_path, prop_name)?;
                check_rewrite_in_bounds(byte_offset, prop_value_len)?;
                push_rewrite(
                    &mut rewrites,
                    &mut rw_count,
                    Rewrite {
                        value_struct_offset: prop_value_offset,
                        byte_offset,
                        kind: RewriteKind::Replace(tp),
                    },
                )?;
            }
        }
    }

    if let Some(local_fixups) = overlay_local_fixups {
        walk_local_fixups(
            local_fixups,
            overlay_tree.root(),
            phandle_shift,
            &mut rewrites,
            &mut rw_count,
            overlay_depth,
        )?;
    }

    Ok(ApplyCtx {
        fragments,
        frag_count: cached_frag_count,
        rewrites,
        rw_count,
        phandle_shift,
    })
}

/// Find the label name in `/__fixups__` whose value contains a
/// `:target:0` entry for the given fragment. `BadFragmentStructure`
/// if the overlay has no `/__fixups__`, or no entry matches.
fn fixup_label_for_cached<'a>(fixups: Option<Node<'a>>, frag_name: &str) -> Result<&'a str, Error> {
    let fixups = fixups.ok_or(MalformedKind::BadFragmentStructure)?;
    for prop in fixups.properties() {
        for s in null_separated_strings(prop.value)? {
            let Some(rest) = s.strip_prefix('/') else {
                continue;
            };
            let Some(rest) = rest.strip_prefix(frag_name) else {
                continue;
            };
            if rest == ":target:0" {
                return Ok(prop.name);
            }
        }
    }
    Err(MalformedKind::BadFragmentStructure.into())
}

// ---------------------------------------------------------------------------
// Fragment-target decoding (called by Overlay::parse).
// ---------------------------------------------------------------------------

/// Validate and decode a `target-path` property value as a
/// NUL-terminated UTF-8 string, preserving the `'a` lifetime of the
/// underlying blob.
fn parse_target_path_value(value: &[u8], offset: u32) -> Result<&str, Error> {
    let bad = || Error::from(MalformedKind::BadString { offset });
    let nul = value.iter().position(|&b| b == 0).ok_or_else(bad)?;
    if nul.checked_add(1).ok_or_else(bad)? != value.len() {
        return Err(bad());
    }
    core::str::from_utf8(value.get(..nul).ok_or_else(bad)?).map_err(|_| bad())
}

/// NUL-separated UTF-8 piece iterator. Pre-validates UTF-8 so the
/// inner iterator is infallible.
fn null_separated_strings(raw: &[u8]) -> Result<NullSepIter<'_>, Error> {
    for piece in raw.split(|&b| b == 0) {
        if piece.is_empty() {
            continue;
        }
        core::str::from_utf8(piece).map_err(|_| MalformedKind::BadFixupEntry)?;
    }
    Ok(NullSepIter { raw, pos: 0 })
}

struct NullSepIter<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for NullSepIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        loop {
            let rest = self.raw.get(self.pos..)?;
            if rest.is_empty() {
                return None;
            }
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let piece = rest.get(..end)?;
            self.pos = self.pos.saturating_add(end).saturating_add(1);
            if piece.is_empty() {
                continue;
            }
            return Some(core::str::from_utf8(piece).unwrap_or(""));
        }
    }
}

// ---------------------------------------------------------------------------
// Phandle shift + rewrite collection.
// ---------------------------------------------------------------------------

fn compute_phandle_shift<const D: u32, const M: u32>(base: &Tree<'_, D, M>) -> Result<u32, Error> {
    base.max_phandle()
        .checked_add(1)
        .ok_or(MalformedKind::PhandleOverflow.into())
}

fn walk_local_fixups<'a>(
    lf_node: Node<'a>,
    overlay_node: Node<'a>,
    shift: u32,
    rewrites: &mut [Option<Rewrite>],
    count: &mut usize,
    depth: u32,
) -> Result<(), Error> {
    if depth == 0 {
        return Err(Limit::Depth.into());
    }
    for lf_prop in lf_node.properties() {
        let target_prop = overlay_node
            .properties()
            .find(|p| p.name == lf_prop.name)
            .ok_or(MalformedKind::FixupTargetMissing)?;
        let value_struct_offset = target_prop.value_struct_offset;
        let target_len = target_prop.value.len();
        let raw = lf_prop.value;
        if !raw.len().is_multiple_of(4) {
            return Err(MalformedKind::BadFixupEntry.into());
        }
        for chunk in raw.chunks_exact(4) {
            let arr: [u8; 4] = chunk.try_into().map_err(|_| MalformedKind::BadFixupEntry)?;
            let byte_offset = u32::from_be_bytes(arr);
            check_rewrite_in_bounds(byte_offset, target_len)?;
            push_rewrite(
                rewrites,
                count,
                Rewrite {
                    value_struct_offset,
                    byte_offset,
                    kind: RewriteKind::Shift(shift),
                },
            )?;
        }
    }
    for lf_child in lf_node.children() {
        let overlay_child = overlay_node
            .child(lf_child.name)
            .ok_or(MalformedKind::FixupTargetMissing)?;
        let next_depth = depth.saturating_sub(1);
        walk_local_fixups(lf_child, overlay_child, shift, rewrites, count, next_depth)?;
    }
    Ok(())
}

fn parse_fixup_entry(s: &str) -> Result<(&str, &str, u32), Error> {
    let last = s.rfind(':').ok_or(MalformedKind::BadFixupEntry)?;
    let (head, off_str) = s.split_at(last);
    let off_str = off_str.get(1..).ok_or(MalformedKind::BadFixupEntry)?;
    let byte_offset = parse_u32_decimal_strict(off_str).ok_or(MalformedKind::BadFixupEntry)?;
    let mid = head.rfind(':').ok_or(MalformedKind::BadFixupEntry)?;
    let (path, prop) = head.split_at(mid);
    let prop = prop.get(1..).ok_or(MalformedKind::BadFixupEntry)?;
    Ok((path, prop, byte_offset))
}

/// Strict ASCII decimal `u32` parser: no signs, no whitespace, no
/// leading `+`, no leading zeros beyond a single `0`. Matches the
/// DTBO format spec exactly so parser-divergence-friendly inputs (`+5`,
/// ` 5`, `005`) are rejected, not silently accepted as `5`.
fn parse_u32_decimal_strict(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    // Reject leading zeros (except literal "0").
    if bytes.len() > 1 && bytes.first() == Some(&b'0') {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        let d = u64::from(b.wrapping_sub(b'0'));
        acc = acc.checked_mul(10)?.checked_add(d)?;
        if acc > u64::from(u32::MAX) {
            return None;
        }
    }
    u32::try_from(acc).ok()
}

fn locate_overlay_property(
    overlay: Tree<'_>,
    path: &str,
    prop_name: &str,
) -> Result<(u32, usize), Error> {
    let node = overlay
        .find_path(path)
        .ok_or(MalformedKind::BadFixupEntry)?;
    let prop = node
        .properties()
        .find(|p| p.name == prop_name)
        .ok_or(MalformedKind::BadFixupEntry)?;
    Ok((prop.value_struct_offset, prop.value.len()))
}

fn check_rewrite_in_bounds(byte_offset: u32, value_len: usize) -> Result<(), Error> {
    let end = (byte_offset as usize)
        .checked_add(4)
        .ok_or(MalformedKind::BadFixupEntry)?;
    if end > value_len {
        return Err(MalformedKind::BadFixupEntry.into());
    }
    Ok(())
}

fn push_rewrite(
    rewrites: &mut [Option<Rewrite>],
    count: &mut usize,
    r: Rewrite,
) -> Result<(), Error> {
    let slot = rewrites.get_mut(*count).ok_or(Limit::Rewrites)?;
    *slot = Some(r);
    *count = count.checked_add(1).ok_or(Limit::Rewrites)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Merge walk.
// ---------------------------------------------------------------------------

enum PropEmit<'a> {
    Base(&'a [u8]),
    Overlay {
        name: &'a str,
        raw: &'a [u8],
        value_struct_offset: u32,
    },
}

impl<'a> PropEmit<'a> {
    fn raw(&self) -> &'a [u8] {
        match *self {
            PropEmit::Base(raw) | PropEmit::Overlay { raw, .. } => raw,
        }
    }
}

struct WriteSink<'b> {
    structs: WriteCursor<'b>,
    strings: WriteCursor<'b>,
}

impl WriteSink<'_> {
    fn begin_node(&mut self, name: &str) -> Result<(), Error> {
        // Single contiguous append: BEGIN_NODE + name + NUL + padding.
        let name_bytes = name.as_bytes();
        let name_end = 4usize
            .checked_add(name_bytes.len())
            .ok_or(MalformedKind::SizeOverflow)?;
        let unpadded = name_end.checked_add(1).ok_or(MalformedKind::SizeOverflow)?;
        let padded = align_up_4(unpadded);
        self.structs.write_with::<_, Error>(padded, |slot| {
            #[allow(clippy::indexing_slicing)]
            {
                slot[0..4].copy_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
                slot[4..name_end].copy_from_slice(name_bytes);
                slot[name_end..padded].fill(0);
            }
            Ok(())
        })?;
        Ok(())
    }
    fn property<const FRAGS: usize, const REWRITES: usize>(
        &mut self,
        name: &str,
        prop: PropEmit<'_>,
        ctx: &ApplyCtx<'_, FRAGS, REWRITES>,
    ) -> Result<(), Error> {
        let name_off = u32_or(self.strings.pos())?;
        let name_bytes = name.as_bytes();
        let name_total = name_bytes
            .len()
            .checked_add(1)
            .ok_or(MalformedKind::SizeOverflow)?;
        self.strings.write_with::<_, Error>(name_total, |slot| {
            #[allow(clippy::indexing_slicing)]
            {
                slot[..name_bytes.len()].copy_from_slice(name_bytes);
                slot[name_bytes.len()] = 0;
            }
            Ok(())
        })?;

        let raw = prop.raw();
        let len = raw.len();
        // Single contiguous append: 12-byte PROP header + value + padding.
        let value_end = PROP_HEADER_SIZE
            .checked_add(len)
            .ok_or(MalformedKind::SizeOverflow)?;
        let padded = align_up_4(value_end);
        let len_u32 = u32_or(len)?;
        let (apply_rewrites, prop_name, value_struct_offset) = match prop {
            PropEmit::Base(_) => (false, "", 0u32),
            PropEmit::Overlay {
                name: pn,
                value_struct_offset,
                ..
            } => (true, pn, value_struct_offset),
        };
        self.structs.write_with::<_, Error>(padded, |slot| {
            #[allow(clippy::indexing_slicing)]
            {
                slot[0..4].copy_from_slice(&FDT_PROP.to_be_bytes());
                slot[4..8].copy_from_slice(&len_u32.to_be_bytes());
                slot[8..12].copy_from_slice(&name_off.to_be_bytes());
                let value_slot = &mut slot[PROP_HEADER_SIZE..value_end];
                value_slot.copy_from_slice(raw);
                if apply_rewrites {
                    apply_rewrites_inplace(value_slot, prop_name, value_struct_offset, ctx)?;
                }
                if padded > value_end {
                    slot[value_end..padded].fill(0);
                }
            }
            Ok(())
        })?;
        Ok(())
    }
    fn end_node(&mut self) -> Result<(), Error> {
        self.structs.write_u32_be(FDT_END_NODE)?;
        Ok(())
    }
}

/// Find the latest overlay layer that defines a property named `name`.
/// Walks layers from last to first.
fn latest_override<'a>(
    layers: &[Option<Node<'a>>],
    count: usize,
    name: &str,
) -> Option<Property<'a>> {
    for slot in layers.get(..count).unwrap_or(&[]).iter().rev() {
        if let Some(layer) = slot
            && let Some(p) = NodeView::property(layer, name)
        {
            return Some(p);
        }
    }
    None
}

/// True if any earlier layer (index `< stop`) defines `name`.
fn earlier_has(layers: &[Option<Node<'_>>], stop: usize, name: &str) -> bool {
    layers
        .get(..stop)
        .unwrap_or(&[])
        .iter()
        .flatten()
        .any(|l| NodeView::property(l, name).is_some())
}

/// True if any earlier layer (index `< stop`) defines a child named `name`.
fn earlier_has_child(layers: &[Option<Node<'_>>], stop: usize, name: &str) -> bool {
    layers
        .get(..stop)
        .unwrap_or(&[])
        .iter()
        .flatten()
        .any(|l| l.child(name).is_some())
}

/// Recursive merge walk that writes into a [`WriteSink`].
///
/// Per frame:
/// 1. Compute this frame's layer set: parent layers descended by name,
///    plus any top-level fragments whose target matches this base node.
/// 2. Emit base properties (preferring the latest layer's override if
///    any).
/// 3. Emit overlay-only properties: walk each layer in order; for each
///    property name not already emitted, emit the *latest* layer's
///    version of it. The earlier-layer dedup is done by checking
///    `earlier_has` at each position.
/// 4. Recurse into children: base children first (each merged with
///    matching overlay children), then overlay-only children.
fn walk_merged<'a, 'b, const FRAGS: usize, const REWRITES: usize, const LAYERS: usize>(
    base: Option<&Node<'b>>,
    name: &str,
    parent_layers: &[Option<Node<'a>>],
    parent_count: usize,
    ctx: &ApplyCtx<'a, FRAGS, REWRITES>,
    sink: &mut WriteSink<'_>,
    depth: u32,
) -> Result<(), Error> {
    let next_depth = depth.checked_sub(1).ok_or(Limit::Depth)?;

    let mut my_layers: [Option<Node<'a>>; LAYERS] = [None; LAYERS];
    let mut my_count = 0usize;

    // Inherited: parent layers descended by current node name (in order).
    for parent_overlay in parent_layers
        .get(..parent_count)
        .unwrap_or(&[])
        .iter()
        .flatten()
    {
        if let Some(child) = parent_overlay.child(name) {
            push_layer(&mut my_layers, &mut my_count, child)?;
        }
    }

    // Top-level fragments targeting this base node — appended (later wins).
    if let Some(base_node) = base {
        let bo = base_node.body_offset;
        for frag in ctx.fragments_slice().iter().flatten() {
            if frag.target_body_offset == bo {
                push_layer(&mut my_layers, &mut my_count, frag.overlay_node)?;
            }
        }
    }

    sink.begin_node(name)?;

    // Emit base props (with latest-layer overrides).
    if let Some(base_node) = base {
        for prop in base_node.properties() {
            match latest_override(&my_layers, my_count, prop.name) {
                Some(op) => sink.property(
                    op.name,
                    PropEmit::Overlay {
                        name: op.name,
                        raw: op.value,
                        value_struct_offset: op.value_struct_offset,
                    },
                    ctx,
                )?,
                None => sink.property(prop.name, PropEmit::Base(prop.value), ctx)?,
            }
        }
    }

    // Emit overlay-only props. For each layer in order, for each prop
    // not yet emitted (not in base, not in earlier layer), emit the
    // *latest* version of it. The earlier-layer dedup is done by
    // checking `earlier_has` at each position.
    for (layer_idx, slot) in my_layers.get(..my_count).unwrap_or(&[]).iter().enumerate() {
        let Some(layer) = slot else {
            continue;
        };
        for op in layer.properties() {
            // Already emitted in base loop?
            if let Some(base_node) = base
                && base_node.property(op.name).is_some()
            {
                continue;
            }
            // Already emitted by earlier layer?
            if earlier_has(&my_layers, layer_idx, op.name) {
                continue;
            }
            // Emit latest layer's version (may be a later one).
            let chosen = latest_override(&my_layers, my_count, op.name).unwrap_or(op);
            sink.property(
                chosen.name,
                PropEmit::Overlay {
                    name: chosen.name,
                    raw: chosen.value,
                    value_struct_offset: chosen.value_struct_offset,
                },
                ctx,
            )?;
        }
    }

    // Recurse into base children (each merged with matching overlay children).
    if let Some(base_node) = base {
        for child in base_node.children() {
            walk_merged::<FRAGS, REWRITES, LAYERS>(
                Some(&child),
                child.name,
                &my_layers,
                my_count,
                ctx,
                sink,
                next_depth,
            )?;
        }
    }

    // Overlay-only children: dedup by name across layers; visit at the
    // earliest layer that mentions a given child name.
    for (layer_idx, slot) in my_layers.get(..my_count).unwrap_or(&[]).iter().enumerate() {
        let Some(layer) = slot else {
            continue;
        };
        for ochild in layer.children() {
            let cname = ochild.name;
            if let Some(base_node) = base
                && base_node.child(cname).is_some()
            {
                continue;
            }
            if earlier_has_child(&my_layers, layer_idx, cname) {
                continue;
            }
            walk_merged::<FRAGS, REWRITES, LAYERS>(
                None, cname, &my_layers, my_count, ctx, sink, next_depth,
            )?;
        }
    }

    sink.end_node()?;
    Ok(())
}

fn push_layer<'a>(
    layers: &mut [Option<Node<'a>>],
    count: &mut usize,
    node: Node<'a>,
) -> Result<(), Error> {
    let slot = layers.get_mut(*count).ok_or(Limit::Layers)?;
    *slot = Some(node);
    *count = count.checked_add(1).ok_or(Limit::Layers)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rewrite application at write time.
// ---------------------------------------------------------------------------

fn apply_rewrites_inplace<const FRAGS: usize, const REWRITES: usize>(
    slot: &mut [u8],
    prop_name: &str,
    value_struct_offset: u32,
    ctx: &ApplyCtx<'_, FRAGS, REWRITES>,
) -> Result<(), Error> {
    if (prop_name == "phandle" || prop_name == "linux,phandle") && slot.len() == 4 {
        apply_shift(slot, 0, ctx.phandle_shift)?;
    }
    for r in ctx.rewrites_slice().iter().flatten() {
        if r.value_struct_offset != value_struct_offset {
            continue;
        }
        match r.kind {
            RewriteKind::Replace(v) => apply_replace(slot, r.byte_offset as usize, v)?,
            RewriteKind::Shift(s) => apply_shift(slot, r.byte_offset as usize, s)?,
        }
    }
    Ok(())
}

fn apply_replace(slot: &mut [u8], byte_offset: usize, value: u32) -> Result<(), Error> {
    let end = byte_offset
        .checked_add(4)
        .ok_or(MalformedKind::SizeOverflow)?;
    let target = slot
        .get_mut(byte_offset..end)
        .ok_or(MalformedKind::SizeOverflow)?;
    target.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn apply_shift(slot: &mut [u8], byte_offset: usize, shift: u32) -> Result<(), Error> {
    let end = byte_offset
        .checked_add(4)
        .ok_or(MalformedKind::SizeOverflow)?;
    let target = slot
        .get_mut(byte_offset..end)
        .ok_or(MalformedKind::SizeOverflow)?;
    let arr: [u8; 4] = (*target)
        .try_into()
        .map_err(|_| MalformedKind::SizeOverflow)?;
    let cur = u32::from_be_bytes(arr);
    let shifted = cur
        .checked_add(shift)
        .ok_or(MalformedKind::PhandleOverflow)?;
    // Refuse to emit reserved phandle values (0, u32::MAX). All three
    // failure modes — overflow, shift to 0, shift to u32::MAX — fold
    // under PhandleOverflow: the shift produced a phandle the crate
    // refuses to emit.
    if shifted == 0 || shifted == u32::MAX {
        return Err(MalformedKind::PhandleOverflow.into());
    }
    target.copy_from_slice(&shifted.to_be_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------
// memrsv: passthrough from base.
// ---------------------------------------------------------------------------

fn write_memrsv<const D: u32, const M: u32>(
    base: &Tree<'_, D, M>,
    dst: &mut [u8],
) -> Result<(), Error> {
    let mut pos: usize = 0;
    for entry in base.reservations() {
        let end1 = pos.checked_add(8).ok_or(MalformedKind::SizeOverflow)?;
        dst.get_mut(pos..end1)
            .ok_or(MalformedKind::SizeOverflow)?
            .copy_from_slice(&entry.address.to_be_bytes());
        let end2 = end1.checked_add(8).ok_or(MalformedKind::SizeOverflow)?;
        dst.get_mut(end1..end2)
            .ok_or(MalformedKind::SizeOverflow)?
            .copy_from_slice(&entry.size.to_be_bytes());
        pos = end2;
    }
    let term_end = pos.checked_add(16).ok_or(MalformedKind::SizeOverflow)?;
    let term = dst
        .get_mut(pos..term_end)
        .ok_or(MalformedKind::SizeOverflow)?;
    term.fill(0);
    if let Some(tail) = dst.get_mut(term_end..) {
        tail.fill(0);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public overlay traits.
// ---------------------------------------------------------------------------

impl<const F: usize, const R: usize, const L: usize> crate::sealed::Sealed
    for Overlay<'_, F, R, L>
{
}

/// Read-side view of a parsed overlay.
///
/// Parse-time caps (`FRAGS`, `REWRITES`, `LAYERS`) live on the concrete
/// [`Overlay`] type. The trait abstracts over them so downstream code
/// can be generic without naming the consts.
pub trait OverlayView<'a>: crate::sealed::Sealed {
    /// Iterate the parsed fragments in declaration order.
    fn fragments(&self) -> impl Iterator<Item = Fragment<'a>> + '_;

    /// Merge this overlay against `base` into `dst` in a single pass.
    /// Returns the number of bytes actually written; the merged blob
    /// is `&dst[..n]`, not all of `dst`.
    ///
    /// The size check runs first and is the cheap path: passing a
    /// short or empty slice returns [`Error::BufferTooSmall`]
    /// without doing any merge work.
    ///
    /// # Errors
    ///
    /// - [`Error::BufferTooSmall`] with `needed` set to a strict
    ///   upper bound on output size. Allocating exactly `needed`
    ///   bytes guarantees the next call fits.
    /// - [`Error::Malformed`] for any of: unresolved fragment target,
    ///   missing base symbol, phandle shift producing a reserved value,
    ///   malformed overlay metadata, or arithmetic overflow on the
    ///   merged output's size/offset fields. Inspect `Display` for the
    ///   specific cause.
    #[must_use = "the returned byte count is the truncation point for `dst`"]
    fn apply<const D: u32, const M: u32>(
        &self,
        base: &Tree<'_, D, M>,
        dst: &mut [u8],
    ) -> Result<usize, Error>;
}

impl<'a, const F: usize, const R: usize, const L: usize> OverlayView<'a> for Overlay<'a, F, R, L> {
    fn fragments(&self) -> impl Iterator<Item = Fragment<'a>> + '_ {
        self.cached_frags
            .iter()
            .take(self.cached_frag_count)
            .flatten()
            .map(|cf| Fragment {
                name: cf.name,
                target: cf.target,
                overlay_node: cf.overlay_node,
            })
    }

    fn apply<const D: u32, const M: u32>(
        &self,
        base: &Tree<'_, D, M>,
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        // Upper bounds, derived structurally from header fields
        // without walking the merge. The struct block is bounded by
        // base+overlay struct lengths plus a 4-byte FDT_END marker
        // (overlay metadata nodes don't contribute, so the bound is
        // loose but cheap and correct). The strings block is bounded
        // by sum of per-prop name bytes — walk_merged writes each
        // property name on every emission with no dedup, so the
        // source strings-block length is *not* a valid bound here.
        let struct_upper = base
            .struct_block_len()
            .checked_add(self.blob.struct_block_len())
            .and_then(|n| n.checked_add(4))
            .ok_or(MalformedKind::SizeOverflow)?;
        let strings_upper = base
            .prop_name_bytes()
            .checked_add(self.blob.prop_name_bytes())
            .ok_or(MalformedKind::SizeOverflow)?;
        let memrsv_size = memrsv_size_for(base)?;
        let total_upper = FDT_HEADER_SIZE
            .checked_add(memrsv_size)
            .and_then(|n| n.checked_add(struct_upper))
            .and_then(|n| n.checked_add(strings_upper))
            .ok_or(MalformedKind::SizeOverflow)?;
        let _ = u32_or(total_upper)?;

        if dst.len() < total_upper {
            return Err(Error::BufferTooSmall {
                needed: total_upper,
            });
        }

        // Build context only after the buffer is known adequate — no
        // sense doing the resolution work on a doomed call.
        let ctx = build_context::<F, R, L, _, _>(self, base, MERGE_DEPTH)?;

        let memrsv_off = FDT_HEADER_SIZE;
        let struct_off = memrsv_off
            .checked_add(memrsv_size)
            .ok_or(MalformedKind::SizeOverflow)?;

        // Single-pass layout: structs grow forward at `struct_off`;
        // strings grow forward at `struct_off + struct_upper` (the
        // worst case position structs could reach). At the end, the
        // strings region is memmove'd back to abut the actual struct
        // tail, and the header is written with the actual sizes.
        let strings_scratch_off = struct_off
            .checked_add(struct_upper)
            .ok_or(MalformedKind::SizeOverflow)?;

        let (struct_actual, strings_actual) = {
            let body = dst
                .get_mut(FDT_HEADER_SIZE..)
                .ok_or(MalformedKind::SizeOverflow)?;
            let (memrsv_dst, rest) = body
                .split_at_mut_checked(memrsv_size)
                .ok_or(MalformedKind::SizeOverflow)?;
            write_memrsv(base, memrsv_dst)?;

            let (struct_dst, rest) = rest
                .split_at_mut_checked(struct_upper)
                .ok_or(MalformedKind::SizeOverflow)?;
            let (strings_dst, _) = rest
                .split_at_mut_checked(strings_upper)
                .ok_or(MalformedKind::SizeOverflow)?;

            let mut write_sink = WriteSink {
                structs: WriteCursor::new(struct_dst),
                strings: WriteCursor::new(strings_dst),
            };
            let root = base.root();
            walk_merged::<F, R, L>(
                Some(&root),
                root.name,
                &[None; L],
                0,
                &ctx,
                &mut write_sink,
                MERGE_DEPTH,
            )?;
            write_sink.structs.write_u32_be(FDT_END)?;
            (write_sink.structs.pos(), write_sink.strings.pos())
        };

        // Move strings down to abut struct tail. `copy_within` is
        // bounds-safe: `src_end = strings_scratch_off + strings_actual
        // <= strings_scratch_off + strings_upper = struct_off +
        // struct_upper + strings_upper <= total_upper <= dst.len()`
        // (the buffer check above). Destination end is
        // `strings_final_off + strings_actual <= strings_scratch_off +
        // strings_actual = src_end`, so it also fits.
        let strings_final_off = struct_off
            .checked_add(struct_actual)
            .ok_or(MalformedKind::SizeOverflow)?;
        if strings_final_off < strings_scratch_off && strings_actual > 0 {
            let src_end = strings_scratch_off
                .checked_add(strings_actual)
                .ok_or(MalformedKind::SizeOverflow)?;
            dst.copy_within(strings_scratch_off..src_end, strings_final_off);
        }

        let total_actual = strings_final_off
            .checked_add(strings_actual)
            .ok_or(MalformedKind::SizeOverflow)?;
        let header = build_header(
            u32_or(total_actual)?,
            u32_or(struct_off)?,
            u32_or(strings_final_off)?,
            u32_or(memrsv_off)?,
            u32_or(struct_actual)?,
            u32_or(strings_actual)?,
        );
        dst.get_mut(..FDT_HEADER_SIZE)
            .ok_or(MalformedKind::SizeOverflow)?
            .copy_from_slice(&header);

        Ok(total_actual)
    }
}

/// Reservation block size: 16 bytes per entry plus the 16-byte (0,0)
/// terminator. `apply` needs this before deciding whether `dst` is
/// large enough, so it's a free function rather than a method on
/// `ApplyCtx` (the context isn't built until after the size check
/// passes).
fn memrsv_size_for<const D: u32, const M: u32>(base: &Tree<'_, D, M>) -> Result<usize, Error> {
    let mut entries: usize = 0;
    for _ in base.reservations() {
        entries = entries.checked_add(1).ok_or(MalformedKind::SizeOverflow)?;
    }
    entries
        .checked_add(1)
        .and_then(|n| n.checked_mul(16))
        .ok_or(MalformedKind::SizeOverflow.into())
}
