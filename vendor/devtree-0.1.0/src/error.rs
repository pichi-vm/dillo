// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Error types.
//!
//! Errors are categorized by **caller remediation**, not by the
//! subsystem that detected them:
//!
//! - [`Error::Malformed`] — input blob is structurally bad or
//!   references missing things. Caller rejects the blob. The variant
//!   is opaque; the `Display` impl carries the diagnostic detail
//!   (which subsystem, which offset).
//! - [`Error::LimitExceeded`] — a configured const-generic cap was
//!   too low for this input. Caller raises the named cap and retries.
//! - [`Error::BufferTooSmall`] — the destination buffer supplied to
//!   [`OverlayView::apply`](crate::OverlayView::apply) is smaller than
//!   the merged output's upper-bound size. Caller grows the buffer to
//!   `needed` bytes.

use core::fmt;

/// Top-level error for every public operation in this crate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input blob is structurally invalid or references missing things.
    /// The inner [`Malformed`] is opaque — pattern-matching on it is
    /// supported (so callers can detect this variant) but its internal
    /// kind is not exposed. The only caller remediation is to reject
    /// the blob; diagnostic detail lives in the `Display` impl.
    Malformed(Malformed),
    /// A configured const-generic cap was exceeded.
    LimitExceeded(Limit),
    /// Destination buffer supplied to
    /// [`OverlayView::apply`](crate::OverlayView::apply) is smaller
    /// than the merged output's strict upper bound. `needed` is that
    /// upper bound, not the additional bytes needed; the actual
    /// written size returned by a successful retry may be smaller.
    BufferTooSmall {
        /// Strict upper bound on bytes the destination buffer must hold.
        needed: usize,
    },
}

/// Opaque marker for a malformed-blob failure. Pattern-matchable via
/// [`Error::Malformed`]; carries diagnostic detail only through
/// [`Display`](fmt::Display).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed(MalformedKind);

impl From<MalformedKind> for Malformed {
    fn from(kind: MalformedKind) -> Self {
        Self(kind)
    }
}

impl From<MalformedKind> for Error {
    fn from(kind: MalformedKind) -> Self {
        Error::Malformed(Malformed(kind))
    }
}

/// Internal classification of a malformed blob. Crate-private; the
/// public surface exposes only opaque [`Malformed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MalformedKind {
    // Header layer
    /// First 4 bytes were not `0xd00dfeed`.
    BadMagic,
    /// Header `version` was not 17, or `last_comp_version` exceeded 17.
    UnsupportedVersion,
    /// Blob shorter than the header claims, a declared block runs
    /// past `totalsize`, or a header offset+size overflowed `usize`.
    Truncated,
    /// A block offset failed its alignment requirement (memrsv: 8,
    /// struct: 4).
    BadAlignment,
    /// Memory-reservation block had no `(0,0)` terminator before the
    /// struct block.
    MemRsvUnterminated,
    // Structure-block layer
    /// An unknown token byte appeared at `offset` (relative to the
    /// structure block start).
    BadToken {
        /// Byte offset within the structure block.
        offset: u32,
    },
    /// A NUL-terminated string at `offset` was not terminated within
    /// the block it sat in, or contained invalid UTF-8.
    BadString {
        /// Byte offset of the string, relative to the block it sat in.
        offset: u32,
    },
    /// A property carried a `name_off` that pointed past the strings
    /// block.
    BadNameOffset {
        /// The out-of-range offset, as stored.
        name_off: u32,
    },
    /// `END_NODE` without matching `BEGIN_NODE`, premature `END`, or
    /// missing terminator.
    BadStructure,
    /// The structure block held no `BEGIN_NODE` — no root.
    NoRoot,
    /// A property named `phandle` or `linux,phandle` had value `0` or
    /// `u32::MAX`. The DT spec reserves both.
    ReservedPhandle,
    // Overlay layer
    /// Fragment is missing `target`/`target-path` or `__overlay__`,
    /// or the overlay has pathologically many root children.
    BadFragmentStructure,
    /// A `__fixups__` or `__local_fixups__` entry was structurally
    /// invalid: bad UTF-8, unparseable entry string, byte offset
    /// out of bounds of the target property, or non-aligned raw.
    BadFixupEntry,
    /// A `__local_fixups__` entry referenced a property or child
    /// that doesn't exist in the matching overlay subtree.
    FixupTargetMissing,
    /// Overlay referenced a label that is not in the base's
    /// `/__symbols__`.
    UnknownSymbol,
    /// A literal `target-path` did not resolve to a node in the base.
    UnresolvedTarget,
    /// Overlay phandle arithmetic produced an invalid value (overflow
    /// of `u32`, or shift result hits a reserved phandle).
    PhandleOverflow,
    /// A computed offset or size in the merged output did not fit in
    /// the `u32` field where the FDT header would need to store it.
    SizeOverflow,
}

/// Which configured cap was exceeded.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Tree depth exceeded `DEPTH` on [`Tree`](crate::Tree) or
    /// [`Overlay`](crate::Overlay) (or the merge-walk bound derived
    /// from both).
    Depth,
    /// Memory-reservation entry count exceeded
    /// [`Tree`](crate::Tree)'s `MEMRSV_CAP`.
    Reservations,
    /// Overlay fragment count exceeded [`Overlay`](crate::Overlay)'s
    /// `FRAGS`.
    Fragments,
    /// Overlay rewrite (fixup) count exceeded
    /// [`Overlay`](crate::Overlay)'s `REWRITES`.
    Rewrites,
    /// Overlay layer count at one node exceeded
    /// [`Overlay`](crate::Overlay)'s `LAYERS`.
    Layers,
}

impl From<Malformed> for Error {
    fn from(m: Malformed) -> Self {
        Error::Malformed(m)
    }
}

impl From<Limit> for Error {
    fn from(l: Limit) -> Self {
        Error::LimitExceeded(l)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::LimitExceeded(l) => write!(f, "limit exceeded: {l}"),
            Error::BufferTooSmall { needed } => {
                write!(f, "destination buffer too small (need {needed} bytes)")
            }
        }
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            MalformedKind::BadMagic => f.write_str("FDT header magic mismatch"),
            MalformedKind::UnsupportedVersion => f.write_str("unsupported FDT version"),
            MalformedKind::Truncated => {
                f.write_str("FDT blob is truncated or header values overflow")
            }
            MalformedKind::BadAlignment => f.write_str("FDT block alignment violation"),
            MalformedKind::MemRsvUnterminated => {
                f.write_str("memory-reservation block missing (0,0) terminator")
            }
            MalformedKind::BadToken { offset } => {
                write!(f, "unknown FDT structure token at struct offset {offset}")
            }
            MalformedKind::BadString { offset } => {
                write!(f, "malformed string at offset {offset}")
            }
            MalformedKind::BadNameOffset { name_off } => {
                write!(f, "property name offset {name_off} out of strings block")
            }
            MalformedKind::BadStructure => f.write_str("FDT structure block is malformed"),
            MalformedKind::NoRoot => f.write_str("FDT has no root node"),
            MalformedKind::ReservedPhandle => {
                f.write_str("phandle value is reserved (0 or u32::MAX)")
            }
            MalformedKind::BadFragmentStructure => {
                f.write_str("overlay fragment lacks target/target-path or __overlay__")
            }
            MalformedKind::BadFixupEntry => {
                f.write_str("overlay __fixups__ or __local_fixups__ entry is malformed")
            }
            MalformedKind::FixupTargetMissing => {
                f.write_str("overlay local-fixup references a missing property or child")
            }
            MalformedKind::UnknownSymbol => {
                f.write_str("overlay references a label not in base __symbols__")
            }
            MalformedKind::UnresolvedTarget => {
                f.write_str("overlay fragment target does not resolve in base")
            }
            MalformedKind::PhandleOverflow => f.write_str(
                "overlay phandle arithmetic produced an invalid value (overflow or reserved)",
            ),
            MalformedKind::SizeOverflow => {
                f.write_str("merged FDT block size or offset does not fit in u32")
            }
        }
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Limit::Depth => f.write_str("tree depth exceeds configured DEPTH cap"),
            Limit::Reservations => {
                f.write_str("memory-reservation entries exceed configured MEMRSV_CAP")
            }
            Limit::Fragments => f.write_str("overlay fragments exceed configured FRAGS cap"),
            Limit::Rewrites => f.write_str("overlay rewrites exceed configured REWRITES cap"),
            Limit::Layers => f.write_str("overlay layers at one node exceed configured LAYERS cap"),
        }
    }
}

impl core::error::Error for Error {}
impl core::error::Error for Limit {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    /// Per-kind Display rounds through `Error::Malformed(_)` to make
    /// sure no variant produces an empty string or skips the
    /// `"malformed:"` prefix that downstream parsers rely on.
    #[test]
    fn every_malformed_kind_renders_nonempty_with_prefix() {
        let variants = [
            MalformedKind::BadMagic,
            MalformedKind::UnsupportedVersion,
            MalformedKind::Truncated,
            MalformedKind::BadAlignment,
            MalformedKind::MemRsvUnterminated,
            MalformedKind::BadToken { offset: 4 },
            MalformedKind::BadString { offset: 0 },
            MalformedKind::BadNameOffset { name_off: 99 },
            MalformedKind::BadStructure,
            MalformedKind::NoRoot,
            MalformedKind::ReservedPhandle,
            MalformedKind::BadFragmentStructure,
            MalformedKind::BadFixupEntry,
            MalformedKind::FixupTargetMissing,
            MalformedKind::UnknownSymbol,
            MalformedKind::UnresolvedTarget,
            MalformedKind::PhandleOverflow,
            MalformedKind::SizeOverflow,
        ];
        for v in variants {
            let s = format!("{}", Error::from(v));
            assert!(!s.is_empty(), "{v:?} -> empty");
            assert!(s.starts_with("malformed:"), "{s:?}");
        }
    }

    #[test]
    fn bad_token_display_includes_offset() {
        let s = format!("{}", Error::from(MalformedKind::BadToken { offset: 42 }));
        assert!(s.contains("42"), "expected offset in {s:?}");
    }
}
