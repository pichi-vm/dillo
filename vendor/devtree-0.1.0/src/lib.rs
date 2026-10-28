// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Zero-copy, `no_std`, `forbid(unsafe_code)` parser, writer, and
//! overlay applier for Flattened Devicetree (FDT v17) blobs.
//!
//! The crate is built to be resilient against adversarial input. Every
//! walk over untrusted bytes is bounded (see [`Tree`]'s `DEPTH`),
//! [`Tree::parse`] does full structural validation in one pass so
//! subsequent walks are **infallible**, and the overlay applier
//! validates phandle math against reserved values before either
//! observing or emitting them.
//!
//! Two top-level types:
//!
//! - [`Tree`] — a parsed base devicetree. Use [`Tree::parse`] then
//!   [`Tree::root`], [`Tree::find_path`], [`Tree::find_phandle`], and
//!   [`Tree::reservations`] to walk it (infallibly).
//! - [`Overlay`] — a parsed DTBO. Use [`Overlay::parse`] then either
//!   [`OverlayView::fragments`] for pre-apply policy inspection or
//!   [`OverlayView::apply`] to merge against a base in one pass into
//!   a caller-supplied buffer. The size is not known up front; on
//!   [`Error::BufferTooSmall`] the `needed` field is a strict upper
//!   bound — allocate that and retry.
//!
//! Caller flow:
//!
//! ```no_run
//! use devtree::{Overlay, OverlayView, Tree};
//!
//! # fn read(_: &str) -> Vec<u8> { Vec::new() }
//! let base_blob = read("base.dtb");
//! let overlay_blob = read("patch.dtbo");
//!
//! let base: Tree = Tree::parse(&base_blob).unwrap();
//! let overlay: Overlay = Overlay::parse(&overlay_blob).unwrap();
//!
//! // Probe for needed size, then allocate. Propagate other errors:
//! // a malformed DTBO can fail with `Error::Malformed(_)` before the
//! // buffer check.
//! let needed = match overlay.apply(&base, &mut []) {
//!     Err(devtree::Error::BufferTooSmall { needed }) => needed,
//!     Err(e) => panic!("size probe failed: {e:?}"),
//!     Ok(_) => unreachable!("empty buffer cannot succeed"),
//! };
//! let mut buf = vec![0u8; needed];
//! let n = overlay.apply(&base, &mut buf).unwrap();
//! let merged: Tree = Tree::parse(&buf[..n]).unwrap();
//! ```
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division,
    clippy::modulo_arithmetic,
    clippy::dbg_macro
)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cursor;
mod error;
mod fdt;
mod header;
mod overlay;
#[cfg(feature = "alloc")]
mod owned;
mod writer;

/// Trait-sealing marker. Not reachable outside the crate, so
/// downstream cannot implement the public read-side traits.
pub(crate) mod sealed {
    /// Sealing marker.
    pub trait Sealed {}
}

pub use error::{Error, Limit, Malformed};
pub use fdt::{NodeView, PropertyView, Reservation, Tree, TreeView};
pub use overlay::{Fragment, Overlay, OverlayView, Target};
#[cfg(feature = "alloc")]
pub use owned::{OwnedNode, OwnedProperty, OwnedTree};
