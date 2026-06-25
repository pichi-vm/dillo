// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared devtree consumption boundary for dillo-owned crates.
//!
//! Implementors consume the nodes/properties they own from a mutable
//! [`devtree::OwnedTree`]. Returning `Ok(None)` means the implementor's device
//! or substrate is absent from this tree.

pub use devtree;

pub mod platform;

/// Construct one object by consuming its DTB-owned facts from a mutable tree.
pub trait FromDevTree: Sized {
    type Error;

    fn from_devtree(tree: &mut devtree::OwnedTree) -> Result<Option<Self>, Self::Error>;
}
