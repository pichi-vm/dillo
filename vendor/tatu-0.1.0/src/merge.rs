// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Apply the host-supplied DTBO onto the image's measured base DTB,
//! writing the merged blob into a caller-supplied workspace.
//!
//! Thin wrapper over [`devtree::OverlayView::apply`]; takes an
//! already-parsed [`devtree::Overlay`] (per
//! `BootInfo::host_dtbo().parse()`) and the measured base
//! `devtree::Tree` (per `BootInfo::base_dtb().parse()`).

use devtree::{Error, Overlay, OverlayView, Tree};

/// Merge `overlay` onto `base`, writing into `workspace`. Returns
/// the number of bytes written.
///
/// The returned size lets the caller slice the workspace to the
/// live portion; the rest of the workspace bytes are untouched.
pub(crate) fn merge_into(
    base: &Tree<'_>,
    overlay: Overlay<'_>,
    workspace: &mut [u8],
) -> Result<usize, Error> {
    overlay.apply(base, workspace)
}
