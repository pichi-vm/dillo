// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for integration tests.

use devtree::{Error, NodeView, Overlay, OverlayView, PropertyView, Tree, TreeView};

/// Compare two devicetrees structurally — same node names in the same
/// order, same properties (name + raw bytes) ignoring order, same
/// children recursively.
pub(crate) fn trees_equal<A: TreeView, B: TreeView>(a: &A, b: &B) -> bool {
    nodes_equal(a.root(), b.root())
}

fn nodes_equal<A: NodeView, B: NodeView>(a: A, b: B) -> bool {
    if a.name() != b.name() {
        return false;
    }
    if a.properties().count() != b.properties().count() {
        return false;
    }
    // Compare property sets by name + raw bytes, order-insensitive.
    // Borrows of name()/raw() are scoped to each iteration step so we
    // never need them to outlive a single property's lifetime.
    for pa in a.properties() {
        let mut found = false;
        for pb in b.properties() {
            if pa.name() == pb.name() && pa.as_ref() == pb.as_ref() {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    let mut ac = a.children();
    let mut bc = b.children();
    loop {
        match (ac.next(), bc.next()) {
            (None, None) => break,
            (Some(ca), Some(cb)) => {
                if !nodes_equal(ca, cb) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Merge an overlay against a base via the single-pass `apply` API.
///
/// Probes for the needed buffer size with an empty `dst`, allocates,
/// applies, and truncates to the actual bytes written.
#[allow(dead_code)]
pub(crate) fn apply(base: &Tree, overlay: &Overlay) -> Vec<u8> {
    let needed = match overlay.apply(base, &mut []) {
        Err(Error::BufferTooSmall { needed }) => needed,
        Err(e) => panic!("size probe failed: {e:?}"),
        Ok(_) => unreachable!("empty buffer cannot succeed"),
    };
    let mut buf = vec![0u8; needed];
    let written = overlay.apply(base, &mut buf).expect("apply");
    assert!(written <= needed, "apply wrote past upper bound");
    buf.truncate(written);
    buf
}
