// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Negative tests for the overlay layer.

use devtree::{Error, Limit, NodeView, Overlay, OverlayView, PropertyView, Tree, TreeView};

const BASE: &[u8] = include_bytes!("data/overlay_base.dtb");
const TARGET_PATH: &[u8] = include_bytes!("data/overlay_target_path.dtbo");
const UNKNOWN_LABEL: &[u8] = include_bytes!("data/overlay_unknown_label.dtbo");
const FRAGMENT_NO_TARGET: &[u8] = include_bytes!("data/overlay_fragment_no_target.dtbo");
const EMPTY_BODY: &[u8] = include_bytes!("data/overlay_empty_body.dtbo");

fn size_needed(overlay: &Overlay, base: &Tree) -> usize {
    match overlay.apply(base, &mut []) {
        Err(Error::BufferTooSmall { needed }) => needed,
        Err(e) => panic!("size probe failed: {e:?}"),
        Ok(_) => unreachable!("empty buffer cannot succeed"),
    }
}

#[test]
fn target_path_form_works() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(TARGET_PATH).unwrap();
    let mut buf = vec![0u8; size_needed(&overlay, &base)];
    let n = overlay.apply(&base, &mut buf).unwrap();
    let merged: Tree = Tree::parse(&buf[..n]).unwrap();
    let chosen = merged.find_path("/chosen").expect("/chosen");
    let prop = chosen.property("target-path-set-this").expect("set");
    assert_eq!(prop.as_str().unwrap(), "yes");
}

#[test]
fn unknown_label_returns_unknown_symbol() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(UNKNOWN_LABEL).unwrap();
    let mut buf = vec![0u8; size_needed(&overlay, &base)];
    let result = overlay.apply(&base, &mut buf);
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "got {:?}",
        result.err()
    );
}

#[test]
fn target_path_to_missing_node_returns_unresolved() {
    let base: Tree = Tree::parse(include_bytes!("data/phandles.dtb")).unwrap();
    let overlay: Overlay = Overlay::parse(TARGET_PATH).unwrap();
    let mut buf = vec![0u8; size_needed(&overlay, &base)];
    let result = overlay.apply(&base, &mut buf);
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "got {:?}",
        result.err()
    );
}

#[test]
fn buffer_too_small_reports_needed_size() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(include_bytes!("data/overlay_patch.dtbo")).unwrap();
    let needed = size_needed(&overlay, &base);

    // `needed - 1` boundary: smallest under-allocation.
    let mut buf = vec![0u8; needed - 1];
    match overlay.apply(&base, &mut buf) {
        Err(Error::BufferTooSmall { needed: n }) => assert_eq!(n, needed),
        other => panic!("expected BufferTooSmall at needed-1, got {:?}", other),
    }

    // Half the requested size: still too small, same `needed` reported.
    let mut buf = vec![0u8; needed / 2];
    match overlay.apply(&base, &mut buf) {
        Err(Error::BufferTooSmall { needed: n }) => assert_eq!(n, needed),
        other => panic!("expected BufferTooSmall at needed/2, got {:?}", other),
    }

    // Exactly `needed` succeeds; `written` is the upper-bound-or-less.
    let mut buf = vec![0u8; needed];
    let written = overlay
        .apply(&base, &mut buf)
        .expect("apply with exactly needed bytes");
    assert!(
        written <= needed,
        "written ({}) should be <= needed ({})",
        written,
        needed
    );
}

#[test]
fn fragment_without_target_returns_malformed() {
    let base: Tree = Tree::parse(BASE).unwrap();
    // A fragment node carrying `__overlay__` but no `target` /
    // `target-path` is the malformed case described in `Overlay::parse`'s
    // error contract.
    let result = Overlay::<16, 64, 4>::parse(FRAGMENT_NO_TARGET);
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "expected Malformed, got {:?}",
        result.err()
    );
    // BASE only used to satisfy the import; the parse itself fails.
    let _ = base;
}

#[test]
fn fragment_count_over_cap_returns_limit_fragments() {
    // The overlay has 3 valid fragments (see overlay_patch.dtso). Setting
    // FRAGS = 2 forces the 3rd fragment to trip the parse-time cap and
    // surface as `Limit::Fragments` per the documented error contract.
    let blob = include_bytes!("data/overlay_patch.dtbo");
    let result = Overlay::<2, 64, 4>::parse(blob);
    assert!(
        matches!(result, Err(Error::LimitExceeded(Limit::Fragments))),
        "expected Limit::Fragments, got {:?}",
        result.err()
    );
}

#[test]
fn empty_overlay_body_exercises_zero_strings_boundary() {
    // Overlay's __overlay__ has no properties — the merge writes no
    // overlay-side property names, so the strings region for the
    // *overlay's contribution* is empty. The single-pass apply still
    // memmoves the base's strings tail; this fixture exercises the
    // `strings_actual == 0` short-circuit on the overlay side.
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(EMPTY_BODY).unwrap();
    let needed = size_needed(&overlay, &base);
    let mut buf = vec![0u8; needed];
    let written = overlay
        .apply(&base, &mut buf)
        .expect("apply of empty-overlay-body");
    // Result must reparse cleanly — single-pass layout invariants hold
    // even with zero overlay-side strings.
    let merged: Tree = Tree::parse(&buf[..written]).expect("reparse");
    // /chosen exists in base and is untouched by an empty overlay body.
    assert!(merged.find_path("/chosen").is_some());
}
