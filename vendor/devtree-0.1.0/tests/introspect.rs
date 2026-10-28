// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pre-merge introspection: verify a caller can enumerate fragments
//! and walk their proposed changes before deciding to apply.

use devtree::{Error, NodeView, Overlay, OverlayView, PropertyView, Target, Tree};

const BASE: &[u8] = include_bytes!("data/overlay_base.dtb");
const PATCH: &[u8] = include_bytes!("data/overlay_patch.dtbo");
const TARGET_PATH: &[u8] = include_bytes!("data/overlay_target_path.dtbo");

#[test]
fn label_form_fragment_surfaces_label_name() {
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let labels: Vec<&str> = overlay
        .fragments()
        .map(|f| match f.target() {
            Target::Label(l) => l,
            Target::Path(_) => panic!("expected Label, got Path"),
            _ => panic!("unexpected Target variant"),
        })
        .collect();
    assert_eq!(labels.len(), 3);
    assert!(labels.contains(&"chosen"));
    assert!(labels.contains(&"memory"));
    assert!(labels.contains(&"cpus"));
}

#[test]
fn fragment_names_are_fragment_indexed() {
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let names: Vec<&str> = overlay.fragments().map(devtree::Fragment::name).collect();
    assert_eq!(names.len(), 3);
    for n in &names {
        assert!(
            n.starts_with("fragment@"),
            "fragment name should be fragment@N, got {n}"
        );
    }
}

#[test]
fn path_form_fragment_surfaces_literal_path() {
    let overlay: Overlay = Overlay::parse(TARGET_PATH).unwrap();
    let mut count = 0;
    for frag in overlay.fragments() {
        count += 1;
        match frag.target() {
            Target::Path(p) => assert_eq!(p, "/chosen"),
            Target::Label(l) => panic!("expected Path, got Label({l})"),
            _ => panic!("unexpected Target variant"),
        }
    }
    assert_eq!(count, 1);
}

#[test]
fn fragment_node_exposes_proposed_properties() {
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    // Collect into owned Strings since property name borrows would die
    // with each iterator step (trait method returns &str tied to &self).
    let mut per_label: Vec<(&str, Vec<String>)> = Vec::new();
    for frag in overlay.fragments() {
        let label = match frag.target() {
            Target::Label(l) => l,
            Target::Path(_) => unreachable!(),
            _ => panic!("unexpected Target variant"),
        };
        let node = frag.node();
        let mut props: Vec<String> = Vec::new();
        for p in node.properties() {
            props.push(p.name().to_owned());
        }
        per_label.push((label, props));
    }
    per_label.sort_by_key(|(l, _)| *l);
    let chosen = per_label.iter().find(|(l, _)| *l == "chosen").unwrap();
    assert!(chosen.1.iter().any(|n| n == "extra-arg"));
    let memory = per_label.iter().find(|(l, _)| *l == "memory").unwrap();
    assert!(memory.1.iter().any(|n| n == "reg"));
}

#[test]
fn introspection_does_not_consume_overlay() {
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let count_before: usize = overlay.fragments().count();
    let count_again: usize = overlay.fragments().count();
    assert_eq!(count_before, count_again);
    assert_eq!(count_before, 3);

    // And apply still works after introspection.
    let base: Tree = Tree::parse(BASE).unwrap();
    let needed = match overlay.apply(&base, &mut []) {
        Err(Error::BufferTooSmall { needed }) => needed,
        other => panic!("size probe: {other:?}"),
    };
    let mut buf = vec![0u8; needed];
    let _ = overlay.apply(&base, &mut buf).unwrap();
}
