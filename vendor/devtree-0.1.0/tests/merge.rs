// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use devtree::{NodeView, Overlay, PropertyView, Tree, TreeView};

mod common;
use common::{apply, trees_equal};

const BASE: &[u8] = include_bytes!("data/overlay_base.dtb");
const PATCH: &[u8] = include_bytes!("data/overlay_patch.dtbo");
const EXPECTED: &[u8] = include_bytes!("data/overlay_expected.dtb");
const NESTED_A: &[u8] = include_bytes!("data/overlay_nested_a.dtbo");
const NESTED_B: &[u8] = include_bytes!("data/overlay_nested_b.dtbo");
const PHANDLES: &[u8] = include_bytes!("data/overlay_phandles.dtbo");

#[test]
fn apply_produces_parseable_dtb() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let buf = apply(&base, &overlay);
    let _: Tree = Tree::parse(&buf).expect("merged blob must parse");
}

#[test]
fn merged_chosen_has_both_props() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let buf = apply(&base, &overlay);
    let merged: Tree = Tree::parse(&buf).unwrap();

    let chosen = merged.find_path("/chosen").expect("/chosen");
    let bootargs = chosen.property("bootargs").expect("bootargs");
    assert_eq!(bootargs.as_str().unwrap(), "console=ttyS0");
    let extra = chosen.property("extra-arg").expect("extra-arg");
    assert_eq!(extra.as_str().unwrap(), "rw");
}

#[test]
fn merged_memory_has_overridden_reg() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let buf = apply(&base, &overlay);
    let merged: Tree = Tree::parse(&buf).unwrap();

    let mem = merged.find_path("/memory@40000000").expect("memory");
    let reg = mem.property("reg").expect("reg");
    let cells: Vec<u32> = reg.as_u32s().unwrap().collect();
    assert_eq!(cells, vec![0x4000_0000, 0x1000_0000]);
}

#[test]
fn merged_cpus_has_added_cpu() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let buf = apply(&base, &overlay);
    let merged: Tree = Tree::parse(&buf).unwrap();

    let cpus = merged.find_path("/cpus").expect("/cpus");
    let mut iter = cpus.children();
    for expected in ["cpu@0", "cpu@1"] {
        let c = iter.next().expect("more cpu children expected");
        assert_eq!(c.name(), expected);
    }
    assert!(iter.next().is_none());

    let cpu1 = merged.find_path("/cpus/cpu@1").expect("cpu@1");
    assert_eq!(
        cpu1.property("compatible").unwrap().as_str(),
        Some("arm,cortex-a53")
    );
}

#[test]
fn merged_matches_dtc_expected_structurally() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PATCH).unwrap();
    let buf = apply(&base, &overlay);
    let merged: Tree = Tree::parse(&buf).unwrap();
    let expected: Tree = Tree::parse(EXPECTED).unwrap();
    assert!(
        trees_equal(&merged, &expected),
        "merged tree should structurally match dtc-produced expected tree"
    );
}

#[test]
fn nested_overlays_compose() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay_a: Overlay = Overlay::parse(NESTED_A).unwrap();
    let buf1 = apply(&base, &overlay_a);
    let layer1: Tree = Tree::parse(&buf1).unwrap();
    let overlay_b: Overlay = Overlay::parse(NESTED_B).unwrap();
    let buf2 = apply(&layer1, &overlay_b);
    let layer2: Tree = Tree::parse(&buf2).unwrap();

    let chosen = layer2.find_path("/chosen").expect("/chosen");
    assert_eq!(
        chosen.property("from-overlay-a").unwrap().as_str(),
        Some("alpha"),
    );
    let memory = layer2.find_path("/memory@40000000").expect("/memory");
    assert_eq!(
        memory.property("from-overlay-b").unwrap().as_str(),
        Some("bravo"),
    );
    assert_eq!(
        chosen.property("bootargs").unwrap().as_str(),
        Some("console=ttyS0")
    );
}

#[test]
fn overlay_internal_phandle_property_is_shifted() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PHANDLES).unwrap();
    let buf = apply(&base, &overlay);
    let out: Tree = Tree::parse(&buf).unwrap();

    let cpu2 = out.find_path("/cpus/cpu@2").expect("cpu@2 should exist");
    let ph = cpu2.property("phandle").unwrap().as_u32().expect("phandle");
    assert_eq!(ph, 5, "overlay phandle 1 should be shifted by 4 -> 5");
}

#[test]
fn overlay_local_fixup_reference_is_shifted() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PHANDLES).unwrap();
    let buf = apply(&base, &overlay);
    let out: Tree = Tree::parse(&buf).unwrap();

    let cpu2 = out.find_path("/cpus/cpu@2").unwrap();
    let next_cpu = cpu2
        .property("next-cpu")
        .unwrap()
        .as_u32()
        .expect("next-cpu");
    assert_eq!(next_cpu, 5);
}

#[test]
fn overlay_external_fixup_resolves_to_base_phandle() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PHANDLES).unwrap();
    let buf = apply(&base, &overlay);
    let out: Tree = Tree::parse(&buf).unwrap();

    let cpu2 = out.find_path("/cpus/cpu@2").unwrap();
    let clocks = cpu2.property("clocks").expect("clocks");
    let raw: &[u8] = clocks.as_ref();
    assert_eq!(raw.len(), 12);
    let cells: Vec<u32> = clocks.as_u32s().unwrap().collect();
    assert_eq!(cells[0], 2);
    assert_eq!(cells[1], 1);
    assert_eq!(cells[2], 2);
}

#[test]
fn base_phandles_are_not_shifted() {
    let base: Tree = Tree::parse(BASE).unwrap();
    let overlay: Overlay = Overlay::parse(PHANDLES).unwrap();
    let buf = apply(&base, &overlay);
    let out: Tree = Tree::parse(&buf).unwrap();

    for (path, expected) in [("/chosen", 1u32), ("/memory@40000000", 2), ("/cpus", 3)] {
        let n = out.find_path(path).expect(path);
        let ph = n.property("phandle").unwrap().as_u32().unwrap();
        assert_eq!(ph, expected, "{path} phandle should be unchanged");
    }
}
