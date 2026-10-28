// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::num::NonZeroU32;

use devtree::{NodeView, PropertyView, Tree, TreeView};

const SIMPLE: &[u8] = include_bytes!("data/simple.dtb");
const PHANDLES: &[u8] = include_bytes!("data/phandles.dtb");

#[test]
fn parses_simple_header() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    assert_eq!(fdt.as_ref().len(), SIMPLE.len());
}

#[test]
fn as_bytes_returns_header_sized_slice() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    assert_eq!(fdt.as_ref().len(), SIMPLE.len());
}

#[test]
fn root_has_expected_properties() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    let root = fdt.root();
    assert_eq!(root.name(), "");
    let model = root.property("model").expect("model");
    assert_eq!(model.as_str().unwrap(), "devtree-test/simple");
    let compat = root.property("compatible").expect("compatible");
    assert_eq!(compat.as_str().unwrap(), "devtree,test-simple");
    let acells = root.property("#address-cells").expect("#address-cells");
    assert_eq!(acells.as_u32().unwrap(), 1);
}

#[test]
fn root_children_iterate_in_source_order() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    let root = fdt.root();
    let mut iter = root.children();
    for expected in ["cpus", "memory@40000000", "chosen"] {
        let c = iter.next().expect("more children expected");
        assert_eq!(c.name(), expected);
    }
    assert!(iter.next().is_none());
}

#[test]
fn nested_lookup() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    let cpu = fdt.find_path("/cpus/cpu@0").expect("cpu@0");
    assert_eq!(cpu.name(), "cpu@0");
    assert_eq!(
        cpu.property("device_type").unwrap().as_str().unwrap(),
        "cpu"
    );
    assert_eq!(cpu.property("reg").unwrap().as_u32().unwrap(), 0);
}

#[test]
fn find_path_root() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    let root = fdt.find_path("/").unwrap();
    assert_eq!(root.name(), "");
}

#[test]
fn find_path_missing() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    assert!(fdt.find_path("/no-such-node").is_none());
    assert!(fdt.find_path("/cpus/cpu@9").is_none());
}

#[test]
fn find_path_relative_returns_none() {
    // With the API simplified to Option, an invalid (non-absolute)
    // path can't match anything in an absolute tree — just None.
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    for path in ["missing-leading-slash", "cpus/cpu@0", ""] {
        assert!(fdt.find_path(path).is_none(), "{path:?} should be None");
    }
}

#[test]
fn memory_property_is_two_u32_cells() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    let mem = fdt.find_path("/memory@40000000").unwrap();
    let reg = mem.property("reg").unwrap();
    let raw: &[u8] = reg.as_ref();
    assert_eq!(raw.len(), 8);
    let cells: Vec<u32> = reg.as_u32s().unwrap().collect();
    assert_eq!(cells, vec![0x4000_0000, 0x1000_0000]);
}

#[test]
fn find_phandle_resolves_intc() {
    let fdt: Tree = Tree::parse(PHANDLES).unwrap();
    let ph = NonZeroU32::new(1).unwrap();
    let intc = fdt.find_phandle(ph).expect("phandle 1 -> intc");
    assert_eq!(intc.name(), "interrupt-controller@10000000");
    assert_eq!(
        intc.property("compatible").unwrap().as_str().unwrap(),
        "arm,gic-v3"
    );
}

#[test]
fn find_phandle_missing() {
    let fdt: Tree = Tree::parse(PHANDLES).unwrap();
    assert!(fdt.find_phandle(NonZeroU32::new(99).unwrap()).is_none());
}

#[test]
fn lookup_key_excludes_zero_by_construction() {
    // NonZeroU32 excludes 0; u32::MAX is rejected at parse time on the
    // property side, so it cannot match any node in a valid tree.
    assert!(NonZeroU32::new(0).is_none());
}

#[test]
fn memory_reservations_empty_for_simple() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    assert_eq!(fdt.reservations().count(), 0);
}
