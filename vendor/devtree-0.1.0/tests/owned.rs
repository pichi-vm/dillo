// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Owned, drainable tree (`alloc` feature). Materialize a zero-copy tree,
//! read it with the same vocabulary, drain it by move, and confirm the
//! shared read traits accept both representations.
#![cfg(feature = "alloc")]

use core::num::NonZeroU32;

use devtree::{
    NodeView, OwnedNode, OwnedProperty, OwnedTree, PropertyView, Reservation, Tree, TreeView,
};

const SIMPLE: &[u8] = include_bytes!("data/simple.dtb");
const PHANDLES: &[u8] = include_bytes!("data/phandles.dtb");

fn simple() -> OwnedTree {
    let tree: Tree = Tree::parse(SIMPLE).expect("parse simple.dtb");
    OwnedTree::materialize(&tree)
}

/// A minimal DTB (empty root) whose memrsv block holds `entries` + terminator.
fn dtb_with_memrsv(entries: &[(u64, u64)]) -> Vec<u8> {
    const MAGIC: u32 = 0xd00d_feed;
    const BEGIN: u32 = 0x1;
    const END_NODE: u32 = 0x2;
    const END: u32 = 0x9;
    let mut structure: Vec<u8> = Vec::new();
    structure.extend_from_slice(&BEGIN.to_be_bytes());
    structure.extend_from_slice(b"\0\0\0\0"); // empty root name, padded
    structure.extend_from_slice(&END_NODE.to_be_bytes());
    structure.extend_from_slice(&END.to_be_bytes());

    let memrsv_off = 40u32;
    let memrsv_size = ((entries.len() + 1) * 16) as u32;
    let struct_off = memrsv_off + memrsv_size;
    let struct_size = structure.len() as u32;
    let strings_off = struct_off + struct_size;
    let totalsize = strings_off; // empty strings block

    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&MAGIC.to_be_bytes());
    blob.extend_from_slice(&totalsize.to_be_bytes());
    blob.extend_from_slice(&struct_off.to_be_bytes());
    blob.extend_from_slice(&strings_off.to_be_bytes());
    blob.extend_from_slice(&memrsv_off.to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes()); // version
    blob.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
    blob.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
    blob.extend_from_slice(&0u32.to_be_bytes()); // size_dt_strings
    blob.extend_from_slice(&struct_size.to_be_bytes());
    for &(addr, sz) in entries {
        blob.extend_from_slice(&addr.to_be_bytes());
        blob.extend_from_slice(&sz.to_be_bytes());
    }
    blob.extend_from_slice(&[0u8; 16]); // (0,0) terminator
    blob.extend_from_slice(&structure);
    blob
}

#[test]
fn materialize_and_read() {
    let t = simple();
    let cpu = t.find_path("/cpus/cpu@0").expect("cpu@0 present");
    assert_eq!(cpu.name(), "cpu@0");
    assert_eq!(
        cpu.property("compatible").and_then(|p| p.as_str()),
        Some("arm,cortex-a53")
    );
    assert_eq!(
        t.root().property("model").and_then(|p| p.as_str()),
        Some("devtree-test/simple")
    );
}

#[test]
fn cells_are_each_node_s_own_declaration() {
    let t = simple();
    // address_cells()/size_cells() report the node's OWN #*-cells (which govern
    // its children's reg), read live.
    assert_eq!(t.root().address_cells(), 1);
    assert_eq!(t.root().size_cells(), 1);
    let cpus = t.find_path("/cpus").unwrap();
    assert_eq!(cpus.address_cells(), 1);
    assert_eq!(cpus.size_cells(), 0);
    // A node without its own #*-cells reports the DT spec defaults (2 / 1).
    let cpu = t.find_path("/cpus/cpu@0").unwrap();
    assert_eq!(cpu.address_cells(), 2);
    assert_eq!(cpu.size_cells(), 1);
    // To parse a node's reg, use its parent's cells: /memory@40000000 is
    // governed by the root (#address-cells=1, #size-cells=1).
    assert_eq!(t.root().address_cells(), 1);
    let mem = t.find_path("/memory@40000000").unwrap();
    let reg: Vec<u32> = mem
        .property("reg")
        .and_then(|p| p.as_u32s())
        .expect("reg")
        .collect();
    assert_eq!(reg, [0x4000_0000, 0x1000_0000]);
}

#[test]
fn cells_reflect_mutation_live() {
    use devtree::OwnedProperty;
    let mut t = simple();
    let cpus = t.root_mut().child_mut("cpus").unwrap();
    assert_eq!(cpus.address_cells(), 1);
    cpus.set_property(OwnedProperty::new("#address-cells").with_u32(2));
    // Live read reflects the in-place mutation (no stale cached cells).
    assert_eq!(cpus.address_cells(), 2);
}

#[test]
fn phandle_index_resolves() {
    let tree: Tree = Tree::parse(PHANDLES).unwrap();
    let t = OwnedTree::materialize(&tree);
    let one = NonZeroU32::new(1).unwrap();
    let intc = t.find_phandle(one).expect("phandle 1 resolves");
    assert_eq!(intc.name(), "interrupt-controller@10000000");
    // The timer references intc via interrupt-parent = <&intc> = 1.
    let timer = t.find_path("/timer").unwrap();
    assert_eq!(
        timer
            .property("interrupt-parent")
            .and_then(devtree::OwnedProperty::as_u32),
        Some(1)
    );
}

#[test]
fn remove_property_is_by_move_and_idempotent() {
    let mut t = simple();
    let mut cpu = t.remove_path("/cpus/cpu@0").expect("pop cpu@0 subtree");
    assert_eq!(cpu.name(), "cpu@0");
    assert!(cpu.remove_property("compatible").is_some());
    assert!(cpu.remove_property("compatible").is_none());
    // The popped node is gone from the tree.
    assert!(t.find_path("/cpus/cpu@0").is_none());
}

#[test]
fn remove_child_at_by_position() {
    let mut t = simple();
    let i = t
        .root()
        .children()
        .position(|c| c.name().starts_with("memory@"))
        .expect("memory child present");
    assert_eq!(
        t.root().child_at(i).map(devtree::OwnedNode::name),
        Some("memory@40000000")
    );
    let mem = t.root_mut().remove_child_at(i).expect("removed");
    assert_eq!(
        mem.property("device_type").and_then(|p| p.as_str()),
        Some("memory")
    );
    assert!(t.find_path("/memory@40000000").is_none());
    assert!(t.root_mut().remove_child_at(9999).is_none());
}

#[test]
fn property_index_locator() {
    let mut t = simple();
    // cpu@0 has device_type, reg, compatible — addressable by position too.
    let mut cpu = t.remove_path("/cpus/cpu@0").expect("cpu@0");
    let by_name = cpu.property("device_type").map(|p| p.name().to_string());
    let i = cpu
        .properties()
        .position(|p| p.name() == "device_type")
        .expect("device_type present");
    assert_eq!(
        cpu.property_at(i).map(devtree::OwnedProperty::name),
        by_name.as_deref()
    );
    let removed = cpu.remove_property_at(i).expect("removed by index");
    assert_eq!(removed.name(), "device_type");
    assert!(cpu.property("device_type").is_none());
    assert!(cpu.remove_property_at(9999).is_none());
}

#[test]
fn property_mutation_round_trips_in_memory() {
    use devtree::OwnedProperty;
    let mut t = simple();
    let mut cpu = t.remove_path("/cpus/cpu@0").unwrap();

    // Replace an existing property by name (returns the old one). Concise
    // typed construction via the builder.
    let old = cpu.set_property(OwnedProperty::new("reg").with_u32(7));
    assert_eq!(old.map(|p| p.name().to_string()).as_deref(), Some("reg"));
    assert_eq!(
        cpu.property("reg").and_then(devtree::OwnedProperty::as_u32),
        Some(7)
    );

    // Insert a new property (no previous → None).
    assert!(
        cpu.set_property(OwnedProperty::new("status").with_str("okay"))
            .is_none()
    );
    assert_eq!(
        cpu.property("status").and_then(|p| p.as_str()),
        Some("okay")
    );

    // Mutate in place — typed setter is the partner of as_u32; read-back
    // reflects it with no serialization.
    cpu.property_mut("reg").expect("reg").set_u32(9);
    assert_eq!(
        cpu.property("reg").and_then(devtree::OwnedProperty::as_u32),
        Some(9)
    );
}

#[test]
fn child_construction_insertion_restamps() {
    use devtree::OwnedProperty;
    let mut t = simple();
    // Build a detached subtree, then attach it under /cpus (#address-cells=1,
    // #size-cells=0).
    let child = OwnedNode::new("cpu@1")
        .with_property(OwnedProperty::new("device_type").with_str("cpu"))
        .with_child(OwnedNode::new("l2"));
    let prev = t
        .root_mut()
        .child_mut("cpus")
        .expect("cpus")
        .set_child(child);
    assert!(prev.is_none());

    let inserted = t.find_path("/cpus/cpu@1").expect("structural find");
    assert_eq!(
        inserted.property("device_type").and_then(|p| p.as_str()),
        Some("cpu")
    );
    // path re-derived from the parent on insertion (cells are read live).
    assert_eq!(inserted.path(), "/cpus/cpu@1");
    // cpu@1 declares no #*-cells of its own → defaults.
    assert_eq!(inserted.address_cells(), 2);
    assert_eq!(inserted.size_cells(), 1);
    assert_eq!(
        t.find_path("/cpus/cpu@1/l2").map(OwnedNode::path),
        Some("/cpus/cpu@1/l2")
    );
}

#[test]
fn find_and_remove_phandle_walk_live_tree() {
    use devtree::OwnedProperty;
    let mut t = simple();
    // simple.dtb has no phandles; an inserted one must still be findable —
    // find_phandle walks the live tree, not a materialize-time index.
    // Insert deep (under /cpus) so find/remove must recurse into a descendant.
    let node = OwnedNode::new("thing").with_property(OwnedProperty::new("phandle").with_u32(42));
    t.root_mut().child_mut("cpus").unwrap().set_child(node);
    let ph = NonZeroU32::new(42).unwrap();
    assert_eq!(t.find_phandle(ph).map(OwnedNode::name), Some("thing"));
    assert_eq!(
        t.remove_phandle(ph)
            .map(|n| n.name().to_string())
            .as_deref(),
        Some("thing")
    );
    assert!(t.find_phandle(ph).is_none());
    // A phandle that doesn't exist walks the whole tree and finds nothing.
    assert!(t.remove_phandle(NonZeroU32::new(999).unwrap()).is_none());
}

#[test]
fn child_at_mut_and_children_mut() {
    let mut t = simple();
    let root = t.root_mut();
    assert!(root.child_at_mut(0).is_some());
    assert!(root.child_at_mut(9999).is_none());
    // Drain every child's properties in place via children_mut.
    for c in root.children_mut() {
        let names: Vec<String> = c.properties().map(|p| p.name().to_string()).collect();
        for n in names {
            c.remove_property(&n);
        }
    }
    assert!(
        t.find_path("/chosen")
            .unwrap()
            .properties()
            .next()
            .is_none()
    );
}

#[test]
fn encode_round_trips() {
    use devtree::OwnedProperty;
    let mut t = simple();
    // Modify: add a property and insert a child.
    t.root_mut()
        .set_property(OwnedProperty::new("extra").with_str("hi"));
    t.root_mut().child_mut("cpus").unwrap().set_child(
        OwnedNode::new("cpu@1").with_property(OwnedProperty::new("device_type").with_str("cpu")),
    );

    let bytes = t.encode().expect("encode");
    let reparsed: Tree = Tree::parse(&bytes).expect("re-parse encoded tree");

    // The modifications survive the round-trip. (Zero-copy `Property` is a
    // by-value view, so bind it before reading the borrowed `&str`.)
    let root = reparsed.root();
    let extra = root.property("extra").expect("extra present");
    assert_eq!(extra.as_str(), Some("hi"));
    let cpu1 = reparsed.find_path("/cpus/cpu@1").expect("cpu@1 present");
    let dt = cpu1.property("device_type").expect("device_type present");
    assert_eq!(dt.as_str(), Some("cpu"));

    // Re-materializing the re-parsed bytes reproduces the owned tree exactly.
    assert_eq!(OwnedTree::materialize(&reparsed), t);
}

#[test]
fn property_at_mut_and_properties_mut() {
    let mut t = simple();
    let cpu = t
        .root_mut()
        .child_mut("cpus")
        .unwrap()
        .child_mut("cpu@0")
        .unwrap();
    // property_at_mut: mutate the property at a located index in place.
    let i = cpu.properties().position(|p| p.name() == "reg").unwrap();
    cpu.property_at_mut(i).unwrap().set_u32(0x99);
    assert_eq!(
        cpu.property("reg").and_then(devtree::OwnedProperty::as_u32),
        Some(0x99)
    );
    assert!(cpu.property_at_mut(9999).is_none());
    // properties_mut: clear every property's value in place.
    for p in cpu.properties_mut() {
        p.set_bytes(Vec::new());
    }
    assert!(cpu.properties().all(|p| p.as_ref().is_empty()));
}

#[test]
fn reservations_round_trip_through_encode() {
    // Fixtures carry no memreserve entries, so the encoder's reservation
    // emission path is otherwise unexercised. Build one, materialize, and
    // confirm the reservation survives encode → re-parse.
    let blob = dtb_with_memrsv(&[(0x4000_0000, 0x1000)]);
    let tree: Tree = Tree::parse(&blob).expect("parse memrsv blob");
    let owned = OwnedTree::materialize(&tree);
    let want = [Reservation {
        address: 0x4000_0000,
        size: 0x1000,
    }];
    assert_eq!(owned.reservations(), want);

    let bytes = owned.encode().expect("encode");
    let reparsed: Tree = Tree::parse(&bytes).expect("re-parse");
    assert_eq!(reparsed.reservations().collect::<Vec<_>>(), want);
}

#[test]
fn property_value_triad_all_types() {
    use devtree::OwnedProperty;
    // Builders + readers for every value type (u32/str were covered already).
    assert_eq!(
        OwnedProperty::new("p").with_u32(0xDEAD_BEEF).as_u32(),
        Some(0xDEAD_BEEF)
    );
    assert_eq!(
        OwnedProperty::new("p")
            .with_u64(0x0102_0304_0506_0708)
            .as_u64(),
        Some(0x0102_0304_0506_0708)
    );
    let s = OwnedProperty::new("p").with_str("hello");
    assert_eq!(s.as_str(), Some("hello"));
    let ss = OwnedProperty::new("p").with_strs(&["a", "b", "c"]);
    assert_eq!(ss.as_strs().unwrap().collect::<Vec<_>>(), ["a", "b", "c"]);
    let cells = OwnedProperty::new("p").with_u32s(&[1, 2, 3]);
    assert_eq!(cells.as_u32s().unwrap().collect::<Vec<_>>(), [1, 2, 3]);
    let raw = OwnedProperty::new("p").with_bytes(vec![0xAA, 0xBB]);
    assert_eq!(raw.as_ref(), [0xAAu8, 0xBB].as_slice());

    // The in-place `set_*` setters mirror the builders.
    let mut q = OwnedProperty::new("q");
    q.set_bytes(vec![1]);
    q.set_u64(9);
    assert_eq!(q.as_u64(), Some(9));
    q.set_u32s(&[4, 5]);
    assert_eq!(q.as_u32s().unwrap().collect::<Vec<_>>(), [4, 5]);
    q.set_strs(&["z"]);
    assert_eq!(q.as_strs().unwrap().collect::<Vec<_>>(), ["z"]);
}

#[test]
fn set_child_replaces_existing_by_name() {
    use devtree::OwnedProperty;
    let mut parent = OwnedNode::new("p");
    assert!(parent.set_child(OwnedNode::new("c")).is_none());
    let prev =
        parent.set_child(OwnedNode::new("c").with_property(OwnedProperty::new("k").with_u32(1)));
    assert!(prev.is_some()); // replaced the previous "c"
    assert_eq!(parent.children().count(), 1);
    assert_eq!(
        parent
            .child("c")
            .and_then(|c| c.property("k"))
            .and_then(devtree::OwnedProperty::as_u32),
        Some(1)
    );
}

#[test]
fn shared_traits_cover_owned_reference_impls() {
    // Drive every read method through the shared traits so the `&Owned*`
    // trait impls (not just the inherent methods) are exercised.
    fn probe_node<N: NodeView>(n: N) {
        let _ = n.name();
        let _ = n.phandle();
        let _ = n.property("compatible");
        for p in n.properties() {
            let _ = p.name();
            let _ = p.as_u32();
            let _ = p.as_u64();
            let _ = p.as_str();
            let _ = p.as_u32s().map(Iterator::count);
            let _ = p.as_strs().map(Iterator::count);
            let _ = p.as_ref().len();
        }
        for c in n.children() {
            probe_node(c);
        }
    }
    fn probe_tree<T: TreeView>(t: T) {
        probe_node(t.root());
        let _ = t.find_path("/cpus/cpu@0");
        let _ = t.find_phandle(NonZeroU32::new(1).unwrap());
        let _ = t.reservations().count();
    }
    let tree: Tree = Tree::parse(SIMPLE).unwrap();
    let owned = OwnedTree::materialize(&tree);
    probe_tree(tree); // zero-copy impls
    probe_tree(&owned); // owned `&`-reference impls
}

#[test]
fn node_equality_is_structural_ignoring_path() {
    use devtree::OwnedProperty;
    // Same name/props/children at different positions → structurally equal,
    // even though their paths differ (path is excluded from equality).
    let detached = OwnedNode::new("dev").with_property(OwnedProperty::new("k").with_u32(1));
    let mut parent = OwnedNode::new("parent");
    parent.set_child(OwnedNode::new("dev").with_property(OwnedProperty::new("k").with_u32(1)));
    let attached = parent.child("dev").expect("dev");
    assert_ne!(detached.path(), attached.path()); // "dev" vs "parent/dev"
    assert_eq!(&detached, attached);
}

#[test]
fn remove_child_by_name() {
    let mut t = simple();
    let cpus = t.root_mut().remove_child("cpus").expect("cpus child");
    assert_eq!(cpus.name(), "cpus");
    assert!(cpus.child("cpu@0").is_some());
    assert!(t.find_path("/cpus").is_none());
    assert!(t.root_mut().remove_child("cpus").is_none());
}

#[test]
fn from_is_materialize() {
    let tree: Tree = Tree::parse(SIMPLE).unwrap();
    let t: OwnedTree = (&tree).into();
    assert!(t.find_path("/chosen").is_some());
}

#[test]
fn shared_treeview_accepts_borrowed_and_owned() {
    fn root_child_count<T: TreeView>(t: T) -> usize {
        t.root().children().count()
    }
    let tree: Tree = Tree::parse(SIMPLE).unwrap();
    let owned = OwnedTree::materialize(&tree);
    // Same generic function over a zero-copy tree and an owned tree.
    assert_eq!(root_child_count(tree), root_child_count(&owned));
}

#[test]
fn drain_to_empty_is_total() {
    let mut t = simple();
    drain(t.root_mut());
    assert_eq!(t.root().properties().count(), 0);
    assert_eq!(t.root().children().count(), 0);
}

fn drain(node: &mut OwnedNode) {
    while let Some(mut child) = node.remove_child_at(0) {
        drain(&mut child);
    }
    let names: Vec<String> = node.properties().map(|p| p.name().to_string()).collect();
    for n in names {
        node.remove_property(&n);
    }
}

#[test]
fn shared_nodeview_accepts_borrowed_and_owned() {
    fn count_props<N: NodeView>(n: N) -> usize {
        n.properties().count()
    }
    let tree: Tree = Tree::parse(SIMPLE).unwrap();
    let owned = OwnedTree::materialize(&tree);

    let zc = tree.find_path("/cpus/cpu@0").unwrap(); // Node<'_>
    let ow = owned.find_path("/cpus/cpu@0").unwrap(); // &OwnedNode

    // Same generic function over both representations, same answer.
    assert_eq!(count_props(zc), 3);
    assert_eq!(count_props(ow), 3);
}

#[test]
fn from_scratch_tree_encodes_and_reparses() {
    // Build an owned tree from nothing (OwnedTree::new), encode it, and read
    // it back through the zero-copy parser. Exercises the encode path on a
    // hand-built (non-materialized) tree — the from-scratch authoring use case.
    let root = OwnedNode::new("")
        .with_property(OwnedProperty::new("#address-cells").with_u32(2))
        .with_property(OwnedProperty::new("#size-cells").with_u32(2))
        .with_property(OwnedProperty::new("model").with_str("pichi-vm"))
        .with_child(
            OwnedNode::new("intc")
                .with_property(OwnedProperty::new("compatible").with_str("arm,gic-v3"))
                .with_property(OwnedProperty::new("reg").with_u32s(&[0, 0x0800_0000, 0, 0x1_0000]))
                .with_property(OwnedProperty::new("phandle").with_u32(1)),
        );
    let tree = OwnedTree::new(root);
    let bytes = tree.encode().expect("encode from-scratch tree");

    let parsed: Tree = Tree::parse(&bytes).expect("reparse from-scratch tree");
    let root = parsed.root();
    let model = root.property("model").unwrap();
    assert_eq!(model.as_str(), Some("pichi-vm"));
    let intc = root.child("intc").expect("intc child");
    assert_eq!(
        intc.property("compatible").unwrap().as_str(),
        Some("arm,gic-v3")
    );
    let reg: Vec<u32> = intc.property("reg").unwrap().as_u32s().unwrap().collect();
    assert_eq!(reg, vec![0, 0x0800_0000, 0, 0x1_0000]);
}
