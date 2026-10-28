// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! With the new API a base `Tree` is just a borrowed slice — its
//! "round-trip" is `as_bytes()`. The interesting round-trip property
//! now lives in `merge.rs`: apply an overlay, parse the merged blob,
//! and confirm structural equality with a dtc-produced expected blob.

use devtree::Tree;

mod common;
use common::trees_equal;

const SIMPLE: &[u8] = include_bytes!("data/simple.dtb");
const PHANDLES: &[u8] = include_bytes!("data/phandles.dtb");

#[test]
fn as_bytes_roundtrips_simple() {
    let fdt: Tree = Tree::parse(SIMPLE).unwrap();
    let bytes = fdt.as_ref();
    let reparsed: Tree = Tree::parse(bytes).unwrap();
    assert!(trees_equal(&fdt, &reparsed));
}

#[test]
fn as_bytes_roundtrips_phandles() {
    let fdt: Tree = Tree::parse(PHANDLES).unwrap();
    let reparsed: Tree = Tree::parse(fdt.as_ref()).unwrap();
    assert!(trees_equal(&fdt, &reparsed));
}
