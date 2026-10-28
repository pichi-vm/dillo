// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Adversarial-input tests: hand-crafted DTBs that exercise the
//! parser's defensive checks.
//!
//! Under the eager-parse contract, every structural error is surfaced
//! at `Tree::parse` time, not later inside an iterator. These tests
//! verify rejection at the parse boundary.

use core::num::NonZeroU32;

use devtree::{Error, Limit, NodeView, Tree, TreeView};

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;
const HEADER: usize = 40;

/// Build a DTB whose tree is `depth` levels deep.
fn build_deep_blob(depth: u32) -> Vec<u8> {
    let mut struct_block: Vec<u8> = Vec::new();
    for _ in 0..=depth {
        struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        struct_block.extend_from_slice(b"\0\0\0\0");
    }
    for _ in 0..=depth {
        struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    }
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = 16;
    let struct_off: u32 = memrsv_off + memrsv_size;
    let struct_size: u32 = struct_block.len() as u32;
    let strings_off: u32 = struct_off + struct_size;
    let strings_size: u32 = 0;
    let totalsize: u32 = strings_off + strings_size;

    let mut blob = Vec::with_capacity(totalsize as usize);
    blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
    blob.extend_from_slice(&totalsize.to_be_bytes());
    blob.extend_from_slice(&struct_off.to_be_bytes());
    blob.extend_from_slice(&strings_off.to_be_bytes());
    blob.extend_from_slice(&memrsv_off.to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes());
    blob.extend_from_slice(&16u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&strings_size.to_be_bytes());
    blob.extend_from_slice(&struct_size.to_be_bytes());
    blob.extend_from_slice(&[0u8; 16]);
    blob.extend_from_slice(&struct_block);
    blob
}

#[test]
fn parse_succeeds_at_max_depth() {
    // Override DEPTH cap to keep the constructed blob small and to
    // decouple the test from whatever the default happens to be.
    const D: u32 = 8;
    let blob = build_deep_blob(D - 1);
    let fdt: Tree<'_, D> = Tree::parse(&blob).expect("parse should succeed");
    // Look up a non-existent phandle to exercise the walk.
    assert!(fdt.find_phandle(NonZeroU32::new(42).unwrap()).is_none());
}

#[test]
fn parse_rejects_deeper_than_max() {
    const D: u32 = 8;
    let blob = build_deep_blob(D);
    // With eager parse, depth-cap failures surface at parse time.
    assert!(matches!(
        Tree::<'_, D>::parse(&blob),
        Err(Error::LimitExceeded(Limit::Depth))
    ));
}

#[test]
fn parse_rejects_truncated_short_blob() {
    let r1: Result<Tree, _> = Tree::parse(&[]);
    let r2: Result<Tree, _> = Tree::parse(&[0u8; 39]);
    assert!(matches!(r1, Err(Error::Malformed(_))));
    assert!(matches!(r2, Err(Error::Malformed(_))));
}

#[test]
fn parse_rejects_garbage() {
    let blob = [0u8; 256];
    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

#[test]
fn parse_rejects_missing_memrsv_terminator_room() {
    let mut blob = vec![0u8; HEADER];
    blob[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
    let totalsize = HEADER as u32;
    blob[4..8].copy_from_slice(&totalsize.to_be_bytes());
    blob[8..12].copy_from_slice(&(HEADER as u32).to_be_bytes());
    blob[12..16].copy_from_slice(&(HEADER as u32).to_be_bytes());
    blob[16..20].copy_from_slice(&(HEADER as u32).to_be_bytes());
    blob[20..24].copy_from_slice(&17u32.to_be_bytes());
    blob[24..28].copy_from_slice(&16u32.to_be_bytes());
    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

#[test]
fn parse_rejects_unknown_token() {
    let mut struct_block = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0");
    struct_block.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = 16;
    let struct_off: u32 = memrsv_off + memrsv_size;
    let struct_size: u32 = struct_block.len() as u32;
    let strings_off: u32 = struct_off + struct_size;
    let strings_size: u32 = 0;
    let totalsize: u32 = strings_off + strings_size;

    let mut blob = Vec::with_capacity(totalsize as usize);
    blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
    blob.extend_from_slice(&totalsize.to_be_bytes());
    blob.extend_from_slice(&struct_off.to_be_bytes());
    blob.extend_from_slice(&strings_off.to_be_bytes());
    blob.extend_from_slice(&memrsv_off.to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes());
    blob.extend_from_slice(&16u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&strings_size.to_be_bytes());
    blob.extend_from_slice(&struct_size.to_be_bytes());
    blob.extend_from_slice(&[0u8; 16]);
    blob.extend_from_slice(&struct_block);

    // Eager parse catches the bad token directly.
    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

/// NOP-bomb: dtc emits FDT_NOP legitimately; attackers can use them
/// to inflate the struct block. Parse must remain linear and never loop.
fn build_nop_bomb_blob(nop_count: u32) -> Vec<u8> {
    let mut struct_block: Vec<u8> = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0");
    for _ in 0..nop_count {
        struct_block.extend_from_slice(&FDT_NOP.to_be_bytes());
    }
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = 16;
    let struct_off: u32 = memrsv_off + memrsv_size;
    let struct_size: u32 = struct_block.len() as u32;
    let strings_off: u32 = struct_off + struct_size;
    let strings_size: u32 = 0;
    let totalsize: u32 = strings_off + strings_size;

    let mut blob = Vec::with_capacity(totalsize as usize);
    blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
    blob.extend_from_slice(&totalsize.to_be_bytes());
    blob.extend_from_slice(&struct_off.to_be_bytes());
    blob.extend_from_slice(&strings_off.to_be_bytes());
    blob.extend_from_slice(&memrsv_off.to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes());
    blob.extend_from_slice(&16u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&strings_size.to_be_bytes());
    blob.extend_from_slice(&struct_size.to_be_bytes());
    blob.extend_from_slice(&[0u8; 16]);
    blob.extend_from_slice(&struct_block);
    blob
}

#[test]
fn nop_bomb_parses_and_walks_in_bounded_time() {
    let blob = build_nop_bomb_blob(250_000);
    let fdt: Tree = Tree::parse(&blob).expect("parse should accept NOP padding");
    assert_eq!(fdt.root().children().count(), 0);
    assert!(fdt.find_phandle(NonZeroU32::new(42).unwrap()).is_none());
}

#[test]
fn memrsv_without_terminator_rejected_at_parse() {
    let mut struct_block = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0");
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = 16; // one entry, no terminator
    let struct_off: u32 = memrsv_off + memrsv_size;
    let struct_size: u32 = struct_block.len() as u32;
    let strings_off: u32 = struct_off + struct_size;
    let totalsize: u32 = strings_off;

    let mut blob = Vec::with_capacity(totalsize as usize);
    blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
    blob.extend_from_slice(&totalsize.to_be_bytes());
    blob.extend_from_slice(&struct_off.to_be_bytes());
    blob.extend_from_slice(&strings_off.to_be_bytes());
    blob.extend_from_slice(&memrsv_off.to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes());
    blob.extend_from_slice(&16u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&struct_size.to_be_bytes());
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&struct_block);

    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

/// Build a single-root blob carrying one property whose `nameoff` is `nameoff`.
fn build_blob_with_prop_nameoff(nameoff: u32, strings: &[u8], value: &[u8]) -> Vec<u8> {
    let mut struct_block: Vec<u8> = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0");
    struct_block.extend_from_slice(&FDT_PROP.to_be_bytes());
    struct_block.extend_from_slice(&(value.len() as u32).to_be_bytes());
    struct_block.extend_from_slice(&nameoff.to_be_bytes());
    struct_block.extend_from_slice(value);
    while !struct_block.len().is_multiple_of(4) {
        struct_block.push(0);
    }
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = 16;
    let struct_off: u32 = memrsv_off + memrsv_size;
    let struct_size: u32 = struct_block.len() as u32;
    let strings_off: u32 = struct_off + struct_size;
    let strings_size: u32 = strings.len() as u32;
    let totalsize: u32 = strings_off + strings_size;

    let mut blob = Vec::with_capacity(totalsize as usize);
    blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
    blob.extend_from_slice(&totalsize.to_be_bytes());
    blob.extend_from_slice(&struct_off.to_be_bytes());
    blob.extend_from_slice(&strings_off.to_be_bytes());
    blob.extend_from_slice(&memrsv_off.to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes());
    blob.extend_from_slice(&16u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&strings_size.to_be_bytes());
    blob.extend_from_slice(&struct_size.to_be_bytes());
    blob.extend_from_slice(&[0u8; 16]);
    blob.extend_from_slice(&struct_block);
    blob.extend_from_slice(strings);
    blob
}

#[test]
fn property_nameoff_past_strings_block_rejected_at_parse() {
    let strings: &[u8] = b"a\0";
    let blob = build_blob_with_prop_nameoff(strings.len() as u32, strings, &[0, 0, 0, 0]);
    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "expected Malformed, got {result:?}"
    );
}

#[test]
fn property_nameoff_into_unterminated_strings_rejected_at_parse() {
    let strings: &[u8] = b"abcd"; // no NUL
    let blob = build_blob_with_prop_nameoff(0, strings, &[0, 0, 0, 0]);
    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "expected Malformed, got {result:?}"
    );
}

#[test]
fn begin_node_with_invalid_utf8_name_rejected_at_parse() {
    let mut struct_block: Vec<u8> = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0"); // root with empty name
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(&[0xff, 0xfe, 0x00, 0x00]);
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = 16;
    let struct_off: u32 = memrsv_off + memrsv_size;
    let struct_size: u32 = struct_block.len() as u32;
    let strings_off: u32 = struct_off + struct_size;
    let totalsize: u32 = strings_off;

    let mut blob = Vec::with_capacity(totalsize as usize);
    blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
    blob.extend_from_slice(&totalsize.to_be_bytes());
    blob.extend_from_slice(&struct_off.to_be_bytes());
    blob.extend_from_slice(&strings_off.to_be_bytes());
    blob.extend_from_slice(&memrsv_off.to_be_bytes());
    blob.extend_from_slice(&17u32.to_be_bytes());
    blob.extend_from_slice(&16u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&struct_size.to_be_bytes());
    blob.extend_from_slice(&[0u8; 16]);
    blob.extend_from_slice(&struct_block);

    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(matches!(result, Err(Error::Malformed(_))));
}
