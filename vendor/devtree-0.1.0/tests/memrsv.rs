// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Coverage for the memory-reservation read path and writer.

use devtree::{Error, Limit, Overlay, OverlayView, Tree, TreeView};

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_END: u32 = 0x9;
const HEADER: usize = 40;

/// Build a minimal DTB whose memrsv block holds the supplied
/// `(address, size)` entries, followed by a (0,0) terminator.
fn build_dtb_with_memrsv(entries: &[(u64, u64)]) -> Vec<u8> {
    let mut struct_block: Vec<u8> = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0");
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = ((entries.len() + 1) * 16) as u32;
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
    for &(addr, sz) in entries {
        blob.extend_from_slice(&addr.to_be_bytes());
        blob.extend_from_slice(&sz.to_be_bytes());
    }
    blob.extend_from_slice(&[0u8; 16]);
    blob.extend_from_slice(&struct_block);
    blob
}

fn build_empty_overlay() -> Vec<u8> {
    let mut struct_block: Vec<u8> = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0");
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
    blob
}

#[test]
fn reads_multiple_nonzero_entries() {
    let entries = [(0x1000u64, 0x100), (0x2000, 0x200), (0x3000, 0x400)];
    let blob = build_dtb_with_memrsv(&entries);
    let fdt: Tree = Tree::parse(&blob).expect("header is valid");
    let parsed: Vec<_> = fdt.reservations().collect();
    assert_eq!(parsed.len(), entries.len());
    for (got, want) in parsed.iter().zip(entries.iter()) {
        assert_eq!(got.address, want.0);
        assert_eq!(got.size, want.1);
    }
}

#[test]
fn apply_preserves_nonzero_memrsv() {
    let entries = [(0x1000_0000u64, 0x10000), (0x2000_0000, 0x4000)];
    let base_blob = build_dtb_with_memrsv(&entries);
    let base: Tree = Tree::parse(&base_blob).expect("base parses");

    let overlay_blob = build_empty_overlay();
    let overlay: Overlay = Overlay::parse(&overlay_blob).expect("overlay parses");
    let needed = match overlay.apply(&base, &mut []) {
        Err(Error::BufferTooSmall { needed }) => needed,
        other => panic!("size probe: {other:?}"),
    };
    let mut buf = vec![0u8; needed];
    let n = overlay.apply(&base, &mut buf).expect("apply");
    let merged: Tree = Tree::parse(&buf[..n]).expect("merged parses");

    let preserved: Vec<_> = merged.reservations().collect();
    assert_eq!(preserved.len(), entries.len());
    for (got, want) in preserved.iter().zip(entries.iter()) {
        assert_eq!(got.address, want.0);
        assert_eq!(got.size, want.1);
    }
}

#[test]
fn parse_rejects_memrsv_above_cap() {
    // 1100 entries with no terminator; cap is 1024. Eager parse rejects.
    const COUNT: usize = 1100;
    let mut entries: Vec<(u64, u64)> = Vec::with_capacity(COUNT);
    for i in 0..COUNT {
        entries.push((i as u64 + 1, 1));
    }
    let mut struct_block: Vec<u8> = Vec::new();
    struct_block.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
    struct_block.extend_from_slice(b"\0\0\0\0");
    struct_block.extend_from_slice(&FDT_END_NODE.to_be_bytes());
    struct_block.extend_from_slice(&FDT_END.to_be_bytes());

    let memrsv_off: u32 = HEADER as u32;
    let memrsv_size: u32 = (COUNT * 16) as u32;
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
    for &(addr, sz) in &entries {
        blob.extend_from_slice(&addr.to_be_bytes());
        blob.extend_from_slice(&sz.to_be_bytes());
    }
    blob.extend_from_slice(&struct_block);

    let result: Result<Tree, _> = Tree::parse(&blob);
    assert!(matches!(
        result,
        Err(Error::LimitExceeded(Limit::Reservations))
    ));
}
