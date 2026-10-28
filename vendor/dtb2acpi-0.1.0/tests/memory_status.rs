// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-memory `status` (DT spec §2.3.4) + `hotpluggable` (DT spec
//! §3.4) → ACPI SRAT Memory Affinity flag mapping.
//!
//! SRAT memory entries carry two relevant flags:
//!   bit 0 ENABLED — region exists and the OS may use it
//!   bit 1 HOT_PLUGGABLE — region may be added/removed at runtime
//!
//! Per ACPI 6.5 §5.2.16.2 these are independent, and DT's
//! `status` + `hotpluggable` map onto them orthogonally.

mod common;

use devtree::Tree;
use dtb2acpi::AcpiBuffer;

const HOTPLUGGABLE_DTB: &[u8] = include_bytes!("data/memory_hotpluggable.dtb");
const DISABLED_HOTPLUGGABLE_DTB: &[u8] = include_bytes!("data/memory_disabled_hotpluggable.dtb");
const TEST_BUF: usize = 8192;

fn build(dtb: &[u8]) -> Box<AcpiBuffer<TEST_BUF>> {
    let tree: Tree<'_> = Tree::parse(dtb).expect("DTB parse");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa)
        .expect("populate");
    buf
}

/// Read the flags u32 from a Type 1 SRAT MemoryAffinity entry's BODY
/// (the `common::decode` slice strips the type/length prefix). Body
/// layout per ACPI 6.5 §5.2.16.2 (after the 2-byte prefix):
///   proximity_domain(u32) reserved_1(u16) base_lo(u32) base_hi(u32)
///   length_lo(u32) length_hi(u32) reserved_2(u32) flags(u32) ...
/// → flags starts at body offset 2 + 4 + 4 + 4 + 4 + 4 + 4 = 26.
fn memory_flags(body: &[u8]) -> u32 {
    u32::from_le_bytes(body[26..30].try_into().unwrap())
}

#[test]
fn okay_memory_with_hotpluggable_sets_both_bits() {
    // memory@40000000: implicit okay, no hotpluggable → flags = 0x1
    // memory@c0000000: implicit okay, hotpluggable present → flags = 0x3
    let buf = build(HOTPLUGGABLE_DTB);
    let d = common::decode(&*buf);
    let mems: Vec<_> = d.srat_entries.iter().filter(|(t, _)| *t == 1).collect();
    assert_eq!(mems.len(), 2, "two memory affinity entries");
    assert_eq!(
        memory_flags(&mems[0].1),
        0x1,
        "memory@40000000 ENABLED only"
    );
    assert_eq!(
        memory_flags(&mems[1].1),
        0x3,
        "memory@c0000000 ENABLED | HOT_PLUGGABLE"
    );
}

#[test]
fn disabled_memory_with_hotpluggable_sets_only_hotpluggable() {
    // Classic hot-add slot: status="disabled" + hotpluggable
    // → flags = 0x2 (HOT_PLUGGABLE only; OS will hot-add later
    // and read affinity from this entry).
    let buf = build(DISABLED_HOTPLUGGABLE_DTB);
    let d = common::decode(&*buf);
    let mems: Vec<_> = d.srat_entries.iter().filter(|(t, _)| *t == 1).collect();
    assert_eq!(mems.len(), 2);
    assert_eq!(
        memory_flags(&mems[0].1),
        0x1,
        "memory@40000000 ENABLED only"
    );
    assert_eq!(
        memory_flags(&mems[1].1),
        0x2,
        "memory@c0000000 HOT_PLUGGABLE only (will be hot-added)"
    );
}
