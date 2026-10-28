// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! DTB-fixture integration tests for `TreeView::extract_e820`.

use devtree::Tree;
use dtb2e820::{E820Entry, E820Type, Error, ExtractE820};

const CAP: usize = 128;

fn fill(dtb: &[u8]) -> Result<(usize, [E820Entry; CAP]), Error> {
    let tree: Tree<'_> = Tree::parse(dtb).expect("parse dtb");
    let mut buf = [E820Entry::default(); CAP];
    let n = tree.extract_e820(&mut buf)?;
    Ok((n, buf))
}

fn pairs_of_kind(entries: &[E820Entry], kind: E820Type) -> Vec<(u64, u64)> {
    // Destructure-by-copy: `let E820Entry { ... } = *e` puts every
    // field into a properly-aligned local, sidestepping the
    // `&packed.field` rule (E0793).
    entries
        .iter()
        .filter_map(|e| {
            let E820Entry {
                addr,
                size,
                kind: k,
            } = *e;
            (k == kind).then_some((addr, size))
        })
        .collect()
}

#[test]
fn basic_emits_usable_reserved_and_ecam() {
    let (n, buf) = fill(include_bytes!("data/basic.dtb")).unwrap();
    // Two memory@ nodes + one reserved-memory child + one ECAM = 4.
    assert_eq!(n, 4, "got entries: {:?}", &buf[..n]);

    let live = &buf[..n];
    let usable = pairs_of_kind(live, E820Type::Usable);
    assert!(usable.contains(&(0x0u64, 0x10000000u64)));
    assert!(usable.contains(&(0x40000000u64, 0x10000000u64)));

    let reserved = pairs_of_kind(live, E820Type::Reserved);
    assert!(reserved.contains(&(0x30000000u64, 0x01000000u64))); // reserved-memory/fb
    assert!(reserved.contains(&(0xb0000000u64, 0x00100000u64))); // pci ECAM
}

/// Bug 1a regression: a DTB carrying `pci-host-ecam-generic` MUST
/// produce a RESERVED e820 entry covering the ECAM window. Linux
/// rejects ECAM (and discovers no PCI devices) otherwise.
#[test]
fn pci_ecam_window_is_reserved_bug_1a() {
    let (n, buf) = fill(include_bytes!("data/basic.dtb")).unwrap();
    let reserved = pairs_of_kind(&buf[..n], E820Type::Reserved);
    assert!(
        reserved.contains(&(0xb0000000, 0x00100000)),
        "ECAM window missing from reserved e820. Got reserved={reserved:?}"
    );
}

#[test]
fn no_pci_emits_only_memory() {
    let (n, buf) = fill(include_bytes!("data/no_pci.dtb")).unwrap();
    assert_eq!(n, 1);
    let E820Entry { addr, size, kind } = buf[0];
    assert_eq!(kind, E820Type::Usable);
    assert_eq!((addr, size), (0x40000000, 0x08000000));
}

#[test]
fn bad_reg_shape_errors() {
    // 12-byte reg: decodes as cells but ends mid-tuple (partial group).
    let err = fill(include_bytes!("data/bad_reg.dtb")).unwrap_err();
    assert_eq!(err, Error::BadRegShape);
}

#[test]
fn unaligned_reg_shape_errors() {
    // 3-byte reg: not a whole number of u32 cells (`as_u32s` rejects).
    let err = fill(include_bytes!("data/bad_reg_unaligned.dtb")).unwrap_err();
    assert_eq!(err, Error::BadRegShape);
}

#[test]
fn caller_can_pre_seed_acpi_entry() {
    let mut buf = [E820Entry::default(); CAP];
    buf[0] = E820Entry {
        addr: 0x4000_0000,
        size: 0x2000,
        kind: E820Type::Acpi,
    };
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/no_pci.dtb")).unwrap();
    let n = tree.extract_e820(&mut buf[1..]).unwrap();
    let total = 1 + n;
    assert_eq!(total, 2);
    let live = &buf[..total];
    let acpi: Vec<E820Entry> = live
        .iter()
        .filter_map(|e| {
            let E820Entry { addr, size, kind } = *e;
            (kind == E820Type::Acpi).then_some(E820Entry { addr, size, kind })
        })
        .collect();
    assert_eq!(acpi.len(), 1);
    let E820Entry { addr, size, .. } = acpi[0];
    assert_eq!((addr, size), (0x4000_0000, 0x2000));
}

#[test]
fn buffer_full_when_slice_too_short() {
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/basic.dtb")).unwrap();
    let mut tiny = [E820Entry::default(); 2]; // need 4 entries; only 2 slots
    let err = tree.extract_e820(&mut tiny).unwrap_err();
    assert_eq!(err, Error::BufferFull);
}

#[test]
fn empty_slice_returns_buffer_full_on_first_entry() {
    let tree: Tree<'_> = Tree::parse(include_bytes!("data/no_pci.dtb")).unwrap();
    let mut empty: [E820Entry; 0] = [];
    let err = tree.extract_e820(&mut empty).unwrap_err();
    assert_eq!(err, Error::BufferFull);
}

#[test]
fn type_discriminants_match_linux_wire_values() {
    // Pinned against arch/x86/include/asm/e820/types.h.
    assert_eq!(E820Type::Invalid as u32, 0);
    assert_eq!(E820Type::Usable as u32, 1);
    assert_eq!(E820Type::Reserved as u32, 2);
    assert_eq!(E820Type::Acpi as u32, 3);
    assert_eq!(E820Type::AcpiNvs as u32, 4);
    assert_eq!(E820Type::Unusable as u32, 5);
    assert_eq!(E820Type::Pmem as u32, 7);
    assert_eq!(E820Type::Pram as u32, 12);
    assert_eq!(E820Type::ReservedKern as u32, 128);
    assert_eq!(E820Type::SoftReserved as u32, 0xefff_ffff);
}

#[test]
fn struct_size_matches_linux_wire_size() {
    // Linux's boot_e820_entry is exactly 20 bytes (packed).
    // `&[E820Entry]` reinterpreted as bytes IS the wire stream.
    assert_eq!(core::mem::size_of::<E820Entry>(), 20);
}

#[test]
fn default_entry_has_invalid_kind() {
    let E820Entry { addr, size, kind } = E820Entry::default();
    assert_eq!(kind, E820Type::Invalid);
    assert_eq!(addr, 0);
    assert_eq!(size, 0);
}
