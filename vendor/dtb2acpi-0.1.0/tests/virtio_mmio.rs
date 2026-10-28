// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The virtio-mmio binding requires one interrupt specifier; the x86
//! IO-APIC binding uses two cells per specifier.

use devtree::Tree;
use dtb2acpi::{AcpiBuffer, DtbError, EmitError, Site};

mod common;

const TEST_BUF: usize = 8192;

#[test]
fn virtio_single_interrupt_is_emitted() {
    let tree: Tree<'_> =
        Tree::parse(include_bytes!("data/virtio_mmio.dtb")).expect("fixture parses");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    buf.populate(&tree, &common::TEST_OEM, gpa)
        .expect("one two-cell interrupt specifier is valid");
    let decoded = common::decode(&*buf);
    let bytes = AsRef::<[u8]>::as_ref(&*buf);
    let dsdt = &bytes[decoded.dsdt.header.offset_in_buf..][..decoded.dsdt.header.length as usize];
    let device = dsdt
        .windows(4)
        .position(|w| w == b"VM00")
        .expect("virtio ACPI device present");
    assert!(dsdt[device..].windows(9).any(|w| w == b"LNRO0005\0"));
    let irq = dsdt[device..]
        .windows(9)
        .find(|w| w[0] == 0x89 && w[1] == 6 && w[2] == 0 && w[4] == 1)
        .expect("one-interrupt ExtendedInterrupt descriptor present");
    assert_eq!(u32::from_le_bytes(irq[5..9].try_into().unwrap()), 16);
}

#[test]
fn virtio_multiple_interrupts_are_malformed() {
    assert_interrupts_malformed(include_bytes!("data/virtio_multiple_interrupts.dtb"));
}

#[test]
fn virtio_extra_interrupt_cell_is_malformed() {
    assert_interrupts_malformed(include_bytes!("data/virtio_extra_interrupt_cell.dtb"));
}

fn assert_interrupts_malformed(dtb: &[u8]) {
    let tree: Tree<'_> = Tree::parse(dtb).expect("fixture parses");
    let mut buf = Box::new(AcpiBuffer::<TEST_BUF>::default());
    let gpa = common::buf_gpa(&buf);
    assert!(matches!(
        buf.populate(&tree, &common::TEST_OEM, gpa),
        Err(EmitError::Dtb {
            source: DtbError::MalformedProperty {
                site: Site::VirtioMmio,
                property: "interrupts",
                ..
            },
            ..
        })
    ));
}
