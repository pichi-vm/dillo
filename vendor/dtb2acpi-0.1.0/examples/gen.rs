// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generate an ACPI blob from a DTB at a given base GPA. For the PMI OVMF demo.
use devtree::Tree;
use dtb2acpi::{AcpiBuffer, OemIdentity};
use std::io::Write;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dtb = std::fs::read(&a[1]).expect("read dtb");
    let base = u64::from_str_radix(a[2].trim_start_matches("0x"), 16).expect("base gpa");
    let tree: Tree<'_> = Tree::parse(&dtb).expect("parse dtb");
    let oem = OemIdentity {
        oem_id: *b"PMIOVM",
        oem_table_id: *b"PMIOVMF ",
        oem_revision: 1,
        creator_id: *b"PMI ",
        creator_revision: 1,
    };
    let mut buf = Box::new(AcpiBuffer::<8192>::default());
    let n = buf.populate(&tree, &oem, base).expect("populate");
    std::io::stdout()
        .write_all(&AsRef::<[u8]>::as_ref(&*buf)[..n])
        .expect("write");
}
