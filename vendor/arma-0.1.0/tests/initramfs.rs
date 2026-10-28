// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exercise complete archives through the CLI and inspect the emitted PMI.
mod common;

use std::process::Command;

use devtree::{NodeView, Tree, TreeView};
use rstest::rstest;
use tempfile::TempDir;

#[rstest]
#[case(include_bytes!("data/initramfs.cpio").as_slice())]
#[case(include_bytes!("data/initramfs.cpio.gz").as_slice())]
#[case(include_bytes!("data/initramfs.cpio.zst").as_slice())]
fn complete_initramfs_reaches_pmi_unchanged(#[case] archive: &[u8]) {
    let (kernel, config) = common::host_kernel().expect("real host kernel and config available");
    let dir = TempDir::new().unwrap();
    let initrd = dir.path().join("initramfs");
    let output = dir.path().join("boot.pmi");
    std::fs::write(&initrd, archive).unwrap();
    let build = || {
        Command::new(common::arma_bin())
            .arg("build")
            .arg("--kernel")
            .arg(kernel)
            .arg("--config")
            .arg(config)
            .arg("--cmdline")
            .arg("console=hvc0")
            .arg("--initrd")
            .arg(&initrd)
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = build();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(&output).unwrap();
    let pe = goblin::pe::PE::parse(&bytes).unwrap();
    let section = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap() == ".initrd")
        .unwrap();
    let start = section.pointer_to_raw_data as usize;
    assert_eq!(&bytes[start..start + archive.len()], archive);
    // The rest of the loaded section is padding, not a second transformed copy.
    assert!(
        bytes[start + archive.len()..start + section.size_of_raw_data as usize]
            .iter()
            .all(|b| *b == 0)
    );
    let dtb = common::base_dtb(&bytes);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let chosen = tree.find_path("/chosen").unwrap();
    let start_prop = chosen.property("linux,initrd-start").unwrap();
    let end_prop = chosen.property("linux,initrd-end").unwrap();
    let start_gpa = u64::from_be_bytes(start_prop.as_ref().try_into().unwrap());
    let end_gpa = u64::from_be_bytes(end_prop.as_ref().try_into().unwrap());
    assert_eq!(end_gpa - start_gpa, archive.len() as u64);

    std::fs::remove_file(&output).unwrap();
    std::fs::write(&initrd, &archive[..archive.len() / 2]).unwrap();
    let result = build();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("materialize initrd"));
    assert!(!output.exists());
}
