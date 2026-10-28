// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage of `arma cmdline <dtb> [cmdline]` — reading and
//! rewriting `/chosen/bootargs` in a detached base DTB.
//!
//! The fixture builds an x86-64 PMI in detached mode to obtain a standalone
//! base DTB, so the whole file is gated to x86-64 like `dtb_modes.rs`.
#![cfg(target_arch = "x86_64")]

mod common;

use std::process::Command;

use common::{arma_bin, build_pmi_dtb, host_kernel};
use tempfile::TempDir;

/// Run `arma cmdline <dtb> [cmdline]`, asserting success, and return stdout.
fn cmdline(dtb: &std::path::Path, new: Option<&str>) -> String {
    let mut cmd = Command::new(arma_bin());
    cmd.arg("cmdline").arg(dtb);
    if let Some(s) = new {
        cmd.arg(s);
    }
    let out = cmd.output().expect("spawn arma cmdline");
    assert!(out.status.success(), "arma cmdline failed: {out:?}");
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

// Build a detached base, then read → rewrite → read the command line back.
#[test]
fn read_then_rewrite_bootargs() {
    let Some((kernel, config)) = host_kernel() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let pmi = tmp.path().join("out.pmi");
    let base = tmp.path().join("base.dtb");
    build_pmi_dtb(kernel, config, &pmi, Some(base.to_str().unwrap()));

    // build_pmi_dtb passes `--cmdline console=ttyS0` (no --serial).
    assert_eq!(cmdline(&base, None).trim_end(), "console=ttyS0");

    // Rewrite it, then read it back verbatim.
    let new = "root=/dev/vda1 ro quiet";
    let write_out = cmdline(&base, Some(new));
    assert!(write_out.is_empty(), "write prints nothing: {write_out:?}");
    assert_eq!(cmdline(&base, None).trim_end(), new);

    // The edited file is still a valid FDT.
    let bytes = std::fs::read(&base).unwrap();
    assert_eq!(&bytes[0..4], &[0xd0, 0x0d, 0xfe, 0xed], "FDT magic");
    let _tree: devtree::Tree<'_> = devtree::Tree::parse(&bytes).expect("edited base parses");
}

// An empty command line is representable (clears bootargs).
#[test]
fn rewrite_to_empty() {
    let Some((kernel, config)) = host_kernel() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let pmi = tmp.path().join("out.pmi");
    let base = tmp.path().join("base.dtb");
    build_pmi_dtb(kernel, config, &pmi, Some(base.to_str().unwrap()));

    cmdline(&base, Some(""));
    assert_eq!(cmdline(&base, None).trim_end(), "");
}
