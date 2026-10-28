// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Negative-path integration tests for `arma build`.
//!
//! Each test asserts non-zero exit + a diagnostic stderr message on a
//! user-visible failure mode. Together they exercise main::main's
//! error-printing branch (which structural tests can't reach) and pin
//! the CLI error UX so it doesn't regress silently.

mod common;

use std::fs;
use std::process::Command;

use tempfile::TempDir;

use common::{arma_bin, host_kernel};

fn run_failing(args: &[&std::ffi::OsStr]) -> (i32, String) {
    let out = Command::new(arma_bin())
        .args(args)
        .output()
        .expect("spawn arma");
    assert!(!out.status.success(), "expected non-zero exit");
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stderr)
}

#[test]
fn missing_kernel_file_fails_with_useful_message() {
    let tmp = TempDir::new().unwrap();
    let nonexistent = tmp.path().join("does-not-exist");
    let out_pmi = tmp.path().join("out.pmi");
    let (_code, stderr) = run_failing(&[
        "build".as_ref(),
        "--kernel".as_ref(),
        nonexistent.as_os_str(),
        "--cmdline".as_ref(),
        "console=ttyS0".as_ref(),
        "--profile".as_ref(),
        "x86-64-v3".as_ref(),
        out_pmi.as_os_str(),
    ]);
    assert!(
        stderr.starts_with("arma:"),
        "expected `arma:` prefix; got: {stderr}"
    );
    assert!(
        stderr.contains("read kernel"),
        "stderr missing `read kernel` context: {stderr}"
    );
    assert!(!out_pmi.exists(), "no output file on failure");
}

#[test]
fn malformed_kernel_fails_with_unrecognized() {
    let tmp = TempDir::new().unwrap();
    let bad_kernel = tmp.path().join("random.bin");
    let out_pmi = tmp.path().join("out.pmi");
    // 1 KiB of zeros — no bzImage magic, no arm64 Image magic.
    fs::write(&bad_kernel, vec![0u8; 1024]).unwrap();
    let (_code, stderr) = run_failing(&[
        "build".as_ref(),
        "--kernel".as_ref(),
        bad_kernel.as_os_str(),
        "--cmdline".as_ref(),
        "console=ttyS0".as_ref(),
        "--profile".as_ref(),
        "x86-64-v3".as_ref(),
        out_pmi.as_os_str(),
    ]);
    assert!(
        stderr.contains("kernel format") || stderr.contains("not recognized"),
        "stderr missing format hint: {stderr}"
    );
    assert!(!out_pmi.exists());
}

#[test]
fn unwritable_output_path_fails() {
    let Some((kernel, config)) = host_kernel() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    // /proc/1/cannot-write is unwritable from any user.
    let unwritable: std::path::PathBuf = "/proc/1/cannot-write.pmi".into();
    let (_code, stderr) = run_failing(&[
        "build".as_ref(),
        "--kernel".as_ref(),
        kernel.as_os_str(),
        "--config".as_ref(),
        config.as_os_str(),
        "--cmdline".as_ref(),
        "console=ttyS0".as_ref(),
        "--profile".as_ref(),
        "x86-64-v3".as_ref(),
        unwritable.as_os_str(),
    ]);
    // The atomic_write step tries the .tmp first; either tmp creation
    // or the rename fails. Both surface as `arma: ...` errors.
    assert!(
        stderr.starts_with("arma:"),
        "expected arma error prefix: {stderr}"
    );
}
