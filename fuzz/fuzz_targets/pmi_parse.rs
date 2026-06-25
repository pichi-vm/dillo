// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: `dillo::pmi_parse::parse(bytes, opts)`.
//!
//! Run with `cargo +nightly fuzz run pmi_parse` from this crate.
//! Asserts that the parser never panics, never OOMs (resource caps
//! enforce bounds), and that any rejection produces a typed
//! `dillo::pmi_parse::Error` rather than aborting.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let opts = dillo::pmi_parse::ParseOptions {
        host_arch: dillo::pmi_parse::HostArch::X86_64,
        memory_mib: 4096,
    };
    let _ = dillo::pmi_parse::parse(data, &opts);
});
