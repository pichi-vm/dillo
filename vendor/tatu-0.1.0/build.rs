// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bare-metal link configuration for tatu.
//!
//! tatu builds for `*-unknown-none` with a fixed-address linker script;
//! the host build (`cargo test`, which exercises the `#[cfg(not(target_os
//! = "none"))]` stub) is an ordinary executable and needs none of this.
//!
//! These were once `[target.*-unknown-none] rustflags` in
//! `.cargo/config.toml`, but config is discovered relative to the
//! invocation's cwd (not the crate), and a relative `-T` linker path is
//! resolved by the linker against rustc's cwd — which is the *workspace
//! root* for a workspace member. Emitting the flags here instead keeps
//! them attached to the crate: the linker-script path is absolute (via
//! `CARGO_MANIFEST_DIR`) so it resolves no matter where cargo runs, and
//! `rerun-if-changed` actually tracks edits to the script. This is what
//! lets tatu be a plain workspace member rather than its own workspace.

use std::env;

fn main() {
    // Only the bare-metal target needs the fixed layout; the host stub
    // links like any other binary.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }

    let dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    // One architecture-agnostic script for both targets — it only orders
    // sections; which sections exist (and thus the per-arch layout) is
    // decided by `#[cfg]` in src/sections.rs.
    let script = format!("{dir}/linker/tatu.ld");

    // Linker script (absolute path) + a 4 KiB max page size so the first
    // PT_LOAD's file offset doesn't waste space, applied to the `tatu`
    // binary only.
    println!("cargo:rustc-link-arg-bin=tatu=-T{script}");
    println!("cargo:rustc-link-arg-bin=tatu=-zmax-page-size=0x1000");

    // x86_64: the reset trampoline uses absolute (R_X86_64_32S) addressing,
    // which a PIE link rejects ("relocation ... cannot be used against local
    // symbol"). Force a non-PIE executable. aarch64 links a fixed-address
    // EXEC without needing this.
    if arch == "x86_64" {
        println!("cargo:rustc-link-arg-bin=tatu=-no-pie");
    }

    println!("cargo:rerun-if-changed=linker/tatu.ld");
}
