// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    for source in ["native.h", "native.c"] {
        println!("cargo:rerun-if-changed={source}");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    cc::Build::new()
        .std("c11")
        .file("native.c")
        .warnings(true)
        .compile("local_message");
    for library in ["ntdll", "advapi32"] {
        println!("cargo:rustc-link-lib={library}");
    }
}
