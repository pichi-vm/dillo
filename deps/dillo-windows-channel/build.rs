// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{env, path::PathBuf, process::Command};

fn main() {
    for source in ["wire.idl", "wire.acf", "native.c"] {
        println!("cargo:rerun-if-changed={source}");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let target = env::var("TARGET").unwrap();
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let sources = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let compiler = cc::Build::new().get_compiler();
    let mut midl = Command::new("midl.exe");
    // cc discovers the installed MSVC/SDK environment even outside a developer shell.
    midl.envs(compiler.env().iter().cloned());
    midl.current_dir(&out)
        .args([
            "/nologo",
            "/target",
            "NT100",
            "/env",
            if target.starts_with("aarch64") {
                "arm64"
            } else {
                "x64"
            },
            "/h",
            "wire.h",
            "/prefix",
            "client",
            "client_",
            "/prefix",
            "server",
            "server_",
            "/acf",
        ])
        .arg(sources.join("wire.acf"))
        .arg(sources.join("wire.idl"));
    assert!(
        midl.status()
            .expect("Windows SDK midl.exe is required")
            .success(),
        "MIDL failed"
    );
    cc::Build::new()
        .include(&out)
        .file("native.c")
        .file(out.join("wire_c.c"))
        .file(out.join("wire_s.c"))
        .warnings(true)
        .compile("local_message");
    for library in ["Rpcrt4", "Advapi32"] {
        println!("cargo:rustc-link-lib={library}");
    }
}
