// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Export the same pinned producer, guest probe, and kernel used by boot tests.

use super::*;

#[test]
#[ignore = "prepares assets for the explicit performance harness"]
fn benchmark_assets() {
    let dir = PathBuf::from(std::env::var_os("DILLO_BENCH_DIR").expect("DILLO_BENCH_DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    sign_dillo_for_hvf();
    let kernel = require(
        &[
            "PCI",
            "VIRTIO_PCI",
            "VIRTIO_MMIO",
            "VIRTIO_BLK",
            "VIRTIO_CONSOLE",
            "VIRTIO_NET",
            "IP_PNP",
        ],
        &[],
    )
    .expect("benchmark kernel unavailable");
    let assets = serde_json::json!({
        "dillo": env!("CARGO_BIN_EXE_dillo"),
        "arma": env!("CARGO_BIN_FILE_ARMA_arma"),
        "snuffler": env!("CARGO_BIN_FILE_SNUFFLER_snuffler"),
        "kernel": kernel,
        "config": host::CONFIG,
        "profile": host::PROFILE,
        "arch": host::ARCH,
    });
    std::fs::write(
        dir.join("assets.json"),
        serde_json::to_vec_pretty(&assets).unwrap(),
    )
    .unwrap();
}
