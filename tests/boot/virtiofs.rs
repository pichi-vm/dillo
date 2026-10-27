// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ongoing real-guest filesystem correctness suite; see tests/VIRTIOFS.md.

use super::*;
use sha2::{Digest, Sha256};
use snuffler::{VIRTIOFS_CHECKS, VIRTIOFS_PROBE_CONTENT, VIRTIOFS_PROBE_FILE};

/// Cloud Hypervisor's release workflow builds these images with the tagged
/// arch/*/configs/ch_defconfig. Keep the image, config and digest together.
fn kernel() -> PathBuf {
    const RELEASE: &str =
        "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v6.12.8-20250613";
    const SOURCE: &str =
        "https://raw.githubusercontent.com/cloud-hypervisor/linux/ch-release-v6.12.8-20250613";
    #[cfg(target_arch = "x86_64")]
    let (image, arch, digest) = (
        "bzImage-x86_64",
        "x86",
        "d4af401aa859e4659d4b08a153ac608eb6a315c6918e567daa46981af5d2e5ef",
    );
    #[cfg(target_arch = "aarch64")]
    let (image, arch, digest) = (
        "Image-arm64",
        "arm64",
        "bec084018bfdea2ccf619166ea4af3fdfecb00a801ae578da14e6cbdba172109",
    );
    let path = burrow::fetch(&format!("{RELEASE}/{image}")).expect(
        "virtiofs kernel download failed; restore access to the pinned release in tests/VIRTIOFS.md",
    );
    assert_eq!(
        hex::encode(Sha256::digest(std::fs::read(&path).unwrap())),
        digest,
        "virtiofs kernel digest mismatch; verify the pinned release before updating it"
    );
    let config_path = burrow::fetch(&format!("{SOURCE}/arch/{arch}/configs/ch_defconfig"))
        .expect("download pinned virtiofs kernel config (see tests/VIRTIOFS.md)");
    let config = std::fs::read_to_string(config_path).unwrap();
    for symbol in [
        "FUSE_FS",
        "VIRTIO_FS",
        "PCI",
        "VIRTIO_PCI",
        "VIRTIO_CONSOLE",
    ] {
        assert!(
            config_is_y(&config, symbol),
            "virtiofs suite requires CONFIG_{symbol}=y; see tests/VIRTIOFS.md"
        );
    }
    path
}

#[test]
fn virtiofs_filesystem_ops() {
    assert!(
        hypervisor_available(),
        "virtiofs suite requires a usable hypervisor; see tests/VIRTIOFS.md"
    );
    let tmp = TempDir::new().unwrap();
    let share = tmp.path().join("share");
    std::fs::create_dir(&share).unwrap();
    std::fs::write(share.join("hello.txt"), "virtiofs host fixture").unwrap();
    std::fs::write(share.join("readme.md"), "# hi").unwrap();
    let ro_share = tmp.path().join("ro");
    std::fs::create_dir(&ro_share).unwrap();
    std::fs::write(ro_share.join("locked.txt"), "do not touch").unwrap();
    std::fs::create_dir(ro_share.join("directory")).unwrap();

    let platform = if cfg!(windows) { "windows" } else { "unix" };
    let cmdline = format!(
        "console=hvc0 dillo.virtiofs_suite=ctx dillo.virtiofs_ro_tag=roctx \
         dillo.virtiofs_host={platform}"
    );
    let pmi = build_pmi_from_path(tmp.path(), &kernel(), host::CONFIG, &cmdline, false);
    let rw = format!("tag=ctx,source={}", share.display());
    let ro = format!("tag=roctx,source={},readonly", ro_share.display());
    let output = boot_with_env(
        &pmi,
        512,
        1,
        tmp.path(),
        &["--fs", &rw, "--fs", &ro],
        &[("RUST_LOG", "dillo_virtio_fs::fuse=trace")],
    );
    let opcodes: std::collections::BTreeSet<u32> = output
        .lines()
        .filter_map(|line| {
            line.split_once("FUSE opcode=")?
                .1
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .collect();
    eprintln!("virtiofs guest FUSE opcodes: {opcodes:?}");
    let report = parse_report(&output)
        .unwrap_or_else(|| panic!("virtiofs guest produced no report:\n{output}"));
    assert_eq!(
        report
            .pci
            .iter()
            .filter(|p| p.vendor == 0x1af4 && p.device == 0x105a)
            .count(),
        2,
        "both virtiofs devices must enumerate"
    );
    let suite = report.virtiofs.expect("virtiofs suite result absent");
    let failures: Vec<_> = suite.checks.iter().filter(|c| c.error.is_some()).collect();
    assert!(
        failures.is_empty(),
        "guest filesystem failures: {failures:#?}"
    );
    let names: Vec<_> = suite.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, VIRTIOFS_CHECKS, "guest omitted filesystem checks");

    // Gate wire coverage as well as POSIX outcomes: a kernel-local cache hit
    // must not accidentally replace the only exercise of a server operation.
    // ACCESS, INTERRUPT and BATCH_FORGET are kernel-controlled; see VIRTIOFS.md.
    for opcode in [
        1, 2, 3, 4, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 35, 38, 43, 45, 46, 47, 50,
    ] {
        assert!(
            opcodes.contains(&opcode),
            "guest did not issue FUSE opcode {opcode}: {opcodes:?}"
        );
    }
    if cfg!(unix) {
        assert!(opcodes.contains(&5), "guest did not issue FUSE_READLINK");
    }

    // The guest leaves a few deliberate witnesses and removes all scratch
    // paths. These assertions prove writes, rename and cleanup reached the host.
    assert_eq!(
        std::fs::read(share.join(VIRTIOFS_PROBE_FILE)).unwrap(),
        VIRTIOFS_PROBE_CONTENT.as_bytes()
    );
    assert_eq!(std::fs::read(share.join("renamed.txt")).unwrap(), b"staged");
    assert_eq!(std::fs::read(share.join("replace.txt")).unwrap(), b"new");
    assert_eq!(std::fs::read(share.join("attrs.txt")).unwrap(), b"abc");
    assert_eq!(
        std::fs::read(share.join("hello.txt")).unwrap(),
        b"virtiofs host fixture"
    );
    let attrs = std::fs::metadata(share.join("attrs.txt")).unwrap();
    assert_eq!(
        attrs
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap(),
        Duration::new(1_700_000_001, 123_456_700),
        "guest utimens did not reach the host"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(attrs.permissions().mode() & 0o777, 0o644);
    }
    let mut entries: Vec<_> = std::fs::read_dir(&share)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        [
            "attrs.txt",
            VIRTIOFS_PROBE_FILE,
            "hello.txt",
            "readme.md",
            "renamed.txt",
            "replace.txt"
        ]
    );
    assert_eq!(
        std::fs::read(ro_share.join("locked.txt")).unwrap(),
        b"do not touch"
    );
    assert_eq!(std::fs::read_dir(&ro_share).unwrap().count(), 2);
    assert!(ro_share.join("directory").is_dir());
}
