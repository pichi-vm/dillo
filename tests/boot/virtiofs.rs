// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ongoing real-guest filesystem correctness suite; see tests/VIRTIOFS.md.

use super::*;
use sha2::{Digest, Sha256};
use snuffler::{
    VIRTIOFS_CHECKS, VIRTIOFS_LARGE_FILE, VIRTIOFS_LARGE_GUEST_FILE, VIRTIOFS_LARGE_LEN,
    VIRTIOFS_PROBE_CONTENT, VIRTIOFS_PROBE_FILE, virtiofs_large_byte,
};

/// Cloud Hypervisor's release workflow builds these images with the tagged
/// arch/*/configs/ch_defconfig. Keep the image, config and digest together.
fn kernel() -> (PathBuf, &'static str) {
    const RELEASE: &str =
        "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v6.12.8-20250613";
    #[cfg(target_arch = "x86_64")]
    let (image, config, digest) = (
        "bzImage-x86_64",
        include_str!("virtiofs-x86_64.config"),
        "d4af401aa859e4659d4b08a153ac608eb6a315c6918e567daa46981af5d2e5ef",
    );
    #[cfg(target_arch = "aarch64")]
    let (image, config, digest) = (
        "Image-arm64",
        include_str!("virtiofs-aarch64.config"),
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
    for symbol in [
        "FUSE_FS",
        "VIRTIO_FS",
        "PCI",
        "VIRTIO_PCI",
        "VIRTIO_CONSOLE",
    ] {
        assert!(
            config_is_y(config, symbol),
            "virtiofs suite requires CONFIG_{symbol}=y; see tests/VIRTIOFS.md"
        );
    }
    (path, config)
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
    let large: Vec<u8> = (0..VIRTIOFS_LARGE_LEN).map(virtiofs_large_byte).collect();
    std::fs::write(share.join(VIRTIOFS_LARGE_FILE), &large).unwrap();
    let ro_share = tmp.path().join("ro");
    std::fs::create_dir(&ro_share).unwrap();
    std::fs::write(ro_share.join("locked.txt"), "do not touch").unwrap();
    std::fs::create_dir(ro_share.join("directory")).unwrap();

    let platform = if cfg!(windows) { "windows" } else { "unix" };
    let cmdline = format!(
        "console=hvc0 dillo.virtiofs_suite=ctx dillo.virtiofs_ro_tag=roctx \
         dillo.virtiofs_host={platform}"
    );
    let (kernel, config) = kernel();
    let pmi = build_pmi_from_path(tmp.path(), &kernel, config, &cmdline, false);
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
    let results: std::collections::BTreeSet<(u32, i32)> = output
        .lines()
        .filter_map(|line| {
            let rest = line.split_once("FUSE result opcode=")?.1;
            let mut parts = rest.split_whitespace();
            let opcode = parts.next()?.parse().ok()?;
            let error = parts.next()?.strip_prefix("error=")?.parse().ok()?;
            Some((opcode, error))
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
    // A kernel fallback after ENOSYS still logs the opcode once. Success
    // replies prove the server performed the operation.
    for opcode in [13, 15, 45, 46, 47] {
        assert!(
            results.contains(&(opcode, 0)),
            "FUSE opcode {opcode} had no success reply: {results:?}"
        );
    }
    let host_unsupported = if cfg!(windows) { -95 } else { 0 };
    for opcode in [8, 21, 22, 23, 24, 43] {
        assert!(
            results.contains(&(opcode, host_unsupported)),
            "FUSE opcode {opcode} reply {host_unsupported} missing: {results:?}"
        );
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
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_eq!(attrs.permissions().mode() & 0o777, 0o644);
        let alloc = std::fs::metadata(share.join("alloc.bin")).unwrap();
        assert_eq!(alloc.len(), 3);
        assert!(
            alloc.blocks() * 512 >= 1024 * 1024,
            "fallocate did not reserve a megabyte: {} blocks",
            alloc.blocks()
        );
        let mut value = [0u8; 64];
        let n = rustix::fs::lgetxattr(share.join("attrs.txt"), "user.dillo", &mut value).unwrap();
        assert_eq!(&value[..n], b"virtiofs-xattr");
        let hello = std::fs::metadata(share.join("hello.txt")).unwrap();
        let link = std::fs::metadata(share.join("hello-link")).unwrap();
        assert_eq!(hello.ino(), link.ino());
        assert!(hello.nlink() >= 2);
    }
    #[cfg(windows)]
    {
        assert_eq!(std::fs::metadata(share.join("alloc.bin")).unwrap().len(), 3);
        let hello = windows_file_id(&share.join("hello.txt"));
        let link = windows_file_id(&share.join("hello-link"));
        assert_eq!(hello.0, link.0, "hard links do not share a file index");
        assert!(hello.1 >= 2, "nNumberOfLinks {}", hello.1);
    }
    assert_eq!(
        std::fs::read(share.join("hello-link")).unwrap(),
        b"virtiofs host fixture"
    );
    assert_eq!(
        std::fs::read(share.join("noreplace-dst")).unwrap(),
        b"noreplace"
    );
    assert_eq!(
        std::fs::read(share.join(VIRTIOFS_LARGE_FILE)).unwrap(),
        large
    );
    assert_eq!(
        std::fs::read(share.join(VIRTIOFS_LARGE_GUEST_FILE)).unwrap(),
        large
    );
    let mut entries: Vec<_> = std::fs::read_dir(&share)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        [
            "alloc.bin",
            "attrs.txt",
            VIRTIOFS_PROBE_FILE,
            "hello-link",
            "hello.txt",
            VIRTIOFS_LARGE_GUEST_FILE,
            VIRTIOFS_LARGE_FILE,
            "noreplace-dst",
            "readme.md",
            "renamed.txt",
            "replace.txt",
        ]
    );
    assert_eq!(
        std::fs::read(ro_share.join("locked.txt")).unwrap(),
        b"do not touch"
    );
    assert_eq!(std::fs::read_dir(&ro_share).unwrap().count(), 2);
    assert!(ro_share.join("directory").is_dir());
}

/// Host file index and link count. Same Win32 query the server uses, so the
/// witness does not depend on the unstable `windows_by_handle` std feature.
#[cfg(windows)]
fn windows_file_id(path: &Path) -> (u64, u32) {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        GetFileInformationByHandle,
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap_or_else(|err| panic!("open {}: {err}", path.display()));
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live handle, and `info` is a valid out-buffer
    // that outlives the call.
    #[allow(unsafe_code)]
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    assert_ne!(
        ok,
        0,
        "GetFileInformationByHandle {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    let ino = u64::from(info.nFileIndexLow) | (u64::from(info.nFileIndexHigh) << 32);
    assert_ne!(ino, 0, "no file index for {}", path.display());
    (ino, info.nNumberOfLinks)
}
