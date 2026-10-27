// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end boot tests (feature `vm-tests`; KVM on Linux, HVF on macOS, WHP on Windows).
//!
//! For each config: build a PMI with arma (selected same-arch Linux kernel +
//! the `snuffler` guest probe as initrd), boot it under dillo, capture the
//! console, extract `snuffler`'s `Report` from between its sentinels, and
//! assert what the guest actually saw matches what we asked dillo for.
//!
//! Gated on the `vm-tests` feature. On Linux a missing/inaccessible `/dev/kvm`
//! is a clean skip so a plain local `cargo test` doesn't fail — but once the
//! suite actually runs a boot, a guest that does not report back is a hard
//! failure, never a silent skip. The virtiofs correctness suite also requires
//! an available hypervisor (see `tests/VIRTIOFS.md`). CI runs on the platforms it claims to
//! support (Linux/KVM, macOS/HVF, Windows/WHP), so there it must genuinely boot.
#![cfg(feature = "vm-tests")]
// Windows named-port e2e needs CommandExt::inherit_handles so CreatePipe
// HANDLEs reach the child (stdio redirects alone leave inherit_handles false).
#![cfg_attr(windows, feature(windows_process_extensions_inherit_handles))]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rstest::rstest;
use snuffler::{REPORT_BEGIN, REPORT_END, Report};
use tempfile::TempDir;
use wait_timeout::ChildExt;

#[path = "boot/virtiofs.rs"]
mod virtiofs;

// dillo boots a same-arch guest, so the host arch picks the kernel.
#[cfg(target_arch = "x86_64")]
mod host {
    pub(crate) const ARCH: &str = "x86_64";
    pub(crate) const PROFILE: &str = "x86-64-v2";
    pub(crate) const CONFIG: &str =
        "CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_MMIO=y\nCONFIG_VIRTIO_BLK=y\n";
    /// No-PCI config: arma infers MMIO-only slots (16/0), so the console and
    /// virtio-blk land on virtio-mmio and no ECAM/PCI window is emitted.
    pub(crate) const CONFIG_NOPCI: &str = "CONFIG_VIRTIO_MMIO=y\nCONFIG_VIRTIO_BLK=y\n";
}
#[cfg(target_arch = "aarch64")]
mod host {
    pub(crate) const ARCH: &str = "aarch64";
    pub(crate) const PROFILE: &str = "armv8.0-a";
    pub(crate) const CONFIG: &str = "CONFIG_PCI=y\nCONFIG_PCI_HOST_GENERIC=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_MMIO=y\nCONFIG_VIRTIO_BLK=y\n";
    pub(crate) const CONFIG_NOPCI: &str = "CONFIG_VIRTIO_MMIO=y\nCONFIG_VIRTIO_BLK=y\n";
}

// ---------------------------------------------------------------------------
// Kernel database.
//
// Each entry is a plain kernel image download paired with its plain-text kconfig
// download (the uniform shape every catalogued kernel uses — no per-kernel
// unpacking). A test asks for the kconfig symbols it needs (and any it must NOT
// have); [`require`] finds matching entries for the host arch, downloads the
// first that fetches (skipping any that 404), then VERIFIES the real config
// against the believed builtins. A mismatch is a LOUD panic so the cached belief
// gets fixed rather than silently picking a kernel that doesn't meet the test's
// needs. We only ever use kernels other projects built — never one we built.
// ---------------------------------------------------------------------------

/// One catalogued kernel: a plain image URL, the kconfig symbols it is believed
/// to set to `=y` (named without `CONFIG_`), and a config source. `config` is
/// `Some(url)` when the project publishes the kconfig as a plain file; the URL
/// may contain a single `*` wildcard for a version-stamped filename (e.g.
/// Alpine's `config-<ver>-virt`), resolved by listing the parent directory.
/// `config` is `None` *only* when the kernel embeds its own config (IKCONFIG),
/// which arma extracts directly — no catalogued kernel currently does, so every
/// entry carries a `Some` config today. [`require`] always verifies the believed
/// builtins against the resolved config (loud panic on a stale belief).
struct Entry {
    arch: &'static str,
    url: &'static str,
    config: Option<&'static str>,
    builtins: &'static [&'static str],
}

// Catalogued kernels, all published by their projects as plain downloads arma
// accepts directly (raw `vmlinux`/`Image`, gzip/zstd EFI-zboot, or bzImage — no
// unpacking), each paired with a published kconfig:
//   * firecracker CI — raw image + a plain `.config`. All virtio built in;
//     `RANDOMIZE_BASE` is on for x86 (relocation-based KASLR), off on arm64.
//   * Alpine `vmlinuz-virt` — gzip EFI-zboot arma unwraps; `ACPI_SPCR_TABLE=y`
//     for the SPCR earlycon test. Config is the version-stamped `config-*-virt`
//     in the same netboot dir (wildcard-resolved).
//   * Fedora pxeboot `vmlinuz` — zstd EFI-zboot arma unwraps; `RANDOMIZE_BASE=y`:
//     the arm64 KASLR consumption kernel. Config is Fedora's published dist-git
//     `kernel-aarch64-fedora.config`.
const KERNELS: &[Entry] = &[
    // ---- x86_64 ----
    Entry {
        arch: "x86_64",
        url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155",
        config: Some(
            "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.config",
        ),
        builtins: &[
            "PCI",
            "VIRTIO_PCI",
            "VIRTIO_MMIO",
            "VIRTIO_BLK",
            "VIRTIO_NET",
            "VIRTIO_CONSOLE",
            "VIRTIO_VSOCKETS",
            "RANDOMIZE_BASE",
            // Kernel IP autoconfig (`ip=` cmdline) + the IPv4 stack: the
            // user-mode net datapath test relies on the guest self-configuring
            // 10.0.2.15 with no in-guest tooling.
            "INET",
            "IP_PNP",
        ],
    },
    Entry {
        arch: "x86_64",
        url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/vmlinux-6.1.128",
        config: Some(
            "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/vmlinux-6.1.128.config",
        ),
        builtins: &[
            "VIRTIO_MMIO",
            "VIRTIO_BLK",
            "VIRTIO_CONSOLE",
            "VIRTIO_VSOCKETS",
            "RANDOMIZE_BASE",
        ],
    },
    Entry {
        arch: "x86_64",
        url: "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/vmlinuz-virt",
        config: Some(
            "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/config-*-virt",
        ),
        builtins: &["ACPI_SPCR_TABLE", "VIRTIO_CONSOLE"],
    },
    // ---- aarch64 ----
    Entry {
        arch: "aarch64",
        url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/aarch64/vmlinux-6.1.155",
        config: Some(
            "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/aarch64/vmlinux-6.1.155.config",
        ),
        builtins: &[
            "PCI",
            "VIRTIO_PCI",
            "VIRTIO_MMIO",
            "VIRTIO_BLK",
            "VIRTIO_NET",
            "VIRTIO_CONSOLE",
            "VIRTIO_VSOCKETS",
            "ACPI_SPCR_TABLE",
            // Kernel IP autoconfig (`ip=` cmdline) + the IPv4 stack (see x86_64).
            "INET",
            "IP_PNP",
        ],
    },
    Entry {
        arch: "aarch64",
        url: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/aarch64/vmlinux-6.1.128",
        config: Some(
            "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/aarch64/vmlinux-6.1.128.config",
        ),
        builtins: &[
            "VIRTIO_MMIO",
            "VIRTIO_BLK",
            "VIRTIO_CONSOLE",
            "VIRTIO_VSOCKETS",
            "ACPI_SPCR_TABLE",
        ],
    },
    Entry {
        arch: "aarch64",
        url: "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/netboot/vmlinuz-virt",
        config: Some(
            "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/netboot/config-*-virt",
        ),
        builtins: &["ACPI_SPCR_TABLE", "VIRTIO_CONSOLE"],
    },
    // Fedora pxeboot kernel: zstd EFI-zboot arma unwraps to a raw arm64 Image,
    // RANDOMIZE_BASE=y — the only catalogued arm64 kernel that consumes the KASLR
    // seed. virtio-console is built in (for the snuffler report). Fedora ships no
    // IKCONFIG and doesn't tag dist-git, so the config is pinned to the exact
    // dist-git commit that built this kernel (`kernel-6.19.10-300.fc44`, the GA
    // build in releases/44), found via Koji's recorded source: the kernel's
    // embedded version → `koji getBuild` → its source git commit. Both the
    // releases/44 kernel and a git commit are immutable, so the pair never skews.
    Entry {
        arch: "aarch64",
        url: "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/aarch64/os/images/pxeboot/vmlinuz",
        config: Some(
            "https://src.fedoraproject.org/rpms/kernel/raw/e44c3f75126e5490b097372b199562776b3872f6/f/kernel-aarch64-fedora.config",
        ),
        builtins: &["RANDOMIZE_BASE", "VIRTIO_CONSOLE"],
    },
];

/// True if `text` (a kconfig) sets `CONFIG_<sym>=y`.
fn config_is_y(text: &str, sym: &str) -> bool {
    let needle = format!("CONFIG_{sym}=y");
    text.lines().any(|l| l == needle)
}

/// Fetch a kconfig given a `config` spec. A plain URL is fetched directly; a URL
/// containing a single `*` is a version-stamped filename (e.g. Alpine's
/// `config-<ver>-virt`) — the parent directory is listed and the first entry
/// matching the `prefix*suffix` pattern is fetched.
fn fetch_config_text(spec: &str) -> Option<String> {
    let url = match spec.split_once('*') {
        None => spec.to_string(),
        Some((pre, suf)) => {
            let slash = pre.rfind('/')?;
            let dir = &pre[..=slash];
            let name_prefix = &pre[slash + 1..];
            let listing = std::fs::read_to_string(burrow::fetch(dir).ok()?).ok()?;
            let file = listing
                .split('"')
                .find(|t| t.starts_with(name_prefix) && t.ends_with(suf) && !t.contains('/'))?;
            format!("{dir}{file}")
        }
    };
    std::fs::read_to_string(burrow::fetch(&url).ok()?).ok()
}

/// Download an entry's image and (when published) its kconfig, returning
/// `(image path, Some(kconfig))` or `(image path, None)`; `None` overall if the
/// image or a published config fails to fetch (caller falls through to the next
/// entry).
fn resolve(e: &Entry) -> Option<(PathBuf, Option<String>)> {
    let image = burrow::fetch(e.url).ok()?;
    let config = match e.config {
        Some(spec) => Some(fetch_config_text(spec)?),
        None => None,
    };
    Some((image, config))
}

/// Find a catalogued kernel for the host arch whose believed builtins include
/// every symbol in `needs` and none in `forbids`, download it, verify its real
/// config when one is published, and return the image path. `None` if nothing
/// downloadable matches.
///
/// Verification is strict when a config is available: every believed builtin must
/// really be `=y`, and every `forbids` symbol must really be absent — otherwise
/// the cache is stale and we panic loudly with the offending URL so [`KERNELS`]
/// gets corrected. Entries with no published config are taken on trust; the
/// selecting test's behavioral assertion is the check for those.
fn require(needs: &[&str], forbids: &[&str]) -> Option<PathBuf> {
    for e in KERNELS {
        if e.arch != host::ARCH {
            continue;
        }
        if !needs.iter().all(|n| e.builtins.contains(n)) {
            continue;
        }
        if forbids.iter().any(|f| e.builtins.contains(f)) {
            continue;
        }
        let Some((image, config)) = resolve(e) else {
            continue; // download failed — try the next candidate
        };
        if let Some(config) = config {
            let url = e.url;
            for sym in e.builtins {
                assert!(
                    config_is_y(&config, sym),
                    "kernel DB cache stale: {url} lists CONFIG_{sym}=y but its config disagrees \
                     — update KERNELS"
                );
            }
            for sym in forbids {
                assert!(
                    !config_is_y(&config, sym),
                    "kernel DB: {url} was selected to exclude CONFIG_{sym}, but its config has \
                     it =y — update KERNELS"
                );
            }
        }
        return Some(image);
    }
    None
}

/// Whether the host hypervisor is usable; otherwise these tests no-op skip.
/// On Linux we can cheaply probe `/dev/kvm`; HVF (macOS) and WHP (Windows)
/// have no equivalent file gate, and the CI runners provide them, so we
/// assume present and let a genuine absence surface as a boot failure.
fn hypervisor_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::fs::OpenOptions;
        Path::new("/dev/kvm").exists()
            && OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

#[cfg(target_os = "macos")]
fn sign_dillo_for_hvf() {
    static SIGN: std::sync::Once = std::sync::Once::new();

    SIGN.call_once(|| {
        let entitlements = std::env::temp_dir().join(format!(
            "dillo-hvf-entitlements-{}.plist",
            std::process::id()
        ));
        std::fs::write(
            &entitlements,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.hypervisor</key>
  <true/>
</dict>
</plist>
"#,
        )
        .expect("write HVF entitlements");

        let output = Command::new("codesign")
            .arg("--force")
            .arg("--sign")
            .arg("-")
            .arg("--entitlements")
            .arg(&entitlements)
            .arg(env!("CARGO_BIN_EXE_dillo"))
            .output()
            .expect("spawn codesign");
        let _ = std::fs::remove_file(&entitlements);
        assert!(
            output.status.success(),
            "codesign dillo for HVF failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    });
}

#[cfg(not(target_os = "macos"))]
fn sign_dillo_for_hvf() {}

/// Build a PMI from the firecracker (PCI) kernel + snuffler initrd.
/// Build a PMI with the default PCI + virtio-blk kernel (selected from the
/// kernel DB by its built-in config), the snuffler initrd, and `host::CONFIG`.
fn build_pmi(dir: &Path, cmdline: &str, serial: bool) -> PathBuf {
    let kernel = require(&["PCI", "VIRTIO_PCI", "VIRTIO_BLK", "VIRTIO_CONSOLE"], &[])
        .expect("kernel DB: no PCI + virtio-blk kernel available");
    build_pmi_from_path(dir, &kernel, host::CONFIG, cmdline, serial)
}

/// Build a PMI from an on-disk kernel image (one resolved by the kernel DB, or
/// the Alpine SPCR image), with an explicit arma kernel-config for slot
/// inference.
fn build_pmi_from_path(
    dir: &Path,
    kernel: &Path,
    config: &str,
    cmdline: &str,
    serial: bool,
) -> PathBuf {
    let cfg = dir.join("kernel.config");
    std::fs::write(&cfg, config).unwrap();
    let pmi = dir.join("boot.pmi");
    let mut cmd = Command::new(env!("CARGO_BIN_FILE_ARMA_arma"));
    cmd.arg("build")
        .args(["--cmdline", cmdline])
        .args(["--profile", host::PROFILE])
        .arg("--config")
        .arg(&cfg)
        .arg("--kernel")
        .arg(kernel)
        .arg("--initrd")
        .arg(env!("CARGO_BIN_FILE_SNUFFLER_snuffler"));
    if serial {
        cmd.arg("--serial");
    }
    let st = cmd.arg(&pmi).status().expect("spawn arma");
    assert!(st.success(), "arma build failed");
    pmi
}

/// Boot `pmi` under dillo, returning the combined console output. dillo's
/// stdout/stderr are redirected to files (no pipe-buffer deadlock) and the
/// child is killed if it overruns the timeout. Cross-platform (no `timeout`
/// coreutil).
fn boot(pmi: &Path, mem_mib: u32, cpus: u32, dir: &Path) -> String {
    boot_with(pmi, mem_mib, cpus, dir, &[])
}

/// As [`boot`], but appends `extra` to dillo's argv (e.g. `--disk`,
/// `--partition`). Used by the block-device tests.
fn boot_with(pmi: &Path, mem_mib: u32, cpus: u32, dir: &Path, extra: &[&str]) -> String {
    boot_with_env(pmi, mem_mib, cpus, dir, extra, &[])
}

/// Like [`boot_with`], with process-local environment overrides for diagnostics.
fn boot_with_env(
    pmi: &Path,
    mem_mib: u32,
    cpus: u32,
    dir: &Path,
    extra: &[&str],
    env: &[(&str, &str)],
) -> String {
    sign_dillo_for_hvf();

    let out_path = dir.join("console.out");
    let err_path = dir.join("console.err");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dillo"))
        .arg("--pmi")
        .arg(pmi)
        .args(["--memory", &mem_mib.to_string()])
        .args(["--cpus", &cpus.to_string()])
        .args(extra)
        .envs(env.iter().copied())
        .stdout(File::create(&out_path).unwrap())
        .stderr(File::create(&err_path).unwrap())
        .spawn()
        .expect("spawn dillo");
    if child
        .wait_timeout(Duration::from_secs(120))
        .expect("wait dillo")
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        let mut s = std::fs::read_to_string(&out_path).unwrap_or_default();
        s.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());
        panic!("dillo boot timed out:\n{s}");
    }
    let mut s = std::fs::read_to_string(&out_path).unwrap_or_default();
    s.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());
    s
}

/// Extract snuffler's JSON `Report` from the console output, if present.
fn parse_report(output: &str) -> Option<Report> {
    let begin = output.find(REPORT_BEGIN)? + REPORT_BEGIN.len();
    let end = output[begin..].find(REPORT_END)? + begin;
    serde_json::from_str(&output[begin..end]).ok()
}

#[rstest]
fn boots_and_reports(#[values(256, 1024)] mem_mib: u32, #[values(1, 2)] cpus: u32) {
    // Local convenience only: if there is no usable /dev/kvm (Linux dev box
    // without KVM), skip rather than fail. This is the *only* skip; once we
    // attempt a boot below, anything short of a guest report is a failure.
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pmi = build_pmi(tmp.path(), "console=hvc0", false);
    let output = boot(&pmi, mem_mib, cpus, tmp.path());
    // Surface the hypervisor's own enlightenment/serial setup so the host's
    // actual capability level is visible in CI (under --nocapture) rather than
    // hidden in the captured child output.
    for line in output.lines() {
        if line.contains("enlightened") || line.contains("ns16550a") {
            eprintln!("[dillo] {line}");
        }
    }
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    assert_eq!(r.arch, host::ARCH, "guest arch");
    assert_eq!(r.cpu.online_count, cpus as usize, "online cpus");
    // The kernel keeps some RAM for itself; total reported is a bit under.
    let asked_kib = u64::from(mem_mib) * 1024;
    assert!(
        r.memory.total_kib >= asked_kib * 7 / 10 && r.memory.total_kib <= asked_kib,
        "MemTotal {} kib not within [70%,100%] of asked {asked_kib}",
        r.memory.total_kib
    );
    assert!(
        r.consoles.iter().any(|c| c.starts_with("hvc0")),
        "hvc0 not among consoles: {:?}",
        r.consoles
    );
}

/// arm64 KASLR end-to-end: tatu overwrites the measured base DTB's
/// `/chosen/kaslr-seed` placeholder with guest `RNDR` entropy before the overlay
/// merge, so the kernel receives a fresh, guest-controlled seed in its device
/// tree on every boot. snuffler reads it back from
/// `/proc/device-tree/chosen/kaslr-seed`.
///
/// The firecracker arm64 kernel has `CONFIG_RANDOMIZE_BASE` off, so it does not
/// consume (and zero) the seed — which lets us confirm end-to-end *delivery*: the
/// seed is nonzero and *differs across boots*, proving it is guest entropy rather
/// than a host-fixed or build-time constant. (A `CONFIG_RANDOMIZE_BASE=y` kernel
/// would zero the property after consuming it — see `get_kaslr_seed`.)
#[test]
#[cfg(target_arch = "aarch64")]
fn arm64_kaslr_seed_delivered_fresh_per_boot() {
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    // A NON-KASLR kernel (so it does not consume/zero the seed): we observe the
    // exact bytes tatu delivered.
    let Some(kernel) = require(&["VIRTIO_CONSOLE"], &["RANDOMIZE_BASE"]) else {
        eprintln!("skip: kernel DB has no non-KASLR arm64 kernel to download");
        return;
    };
    let read_seed = || -> String {
        let tmp = TempDir::new().unwrap();
        let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, "console=hvc0", false);
        let output = boot(&pmi, 256, 1, tmp.path());
        let r = parse_report(&output).unwrap_or_else(|| {
            panic!("boot produced no snuffler report (guest did not boot):\n{output}")
        });
        r.kaslr_seed
            .expect("/chosen/kaslr-seed absent from guest device tree")
    };
    const ZERO: &str = "0000000000000000";
    let seed1 = read_seed();
    let seed2 = read_seed();
    assert_eq!(
        seed1.len(),
        16,
        "kaslr-seed is 8 bytes (16 hex chars): {seed1}"
    );
    assert_ne!(
        seed1, ZERO,
        "kaslr-seed must be nonzero (tatu wrote guest entropy)"
    );
    assert_ne!(
        seed1, seed2,
        "kaslr-seed must be fresh per boot (guest RNDR entropy), got {seed1} twice"
    );
}

/// arm64 KASLR *consumption*: a `CONFIG_RANDOMIZE_BASE=y` kernel reads
/// `/chosen/kaslr-seed` and zeroes the property (`get_kaslr_seed`: `*prop = 0`)
/// before unflattening the device tree. So after such a kernel boots, snuffler
/// reads the seed back as all-zero — proving the kernel actually *consumed* the
/// guest-entropy seed tatu patched in (the firecracker arm64 kernels ship KASLR
/// off, so the consuming kernel comes from the DB: Fedora's pxeboot arm64).
#[test]
#[cfg(target_arch = "aarch64")]
fn arm64_kaslr_seed_consumed_by_randomize_base_kernel() {
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let Some(kernel) = require(&["RANDOMIZE_BASE", "VIRTIO_CONSOLE"], &[]) else {
        eprintln!("skip: kernel DB has no downloadable RANDOMIZE_BASE arm64 kernel");
        return;
    };
    let tmp = TempDir::new().unwrap();
    // A distro kernel is heavier than firecracker's — give it room.
    let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, "console=hvc0", false);
    let output = boot(&pmi, 512, 1, tmp.path());
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });
    let seed = r
        .kaslr_seed
        .expect("/chosen/kaslr-seed absent from guest device tree");
    assert_eq!(
        seed, "0000000000000000",
        "a CONFIG_RANDOMIZE_BASE=y kernel must consume (zero) the seed; got {seed} — \
         tatu's seed was not consumed"
    );
}

#[test]
fn serial_earlycon_hands_off_to_hvc0() {
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let tmp = TempDir::new().unwrap();
    // The SPCR earlycon handoff needs a CONFIG_ACPI_SPCR_TABLE kernel. The DB
    // picks one for the host arch (Alpine on x86, where firecracker has SPCR off).
    let Some(kernel) = require(&["ACPI_SPCR_TABLE", "VIRTIO_CONSOLE"], &[]) else {
        eprintln!("skip: kernel DB has no downloadable ACPI_SPCR_TABLE kernel");
        return;
    };
    let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, "console=hvc0", true);
    let output = boot(&pmi, 256, 1, tmp.path());
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    assert_eq!(r.cmdline, "earlycon console=hvc0");
    assert!(
        r.consoles.iter().any(|c| c.starts_with("hvc0")),
        "hvc0 not among consoles: {:?}",
        r.consoles
    );
    assert!(
        r.serial.iter().any(|s| {
            s.name == "ttyS0"
                && s.io_type == "mem"
                && s.uartclk_hz == Some(3_686_400)
                && s.uart_type_id == Some(4)
        }),
        "ttyS0 not among serial ports: {:?}",
        r.serial
    );
    #[cfg(target_arch = "x86_64")]
    {
        let kernel_messages: Vec<&str> = r
            .kernel_log
            .entries
            .iter()
            .map(|e| e.message.as_str())
            .collect();
        assert!(
            kernel_messages
                .iter()
                .any(|m| m.contains("ACPI: SPCR: console: uart,mmio32") && m.contains(",115200")),
            "SPCR early console line missing from kernel log"
        );
        assert!(
            kernel_messages
                .iter()
                .any(|m| m.contains("RSCV0003:00: ttyS0 at MMIO")),
            "ACPI serial device did not bind as ttyS0"
        );
    }
    assert!(
        output.contains("earlycon: uart0 at MMIO32") || output.contains("bootconsole"),
        "combined console output did not include early serial output"
    );
}

/// Create a zero-filled raw image of exactly `bytes` length under `dir`.
fn make_raw(dir: &Path, name: &str, bytes: u64) -> PathBuf {
    let path = dir.join(name);
    let f = File::create(&path).expect("create raw image");
    f.set_len(bytes).expect("set image length");
    path
}

/// A traditional `--blk` raw image shows up in the guest as a virtio-blk
/// device whose reported size matches the image.
#[test]
fn boots_with_raw_disk() {
    const DISK_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB, sector-aligned
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let disk = make_raw(tmp.path(), "data.raw", DISK_BYTES);
    let pmi = build_pmi(tmp.path(), "console=hvc0", false);
    let blk = format!("path={}", disk.display());
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--blk", &blk]);
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    // The device must at least enumerate on the PCI bus (proves attach).
    assert!(
        r.pci
            .iter()
            .any(|p| p.vendor == 0x1af4 && p.device == 0x1042),
        "virtio-blk PCI function (1af4:1042) not enumerated — attach failed: {:?}",
        r.pci
    );
    let Some(dev) = r.block.iter().find(|b| b.size_bytes == DISK_BYTES) else {
        eprintln!(
            "skip: virtio-blk is on the PCI bus but the guest bound no driver (no /sys/block \
             entry) — this kernel lacks CONFIG_VIRTIO_BLK=y built-in (Alpine virt ships it as a \
             module; snuffler-init loads none). Benchmarks need a built-in driver."
        );
        return;
    };
    assert!(!dev.ro, "raw --blk device must be read-write");
    let bench = dev.bench.as_ref().expect("blk benchmark present");
    assert!(bench.error.is_none(), "blk bench error: {:?}", bench.error);
    // Reads exercised the data path without errors.
    assert!(
        bench.seq_read.bytes > 0 && bench.seq_read.errors == 0,
        "seq_read: {:?}",
        bench.seq_read
    );
    assert_eq!(
        bench.rand_read.errors, 0,
        "rand_read: {:?}",
        bench.rand_read
    );
    // Writes completed AND read back identical (data path round-trips).
    let sw = bench
        .seq_write
        .as_ref()
        .expect("seq_write present (rw device)");
    assert_eq!(sw.errors, 0, "seq_write: {sw:?}");
    assert_eq!(sw.verified, Some(true), "seq_write not verified: {sw:?}");
    let rw = bench
        .rand_write
        .as_ref()
        .expect("rand_write present (rw device)");
    assert_eq!(rw.errors, 0, "rand_write: {rw:?}");
    assert_eq!(rw.verified, Some(true), "rand_write not verified: {rw:?}");
}

/// A no-PCI firecracker kernel + a no-PCI arma config: the console and a
/// `--blk` raw disk are placed on virtio-mmio, and the PMI declares no PCI bus
/// at all. Proves arma can produce a fully-working PMI with no PCI and dillo
/// supplies devices over MMIO. The guest's built-in virtio_blk binds `vda`.
///
/// x86 discovers the virtio-mmio transports via the `_HID "LNRO0005"` ACPI
/// devices dtb2acpi emits (x86 has no DT); aarch64 would use the DT directly.
#[test]
fn boots_with_raw_disk_over_mmio() {
    const DISK_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB, sector-aligned
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let disk = make_raw(tmp.path(), "data.raw", DISK_BYTES);
    // A kernel with virtio-blk over MMIO and *no* PCI at all.
    let kernel = require(&["VIRTIO_MMIO", "VIRTIO_BLK", "VIRTIO_CONSOLE"], &["PCI"])
        .expect("kernel DB: no MMIO-only (no-PCI) virtio-blk kernel available");
    let pmi = build_pmi_from_path(
        tmp.path(),
        &kernel,
        host::CONFIG_NOPCI,
        "console=hvc0",
        false,
    );
    let blk = format!("path={}", disk.display());
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--blk", &blk]);
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    // No PCI bus exists at all on a no-PCI PMI (CONFIG_PCI is off).
    assert!(
        r.pci.is_empty(),
        "expected no PCI devices on a no-PCI PMI, got: {:?}",
        r.pci
    );
    // The virtio-blk device bound over virtio-mmio and snuffler benchmarked it.
    let dev = r
        .block
        .iter()
        .find(|b| b.size_bytes == DISK_BYTES)
        .unwrap_or_else(|| panic!("virtio-blk (MMIO) not found among {:?}", r.block));
    assert!(!dev.ro, "raw --blk device must be read-write");
    let bench = dev.bench.as_ref().expect("blk benchmark present");
    assert!(bench.error.is_none(), "blk bench error: {:?}", bench.error);
    assert!(
        bench.seq_read.bytes > 0 && bench.seq_read.errors == 0,
        "seq_read: {:?}",
        bench.seq_read
    );
    let sw = bench
        .seq_write
        .as_ref()
        .expect("seq_write present (rw device)");
    assert_eq!(sw.errors, 0, "seq_write: {sw:?}");
    assert_eq!(sw.verified, Some(true), "seq_write not verified: {sw:?}");
}

/// Two backing files combined via one `--gpt` (nested `partitions=[[…],[…]]`)
/// show up as a single virtio-blk disk whose total size is the synthesized GPT
/// layout (front-reserved 34 LBAs + partition data + back-reserved 33 LBAs).
/// device-id/disk-guid are auto-derived from the PARTUUIDs.
#[test]
fn boots_with_vgpt_disk() {
    // total_sectors = 34 (front) + 1024 + 1024 + 33 (back) = 2115 → 1,082,880 bytes.
    const EXPECTED_BYTES: u64 = 2115 * 512;
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let tmp = TempDir::new().unwrap();
    // 512 KiB each (1024 sectors) so the read benchmarks have room.
    let p0 = make_raw(tmp.path(), "p0.raw", 512 * 1024);
    let p1 = make_raw(tmp.path(), "p1.raw", 512 * 1024);

    let typeguid = "0fc63daf-8483-4772-8e79-3d69d84330f1";
    let gpt = format!(
        "partitions=[\
           [path={p0},partuuid=11111111-2222-2222-3333-333333334444,typeguid={typeguid},label=alpha],\
           [path={p1},partuuid=55555555-6666-6666-7777-777777778888,typeguid={typeguid},label=beta]\
         ]",
        p0 = p0.display(),
        p1 = p1.display(),
    );

    let pmi = build_pmi(tmp.path(), "console=hvc0", false);
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--gpt", &gpt]);
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    assert!(
        r.pci
            .iter()
            .any(|p| p.vendor == 0x1af4 && p.device == 0x1042),
        "virtio-blk PCI function (1af4:1042) not enumerated — attach failed: {:?}",
        r.pci
    );
    let Some(dev) = r.block.iter().find(|b| b.size_bytes == EXPECTED_BYTES) else {
        eprintln!(
            "skip: virtualized-GPT disk is on the PCI bus but the guest bound no virtio-blk \
             driver (no /sys/block entry) — this kernel lacks CONFIG_VIRTIO_BLK=y built-in."
        );
        return;
    };
    assert!(dev.ro, "virtualized-GPT device must be read-only");
    let bench = dev.bench.as_ref().expect("blk benchmark present");
    assert!(bench.error.is_none(), "blk bench error: {:?}", bench.error);
    // Reads work on the synthesized read-only disk.
    assert!(
        bench.seq_read.bytes > 0 && bench.seq_read.errors == 0,
        "seq_read: {:?}",
        bench.seq_read
    );
    assert_eq!(
        bench.rand_read.errors, 0,
        "rand_read: {:?}",
        bench.rand_read
    );
    // No writes on a read-only device, and the kernel rejected O_RDWR open
    // (VIRTIO_BLK_F_RO enforcement).
    assert!(bench.seq_write.is_none(), "RO device must not write");
    assert!(bench.rand_write.is_none(), "RO device must not write");
    assert_eq!(
        bench.ro_write_rejected,
        Some(true),
        "RO device must reject O_RDWR open"
    );
}

/// A `--vsock` device gives the guest an AF_VSOCK transport. The guest probe
/// (snuffler, when `dillo.vsock_port=N` is on the cmdline) connects to host
/// CID 2 on port N; dillo's in-process device bridges that to the host Unix
/// socket `<uds>/N.sock`, which this test serves with an echo. snuffler reports
/// the round-trip in `Report.vsock`.
///
/// Unix-only: `--vsock` (and the host `UnixListener` bridge) are gated to Unix
/// hosts, so this test does not run on the Windows/WHP lane.
#[test]
#[cfg(unix)]
fn boots_with_vsock() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    const PORT: u32 = 1234;

    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let Some(kernel) = require(&["VIRTIO_VSOCKETS", "VIRTIO_PCI", "VIRTIO_CONSOLE"], &[]) else {
        eprintln!("skip: kernel DB has no downloadable virtio-vsock kernel");
        return;
    };

    let tmp = TempDir::new().unwrap();

    // Serve the host end of the bridge BEFORE launching dillo: the device's UDS
    // backend connects to `<uds>/<PORT>.sock` when the guest dials port PORT.
    let sock_path = tmp.path().join(format!("{PORT}.sock"));
    let listener = UnixListener::bind(&sock_path).expect("bind host vsock bridge socket");
    let echo = std::thread::spawn(move || {
        // One guest connection; echo everything until the guest closes (EOF).
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 256];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = stream.flush();
                    }
                }
            }
        }
    });

    let cmdline = format!("console=hvc0 dillo.vsock_port={PORT}");
    let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, &cmdline, false);
    let vsock = format!("cid=3,uds={}", tmp.path().display());
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--vsock", &vsock]);
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    let v = r
        .vsock
        .expect("vsock probe result absent (cmdline requested dillo.vsock_port)");
    assert_eq!(v.port, PORT, "probed unexpected port");
    assert!(v.connected, "guest AF_VSOCK connect failed: {:?}", v.error);
    assert!(
        v.echo_ok,
        "guest vsock echo round-trip mismatch: {:?}",
        v.error
    );

    let _ = echo.join();
}

/// A `--net` device gives the guest a virtio-net NIC. With the default `user`
/// backend (cross-platform user-mode NAT, no privilege), it runs on every host
/// lane (Linux/KVM, Windows/WHP, macOS/HVF).
///
/// Two assertions, mirroring the virtio-fs test's layered proof:
///   1. Attach: the virtio-net PCI function (`1af4:1041` = 0x1040 + type 1)
///      enumerates — dillo built and attached the transport. Always checked.
///   2. Driver bind: snuffler finds an interface carrying the host-assigned MAC
///      (`dillo.net_mac=…`), proving the guest's built-in virtio-net driver
///      bound the device and read its config-space MAC. The kernel DB selects a
///      `VIRTIO_NET=y` kernel, so this should hold; a kernel without the
///      built-in driver is a clean skip *after* the attach assertion.
///
/// This validates attach + driver-bind only; the real user-mode datapath (TCP/
/// UDP round-trips, port forwarding) is proven by `boots_with_net_user` and by
/// `dillo-virtio-net`'s in-process datapath unit tests.
#[test]
fn boots_with_net() {
    const MAC: &str = "52:54:00:ab:cd:ef";
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let Some(kernel) = require(&["VIRTIO_NET", "VIRTIO_PCI", "VIRTIO_CONSOLE"], &[]) else {
        eprintln!("skip: kernel DB has no downloadable virtio-net kernel");
        return;
    };

    let tmp = TempDir::new().unwrap();

    let cmdline = format!("console=hvc0 dillo.net_mac={MAC}");
    let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, &cmdline, false);
    let net = format!("mac={MAC}");
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--net", &net]);
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    // Attach proof: a virtio-net PCI function (1af4:1041) must enumerate even if
    // the guest binds no driver.
    let net_funcs = r
        .pci
        .iter()
        .filter(|p| p.vendor == 0x1af4 && p.device == 0x1041)
        .count();
    assert!(
        net_funcs >= 1,
        "expected a virtio-net PCI function (1af4:1041), found {net_funcs}: {:?}",
        r.pci
    );

    // Driver-bind proof.
    let np = r
        .net_probe
        .expect("net probe result absent (cmdline requested dillo.net_mac)");
    assert_eq!(np.requested_mac, MAC, "probed unexpected MAC");
    if !np.found {
        eprintln!(
            "skip: virtio-net attached on PCI but the guest bound no driver — this kernel \
             lacks CONFIG_VIRTIO_NET=y built-in"
        );
        return;
    }
    assert_eq!(
        np.mac.as_deref().map(str::to_ascii_lowercase),
        Some(MAC.to_string()),
        "guest interface MAC mismatch: {np:?}"
    );
    assert!(
        np.iface.is_some(),
        "matched MAC but no interface name: {np:?}"
    );
}

/// Exercise the **user-mode** networking datapath end to end, in a single boot.
/// The guest self-configures `10.0.2.15` via the kernel `ip=` cmdline
/// (`CONFIG_IP_PNP=y`), so snuffler uses pure `std::net`. Three legs:
///   1. guest → host TCP echo via the gateway (`10.0.2.2`), with a `NetBench`
///      (bytes moved, errors == 0, the echo verified byte-for-byte);
///   2. guest → host UDP echo via the gateway;
///   3. host → guest TCP through an inbound `forward` into a listener snuffler
///      opens in the guest (the host harness connects and gets its bytes echoed).
///
/// Cross-platform: the user backend runs in-process with no privilege, so this
/// runs on every host lane (Linux/KVM, Windows/WHP, macOS/HVF).
#[test]
fn boots_with_net_user() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const GUEST_FWD_PORT: u16 = 4545;
    const FWD_PAYLOAD: &[u8] = b"host-to-guest-hello";

    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let Some(kernel) = require(
        &[
            "VIRTIO_NET",
            "INET",
            "IP_PNP",
            "VIRTIO_PCI",
            "VIRTIO_CONSOLE",
        ],
        &[],
    ) else {
        eprintln!("skip: kernel DB has no virtio-net + IP_PNP kernel");
        return;
    };

    // A port that was bound then released — almost certainly free.
    let free_port = || {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let tcp_echo_port = free_port();
    // Bind the UDP echo socket to an OS-chosen UDP port. Reusing a port
    // probed via TCP can land in a Windows UDP excluded-port range and
    // fail with WSAEACCES (10013).
    let udp_echo_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_echo_port = udp_echo_sock.local_addr().unwrap().port();
    let fwd_host_port = free_port();

    // 1. Host TCP echo server (the guest dials it via the gateway).
    let tcp_echo = {
        let listener = TcpListener::bind(("127.0.0.1", tcp_echo_port)).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        })
    };

    // 2. Host UDP echo server.
    let udp_echo = {
        let sock = udp_echo_sock;
        sock.set_read_timeout(Some(Duration::from_secs(30))).ok();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&buf[..n], peer);
            }
        })
    };

    // 3. Host-side forward connector: dial the forwarded port (retrying until
    //    the guest's listener is reachable), send a payload, capture the echo.
    let echoed_back: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let fwd_thread = {
        let echoed_back = Arc::clone(&echoed_back);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                if Instant::now() >= deadline {
                    return;
                }
                match TcpStream::connect(("127.0.0.1", fwd_host_port)) {
                    Ok(mut s) => {
                        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                        if s.write_all(FWD_PAYLOAD).is_err() {
                            std::thread::sleep(Duration::from_millis(200));
                            continue;
                        }
                        let _ = s.shutdown(std::net::Shutdown::Write);
                        let mut buf = Vec::new();
                        let _ = s.read_to_end(&mut buf);
                        if !buf.is_empty() {
                            *echoed_back.lock().unwrap() = Some(buf);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(200)),
                }
            }
        })
    };

    // Host-side egress pre-check for the real-internet leg. The guest's
    // masquerade uses the host's network stack, so the host's own reachability
    // is an exact predictor: only endpoints the host can reach are worth
    // asserting the guest can reach. A locked-down CI runner with no egress to
    // these public IPs is an environmental skip (like no-/dev/kvm), not a
    // failure — but where egress exists it stays a hard assertion that catches a
    // real masquerade regression.
    let reach_endpoints: Vec<&str> = ["1.1.1.1:443", "1.0.0.1:443"]
        .into_iter()
        .filter(|ep| {
            ep.parse::<std::net::SocketAddr>()
                .ok()
                .and_then(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_secs(5)).ok())
                .is_some()
        })
        .collect();

    let tmp = TempDir::new().unwrap();
    let reach_token = if reach_endpoints.is_empty() {
        String::new()
    } else {
        format!(" dillo.net_reach={}", reach_endpoints.join(","))
    };
    let cmdline = format!(
        "ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off console=hvc0 \
         dillo.net_echo=10.0.2.2:{tcp_echo_port} dillo.net_udp=10.0.2.2:{udp_echo_port} \
         dillo.net_listen={GUEST_FWD_PORT}{reach_token}"
    );
    let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, &cmdline, false);
    let net = format!("backend=user,forwards=[{fwd_host_port}:{GUEST_FWD_PORT}]");
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--net", &net]);
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (guest did not boot):\n{output}")
    });

    // Attach proof first (holds even if the guest's IP stack didn't come up).
    let net_funcs = r
        .pci
        .iter()
        .filter(|p| p.vendor == 0x1af4 && p.device == 0x1041)
        .count();
    assert!(
        net_funcs >= 1,
        "expected a virtio-net PCI function (1af4:1041), found {net_funcs}: {:?}",
        r.pci
    );

    let bench = r
        .net_bench
        .expect("net_bench absent (cmdline requested dillo.net_echo)");
    if let Some(err) = &bench.error {
        // A guest that never brought its IP stack up is a clean skip *after* the
        // attach proof — but the kernel DB selected an IP_PNP kernel, so this is
        // unexpected; surface the detail.
        panic!("user-mode net datapath probe failed in guest: {err}\n{output}");
    }

    // Leg 1: guest → host TCP echo (the headline real-I/O proof).
    assert!(bench.tx.bytes > 0, "guest sent no bytes: {:?}", bench.tx);
    assert_eq!(bench.tx.errors, 0, "guest TX errors: {:?}", bench.tx);
    assert_eq!(bench.rx.errors, 0, "guest RX errors: {:?}", bench.rx);
    assert_eq!(
        bench.rx.verified,
        Some(true),
        "guest did not read its TCP echo back intact: {:?}",
        bench.rx
    );
    eprintln!(
        "net_bench: tx {:.1} MiB/s, rx {:.1} MiB/s ({} bytes)",
        bench.tx.throughput_mibps, bench.rx.throughput_mibps, bench.rx.bytes
    );

    // Leg 2: UDP echo via the gateway.
    assert_eq!(
        bench.udp_ok,
        Some(true),
        "guest UDP echo via gateway failed: {bench:?}"
    );

    // Leg 3: inbound forward (host → guest). The guest accepted + echoed, and
    // the host connector received its bytes back.
    assert_eq!(
        bench.forward_ok,
        Some(true),
        "guest never accepted the forwarded connection: {bench:?}"
    );
    let _ = fwd_thread.join();
    assert_eq!(
        echoed_back.lock().unwrap().as_deref(),
        Some(FWD_PAYLOAD),
        "host did not get its forwarded payload echoed back by the guest"
    );

    // Leg 4: real-internet reach. The guest masquerades out through the proxy to
    // a well-known external endpoint (Cloudflare anycast on 443) and the
    // connection holds — proving the user-mode NAT actually carries traffic to
    // the internet, not just to the host. Asserted only where the host itself has
    // egress (see the pre-check above); skipped as environmental otherwise.
    if reach_endpoints.is_empty() {
        eprintln!(
            "skip: host has no egress to the public test endpoints; \
             real-internet masquerade leg not asserted on this runner"
        );
    } else {
        assert_eq!(
            bench.external_ok,
            Some(true),
            "guest could not reach the real internet via masquerade (host can reach {reach_endpoints:?}): {bench:?}"
        );
    }

    let _ = tcp_echo.join();
    let _ = udp_echo.join();
}

/// A `--console endpoint=stdio,ports=[[…]]` turns the single virtio-console
/// into a MULTIPORT device: port 0 stays the unnamed `hvc0` the guest boots on,
/// and each `ports=` entry becomes an additional **named** port the guest's
/// `virtio_console` driver discovers over the control plane.
///
/// This exercises the whole path in one boot:
///   1. port 0 is untouched — the guest still boots on `hvc0` and its report
///      still reaches the host over it (if MULTIPORT broke port 0, there would
///      be no report at all);
///   2. the control plane announced both named ports — snuffler reads every
///      `/sys/class/virtio-ports/*/name` and must see both;
///   3. the `rx=pipe:N` data path works host → guest — the host writes to its
///      end of the pipe before boot and the guest reads those exact bytes off
///      `/dev/vport*`;
///   4. the `tx=pipe:N` data path works guest → host — the guest writes to the
///      named port and the host reads it back off its own pipe end.
///
/// Unix path (Linux/KVM and macOS/HVF): pass device-side pipe ends to dillo
/// by inheritance, clearing `FD_CLOEXEC` in `pre_exec`. This is a real e2e
/// on both hosts — macOS is not "covered by Linux"; the macos-arm64 CI lane
/// runs this under HVF. Windows has a parallel test below that uses
/// `CreatePipe` + inheritable handles. The schema, device, and control plane
/// are host-agnostic and covered by unit tests everywhere.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn boots_with_named_console_ports() {
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    use std::os::unix::process::CommandExt as _;

    /// Host → guest payload, written before boot so it is already queued.
    const TO_GUEST: &str = "dillo-console-port-rx";
    /// Guest → host payload the probe writes to the named port.
    const FROM_GUEST: &str = "dillo-console-port-tx";

    if !hypervisor_available() {
        // Linux probes /dev/kvm; macOS/HVF has no file gate (see
        // `hypervisor_available`) so this branch is local-dev only and must
        // never soft-skip a missing HVF in CI — absence surfaces as boot fail.
        #[cfg(target_os = "linux")]
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        #[cfg(target_os = "macos")]
        eprintln!("skip: no usable hypervisor on this host (local dev only)");
        return;
    }
    let Some(kernel) = require(&["VIRTIO_PCI", "VIRTIO_CONSOLE"], &[]) else {
        eprintln!("skip: kernel DB has no downloadable virtio-console kernel");
        return;
    };

    let tmp = TempDir::new().unwrap();

    // The parent creates every pipe; dillo only ever adopts an inherited end.
    // `build` is bi-directional; `log` is uni-directional (guest → host only,
    // its rx direction closed) — both must be announced to the guest.
    let (device_rx, host_tx) = pipe_pair();
    let (host_rx, device_tx) = pipe_pair();
    let (_log_host_rx, log_device_tx) = pipe_pair();

    // Queue the host → guest bytes now: dillo's rx worker will find them
    // waiting the moment the guest opens the port.
    (&host_tx)
        .write_all(TO_GUEST.as_bytes())
        .expect("host write to the rx pipe");

    let cmdline = format!(
        "console=hvc0 dillo.console_port=build dillo.console_port_read={} \
         dillo.console_port_write={FROM_GUEST}",
        TO_GUEST.len()
    );
    let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, &cmdline, false);

    // dillo names the ends by the descriptor numbers it inherits, so the
    // numbers must survive exec: hand over the raw fds with CLOEXEC cleared.
    let device_rx = device_rx.into_raw_fd();
    let device_tx = device_tx.into_raw_fd();
    let log_device_tx = log_device_tx.into_raw_fd();
    let console = format!(
        "endpoint=stdio,ports=[[name=build,rx=pipe:{device_rx},tx=pipe:{device_tx}],\
         [name=log,tx=pipe:{log_device_tx}]]"
    );

    let out_path = tmp.path().join("console.out");
    let err_path = tmp.path().join("console.err");
    // Required on macOS/HVF (codesign entitlements); no-op on Linux.
    sign_dillo_for_hvf();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dillo"));
    cmd.arg("--pmi")
        .arg(&pmi)
        .args(["--memory", "256", "--cpus", "1"])
        .args(["--console", &console])
        .stdout(File::create(&out_path).unwrap())
        .stderr(File::create(&err_path).unwrap());
    // SAFETY: `fcntl` is async-signal-safe, and this closure touches nothing
    // else between fork and exec.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            for fd in [device_rx, device_tx, log_device_tx] {
                clear_cloexec(fd)?;
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn dillo");

    // Our copies of the device-side ends are now the child's business: close
    // them so the guest sees a real EOF if dillo ever drops its own.
    close_raw(device_rx);
    close_raw(device_tx);
    close_raw(log_device_tx);

    // Read the guest → host side while dillo runs, so a full pipe can never
    // wedge the boot.
    let tx_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while buf.len() < FROM_GUEST.len() && std::time::Instant::now() < deadline {
            match (&host_rx).read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("host read from the tx pipe: {e}"),
            }
        }
        buf
    });

    if child
        .wait_timeout(Duration::from_secs(120))
        .expect("wait dillo")
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("dillo boot timed out");
    }
    // Drop the write end so the reader thread sees EOF rather than blocking.
    drop(host_tx);

    let mut output = std::fs::read_to_string(&out_path).unwrap_or_default();
    output.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());

    // (1) Port 0 is untouched: the report still arrives over hvc0.
    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (MULTIPORT broke port 0?):\n{output}")
    });
    assert!(
        r.consoles.iter().any(|c| c.starts_with("hvc0")),
        "hvc0 not among consoles under MULTIPORT: {:?}",
        r.consoles
    );

    let probe = r
        .console_port
        .expect("console-port probe absent (cmdline requested dillo.console_port)");

    // (2) Both named ports were announced over the control plane.
    assert!(
        !probe.names.is_empty(),
        "guest enumerated no virtio-ports — MULTIPORT control plane failed \
         (expected named ports when VIRTIO_CONSOLE_F_MULTIPORT is on): {probe:?}\n{output}"
    );
    for name in ["build", "log"] {
        assert!(
            probe.names.iter().any(|n| n == name),
            "named port {name:?} missing from the guest's ports {:?}",
            probe.names
        );
    }
    assert!(
        probe.found,
        "the guest did not find the `build` port: {probe:?}"
    );

    // (3) host → guest over rx=pipe:N.
    assert_eq!(
        probe.read.as_deref(),
        Some(TO_GUEST),
        "guest did not read the host's bytes off the named port: {probe:?}\n{output}"
    );

    // (4) guest → host over tx=pipe:N.
    assert!(
        probe.wrote,
        "guest write to the named port failed: {probe:?}"
    );
    let from_guest = tx_reader.join().expect("tx reader thread");
    assert_eq!(
        String::from_utf8_lossy(&from_guest),
        FROM_GUEST,
        "host did not receive the guest's bytes on the tx pipe"
    );
}

/// An anonymous pipe as `(read_end, write_end)`, the way a parent process
/// creates one before handing a device-side end to dillo.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn pipe_pair() -> (std::fs::File, std::fs::File) {
    let (read_end, write_end) = nix::unistd::pipe().expect("pipe");
    (
        std::fs::File::from(read_end),
        std::fs::File::from(write_end),
    )
}

/// Clear `FD_CLOEXEC` so `fd` survives into the child under the same number.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn clear_cloexec(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use std::os::fd::BorrowedFd;

    // SAFETY: `fd` is a descriptor this process still owns (from into_raw_fd
    // on a pipe end we created); we only clear FD_CLOEXEC on it.
    #[allow(unsafe_code)]
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags = fcntl(borrowed, FcntlArg::F_GETFD).map_err(std::io::Error::from)?;
    let cleared = FdFlag::from_bits_truncate(flags) & !FdFlag::FD_CLOEXEC;
    fcntl(borrowed, FcntlArg::F_SETFD(cleared)).map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn close_raw(fd: std::os::fd::RawFd) {
    // Parent's own copy of a descriptor it created and no longer uses.
    let _ = nix::unistd::close(fd);
}

/// Windows process-inheritance e2e for named console ports (Nathaniel lock:
/// multi-platform features must exercise every supported host path).
///
/// Mirrors the Linux coverage intent with WHP plumbing: the parent creates
/// anonymous pipes via `CreatePipe`, marks only the device-side ends
/// inheritable, spawns dillo with `inherit_handles(true)`, and names each end
/// as `pipe:N` using the HANDLE value the child receives unchanged. Proves
/// adopt + boot + named-port traffic on the Windows HANDLE path.
#[cfg(target_os = "windows")]
#[test]
fn boots_with_named_console_ports() {
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawHandle, IntoRawHandle};
    use std::os::windows::process::CommandExt as _;

    /// Host → guest payload, written before boot so it is already queued.
    const TO_GUEST: &str = "dillo-console-port-rx";
    /// Guest → host payload the probe writes to the named port.
    const FROM_GUEST: &str = "dillo-console-port-tx";

    if !hypervisor_available() {
        eprintln!("skip: no usable hypervisor on this host (local dev only)");
        return;
    }
    let Some(kernel) = require(&["VIRTIO_PCI", "VIRTIO_CONSOLE"], &[]) else {
        eprintln!("skip: kernel DB has no downloadable virtio-console kernel");
        return;
    };

    let tmp = TempDir::new().unwrap();

    // Parent creates every pipe; dillo only adopts an inherited HANDLE.
    // `build` is bi-directional; `log` is uni-directional (guest → host).
    let (device_rx, host_tx) = pipe_pair();
    let (host_rx, device_tx) = pipe_pair();
    let (log_host_rx, log_device_tx) = pipe_pair();

    // Only device-side ends may cross into the child. Clear inherit on the
    // ends this parent keeps, or CreateProcess would hand those over too.
    clear_inherit(host_tx.as_raw_handle());
    clear_inherit(host_rx.as_raw_handle());
    clear_inherit(log_host_rx.as_raw_handle());

    (&host_tx)
        .write_all(TO_GUEST.as_bytes())
        .expect("host write to the rx pipe");

    let cmdline = format!(
        "console=hvc0 dillo.console_port=build dillo.console_port_read={} \
         dillo.console_port_write={FROM_GUEST}",
        TO_GUEST.len()
    );
    let pmi = build_pmi_from_path(tmp.path(), &kernel, host::CONFIG, &cmdline, false);

    // On Windows an inherited HANDLE keeps the same numeric value in the
    // child, so `pipe:N` is just that value as u64.
    let device_rx = device_rx.into_raw_handle();
    let device_tx = device_tx.into_raw_handle();
    let log_device_tx = log_device_tx.into_raw_handle();
    let console = format!(
        "endpoint=stdio,ports=[[name=build,rx=pipe:{},tx=pipe:{}],\
         [name=log,tx=pipe:{}]]",
        handle_number(device_rx),
        handle_number(device_tx),
        handle_number(log_device_tx),
    );

    let out_path = tmp.path().join("console.out");
    let err_path = tmp.path().join("console.err");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dillo"));
    cmd.arg("--pmi")
        .arg(&pmi)
        .args(["--memory", "256", "--cpus", "1"])
        .args(["--console", &console])
        .stdout(File::create(&out_path).unwrap())
        .stderr(File::create(&err_path).unwrap())
        // Required: with redirected stdio, Rust may otherwise skip inheriting
        // the extra pipe handles we prepared for `pipe:N`.
        .inherit_handles(true);
    let mut child = cmd.spawn().expect("spawn dillo");

    // Parent copies of the device-side ends are now the child's: close them
    // so the guest sees a real EOF if dillo ever drops its own.
    close_handle(device_rx);
    close_handle(device_tx);
    close_handle(log_device_tx);
    // Keep `log_host_rx` alive so the log pipe stays open for dillo.
    let _keep_log_host_rx = log_host_rx;

    let tx_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while buf.len() < FROM_GUEST.len() && std::time::Instant::now() < deadline {
            match (&host_rx).read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("host read from the tx pipe: {e}"),
            }
        }
        buf
    });

    if child
        .wait_timeout(Duration::from_secs(120))
        .expect("wait dillo")
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("dillo boot timed out");
    }
    drop(host_tx);

    let mut output = std::fs::read_to_string(&out_path).unwrap_or_default();
    output.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());

    let r = parse_report(&output).unwrap_or_else(|| {
        panic!("boot produced no snuffler report (MULTIPORT broke port 0?):\n{output}")
    });
    assert!(
        r.consoles.iter().any(|c| c.starts_with("hvc0")),
        "hvc0 not among consoles under MULTIPORT: {:?}",
        r.consoles
    );

    let probe = r
        .console_port
        .expect("console-port probe absent (cmdline requested dillo.console_port)");

    assert!(
        !probe.names.is_empty(),
        "guest enumerated no virtio-ports — MULTIPORT control plane failed \
         (expected named ports when VIRTIO_CONSOLE_F_MULTIPORT is on): {probe:?}\n{output}"
    );
    for name in ["build", "log"] {
        assert!(
            probe.names.iter().any(|n| n == name),
            "named port {name:?} missing from the guest's ports {:?}",
            probe.names
        );
    }
    assert!(
        probe.found,
        "the guest did not find the `build` port: {probe:?}"
    );

    assert_eq!(
        probe.read.as_deref(),
        Some(TO_GUEST),
        "guest did not read the host's bytes off the named port: {probe:?}\n{output}"
    );

    assert!(
        probe.wrote,
        "guest write to the named port failed: {probe:?}"
    );
    let from_guest = tx_reader.join().expect("tx reader thread");
    assert_eq!(
        String::from_utf8_lossy(&from_guest),
        FROM_GUEST,
        "host did not receive the guest's bytes on the tx pipe"
    );
}

/// Anonymous pipe `(read_end, write_end)` with both ends inheritable. The
/// caller clears inherit on the ends it keeps before spawning dillo.
#[cfg(target_os = "windows")]
fn pipe_pair() -> (std::fs::File, std::fs::File) {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read_end: HANDLE = std::ptr::null_mut();
    let mut write_end: HANDLE = std::ptr::null_mut();
    // SAFETY: out-params are live locals; `sa` is a valid attributes block.
    #[allow(unsafe_code)]
    let ok = unsafe { CreatePipe(&raw mut read_end, &raw mut write_end, &raw const sa, 0) };
    assert_ne!(ok, 0, "CreatePipe: {}", std::io::Error::last_os_error());
    // SAFETY: CreatePipe succeeded; both HANDLEs are owned by this process.
    #[allow(unsafe_code)]
    unsafe {
        (
            std::fs::File::from_raw_handle(read_end as RawHandle),
            std::fs::File::from_raw_handle(write_end as RawHandle),
        )
    }
}

/// Clear `HANDLE_FLAG_INHERIT` so this end stays in the parent only.
#[cfg(target_os = "windows")]
fn clear_inherit(handle: std::os::windows::io::RawHandle) {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

    // SAFETY: `handle` is an owned pipe end from `pipe_pair`.
    #[allow(unsafe_code)]
    let ok = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    assert_ne!(
        ok,
        0,
        "SetHandleInformation: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(target_os = "windows")]
fn close_handle(handle: std::os::windows::io::RawHandle) {
    use windows_sys::Win32::Foundation::CloseHandle;

    // SAFETY: parent's own copy of a handle it created and no longer uses.
    #[allow(unsafe_code)]
    unsafe {
        CloseHandle(handle);
    }
}

#[cfg(target_os = "windows")]
fn handle_number(handle: std::os::windows::io::RawHandle) -> u64 {
    handle as usize as u64
}

// ---------------------------------------------------------------------------
// dt extension channel modes (pmi/spec/dt.md). Each mode is exercised through
// the real arma → dillo path: attached and detached boot, and the two clear
// refusals (detached without --dtb; --dtb against a bundled image).
// ---------------------------------------------------------------------------

/// Build a PMI selecting an arma `--dtb` channel mode: `None` = optional (the
/// default), `Some("attached")` = bundled, or `Some(<path>)` = detached (arma
/// writes the base DTB to that path).
fn build_pmi_mode(dir: &Path, cmdline: &str, dtb: Option<&str>) -> PathBuf {
    let kernel = require(&["PCI", "VIRTIO_PCI", "VIRTIO_BLK", "VIRTIO_CONSOLE"], &[])
        .expect("kernel DB: no PCI + virtio-blk kernel available");
    let cfg = dir.join("kernel.config");
    std::fs::write(&cfg, host::CONFIG).unwrap();
    let pmi = dir.join("boot.pmi");
    let mut cmd = Command::new(env!("CARGO_BIN_FILE_ARMA_arma"));
    cmd.arg("build")
        .args(["--cmdline", cmdline])
        .args(["--profile", host::PROFILE])
        .arg("--config")
        .arg(&cfg)
        .arg("--kernel")
        .arg(&kernel)
        .arg("--initrd")
        .arg(env!("CARGO_BIN_FILE_SNUFFLER_snuffler"));
    if let Some(d) = dtb {
        cmd.args(["--dtb", d]);
    }
    let st = cmd.arg(&pmi).status().expect("spawn arma");
    assert!(st.success(), "arma build failed");
    pmi
}

fn subdir(base: &Path, name: &str) -> PathBuf {
    let p = base.join(name);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Attached (bundled) mode: the base is loaded, dillo boots it with no `--dtb`.
#[test]
fn attached_mode_boots() {
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pmi = build_pmi_mode(tmp.path(), "console=hvc0", Some("attached"));
    let output = boot(&pmi, 256, 1, tmp.path());
    parse_report(&output)
        .unwrap_or_else(|| panic!("attached PMI produced no guest report:\n{output}"));
}

/// Detached mode: the base is delivered out-of-band; dillo boots it with
/// `--dtb <base>`.
#[test]
fn detached_mode_boots_with_dtb() {
    if !hypervisor_available() {
        eprintln!("skip: no usable /dev/kvm on this host (local dev only)");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base.dtb");
    let pmi = build_pmi_mode(tmp.path(), "console=hvc0", Some(base.to_str().unwrap()));
    let base_arg = base.to_str().unwrap();
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--dtb", base_arg]);
    parse_report(&output)
        .unwrap_or_else(|| panic!("detached PMI produced no guest report with --dtb:\n{output}"));
}

/// Detached mode without `--dtb` is refused with a clear message. This is a
/// preflight failure, so it needs no hypervisor.
#[test]
fn detached_mode_without_dtb_is_refused() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path().join("base.dtb");
    let pmi = build_pmi_mode(tmp.path(), "console=hvc0", Some(base.to_str().unwrap()));
    let output = boot(&pmi, 256, 1, tmp.path()); // no --dtb
    assert!(
        parse_report(&output).is_none(),
        "detached PMI must not boot without --dtb:\n{output}"
    );
    assert!(
        output.contains("detached") && output.contains("--dtb"),
        "refusal should name detached mode and --dtb:\n{output}"
    );
}

/// Passing `--dtb` for a bundled image is refused with a clear message.
#[test]
fn dtb_rejected_for_bundled_image() {
    let tmp = TempDir::new().unwrap();
    // A real base DTB, obtained from a detached build.
    let base = tmp.path().join("base.dtb");
    build_pmi_mode(
        &subdir(tmp.path(), "detached"),
        "console=hvc0",
        Some(base.to_str().unwrap()),
    );
    // A bundled image whose base cannot be substituted.
    let pmi = build_pmi_mode(
        &subdir(tmp.path(), "bundled"),
        "console=hvc0",
        Some("attached"),
    );
    let output = boot_with(&pmi, 256, 1, tmp.path(), &["--dtb", base.to_str().unwrap()]);
    assert!(
        parse_report(&output).is_none(),
        "bundled image must not boot with a substituted base:\n{output}"
    );
    assert!(
        output.contains("bundles its base") || output.contains("cannot be substituted"),
        "refusal should explain the bundled base cannot be substituted:\n{output}"
    );
}
