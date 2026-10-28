// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Kernel/config catalog + caching downloader for the pichi-vm test suites.
//!
//! Two roles: (1) a database of available kernels and their published kconfigs
//! ([`KERNELS`] / [`Entry`] / [`resolve`]); (2) a download cache so each file is
//! fetched once. [`catalog_is_fresh`](self) (a scheduled test) guards the
//! database; the cache is exercised cross-platform.
//!
//! [`fetch`] downloads a URL once into a cache directory under the cargo
//! `target/` tree (so `cargo clean` reclaims it) and returns the local
//! path; later calls reuse it. It is keyed by URL, not content — a cache,
//! not a verifier; callers that need integrity pin the URL to an immutable
//! artifact. Concurrent callers (threads, or separate test processes) are
//! serialized per URL with an advisory file lock.
//!
//! Cache location (resolved at runtime): `$BURROW_CACHE` if set, else
//! `$CARGO_TARGET_TMPDIR/burrow` (cargo sets this for integration tests, so it
//! lives under `target/`), else the system temp dir. CI can point
//! `$BURROW_CACHE` at a directory it restores across runs.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;

/// Cache directory, resolved at runtime:
///   1. `$BURROW_CACHE` if set (CI can point this at a restored directory);
///   2. else `$CARGO_TARGET_TMPDIR/burrow` — cargo sets this for integration
///      tests, so the cache lives under `target/` and `cargo clean` removes it;
///   3. else the system temp dir (non-cargo / unit-test fallback).
fn cache_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("BURROW_CACHE") {
        return PathBuf::from(p);
    }
    if let Some(t) = std::env::var_os("CARGO_TARGET_TMPDIR") {
        return Path::new(&t).join("burrow");
    }
    std::env::temp_dir().join("burrow")
}

/// Stable, dependency-free cache key for a URL: 64-bit FNV-1a (hex) plus a
/// sanitized basename for human-readability.
fn url_key(url: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in url.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let base = url
        .rsplit(['/', '?', '#'])
        .find(|s| !s.is_empty())
        .unwrap_or("download");
    let base: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(64)
        .collect();
    format!("{hash:016x}-{base}")
}

/// Download `url` (caching under `target/`) and return the local path.
/// Re-uses the cached copy on subsequent calls.
pub fn fetch(url: &str) -> io::Result<PathBuf> {
    let dir = cache_dir();
    fs::create_dir_all(&dir)?;
    let dest = dir.join(url_key(url));

    // Hold an exclusive lock for the whole check-then-download so parallel
    // callers don't both download (the lock auto-releases if a process dies).
    let lock = File::create(dest.with_extension("lock"))?;
    lock.lock_exclusive()?;
    let result = fetch_locked(url, &dest);
    let _ = FileExt::unlock(&lock);
    result
}

fn fetch_locked(url: &str, dest: &Path) -> io::Result<PathBuf> {
    if dest.exists() {
        return Ok(dest.to_path_buf());
    }
    let tmp = dest.with_extension("tmp");
    let resp = ureq::get(url)
        .call()
        .map_err(|e| io::Error::other(format!("GET {url}: {e}")))?;
    let mut reader = resp.into_reader();
    let mut file = File::create(&tmp)?;
    io::copy(&mut reader, &mut file)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, dest)?; // atomic publish
    Ok(dest.to_path_buf())
}

// ─── Kernel/config catalog ────────────────────────────────────────────────
//
// The database of kernels available to the test suites, each a plain download
// arma accepts directly (raw `vmlinux`/`Image`, gzip/zstd EFI-zboot, or bzImage),
// paired with a published kconfig:
//   * firecracker CI — raw image + a plain `.config`. All virtio built in.
//   * Alpine `vmlinuz-virt` — gzip EFI-zboot; config is the version-stamped
//     `config-*-virt` in the same netboot dir (wildcard-resolved).
//   * Fedora pxeboot `vmlinuz` — zstd EFI-zboot; config pinned to the dist-git
//     commit that built it.

/// A catalogued kernel and its published kconfig.
///
/// `config` may contain a single `*` wildcard for a version-stamped filename
/// (e.g. Alpine's `config-<ver>-virt`), resolved by listing the parent
/// directory. `config` is `None` only when the kernel embeds its own config
/// (IKCONFIG); no catalogued kernel currently does. `builtins` are the kconfig
/// symbols believed to be `=y`; [`catalog_is_fresh`](self) verifies them.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub arch: &'static str,
    pub url: &'static str,
    pub config: Option<&'static str>,
    pub builtins: &'static [&'static str],
}

/// The catalog of available kernels.
pub const KERNELS: &[Entry] = &[
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
    // Fedora pxeboot: zstd EFI-zboot → raw arm64 Image, RANDOMIZE_BASE=y (the
    // KASLR-consuming kernel). Fedora ships no IKCONFIG and doesn't tag dist-git,
    // so the config is pinned to the exact dist-git commit that built it; both the
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
#[must_use]
pub fn config_is_y(text: &str, sym: &str) -> bool {
    let needle = format!("CONFIG_{sym}=y");
    text.lines().any(|l| l == needle)
}

/// Fetch a kconfig given a `config` spec. A plain URL is fetched directly; a URL
/// with a single `*` is a version-stamped filename (e.g. Alpine's
/// `config-<ver>-virt`) — the parent directory is listed and the first entry
/// matching the `prefix*suffix` pattern is fetched.
#[must_use]
pub fn fetch_config_text(spec: &str) -> Option<String> {
    let url = match spec.split_once('*') {
        None => spec.to_string(),
        Some((pre, suf)) => {
            let slash = pre.rfind('/')?;
            let dir = &pre[..=slash];
            let name_prefix = &pre[slash + 1..];
            let listing = fs::read_to_string(fetch(dir).ok()?).ok()?;
            let file = listing
                .split('"')
                .find(|t| t.starts_with(name_prefix) && t.ends_with(suf) && !t.contains('/'))?;
            format!("{dir}{file}")
        }
    };
    fs::read_to_string(fetch(&url).ok()?).ok()
}

/// Download an entry's image and (when published) its kconfig, returning
/// `(image path, Some(kconfig))` or `(image path, None)`; `None` overall if the
/// image or a published config fails to fetch.
#[must_use]
pub fn resolve(e: &Entry) -> Option<(PathBuf, Option<String>)> {
    let image = fetch(e.url).ok()?;
    let config = match e.config {
        Some(spec) => Some(fetch_config_text(spec)?),
        None => None,
    };
    Some((image, config))
}

#[cfg(test)]
mod tests {
    use super::{KERNELS, config_is_y, fetch, fetch_config_text, url_key};

    #[test]
    fn key_is_stable_and_distinct() {
        let a = url_key("https://example.com/a/vmlinuz-virt");
        assert_eq!(a, url_key("https://example.com/a/vmlinuz-virt"));
        assert!(a.ends_with("-vmlinuz-virt"));
        assert_ne!(a, url_key("https://example.com/b/vmlinuz-virt"));
    }

    #[test]
    fn key_has_no_separators_and_tracks_full_url() {
        let k = url_key("https://host/path/k.bin?token=x/y/z");
        assert!(!k.contains(['/', '?', '#']));
        // The whole URL feeds the hash, so a different query → different key.
        assert_ne!(k, url_key("https://host/path/k.bin?token=other"));
    }

    /// Network smoke test (offline-skipped). Verifies a real HTTPS download
    /// and that the second call is a cache hit returning the same path.
    #[test]
    #[ignore = "requires network"]
    fn fetches_and_caches() {
        let url = "https://dl-cdn.alpinelinux.org/alpine/MIRRORS.txt";
        let a = fetch(url).expect("fetch");
        assert!(std::fs::metadata(&a).unwrap().len() > 0);
        assert_eq!(a, fetch(url).expect("cache hit"));
    }

    /// Catalog freshness (offline-skipped; run on a schedule). Every catalogued
    /// kernel URL must be reachable, every config must resolve, and the believed
    /// `builtins` must still be `=y` — catching `latest-stable` drift, dead
    /// mirrors, moved configs, and stale builtin beliefs.
    #[test]
    #[ignore = "requires network; run on schedule"]
    fn catalog_is_fresh() {
        let mut failures = Vec::new();
        for e in KERNELS {
            // Kernel image: reachability only (HEAD — don't download MBs).
            if ureq::head(e.url).call().is_err() {
                failures.push(format!("unreachable kernel: {}", e.url));
            }
            if let Some(spec) = e.config {
                match fetch_config_text(spec) {
                    None => failures.push(format!("unresolvable config: {spec}")),
                    Some(cfg) => {
                        for sym in e.builtins {
                            if !config_is_y(&cfg, sym) {
                                failures.push(format!("{}: CONFIG_{sym} no longer =y", e.url));
                            }
                        }
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "stale catalog:\n  {}",
            failures.join("\n  ")
        );
    }
}
