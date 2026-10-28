// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for integration tests.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Path to the built `arma` binary. Cargo sets `CARGO_BIN_EXE_<name>`
/// for integration tests.
pub(crate) fn arma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_arma"))
}

/// The first catalogued real kernel for the host arch, with its published
/// kconfig, downloaded and cached once (via `burrow`). Returns `None` if the
/// download failed (offline) so callers can skip rather than fail spuriously.
///
/// arma only ever consumes real kernels — they carry the relocation table arma
/// requires for KASLR, which a hand-built ELF cannot supply. The kernel path is
/// burrow's content cache; the config is materialized into a process-private
/// temp file (kept for the process lifetime) so its path stays valid.
pub(crate) fn host_kernel() -> Option<(&'static Path, &'static Path)> {
    static CACHE: OnceLock<Option<(PathBuf, PathBuf)>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let arch = if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            };
            let entry = burrow::KERNELS.iter().find(|e| e.arch == arch)?;
            let (kernel, config) = burrow::resolve(entry)?;
            let config = config.expect("catalogued kernels publish a config");
            let mut f = tempfile::Builder::new()
                .prefix("arma-test-")
                .suffix(".config")
                .tempfile()
                .ok()?;
            f.write_all(config.as_bytes()).ok()?;
            let (_, cfg_path) = f.keep().ok()?;
            Some((kernel, cfg_path))
        })
        .as_ref()
        .map(|(k, c)| (k.as_path(), c.as_path()))
}

pub(crate) fn build_pmi(
    kernel: &Path,
    initrd: Option<&Path>,
    cmdline: &str,
    config: &Path,
    out: &Path,
) {
    build_pmi_with_profile(kernel, initrd, cmdline, "x86-64-v3", config, out);
}

pub(crate) fn build_pmi_with_profile(
    kernel: &Path,
    initrd: Option<&Path>,
    cmdline: &str,
    cpu_profile: &str,
    config: &Path,
    out: &Path,
) {
    let mut cmd = Command::new(arma_bin());
    cmd.arg("build")
        .arg("--kernel")
        .arg(kernel)
        .arg("--config")
        .arg(config)
        .arg("--cmdline")
        .arg(cmdline)
        .arg("--profile")
        .arg(cpu_profile);
    if let Some(p) = initrd {
        cmd.arg("--initrd").arg(p);
    }
    cmd.arg(out); // positional <output>, last
    let st = cmd.status().expect("spawn arma");
    assert!(st.success(), "arma build failed: {st:?}");
}

/// Locate the `.pmi.vm` section in a PE file's section table and
/// return (offset, size). Panics if not found.
pub(crate) fn find_pmi_vm(bytes: &[u8]) -> (usize, usize) {
    let pe = goblin::pe::PE::parse(bytes).expect("parse PE");
    for s in &pe.sections {
        // Section name padded with NULs to 8 bytes; goblin may also
        // resolve long names via the string table.
        let name = s.name().unwrap_or("");
        if name == ".pmi.vm" {
            return (s.pointer_to_raw_data as usize, s.virtual_size as usize);
        }
    }
    panic!("no .pmi.vm section found");
}

/// Build a PMI selecting a base-DTB channel mode via `--dtb`: `None` for the
/// optional default, `Some("attached")`, or `Some(<path>)` for detached.
#[allow(dead_code)]
pub(crate) fn build_pmi_dtb(kernel: &Path, config: &Path, out: &Path, dtb: Option<&str>) {
    let mut cmd = Command::new(arma_bin());
    cmd.arg("build")
        .arg("--kernel")
        .arg(kernel)
        .arg("--config")
        .arg(config)
        .arg("--cmdline")
        .arg("console=ttyS0")
        .arg("--profile")
        .arg("x86-64-v3");
    if let Some(d) = dtb {
        cmd.arg("--dtb").arg(d);
    }
    cmd.arg(out);
    let st = cmd.status().expect("spawn arma");
    assert!(st.success(), "arma build failed: {st:?}");
}

/// Size of a named PE section's raw data, or `None` if the section is absent.
#[allow(dead_code)]
pub(crate) fn section_raw_size(bytes: &[u8], name: &str) -> Option<u32> {
    let pe = goblin::pe::PE::parse(bytes).expect("parse PE");
    pe.sections
        .iter()
        .find(|s| s.name().unwrap_or("").trim_end_matches('\0') == name)
        .map(|s| s.size_of_raw_data)
}

/// The section name held by the `.pmi.vm` `dt:dtb` attribute, or `None` when the
/// image is detached (no attribute).
#[allow(dead_code)]
pub(crate) fn dt_dtb_attribute(bytes: &[u8]) -> Option<String> {
    use ciborium::value::Value;
    let (off, len) = find_pmi_vm(bytes);
    let value: Value = ciborium::from_reader(&bytes[off..off + len]).expect("decode .pmi.vm");
    let Value::Map(entries) = value else {
        panic!(".pmi.vm is not a CBOR map");
    };
    entries.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(t), Value::Text(n)) if t == "dt:dtb" => Some(n.clone()),
        _ => None,
    })
}

/// Extract the bundled base DTB bytes from a PMI by following the `dt:dtb`
/// attribute (`.tatu.dtb` attached / `.dtb` optional). Panics for a detached
/// image, which carries no bundled base.
#[allow(dead_code)]
pub(crate) fn base_dtb(bytes: &[u8]) -> Vec<u8> {
    let name = dt_dtb_attribute(bytes).expect("dt:dtb attribute present (not detached)");
    let pe = goblin::pe::PE::parse(bytes).expect("parse PE");
    let sec = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap_or("").trim_end_matches('\0') == name)
        .unwrap_or_else(|| panic!("base section `{name}` present"));
    let off = sec.pointer_to_raw_data as usize;
    let len = sec.virtual_size as usize;
    bytes[off..off + len].to_vec()
}
