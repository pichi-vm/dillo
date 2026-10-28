// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Real-kernel image-generation tests.
//!
//! Builds PMIs from the catalogued real kernels (the `burrow` database) for the
//! host arch, each paired with its real published kconfig, and asserts the
//! produced PMI is well-formed. Iterating the catalog exercises arma's
//! config-driven slot inference against genuinely different real configs. Pure
//! image construction (no VM), so it runs on every host OS. Kernels and configs
//! are fetched once and cached by burrow.

mod common;

use std::path::Path;
use std::process::Command;

use burrow::{Entry, KERNELS, resolve};
use ciborium::de::from_reader;
use pmi::vm::{Spec, vcpu};
use tempfile::TempDir;

use common::{arma_bin, find_pmi_vm};

const GRAN: u64 = 2 * 1024 * 1024;

// arma builds for its native host arch only (it embeds the host-arch tatu).
#[cfg(target_arch = "x86_64")]
mod host {
    pub(crate) const ARCH: &str = "x86_64";
    pub(crate) const PROFILE: &str = "x86-64-v2";
    pub(crate) const CMDLINE: &str = "console=ttyS0";
    pub(crate) const PE_MACHINE: u16 = 0x8664;
}
#[cfg(target_arch = "aarch64")]
mod host {
    pub(crate) const ARCH: &str = "aarch64";
    pub(crate) const PROFILE: &str = "armv8.0-a";
    pub(crate) const CMDLINE: &str = "console=ttyAMA0";
    pub(crate) const PE_MACHINE: u16 = 0xAA64;
}

/// Catalogued kernels for the host arch.
fn native_entries() -> Vec<&'static Entry> {
    KERNELS.iter().filter(|e| e.arch == host::ARCH).collect()
}

#[derive(Clone, Copy, Default)]
struct Case {
    serial: bool,
    initrd: bool,
    pci_slots: Option<u32>,
    mmio_slots: Option<u32>,
}

/// Build a PMI from a catalogued kernel + its real config. Returns `None` if the
/// download failed (network) so callers can skip rather than fail spuriously.
fn build(e: &Entry, case: Case, dir: &Path) -> Option<Vec<u8>> {
    let (kernel, config) = resolve(e)?;
    let config = config.expect("catalogued kernels publish a config");
    std::fs::create_dir_all(dir).unwrap();
    let cfg = dir.join("kernel.config");
    std::fs::write(&cfg, config).unwrap();
    let pmi = dir.join("out.pmi");

    let mut cmd = Command::new(arma_bin());
    cmd.arg("build")
        .arg("--kernel")
        .arg(&kernel)
        .arg("--config")
        .arg(&cfg)
        .arg("--cmdline")
        .arg(host::CMDLINE)
        .arg("--profile")
        .arg(host::PROFILE);
    if case.serial {
        cmd.arg("--serial");
    }
    if let Some(n) = case.pci_slots {
        cmd.arg("--pci-slots").arg(n.to_string());
    }
    if let Some(n) = case.mmio_slots {
        cmd.arg("--mmio-slots").arg(n.to_string());
    }
    if case.initrd {
        let init = dir.join("init");
        std::fs::write(&init, include_bytes!("data/initramfs.cpio")).unwrap();
        cmd.arg("--initrd").arg(&init);
    }
    cmd.arg(&pmi);

    let st = cmd.status().expect("spawn arma");
    assert!(st.success(), "arma build failed: {}", e.url);
    Some(std::fs::read(&pmi).unwrap())
}

/// A well-formed PMI: a valid PE for the host arch, every LARGE (>=2 MiB)
/// section 2 MiB-aligned in both VA and file offset (the granularity contract),
/// and a parseable `.pmi.vm` manifest with at least one action.
fn assert_well_formed(bytes: &[u8]) {
    assert_eq!(&bytes[..2], b"MZ", "not a PE");
    let pe = goblin::pe::PE::parse(bytes).expect("parse PE");
    assert_eq!(pe.header.coff_header.machine, host::PE_MACHINE);
    for s in &pe.sections {
        if u64::from(s.virtual_size) >= GRAN {
            let name = s.name().unwrap_or("?");
            assert_eq!(
                u64::from(s.virtual_address) % GRAN,
                0,
                "{name} VA not 2 MiB-aligned"
            );
            assert_eq!(
                u64::from(s.pointer_to_raw_data) % GRAN,
                0,
                "{name} file offset not 2 MiB-aligned"
            );
        }
    }
    let (off, size) = find_pmi_vm(bytes);
    let manifest = &bytes[off..off + size];
    let actions = match host::ARCH {
        "x86_64" => from_reader::<Spec<vcpu::x86_64::CpuState>, _>(manifest)
            .expect("decode x86 .pmi.vm")
            .actions
            .len(),
        _ => from_reader::<Spec<vcpu::aarch64::CpuState>, _>(manifest)
            .expect("decode arm .pmi.vm")
            .actions
            .len(),
    };
    assert!(actions > 0, "manifest has no actions");
}

/// Every catalogued kernel for the host arch builds a well-formed PMI from its
/// real config — exercising slot inference across genuinely different configs.
#[test]
fn catalogued_kernels_build_well_formed_pmis() {
    let entries = native_entries();
    assert!(
        !entries.is_empty(),
        "no catalogued kernels for {}",
        host::ARCH
    );
    let tmp = TempDir::new().unwrap();
    let mut built = 0;
    for (i, e) in entries.iter().enumerate() {
        match build(e, Case::default(), &tmp.path().join(i.to_string())) {
            Some(bytes) => {
                assert_well_formed(&bytes);
                built += 1;
            }
            None => eprintln!("skip (download failed): {}", e.url),
        }
    }
    assert!(
        built > 0,
        "no catalogued kernel could be downloaded and built"
    );
}

/// The device-config flags (serial/initrd/pci+mmio slots) all produce a
/// well-formed PMI, on the first catalogued host-arch kernel.
#[test]
fn build_options_produce_well_formed_pmis() {
    let e = native_entries()[0];
    let tmp = TempDir::new().unwrap();
    for (i, case) in [
        Case {
            serial: true,
            ..Case::default()
        },
        Case {
            initrd: true,
            ..Case::default()
        },
        Case {
            pci_slots: Some(4),
            mmio_slots: Some(2),
            ..Case::default()
        },
        Case {
            pci_slots: Some(8),
            mmio_slots: Some(0),
            ..Case::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        let Some(bytes) = build(e, case, &tmp.path().join(i.to_string())) else {
            eprintln!("skip (download failed): {}", e.url);
            return;
        };
        assert_well_formed(&bytes);
    }
}

/// Same inputs → byte-identical PMI (arma is a deterministic translator).
#[test]
fn deterministic() {
    let e = native_entries()[0];
    let tmp = TempDir::new().unwrap();
    let case = Case {
        serial: true,
        initrd: true,
        pci_slots: Some(4),
        mmio_slots: Some(2),
    };
    let Some(a) = build(e, case, &tmp.path().join("a")) else {
        eprintln!("skip (download failed): {}", e.url);
        return;
    };
    let b = build(e, case, &tmp.path().join("b")).expect("second build");
    assert_eq!(a, b, "build is not deterministic");
}
