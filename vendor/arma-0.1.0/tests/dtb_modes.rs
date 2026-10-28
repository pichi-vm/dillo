// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage of the `--dtb` channel modes (`dt` extension,
//! pmi/spec/dt.md). Each mode must emit the base-DTB action, `dt:dtb`
//! attribute, and PE sections the spec prescribes.
//!
//! The assertions are arch-neutral, but the fixtures build x86-64 PMIs (the
//! `x86-64-v3` profile and x86 `CpuState` decode), so the whole file is gated
//! to x86-64. aarch64 emission is covered by the unit tests in `manifest.rs`.
#![cfg(target_arch = "x86_64")]

mod common;

use std::fs;

use ciborium::de::from_reader;
use common::{build_pmi_dtb, dt_dtb_attribute, find_pmi_vm, host_kernel, section_raw_size};
use pmi::vm::{Action, FillKind, Spec, vcpu};
use tempfile::TempDir;

#[cfg(target_arch = "x86_64")]
fn spec_of(bytes: &[u8]) -> Spec<vcpu::x86_64::CpuState> {
    let (off, size) = find_pmi_vm(bytes);
    from_reader(&bytes[off..off + size]).expect("decode .pmi.vm")
}

#[cfg(target_arch = "x86_64")]
fn build(dtb: Option<&str>) -> Option<(TempDir, Vec<u8>)> {
    let (kernel, config) = host_kernel()?;
    let tmp = TempDir::new().unwrap();
    let pmi = tmp.path().join("out.pmi");
    build_pmi_dtb(kernel, config, &pmi, dtb);
    let bytes = fs::read(&pmi).unwrap();
    Some((tmp, bytes))
}

// Attached: the base is bundled in `.tatu.dtb`, delivered by a `default` load,
// and named by the `dt:dtb` attribute. No `dt:dtb` fill, no separate fallback.
#[test]
#[cfg(target_arch = "x86_64")]
fn attached_bundles_and_loads_base() {
    let Some((_tmp, bytes)) = build(Some("attached")) else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let spec = spec_of(&bytes);
    assert_eq!(spec.dt_dtb.as_deref(), Some(".tatu.dtb"));
    assert!(
        spec.actions
            .iter()
            .any(|a| matches!(a, Action::Load(l) if l.section == ".tatu.dtb")),
        "base delivered by a default load"
    );
    assert!(
        !spec
            .actions
            .iter()
            .any(|a| matches!(a, Action::Fill(f) if f.section == ".tatu.dtb")),
        "no dt:dtb fill in attached mode"
    );
    assert!(
        section_raw_size(&bytes, ".tatu.dtb").unwrap() > 0,
        "base bytes present"
    );
    assert!(
        section_raw_size(&bytes, ".dtb").is_none(),
        "no fallback section"
    );
}

// Detached: no `dt:dtb` attribute; a `dt:dtb` fill delivers the base into the
// reserved `.tatu.dtb` Zero section; the base is written out-of-band.
#[test]
#[cfg(target_arch = "x86_64")]
fn detached_writes_external_base_and_omits_attribute() {
    let Some((kernel, config)) = host_kernel() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let pmi = tmp.path().join("out.pmi");
    let base = tmp.path().join("base.dtb");
    build_pmi_dtb(kernel, config, &pmi, Some(base.to_str().unwrap()));
    let bytes = fs::read(&pmi).unwrap();
    let spec = spec_of(&bytes);

    assert_eq!(
        dt_dtb_attribute(&bytes),
        None,
        "no attribute in detached mode"
    );
    assert!(
        spec.actions.iter().any(|a| matches!(
            a, Action::Fill(f) if f.section == ".tatu.dtb" && matches!(f.kind, FillKind::DtDtb)
        )),
        "base delivered by a dt:dtb fill"
    );
    assert_eq!(
        section_raw_size(&bytes, ".tatu.dtb").unwrap(),
        0,
        ".tatu.dtb is a Zero fill target"
    );
    assert!(
        section_raw_size(&bytes, ".dtb").is_none(),
        "no bundled base"
    );

    // The generated base was written out-of-band and is a valid FDT.
    let dtb = fs::read(&base).expect("base DTB written out-of-band");
    assert_eq!(&dtb[0..4], &[0xd0, 0x0d, 0xfe, 0xed], "FDT magic");
    let _tree: devtree::Tree<'_> = devtree::Tree::parse(&dtb).expect("external base parses");
}

// Optional (default): a `dt:dtb` fill delivers the base into `.tatu.dtb`, and
// the `dt:dtb` attribute names the bundled `.dtb` fallback.
#[test]
#[cfg(target_arch = "x86_64")]
fn optional_default_has_fallback_and_fill() {
    let Some((_tmp, bytes)) = build(None) else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let spec = spec_of(&bytes);
    assert_eq!(spec.dt_dtb.as_deref(), Some(".dtb"));
    assert!(
        spec.actions.iter().any(|a| matches!(
            a, Action::Fill(f) if f.section == ".tatu.dtb" && matches!(f.kind, FillKind::DtDtb)
        )),
        "base delivered by a dt:dtb fill"
    );
    assert_eq!(
        section_raw_size(&bytes, ".tatu.dtb").unwrap(),
        0,
        ".tatu.dtb is a Zero fill target"
    );
    assert!(
        section_raw_size(&bytes, ".dtb").unwrap() > 0,
        "fallback carries the base"
    );
}
