// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for arma's structural success criteria.

mod common;

use std::fs;
use std::sync::OnceLock;

use ciborium::de::from_reader;
use pmi::vm::{Action, FillKind, Spec, vcpu};
#[cfg(target_arch = "x86_64")]
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use common::{build_pmi, find_pmi_vm, host_kernel};

// ---------------------------------------------------------------------------
// Per-arch fixtures (built once for the whole suite from the host's catalogued
// real kernel; tests skip cleanly when the kernel can't be downloaded).
// ---------------------------------------------------------------------------

struct Fixture {
    pmi_bytes: Vec<u8>,
}

#[cfg(target_arch = "x86_64")]
fn x86_fixture() -> Option<&'static Fixture> {
    static F: OnceLock<Option<Fixture>> = OnceLock::new();
    F.get_or_init(|| {
        let (kernel, config) = host_kernel()?;
        let tmp = TempDir::new().unwrap();
        let init = tmp.path().join("init");
        let pmi = tmp.path().join("out.pmi");
        fs::write(&init, include_bytes!("data/initramfs.cpio")).unwrap();
        build_pmi(kernel, Some(&init), "console=ttyS0", config, &pmi);
        Some(Fixture {
            pmi_bytes: fs::read(&pmi).unwrap(),
        })
    })
    .as_ref()
}

#[cfg(target_arch = "aarch64")]
fn aarch64_fixture() -> Option<&'static Fixture> {
    static F: OnceLock<Option<Fixture>> = OnceLock::new();
    F.get_or_init(|| {
        let (kernel, config) = host_kernel()?;
        let tmp = TempDir::new().unwrap();
        let pmi = tmp.path().join("out.pmi");
        build_pmi(kernel, None, "console=hvc0", config, &pmi);
        Some(Fixture {
            pmi_bytes: fs::read(&pmi).unwrap(),
        })
    })
    .as_ref()
}

// ---------------------------------------------------------------------------
// §15.1 #1 — PE validity
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn pe_validity_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    assert_eq!(&f.pmi_bytes[..2], b"MZ");
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).expect("parse PE");
    assert_eq!(pe.header.coff_header.machine, 0x8664);
    assert!(pe.is_64);
    assert_eq!(
        pe.header.coff_header.number_of_sections as usize,
        pe.sections.len()
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn pe_validity_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    assert_eq!(&f.pmi_bytes[..2], b"MZ");
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).expect("parse PE");
    assert_eq!(pe.header.coff_header.machine, 0xAA64);
}

// ---------------------------------------------------------------------------
// §15.1 #2 — PMI core conformance: sections referenced by actions
// exist; no overlapping VirtualAddress ranges among load/fill sections.
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn pmi_core_conformance_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    // Use the arch-specific decoder path directly to avoid the
    // generic CBOR retry gymnastics above.
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).unwrap();
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let cbor = &f.pmi_bytes[off..off + size];
    let spec: Spec<vcpu::x86_64::CpuState> = from_reader(cbor).expect("decode");

    let sec_names: std::collections::HashSet<String> = pe
        .sections
        .iter()
        .map(|s| s.name().unwrap_or("").to_string())
        .collect();

    let mut referenced = Vec::new();
    for a in &spec.actions {
        let n = match a {
            Action::Load(l) => l.section.as_str(),
            Action::Fill(f) => f.section.as_str(),
        };
        referenced.push(n);
        assert!(sec_names.contains(n), "missing section `{n}`");
    }
    // Pairwise non-overlap (u64 to handle .tatu.reset at 0xFFFFF000 + 4 KiB = 0x1_0000_0000).
    let ref_set: std::collections::HashSet<&str> = referenced.iter().copied().collect();
    let mut ranges: Vec<(u64, u64)> = pe
        .sections
        .iter()
        .filter(|s| ref_set.contains(s.name().unwrap_or("")))
        .map(|s| {
            let lo = s.virtual_address as u64;
            (lo, lo + s.virtual_size as u64)
        })
        .collect();
    ranges.sort_by_key(|r| r.0);
    for w in ranges.windows(2) {
        assert!(w[0].1 <= w[1].0, "overlap: {:?} vs {:?}", w[0], w[1]);
    }
}

#[test]
#[cfg(target_arch = "aarch64")]
fn pmi_core_conformance_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).unwrap();
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let cbor = &f.pmi_bytes[off..off + size];
    let spec: Spec<vcpu::aarch64::CpuState> = from_reader(cbor).expect("decode");
    let sec_names: std::collections::HashSet<String> = pe
        .sections
        .iter()
        .map(|s| s.name().unwrap_or("").to_string())
        .collect();
    for a in &spec.actions {
        let n = match a {
            Action::Load(l) => l.section.as_str(),
            Action::Fill(f) => f.section.as_str(),
        };
        assert!(sec_names.contains(n), "missing section `{n}`");
    }
}

// ---------------------------------------------------------------------------
// §15.1 #3 — PMI granularity rules.
// ---------------------------------------------------------------------------

fn check_granularity(pmi_bytes: &[u8]) {
    let pe = goblin::pe::PE::parse(pmi_bytes).unwrap();
    for s in &pe.sections {
        if s.virtual_size == 0 {
            continue;
        }
        let small = s.virtual_size < 2 * 1024 * 1024;
        let align = if small { 0x1000 } else { 0x20_0000 };
        // VirtualAddress must be aligned. Skip non-loaded (.pmi.vm)
        // which has VirtualAddress = 0.
        if s.virtual_address != 0 {
            assert_eq!(
                s.virtual_address as u64 % align,
                0,
                "section `{}` VirtualAddress not {align:#x}-aligned",
                s.name().unwrap_or("")
            );
        }
        if s.pointer_to_raw_data != 0 {
            assert_eq!(
                s.pointer_to_raw_data as u64 % 0x1000,
                0,
                "section `{}` PointerToRawData not 4 KiB-aligned",
                s.name().unwrap_or("")
            );
        }
        assert_eq!(
            s.size_of_raw_data as u64 % 0x1000,
            0,
            "section `{}` SizeOfRawData not 4 KiB-multiple",
            s.name().unwrap_or("")
        );
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn granularity_rules_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    check_granularity(&f.pmi_bytes);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn granularity_rules_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    check_granularity(&f.pmi_bytes);
}

// ---------------------------------------------------------------------------
// §15.1 #4 — CBOR strict-decode round-trip.
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn cbor_round_trip_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let cbor = &f.pmi_bytes[off..off + size];
    let spec: Spec<vcpu::x86_64::CpuState> = from_reader(cbor).expect("decode 1");
    // Re-encode and decode again; bytes need not match (CBOR has
    // multiple canonical-ish representations), but the decoded value
    // must be stable.
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&spec, &mut buf).unwrap();
    let spec2: Spec<vcpu::x86_64::CpuState> = from_reader(buf.as_slice()).expect("decode 2");
    assert_eq!(spec2.vcpu.rip, spec.vcpu.rip);
    assert_eq!(spec2.actions.len(), spec.actions.len());
}

#[test]
#[cfg(target_arch = "aarch64")]
fn cbor_round_trip_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let cbor = &f.pmi_bytes[off..off + size];
    let spec: Spec<vcpu::aarch64::CpuState> = from_reader(cbor).expect("decode 1");
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&spec, &mut buf).unwrap();
    let spec2: Spec<vcpu::aarch64::CpuState> = from_reader(buf.as_slice()).expect("decode 2");
    assert_eq!(spec2.vcpu.pc, spec.vcpu.pc);
    assert_eq!(spec2.actions.len(), spec.actions.len());
}

// ---------------------------------------------------------------------------
// §15.1 #5 — Manifest correctness.
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn manifest_correctness_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let spec: Spec<vcpu::x86_64::CpuState> = from_reader(&f.pmi_bytes[off..off + size]).unwrap();
    // Default build is optional mode: the `dt:dtb` attribute names the bundled
    // fallback `.dtb`, and a `dt:dtb` fill delivers the base into `.tatu.dtb`.
    assert_eq!(spec.dt_dtb.as_deref(), Some(".dtb"));
    assert!(spec.actions.iter().any(|a| matches!(
        a, Action::Fill(fl) if fl.section == ".tatu.dtb" && matches!(fl.kind, FillKind::DtDtb)
    )));
    // Last action must be Fill with dt:dtbo on .tatu.dtbo.
    match spec.actions.last() {
        Some(Action::Fill(fl)) => {
            assert_eq!(fl.section, ".tatu.dtbo");
            assert!(matches!(fl.kind, FillKind::DtDtbo));
        }
        _ => panic!("last action must be dt:dtbo fill"),
    }
    // .linux is loaded.
    assert!(spec.actions.iter().any(|a| matches!(
        a, Action::Load(l) if l.section == ".linux"
    )));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn manifest_correctness_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let spec: Spec<vcpu::aarch64::CpuState> = from_reader(&f.pmi_bytes[off..off + size]).unwrap();
    // Default build is optional mode (see the x86 twin for the rationale).
    assert_eq!(spec.dt_dtb.as_deref(), Some(".dtb"));
    assert!(spec.actions.iter().any(|a| matches!(
        a, Action::Fill(fl) if fl.section == ".tatu.dtb" && matches!(fl.kind, FillKind::DtDtb)
    )));
    match spec.actions.last() {
        Some(Action::Fill(fl)) => {
            assert_eq!(fl.section, ".tatu.dtbo");
            assert!(matches!(fl.kind, FillKind::DtDtbo));
        }
        _ => panic!("last action must be dt:dtbo fill"),
    }
    assert!(spec.actions.iter().any(|a| matches!(
        a, Action::Load(l) if l.section == ".linux"
    )));
    // aarch64 fixture passes no initrd; assert .initrd is NOT loaded.
    assert!(!spec.actions.iter().any(|a| matches!(
        a, Action::Load(l) if l.section == ".initrd"
    )));
}

// ---------------------------------------------------------------------------
// §15.1 #6 — TatuBootInfo correctness.
// ---------------------------------------------------------------------------

fn check_tatu_bootinfo_header(pmi_bytes: &[u8]) {
    let pe = goblin::pe::PE::parse(pmi_bytes).unwrap();
    let bi_sec = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap_or("") == ".tatu.bootinfo")
        .expect(".tatu.bootinfo present");
    let off = bi_sec.pointer_to_raw_data as usize;
    let hdr = &pmi_bytes[off..off + 76];
    assert_eq!(&hdr[..8], b"TATUBOOT");
    let base_dtb_gpa = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
    let host_dtbo_gpa = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let kernel_gpa = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let kernel_entry_gpa = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let relocs_gpa = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
    let base_dtb_size = u32::from_le_bytes(hdr[48..52].try_into().unwrap());
    let host_dtbo_size = u32::from_le_bytes(hdr[52..56].try_into().unwrap());
    let kernel_size = u32::from_le_bytes(hdr[56..60].try_into().unwrap());
    let _kernel_alloc_size = u32::from_le_bytes(hdr[60..64].try_into().unwrap());
    let relocs64_count = u32::from_le_bytes(hdr[64..68].try_into().unwrap());
    let relocs32neg_count = u32::from_le_bytes(hdr[68..72].try_into().unwrap());
    let relocs32_count = u32::from_le_bytes(hdr[72..76].try_into().unwrap());
    // The entry GPA lies within the loaded kernel image.
    assert!(
        kernel_entry_gpa >= kernel_gpa && kernel_entry_gpa < kernel_gpa + u64::from(kernel_size),
        "entry GPA {kernel_entry_gpa:#x} within image [{kernel_gpa:#x}, +{kernel_size:#x})"
    );
    // KASLR relocs are an x86 concern: arma applies the appended reloc table so
    // the recorded GPA is non-zero with at least the 64-bit list (the signed-32
    // list is empty on kernels ≥ v6.15). aarch64 randomizes via the DTB
    // kaslr-seed instead, so the bootinfo carries no reloc table at all.
    if cfg!(target_arch = "x86_64") {
        assert_ne!(relocs_gpa, 0, "relocs present for a KASLR-capable kernel");
        assert!(relocs64_count > 0, "64-bit relocs present");
    } else {
        assert_eq!(relocs_gpa, 0, "aarch64 uses the DTB kaslr-seed, no relocs");
        assert_eq!(relocs64_count, 0);
        assert_eq!(relocs32neg_count, 0);
        assert_eq!(relocs32_count, 0);
    }
    // Bootinfo carries NATURAL byte counts (what tatu/Linux read).
    // `.dtb` is Data-shape padded (VirtSize == RawSize, both ≥ natural).
    // `.linux` is Padded-shape on x86: VirtualSize includes the bzImage
    // decompressor scratch buffer, so VirtSize ≥ RawSize ≥ natural.
    let look = |name: &str| {
        pe.sections
            .iter()
            .find(|s| s.name().unwrap_or("") == name)
            .map(|s| (s.virtual_address as u64, s.virtual_size, s.size_of_raw_data))
    };
    let check_data_shape = |name: &str, gpa: u64, natural: u32| {
        let (va, vs, rs) = look(name).unwrap_or_else(|| panic!("{name} present"));
        assert_eq!(va, gpa, "{name} VA");
        assert!(u64::from(natural) <= u64::from(vs), "{name} natural fits");
        assert_eq!(vs, rs, "{name} Data shape");
    };
    let check_padded_shape = |name: &str, gpa: u64, natural: u32| {
        let (va, vs, rs) = look(name).unwrap_or_else(|| panic!("{name} present"));
        assert_eq!(va, gpa, "{name} VA");
        assert!(
            u64::from(natural) <= u64::from(rs),
            "{name} natural fits raw"
        );
        assert!(rs <= vs, "{name} Padded shape (raw ≤ virtual)");
    };
    // Default build is optional mode: `.tatu.dtb` is the `dt:dtb` fill target,
    // a Zero section (RawSize = 0, VirtualSize = the reservation that must fit
    // the base), and the base rides in the bundled `.dtb` fallback below.
    let _ = check_data_shape;
    let (dva, dvs, drs) = look(".tatu.dtb").expect(".tatu.dtb present");
    assert_eq!(dva, base_dtb_gpa, ".tatu.dtb VA");
    assert_eq!(drs, 0, ".tatu.dtb is a Zero fill target");
    assert!(
        u64::from(base_dtb_size) <= u64::from(dvs),
        "base fits the .tatu.dtb reservation"
    );
    // The bundled fallback carries the base bytes; it is non-loaded (VA = 0).
    let (fva, _fvs, frs) = look(".dtb").expect(".dtb fallback present");
    assert_eq!(fva, 0, ".dtb fallback is non-loaded");
    assert!(base_dtb_size <= frs, ".dtb holds the base DTB");
    check_padded_shape(".linux", kernel_gpa, kernel_size);
    // .dtbo is Zero shape — RawSize = 0, VirtualSize = host_dtbo_size.
    let (va, vs, rs) = look(".tatu.dtbo").expect(".dtbo present");
    assert_eq!(va, host_dtbo_gpa);
    assert_eq!(vs, host_dtbo_size);
    assert_eq!(rs, 0);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn tatu_bootinfo_header_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    check_tatu_bootinfo_header(&f.pmi_bytes);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn tatu_bootinfo_header_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    check_tatu_bootinfo_header(&f.pmi_bytes);
}

// ---------------------------------------------------------------------------
// §15.1 #7 — Tatu sections present.
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn tatu_sections_present_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).unwrap();
    let names: std::collections::HashSet<String> = pe
        .sections
        .iter()
        .map(|s| s.name().unwrap_or("").to_string())
        .collect();
    for must in [
        ".tatu.bootinfo",
        ".tatu.stack",
        ".tatu.rodata",
        ".tatu.text",
        ".tatu.reset",
    ] {
        assert!(names.contains(must), "missing tatu section `{must}`");
    }
}

#[test]
#[cfg(target_arch = "aarch64")]
fn tatu_sections_present_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).unwrap();
    let names: std::collections::HashSet<String> = pe
        .sections
        .iter()
        .map(|s| s.name().unwrap_or("").to_string())
        .collect();
    for must in [
        ".tatu.bootinfo",
        ".tatu.stack",
        ".tatu.rodata",
        ".tatu.text",
    ] {
        assert!(names.contains(must), "missing tatu section `{must}`");
    }
}

// ---------------------------------------------------------------------------
// §15.1 #8 — Base DTB validity (parses via devtree).
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn base_dtb_parses_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = common::base_dtb(&f.pmi_bytes);
    let _tree: devtree::Tree<'_> = devtree::Tree::parse(&dtb).expect("base DTB parses");
}

#[test]
#[cfg(target_arch = "aarch64")]
fn base_dtb_parses_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = common::base_dtb(&f.pmi_bytes);
    let _tree: devtree::Tree<'_> = devtree::Tree::parse(&dtb).expect("base DTB parses");
}

// ---------------------------------------------------------------------------
// §15.1 #9 — vm:vcpu register validity.
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn vcpu_register_validity_x86() {
    let Some(f) = x86_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let spec: Spec<vcpu::x86_64::CpuState> = from_reader(&f.pmi_bytes[off..off + size]).unwrap();
    assert_eq!(spec.vcpu.rip, 0xFFFF_FFF0, "rip is the reset vector");
    assert_eq!(spec.vcpu.rflags.get() & 0x2, 0x2, "rflags bit 1 must be 1");
    // gdtr.base equals the .tatu.gdt section's GPA.
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).unwrap();
    let gdt = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap_or("") == ".tatu.gdt")
        .expect(".tatu.gdt present");
    assert_eq!(spec.vcpu.gdtr.base, gdt.virtual_address as u64);
    // cr3 equals .tatu.pgt's GPA.
    let pg = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap_or("") == ".tatu.pgt")
        .expect(".tatu.pgt present");
    assert_eq!(spec.vcpu.cr3, pg.virtual_address as u64);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn vcpu_register_validity_aarch64() {
    let Some(f) = aarch64_fixture() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let (off, size) = find_pmi_vm(&f.pmi_bytes);
    let spec: Spec<vcpu::aarch64::CpuState> = from_reader(&f.pmi_bytes[off..off + size]).unwrap();
    // pstate.M[3:0] = 0x5 (EL1h); M[4] = 0 (AArch64).
    assert_eq!(spec.vcpu.pstate.get() & 0xF, 0x5);
    assert_eq!((spec.vcpu.pstate.get() >> 4) & 1, 0);
    // pc lies inside .tatu.text.
    let pe = goblin::pe::PE::parse(&f.pmi_bytes).unwrap();
    let text = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap_or("") == ".tatu.text")
        .expect(".tatu.text present");
    let lo = text.virtual_address as u64;
    let hi = lo + text.virtual_size as u64;
    assert!(
        spec.vcpu.pc >= lo && spec.vcpu.pc < hi,
        "pc {:#x} must lie in .tatu.text [{:#x}, {:#x})",
        spec.vcpu.pc,
        lo,
        hi
    );
}

// ---------------------------------------------------------------------------
// §15.1 #10 — Determinism.
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_arch = "x86_64")]
fn determinism_two_builds_same_inputs_same_output() {
    let Some((kernel, config)) = host_kernel() else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let init = tmp.path().join("init");
    let pmi1 = tmp.path().join("out1.pmi");
    let pmi2 = tmp.path().join("out2.pmi");
    fs::write(&init, include_bytes!("data/initramfs.cpio")).unwrap();
    build_pmi(kernel, Some(&init), "ro", config, &pmi1);
    build_pmi(kernel, Some(&init), "ro", config, &pmi2);
    let b1 = fs::read(&pmi1).unwrap();
    let b2 = fs::read(&pmi2).unwrap();
    let h1 = Sha256::digest(&b1);
    let h2 = Sha256::digest(&b2);
    assert_eq!(
        h1, h2,
        "two builds with identical inputs must match byte-for-byte"
    );
}

// ---------------------------------------------------------------------------
// Build/distribution sanity (§15.3).
// ---------------------------------------------------------------------------

#[test]
#[cfg(any())]
fn single_binary_emits_both_arch_pmis() {
    // §15.3: a single arma binary builds PMIs for both x86_64 and
    // aarch64. We already exercise both fixtures elsewhere; this test
    // explicitly asserts that the PE Machine fields differ.
    let f86 = x86_fixture().unwrap();
    let farm = aarch64_fixture().unwrap();
    let m86 = goblin::pe::PE::parse(&f86.pmi_bytes)
        .unwrap()
        .header
        .coff_header
        .machine;
    let marm = goblin::pe::PE::parse(&farm.pmi_bytes)
        .unwrap()
        .header
        .coff_header
        .machine;
    assert_eq!(m86, 0x8664);
    assert_eq!(marm, 0xAA64);
}
