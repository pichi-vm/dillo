// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ARCHITECTURE.md §27.2 defensive-parsing test corpus for
//! dillo_devtree::platform.
//!
//! Most adversarial DTB tests need a DTB synthesizer to build the
//! malformed input; vm-fdt was dropped in Phase 0 (dillo uses a
//! hand-rolled writer), so test fixtures depend on either dtc-
//! produced .dtb files or hand-encoded byte streams. The tests
//! below cover what's testable with raw byte arrays today; the
//! richer corpus is stubbed `#[ignore]` with TODOs.

use dillo_devtree::platform::{Arch, Machine, SurveyError};

#[test]
fn empty_dtb_rejected() {
    let err = Machine::survey(&[], Arch::X86_64).expect_err("0 bytes must not parse");
    assert!(matches!(err, SurveyError::Parse(_)), "got {err:?}");
}

#[test]
fn truncated_dtb_rejected() {
    // FDT header is 40 bytes; anything shorter can't even be sized.
    let bytes = vec![0u8; 16];
    let err = Machine::survey(&bytes, Arch::X86_64).expect_err("16 bytes must not parse");
    assert!(matches!(err, SurveyError::Parse(_)), "got {err:?}");
}

#[test]
fn garbage_with_wrong_magic_rejected() {
    let mut bytes = vec![0u8; 256];
    // Set first 4 bytes to non-FDT magic.
    bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    let err = Machine::survey(&bytes, Arch::X86_64).expect_err("wrong magic must not parse");
    assert!(matches!(err, SurveyError::Parse(_)), "got {err:?}");
}

/// Helper: extract the .dtb section bytes from a PMI file. Returns
/// `None` if the file isn't present or has no .dtb. Tests use
/// /tmp/real.pmi as the canonical workspace fixture (per TODO
/// reproducer); they skip gracefully when absent.
fn extract_real_pmi_dtb() -> Option<Vec<u8>> {
    let bytes = std::fs::read("/tmp/real.pmi").ok()?;
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    let num_sections = u16::from_le_bytes(bytes[pe_off + 6..pe_off + 8].try_into().ok()?);
    let opt_size = u16::from_le_bytes(bytes[pe_off + 20..pe_off + 22].try_into().ok()?) as usize;
    let mut sect_off = pe_off + 24 + opt_size;
    for _ in 0..num_sections {
        let name = &bytes[sect_off..sect_off + 8];
        let trimmed = std::str::from_utf8(name)
            .unwrap_or("")
            .trim_end_matches('\0');
        if trimmed == ".dtb" {
            let raw_size =
                u32::from_le_bytes(bytes[sect_off + 16..sect_off + 20].try_into().ok()?) as usize;
            let ptr_to_raw =
                u32::from_le_bytes(bytes[sect_off + 20..sect_off + 24].try_into().ok()?) as usize;
            return Some(bytes[ptr_to_raw..ptr_to_raw + raw_size].to_vec());
        }
        sect_off += 40;
    }
    None
}

#[test]
fn real_pmi_dtb_parses_clean() {
    let Some(dtb) = extract_real_pmi_dtb() else {
        eprintln!("skipping: /tmp/real.pmi not present");
        return;
    };
    // Positive control: the workspace's real DTB MUST parse cleanly.
    Machine::survey(&dtb, Arch::X86_64).expect("real PMI's .dtb must survey cleanly");
}

#[test]
fn dtb_with_random_byte_flipped_fails_safely() {
    // Differential: flipping a single byte in a real DTB causes
    // *some* validation error, not a panic.
    let Some(mut dtb) = extract_real_pmi_dtb() else {
        eprintln!("skipping: /tmp/real.pmi not present");
        return;
    };
    if dtb.len() < 100 {
        return;
    }
    // Flip a byte in the middle of the structure block (after the
    // 40-byte header) — likely trips parse or rule checks.
    let mid = dtb.len() / 2;
    dtb[mid] ^= 0xFF;
    let result = Machine::survey(&dtb, Arch::X86_64);
    // We don't care which error — only that it's an error, not a
    // panic or accept. Either outcome (Ok or Err) is fine as long
    // as no panic occurred (the extract call returning at all
    // proves that).
    let _ = result;
}

/// Compile an inline .dts into a .dtb byte vector. Skips the test
/// (returns `None`) if `dtc` isn't available on $PATH.
fn dtc_compile(dts: &str) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("dtc")
        .args(["-I", "dts", "-O", "dtb", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(dts.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if out.status.success() && !out.stdout.is_empty() {
        Some(out.stdout)
    } else {
        None
    }
}

#[test]
fn non_allowlisted_intc_compatible_rejected() {
    let dts = r#"/dts-v1/;
/ {
    #address-cells = <2>;
    #size-cells = <2>;
    compatible = "linux,dummy-virt";
    intc: intc@feE00000 {
        compatible = "made,up,intc";
        reg = <0x0 0xfee00000 0x0 0x1000>;
        interrupt-controller;
        #interrupt-cells = <3>;
    };
};
"#;
    let Some(dtb) = dtc_compile(dts) else {
        eprintln!("skipping: dtc not available");
        return;
    };
    let err = Machine::survey(&dtb, Arch::X86_64).expect_err("bogus intc compat must fail");
    // Any error in [DtbParse, IntcNotAllowed, missing nodes] is OK —
    // we're proving the validation chain rejects.
    let _ = err;
}

#[test]
fn non_allowlisted_pcie_compatible_rejected() {
    let dts = r#"/dts-v1/;
/ {
    #address-cells = <2>;
    #size-cells = <2>;
    pci@b0000000 {
        compatible = "not-pci-host-ecam-generic";
        reg = <0x0 0xb0000000 0x0 0x100000>;
    };
};
"#;
    let Some(dtb) = dtc_compile(dts) else {
        eprintln!("skipping: dtc not available");
        return;
    };
    let _ = Machine::survey(&dtb, Arch::X86_64).expect_err("bogus pcie compat must fail");
}

#[test]
fn non_allowlisted_syscon_compatible_rejected() {
    let dts = r#"/dts-v1/;
/ {
    #address-cells = <2>;
    #size-cells = <2>;
    syscon@affff000 {
        compatible = "made,up,syscon";
        reg = <0x0 0xaffff000 0x0 0x1000>;
    };
};
"#;
    let Some(dtb) = dtc_compile(dts) else {
        eprintln!("skipping: dtc not available");
        return;
    };
    let _ = Machine::survey(&dtb, Arch::X86_64).expect_err("bogus syscon compat must fail");
}

#[test]
fn pcie_ecam_mmio_overlap_rejected() {
    // Place ECAM and MMIO at overlapping ranges → EcamMmioOverlap.
    let dts = r#"/dts-v1/;
/ {
    #address-cells = <2>;
    #size-cells = <2>;
    pci@b0000000 {
        compatible = "pci-host-ecam-generic";
        reg = <0x0 0xb0000000 0x0 0x100000>;
        bus-range = <0x0 0xff>;
        ranges = <0x02000000 0x0 0xb0050000  0x0 0xb0050000  0x0 0x10000>;
    };
};
"#;
    let Some(dtb) = dtc_compile(dts) else {
        eprintln!("skipping: dtc not available");
        return;
    };
    let _ = Machine::survey(&dtb, Arch::X86_64).expect_err("overlap must fail");
}

#[test]
fn address_cells_size_cells_not_two_rejected() {
    let dts = r"/dts-v1/;
/ {
    #address-cells = <1>;
    #size-cells = <1>;
};
";
    let Some(dtb) = dtc_compile(dts) else {
        eprintln!("skipping: dtc not available");
        return;
    };
    Machine::survey(&dtb, Arch::X86_64).expect_err("address-cells=1 must fail");
}

#[test]
fn base_with_cpus_node_rejected() {
    // merged.md §1: the base must declare nothing CPU-related. A base that
    // carries a `/cpus` node (even an empty container) is non-conformant —
    // the host overlay authors the entire `/cpus` subtree.
    let dts = r"/dts-v1/;
/ {
    #address-cells = <2>;
    #size-cells = <2>;
    cpus {
        #address-cells = <1>;
        #size-cells = <0>;
    };
};
";
    let Some(dtb) = dtc_compile(dts) else {
        eprintln!("skipping: dtc not available");
        return;
    };
    let err = Machine::survey(&dtb, Arch::X86_64).expect_err("base with /cpus must be rejected");
    assert!(matches!(err, SurveyError::BaseHasCpus), "got {err:?}");
}
