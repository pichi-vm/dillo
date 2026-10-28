// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Structural assertions on the base DTB arma builds.
//!
//! The base_dtb unit tests check FDT magic + non-trivial size; the
//! integration suite already verifies the .dtb section parses via
//! devtree (`base_dtb_parses_*` in structural.rs). This file goes
//! deeper: walk the parsed DTB and assert the required nodes /
//! properties (cmdline, initrd extents, absence of /cpus, intc, pci)
//! are present and correctly populated.

mod common;

use std::fs;

use devtree::{NodeView, PropertyView, Tree, TreeView};
use tempfile::TempDir;

use common::{build_pmi, host_kernel};

// The default build is optional mode, so the base DTB rides in the bundled
// `.dtb` fallback named by the `dt:dtb` attribute (not the `.tatu.dtb` fill
// target, which is a Zero section). Resolve it through the attribute.
fn dtb_bytes_from(pmi_bytes: &[u8]) -> Vec<u8> {
    common::base_dtb(pmi_bytes)
}

/// Build a PMI from the host's catalogued real kernel. Returns `None` when the
/// kernel can't be downloaded (offline) so callers skip rather than fail.
#[cfg(target_arch = "x86_64")]
fn build_x86(cmdline: &str, with_initrd: bool) -> Option<(TempDir, Vec<u8>)> {
    let (kernel, config) = host_kernel()?;
    let tmp = TempDir::new().unwrap();
    let pmi = tmp.path().join("out.pmi");
    let initrd = if with_initrd {
        let p = tmp.path().join("init");
        fs::write(&p, include_bytes!("data/initramfs.cpio")).unwrap();
        Some(p)
    } else {
        None
    };
    build_pmi(kernel, initrd.as_deref(), cmdline, config, &pmi);
    let bytes = fs::read(&pmi).unwrap();
    Some((tmp, bytes))
}

#[cfg(target_arch = "aarch64")]
fn build_aarch64(cmdline: &str) -> Option<(TempDir, Vec<u8>)> {
    let (kernel, config) = host_kernel()?;
    let tmp = TempDir::new().unwrap();
    let pmi = tmp.path().join("out.pmi");
    build_pmi(kernel, None, cmdline, config, &pmi);
    let bytes = fs::read(&pmi).unwrap();
    Some((tmp, bytes))
}

/// Find a node's property by name and read it as &str. Need to bind
/// the Property to a local so the returned &str outlives the call.
fn prop_str<N: NodeView>(node: &N, name: &str) -> Option<String> {
    let p = node.property(name)?;
    p.as_str().map(str::to_string)
}

#[cfg(target_arch = "x86_64")]
fn prop_u64<N: NodeView>(node: &N, name: &str) -> Option<u64> {
    node.property(name)?.as_u64()
}

#[cfg(target_arch = "x86_64")]
fn prop_u32s<N: NodeView>(node: &N, name: &str) -> Option<Vec<u32>> {
    let p = node.property(name)?;
    Some(p.as_u32s()?.collect())
}

#[test]
#[cfg(target_arch = "x86_64")]
fn chosen_carries_exact_cmdline_x86() {
    let Some((_tmp, pmi)) = build_x86("ro single CUSTOM_TOKEN", true) else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let chosen = tree.find_path("/chosen").expect("/chosen present");
    assert_eq!(
        prop_str(&chosen, "bootargs").as_deref(),
        Some("ro single CUSTOM_TOKEN")
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn chosen_carries_exact_cmdline_aarch64() {
    let Some((_tmp, pmi)) = build_aarch64("aarch64-mark another-token") else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let chosen = tree.find_path("/chosen").expect("/chosen present");
    assert_eq!(
        prop_str(&chosen, "bootargs").as_deref(),
        Some("aarch64-mark another-token")
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn chosen_initrd_range_is_consistent_x86() {
    let Some((_tmp, pmi)) = build_x86("ro", true) else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let chosen = tree.find_path("/chosen").expect("/chosen present");
    let start = prop_u64(&chosen, "linux,initrd-start").expect("initrd-start");
    let end = prop_u64(&chosen, "linux,initrd-end").expect("initrd-end");
    assert!(
        end > start,
        "initrd-end ({end:#x}) must exceed start ({start:#x})"
    );
    // Cross-check with the .initrd PE section.
    let pe = goblin::pe::PE::parse(&pmi).unwrap();
    let initrd_sec = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap_or("") == ".initrd")
        .expect(".initrd section present");
    assert_eq!(start, u64::from(initrd_sec.virtual_address));
    // /chosen carries the natural initrd byte count (what Linux reads),
    // while the .initrd section's VirtualSize equals SizeOfRawData
    // (Data shape per PMI core spec — see pe.rs alignment_for). The
    // natural size fits within the padded extent and the extent is
    // 4 KiB-aligned.
    let natural = end - start;
    let padded = u64::from(initrd_sec.virtual_size);
    assert!(natural > 0 && natural <= padded);
    assert_eq!(padded, u64::from(initrd_sec.size_of_raw_data));
    assert_eq!(padded % 0x1000, 0);
}

#[test]
#[cfg(target_arch = "aarch64")]
fn chosen_omits_initrd_when_none_supplied() {
    let Some((_tmp, pmi)) = build_aarch64("ro") else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let chosen = tree.find_path("/chosen").expect("/chosen present");
    assert!(chosen.property("linux,initrd-start").is_none());
    assert!(chosen.property("linux,initrd-end").is_none());
}

#[test]
#[cfg(target_arch = "x86_64")]
fn base_has_no_cpus_node_x86() {
    let Some((_tmp, pmi)) = build_x86("ro", false) else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    // merged.md §1: the base declares nothing CPU-related; the host
    // overlay authors the entire /cpus subtree. No /cpus in the base.
    assert!(
        tree.find_path("/cpus").is_none(),
        "base must declare no /cpus node"
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn base_has_no_cpus_node_aarch64() {
    let Some((_tmp, pmi)) = build_aarch64("ro") else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    // merged.md §1: the base declares nothing CPU-related; the host
    // overlay authors the entire /cpus subtree. No /cpus in the base.
    assert!(
        tree.find_path("/cpus").is_none(),
        "base must declare no /cpus node"
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn x86_intc_two_nodes_lapic_and_ioapic() {
    let Some((_tmp, pmi)) = build_x86("ro", false) else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();

    // A3: LAPIC + IO-APIC are TWO separate interrupt-controller nodes at their
    // architecturally-fixed addresses, each #interrupt-cells=<2>.
    let lapic = tree
        .find_path("/interrupt-controller@fee00000")
        .expect("LAPIC node present");
    assert_eq!(
        prop_str(&lapic, "compatible").as_deref(),
        Some("intel,ce4100-lapic")
    );
    let lreg = prop_u32s(&lapic, "reg").expect("lapic reg");
    assert_eq!((u64::from(lreg[0]) << 32) | u64::from(lreg[1]), 0xFEE0_0000);
    assert_eq!(prop_u32s(&lapic, "#interrupt-cells").unwrap(), vec![2]);

    let ioapic = tree
        .find_path("/interrupt-controller@fec00000")
        .expect("IO-APIC node present");
    assert_eq!(
        prop_str(&ioapic, "compatible").as_deref(),
        Some("intel,ce4100-ioapic")
    );
    let ireg = prop_u32s(&ioapic, "reg").expect("ioapic reg");
    assert_eq!((u64::from(ireg[0]) << 32) | u64::from(ireg[1]), 0xFEC0_0000);
    assert_eq!(prop_u32s(&ioapic, "#interrupt-cells").unwrap(), vec![2]);

    // A5: standalone syscon poweroff with its own reg + value 0x34 (S5 byte).
    let po = tree
        .find_path("/poweroff@fec01000")
        .expect("poweroff node present");
    assert_eq!(
        prop_str(&po, "compatible").as_deref(),
        Some("syscon-poweroff")
    );
    assert_eq!(prop_u32s(&po, "value").unwrap(), vec![0x34]);
    assert!(po.property("regmap").is_none(), "no deprecated regmap");
}

#[test]
#[cfg(target_arch = "aarch64")]
fn aarch64_psci_present_at_root() {
    let Some((_tmp, pmi)) = build_aarch64("ro") else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    // A2: PSCI is a root-level node (arm,psci.yaml), not under /firmware.
    let psci = tree.find_path("/psci").expect("/psci present at root");
    assert_eq!(prop_str(&psci, "method").as_deref(), Some("hvc"));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn pci_host_bridge_present_x86() {
    let Some((_tmp, pmi)) = build_x86("ro", false) else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let root = tree.root();
    let pci = root
        .children()
        .find(|c| prop_str(c, "compatible").as_deref() == Some("pci-host-ecam-generic"))
        .expect("a PCIe ECAM host bridge");
    assert_eq!(
        prop_str(&pci, "compatible").as_deref(),
        Some("pci-host-ecam-generic")
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn pci_host_bridge_present_aarch64() {
    let Some((_tmp, pmi)) = build_aarch64("ro") else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    let dtb = dtb_bytes_from(&pmi);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let root = tree.root();
    let pci = root
        .children()
        .find(|c| prop_str(c, "compatible").as_deref() == Some("pci-host-ecam-generic"))
        .expect("a PCIe ECAM host bridge");
    assert_eq!(
        prop_str(&pci, "compatible").as_deref(),
        Some("pci-host-ecam-generic")
    );
}

/// Stage-0 gate: arma's actual emitted DTB validates against the real kernel
/// devicetree-bindings (dt-schema). Skips cleanly if the harness isn't present
/// so a bare CI stays green; gates wherever `/tmp/dtsv` + `/tmp/processed.json`
/// are installed. dt-validate reports errors on stdout and exits 0, so a clean
/// run is empty output.
#[test]
fn emitted_dtb_passes_dt_validate() {
    use std::process::Command;
    let dtval = std::path::Path::new("/tmp/dtsv/bin/dt-validate");
    let schema = std::path::Path::new("/tmp/processed.json");
    if !dtval.exists() || !schema.exists() {
        eprintln!(
            "SKIP dt-validate: harness absent (/tmp/dtsv/bin/dt-validate + /tmp/processed.json)"
        );
        return;
    }
    #[cfg(target_arch = "aarch64")]
    let built = build_aarch64("console=ttyS0").map(|p| ("aarch64", p));
    #[cfg(target_arch = "x86_64")]
    let built = build_x86("console=ttyS0", false).map(|p| ("x86_64", p));
    let Some((name, (_tmp, pmi))) = built else {
        eprintln!("skip (kernel download failed)");
        return;
    };
    {
        let dtb = dtb_bytes_from(&pmi);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(format!("{name}.dtb"));
        fs::write(&path, &dtb).unwrap();
        let out = Command::new(dtval)
            .arg("-s")
            .arg(schema)
            .arg(&path)
            .output()
            .expect("run dt-validate");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.trim().is_empty(),
            "dt-validate flagged the {name} base DTB:\n{stdout}"
        );
    }
}
