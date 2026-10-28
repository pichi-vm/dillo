// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Base DTB construction.
//!
//! The base DTB is the measured half of the merged extension: arma
//! builds it from CLI inputs (plus arch-specific platform definition)
//! and emits it as the `.tatu.dtb` PE section loaded into guest memory.
//!
//! Per `pmi/spec/merged.md` §2 the base must NOT declare resource
//! allocation (no `/memory@*`, no `cpu@N` for N>0, no `/distance-map`,
//! no `numa-node-id`); those come from the host overlay at launch.
//!
//! Device MMIO addresses are **not** chosen here — the [`crate::planner`]
//! decides the generic devices (serial, virtio-mmio, ECAM, the 64-bit BAR
//! window) and passes them in via [`Inputs`]; this module serializes them.
//! The architecture-fixed (x86 LAPIC/IOAPIC) and architecture-specific
//! (aarch64 GIC/v2m, x86 syscon) devices live as per-arch constants here and
//! are exposed to the planner as carve-outs via [`arch_reserved`].

mod aarch64;
mod x86_64;

use core::ops::Range;

use thiserror::Error;
use vm_fdt::{Error as FdtError, FdtWriter};

use crate::kernel::Arch;

/// Per-build inputs to the DTB. Device GPAs/sizes are decided by the
/// [`crate::planner`] and passed in here as ranges.
#[derive(Debug, Clone)]
pub(crate) struct Inputs<'a> {
    pub(crate) arch: Arch,
    pub(crate) cmdline: &'a str,
    /// `Some((gpa, size))` when an initrd is present; `None` otherwise.
    pub(crate) initrd: Option<(u64, u64)>,
    /// ns16550a serial MMIO range, if a serial port is declared.
    pub(crate) serial: Option<Range<u64>>,
    /// virtio-mmio transport ranges (one per slot), in declaration order.
    pub(crate) virtio: &'a [Range<u64>],
    /// ECAM range, if a PCIe host bridge is declared (`None` ⇒ no bridge).
    pub(crate) ecam: Option<Range<u64>>,
    /// PCIe 64-bit BAR window range, present iff `ecam` is.
    pub(crate) pci_window: Option<Range<u64>>,
}

#[derive(Debug, Error)]
pub(crate) enum DtbError {
    #[error(transparent)]
    Fdt(#[from] FdtError),
}

/// ECAM buses (`bus-range = <0 0x0f>`). Must match `planner::ECAM_BUSES`.
pub(super) const ECAM_BUSES: u32 = 16;

/// PCI space code in `ranges` phys.hi: 64-bit non-prefetchable memory. The
/// legacy 32-bit (`0x0200_0000`) and I/O (`0x0100_0000`) windows are dropped.
const PCI_MEM64: u32 = 0x0300_0000;
const SERIAL_ALIAS: &str = "serial0";
const SERIAL_OPTIONS: &str = "115200n8";

/// The architecture-fixed and architecture-specific MMIO the planner must
/// avoid but never assigns: x86 LAPIC/IOAPIC + syscon, aarch64 GIC/v2m.
pub(crate) fn arch_reserved(arch: Arch) -> Vec<Range<u64>> {
    match arch {
        Arch::X86_64 => x86_64::reserved(),
        Arch::Aarch64 => aarch64::reserved(),
    }
}

// ---------------------------------------------------------------------------
// Build entry point.
// ---------------------------------------------------------------------------

/// Build the base DTB. Returns a well-formed FDT v17 blob.
pub(crate) fn build(inputs: &Inputs<'_>) -> Result<Vec<u8>, DtbError> {
    let mut fdt = FdtWriter::new()?;

    let root = fdt.begin_node("")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_string("model", "Arma Virtual Platform")?;
    fdt.property_string_list("compatible", vec!["arma,v1".to_string()])?;

    // /chosen — cmdline + initrd extents.
    chosen_node(&mut fdt, inputs)?;
    aliases_node(&mut fdt, inputs)?;

    // No `/cpus`: the base declares nothing CPU-related. The host overlay
    // authors the entire `/cpus` subtree (container + cpu@N) per merged.md §1.

    // Arch-specific platform definition.
    match inputs.arch {
        Arch::X86_64 => x86_64::add_platform(&mut fdt, inputs)?,
        Arch::Aarch64 => aarch64::add_platform(&mut fdt, inputs)?,
    }

    // PCIe host bridge — shared by both arches. Present iff the planner
    // assigned an ECAM (i.e. `--pci-slots > 0`).
    if let (Some(ecam), Some(window)) = (inputs.ecam.clone(), inputs.pci_window.clone()) {
        pci_node(&mut fdt, inputs.arch, &ecam, &window)?;
    }

    fdt.end_node(root)?;
    Ok(fdt.finish()?)
}

// ---------------------------------------------------------------------------
// Cross-arch nodes.
// ---------------------------------------------------------------------------

fn chosen_node(fdt: &mut FdtWriter, inputs: &Inputs<'_>) -> Result<(), DtbError> {
    let node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", inputs.cmdline)?;
    if inputs.serial.is_some() {
        fdt.property_string("stdout-path", &format!("{SERIAL_ALIAS}:{SERIAL_OPTIONS}"))?;
    }
    if let Some((gpa, size)) = inputs.initrd {
        let end = gpa.saturating_add(size);
        fdt.property_u64("linux,initrd-start", gpa)?;
        fdt.property_u64("linux,initrd-end", end)?;
    }
    // No `kaslr-seed` here: it is guest-generated entropy and MUST NOT live in
    // the measured base DTB (it would make the measurement non-deterministic).
    // tatu injects it at boot via a trusted kaslr overlay merged onto the base
    // before the host overlay (aarch64 only; x86 randomizes via relocations).
    fdt.end_node(node)?;
    Ok(())
}

fn aliases_node(fdt: &mut FdtWriter, inputs: &Inputs<'_>) -> Result<(), DtbError> {
    let Some(serial) = &inputs.serial else {
        return Ok(());
    };
    let node = fdt.begin_node("aliases")?;
    fdt.property_string(SERIAL_ALIAS, &format!("/serial@{:x}", serial.start))?;
    fdt.end_node(node)?;
    Ok(())
}

fn pci_node(
    fdt: &mut FdtWriter,
    arch: Arch,
    ecam: &Range<u64>,
    window: &Range<u64>,
) -> Result<(), DtbError> {
    let ecam_base = ecam.start;
    let ecam_size = ecam.end - ecam.start;
    let win_base = window.start;
    let win_size = window.end - window.start;

    let name = format!("pcie@{ecam_base:x}");
    let node = fdt.begin_node(&name)?;
    fdt.property_string("compatible", "pci-host-ecam-generic")?;
    fdt.property_string("device_type", "pci")?;
    fdt.property_array_u32(
        "reg",
        &[
            (ecam_base >> 32) as u32,
            ecam_base as u32,
            (ecam_size >> 32) as u32,
            ecam_size as u32,
        ],
    )?;
    fdt.property_array_u32("bus-range", &[0, ECAM_BUSES - 1])?;
    fdt.property_u32("#address-cells", 3)?;
    fdt.property_u32("#size-cells", 2)?;
    // ranges per PCI binding: <phys.hi phys.mid phys.lo cpu.hi cpu.lo size.hi size.lo>
    //   phys.hi  = space code (0x0300_0000 = 64-bit non-prefetchable memory)
    //   phys.mid:phys.lo = PCI-space base (1:1 with CPU)
    //   cpu.hi:cpu.lo    = CPU physical base
    //   size.hi:size.lo  = window size
    // A single 64-bit window — no 32-bit, no I/O (§4 PCIe).
    fdt.property_array_u32(
        "ranges",
        &[
            PCI_MEM64,
            (win_base >> 32) as u32,
            win_base as u32,
            (win_base >> 32) as u32,
            win_base as u32,
            (win_size >> 32) as u32,
            win_size as u32,
        ],
    )?;
    // No dma-ranges: DMA is 1:1 (no IOMMU); the contract omits it. aarch64
    // states cache-coherence via dma-coherent below.
    // aarch64: route PCIe MSI-X to the GICv2m MSI frame (Apple hv_gic has no
    // ITS and no MBIS bit, so the v2m frame is the usable MSI controller), and
    // declare DMA cache-coherent (aarch64 must state this explicitly). x86
    // needs neither: MSI targets the LAPIC and DMA is coherent by arch.
    if matches!(arch, Arch::Aarch64) {
        fdt.property_null("dma-coherent")?;
        fdt.property_u32("msi-parent", aarch64::V2M_PHANDLE)?;
    }
    fdt.end_node(node)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x86_inputs() -> Inputs<'static> {
        Inputs {
            arch: Arch::X86_64,
            cmdline: "console=ttyS0",
            initrd: Some((0x0500_0000, 0x10_0000)),
            serial: Some(0x0900_0000..0x0900_1000),
            virtio: &[],
            ecam: Some(0x1000_0000..0x1100_0000),
            // default x86 X=39/B=37 ⇒ window at 2^38, size 2^37.
            pci_window: Some((1 << 38)..((1 << 38) + (1 << 37))),
        }
    }

    fn arm_inputs() -> Inputs<'static> {
        Inputs {
            arch: Arch::Aarch64,
            cmdline: "console=hvc0",
            initrd: None,
            serial: Some(0x0A11_0000..0x0A11_1000),
            virtio: &[],
            ecam: Some(0x0A20_0000..0x0B20_0000),
            // default aarch64 X=36/B=34 ⇒ window at 2^35, size 2^34.
            pci_window: Some((1 << 35)..((1 << 35) + (1 << 34))),
        }
    }

    #[test]
    fn build_x86_succeeds() {
        use devtree::{NodeView, PropertyView, Tree, TreeView};

        let bytes = build(&x86_inputs()).expect("build");
        assert!(bytes.len() > 0x80, "non-trivial DTB");
        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(magic, 0xd00d_feed);
        let tree: Tree<'_> = Tree::parse(&bytes).expect("parse x86 DTB");
        let chosen = tree.find_path("/chosen").expect("/chosen present");
        assert_eq!(
            chosen.property("stdout-path").unwrap().as_str(),
            Some("serial0:115200n8")
        );
        let aliases = tree.find_path("/aliases").expect("/aliases present");
        assert_eq!(
            aliases.property("serial0").unwrap().as_str(),
            Some("/serial@9000000")
        );
    }

    #[test]
    fn build_aarch64_succeeds() {
        let bytes = build(&arm_inputs()).expect("build");
        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(magic, 0xd00d_feed);
    }

    /// No `ecam` ⇒ no `/pcie` node at all (microVM / virtio-mmio-only).
    #[test]
    fn pci_omitted_without_ecam() {
        use devtree::{Tree, TreeView};
        let nopci = Inputs {
            ecam: None,
            pci_window: None,
            ..arm_inputs()
        };
        let bytes = build(&nopci).expect("build no-pci");
        let tree: Tree<'_> = Tree::parse(&bytes).expect("parse");
        assert!(
            tree.find_path("/pcie@a200000").is_none(),
            "no bridge when ecam is None"
        );
    }

    /// The PCIe bridge serializes the planner-assigned ECAM + window, and on
    /// aarch64 carries GICv2m MSI routing.
    #[test]
    fn aarch64_pci_serializes_planner_addresses() {
        use devtree::{NodeView, Tree, TreeView};

        let bytes = build(&arm_inputs()).expect("build");
        let tree: Tree<'_> = Tree::parse(&bytes).expect("parse aarch64 DTB");

        let pci = tree
            .find_path("/pcie@a200000")
            .expect("/pcie@a200000 present");
        let mp = pci.property("msi-parent").expect("msi-parent");
        assert_eq!(mp.as_ref(), &[0, 0, 0, 3]); // V2M_PHANDLE
        // window from inputs: base 2^35 (32 GiB), size 2^34 (16 GiB).
        let ranges = pci.property("ranges").expect("ranges");
        assert_eq!(
            ranges.as_ref(),
            &[
                0x03, 0, 0, 0, // phys.hi = Mem64
                0, 0, 0, 8, 0, 0, 0, 0, // PCI base 0x8_0000_0000 (32 GiB)
                0, 0, 0, 8, 0, 0, 0, 0, // CPU base 0x8_0000_0000
                0, 0, 0, 4, 0, 0, 0, 0, // size 0x4_0000_0000 (16 GiB)
            ]
        );
    }

    /// The GIC + v2m frame are arch-specific constants (not planner-placed).
    #[test]
    fn aarch64_dtb_has_v2m_msi_routing() {
        use devtree::{NodeView, Tree, TreeView};

        let bytes = build(&arm_inputs()).expect("build");
        let tree: Tree<'_> = Tree::parse(&bytes).expect("parse aarch64 DTB");

        let intc = tree
            .find_path("/interrupt-controller@8000000")
            .expect("GIC present");
        let reg = intc.property("reg").expect("reg");
        assert_eq!(reg.as_ref().len(), 32, "GICD + GICR each <base size>");

        let v2m = tree
            .find_path("/msi-controller@a100000")
            .expect("v2m present");
        let compat = v2m.property("compatible").expect("compatible");
        assert!(compat.as_ref().starts_with(b"arm,gic-v2m-frame"));
    }

    /// A4/A7: ns16550a serial + virtio-mmio at the planner-assigned ranges.
    #[test]
    fn aarch64_serial_and_virtio_mmio() {
        use devtree::{NodeView, PropertyView, Tree, TreeView};
        let virtio: Vec<Range<u64>> = (0..3)
            .map(|i| {
                let b = 0x0A11_1000 + i * 0x200;
                b..b + 0x200
            })
            .collect();
        let inputs = Inputs {
            virtio: &virtio,
            ..arm_inputs()
        };
        let bytes = build(&inputs).expect("build");
        let tree: Tree<'_> = Tree::parse(&bytes).expect("parse");

        let chosen = tree.find_path("/chosen").expect("/chosen present");
        assert_eq!(
            chosen.property("stdout-path").unwrap().as_str(),
            Some("serial0:115200n8")
        );
        let aliases = tree.find_path("/aliases").expect("/aliases present");
        assert_eq!(
            aliases.property("serial0").unwrap().as_str(),
            Some("/serial@a110000")
        );

        let s = tree.find_path("/serial@a110000").expect("/serial present");
        assert!(
            s.property("compatible")
                .unwrap()
                .as_ref()
                .starts_with(b"ns16550a")
        );
        assert_eq!(
            s.property("interrupts").unwrap().as_ref(),
            &[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4] // <SPI 1 level-high>
        );
        assert_eq!(s.property("current-speed").unwrap().as_u32(), Some(115_200));

        for i in 0..3u64 {
            let base = 0x0A11_1000 + i * 0x200;
            let n = tree
                .find_path(&format!("/virtio_mmio@{base:x}"))
                .expect("virtio_mmio node");
            assert!(
                n.property("compatible")
                    .unwrap()
                    .as_ref()
                    .starts_with(b"virtio,mmio")
            );
            let spi = 16 + i as u32;
            let mut exp = Vec::new();
            exp.extend_from_slice(&0u32.to_be_bytes());
            exp.extend_from_slice(&spi.to_be_bytes());
            exp.extend_from_slice(&1u32.to_be_bytes()); // edge-rising
            assert_eq!(n.property("interrupts").unwrap().as_ref(), exp.as_slice());
        }
    }
}
