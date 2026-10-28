// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! aarch64-specific base DTB additions (device-model §4): GICv3 interrupt
//! controller + a top-level GICv2m MSI frame, armv8 timer, root `/psci`,
//! `ns16550a` MMIO serial, and the virtio-mmio transport slots.
//!
//! MSI routes through a standalone `arm,gic-v2m-frame` (not GIC-child MBI):
//! Apple `hv_gic` has no ITS and clears `GICD_TYPER.MBIS`, and
//! `arm,gic-v3.yaml` admits only an ITS as a GIC child — so a v2m frame is
//! the conformant MSI mechanism Linux can drive. The redistributor is one
//! fixed 32 MiB region (Apple `hv_gic`, ≤256 vCPUs).

use core::ops::Range;

use vm_fdt::FdtWriter;

use super::DtbError;

const GIC_DIST_BASE: u64 = 0x0800_0000;
const GIC_DIST_SIZE: u64 = 0x0001_0000; // 64 KiB
const GIC_REDIST_BASE: u64 = 0x0810_0000;
const GIC_REDIST_SIZE: u64 = 0x0200_0000; // fixed 32 MiB (Apple hv_gic; 256 vCPUs × 128 KiB)
const GIC_MSI_BASE: u64 = 0x0A10_0000; // MSI frame doorbell (V2M_MSI_SETSPI_NS @ +0x40)
const GIC_MSI_SIZE: u64 = 0x0001_0000; // 64 KiB

// Serial/virtio MMIO addresses are planner-assigned (passed in `Inputs`);
// only the clock + IRQ routing constants live here.
const SERIAL_CLK_HZ: u32 = 3_686_400; // 16550 reference clock
const SERIAL_CURRENT_SPEED: u32 = 115_200;
const SERIAL_SPI: u32 = 1; // GIC SPI 1, level-high

const VIRTIO_MMIO_SPI_BASE: u32 = 16; // SPI 16, 17, … (edge), one per transport

pub(super) const INTC_PHANDLE: u32 = 1;
pub(super) const V2M_PHANDLE: u32 = 3;

/// aarch64 architecture-specific MMIO carve-outs: the GICv3
/// distributor/redistributor and the GICv2m MSI frame. The VMM *could*
/// place these (they're not arch-fixed), but arma pins them to the proven
/// Apple-`hv_gic` addresses, so they enter the planner as reserved rather
/// than being placed; [`add_platform`] emits them from the same constants.
pub(super) fn reserved() -> Vec<Range<u64>> {
    vec![
        GIC_DIST_BASE..GIC_DIST_BASE + GIC_DIST_SIZE,
        GIC_REDIST_BASE..GIC_REDIST_BASE + GIC_REDIST_SIZE,
        GIC_MSI_BASE..GIC_MSI_BASE + GIC_MSI_SIZE,
    ]
}

// MSI interrupt-id window within the SPI range (Apple hv_gic SPI range is
// [32, +988]). Wired SPIs (serial = 1, virtio-mmio = 16…) stay below 64; the
// GICv2m frame uses 64..95 for message-based PCIe MSI.
const MSI_INTID_BASE: u32 = 64;
const MSI_INTID_COUNT: u32 = 32;

pub(super) fn add_platform(
    fdt: &mut FdtWriter,
    inputs: &super::Inputs<'_>,
) -> Result<(), DtbError> {
    // interrupt-controller@… — GIC v3 (unit-addressed per arm,gic-v3.yaml).
    let intc = fdt.begin_node(&format!("interrupt-controller@{GIC_DIST_BASE:x}"))?;
    fdt.property_string("compatible", "arm,gic-v3")?;
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_array_u32(
        "reg",
        &[
            (GIC_DIST_BASE >> 32) as u32,
            GIC_DIST_BASE as u32,
            (GIC_DIST_SIZE >> 32) as u32,
            GIC_DIST_SIZE as u32,
            (GIC_REDIST_BASE >> 32) as u32,
            GIC_REDIST_BASE as u32,
            (GIC_REDIST_SIZE >> 32) as u32,
            GIC_REDIST_SIZE as u32,
        ],
    )?;
    fdt.property_phandle(INTC_PHANDLE)?;
    fdt.end_node(intc)?;

    // /v2m — GICv2m MSI frame. Apple `hv_gic` exposes MSI as a doorbell→SPI
    // (no ITS, and GICD_TYPER.MBIS is clear, so Linux's ITS/MBI paths don't
    // activate). A GICv2m frame is the GICv3-compatible MSI mechanism Linux
    // *can* drive without an ITS: `gicv2m_init` runs because LPIs are off, and
    // PCIe `msi-parent` points here. The frame reg is Apple's MSI region;
    // `arm,msi-base-spi`/`arm,msi-num-spis` declare the SPI window (must match
    // the dillo `GicConfig` MSI interrupt range). Delivery is via the VMM's
    // notifier → `hv_gic_send_msi`.
    let v2m = fdt.begin_node(&format!("msi-controller@{GIC_MSI_BASE:x}"))?;
    fdt.property_string("compatible", "arm,gic-v2m-frame")?;
    fdt.property_null("msi-controller")?;
    fdt.property_array_u32(
        "reg",
        &[
            (GIC_MSI_BASE >> 32) as u32,
            GIC_MSI_BASE as u32,
            (GIC_MSI_SIZE >> 32) as u32,
            GIC_MSI_SIZE as u32,
        ],
    )?;
    fdt.property_u32("arm,msi-base-spi", MSI_INTID_BASE)?;
    fdt.property_u32("arm,msi-num-spis", MSI_INTID_COUNT)?;
    fdt.property_phandle(V2M_PHANDLE)?;
    fdt.end_node(v2m)?;

    // /timer — armv8 generic timer (4 standard PPIs).
    let timer = fdt.begin_node("timer")?;
    fdt.property_string("compatible", "arm,armv8-timer")?;
    fdt.property_array_u32(
        "interrupts",
        &[
            1, 13, 0xff08, // secure phys
            1, 14, 0xff08, // non-secure phys
            1, 11, 0xff08, // virtual
            1, 10, 0xff08, // hyp
        ],
    )?;
    // The timer's PPIs are routed by the GIC; without interrupt-parent the
    // kernel can't map them ("arch_timer: No interrupt available").
    fdt.property_u32("interrupt-parent", INTC_PHANDLE)?;
    fdt.property_null("always-on")?;
    fdt.end_node(timer)?;

    // /psci — root-level (A2): SYSTEM_OFF, SYSTEM_RESET, CPU_ON. Per
    // arm,psci.yaml the node is a root child, not under a /firmware wrapper;
    // method = "hvc" traps PSCI calls to the hypervisor.
    let psci = fdt.begin_node("psci")?;
    fdt.property_string_list(
        "compatible",
        vec!["arm,psci-1.0".to_string(), "arm,psci-0.2".to_string()],
    )?;
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci)?;

    // serial@… — ns16550a over MMIO (A4). The 8250 driver is built into every
    // mainstream kernel, so the platform standardizes on it for both arches.
    if let Some(serial) = &inputs.serial {
        let base = serial.start;
        let size = serial.end - serial.start;
        let s = fdt.begin_node(&format!("serial@{base:x}"))?;
        fdt.property_string("compatible", "ns16550a")?;
        fdt.property_array_u32(
            "reg",
            &[
                (base >> 32) as u32,
                base as u32,
                (size >> 32) as u32,
                size as u32,
            ],
        )?;
        fdt.property_u32("reg-shift", 2)?;
        fdt.property_u32("reg-io-width", 4)?;
        fdt.property_u32("clock-frequency", SERIAL_CLK_HZ)?;
        fdt.property_u32("current-speed", SERIAL_CURRENT_SPEED)?;
        fdt.property_u32("interrupt-parent", INTC_PHANDLE)?;
        fdt.property_array_u32("interrupts", &[0, SERIAL_SPI, 4])?; // SPI, level-high
        fdt.end_node(s)?;
    }

    // virtio_mmio@… — one transport per slot (A7). Addresses are
    // planner-assigned (Inputs::virtio); each gets its own GIC SPI (edge,
    // positional); the guest probes magic/DeviceID for occupancy.
    for (i, v) in inputs.virtio.iter().enumerate() {
        let base = v.start;
        let size = v.end - v.start;
        let spi = VIRTIO_MMIO_SPI_BASE + i as u32;
        debug_assert!(spi < MSI_INTID_BASE, "virtio-mmio SPIs must stay below MSI");
        let n = fdt.begin_node(&format!("virtio_mmio@{base:x}"))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u32(
            "reg",
            &[
                (base >> 32) as u32,
                base as u32,
                (size >> 32) as u32,
                size as u32,
            ],
        )?;
        fdt.property_u32("interrupt-parent", INTC_PHANDLE)?;
        fdt.property_array_u32("interrupts", &[0, spi, 1])?; // SPI, edge-rising
        fdt.end_node(n)?;
    }

    Ok(())
}
