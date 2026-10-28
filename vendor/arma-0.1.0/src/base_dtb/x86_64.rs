// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! x86_64-specific base DTB additions: LAPIC + IOAPIC intc, syscon
//! poweroff/reboot, optional ISA-bus + ns16550a serial (`--serial`).
//!
//! Per tatu/ARCHITECTURE.md §12.10, the LAPIC base MUST be exactly
//! `0xFEE00000` — the architectural default. Tatu propagates this
//! into MADT's `local_apic_address` field unchanged. The IOAPIC at
//! `0xFEC00000` is the KVM in-kernel IRQ chip's architectural default;
//! declaring it makes dtb2acpi emit a MADT IOAPIC entry, which is what
//! lets the kernel actually deliver legacy ISA IRQs (notably IRQ 4 for
//! COM1 when `--serial` is set).

use core::ops::Range;

use vm_fdt::FdtWriter;

use super::DtbError;

// Architecturally-fixed interrupt-controller addresses (device-model §4 x86).
const LAPIC_BASE: u64 = 0xFEE0_0000;
const LAPIC_SIZE: u64 = 0x1000;
const IOAPIC_BASE: u64 = 0xFEC0_0000;
const IOAPIC_SIZE: u64 = 0x1000;

const LAPIC_PHANDLE: u32 = 1;
const IOAPIC_PHANDLE: u32 = 2;

// Serial/virtio MMIO addresses are planner-assigned (passed in `Inputs`);
// only the IRQ routing constants live here.
const SERIAL_CLK_HZ: u32 = 3_686_400;
const SERIAL_CURRENT_SPEED: u32 = 115_200;
const SERIAL_IOAPIC_PIN: u32 = 4; // IO-APIC pin 4 (legacy COM1 line)

// syscon power management — arma-assigned but arch-specific, so fixed here and
// reserved (not planner-placed). Placed in the IOAPIC's 2 MiB page, just above
// the IOAPIC register window, so the syscon shares the fixed APIC device island
// (IOAPIC + LAPIC) instead of forming a separate low island — keeping guest RAM
// contiguous below the APIC block. The island's low edge stays the IOAPIC base
// (already 2 MiB-aligned; see device-model §6 and `arma check`). Only one IOAPIC
// is declared, so the conventional multi-IOAPIC slots in this page are unused.
const POWEROFF_BASE: u64 = 0xFEC0_1000;
const REBOOT_BASE: u64 = 0xFEC0_2000;
const SYSCON_REG_SIZE: u64 = 0x4;

const VIRTIO_MMIO_PIN_BASE: u32 = 16; // IO-APIC pins 16, 17, … per transport

/// x86 architecture-fixed + arch-specific MMIO carve-outs: LAPIC, IOAPIC,
/// and the two syscon registers. Fed to the planner so RAM/devices avoid
/// them; emitted as nodes by [`add_platform`] from the same constants.
pub(super) fn reserved() -> Vec<Range<u64>> {
    vec![
        LAPIC_BASE..LAPIC_BASE + LAPIC_SIZE,
        IOAPIC_BASE..IOAPIC_BASE + IOAPIC_SIZE,
        POWEROFF_BASE..POWEROFF_BASE + SYSCON_REG_SIZE,
        REBOOT_BASE..REBOOT_BASE + SYSCON_REG_SIZE,
    ]
}

pub(super) fn add_platform(
    fdt: &mut FdtWriter,
    inputs: &super::Inputs<'_>,
) -> Result<(), DtbError> {
    // A3: LAPIC + IO-APIC are TWO separate interrupt-controller nodes, each
    // #interrupt-cells=<2>, at their architecturally-fixed addresses.
    let lapic = fdt.begin_node(&format!("interrupt-controller@{LAPIC_BASE:x}"))?;
    fdt.property_string("compatible", "intel,ce4100-lapic")?;
    fdt.property_array_u32(
        "reg",
        &[
            (LAPIC_BASE >> 32) as u32,
            LAPIC_BASE as u32,
            (LAPIC_SIZE >> 32) as u32,
            LAPIC_SIZE as u32,
        ],
    )?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 2)?;
    fdt.property_phandle(LAPIC_PHANDLE)?;
    fdt.end_node(lapic)?;

    let ioapic = fdt.begin_node(&format!("interrupt-controller@{IOAPIC_BASE:x}"))?;
    fdt.property_string("compatible", "intel,ce4100-ioapic")?;
    fdt.property_u32("#interrupt-cells", 2)?; // <pin, sense>
    fdt.property_null("interrupt-controller")?;
    fdt.property_array_u32(
        "reg",
        &[
            (IOAPIC_BASE >> 32) as u32,
            IOAPIC_BASE as u32,
            (IOAPIC_SIZE >> 32) as u32,
            IOAPIC_SIZE as u32,
        ],
    )?;
    fdt.property_phandle(IOAPIC_PHANDLE)?;
    fdt.end_node(ioapic)?;

    // A5: poweroff/reset are standalone syscon nodes with their OWN `reg`
    // (no /syscon, no regmap/offset). poweroff value 0x34 = SLP_TYP=5 | SLP_EN
    // (the S5 byte); reboot value 0x1.
    syscon_action(fdt, "poweroff", "syscon-poweroff", POWEROFF_BASE, 0x34)?;
    syscon_action(fdt, "reboot", "syscon-reboot", REBOOT_BASE, 0x1)?;

    // A4 (x86): serial is ns16550a over MMIO (no ISA 0x3f8), IO-APIC pin 4.
    // Address is planner-assigned (Inputs::serial).
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
        fdt.property_u32("interrupt-parent", IOAPIC_PHANDLE)?;
        fdt.property_array_u32("interrupts", &[SERIAL_IOAPIC_PIN, 1])?; // <pin, sense>
        fdt.end_node(s)?;
    }

    // A7 (x86): one virtio_mmio transport per slot, IO-APIC pin 16+. Addresses
    // are planner-assigned (Inputs::virtio); the IRQ pin is positional.
    for (i, v) in inputs.virtio.iter().enumerate() {
        let base = v.start;
        let size = v.end - v.start;
        let pin = VIRTIO_MMIO_PIN_BASE + i as u32;
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
        fdt.property_u32("interrupt-parent", IOAPIC_PHANDLE)?;
        fdt.property_array_u32("interrupts", &[pin, 1])?; // <pin, sense>
        fdt.end_node(n)?;
    }

    Ok(())
}

/// Emit a standalone `syscon-poweroff`/`syscon-reboot` node with its own `reg`
/// and trigger `value` (no `regmap`/`offset`).
fn syscon_action(
    fdt: &mut FdtWriter,
    name: &str,
    compatible: &str,
    base: u64,
    value: u32,
) -> Result<(), DtbError> {
    let node = fdt.begin_node(&format!("{name}@{base:x}"))?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_array_u32(
        "reg",
        &[
            (base >> 32) as u32,
            base as u32,
            (SYSCON_REG_SIZE >> 32) as u32,
            SYSCON_REG_SIZE as u32,
        ],
    )?;
    fdt.property_u32("value", value)?;
    fdt.end_node(node)?;
    Ok(())
}
