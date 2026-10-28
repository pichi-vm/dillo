// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixed ACPI Description Table — HW-Reduced, ACPI 6.5.
//!
//! ACPI 6.5 §5.2.9. The FADT is 276 bytes (revision 6 / minor 5)
//! covering legacy PM blocks, extended PM blocks, sleep/reset
//! registers, and feature flags. Under HW_REDUCED_ACPI (bit 20 of
//! `flags`), legacy PM blocks are unused; the OS interacts with the
//! platform through `SLEEP_CONTROL_REG` / `SLEEP_STATUS_REG` /
//! `RESET_REG` only.
//!
//! The DSDT pointer (`X_DSDT`) is the 64-bit form; `DSDT` is the
//! legacy 32-bit alias that we set when it fits (always, on x86_64
//! guests where the DSDT lives in the low 4 GiB).

use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::flag_type;
use super::sdt::{GAS_ZERO, GenericAddress, SdtHeader};
use super::set_sdt_checksum;
use crate::count::Fadt as FadtPlan;
use crate::error::DtbError;
use crate::oem::OemIdentity;

/// FADT revision (major).
pub(crate) const REVISION: u8 = 6;

/// FADT minor version (ACPI 6.5).
pub(crate) const MINOR_VERSION: u8 = 5;

flag_type! {
    /// FADT `flags` field. ACPI 6.5 §5.2.9.3 Table 5.36.
    pub(crate) struct FadtFlags: U32 as u32 {
        /// Bit 10 — RESET_REG is supported. The OS only inspects
        /// `reset_reg` when this bit is set.
        const RESET_REG_SUP = 1 << 10;
        /// Bit 20 — HW-Reduced ACPI platform.
        const HW_REDUCED_ACPI = 1 << 20;
    }
}

/// FADT `IAPC_BOOT_ARCH` value — VGA absent + CMOS RTC absent — the
/// only combination we emit. Per ACPI 6.5 §5.2.9.3 Table 5.10:
///
/// | Bit | Name                | Reason                                                |
/// |-----|---------------------|-------------------------------------------------------|
/// |   0 | LEGACY_DEVICES      | Clear — no LPT/COM/etc.                               |
/// |   1 | 8042                | Clear — no PS/2 keyboard controller                   |
/// |   2 | VGA_NOT_PRESENT     | **Set** — no legacy VGA in a virtio guest             |
/// |   3 | MSI_NOT_SUPPORTED   | Clear — virtio-pci REQUIRES MSI-X                     |
/// |   4 | PCIE_ASPM_CONTROLS  | Clear — let the OS make ASPM decisions per-device     |
/// |   5 | CMOS_RTC_NOT_PRESENT| **Set** — no MC146818 CMOS RTC                        |
///
/// Bits 6..=15 are reserved and zero. Zero would mean "assume legacy
/// hardware is present" — a worse default for a HW-Reduced virtio
/// guest. DT has no binding for any of these bits; the value is fully
/// determined by the no-legacy-hardware contract.
const IAPC_BOOT_ARCH_NO_LEGACY: u16 = (1 << 2) | (1 << 5);

/// FADT layout, 276 bytes.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Fadt {
    pub header: SdtHeader,
    pub firmware_ctrl: U32,
    pub dsdt: U32,
    pub reserved_1: u8,
    pub preferred_pm_profile: u8,
    pub sci_int: U16,
    pub smi_cmd: U32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4bios_req: u8,
    pub pstate_cnt: u8,
    pub pm1a_evt_blk: U32,
    pub pm1b_evt_blk: U32,
    pub pm1a_cnt_blk: U32,
    pub pm1b_cnt_blk: U32,
    pub pm2_cnt_blk: U32,
    pub pm_tmr_blk: U32,
    pub gpe0_blk: U32,
    pub gpe1_blk: U32,
    pub pm1_evt_len: u8,
    pub pm1_cnt_len: u8,
    pub pm2_cnt_len: u8,
    pub pm_tmr_len: u8,
    pub gpe0_blk_len: u8,
    pub gpe1_blk_len: u8,
    pub gpe1_base: u8,
    pub cst_cnt: u8,
    pub p_lvl2_lat: U16,
    pub p_lvl3_lat: U16,
    pub flush_size: U16,
    pub flush_stride: U16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alrm: u8,
    pub mon_alrm: u8,
    pub century: u8,
    pub iapc_boot_arch: U16,
    pub reserved_2: u8,
    pub flags: FadtFlags,
    pub reset_reg: GenericAddress,
    pub reset_value: u8,
    pub arm_boot_arch: U16,
    pub fadt_minor_version: u8,
    pub x_firmware_ctrl: U64,
    pub x_dsdt: U64,
    pub x_pm1a_evt_blk: GenericAddress,
    pub x_pm1b_evt_blk: GenericAddress,
    pub x_pm1a_cnt_blk: GenericAddress,
    pub x_pm1b_cnt_blk: GenericAddress,
    pub x_pm2_cnt_blk: GenericAddress,
    pub x_pm_tmr_blk: GenericAddress,
    pub x_gpe0_blk: GenericAddress,
    pub x_gpe1_blk: GenericAddress,
    pub sleep_control_reg: GenericAddress,
    pub sleep_status_reg: GenericAddress,
    pub hypervisor_vendor_identity: U64,
}

impl Fadt {
    /// Total bytes for revision 6.5.
    pub(crate) const SIZE: usize = 276;
}

/// Emit a complete, checksummed FADT into `slot`.
///
/// Precondition (enforced by [`crate::AcpiBuffer::populate`]):
/// `slot.len() == Fadt::SIZE`.
///
/// If `dsdt_gpa > u32::MAX` the legacy 32-bit `dsdt` field is set to
/// zero; ACPI 2.0+ consumers (the only ones that understand the
/// HW-Reduced FADT we emit) read `x_dsdt` instead, which is always
/// the correct 64-bit GPA.
///
/// # Errors
/// [`DtbError::Internal`] only via the `u32::try_from(Fadt::SIZE)`
/// defensive guard — unreachable on any practical target.
pub(crate) fn emit(
    slot: &mut [u8],
    dsdt_gpa: u64,
    plan: &FadtPlan,
    oem: &OemIdentity,
) -> Result<(), DtbError> {
    debug_assert!(slot.len() >= Fadt::SIZE, "FADT slot smaller than required");
    let length = u32::try_from(Fadt::SIZE).map_err(|_| DtbError::Internal)?;
    let dsdt32 = u32::try_from(dsdt_gpa).unwrap_or(0);

    let f = Fadt {
        header: SdtHeader::new(*b"FACP", length, REVISION, oem),
        firmware_ctrl: U32::new(0),
        dsdt: U32::new(dsdt32),
        reserved_1: 0,
        preferred_pm_profile: 0,
        sci_int: U16::new(0),
        smi_cmd: U32::new(0),
        acpi_enable: 0,
        acpi_disable: 0,
        s4bios_req: 0,
        pstate_cnt: 0,
        pm1a_evt_blk: U32::new(0),
        pm1b_evt_blk: U32::new(0),
        pm1a_cnt_blk: U32::new(0),
        pm1b_cnt_blk: U32::new(0),
        pm2_cnt_blk: U32::new(0),
        pm_tmr_blk: U32::new(0),
        gpe0_blk: U32::new(0),
        gpe1_blk: U32::new(0),
        pm1_evt_len: 0,
        pm1_cnt_len: 0,
        pm2_cnt_len: 0,
        pm_tmr_len: 0,
        gpe0_blk_len: 0,
        gpe1_blk_len: 0,
        gpe1_base: 0,
        cst_cnt: 0,
        p_lvl2_lat: U16::new(0),
        p_lvl3_lat: U16::new(0),
        flush_size: U16::new(0),
        flush_stride: U16::new(0),
        duty_offset: 0,
        duty_width: 0,
        day_alrm: 0,
        mon_alrm: 0,
        century: 0,
        iapc_boot_arch: U16::new(IAPC_BOOT_ARCH_NO_LEGACY),
        reserved_2: 0,
        flags: if plan.reset_reg.is_some() {
            FadtFlags::HW_REDUCED_ACPI | FadtFlags::RESET_REG_SUP
        } else {
            FadtFlags::HW_REDUCED_ACPI
        },
        reset_reg: plan.reset_reg.unwrap_or(GAS_ZERO),
        reset_value: plan.reset_value,
        arm_boot_arch: U16::new(0),
        fadt_minor_version: MINOR_VERSION,
        x_firmware_ctrl: U64::new(0),
        x_dsdt: U64::new(dsdt_gpa),
        x_pm1a_evt_blk: GAS_ZERO,
        x_pm1b_evt_blk: GAS_ZERO,
        x_pm1a_cnt_blk: GAS_ZERO,
        x_pm1b_cnt_blk: GAS_ZERO,
        x_pm2_cnt_blk: GAS_ZERO,
        x_pm_tmr_blk: GAS_ZERO,
        x_gpe0_blk: GAS_ZERO,
        x_gpe1_blk: GAS_ZERO,
        sleep_control_reg: plan.sleep_control_reg,
        sleep_status_reg: plan.sleep_status_reg,
        // ACPI 6.5 added this field (FADT offset 268) for firmware to
        // stamp a hypervisor vendor ID. systemd-detect-virt, the
        // Linux kernel's hypervisor-detection path, and every common
        // tool use CPUID leaf 0x40000000 instead; the FADT field is
        // not part of any guest's detection logic in practice. Stays
        // zero. If a real consumer ever surfaces, it would be a
        // caller-supplied value alongside `OemIdentity`.
        hypervisor_vendor_identity: U64::new(0),
    };

    super::write_header(slot, &f)?;
    set_sdt_checksum(slot)
}
