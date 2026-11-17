// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! macOS / Hypervisor.framework backend (aarch64).
//!
//! Concrete `Vm` / `Vcpu` mirroring the KVM backend's role, built on the
//! `applevisor` safe wrapper. HVF specifics (proven empirically in the Phase-0
//! spike, see TODO.md):
//!   - one VM per process (the `VirtualMachineStaticInstance` singleton);
//!   - `hv_gic` must be configured before any vCPU is created — so
//!     [`Vm::new`] does `init_with_gic`;
//!   - in-kernel GICv3 with **message-based** MSI (no ITS): inject via
//!     `gic_send_msi` (message interrupt) / `gic_set_spi` (wired, e.g. the serial UART);
//!   - a vCPU is bound to its creating thread, so [`Vcpu::prepare`] creates
//!     and retains it on each owner thread;
//!   - exits arrive as synchronous exceptions; EC = `ESR >> 26`
//!     (HVC `0x16`, data-abort/MMIO `0x24`, WFI `0x01`).

use std::cell::Cell;

use applevisor::prelude::{
    ExitReason, FeatureReg, GicConfig, GicEnabled, MemPerms, Memory, Reg, SysReg, Vcpu as AvVcpu,
    VcpuConfig, VcpuExit, VcpuHandle, VirtualMachineConfig, VirtualMachineInstance,
    VirtualMachineStaticInstance,
};

use crate::VmExit;

/// Canonical aarch64 platform memmap (must match arma's base DTB; see
/// `arma/src/base_dtb/aarch64.rs` and TODO.md #10).
/// AArch64 instruction length (no 16-bit encodings).
const INSN_LEN: u64 = 4;

/// In-kernel GICv3 placement, derived by the platform layer from the DTB
/// (`/intc`+`/v2m`) and handed to [`Vm::new`]. The hypervisor never hardcodes
/// these — addresses are the image's to assign (device-model §4); F7a.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GicParams {
    pub dist_base: u64,
    pub redist_base: u64,
    pub msi_base: u64,
    pub msi_intid_base: u32,
    pub msi_intid_count: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Arm CPU admission: {0}")]
    ArmAdmission(#[from] dillo_machine::aarch64::AdmissionError),
    #[error("hvf: {0}")]
    Hv(String),
    #[error("hvf: parse DTB: {0}")]
    ParseDtb(dillo_devtree::devtree::Error),
    #[error("hvf: missing required DTB substrate {0}")]
    MissingSubstrate(&'static str),
    #[error("hvf: bad DTB substrate property {node}:{prop}: {reason}")]
    BadSubstrateProperty {
        node: &'static str,
        prop: &'static str,
        reason: &'static str,
    },
    #[error("hvf: VM not initialized")]
    NoVm,
    #[error("hvf: guest address {0:#x} not in any mapped region")]
    UnmappedGuestAddr(u64),
}

impl From<applevisor::prelude::HypervisorError> for Error {
    fn from(e: applevisor::prelude::HypervisorError) -> Self {
        Self::Hv(format!("{e:?}"))
    }
}

pub(crate) fn guest_address_bits() -> Result<u32, Error> {
    let ipa = VirtualMachineConfig::get_max_ipa_size()?;
    let mmfr0 = VcpuConfig::default().get_feature_reg(FeatureReg::ID_AA64MMFR0_EL1)?;
    let physical = dillo_machine::aarch64_pa_bits(mmfr0)
        .ok_or_else(|| Error::Hv("reserved guest PARange encoding".into()))?;
    Ok(ipa.min(physical))
}

/// The per-process HVF virtual machine. Owns the guest-memory mappings; the
/// VM/GIC themselves live in the `applevisor` process-global singleton.
#[derive(Debug)]
pub(crate) struct Vm {
    native: NativeVm,
    /// Kept alive for the VM's lifetime; `Memory::drop` unmaps each region.
    regions: Vec<Region>,
}

#[derive(Debug)]
struct Region {
    base: u64,
    size: u64,
    mem: Memory,
}

impl Vm {
    /// Create the VM with the host's maximum IPA size and configure the
    /// in-kernel GICv3 at the canonical platform addresses. Must be called
    /// before any vCPU is created.
    /// Create the VM and configure the in-kernel GICv3 from DTB-derived
    /// placement (`gic`). `min_addr_space_bits` is the device-model watermark
    /// `X` the image requires (F7): the host's max IPA must be ≥ `X` or the
    /// image cannot run here. IPA is set to the host max (≥ `X`) so guest RAM
    /// can still scale above `2^X` on wider hosts.
    pub(crate) fn new(gic: &GicParams, min_addr_space_bits: u32) -> Result<Self, Error> {
        let mut vm_config = VirtualMachineConfig::new();
        let max_ipa = VirtualMachineConfig::get_max_ipa_size()?;
        let available = guest_address_bits()?;
        if available < min_addr_space_bits {
            return Err(Error::Hv(format!(
                "launch requires {min_addr_space_bits} address bits; backend provides {available}"
            )));
        }
        vm_config.set_ipa_size(max_ipa)?;

        let mut g = GicConfig::new();
        g.set_distributor_base(gic.dist_base)?;
        g.set_redistributor_base(gic.redist_base)?;
        g.set_msi_region_base(gic.msi_base)?;
        g.set_msi_interrupt_range(gic.msi_intid_base, gic.msi_intid_count)?;

        VirtualMachineStaticInstance::init_with_gic(vm_config, g)?;
        Ok(Self {
            native: VirtualMachineStaticInstance::get_gic().ok_or(Error::NoVm)?,
            regions: Vec::new(),
        })
    }

    pub(crate) fn cpu_instance(&self) -> NativeVm {
        self.native.clone()
    }

    /// Allocate `size` bytes of guest RAM and map it at `base`.
    pub(crate) fn add_memory(&mut self, base: u64, size: u64) -> Result<(), Error> {
        let vm = VirtualMachineStaticInstance::get_gic().ok_or(Error::NoVm)?;
        let mut mem = vm.memory_create(size as usize)?;
        mem.map(base, MemPerms::ReadWriteExec)?;
        self.regions.push(Region { base, size, mem });
        Ok(())
    }

    /// Copy `data` into guest memory at `gpa` (used to load PMI sections).
    pub(crate) fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        let region = self
            .regions
            .iter_mut()
            .find(|r| gpa >= r.base && gpa + data.len() as u64 <= r.base + r.size)
            .ok_or(Error::UnmappedGuestAddr(gpa))?;
        region.mem.write(gpa, data)?;
        Ok(())
    }

    /// `(gpa, host_addr, size)` for every mapped guest-RAM region — used to
    /// build a `vm-memory` view so virtio-pci can walk queues/descriptors.
    pub(crate) fn region_mappings(&self) -> Vec<(u64, u64, u64)> {
        self.regions
            .iter()
            .map(|r| (r.base, r.mem.host_addr() as u64, r.size))
            .collect()
    }

    /// Reset the in-kernel GIC to its initial state — used for a warm in-VM
    /// reboot (Phase 2), so the new boot doesn't inherit pending IRQs /
    /// distributor state from the previous run.
    // Takes `&self` for API clarity (it resets *this* VM's GIC); the GIC lives
    // in the process-global singleton, so the body reaches it directly.
    #[allow(clippy::unused_self)]
    pub(crate) fn reset_gic(&self) -> Result<(), Error> {
        let vm = VirtualMachineStaticInstance::get_gic().ok_or(Error::NoVm)?;
        vm.gic_reset()?;
        Ok(())
    }
}

/// A shareable keepalive for this exact VM, captured before owner dispatch.
pub(crate) type NativeVm = VirtualMachineInstance<GicEnabled>;

/// Inject a message-based MSI into the GIC without a `Vm` reference — uses the
/// process-global singleton, so a device worker thread can call it (the message
/// `Interrupt` closure). `address` is the guest-programmed MSI doorbell;
/// `intid` is the message data (the MBI SPI number).
pub(crate) fn send_msi(address: u64, intid: u32) -> Result<(), Error> {
    let vm = VirtualMachineStaticInstance::get_gic().ok_or(Error::NoVm)?;
    vm.gic_send_msi(address, intid)?;
    Ok(())
}

/// Assert/deassert a wired SPI through the in-kernel GIC, from any thread (the
/// virtio-mmio interrupt path). Mirrors [`send_msi`] for level-style wired IRQs.
pub(crate) fn set_spi(intid: u32, level: bool) -> Result<(), Error> {
    let vm = VirtualMachineStaticInstance::get_gic().ok_or(Error::NoVm)?;
    vm.gic_set_spi(intid, level)?;
    Ok(())
}

/// Decoded source/destination of an in-flight MMIO access, retained between a
/// `VmExit::MmioRead` and the caller's `complete_mmio_read`.
#[derive(Clone, Copy, Debug)]
struct PendingMmio {
    /// Destination GPR index for a read (`srt`); 31 = XZR (discard).
    srt: u8,
}

/// A single vCPU, bound to the thread that created it.
#[derive(Debug)]
pub(crate) struct Vcpu {
    admitted: dillo_machine::aarch64::AdmittedCpu,
    inner: AvVcpu,
    pending_mmio: Cell<Option<PendingMmio>>,
}

impl Vcpu {
    pub(crate) fn max_count() -> Result<u32, Error> {
        Ok(AvVcpu::get_max_count()?)
    }

    /// Inspect and consume the exact configuration on its future CPU owner,
    /// and admit the implemented architectural floor before owner readiness.
    pub(crate) fn prepare(vm: &NativeVm, profile: pmi::aarch64::Profile) -> Result<Self, Error> {
        use dillo_machine::aarch64::{AdmissionError, CpuSnapshot, Register};
        if profile != pmi::aarch64::Profile::V8_0 {
            return Err(AdmissionError::UnsupportedProfile(profile).into());
        }
        let config = VcpuConfig::new();
        let configured = config
            .get_feature_reg(FeatureReg::ID_AA64MMFR0_EL1)
            .map_err(|e| AdmissionError::Unavailable {
                register: Register::Mmfr0,
                reason: e.to_string(),
            })?;
        let configured_bits = dillo_machine::aarch64_pa_bits(configured)
            .ok_or_else(|| Error::Hv("reserved configured CPU PARange encoding".into()))?;
        // applevisor has a configuration CTR selector, but no native SysReg
        // discriminant for CTR. Retain this exact config's value, and realize
        // any trapped guest CTR read from the admitted immutable snapshot.
        let ctr = config.get_feature_reg(FeatureReg::CTR_EL0).map_err(|e| {
            AdmissionError::Unavailable {
                register: Register::Ctr,
                reason: e.to_string(),
            }
        })?;
        let inner = vm.vcpu_with_config(config)?;
        let snapshot = CpuSnapshot::capture(|register| {
            let native = match register {
                Register::Pfr0 => SysReg::ID_AA64PFR0_EL1,
                Register::Isar0 => SysReg::ID_AA64ISAR0_EL1,
                Register::Mmfr0 => SysReg::ID_AA64MMFR0_EL1,
                Register::Dfr0 => SysReg::ID_AA64DFR0_EL1,
                Register::Sctlr => SysReg::SCTLR_EL1,
                Register::Ctr => return Ok(ctr),
            };
            inner
                .get_sys_reg(native)
                .map_err(|e| AdmissionError::Unavailable {
                    register,
                    reason: e.to_string(),
                })
        })?;
        if dillo_machine::aarch64_pa_bits(snapshot.value(Register::Mmfr0)) != Some(configured_bits)
        {
            return Err(Error::Hv(
                "created CPU PARange differs from its inspected configuration".into(),
            ));
        }
        let admitted = snapshot.admit(profile)?;
        Ok(Self {
            inner,
            pending_mmio: Cell::new(None),
            admitted,
        })
    }

    /// Apply only the register values fixed by PMI's AArch64 vm contract.
    pub(crate) fn initialize_bsp(&self) -> Result<(), Error> {
        self.initialize_el1(0, 0)
    }

    /// PSCI CPU_ON supplies a guest-selected entry and context at EL1.
    pub(crate) fn initialize_secondary(&self, entry: u64, context: u64) -> Result<(), Error> {
        self.initialize_el1(entry, context)
    }

    fn initialize_el1(&self, entry: u64, context: u64) -> Result<(), Error> {
        for n in 0..=30 {
            self.inner
                .set_reg(gpr(n), if n == 0 { context } else { 0 })?;
        }
        self.inner.set_reg(Reg::PC, entry)?;
        self.inner.set_reg(Reg::CPSR, 0x3c5)?;
        self.inner.set_sys_reg(SysReg::SP_EL0, 0)?;
        self.inner.set_sys_reg(SysReg::SP_EL1, 0)?;
        let sctlr = self.inner.get_sys_reg(SysReg::SCTLR_EL1)?;
        self.inner.set_sys_reg(
            SysReg::SCTLR_EL1,
            sctlr & !((1 << 0) | (1 << 2) | (1 << 12) | (1 << 25)),
        )?;
        Ok(())
    }

    /// Set this vCPU's MPIDR_EL1 affinity (must be done before GIC redistributor
    /// resources are queried / vCPUs run).
    pub(crate) fn set_mpidr(&self, mpidr: u64) -> Result<(), Error> {
        self.inner.set_sys_reg(SysReg::MPIDR_EL1, mpidr)?;
        Ok(())
    }

    /// Bind logical affinity before asking HVF to realize its GIC redistributor.
    /// Native allocation handles do not encode logical CPU identity.
    pub(crate) fn prepare_affinity(&self, mpidr: u64) -> Result<(), Error> {
        self.set_mpidr(mpidr)?;
        if self.inner.get_sys_reg(SysReg::MPIDR_EL1)? != mpidr {
            return Err(Error::Hv(
                "created CPU did not retain its logical MPIDR".into(),
            ));
        }
        let redistributor = self.inner.get_redistributor_base()?;
        let typer = self
            .inner
            .get_redistributor_reg(applevisor::prelude::GicRedistributorReg::TYPER)?;
        let affinity = (mpidr & 0x00ff_ffff) | ((mpidr >> 8) & 0xff00_0000);
        if typer >> 32 != affinity {
            return Err(Error::Hv(
                "GIC redistributor affinity differs from logical CPU MPIDR".into(),
            ));
        }
        log::debug!(
            "HVF CPU affinity={mpidr:#x} native={} redistributor={redistributor:#x}",
            self.inner.id()
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn native_identity(&self) -> Result<(u64, u64, u64, u64), Error> {
        Ok((
            self.inner.id(),
            self.inner.get_sys_reg(SysReg::MPIDR_EL1)?,
            self.inner.get_redistributor_base()?,
            self.inner
                .get_redistributor_reg(applevisor::prelude::GicRedistributorReg::TYPER)?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn read_register(&self, register: Reg) -> Result<u64, Error> {
        Ok(self.inner.get_reg(register)?)
    }

    /// Snapshot the guest's EL1 exception state `(ESR_EL1, ELR_EL1, FAR_EL1)`.
    /// After a stage-2 fault at the (unmapped) EL1 vector, these still hold the
    /// *original* in-guest exception that vectored there — the real diagnostic.
    pub(crate) fn el1_exception_state(&self) -> (u64, u64, u64) {
        let esr = self.inner.get_sys_reg(SysReg::ESR_EL1).unwrap_or(0);
        let elr = self.inner.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
        let far = self.inner.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);
        (esr, elr, far)
    }

    /// Write a general-purpose register x0..x30.
    pub(crate) fn set_gpr(&self, n: u8, value: u64) -> Result<(), Error> {
        self.inner.set_reg(gpr(n), value)?;
        Ok(())
    }

    /// A `Send`/`Sync` handle to this vCPU, usable from other threads only to
    /// force it out of `run()` through the bound VM.
    pub(crate) fn handle(&self) -> VcpuHandle {
        self.inner.get_handle()
    }

    /// Run until the next exit that the caller must handle, returning a
    /// decoded [`VmExit`]. Admission-relevant system-register reads preserve
    /// the admitted values. Other trapped registers retain the existing
    /// read-as-zero/write-ignored fallback.
    pub(crate) fn run(
        &self,
        termination: &dyn dillo_machine::CpuTermination,
    ) -> Result<VmExit, Error> {
        loop {
            if termination.is_requested() {
                return Ok(VmExit::Interrupted);
            }
            self.inner.run()?;
            let exit = self.inner.get_exit_info();
            // The virtual timer fired. HVF delivers the timer PPI to the
            // in-kernel GIC; we mask the vtimer so it does not immediately
            // re-assert on resume, and continue. The guest re-arms it by
            // writing CNTV_* after servicing the IRQ.
            if exit.reason == ExitReason::VTIMER_ACTIVATED {
                self.inner.set_vtimer_mask(true)?;
                continue;
            }
            if exit.reason == ExitReason::EXCEPTION && (exit.exception.syndrome >> 26) == 0x18 {
                self.handle_sysreg_trap(exit.exception.syndrome)?;
                continue;
            }
            return self.translate(&exit);
        }
    }

    /// Realize admitted ID reads and live SCTLR reads after an EC=0x18 trap.
    /// Unrelated registers retain the existing RAZ/WI fallback.
    fn handle_sysreg_trap(&self, esr: u64) -> Result<(), Error> {
        let iss = esr & 0x1FF_FFFF;
        let is_read = iss & 1 == 1; // ISS[0]: 0=MSR(write), 1=MRS(read)
        if is_read {
            let rt = ((iss >> 5) & 0x1F) as u8; // ISS[9:5]
            if rt != 31 {
                use dillo_machine::aarch64::Register;
                let encoding = (((iss >> 20) & 3) << 14)
                    | (((iss >> 14) & 7) << 11)
                    | (((iss >> 10) & 15) << 7)
                    | (((iss >> 1) & 15) << 3)
                    | ((iss >> 17) & 7);
                let value = match Register::from_encoding(encoding as u16) {
                    // SCTLR is mutable guest control state, not an ID register.
                    Some(Register::Sctlr) => self.inner.get_sys_reg(SysReg::SCTLR_EL1)?,
                    Some(register) => self.admitted.value(register),
                    None => 0,
                };
                self.inner.set_reg(gpr(rt), value)?;
            }
        }
        self.advance_pc()
    }

    /// Complete an [`VmExit::MmioRead`] by writing the bus-provided value into
    /// the destination register and advancing past the load instruction.
    pub(crate) fn complete_mmio_read(&self, value: u64) -> Result<(), Error> {
        if let Some(p) = self.pending_mmio.take()
            && p.srt != 31
        {
            self.inner.set_reg(gpr(p.srt), value)?;
        }
        self.advance_pc()
    }

    /// Advance PC past the current (trapping) instruction.
    pub(crate) fn advance_pc(&self) -> Result<(), Error> {
        let pc = self.inner.get_reg(Reg::PC)?;
        self.inner.set_reg(Reg::PC, pc.wrapping_add(INSN_LEN))?;
        Ok(())
    }

    fn translate(&self, exit: &VcpuExit) -> Result<VmExit, Error> {
        if exit.reason == ExitReason::CANCELED {
            return Ok(VmExit::Interrupted);
        }
        if exit.reason != ExitReason::EXCEPTION {
            return Ok(VmExit::Unknown(format!(
                "hvf exit reason {:?}",
                exit.reason
            )));
        }
        let esr = exit.exception.syndrome;
        let ec = esr >> 26;
        match ec {
            // HVC from EL1. ELR already points past the HVC.
            0x16 => {
                let mut args = [0u64; 8];
                for (i, a) in args.iter_mut().enumerate() {
                    *a = self.inner.get_reg(gpr(i as u8))?;
                }
                Ok(VmExit::Hvc { args })
            }
            // SMC from EL1.
            0x17 => {
                let mut args = [0u64; 8];
                for (i, a) in args.iter_mut().enumerate() {
                    *a = self.inner.get_reg(gpr(i as u8))?;
                }
                Ok(VmExit::Smc { args })
            }
            // Data abort from a lower EL → MMIO. IPA in physical_address.
            0x24 => self.translate_mmio(esr, exit.exception.physical_address),
            // Trapped WFI/WFE. Advance past it and report Halted.
            0x01 => {
                self.advance_pc()?;
                Ok(VmExit::Halted)
            }
            _ => Ok(VmExit::Unknown(format!(
                "hvf exception EC={ec:#x} ESR={esr:#x} FAR={:#x} IPA={:#x}",
                exit.exception.virtual_address, exit.exception.physical_address
            ))),
        }
    }

    fn translate_mmio(&self, esr: u64, ipa: u64) -> Result<VmExit, Error> {
        // ISS layout for a Data Abort with a valid syndrome (ISV=1):
        //   SAS [23:22] size, SRT [20:16] reg, WnR [6] write.
        let isv = (esr >> 24) & 1;
        if isv == 0 {
            return Ok(VmExit::Unknown(format!(
                "hvf data abort without valid syndrome (ESR={esr:#x}, IPA={ipa:#x})"
            )));
        }
        let sas = (esr >> 22) & 0b11;
        let size = 1u8 << sas; // 1,2,4,8 bytes
        let srt = ((esr >> 16) & 0x1f) as u8;
        let is_write = (esr >> 6) & 1 == 1;

        if is_write {
            let value = if srt == 31 {
                0
            } else {
                self.inner.get_reg(gpr(srt))?
            };
            // Writes advance PC immediately (no completion step).
            self.advance_pc()?;
            Ok(VmExit::MmioWrite {
                addr: ipa,
                data: value.to_le_bytes(),
                size,
            })
        } else {
            self.pending_mmio.set(Some(PendingMmio { srt }));
            Ok(VmExit::MmioRead { addr: ipa, size })
        }
    }
}

/// Map a GPR index (0..=30) to the corresponding `applevisor::Reg`.
fn gpr(n: u8) -> Reg {
    match n {
        0 => Reg::X0,
        1 => Reg::X1,
        2 => Reg::X2,
        3 => Reg::X3,
        4 => Reg::X4,
        5 => Reg::X5,
        6 => Reg::X6,
        7 => Reg::X7,
        8 => Reg::X8,
        9 => Reg::X9,
        10 => Reg::X10,
        11 => Reg::X11,
        12 => Reg::X12,
        13 => Reg::X13,
        14 => Reg::X14,
        15 => Reg::X15,
        16 => Reg::X16,
        17 => Reg::X17,
        18 => Reg::X18,
        19 => Reg::X19,
        20 => Reg::X20,
        21 => Reg::X21,
        22 => Reg::X22,
        23 => Reg::X23,
        24 => Reg::X24,
        25 => Reg::X25,
        26 => Reg::X26,
        27 => Reg::X27,
        28 => Reg::X28,
        29 => Reg::X29,
        _ => Reg::X30,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Each native test runs in its own entitled process because HVF owns a
    /// process-wide VM singleton. The directory outlives the reaped child.
    pub(crate) struct SignedNativeTest {
        child: std::process::Child,
        _directory: tempfile::TempDir,
    }

    impl SignedNativeTest {
        pub(crate) fn spawn(name: &str) -> Self {
            let directory = tempfile::tempdir().expect("create native-test directory");
            let executable = directory.path().join("hvf-native-test");
            std::fs::copy(
                std::env::current_exe().expect("current test executable"),
                &executable,
            )
            .expect("copy native test executable");
            let entitlements = directory.path().join("hypervisor.plist");
            std::fs::write(&entitlements, r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>"#)
                .expect("write native test entitlements");
            let signed = std::process::Command::new("codesign")
                .args(["--force", "--sign", "-", "--entitlements"])
                .arg(&entitlements)
                .arg(&executable)
                .status()
                .expect("run codesign");
            assert!(
                signed.success(),
                "HVF native tests require hypervisor entitlement signing"
            );
            let child = std::process::Command::new(&executable)
                .args([name, "--exact", "--nocapture", "--test-threads=1"])
                .env("DILLO_SIGNED_HVF_BSP_TEST", "1")
                .spawn()
                .expect("start entitled native test");
            Self {
                child,
                _directory: directory,
            }
        }

        pub(crate) fn verify(mut self) {
            use wait_timeout::ChildExt;
            let status = self
                .child
                .wait_timeout(std::time::Duration::from_secs(60))
                .expect("wait for entitled native test")
                .expect("HVF native test exceeded 60 seconds");
            assert!(
                status.success(),
                "entitled HVF native state assertions failed: {status}"
            );
        }
    }

    impl Drop for SignedNativeTest {
        fn drop(&mut self) {
            // Child::drop does not retire a process. Kill and reap before the
            // executable and entitlement directory can be reclaimed.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn hvf_admitted_owner_matches_guest_mrs_and_trap_reads() {
        use dillo_machine::aarch64::Register;
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            SignedNativeTest::spawn(
                "hypervisor::tests::hvf_admitted_owner_matches_guest_mrs_and_trap_reads",
            )
            .verify();
            return;
        }
        let gic = GicParams {
            dist_base: 0x0800_0000,
            redist_base: 0x0810_0000,
            msi_base: 0x0a10_0000,
            msi_intid_base: 64,
            msi_intid_count: 32,
        };
        let mut vm = Vm::new(&gic, 36).expect("native HVF/GIC is required");
        vm.add_memory(0, 0x4000).unwrap();
        let inputs = [
            (Register::Pfr0, 0xd538_0400u32),
            (Register::Isar0, 0xd538_0600),
            (Register::Mmfr0, 0xd538_0700),
            (Register::Dfr0, 0xd538_0500),
            (Register::Ctr, 0xd53b_0020),
            (Register::Sctlr, 0xd538_1000),
        ];
        let mut code = Vec::new();
        for (index, (_, instruction)) in inputs.iter().enumerate() {
            code.extend_from_slice(&instruction.to_le_bytes());
            code.extend_from_slice(&(0xf900_0020 | ((index as u32) << 10)).to_le_bytes());
        }
        code.extend_from_slice(&0xf900_0040u32.to_le_bytes());
        vm.write_guest(0, &code).unwrap();
        let native = vm.cpu_instance();
        let admitted = std::thread::spawn(move || {
            let cpu =
                Vcpu::prepare(&native, pmi::aarch64::Profile::V8_0).expect("admit retained owner");
            cpu.prepare_affinity(0x8000_0000).unwrap();
            cpu.initialize_bsp().unwrap();
            cpu.set_gpr(1, 0x1000).unwrap();
            cpu.set_gpr(2, 0x2_0000).unwrap();
            let exit = cpu.run(&std::sync::atomic::AtomicBool::new(false)).unwrap();
            assert!(
                matches!(
                    exit,
                    VmExit::MmioWrite {
                        addr: 0x2_0000,
                        size: 8,
                        ..
                    }
                ),
                "{exit:?}"
            );
            // Native API readback and an explicit decoder exercise complement
            // the real guest MRS path, regardless of which IDs HVF traps.
            for (register, instruction) in inputs {
                let op = instruction >> 5;
                let iss = (((op >> 14) & 3) << 20)
                    | ((op & 7) << 17)
                    | (((op >> 11) & 7) << 14)
                    | (((op >> 7) & 15) << 10)
                    | (((op >> 3) & 15) << 1)
                    | (3 << 5)
                    | 1;
                cpu.handle_sysreg_trap((0x18 << 26) | u64::from(iss))
                    .unwrap();
                let expected = if register == Register::Sctlr {
                    cpu.inner.get_sys_reg(SysReg::SCTLR_EL1).unwrap()
                } else {
                    cpu.admitted.value(register)
                };
                assert_eq!(
                    cpu.inner.get_reg(Reg::X3).unwrap(),
                    expected,
                    "trapped {}",
                    register.name()
                );
            }
            cpu.admitted.clone()
        })
        .join()
        .unwrap();
        let mut bytes = [0; 48];
        vm.regions[0].mem.read(0x1000, &mut bytes).unwrap();
        for (index, (register, _)) in inputs.into_iter().enumerate() {
            let value = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
            // Admission uses only SCTLR's fixed-endian capability bits. BSP
            // initialization may change its other guest-control bits.
            let mask = if register == Register::Sctlr {
                0x0300_0000
            } else {
                u64::MAX
            };
            assert_eq!(
                value & mask,
                admitted.value(register) & mask,
                "guest MRS {}",
                register.name()
            );
        }
    }

    #[test]
    fn hvf_fixed_bsp_state_matches_pmi_and_preserves_guest_ap() {
        const GPRS: [Reg; 31] = [
            Reg::X0,
            Reg::X1,
            Reg::X2,
            Reg::X3,
            Reg::X4,
            Reg::X5,
            Reg::X6,
            Reg::X7,
            Reg::X8,
            Reg::X9,
            Reg::X10,
            Reg::X11,
            Reg::X12,
            Reg::X13,
            Reg::X14,
            Reg::X15,
            Reg::X16,
            Reg::X17,
            Reg::X18,
            Reg::X19,
            Reg::X20,
            Reg::X21,
            Reg::X22,
            Reg::X23,
            Reg::X24,
            Reg::X25,
            Reg::X26,
            Reg::X27,
            Reg::X28,
            Reg::X29,
            Reg::X30,
        ];
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            SignedNativeTest::spawn(
                "hypervisor::tests::hvf_fixed_bsp_state_matches_pmi_and_preserves_guest_ap",
            )
            .verify();
            return;
        }
        let gic = GicParams {
            dist_base: 0x0800_0000,
            redist_base: 0x0810_0000,
            msi_base: 0x0a10_0000,
            msi_intid_base: 64,
            msi_intid_count: 32,
        };
        let vm = Vm::new(&gic, 36).expect("native HVF/GIC support is required");
        let ap_vm = vm.cpu_instance();
        std::thread::scope(|scope| {
            // Hypervisor.framework permits only one vCPU per owner thread.
            let (ready, prepared) = std::sync::mpsc::sync_channel(0);
            let (release, finished) = std::sync::mpsc::sync_channel(0);
            let ap_owner = scope.spawn(move || {
                let ap = Vcpu::prepare(&ap_vm, pmi::aarch64::Profile::V8_0)
                    .expect("create AP on its owner thread");
                ap.prepare_affinity(0x8000_0001)
                    .expect("set guest AP affinity");
                let (_, mpidr, redistributor, typer) = ap.native_identity().unwrap();
                assert_eq!(mpidr, 0x8000_0001);
                assert_eq!(typer >> 32, 1);
                assert!(redistributor >= gic.redist_base);
                ap.initialize_secondary(0x4000_0000, 0x77)
                    .expect("guest-directed PSCI entry");
                ready.send(()).expect("announce AP prepared");
                finished.recv().expect("BSP assertions completed");
                assert_eq!(ap.inner.get_reg(Reg::PC).unwrap(), 0x4000_0000);
                assert_eq!(ap.inner.get_reg(Reg::X0).unwrap(), 0x77);
                assert_eq!(ap.inner.get_reg(Reg::CPSR).unwrap(), 0x3c5);
            });
            prepared.recv().expect("AP preparation succeeds");
            let bsp = Vcpu::prepare(&vm.cpu_instance(), pmi::aarch64::Profile::V8_0)
                .expect("create BSP on its owner thread");
            bsp.prepare_affinity(0x8000_0000)
                .expect("set logical BSP affinity");
            let (_, mpidr, redistributor, typer) = bsp.native_identity().unwrap();
            assert_eq!(mpidr, 0x8000_0000);
            assert_eq!(typer >> 32, 0);
            assert!(redistributor >= gic.redist_base);
            for register in GPRS {
                bsp.inner.set_reg(register, 0x55).expect("seed BSP GPR");
            }
            bsp.inner.set_reg(Reg::PC, 0x8000).expect("seed BSP PC");
            bsp.inner
                .set_reg(Reg::CPSR, 0xf000_03c5)
                .expect("seed BSP PSTATE");
            bsp.inner
                .set_sys_reg(SysReg::SP_EL0, 0x1000)
                .expect("seed SP_EL0");
            bsp.inner
                .set_sys_reg(SysReg::SP_EL1, 0x2000)
                .expect("seed SP_EL1");
            let sctlr = bsp
                .inner
                .get_sys_reg(SysReg::SCTLR_EL1)
                .expect("read SCTLR");
            bsp.inner
                .set_sys_reg(SysReg::SCTLR_EL1, sctlr | 0x0200_1005)
                .expect("seed SCTLR");
            bsp.initialize_bsp().expect("program full fixed BSP state");
            for register in GPRS {
                assert_eq!(bsp.inner.get_reg(register).unwrap(), 0, "{register:?}");
            }
            assert_eq!(bsp.inner.get_reg(Reg::PC).unwrap(), 0);
            assert_eq!(bsp.inner.get_reg(Reg::CPSR).unwrap(), 0x3c5);
            assert_eq!(bsp.inner.get_sys_reg(SysReg::SP_EL0).unwrap(), 0);
            assert_eq!(bsp.inner.get_sys_reg(SysReg::SP_EL1).unwrap(), 0);
            assert_eq!(
                bsp.inner.get_sys_reg(SysReg::SCTLR_EL1).unwrap() & 0x0200_1005,
                0
            );
            release.send(()).expect("release AP readback");
            ap_owner.join().expect("AP native state preserved");
        });
    }

    #[test]
    #[ignore = "requires a codesigned binary with com.apple.security.hypervisor; run via the codesigned harness with --ignored"]
    fn hvf_exit_decoding_roundtrip() {
        let gic = GicParams {
            dist_base: 0x0800_0000,
            redist_base: 0x0810_0000,
            msi_base: 0x0a10_0000,
            msi_intid_base: 64,
            msi_intid_count: 32,
        };
        let mut vm = Vm::new(&gic, 36).expect("vm new");
        let base = 0x4000_0000u64;
        let mmio = 0x0C10_0000u64; // unmapped IPA in the device band
        vm.add_memory(base, 0x1_0000).expect("add_memory");

        // hvc #0 ; ldr x1,[x2] ; str x1,[x2]
        let code: [u32; 3] = [0xd400_0002, 0xf940_0041, 0xf900_0041];
        let mut bytes = Vec::new();
        for w in code {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        vm.write_guest(base, &bytes).expect("write_guest");

        let vcpu =
            Vcpu::prepare(&vm.cpu_instance(), pmi::aarch64::Profile::V8_0).expect("create_vcpu");
        let termination = std::sync::atomic::AtomicBool::new(false);

        // 1) HVC.
        vcpu.initialize_secondary(base, 0).expect("state");
        let e = vcpu.run(&termination).expect("run hvc");
        eprintln!("exit 1 (expect Hvc): {e:?}");
        assert!(matches!(e, VmExit::Hvc { .. }), "expected Hvc, got {e:?}");

        // 2) Faulting load from an unmapped IPA → MmioRead (64-bit → size 8).
        vcpu.initialize_secondary(base + 4, 0).expect("state");
        vcpu.set_gpr(2, mmio).expect("x2");
        let e = vcpu.run(&termination).expect("run ldr");
        eprintln!("exit 2 (expect MmioRead): {e:?}");
        match e {
            VmExit::MmioRead { addr, size } => {
                assert_eq!(addr, mmio, "MMIO read IPA");
                assert_eq!(size, 8, "ldr x1 is 64-bit");
            }
            other => panic!("expected MmioRead, got {other:?}"),
        }
        vcpu.complete_mmio_read(0).expect("complete read");

        // 3) Faulting store → MmioWrite carrying the source register's value.
        vcpu.initialize_secondary(base + 8, 0).expect("state");
        vcpu.set_gpr(1, 0xDEAD_BEEF_u64).expect("x1");
        vcpu.set_gpr(2, mmio).expect("x2");
        let e = vcpu.run(&termination).expect("run str");
        eprintln!("exit 3 (expect MmioWrite): {e:?}");
        match e {
            VmExit::MmioWrite { addr, data, size } => {
                assert_eq!(addr, mmio, "MMIO write IPA");
                assert_eq!(size, 8, "str x1 is 64-bit");
                assert_eq!(u64::from_le_bytes(data), 0xDEAD_BEEF, "write data = x1");
            }
            other => panic!("expected MmioWrite, got {other:?}"),
        }
    }
}
