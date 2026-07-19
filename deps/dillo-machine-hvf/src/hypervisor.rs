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
//!   - a vCPU is bound to its creating thread, so [`Vm::create_vcpu`] is
//!     called from each vCPU thread;
//!   - exits arrive as synchronous exceptions; EC = `ESR >> 26`
//!     (HVC `0x16`, data-abort/MMIO `0x24`, WFI `0x01`).

use std::cell::Cell;

use applevisor::prelude::{
    ExitReason, GicConfig, MemPerms, Memory, Reg, SysReg, Vcpu as AvVcpu, VcpuExit, VcpuHandle,
    VirtualMachineConfig, VirtualMachineStaticInstance,
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

/// The per-process HVF virtual machine. Owns the guest-memory mappings; the
/// VM/GIC themselves live in the `applevisor` process-global singleton.
#[derive(Debug)]
pub(crate) struct Vm {
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
        if max_ipa < min_addr_space_bits {
            return Err(Error::Hv(format!(
                "host max IPA {max_ipa} bits < image requires {min_addr_space_bits} bits \
                 (--min-addr-space); cannot launch on this host"
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
            regions: Vec::new(),
        })
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

/// Create a vCPU bound to the **current** thread, without borrowing the `Vm`.
///
/// A `Vcpu` is `!Send` (bound to its creating thread), so each vCPU thread must
/// create its own. The VM + GIC live in the process-global singleton, so this
/// needs no `Vm` reference — which lets the SMP launcher keep the (non-`Sync`)
/// `Vm` and its memory mappings on the main thread while worker threads each
/// create and run their own vCPU.
pub(crate) fn create_vcpu_current_thread() -> Result<Vcpu, Error> {
    let vm = VirtualMachineStaticInstance::get_gic().ok_or(Error::NoVm)?;
    Ok(Vcpu {
        inner: vm.vcpu_create()?,
        pending_mmio: Cell::new(None),
    })
}

/// Force the given vCPUs out of their in-flight `run()` (used on shutdown to
/// kick running secondaries so their threads observe the shutdown flag).
pub(crate) fn force_vcpus_exit(handles: &[VcpuHandle]) -> Result<(), Error> {
    let vm = VirtualMachineStaticInstance::get_gic().ok_or(Error::NoVm)?;
    vm.vcpus_exit(handles)?;
    Ok(())
}

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
    inner: AvVcpu,
    pending_mmio: Cell<Option<PendingMmio>>,
}

impl Vcpu {
    /// Program the boot vCPU register state from the PMI `vm:vcpu` map.
    pub(crate) fn set_aarch64_state(
        &self,
        state: &pmi::vm::vcpu::aarch64::CpuState,
    ) -> Result<(), Error> {
        // General-purpose registers x0..x30.
        let gprs = [
            state.x0, state.x1, state.x2, state.x3, state.x4, state.x5, state.x6, state.x7,
            state.x8, state.x9, state.x10, state.x11, state.x12, state.x13, state.x14, state.x15,
            state.x16, state.x17, state.x18, state.x19, state.x20, state.x21, state.x22, state.x23,
            state.x24, state.x25, state.x26, state.x27, state.x28, state.x29, state.x30,
        ];
        for (n, &v) in gprs.iter().enumerate() {
            self.inner.set_reg(gpr(n as u8), v)?;
        }
        self.inner.set_reg(Reg::PC, state.pc)?;
        self.inner.set_reg(Reg::CPSR, state.pstate.get())?;
        self.inner.set_sys_reg(SysReg::SP_EL1, state.sp_el1)?;
        self.inner.set_sys_reg(SysReg::SCTLR_EL1, state.sctlr_el1)?;
        self.inner.set_sys_reg(SysReg::VBAR_EL1, state.vbar_el1)?;
        self.inner.set_sys_reg(SysReg::CPACR_EL1, state.cpacr_el1)?;
        self.inner.set_sys_reg(SysReg::TCR_EL1, state.tcr_el1)?;
        self.inner.set_sys_reg(SysReg::TTBR0_EL1, state.ttbr0_el1)?;
        self.inner.set_sys_reg(SysReg::TTBR1_EL1, state.ttbr1_el1)?;
        self.inner.set_sys_reg(SysReg::MAIR_EL1, state.mair_el1)?;
        Ok(())
    }

    /// Set this vCPU's MPIDR_EL1 affinity (must be done before GIC redistributor
    /// resources are queried / vCPUs run).
    pub(crate) fn set_mpidr(&self, mpidr: u64) -> Result<(), Error> {
        self.inner.set_sys_reg(SysReg::MPIDR_EL1, mpidr)?;
        Ok(())
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
    /// force it out of `run()` via [`force_vcpus_exit`].
    pub(crate) fn handle(&self) -> VcpuHandle {
        self.inner.get_handle()
    }

    /// Run until the next exit that the caller must handle, returning a
    /// decoded [`VmExit`]. Trapped system-register accesses (`EC=0x18`) are
    /// handled inline as RAZ/WI and the guest is resumed — HVF traps the
    /// debug/PMU/unimplemented sysregs the kernel probes during boot, and
    /// read-as-zero / write-ignored is the standard VMM treatment.
    pub(crate) fn run(&self) -> Result<VmExit, Error> {
        loop {
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

    /// RAZ/WI a trapped MSR/MRS (`EC=0x18`): for a read (`MRS`), write 0 into
    /// the destination GPR; for a write (`MSR`), ignore the value. Then step
    /// past the instruction so the guest makes progress.
    fn handle_sysreg_trap(&self, esr: u64) -> Result<(), Error> {
        let iss = esr & 0x1FF_FFFF;
        let is_read = iss & 1 == 1; // ISS[0]: 0=MSR(write), 1=MRS(read)
        if is_read {
            let rt = ((iss >> 5) & 0x1F) as u8; // ISS[9:5]
            if rt != 31 {
                self.inner.set_reg(gpr(rt), 0)?;
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
mod tests {
    use super::*;

    fn boot_state(pc: u64) -> pmi::vm::vcpu::aarch64::CpuState {
        pmi::vm::vcpu::aarch64::CpuState {
            pc,
            pstate: 0x3c5, // EL1h, DAIF masked
            sctlr_el1: 0,  // MMU off → flat IPA=VA
            ..Default::default()
        }
    }

    /// Runtime verification: a tiny guest (HVC → faulting load → faulting
    /// store) must produce the expected decoded `VmExit`s. This exercises
    /// vCPU register programming (`set_aarch64_state`/`set_gpr`), the run
    /// loop, ESR/ISS decoding, and MMIO write-data extraction.
    ///
    /// NB: WFI is intentionally NOT tested — with the in-kernel GIC enabled,
    /// `WFI` waits for an interrupt instead of trapping, so `hv_vcpu_run`
    /// blocks (correct arch behavior). PSCI SYSTEM_OFF uses HVC, not WFI.
    ///
    /// Requires a codesigned binary with `com.apple.security.hypervisor`.
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

        let vcpu = create_vcpu_current_thread().expect("create_vcpu");

        // 1) HVC.
        vcpu.set_aarch64_state(&boot_state(base)).expect("state");
        let e = vcpu.run().expect("run hvc");
        eprintln!("exit 1 (expect Hvc): {e:?}");
        assert!(matches!(e, VmExit::Hvc { .. }), "expected Hvc, got {e:?}");

        // 2) Faulting load from an unmapped IPA → MmioRead (64-bit → size 8).
        vcpu.set_aarch64_state(&boot_state(base + 4))
            .expect("state");
        vcpu.set_gpr(2, mmio).expect("x2");
        let e = vcpu.run().expect("run ldr");
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
        vcpu.set_aarch64_state(&boot_state(base + 8))
            .expect("state");
        vcpu.set_gpr(1, 0xDEAD_BEEF_u64).expect("x1");
        vcpu.set_gpr(2, mmio).expect("x2");
        let e = vcpu.run().expect("run str");
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
