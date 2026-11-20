// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! macOS / Hypervisor.framework backend (aarch64).
//!
//! Concrete `Vm` / `Vcpu` mirroring the KVM backend's role, built on the
//! `applevisor` safe wrapper. HVF specifics (proven empirically in the Phase-0
//! spike, see TODO.md):
//!   - one native VM per process, with the GIC configured before any vCPU;
//!   - in-kernel GICv3 with **message-based** MSI (no ITS): inject via
//!     `gic_send_msi` (message interrupt) / `gic_set_spi` (wired, e.g. the serial UART);
//!   - a vCPU is bound to its creating thread, so [`Vm::create_vcpu`] is
//!     called from each vCPU thread;
//!   - exits arrive as synchronous exceptions; EC = `ESR >> 26`
//!     (HVC `0x16`, data-abort/MMIO `0x24`, WFI `0x01`).

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use applevisor::prelude::{
    ExitReason, FeatureReg, GicConfig, GicEnabled, HypervisorError, Reg, SysReg, Vcpu as AvVcpu,
    VcpuConfig, VcpuExit, VcpuHandle, VirtualMachine, VirtualMachineConfig, VirtualMachineInstance,
};

use dillo_devtree::platform::PsciMethod;
use dillo_machine::RamRange;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

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
    #[error("hvf: guest used {actual:?} while /psci declares {declared:?}")]
    UnexpectedPsciConduit {
        actual: PsciMethod,
        declared: PsciMethod,
    },
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

impl From<HypervisorError> for Error {
    fn from(e: HypervisorError) -> Self {
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

static PROCESS_OCCUPIED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
struct ProcessReservation;

impl ProcessReservation {
    fn acquire() -> Result<Self, Error> {
        PROCESS_OCCUPIED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Hv("HVF process already has a native VM owner".into()))?;
        Ok(Self)
    }
}

impl Drop for ProcessReservation {
    fn drop(&mut self) {
        PROCESS_OCCUPIED.store(false, Ordering::Release);
    }
}

#[derive(Debug, Default)]
enum RamRegistration {
    #[default]
    Empty,
    Attempted {
        _backing: GuestMemoryMmap,
    },
    Ready(GuestMemoryMmap),
}

#[derive(Debug)]
struct NativeVm {
    owner: Option<(VirtualMachineInstance<GicEnabled>, ProcessReservation)>,
    ram: Mutex<RamRegistration>,
}

fn retire<Gic>(
    instance: VirtualMachineInstance<Gic>,
    ram: RamRegistration,
    reservation: ProcessReservation,
) -> Result<(), HypervisorError> {
    match instance.try_destroy() {
        Ok(()) => Ok(()),
        Err((instance, error)) => {
            // Retirement is uncertain. Keep the native owner, RAM and process
            // slot together until process exit. Dropping the returned instance
            // would make an unchecked second attempt.
            std::mem::forget((instance, ram, reservation));
            Err(error)
        }
    }
}

impl NativeVm {
    fn try_retire(&mut self) -> Result<(), HypervisorError> {
        let Some((instance, reservation)) = self.owner.take() else {
            return Ok(());
        };
        let ram = self
            .ram
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retire(instance, std::mem::take(ram), reservation)
    }

    fn register_memory(
        &self,
        ranges: &[RamRange],
        #[cfg(test)] fail_at: Option<u64>,
    ) -> Result<(), Error> {
        let mut ram = self
            .ram
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*ram, RamRegistration::Empty) {
            return Err(Error::Hv(
                "RAM registration is already complete or failed".into(),
            ));
        }
        let page = applevisor_sys::PAGE_SIZE as u64;
        let ranges = ranges
            .iter()
            .map(|range| {
                if range.size == 0
                    || !range.gpa.is_multiple_of(page)
                    || !range.size.is_multiple_of(page)
                {
                    return Err(Error::Hv(
                        "HVF RAM requires nonempty, page-aligned extents".into(),
                    ));
                }
                let size = usize::try_from(range.size)
                    .map_err(|_| Error::Hv("HVF RAM extent exceeds host address size".into()))?;
                Ok((GuestAddress(range.gpa), size))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let backing = GuestMemoryMmap::from_ranges(&ranges)
            .map_err(|error| Error::Hv(format!("allocate HVF RAM: {error}")))?;
        // Publish the owning views before any native map. Retain all attempted
        // ranges on failure, including the one whose call returned an error.
        *ram = RamRegistration::Attempted {
            _backing: backing.clone(),
        };
        for region in backing.iter() {
            let gpa = region.start_addr().raw_value();
            #[cfg(test)]
            if fail_at == Some(gpa) {
                return Err(Error::Hv("injected HVF map failure".into()));
            }
            // SAFETY: Each region is an owned page-aligned mmap. The native
            // VM owner retains it until checked retirement succeeds.
            #[allow(unsafe_code)]
            let result = unsafe {
                applevisor_sys::hv_vm_map(
                    region.as_ptr().cast(),
                    gpa,
                    region.size(),
                    applevisor_sys::HV_MEMORY_READ
                        | applevisor_sys::HV_MEMORY_WRITE
                        | applevisor_sys::HV_MEMORY_EXEC,
                )
            };
            if result != 0 {
                return Err(Error::Hv(format!(
                    "map HVF RAM at {gpa:#x}: {}",
                    HypervisorError::from(result)
                )));
            }
        }
        *ram = RamRegistration::Ready(backing);
        Ok(())
    }
}

impl Drop for NativeVm {
    fn drop(&mut self) {
        if let Err(error) = self.try_retire() {
            log::error!("HVF VM retirement failed, retaining VM and RAM: {error}");
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Vm(Arc<NativeVm>);

impl Vm {
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

        let reservation = ProcessReservation::acquire()?;
        let instance = VirtualMachine::with_config(vm_config)?;
        let instance = match instance.enable_gic(g) {
            Ok(instance) => instance,
            Err((instance, setup_error)) => {
                if let Err(retirement_error) = retire(instance, RamRegistration::Empty, reservation)
                {
                    return Err(Error::Hv(format!(
                        "create GIC: {setup_error}; VM retirement failed: {retirement_error}"
                    )));
                }
                return Err(setup_error.into());
            }
        };
        Ok(Self(Arc::new(NativeVm {
            owner: Some((instance, reservation)),
            ram: Mutex::new(RamRegistration::Empty),
        })))
    }

    fn instance(&self) -> &VirtualMachineInstance<GicEnabled> {
        let (instance, _) = self.0.owner.as_ref().expect("native HVF owner");
        instance
    }

    /// Register initial RAM while construction still owns the only native handle.
    pub(crate) fn with_memory(mut self, ranges: &[RamRange]) -> Result<Self, Error> {
        let native = Arc::get_mut(&mut self.0)
            .ok_or_else(|| Error::Hv("initial RAM requires exclusive HVF VM ownership".into()))?;
        if let Err(map_error) = native.register_memory(
            ranges,
            #[cfg(test)]
            None,
        ) {
            return match native.try_retire() {
                Ok(()) => Err(map_error),
                Err(retirement_error) => Err(Error::Hv(format!(
                    "initial RAM registration failed ({map_error}); VM retirement failed: {retirement_error}"
                ))),
            };
        }
        Ok(self)
    }

    #[cfg(test)]
    fn attach_memory(&self, ranges: &[RamRange]) -> Result<(), Error> {
        self.0.register_memory(
            ranges,
            #[cfg(test)]
            None,
        )
    }

    pub(crate) fn guest_memory(&self) -> Result<GuestMemoryMmap, Error> {
        match &*self
            .0
            .ram
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            RamRegistration::Ready(backing) => Ok(backing.clone()),
            _ => Err(Error::Hv("HVF RAM registration is incomplete".into())),
        }
    }

    pub(crate) fn write_guest(&self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        let ram = self.guest_memory()?;
        let addr = GuestAddress(gpa);
        ram.find_region(addr)
            .filter(|region| {
                data.len() as u64 <= region.len() - (gpa - region.start_addr().raw_value())
            })
            .ok_or(Error::UnmappedGuestAddr(gpa))?;
        ram.write_slice(data, addr)
            .map_err(|error| Error::Hv(format!("write HVF RAM: {error}")))
    }

    pub(crate) fn reset_gic(&self) -> Result<(), Error> {
        Ok(self.instance().gic_reset()?)
    }

    pub(crate) fn create_vcpu_current_thread(&self) -> Result<Vcpu, Error> {
        self.guest_memory()?;
        self.create_vcpu()
    }

    fn create_vcpu(&self) -> Result<Vcpu, Error> {
        Ok(Vcpu {
            inner: self.instance().vcpu_create()?,
            pending_mmio: Cell::new(None),
            _vm: self.clone(),
        })
    }

    pub(crate) fn force_vcpus_exit(&self, handles: &[VcpuHandle]) -> Result<(), Error> {
        Ok(self.instance().vcpus_exit(handles)?)
    }

    pub(crate) fn send_msi(&self, address: u64, intid: u32) -> Result<(), Error> {
        Ok(self.instance().gic_send_msi(address, intid)?)
    }

    pub(crate) fn set_spi(&self, intid: u32, level: bool) -> Result<(), Error> {
        Ok(self.instance().gic_set_spi(intid, level)?)
    }
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
    // Destroy the native vCPU before releasing its VM.
    _vm: Vm,
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
    /// force it out of `run()` via [`Vm::force_vcpus_exit`].
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
            // HVC (0x16) and SMC (0x17) from EL1.
            0x16 | 0x17 => {
                let method = if ec == 0x16 {
                    PsciMethod::Hvc
                } else {
                    PsciMethod::Smc
                };
                let mut args = [0u64; 8];
                for (i, a) in args.iter_mut().enumerate() {
                    *a = self.inner.get_reg(gpr(i as u8))?;
                }
                Ok(VmExit::Smccc { method, args })
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

    static NATIVE_TESTS: Mutex<()> = Mutex::new(());
    const RAM_BASE: u64 = 0x4000_0000;
    const RAM_SIZE: u64 = 0x1_0000;

    fn gic() -> GicParams {
        GicParams {
            dist_base: 0x0800_0000,
            redist_base: 0x0810_0000,
            msi_base: 0x0a10_0000,
            msi_intid_base: 64,
            msi_intid_count: 32,
        }
    }

    fn boot_state(pc: u64) -> pmi::vm::vcpu::aarch64::CpuState {
        // aarch64 CpuState has no Default (PState is a validating newtype).
        pmi::vm::vcpu::aarch64::CpuState {
            pc,
            pstate: pmi::vm::vcpu::aarch64::PState::new(0x3c5).unwrap(), // EL1h, DAIF masked
            sctlr_el1: 0,                                                // MMU off → flat IPA=VA
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
            x7: 0,
            x8: 0,
            x9: 0,
            x10: 0,
            x11: 0,
            x12: 0,
            x13: 0,
            x14: 0,
            x15: 0,
            x16: 0,
            x17: 0,
            x18: 0,
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            x29: 0,
            x30: 0,
            sp_el1: 0,
            tcr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            mair_el1: 0,
            vbar_el1: 0,
            cpacr_el1: 0,
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
        let _native_test = NATIVE_TESTS.lock().unwrap();
        let base = RAM_BASE;
        let mmio = 0x0C10_0000u64; // unmapped IPA in the device band
        let malformed = Vm::new(&gic(), 36)
            .unwrap()
            .with_memory(&[RamRange {
                gpa: base + 1,
                size: RAM_SIZE,
            }])
            .expect_err("initial RAM must be page-aligned");
        assert!(malformed.to_string().contains("page-aligned"));
        let vm = Vm::new(&gic(), 36).unwrap();
        let ranges = [RamRange {
            gpa: base,
            size: RAM_SIZE,
        }];
        let shared = vm
            .clone()
            .with_memory(&ranges)
            .expect_err("initial RAM requires an exclusive owner");
        assert!(
            shared
                .to_string()
                .contains("requires exclusive HVF VM ownership")
        );
        let vm = vm
            .with_memory(&ranges)
            .expect("successful initial RAM registration after checked rollback");

        // hvc #0 ; ldr x1,[x2] ; str x1,[x2]
        let code: [u32; 3] = [0xd400_0002, 0xf940_0041, 0xf900_0041];
        let mut bytes = Vec::new();
        for w in code {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        vm.write_guest(base, &bytes).expect("write_guest");

        let exported = vm.guest_memory().unwrap();
        let vcpu = vm.create_vcpu_current_thread().expect("create_vcpu");
        drop(vm);

        // 1) HVC.
        vcpu.set_aarch64_state(&boot_state(base)).expect("state");
        let e = vcpu.run().expect("run hvc");
        eprintln!("exit 1 (expect Hvc): {e:?}");
        assert!(
            matches!(
                e,
                VmExit::Smccc {
                    method: PsciMethod::Hvc,
                    ..
                }
            ),
            "expected Hvc, got {e:?}"
        );

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
        drop(vcpu);
        Vm::new(&gic(), 36).expect("host export does not retain the native VM");
        let mut preserved = [0; 12];
        exported
            .read_slice(&mut preserved, GuestAddress(base))
            .unwrap();
        assert_eq!(bytes, preserved);
    }

    #[test]
    #[ignore = "requires a codesigned binary with com.apple.security.hypervisor"]
    fn hvf_partial_registration_preserves_first_native_map_until_retirement() {
        let _native_test = NATIVE_TESTS.lock().unwrap();
        let vm = Vm::new(&gic(), 36).unwrap();
        let later = RAM_BASE + RAM_SIZE;
        let result = vm.0.register_memory(
            &[
                RamRange {
                    gpa: RAM_BASE,
                    size: RAM_SIZE,
                },
                RamRange {
                    gpa: later,
                    size: RAM_SIZE,
                },
            ],
            Some(later),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected HVF map failure")
        );
        let pages: Vec<_> = {
            let ram = vm.0.ram.lock().unwrap();
            let RamRegistration::Attempted { _backing: backing } = &*ram else {
                panic!("attempted RAM was not retained");
            };
            backing
                .write_slice(&0xd400_0002u32.to_le_bytes(), GuestAddress(RAM_BASE))
                .unwrap();
            backing
                .iter()
                .map(|region| Arc::downgrade(&region.get_mmap()))
                .collect()
        };
        assert!(vm.guest_memory().is_err());
        assert!(vm.create_vcpu_current_thread().is_err());
        assert!(
            vm.attach_memory(&[RamRange {
                gpa: RAM_BASE,
                size: RAM_SIZE
            }])
            .is_err()
        );
        assert!(pages.iter().all(|page| page.upgrade().is_some()));

        // Bypass only the readiness check in this fixture to read the earlier
        // native map through a real guest instruction fetch.
        let cpu = vm.create_vcpu().unwrap();
        cpu.set_aarch64_state(&boot_state(RAM_BASE)).unwrap();
        drop(vm);
        assert!(matches!(
            cpu.run().unwrap(),
            VmExit::Smccc {
                method: PsciMethod::Hvc,
                ..
            }
        ));
        assert!(Vm::new(&gic(), 36).is_err());
        drop(cpu);
        assert!(pages.iter().all(|page| page.upgrade().is_none()));
        Vm::new(&gic(), 36).expect("native retirement allows a fresh VM");
    }

    #[test]
    #[ignore = "requires a codesigned binary with com.apple.security.hypervisor"]
    fn hvf_failed_retirement_keeps_backing_and_process_reservation() {
        // The failure leaves the VM process slot occupied until process exit.
        if !native_test_child(
            "hypervisor::tests::hvf_failed_retirement_keeps_backing_and_process_reservation",
        ) {
            return;
        }

        let vm = Vm::new(&gic(), 36).unwrap();
        vm.attach_memory(&[RamRange {
            gpa: RAM_BASE,
            size: RAM_SIZE,
        }])
        .unwrap();
        let backing = vm.guest_memory().unwrap();
        let witness = Arc::downgrade(&backing.iter().next().unwrap().get_mmap());
        drop(backing);
        // SAFETY: This process owns the VM exclusively, without any vCPUs.
        // Retire it behind the wrapper to force a real error on its next call.
        #[allow(unsafe_code)]
        let result = unsafe { applevisor_sys::hv_vm_destroy() };
        assert_eq!(result, 0);
        drop(vm);
        assert!(witness.upgrade().is_some());
        let error = Vm::new(&gic(), 36).unwrap_err();
        assert!(error.to_string().contains("already has a native VM owner"));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    #[ignore = "requires a codesigned binary with com.apple.security.hypervisor"]
    fn hvf_psci_uses_only_the_surveyed_conduit() {
        if native_test_child("hypervisor::tests::hvf_psci_uses_only_the_surveyed_conduit") {
            crate::imp::tests::check_psci_conduits(boot_state(RAM_BASE), RAM_SIZE);
        }
    }

    fn native_test_child(name: &str) -> bool {
        use std::process::Stdio;
        use std::time::Duration;
        use wait_timeout::ChildExt;

        const CHILD: &str = "DILLO_HVF_NATIVE_TEST_CHILD";
        if std::env::var_os(CHILD).as_deref() == Some(name.as_ref()) {
            return true;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", name])
            .env(CHILD, name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let finished = child.wait_timeout(Duration::from_secs(15));
        if !matches!(finished, Ok(Some(_))) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{name} did not complete: {finished:?}");
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }
}
