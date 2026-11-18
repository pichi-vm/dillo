// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! macOS / Hypervisor.framework backend (aarch64).
//!
//! Concrete `Vm` / `Vcpu` mirroring the KVM backend's role, built on the
//! `applevisor` safe wrapper. HVF specifics (proven empirically in the Phase-0
//! spike, see TODO.md):
//!   - one live VM per process, with reusable native ownership;
//!   - `hv_gic` must be configured before any vCPU is created — so
//!     [`Vm::new`] constructs the VM and GIC together;
//!   - in-kernel GICv3 with **message-based** MSI (no ITS): inject via
//!     `gic_send_msi` (message interrupt) / `gic_set_spi` (wired, e.g. the serial UART);
//!   - a vCPU is bound to its creating thread, so [`Vcpu::prepare`] creates
//!     and retains it on each owner thread;
//!   - exits arrive as synchronous exceptions; EC = `ESR >> 26`
//!     (HVC `0x16`, data-abort/MMIO `0x24`, WFI `0x01`).

use std::cell::Cell;
use std::sync::{Arc, Mutex};

use applevisor::prelude::{
    ExitReason, FeatureReg, GicConfig, GicEnabled, Reg, SysReg, Vcpu as AvVcpu, VcpuConfig,
    VcpuExit, VcpuHandle, VirtualMachine, VirtualMachineConfig, VirtualMachineInstance,
};

use crate::VmExit;

/// Canonical aarch64 platform memmap (must match arma's base DTB; see
/// `arma/src/base_dtb/aarch64.rs` and TODO.md #10).
/// AArch64 instruction length (no 16-bit encodings).
const INSN_LEN: u64 = 4;

/// Base addresses and MSI ID range used by the native GICv3 setters.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GicParams {
    pub dist_base: u64,
    pub redist_base: u64,
    pub msi_base: u64,
    pub msi_intid_base: u32,
    pub msi_intid_count: u32,
}

impl GicParams {
    pub(crate) fn from_survey(
        declared: &dillo_devtree::platform::GicConfig,
    ) -> Result<Self, Error> {
        for (region, declared_size, required) in [
            (
                "GICD",
                declared.dist_size,
                GicConfig::get_distributor_size()?,
            ),
            (
                "GICR",
                declared.redist_size,
                GicConfig::get_redistributor_region_size()?,
            ),
            (
                "MSI",
                declared.msi_frame_size,
                GicConfig::get_msi_region_size()?,
            ),
        ] {
            let required = required as u64;
            if declared_size < required {
                return Err(Error::GicExtent {
                    region,
                    declared: declared_size,
                    required,
                });
            }
        }
        Ok(Self {
            dist_base: declared.dist_base,
            redist_base: declared.redist_base,
            msi_base: declared.msi_frame_base,
            msi_intid_base: declared.spi_base,
            msi_intid_count: declared.spi_count,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Arm CPU admission: {0}")]
    ArmAdmission(#[from] dillo_machine::aarch64::AdmissionError),
    #[error("hvf: {0}")]
    Hv(String),
    #[error("hvf: missing required DTB substrate {0}")]
    MissingSubstrate(&'static str),
    #[error("hvf: native {region} requires {required} bytes within the declared {declared} bytes")]
    GicExtent {
        region: &'static str,
        declared: u64,
        required: u64,
    },
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

/// A construction slot remains occupied until the native VM destructor returns.
/// HVF addresses a process VM, so a replacement cannot overlap its predecessor.
static PROCESS_OCCUPIED: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

#[derive(Debug)]
struct ProcessReservation;

impl ProcessReservation {
    fn acquire() -> Result<Self, Error> {
        let mut occupied = PROCESS_OCCUPIED.lock().expect("HVF process slot poisoned");
        if *occupied {
            return Err(Error::Hv(
                "HVF process already has a native VM owner".into(),
            ));
        }
        *occupied = true;
        Ok(Self)
    }
}

impl Drop for ProcessReservation {
    fn drop(&mut self) {
        *PROCESS_OCCUPIED.lock().expect("HVF process slot poisoned") = false;
    }
}

#[derive(Debug)]
enum RamRegistration {
    Empty,
    Attempted {
        backing: Arc<crate::memory::MappedMemory>,
        attempts: usize,
    },
    Ready(Arc<crate::memory::MappedMemory>),
}

#[derive(Debug)]
struct NativeVmOwner {
    // applevisor aborts if native VM destruction fails. This field must be
    // destroyed before registered RAM and before the process slot is reopened.
    native: VirtualMachineInstance<GicEnabled>,
    ram: Mutex<RamRegistration>,
    #[cfg(test)]
    fail_map_at: Mutex<Option<usize>>,
    _reservation: ProcessReservation,
}

/// Retains the actual native VM and registrations, rather than only applevisor's guard.
#[derive(Clone, Debug)]
pub(crate) struct NativeVm(Arc<NativeVmOwner>);

impl NativeVm {
    fn create(config: VirtualMachineConfig, gic: GicConfig) -> Result<Self, Error> {
        let reservation = ProcessReservation::acquire()?;
        // with_gic rolls back partial construction through the same fail-closed
        // native destructor before the process reservation can be released.
        let native = VirtualMachine::with_gic(config, gic)?;
        Ok(Self(Arc::new(NativeVmOwner {
            native,
            ram: Mutex::new(RamRegistration::Empty),
            #[cfg(test)]
            fail_map_at: Mutex::new(None),
            _reservation: reservation,
        })))
    }

    fn gic(&self) -> &VirtualMachineInstance<GicEnabled> {
        &self.0.native
    }

    pub(crate) fn require_ram(&self) -> Result<(), Error> {
        let ram = self.0.ram.lock().expect("HVF RAM registration poisoned");
        match &*ram {
            RamRegistration::Ready(_) => Ok(()),
            RamRegistration::Empty => Err(Error::Hv(
                "RAM must be attached before CPU preparation".into(),
            )),
            RamRegistration::Attempted { attempts, backing } => Err(Error::Hv(format!(
                "RAM registration failed after {attempts}/{} attempted maps",
                backing.regions().len()
            ))),
        }
    }

    fn attach(&self, backing: Arc<crate::memory::MappedMemory>) -> Result<(), Error> {
        let mut ram = self.0.ram.lock().expect("HVF RAM registration poisoned");
        if !matches!(*ram, RamRegistration::Empty) {
            return Err(Error::Hv(
                "RAM registration cannot be replaced or enlarged".into(),
            ));
        }
        // Publish ownership before the first call, including failed/uncertain calls.
        *ram = RamRegistration::Attempted {
            backing: Arc::clone(&backing),
            attempts: 0,
        };
        for (index, region) in backing.regions().iter().enumerate() {
            if let RamRegistration::Attempted { attempts, .. } = &mut *ram {
                *attempts = index + 1;
            }
            #[cfg(test)]
            if *self.0.fail_map_at.lock().unwrap() == Some(index) {
                return Err(Error::Hv("injected hv_vm_map failure".into()));
            }
            // SAFETY: backing owns this complete page-aligned host VM region;
            // it remains in ram until the native VM destructor returns.
            #[allow(unsafe_code)]
            let result = unsafe {
                applevisor_sys::hv_vm_map(
                    region.address as *const libc::c_void,
                    region.gpa,
                    region.size as usize,
                    applevisor_sys::HV_MEMORY_READ
                        | applevisor_sys::HV_MEMORY_WRITE
                        | applevisor_sys::HV_MEMORY_EXEC,
                )
            };
            if result != 0 {
                return Err(Error::Hv(format!(
                    "hv_vm_map at {:#x}: {result:#x}",
                    region.gpa
                )));
            }
        }
        *ram = RamRegistration::Ready(backing);
        Ok(())
    }

    fn backing(&self) -> Result<Arc<crate::memory::MappedMemory>, Error> {
        match &*self.0.ram.lock().expect("HVF RAM registration poisoned") {
            RamRegistration::Ready(backing) => Ok(Arc::clone(backing)),
            RamRegistration::Attempted { .. } => {
                Err(Error::Hv("RAM registration is incomplete".into()))
            }
            RamRegistration::Empty => Err(Error::Hv("RAM is not attached".into())),
        }
    }

    fn vcpu_with_config(&self, config: VcpuConfig) -> Result<AvVcpu, Error> {
        self.require_ram()?;
        Ok(self.gic().vcpu_with_config(config)?)
    }

    pub(crate) fn vcpus_exit(&self, handles: &[VcpuHandle]) -> Result<(), Error> {
        Ok(self.gic().vcpus_exit(handles)?)
    }

    pub(crate) fn send_msi(&self, address: u64, intid: u32) -> Result<(), Error> {
        Ok(self.gic().gic_send_msi(address, intid)?)
    }

    pub(crate) fn set_spi(&self, intid: u32, level: bool) -> Result<(), Error> {
        Ok(self.gic().gic_set_spi(intid, level)?)
    }
}

/// Native machine authority. Host-only exported mappings need not retain this owner.
#[derive(Debug)]
pub(crate) struct Vm {
    native: NativeVm,
}

impl Vm {
    pub(crate) fn new(gic: &GicParams, min_addr_space_bits: u32) -> Result<Self, Error> {
        let mut config = VirtualMachineConfig::new();
        let max_ipa = VirtualMachineConfig::get_max_ipa_size()?;
        let available = guest_address_bits()?;
        if available < min_addr_space_bits {
            return Err(Error::Hv(format!(
                "launch requires {min_addr_space_bits} address bits; backend provides {available}"
            )));
        }
        config.set_ipa_size(max_ipa)?;
        let mut g = GicConfig::new();
        g.set_distributor_base(gic.dist_base)?;
        g.set_redistributor_base(gic.redist_base)?;
        g.set_msi_region_base(gic.msi_base)?;
        g.set_msi_interrupt_range(gic.msi_intid_base, gic.msi_intid_count)?;
        Ok(Self {
            native: NativeVm::create(config, g)?,
        })
    }

    pub(crate) fn cpu_instance(&self) -> NativeVm {
        self.native.clone()
    }

    pub(crate) fn attach(&self, backing: Arc<crate::memory::MappedMemory>) -> Result<(), Error> {
        self.native.attach(backing)
    }

    #[cfg(test)]
    pub(crate) fn add_memory(&mut self, base: u64, size: u64) -> Result<(), Error> {
        self.attach(Arc::new(crate::memory::MappedMemory::new(&[
            dillo_machine::RamRange { gpa: base, size },
        ])?))
    }

    #[cfg(test)]
    pub(crate) fn mapping_probe(&self, index: usize) -> crate::memory::MappingProbe {
        crate::memory::MappingProbe::new(&self.native.backing().unwrap(), index)
    }

    pub(crate) fn guest_memory(&self) -> Result<Arc<dillo_machine::memory::MappedRam>, Error> {
        Ok(self.native.backing()?.guest_memory())
    }

    pub(crate) fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        self.native.backing()?.write(gpa, data)
    }

    pub(crate) fn reset_gic(&self) -> Result<(), Error> {
        Ok(self.native.gic().gic_reset()?)
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
    admitted: dillo_machine::aarch64::AdmittedCpu,
    inner: AvVcpu,
    // Native CPU destruction precedes release of registered RAM and VM authority.
    _native: NativeVm,
    pending_mmio: Cell<Option<PendingMmio>>,
    // Guest emulation is separate from unavailable admission evidence.
    served_isar1: u64,
    served_mmfr2: u64,
    #[cfg(test)]
    require_native_operations: bool,
    #[cfg(test)]
    configured_mmfr1: u64,
    #[cfg(test)]
    configured_v82: [Result<u64, dillo_machine::aarch64::AdmissionError>; 2],
}

impl Vcpu {
    pub(crate) fn max_count() -> Result<u32, Error> {
        Ok(AvVcpu::get_max_count()?)
    }

    /// Inspect and consume the exact configuration on its future CPU owner,
    /// and admit the implemented architectural floor before owner readiness.
    pub(crate) fn prepare(vm: &NativeVm, profile: pmi::aarch64::Profile) -> Result<Self, Error> {
        use dillo_machine::aarch64::{AdmissionError, CpuSnapshot, Register};
        if !matches!(
            profile,
            pmi::aarch64::Profile::V8_0 | pmi::aarch64::Profile::V8_1 | pmi::aarch64::Profile::V8_2
        ) {
            return Err(AdmissionError::UnsupportedProfile(profile).into());
        }
        let config = VcpuConfig::new();
        #[cfg(test)]
        let configured_mmfr1 = config.get_feature_reg(FeatureReg::ID_AA64MMFR1_EL1)?;
        let configured_v82 = [
            (Register::Isar1, FeatureReg::ID_AA64ISAR1_EL1),
            (Register::Mmfr2, FeatureReg::ID_AA64MMFR2_EL1),
        ]
        .map(|(register, native)| {
            config
                .get_feature_reg(native)
                .map_err(|error| AdmissionError::Unavailable {
                    register,
                    reason: error.to_string(),
                })
        });
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
                Register::Isar1 => SysReg::ID_AA64ISAR1_EL1,
                Register::Mmfr2 => SysReg::ID_AA64MMFR2_EL1,
                Register::A32Mmfr4 => {
                    return Err(AdmissionError::Unavailable {
                        register,
                        reason: "native HVF binding has no AArch32 MMFR4 selector".into(),
                    });
                }
                Register::Mmfr0 => SysReg::ID_AA64MMFR0_EL1,
                Register::Mmfr1 => SysReg::ID_AA64MMFR1_EL1,
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
        if dillo_machine::aarch64_pa_bits(snapshot.value(Register::Mmfr0)?) != Some(configured_bits)
        {
            return Err(Error::Hv(
                "created CPU PARange differs from its inspected configuration".into(),
            ));
        }
        // Native/config values may serve optional baseline IDs even if one
        // API cannot read them. If neither can, preserve the earlier-profile
        // RAZ emulation. These values never replace failed admission evidence;
        // v8.2 requires successful retained native reads before construction.
        let served_isar1 = snapshot
            .value(Register::Isar1)
            .or_else(|_| configured_v82[0].clone())
            .unwrap_or(0);
        let served_mmfr2 = snapshot
            .value(Register::Mmfr2)
            .or_else(|_| configured_v82[1].clone())
            .unwrap_or(0);
        let admitted = snapshot.admit(profile)?;
        Ok(Self {
            inner,
            _native: vm.clone(),
            pending_mmio: Cell::new(None),
            served_isar1,
            served_mmfr2,
            #[cfg(test)]
            require_native_operations: false,
            #[cfg(test)]
            configured_mmfr1,
            #[cfg(test)]
            configured_v82,
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
        let encoding = (((iss >> 20) & 3) << 14)
            | (((iss >> 14) & 7) << 11)
            | (((iss >> 10) & 15) << 7)
            | (((iss >> 1) & 15) << 3)
            | ((iss >> 17) & 7);
        #[cfg(test)]
        {
            eprintln!("HVF served SYS trap: encoding={encoding:#x}, read={is_read}");
            if self.require_native_operations
                && !(is_read
                    && dillo_machine::aarch64::Register::from_encoding(encoding as u16).is_some())
            {
                return Err(Error::Hv(format!(
                    "native operation probe reached unsupported SYS trap {encoding:#x}, read={is_read}"
                )));
            }
        }
        if is_read {
            let rt = ((iss >> 5) & 0x1F) as u8; // ISS[9:5]
            if rt != 31 {
                use dillo_machine::aarch64::Register;
                let value = match Register::from_encoding(encoding as u16) {
                    Some(register) => self.guest_register_value(register)?,
                    None => 0,
                };
                self.inner.set_reg(gpr(rt), value)?;
            }
        }
        self.advance_pc()
    }

    fn guest_register_value(
        &self,
        register: dillo_machine::aarch64::Register,
    ) -> Result<u64, Error> {
        use dillo_machine::aarch64::Register;
        Ok(match register {
            // SCTLR is mutable guest control state, not an immutable ID.
            Register::Sctlr => self.inner.get_sys_reg(SysReg::SCTLR_EL1)?,
            Register::Isar1 => self.served_isar1,
            Register::Mmfr2 => self.served_mmfr2,
            // Without AArch32, MMFR4 is UNKNOWN (D24.2.111). With AArch32,
            // preserve earlier-profile RAZ; v8.2 refuses unavailable evidence
            // because this native binding has no MMFR4 selector.
            Register::A32Mmfr4 => 0,
            _ => self.admitted.value(register)?,
        })
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
#[path = "../../dillo-machine/tests/fixtures/arm_v81.rs"]
mod arm_v81;

#[cfg(test)]
#[path = "../../dillo-machine/tests/fixtures/arm_v82.rs"]
mod arm_v82;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use dillo_virtio::test_support::TestGuestMemory;
    use vm_memory::{Bytes, GuestAddress, VolatileMemory};

    #[test]
    fn hvf_v82_native_operations_for_one_and_two_owners() {
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            SignedNativeTest::spawn(
                "hypervisor::tests::hvf_v82_native_operations_for_one_and_two_owners",
            )
            .verify();
            return;
        }
        hvf_native_operations(pmi::aarch64::Profile::V8_2);
    }

    #[test]
    fn hvf_applicable_feature_operations_for_one_and_two_owners() {
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            SignedNativeTest::spawn(
                "hypervisor::tests::hvf_applicable_feature_operations_for_one_and_two_owners",
            )
            .verify();
            return;
        }
        eprintln!(
            "HVF applicable-feature execution on armv8.1-a owners; this does not qualify armv8.2-a admission"
        );
        hvf_native_operations(pmi::aarch64::Profile::V8_1);
    }

    fn hvf_native_operations(profile: pmi::aarch64::Profile) {
        use dillo_machine::aarch64::{AdmissionError, Register};
        let applicable_features = profile == pmi::aarch64::Profile::V8_1;
        let label = if applicable_features {
            "HVF applicable features under armv8.1-a"
        } else {
            "HVF"
        };
        for count in [1u32, 2] {
            let gic = GicParams {
                dist_base: 0x0800_0000,
                redist_base: 0x0810_0000,
                msi_base: 0x0a10_0000,
                msi_intid_base: 64,
                msi_intid_count: 32,
            };
            let vm = Vm::new(&gic, 36).expect("native HVF/GIC is required");
            vm.attach(std::sync::Arc::new(
                crate::memory::MappedMemory::new(&arm_v82::RANGES).unwrap(),
            ))
            .unwrap();
            let memory = vm.guest_memory().unwrap();
            let probe = arm_v82::NativeOperations::new(memory, count);
            let (all_ready, results) = std::thread::scope(|scope| {
                let probe = &probe;
                let (ready, prepared) = std::sync::mpsc::channel();
                let mut owners = Vec::new();
                let mut releases = Vec::new();
                for index in 0..count {
                    let native = vm.cpu_instance();
                    let ready = ready.clone();
                    let (release, gate) = std::sync::mpsc::channel();
                    releases.push(release);
                    owners.push(scope.spawn(move || {
                        let prepared = (|| {
                            let mut cpu = Vcpu::prepare(&native, profile)?;
                            eprintln!(
                                "{label} native operations owner {index} admission: {:?}",
                                cpu.admitted
                            );
                            if applicable_features {
                                // Require the operations this fixture executes, without
                                // promoting the owner to a different architectural profile.
                                for (register, shift, minimum, feature) in [
                                    (Register::Isar1, 0, 1, "FEAT_DPB"),
                                    (Register::Mmfr1, 20, 2, "FEAT_PAN2"),
                                    (Register::Pfr0, 28, 1, "FEAT_RAS"),
                                    (Register::Mmfr2, 0, 1, "FEAT_TTCNP"),
                                    (Register::Mmfr2, 4, 1, "FEAT_UAO"),
                                ] {
                                    let observed = (cpu.admitted.value(register)? >> shift) & 15;
                                    eprintln!(
                                        "{label} owner {index}: {feature} observed={observed}, minimum={minimum}"
                                    );
                                    if observed < minimum {
                                        return Err(AdmissionError::MissingField {
                                            feature,
                                            register,
                                            observed,
                                            minimum,
                                        }
                                        .into());
                                    }
                                }
                            }
                            let (owner, owners) = probe
                                .entry_arguments(index, &cpu.admitted)
                                .map_err(|message| Error::Hv(message.into()))?;
                            cpu.prepare_affinity(0x8000_0000 | u64::from(index))?;
                            cpu.initialize_bsp()?;
                            cpu.set_gpr(0, owner)?;
                            cpu.set_gpr(1, owners)?;
                            cpu.require_native_operations = true;
                            Ok::<_, Error>(cpu)
                        })();
                        ready.send(prepared.is_ok()).unwrap();
                        let cpu = prepared?;
                        if gate.recv().is_err() {
                            return Ok(None);
                        }
                        cpu.run(&std::sync::atomic::AtomicBool::new(false))
                            .map(Some)
                    }));
                }
                drop(ready);
                let all_ready = (0..count).all(|_| {
                    prepared
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap_or(false)
                });
                if all_ready {
                    for release in &releases {
                        let _ = release.send(());
                    }
                }
                drop(releases);
                let results: Vec<_> = owners
                    .into_iter()
                    .map(std::thread::ScopedJoinHandle::join)
                    .collect();
                (all_ready, results)
            });
            for (owner, result) in results.iter().enumerate() {
                eprintln!("{label} native operations owner {owner} exit: {result:?}");
            }
            probe.report(label);
            if applicable_features && !all_ready {
                probe.verify_unexecuted();
                panic!("applicable-feature execution requires every native owner to prepare");
            }
            if !all_ready {
                let mut deficient = false;
                for result in results {
                    match result.expect("native owner panic") {
                        Err(Error::ArmAdmission(AdmissionError::MissingField {
                            feature: "FEAT_Debugv8p2",
                            register: Register::Dfr0,
                            observed: 6,
                            minimum: 8,
                        })) => deficient = true,
                        Ok(None) => {}
                        other => panic!("unexpected native V82 preparation result: {other:?}"),
                    }
                }
                assert!(
                    deficient,
                    "refusal must be bound to actual DebugVer 6 evidence"
                );
                probe.verify_unexecuted();
                eprintln!(
                    "HVF V82 operations NOT EXECUTED ({count} owners): actual DebugVer 6 < 8; positive HVF qualification remains open"
                );
                continue;
            }
            for result in results {
                let exit = result
                    .expect("native owner panic")
                    .expect("native operation provider failure")
                    .expect("initial gate release");
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
            }
            probe.verify();
            if applicable_features {
                eprintln!(
                    "HVF applicable-feature execution verified for {count} owners; armv8.2-a profile qualification is unchanged"
                );
            }
        }
    }

    #[test]
    fn hvf_v81_native_lor_and_owner_floor() {
        use dillo_machine::aarch64::{CpuSnapshot, Register};
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            SignedNativeTest::spawn("hypervisor::tests::hvf_v81_native_lor_and_owner_floor")
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
        for (base, instructions) in [(0, arm_v81::PROGRAM), (0xa00, arm_v81::SYNC_HANDLER)] {
            for (index, instruction) in instructions.iter().enumerate() {
                vm.write_guest(base + index as u64 * 4, &instruction.to_le_bytes())
                    .unwrap();
            }
        }
        let (ready, prepared) = std::sync::mpsc::channel();
        let mut owners = Vec::new();
        let mut releases = Vec::new();
        for index in 0..2 {
            let native = vm.cpu_instance();
            let ready = ready.clone();
            let (release, gate) = std::sync::mpsc::channel();
            releases.push(release);
            owners.push(std::thread::spawn(move || {
                // Raw native fixture startup; production AP execution still
                // requires guest PSCI CPU_ON through the platform mailbox.
                let cpu = Vcpu::prepare(&native, pmi::aarch64::Profile::V8_0).unwrap();
                cpu.prepare_affinity(0x8000_0000 | index).unwrap();
                cpu.initialize_bsp().unwrap();
                cpu.set_gpr(0, index).unwrap();
                eprintln!(
                    "HVF owner {index} exact consumed config MMFR1={:#x}",
                    cpu.configured_mmfr1
                );
                for register in Register::ALL {
                    eprintln!(
                        "HVF owner {index} {}: actual/default effective={:#x?}",
                        register.name(),
                        cpu.admitted.value(register)
                    );
                }
                let v81 = CpuSnapshot::capture(|register| cpu.admitted.value(register))
                    .and_then(|snapshot| snapshot.admit(pmi::aarch64::Profile::V8_1));
                eprintln!("HVF owner {index} actual-owner v8.1 admission: {v81:?}");
                ready.send(()).unwrap();
                if gate.recv().is_err() {
                    return None;
                }
                let exit = cpu.run(&std::sync::atomic::AtomicBool::new(false));
                Some((cpu.admitted.value(Register::Mmfr1).unwrap(), v81, exit))
            }));
        }
        drop(ready);
        let ready = (0..2)
            .filter(|_| {
                prepared
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .is_ok()
            })
            .count();
        if ready == 2 {
            for release in releases {
                let _ = release.send(());
            }
        } else {
            drop(releases);
        }
        let results: Vec<_> = owners
            .into_iter()
            .map(std::thread::JoinHandle::join)
            .collect();
        let observed: [[u64; arm_v81::RESULT_WORDS]; 2] = std::array::from_fn(|index| {
            let mut bytes = [0; arm_v81::RESULT_WORDS * 8];
            TestGuestMemory::from_owner(vm.guest_memory().unwrap())
                .read_slice(
                    &mut bytes,
                    GuestAddress(arm_v81::RESULTS + index as u64 * arm_v81::RESULT_STRIDE),
                )
                .unwrap();
            std::array::from_fn(|word| {
                u64::from_le_bytes(bytes[word * 8..word * 8 + 8].try_into().unwrap())
            })
        });
        for (index, observed) in observed.iter().enumerate() {
            eprintln!("HVF owner {index} guest LOR observations: {observed:#x?}");
        }
        for (result, observed) in results.into_iter().zip(observed) {
            let (mmfr1, v81, exit) = result.unwrap().expect("owner release");
            assert!(matches!(
                exit.unwrap(),
                VmExit::MmioWrite {
                    addr: 0x2_0000,
                    size: 8,
                    ..
                }
            ));
            assert_eq!(
                observed[2], mmfr1,
                "guest MMFR1 versus actual owner/default effective view"
            );
            arm_v81::verify_lor(&observed);
            if let Err(error) = v81 {
                eprintln!("positive HVF v8.1 qualification remains outstanding: {error}");
            }
        }
    }

    /// Each native test runs in its own entitled process because HVF owns a
    /// process-wide native VM. Each test can retire and reconstruct it. The directory outlives the reaped child.
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
    fn hvf_partial_registration_retains_ram_through_native_drop() {
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            SignedNativeTest::spawn(
                "hypervisor::tests::hvf_partial_registration_retains_ram_through_native_drop",
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
        let vm = Vm::new(&gic, 36).unwrap();
        let ram = Arc::new(
            crate::memory::MappedMemory::new(&[
                dillo_machine::RamRange {
                    gpa: 0,
                    size: 0x4000,
                },
                dillo_machine::RamRange {
                    gpa: 0x10000,
                    size: 0x4000,
                },
            ])
            .unwrap(),
        );
        let first = crate::memory::MappingProbe::new(&ram, 0);
        let second = crate::memory::MappingProbe::new(&ram, 1);
        // A real guest store followed by HVC proves the first registration
        // survives the later failure. Only this private test bypasses Ready.
        ram.write(0, &[0x20, 0x00, 0x00, 0xf9, 0x02, 0x00, 0x00, 0xd4])
            .unwrap();
        *vm.native.0.fail_map_at.lock().unwrap() = Some(1);
        assert!(
            vm.attach(Arc::clone(&ram)).is_err(),
            "real first map, injected second call failure"
        );
        assert!(vm.native.require_ram().is_err());
        assert!(Vcpu::prepare(&vm.cpu_instance(), pmi::aarch64::Profile::V8_0).is_err());
        assert!(
            vm.attach(Arc::clone(&ram)).is_err(),
            "no retry/replacement after partial registration"
        );
        {
            let cpu = vm.native.gic().vcpu_with_config(VcpuConfig::new()).unwrap();
            cpu.set_reg(Reg::PC, 0).unwrap();
            cpu.set_reg(Reg::CPSR, 0x3c5).unwrap();
            cpu.set_reg(Reg::X0, 0xa5).unwrap();
            cpu.set_reg(Reg::X1, 0x1000).unwrap();
            let sctlr = cpu.get_sys_reg(SysReg::SCTLR_EL1).unwrap();
            cpu.set_sys_reg(SysReg::SCTLR_EL1, sctlr & !0x0200_1005)
                .unwrap();
            cpu.run().unwrap();
            assert_eq!(cpu.get_exit_info().reason, ExitReason::EXCEPTION);
            let syndrome = cpu.get_exit_info().exception.syndrome;
            assert_eq!(syndrome >> 26, 0x16);
            let value: u64 = TestGuestMemory::from_owner(ram.guest_memory())
                .read_obj(GuestAddress(0x1000))
                .unwrap();
            assert_eq!(
                value, 0xa5,
                "earlier real HVF map remains backed after partial failure"
            );
        }
        drop(ram);
        assert!(first.is_mapped());
        assert!(second.is_mapped());
        let authority = vm.cpu_instance();
        drop(vm);
        assert!(
            first.is_mapped(),
            "native authority retains earlier registration backing"
        );
        assert!(second.is_mapped());
        assert!(
            Vm::new(&gic, 36).is_err(),
            "retained owner still occupies the process slot"
        );
        drop(authority);
        assert!(!first.is_mapped());
        assert!(!second.is_mapped());
        drop(Vm::new(&gic, 36).unwrap());
    }

    #[test]
    fn hvf_failed_gic_initialization_releases_plain_owner() {
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            SignedNativeTest::spawn(
                "hypervisor::tests::hvf_failed_gic_initialization_releases_plain_owner",
            )
            .verify();
            return;
        }
        // Missing the required redistributor base reaches hv_gic_create after
        // actual VM creation, rather than failing a configuration setter.
        let error = NativeVm::create(VirtualMachineConfig::new(), GicConfig::new()).unwrap_err();
        assert!(matches!(error, Error::Hv(_)), "{error}");
        let valid = GicParams {
            dist_base: 0x0800_0000,
            redist_base: 0x0810_0000,
            msi_base: 0x0a10_0000,
            msi_intid_base: 64,
            msi_intid_count: 32,
        };
        drop(Vm::new(&valid, 36).unwrap());
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
        let probe = vm.mapping_probe(0);
        let alias = probe.alias();
        let inputs = [
            (Register::Pfr0, 0xd538_0400u32),
            (Register::Isar0, 0xd538_0600),
            (Register::Mmfr0, 0xd538_0700),
            (Register::Mmfr1, 0xd538_0720),
            (Register::Dfr0, 0xd538_0500),
            (Register::Ctr, 0xd53b_0020),
            (Register::Sctlr, 0xd538_1000),
            (Register::Isar1, 0xd538_0620),
            (Register::Mmfr2, 0xd538_0740),
            (Register::A32Mmfr4, 0xd538_02c0),
        ];
        let mut code = Vec::new();
        for (index, (_, instruction)) in inputs.iter().enumerate() {
            code.extend_from_slice(&instruction.to_le_bytes());
            code.extend_from_slice(&(0xf900_0020 | ((index as u32) << 10)).to_le_bytes());
        }
        code.extend_from_slice(&0xf900_0040u32.to_le_bytes());
        vm.write_guest(0, &code).unwrap();
        let native = vm.cpu_instance();
        let (admitted, trapped, saved_sctlr, configured_mmfr1, configured_v82, served) =
            std::thread::spawn(move || {
                let mut cpu = Vcpu::prepare(&native, pmi::aarch64::Profile::V8_0)
                    .expect("admit retained owner");
                let v82 = dillo_machine::aarch64::CpuSnapshot::capture(|register| {
                    cpu.admitted.value(register)
                })
                .and_then(|snapshot| snapshot.admit(pmi::aarch64::Profile::V8_2));
                eprintln!("HVF actual-owner armv8.2-a admission: {v82:?}");
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
                eprintln!("HVF native MRS run complete; explicit decoder checks begin");
                let admitted = cpu.admitted.clone();
                let served =
                    inputs.map(|(register, _)| cpu.guest_register_value(register).unwrap());
                let trapped = inputs.map(|(_, instruction)| {
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
                    cpu.inner.get_reg(Reg::X3).unwrap()
                });
                // Inject unavailable optional evidence on an earlier profile,
                // including exposed AArch32. Guest-serving values must survive;
                // their separate values cannot admit the newer floor.
                let unavailable = dillo_machine::aarch64::CpuSnapshot::capture(|register| {
                    use dillo_machine::aarch64::AdmissionError;
                    match register {
                        Register::Isar1 | Register::Mmfr2 | Register::A32Mmfr4 => {
                            Err(AdmissionError::Unavailable {
                                register,
                                reason: "injected optional native read failure".into(),
                            })
                        }
                        Register::Pfr0 => admitted.value(register).map(|value| (value & !15) | 2),
                        _ => admitted.value(register),
                    }
                })
                .unwrap();
                assert!(
                    unavailable
                        .clone()
                        .admit(pmi::aarch64::Profile::V8_2)
                        .is_err()
                );
                cpu.admitted = unavailable.admit(pmi::aarch64::Profile::V8_0).unwrap();
                for register in [Register::Isar1, Register::Mmfr2, Register::A32Mmfr4] {
                    let encoding = u32::from(register.encoding());
                    let iss = (((encoding >> 14) & 3) << 20)
                        | ((encoding & 7) << 17)
                        | (((encoding >> 11) & 7) << 14)
                        | (((encoding >> 7) & 15) << 10)
                        | (((encoding >> 3) & 15) << 1)
                        | (3 << 5)
                        | 1;
                    let expected = cpu.guest_register_value(register).unwrap();
                    cpu.handle_sysreg_trap((0x18 << 26) | u64::from(iss))
                        .unwrap();
                    assert_eq!(cpu.inner.get_reg(Reg::X3).unwrap(), expected);
                }
                cpu.require_native_operations = true;
                for encoding in [0x43c8u32, 0x5be1] {
                    // AT S1E1RP, DC CVAP
                    let iss = (((encoding >> 14) & 3) << 20)
                        | ((encoding & 7) << 17)
                        | (((encoding >> 11) & 7) << 14)
                        | (((encoding >> 7) & 15) << 10)
                        | (((encoding >> 3) & 15) << 1);
                    let before = cpu.inner.get_reg(Reg::PC).unwrap();
                    let error = cpu
                        .handle_sysreg_trap((0x18 << 26) | u64::from(iss))
                        .unwrap_err();
                    assert!(error.to_string().contains("unsupported SYS trap"));
                    assert_eq!(
                        cpu.inner.get_reg(Reg::PC).unwrap(),
                        before,
                        "unsupported operation is not silently completed"
                    );
                }
                (
                    admitted,
                    trapped,
                    cpu.inner.get_sys_reg(SysReg::SCTLR_EL1).unwrap(),
                    cpu.configured_mmfr1,
                    cpu.configured_v82,
                    served,
                )
            })
            .join()
            .unwrap();
        let mut bytes = [0; 80];
        TestGuestMemory::from_owner(vm.guest_memory().unwrap())
            .read_slice(&mut bytes, GuestAddress(0x1000))
            .unwrap();
        let mut file_bytes = [0; 80];
        alias
            .as_volatile_slice()
            .read_slice(&mut file_bytes, 0x1000)
            .unwrap();
        let observed: [u64; 10] = std::array::from_fn(|index| {
            u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
        });
        eprintln!(
            "HVF exact consumed config MMFR1={configured_mmfr1:#x}, ISAR1={:#x?}, MMFR2={:#x?}; post-run SCTLR={saved_sctlr:#x}",
            configured_v82[0], configured_v82[1]
        );
        for (index, (register, _)) in inputs.iter().enumerate() {
            eprintln!(
                "HVF {}: guest={:#x}, admitted API={:#x?}, explicit trap={:#x}",
                register.name(),
                observed[index],
                admitted.value(*register),
                trapped[index]
            );
        }
        for (register, configured) in [Register::Isar1, Register::Mmfr2]
            .into_iter()
            .zip(configured_v82)
        {
            if let (Ok(native), Ok(configured)) = (admitted.value(register), configured) {
                assert_eq!(native, configured, "consumed config {}", register.name());
            }
        }
        assert_eq!(
            file_bytes, bytes,
            "native guest writes reach an independent MAP_SHARED object mapping"
        );
        for (index, (register, _)) in inputs.into_iter().enumerate() {
            assert_eq!(
                trapped[index],
                served[index],
                "explicit guest serving {}",
                register.name()
            );
            let Ok(expected) = admitted.value(register) else {
                continue;
            };
            if register == Register::Sctlr {
                assert_eq!(
                    observed[index] & 0x0300_0000,
                    expected & 0x0300_0000,
                    "guest admission endianness"
                );
                assert_eq!(observed[index] & 0x0200_1005, 0, "guest fixed BSP M/C/I/EE");
                assert_eq!(observed[index], saved_sctlr, "guest live SCTLR");
                assert_eq!(trapped[index], saved_sctlr, "trapped live SCTLR");
            } else {
                assert_eq!(observed[index], expected, "guest MRS {}", register.name());
                assert_eq!(trapped[index], expected, "trapped {}", register.name());
            }
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
        let mut vm = Vm::new(&gic, 36).expect("native HVF/GIC support is required");
        vm.add_memory(0, 0x4000)
            .expect("attach owning RAM before CPU creation");
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
