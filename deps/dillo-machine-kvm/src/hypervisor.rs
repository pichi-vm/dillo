// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! KVM-backed `Vm` and `Vcpu`.
//!
//! See `dillo/ARCHITECTURE.md` §9, §16–§17 (x86), §21–§22 (aarch64).

#![allow(clippy::cast_possible_truncation)]

use std::os::fd::AsRawFd;
#[cfg(target_arch = "aarch64")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::kvm_userspace_memory_region;
#[cfg(target_arch = "aarch64")]
use kvm_bindings::{
    KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_DEV_ARM_VGIC_CTRL_INIT,
    KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
    KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_SHIFT,
    KVM_REG_ARM64_SYSREG_CRN_SHIFT, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_SHIFT,
    KVM_REG_ARM64_SYSREG_OP2_SHIFT, KVM_REG_SIZE_U64, KVM_VGIC_V3_ADDR_TYPE_DIST,
    KVM_VGIC_V3_ADDR_TYPE_REDIST, kvm_create_device, kvm_device_attr,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_vcpu_init,
};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_regs, kvm_segment};
#[cfg(target_arch = "aarch64")]
use kvm_ioctls::DeviceFd;
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd, VmFd};
use thiserror::Error;

use crate::VmExit;
#[cfg(target_arch = "x86_64")]
use crate::amd_tsc::AmdTsc as _;
#[cfg(target_arch = "x86_64")]
use crate::cpuid_x86;

/// Hypervisor / VM errors.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Mmio(#[from] dillo_mmio::AccessError),
    #[error("Arm CPU admission: {0}")]
    ArmAdmission(#[from] dillo_machine::aarch64::AdmissionError),
    #[error("KVM guest address space: {0}")]
    AddressSpace(String),
    #[error("configure vCPU kick signal mask: {0}")]
    SignalMask(std::io::Error),
    #[error("interrupt vCPU owner: {0}")]
    CpuInterrupt(std::io::Error),

    #[error("open /dev/kvm: {0}")]
    OpenKvm(std::io::Error),

    #[error("KVM API version mismatch: got {0}, expected 12")]
    ApiVersion(i32),

    #[error("required KVM capability {0:?} missing")]
    MissingCap(Cap),

    #[error("create VM: {0}")]
    CreateVm(std::io::Error),

    #[error("KVM RAM registration: {0}")]
    MemoryRegistration(&'static str),

    #[error("create IRQ chip: {0}")]
    CreateIrqChip(std::io::Error),

    #[error("set vCPU {0} LAPIC base: {1}")]
    SetLapicBase(u32, std::io::Error),

    #[error(
        "declared LAPIC at {base:#x} cannot be realized by KVM ({reason}); \
         the contract must declare a base KVM can program"
    )]
    UnsupportedLapicBase { base: u64, reason: &'static str },

    #[error(
        "declared LAPIC window of {size:#x} bytes is smaller than the \
         {decoded:#x} bytes KVM decodes at the LAPIC base"
    )]
    UnsupportedLapicSize { size: u64, decoded: u64 },

    #[error(
        "declared IOAPIC at {base:#x} cannot be realized: KVM's in-kernel \
         IOAPIC decodes only {default:#x} and offers no interface to move it"
    )]
    UnsupportedIoapicBase { base: u64, default: u64 },

    #[error(
        "declared IOAPIC window of {size:#x} bytes is smaller than the \
         {decoded:#x} bytes KVM decodes at the IOAPIC base"
    )]
    UnsupportedIoapicSize { size: u64, decoded: u64 },

    #[error("configure IRQ routing: {0}")]
    Irq(String),

    #[error("create VGIC: {0}")]
    CreateVgic(std::io::Error),

    #[error("configure VGIC: {0}")]
    ConfigureVgic(std::io::Error),

    #[error("parse DTB for KVM platform substrate: {0:?}")]
    ParseDtb(dillo_devtree::devtree::Error),

    #[error("DTB missing KVM platform substrate node `{0}`")]
    MissingSubstrate(&'static str),

    #[error("DTB property `{prop}` on `{node}` is malformed ({reason})")]
    BadSubstrateProperty {
        node: &'static str,
        prop: &'static str,
        reason: &'static str,
    },

    #[error("set TSS address: {0}")]
    SetTss(std::io::Error),

    #[error("allocate guest memory (2 MiB huge pages): {0:#}")]
    AllocateMemory(#[source] anyhow::Error),

    #[error("set user memory slot {slot}: {source}")]
    SetMemRegion {
        slot: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("create vCPU {0}: {1}")]
    CreateVcpu(u32, std::io::Error),

    #[error("set vCPU {0} regs: {1}")]
    SetRegs(u32, std::io::Error),

    #[error("set vCPU {0} sregs: {1}")]
    SetSregs(u32, std::io::Error),

    #[error("get vCPU {0} sregs: {1}")]
    GetSregs(u32, std::io::Error),

    #[error("run vCPU {0}: {1}")]
    RunVcpu(u32, std::io::Error),

    #[error("unhandled KVM vCPU exit: {0}")]
    UnhandledExit(String),

    #[error("cpu:profile {profile:?} not recognized by dillo")]
    UnknownCpuProfile { profile: String },

    #[error(
        "cpu:profile {profile:?} requires host CPUID feature `{feature}` which is not available"
    )]
    HostMissingCpuFeature {
        profile: String,
        feature: &'static str,
    },
}

/// Convert kvm-ioctls' `vmm_sys_util::errno::Error` into `std::io::Error`
/// so our public Error variants stay platform-neutral.
fn io(e: kvm_ioctls::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.errno())
}

pub(crate) fn guest_address_bits() -> Result<u32, Error> {
    let kvm = Kvm::new().map_err(io).map_err(Error::OpenKvm)?;
    #[cfg(target_arch = "x86_64")]
    {
        let supported = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|err| Error::AddressSpace(err.to_string()))?;
        cpuid_x86::guest_address_bits(&supported)
            .ok_or_else(|| Error::AddressSpace("missing or invalid CPUID address widths".into()))
    }
    #[cfg(target_arch = "aarch64")]
    {
        // create_vm uses this same maximum-IPA policy. On kernels without
        // KVM_CAP_ARM_VM_IPA_SIZE, VM type 0 has the documented 40-bit limit.
        let ipa = match kvm.get_host_ipa_limit() {
            0 => 40,
            bits if bits > 0 => bits as u32,
            _ => return Err(Error::AddressSpace("query host IPA size failed".into())),
        };
        let vm = kvm.create_vm().map_err(io).map_err(Error::CreateVm)?;
        let vcpu = vm
            .create_vcpu(0)
            .map_err(|err| Error::CreateVcpu(0, io(err)))?;
        let mut init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut init)
            .map_err(|err| Error::CreateVcpu(0, io(err)))?;
        init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        vcpu.vcpu_init(&init)
            .map_err(|err| Error::CreateVcpu(0, io(err)))?;
        let mut mmfr0 = [0; 8];
        vcpu.get_one_reg(sys_reg(3, 0, 0, 7, 0), &mut mmfr0)
            .map_err(|err| Error::AddressSpace(err.to_string()))?;
        let physical = dillo_machine::aarch64_pa_bits(u64::from_le_bytes(mmfr0))
            .ok_or_else(|| Error::AddressSpace("reserved guest PARange encoding".into()))?;
        Ok(ipa.min(physical))
    }
}

/// VM handle. Cheaply cloned via Arc-wrapped inner state.
#[derive(Clone, Debug)]
pub(crate) struct Vm {
    inner: Arc<VmInner>,
}

#[derive(Debug)]
struct VmInner {
    // Only consumed on x86_64 (KVM_GET_SUPPORTED_CPUID in `create_vcpu`);
    // aarch64 keeps the handle alive to own the VM lifetime but never reads it.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    kvm: Kvm,
    vm: VmFd,
    /// The declared controller model this VM realizes. The LAPIC base is
    /// per-vCPU, so it must outlive construction to reach every vCPU.
    #[cfg(target_arch = "x86_64")]
    intc: crate::intc_x86::X86Intc,
    #[cfg(target_arch = "aarch64")]
    vgic: Option<DeviceFd>,
    #[cfg(target_arch = "aarch64")]
    vgic_initialized: AtomicBool,
    // Must drop after VmFd and DeviceFd: both retain the kernel VM and its
    // memslots. Every native service/CPU retains this same context owner.
    memory: Mutex<MemoryRegistration>,
}

#[derive(Debug)]
enum MemoryRegistration {
    Empty,
    Failed {
        _backing: Arc<crate::memory::MappedMemory>,
    },
    Ready(Arc<crate::memory::MappedMemory>),
}

impl Vm {
    /// Borrow only for a native operation. Retaining services keep a Vm, not
    /// an independently owned descriptor that could outlive its RAM mappings.
    pub(crate) fn fd(&self) -> &VmFd {
        &self.inner.vm
    }

    #[cfg(test)]
    pub(crate) fn test_from_native(kvm: Kvm, vm: VmFd) -> Self {
        Self {
            inner: Arc::new(VmInner {
                kvm,
                vm,
                #[cfg(target_arch = "x86_64")]
                intc: crate::intc_x86::X86Intc::new(0xfee0_0000, 0x1000, 0xfec0_0000, 0x1000)
                    .unwrap(),
                #[cfg(target_arch = "aarch64")]
                vgic: None,
                #[cfg(target_arch = "aarch64")]
                vgic_initialized: AtomicBool::new(false),
                memory: Mutex::new(MemoryRegistration::Empty),
            }),
        }
    }

    /// Open `/dev/kvm`, create a VM, and set up the in-kernel LAPIC + I/O APIC
    /// realizing the interrupt-controller model `intc` declares.
    ///
    /// `intc` has already been checked against what KVM can configure, so the
    /// IOAPIC lands where the contract declares it by construction. The LAPIC
    /// base is per-vCPU state in `IA32_APIC_BASE`; it is carried here and
    /// programmed by [`Vm::create_vcpu`] as each vCPU appears, before any of
    /// them runs.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn new_with_intc(intc: crate::intc_x86::X86Intc) -> Result<Self, Error> {
        let kvm = Kvm::new().map_err(io).map_err(Error::OpenKvm)?;
        let api = kvm.get_api_version();
        if api != 12 {
            return Err(Error::ApiVersion(api));
        }
        let vm = kvm.create_vm().map_err(io).map_err(Error::CreateVm)?;

        // In-kernel IRQchip (LAPIC + I/O APIC + PIC). Must be created
        // before any vCPU.
        vm.create_irq_chip()
            .map_err(io)
            .map_err(Error::CreateIrqChip)?;
        // KVM_SET_TSS_ADDR is required by Intel VMX (Intel CPUs that
        // don't support unrestricted guest). AMD/SVM does not need it.
        // Place at a low GPA below arma's first loaded section
        // (which on x86 starts at 0x3EE00000) to avoid any memslot
        // collision. AMD-SVM accepts and ignores the value.
        vm.set_tss_address(0x3000_0000)
            .map_err(io)
            .map_err(Error::SetTss)?;

        Ok(Self {
            inner: Arc::new(VmInner {
                kvm,
                vm,
                intc,
                memory: Mutex::new(MemoryRegistration::Empty),
            }),
        })
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn new_with_gic(gic: &crate::imp::Aarch64Substrate) -> Result<Self, Error> {
        let kvm = Kvm::new().map_err(io).map_err(Error::OpenKvm)?;
        let api = kvm.get_api_version();
        if api != 12 {
            return Err(Error::ApiVersion(api));
        }
        let vm = kvm.create_vm().map_err(io).map_err(Error::CreateVm)?;
        let vgic = create_vgic(&vm, gic)?;
        Ok(Self {
            inner: Arc::new(VmInner {
                kvm,
                vm,
                vgic: Some(vgic),
                vgic_initialized: AtomicBool::new(false),
                memory: Mutex::new(MemoryRegistration::Empty),
            }),
        })
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn init_gic(&self) -> Result<(), Error> {
        if self.inner.vgic_initialized.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(vgic) = self.inner.vgic.as_ref() {
            init_vgic(vgic)?;
            self.inner.vgic_initialized.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Register immutable RAM layout once. Publish the backing owner before
    /// the first ioctl so even a partial failure cannot leave dangling slots.
    /// Failed setup is terminal; the retained context closes every native VM
    /// reference before dropping the backing, retiring partial slots as well.
    pub(crate) fn attach_memory(
        &self,
        backing: Arc<crate::memory::MappedMemory>,
    ) -> Result<(), Error> {
        let mut memory = self
            .inner
            .memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*memory, MemoryRegistration::Empty) {
            return Err(Error::MemoryRegistration(
                "RAM is already registered or setup failed",
            ));
        }
        // Failure is the retained terminal state unless every ioctl succeeds.
        // The mutex hides the in-progress transition from all native services.
        *memory = MemoryRegistration::Failed {
            _backing: Arc::clone(&backing),
        };
        for (slot, region) in backing.regions().iter().enumerate() {
            let slot =
                u32::try_from(slot).map_err(|_| Error::MemoryRegistration("too many RAM slots"))?;
            let native = kvm_userspace_memory_region {
                slot,
                flags: 0,
                guest_phys_addr: region.gpa(),
                memory_size: region.size(),
                userspace_addr: region.host_addr(),
            };
            // SAFETY: registration already owns the actual mapping. CPU,
            // notification and IRQ services retain this context; its native
            // VM/vGIC descriptors drop before this backing on every path.
            #[allow(unsafe_code)]
            unsafe { self.inner.vm.set_user_memory_region(native) }.map_err(|error| {
                Error::SetMemRegion {
                    slot,
                    source: io(error),
                }
            })?;
        }
        *memory = MemoryRegistration::Ready(backing);
        Ok(())
    }

    pub(crate) fn guest_memory(&self) -> Result<vm_memory::GuestMemoryMmap, Error> {
        let memory = self
            .inner
            .memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*memory {
            MemoryRegistration::Ready(backing) => Ok(backing.guest_memory()),
            _ => Err(Error::MemoryRegistration("RAM setup is incomplete")),
        }
    }

    pub(crate) fn write_guest(&self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        let memory = self
            .inner
            .memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*memory {
            MemoryRegistration::Ready(backing) => backing
                .write(gpa, data)
                .map_err(|error| Error::UnhandledExit(error.to_string())),
            _ => Err(Error::MemoryRegistration("RAM setup is incomplete")),
        }
    }

    /// Create vCPU `idx` and apply the CPUID derived from `cpu_profile`.
    ///
    /// Per `pmi/spec/cpu.md` and ARCH §20.2: the `vm` target is
    /// non-measured, so dillo MAY pass additional host-supported leaves
    /// through unchanged. The profile is a FLOOR — every mandatory
    /// feature must be present on the host (per-feature check, host's
    /// claimed vendor/family not trusted). On x86_64 we apply via
    /// `KVM_SET_CPUID2(KVM_GET_SUPPORTED_CPUID)` and refuse with
    /// [`Error::HostMissingCpuFeature`] if the floor is unmet.
    pub(crate) fn create_vcpu(&self, idx: u32, cpu_profile: &str) -> Result<Vcpu, Error> {
        // Successful attachment is immutable. After observing Ready there is
        // no replacement/unmap transition that could race native CPU creation.
        if !matches!(
            *self
                .inner
                .memory
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            MemoryRegistration::Ready(_)
        ) {
            return Err(Error::MemoryRegistration(
                "CPU creation requires complete RAM setup",
            ));
        }
        let fd = self
            .inner
            .vm
            .create_vcpu(idx.into())
            .map_err(|e| Error::CreateVcpu(idx, io(e)))?;

        #[cfg(target_arch = "x86_64")]
        {
            let level = cpuid_x86::X86Level::parse(cpu_profile).ok_or_else(|| {
                Error::UnknownCpuProfile {
                    profile: cpu_profile.to_string(),
                }
            })?;
            let mut supported = self
                .inner
                .kvm
                .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                .map_err(|e| Error::CreateVcpu(idx, io(e)))?;
            if let Some(missing) = cpuid_x86::first_missing(level, &supported) {
                return Err(Error::HostMissingCpuFeature {
                    profile: level.as_str().to_string(),
                    feature: missing,
                });
            }
            cpuid_x86::set_apic_id(&mut supported, idx);
            fd.set_cpuid2(&supported)
                .map_err(|e| Error::CreateVcpu(idx, io(e)))?;
            fd.initialize_amd_tsc(&supported)
                .map_err(|e| Error::CreateVcpu(idx, e))?;

            // Point this vCPU's in-kernel LAPIC at the declared base. KVM
            // resets `IA32_APIC_BASE` to its own default when the vCPU is
            // created, so the contract's base is applied here — before the
            // vCPU can run, and before any PMI boot state is written, which
            // `initialize_bsp` layers on top of this same sregs block.
            set_lapic_base(&fd, idx, self.inner.intc.lapic_base())?;
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = cpu_profile;
        }

        #[cfg(target_arch = "aarch64")]
        {
            let mut init = kvm_vcpu_init::default();
            self.inner
                .vm
                .get_preferred_target(&mut init)
                .map_err(|e| Error::CreateVcpu(idx, io(e)))?;
            init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
            if idx != 0 {
                init.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
            }
            fd.vcpu_init(&init)
                .map_err(|e| Error::CreateVcpu(idx, io(e)))?;
        }

        Ok(Vcpu {
            fd,
            _vm: self.clone(),
            idx,
            #[cfg(target_arch = "x86_64")]
            xsave_size: (self.inner.vm.check_extension_int(Cap::Xsave2) as usize)
                .max(std::mem::size_of::<kvm_bindings::kvm_xsave>()),
        })
    }
}

/// Per-vCPU handle. Move into the vCPU thread; call `run()` in a loop.
#[derive(Debug)]
pub(crate) struct Vcpu {
    // The CPU descriptor must close before its VM/RAM context can be dropped.
    fd: VcpuFd,
    _vm: Vm,
    idx: u32,
    #[cfg(target_arch = "x86_64")]
    xsave_size: usize,
}

impl Vcpu {
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn admit_arm_profile(
        &self,
        profile: pmi::aarch64::Profile,
    ) -> Result<dillo_machine::aarch64::AdmittedCpu, Error> {
        use dillo_machine::aarch64::{AdmissionError, CpuSnapshot, Register};
        if !matches!(
            profile,
            pmi::aarch64::Profile::V8_0 | pmi::aarch64::Profile::V8_1 | pmi::aarch64::Profile::V8_2
        ) {
            return Err(AdmissionError::UnsupportedProfile(profile).into());
        }
        let unavailable = |reason: String| AdmissionError::Unavailable {
            register: Register::Pfr0,
            reason,
        };
        let mut registers =
            kvm_bindings::RegList::new(0).map_err(|e| unavailable(e.to_string()))?;
        if let Err(error) = self.fd.get_reg_list(&mut registers)
            && error.errno() != libc::E2BIG
        {
            return Err(unavailable(format!("KVM_GET_REG_LIST: {error}")).into());
        }
        let mut registers = kvm_bindings::RegList::new(registers.as_fam_struct_ref().n as usize)
            .map_err(|e| unavailable(e.to_string()))?;
        self.fd
            .get_reg_list(&mut registers)
            .map_err(|e| unavailable(format!("KVM_GET_REG_LIST: {e}")))?;
        let snapshot = CpuSnapshot::capture(|register| {
            let id = KVM_REG_ARM64
                | KVM_REG_SIZE_U64
                | u64::from(KVM_REG_ARM64_SYSREG)
                | u64::from(register.encoding());
            if !registers.as_slice().contains(&id) {
                return Err(AdmissionError::Unavailable {
                    register,
                    reason: "native selector is absent from KVM_GET_REG_LIST".into(),
                });
            }
            let mut bytes = [0; 8];
            self.fd
                .get_one_reg(id, &mut bytes)
                .map_err(|e| AdmissionError::Unavailable {
                    register,
                    reason: format!("KVM_GET_ONE_REG: {e}"),
                })?;
            Ok(u64::from_le_bytes(bytes))
        })?;
        Ok(snapshot.admit(profile)?)
    }
    /// Apply PMI's fixed vm BSP state. APs retain native guest-startup state.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn initialize_bsp(&mut self) -> Result<(), Error> {
        use kvm_bindings::{Msrs, kvm_debugregs, kvm_msr_entry, kvm_xcr, kvm_xcrs};
        self.fd
            .set_regs(&kvm_regs {
                rip: 0xffff_fff0,
                rflags: 2,
                ..Default::default()
            })
            .map_err(|e| Error::SetRegs(self.idx, io(e)))?;
        let mut sregs = self
            .fd
            .get_sregs()
            .map_err(|e| Error::SetSregs(self.idx, io(e)))?;
        sregs.cr0 = 0x21;
        sregs.cr3 = 0;
        sregs.cr4 = 0x40;
        sregs.efer = 0x901;
        let data = kvm_segment {
            limit: u32::MAX,
            type_: 3,
            present: 1,
            s: 1,
            db: 1,
            g: 1,
            ..Default::default()
        };
        sregs.cs = kvm_segment { type_: 0xb, ..data };
        sregs.ds = data;
        sregs.es = data;
        sregs.fs = data;
        sregs.gs = data;
        sregs.ss = data;
        sregs.tr = kvm_segment {
            limit: 0xffff,
            type_: 0xb,
            present: 1,
            ..Default::default()
        };
        sregs.ldt = kvm_segment {
            unusable: 1,
            ..Default::default()
        };
        sregs.gdt = kvm_bindings::kvm_dtable {
            base: 0,
            limit: 0xffff,
            ..Default::default()
        };
        sregs.idt = kvm_bindings::kvm_dtable::default();
        self.fd
            .set_sregs(&sregs)
            .map_err(|e| Error::SetSregs(self.idx, io(e)))?;
        self.fd
            .set_debug_regs(&kvm_debugregs {
                dr6: 0xffff_0ff0,
                dr7: 0x400,
                ..Default::default()
            })
            .map_err(|e| Error::SetRegs(self.idx, io(e)))?;
        let pat = Msrs::from_entries(&[kvm_msr_entry {
            index: 0x277,
            data: 0x0007_0406_0007_0406,
            ..Default::default()
        }])
        .map_err(|e| Error::UnhandledExit(format!("construct BSP PAT: {e}")))?;
        let written = self
            .fd
            .set_msrs(&pat)
            .map_err(|e| Error::SetRegs(self.idx, io(e)))?;
        if written != 1 {
            return Err(Error::UnhandledExit(
                "KVM did not write BSP IA32_PAT".into(),
            ));
        }
        let mut xcrs = kvm_xcrs {
            nr_xcrs: 1,
            ..Default::default()
        };
        xcrs.xcrs[0] = kvm_xcr {
            xcr: 0,
            value: 1,
            ..Default::default()
        };
        self.fd
            .set_xcrs(&xcrs)
            .map_err(|e| Error::SetRegs(self.idx, io(e)))?;
        // KVM_SET_FPU does not write MXCSR on current kernels. Use the
        // standard XSAVE layout to initialize both x87 and SSE explicitly.
        let extra = self
            .xsave_size
            .saturating_sub(std::mem::size_of::<kvm_bindings::kvm_xsave>())
            .div_ceil(4);
        let mut xsave = kvm_bindings::Xsave::new(extra)
            .map_err(|e| Error::UnhandledExit(format!("allocate BSP XSAVE: {e}")))?;
        // SAFETY: only fixed-size fields are mutated; the allocation's FAM
        // length and layout remain unchanged.
        #[allow(unsafe_code)]
        let state = unsafe { xsave.as_mut_fam_struct() };
        state.xsave.region[0] = 0x37f; // FCW, FSW=0
        state.xsave.region[6] = 0x1f80; // MXCSR
        state.xsave.region[128] = 3; // x87 and SSE components are present
        // SAFETY: the allocation covers KVM_CAP_XSAVE2 (or the legacy 4 KiB
        // size). Dillo never dynamically enables additional XSTATE features.
        #[allow(unsafe_code)]
        unsafe { self.fd.set_xsave2(&xsave) }.map_err(|e| Error::SetRegs(self.idx, io(e)))?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn initialize_bsp(&mut self) -> Result<(), Error> {
        for idx in 0..=31 {
            // X0..X30 and SP_EL0
            self.set_one_u64(core_reg(idx), 0)?;
        }
        self.set_one_u64(core_reg(32), 0)?;
        self.set_one_u64(core_reg(33), 0x3c5)?;
        self.set_one_u64(core_reg(34), 0)?; // SP_EL1
        let sctlr = sys_reg(3, 0, 1, 0, 0);
        let mut raw = [0; 8];
        self.fd
            .get_one_reg(sctlr, &mut raw)
            .map_err(|e| Error::SetRegs(self.idx, io(e)))?;
        self.set_one_u64(
            sctlr,
            u64::from_le_bytes(raw) & !((1 << 0) | (1 << 2) | (1 << 12) | (1 << 25)),
        )
    }

    #[cfg(target_arch = "aarch64")]
    fn set_one_u64(&self, reg_id: u64, value: u64) -> Result<(), Error> {
        self.fd
            .set_one_reg(reg_id, &value.to_le_bytes())
            .map_err(|e| Error::SetRegs(self.idx, io(e)))?;
        Ok(())
    }

    /// Run the vCPU until the next exit. PIO and MMIO reads are
    /// handled inline via the supplied callbacks — the response is
    /// written into `kvm_run.io.data` / `kvm_run.mmio.data` before
    /// this call returns so the guest sees the value at its next
    /// instruction.
    ///
    /// A mapped failure returns before re-entering KVM. Only an unmapped
    /// access receives the existing zero response.
    ///
    /// `KVM_RUN` returning `EAGAIN` is not a real failure — per
    /// `Documentation/virt/kvm/api.rst`, "the call may be retried." In
    /// particular, APs created with an in-kernel IRQchip start in
    /// `MP_STATE_UNINITIALIZED`; their `KVM_RUN` returns `EAGAIN` until the BSP
    /// delivers INIT+SIPI. Retry transparently.
    ///
    /// `EINTR` is returned to the caller so the supervisor can use a
    /// thread-directed signal to make blocked vCPUs observe shutdown.
    pub(crate) fn run(
        &mut self,
        pio_read: impl Fn(u16, u8) -> u32,
        mmio_read: impl Fn(u64, &mut [u8]) -> Result<Option<()>, dillo_mmio::AccessError>,
        termination: &dyn dillo_machine::CpuTermination,
    ) -> Result<VmExit, Error> {
        let exit = loop {
            if termination.is_requested() {
                return Ok(VmExit::Interrupted);
            }
            match self.fd.run() {
                Ok(e) => break e,
                Err(e) if e.errno() == nix::libc::EAGAIN => continue,
                Err(e) if e.errno() == nix::libc::EINTR => return Ok(VmExit::Interrupted),
                Err(e) => return Err(Error::RunVcpu(self.idx, io(e))),
            }
        };
        if matches!(exit, kvm_ioctls::VcpuExit::InternalError) {
            let run = self.fd.get_kvm_run();
            // SAFETY: kvm_run is kernel-mediated; union fields valid for the active variant.
            #[allow(unsafe_code)]
            let internal = unsafe { &run.__bindgen_anon_1.internal };
            return Ok(VmExit::Unknown(format!(
                "InternalError(suberror={:#x}, ndata={}, data={:x?})",
                internal.suberror,
                internal.ndata,
                &internal.data[..(internal.ndata as usize).min(internal.data.len())]
            )));
        }
        // Handle PIO read in-place: write the value the device returns
        // into kvm_run's io.data buffer before returning.
        if let kvm_ioctls::VcpuExit::IoIn(port, data) = exit {
            let size = data.len() as u8;
            let value = pio_read(port, size);
            for (i, slot) in data.iter_mut().enumerate() {
                *slot = ((value >> (8 * i)) & 0xFF) as u8;
            }
            return Ok(VmExit::PioRead { port, size });
        }
        // Handle MMIO read in-place.
        if let kvm_ioctls::VcpuExit::MmioRead(addr, data) = exit {
            let size = data.len() as u8;
            if mmio_read(addr, data)?.is_none() {
                // Leave KVM's pre-zeroed buffer — matches real hardware
                // "no device" all-zeros on unmapped MMIO.
                for slot in data.iter_mut() {
                    *slot = 0;
                }
            }
            return Ok(VmExit::MmioRead { addr, size });
        }
        Ok(translate_exit(exit))
    }
}

impl AsRawFd for Vcpu {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
impl Vcpu {
    /// The base this vCPU's in-kernel LAPIC actually decodes at, read back
    /// from KVM. Lets a test check realized hardware, not intent.
    pub(crate) fn realized_lapic_base(&self) -> Result<u64, Error> {
        let sregs = self
            .fd
            .get_sregs()
            .map_err(|e| Error::GetSregs(self.idx, io(e)))?;
        Ok(sregs.apic_base & (0xF_FFFF << 12))
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
impl Vm {
    /// The base KVM's in-kernel IOAPIC reports for this VM, read back via
    /// `KVM_GET_IRQCHIP`.
    pub(crate) fn realized_ioapic_base(&self) -> Result<u64, Error> {
        let mut chip = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        self.inner
            .vm
            .get_irqchip(&mut chip)
            .map_err(io)
            .map_err(Error::CreateIrqChip)?;
        // SAFETY: `chip_id` selects the IOAPIC variant of the union, so the
        // kernel filled `ioapic`.
        #[allow(unsafe_code)]
        Ok(unsafe { chip.chip.ioapic }.base_address)
    }
}

/// Move `fd`'s in-kernel LAPIC to `base` via `IA32_APIC_BASE`, preserving the
/// enable and BSP bits KVM set at vCPU reset.
///
/// `kvm_apic_set_base` re-points the APIC's MMIO decode at the new address, so
/// this is what actually realizes a relocated LAPIC declaration. The base is
/// validated before VM construction (see [`crate::intc_x86`]), so a value KVM
/// would truncate never reaches here.
#[cfg(target_arch = "x86_64")]
fn set_lapic_base(fd: &VcpuFd, idx: u32, base: u64) -> Result<(), Error> {
    /// `IA32_APIC_BASE` base field — bits 12-31 (`MSR_IA32_APICBASE_BASE`).
    const APIC_BASE_MASK: u64 = 0xF_FFFF << 12;

    let mut sregs = fd.get_sregs().map_err(|e| Error::GetSregs(idx, io(e)))?;
    let wanted = (sregs.apic_base & !APIC_BASE_MASK) | (base & APIC_BASE_MASK);
    if sregs.apic_base == wanted {
        return Ok(());
    }
    sregs.apic_base = wanted;
    fd.set_sregs(&sregs)
        .map_err(|e| Error::SetLapicBase(idx, io(e)))?;

    // KVM silently keeps the old base if it rejects the mode transition, so
    // confirm the controller actually moved rather than assume it did.
    let applied = fd.get_sregs().map_err(|e| Error::GetSregs(idx, io(e)))?;
    if applied.apic_base & APIC_BASE_MASK != base & APIC_BASE_MASK {
        return Err(Error::SetLapicBase(
            idx,
            std::io::Error::other(format!(
                "KVM held IA32_APIC_BASE at {:#x} instead of the declared {base:#x}",
                applied.apic_base & APIC_BASE_MASK
            )),
        ));
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn create_vgic(vm: &VmFd, gic: &crate::imp::Aarch64Substrate) -> Result<DeviceFd, Error> {
    let mut device = kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        fd: 0,
        flags: 0,
    };
    let vgic = vm
        .create_device(&mut device)
        .map_err(io)
        .map_err(Error::CreateVgic)?;
    set_vgic_addr(&vgic, KVM_VGIC_V3_ADDR_TYPE_DIST, gic.dist_base)?;
    set_vgic_addr(&vgic, KVM_VGIC_V3_ADDR_TYPE_REDIST, gic.redist_base)?;
    let nr_irqs = 32 + gic.spi_count.max(96);
    let nr_irqs_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
        attr: 0,
        addr: &raw const nr_irqs as u64,
        flags: 0,
    };
    vgic.set_device_attr(&nr_irqs_attr)
        .map_err(io)
        .map_err(Error::ConfigureVgic)?;
    Ok(vgic)
}

#[cfg(target_arch = "aarch64")]
fn init_vgic(vgic: &DeviceFd) -> Result<(), Error> {
    let init_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0,
        flags: 0,
    };
    vgic.set_device_attr(&init_attr)
        .map_err(io)
        .map_err(Error::ConfigureVgic)
}

#[cfg(target_arch = "aarch64")]
fn set_vgic_addr(vgic: &DeviceFd, attr: u32, addr: u64) -> Result<(), Error> {
    let device_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(attr),
        addr: &raw const addr as u64,
        flags: 0,
    };
    vgic.set_device_attr(&device_attr)
        .map_err(io)
        .map_err(Error::ConfigureVgic)
}

#[cfg(target_arch = "aarch64")]
fn core_reg(index: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | u64::from(KVM_REG_ARM_CORE) | (2 * index)
}

#[cfg(target_arch = "aarch64")]
fn sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | u64::from(KVM_REG_ARM64_SYSREG)
        | (op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
        | (op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
        | (crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
        | (crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
        | (op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
}

fn translate_exit(exit: VcpuExit<'_>) -> VmExit {
    match exit {
        VcpuExit::IoIn(port, data) => VmExit::PioRead {
            port,
            size: data.len() as u8,
        },
        VcpuExit::IoOut(port, data) => {
            let mut buf = [0u8; 4];
            let n = data.len().min(4);
            buf[..n].copy_from_slice(&data[..n]);
            VmExit::PioWrite {
                port,
                data: buf,
                size: n as u8,
            }
        }
        VcpuExit::MmioRead(addr, data) => VmExit::MmioRead {
            addr,
            size: data.len() as u8,
        },
        VcpuExit::MmioWrite(addr, data) => {
            let mut buf = [0u8; 8];
            let n = data.len().min(8);
            buf[..n].copy_from_slice(&data[..n]);
            VmExit::MmioWrite {
                addr,
                data: buf,
                size: n as u8,
            }
        }
        VcpuExit::Hlt => VmExit::Halted,
        VcpuExit::Shutdown => VmExit::Shutdown,
        VcpuExit::Debug(_) => VmExit::Unknown("debug exit unsupported".to_owned()),
        VcpuExit::SystemEvent(_ty, _data) => VmExit::Shutdown,
        other => VmExit::Unknown(format!("{other:?}")),
    }
}

/// Block the kick outside KVM_RUN, which atomically unmasks it on entry.
/// A kick delivered between the stop check and guest entry remains pending.
pub(crate) fn block_kick_signal(
    vcpu: &impl AsRawFd,
    signal: nix::sys::signal::Signal,
) -> Result<KickSignalMask, Error> {
    use nix::sys::signal::{SigSet, SigmaskHow};

    // Linux exposes 64 signals to the kernel; libc's sigset_t reserves
    // more space. KVM's flexible-array payload begins immediately after len.
    #[repr(C)]
    struct KernelMask {
        len: u32,
        sigset: [u8; 8],
    }
    nix::ioctl_write_ptr!(
        set_signal_mask,
        kvm_bindings::KVMIO,
        0x8b,
        kvm_bindings::kvm_signal_mask
    );

    let mut blocked = SigSet::empty();
    blocked.add(signal);
    let previous = blocked
        .thread_swap_mask(SigmaskHow::SIG_BLOCK)
        .map_err(|error| Error::SignalMask(error.into()))?;
    let guard = KickSignalMask {
        previous,
        _thread_bound: std::marker::PhantomData,
    };
    let mut running = previous;
    running.remove(signal);
    let mut mask = KernelMask {
        len: 8,
        sigset: [0; 8],
    };
    // SAFETY: both objects contain at least eight initialized bytes. Copying
    // the native representation preserves every signal, including realtime.
    #[allow(unsafe_code)]
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(running.as_ref()).cast::<u8>(),
            mask.sigset.as_mut_ptr(),
            mask.sigset.len(),
        );
    }
    // SAFETY: the fd is a live vCPU; mask has the UAPI header and exactly
    // len trailing bytes, and remains alive through this synchronous ioctl.
    #[allow(unsafe_code)]
    unsafe { set_signal_mask(vcpu.as_raw_fd(), std::ptr::from_ref(&mask).cast()) }
        .map_err(|error| Error::SignalMask(error.into()))?;
    Ok(guard)
}

pub(crate) struct KickSignalMask {
    previous: nix::sys::signal::SigSet,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for KickSignalMask {
    fn drop(&mut self) {
        self.previous
            .thread_set_mask()
            .expect("restore vCPU signal mask");
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod bsp_tests {
    use super::*;

    #[test]
    fn fixed_bsp_state_is_written_and_ap_remains_uninitialized() {
        use vm_memory::{Bytes, GuestAddress};
        let backing = Arc::new(
            crate::memory::MappedMemory::test_backing(&[(0x1000, 0x1000), (0xffff_f000, 0x1000)])
                .unwrap(),
        );
        let memory = backing.guest_memory();
        let intc = crate::intc_x86::X86Intc::new(0xfee0_0000, 0x1000, 0xfec0_0000, 0x1000).unwrap();
        let vm = Vm::new_with_intc(intc).unwrap();
        vm.attach_memory(backing).unwrap();
        // Reset-vector jump, then guest enables OSFXSR and stores its initial
        // MXCSR before any firmware can overwrite it. XCR0 stays at PMI's 1.
        memory
            .write_slice(&[0xe9, 0x0b, 0xf0, 0xff, 0xff], GuestAddress(0xffff_fff0))
            .unwrap();
        memory
            .write_slice(
                &[
                    0x0f, 0x20, 0xe0, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x0f, 0x22, 0xe0, 0x0f, 0xae,
                    0x1d, 0x00, 0x10, 0x00, 0x00, 0xe6, 0x42, 0xf4,
                ],
                GuestAddress(0xffff_f000),
            )
            .unwrap();
        let mut bsp = vm.create_vcpu(0, "x86-64-v1").unwrap();
        let ap = vm.create_vcpu(1, "x86-64-v1").unwrap();
        let ap_before = ap.fd.get_sregs().unwrap();
        bsp.initialize_bsp().unwrap();
        let regs = bsp.fd.get_regs().unwrap();
        assert_eq!(regs.rip, 0xffff_fff0);
        assert_eq!(regs.rflags, 2);
        let s = bsp.fd.get_sregs().unwrap();
        assert_eq!(s.cr0 & !0x10, 0x21); // ET is architectural read-as-one.
        assert_eq!((s.cr3, s.cr4, s.efer), (0, 0x40, 0x901));
        for (segment, kind) in [
            (s.cs, 0xb),
            (s.ds, 3),
            (s.es, 3),
            (s.fs, 3),
            (s.gs, 3),
            (s.ss, 3),
        ] {
            assert_eq!(
                (segment.selector, segment.base, segment.limit),
                (0, 0, u32::MAX)
            );
            assert_eq!(
                (
                    segment.type_,
                    segment.present,
                    segment.dpl,
                    segment.db,
                    segment.s,
                    segment.g
                ),
                (kind, 1, 0, 1, 1, 1)
            );
            assert_eq!((segment.avl, segment.l, segment.unusable), (0, 0, 0));
        }
        assert_eq!(
            (
                s.tr.selector,
                s.tr.base,
                s.tr.limit,
                s.tr.type_,
                s.tr.present,
                s.tr.s,
                s.tr.g,
                s.tr.db,
                s.tr.avl,
                s.tr.l
            ),
            (0, 0, 0xffff, 0xb, 1, 0, 0, 0, 0, 0)
        );
        assert_eq!(s.ldt.selector, 0);
        assert_eq!(
            (s.gdt.base, s.gdt.limit, s.idt.base, s.idt.limit),
            (0, 0xffff, 0, 0)
        );
        let debug = bsp.fd.get_debug_regs().unwrap();
        assert_eq!((debug.dr6, debug.dr7), (0xffff_0ff0, 0x400));
        let mut pat = kvm_bindings::Msrs::from_entries(&[kvm_bindings::kvm_msr_entry {
            index: 0x277,
            ..Default::default()
        }])
        .unwrap();
        assert_eq!(bsp.fd.get_msrs(&mut pat).unwrap(), 1);
        assert_eq!(pat.as_slice()[0].data, 0x0007_0406_0007_0406);
        let xcrs = bsp.fd.get_xcrs().unwrap();
        assert_eq!(xcrs.xcrs.iter().find(|r| r.xcr == 0).unwrap().value, 1);
        let fpu = bsp.fd.get_fpu().unwrap();
        assert_eq!(
            (
                fpu.fcw,
                fpu.fsw,
                fpu.ftwx,
                fpu.last_opcode,
                fpu.last_ip,
                fpu.last_dp
            ),
            (0x37f, 0, 0, 0, 0, 0)
        );
        assert_eq!(bsp.fd.get_xsave().unwrap().region[6], 0x1f80);
        assert_eq!(fpu.fpr, [[0; 16]; 8]);
        assert_eq!(fpu.xmm, [[0; 16]; 16]);
        let exit = bsp
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap();
        assert!(
            matches!(exit, VmExit::PioWrite { port: 0x42, .. }),
            "{exit:?}"
        );
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
            0x1f80
        );
        assert_eq!(ap.fd.get_sregs().unwrap(), ap_before);
        assert_eq!(
            ap.fd.get_mp_state().unwrap().mp_state,
            kvm_bindings::KVM_MP_STATE_UNINITIALIZED
        );
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
#[path = "../../dillo-machine/tests/fixtures/arm_v81.rs"]
mod arm_v81;

#[cfg(all(test, target_arch = "aarch64"))]
#[path = "../../dillo-machine/tests/fixtures/arm_v82.rs"]
mod arm_v82;

#[cfg(all(test, target_arch = "aarch64"))]
mod arm_bsp_tests {
    use super::*;

    #[test]
    fn arm_v82_native_operations_for_one_and_two_owners() {
        for count in [1u32, 2] {
            let ranges = arm_v82::RANGES.map(|range| (range.gpa, range.size));
            let backing = Arc::new(crate::memory::MappedMemory::test_backing(&ranges).unwrap());
            let memory = backing.guest_memory();
            let vm = Vm::new_with_gic(&crate::imp::Aarch64Substrate {
                dist_base: 0x0800_0000,
                redist_base: 0x080a_0000,
                spi_count: 64,
            })
            .expect("native ARM KVM is required");
            vm.attach_memory(backing).unwrap();
            let probe = arm_v82::NativeOperations::new(memory, count);
            let (all_ready, gic, results) = std::thread::scope(|scope| {
                let probe = &probe;
                let (ready, prepared) = std::sync::mpsc::channel();
                let mut owners = Vec::new();
                let mut releases = Vec::new();
                for index in 0..count {
                    let vm = vm.clone();
                    let ready = ready.clone();
                    let (release, gate) = std::sync::mpsc::channel();
                    releases.push(release);
                    owners.push(scope.spawn(move || {
                        let prepared = (|| {
                            let mut cpu = vm.create_vcpu(index, "armv8.2-a")?;
                            let admitted = cpu.admit_arm_profile(pmi::aarch64::Profile::V8_2)?;
                            eprintln!(
                                "KVM native operations owner {index} admission: {admitted:?}"
                            );
                            let (owner, owners) = probe
                                .entry_arguments(index, &admitted)
                                .map_err(|message| Error::AddressSpace(message.into()))?;
                            cpu.initialize_bsp()?;
                            cpu.fd
                                .set_mp_state(kvm_bindings::kvm_mp_state {
                                    mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
                                })
                                .map_err(|error| Error::SetRegs(index, io(error)))?;
                            cpu.set_one_u64(core_reg(0), owner)?;
                            cpu.set_one_u64(core_reg(1), owners)?;
                            Ok::<_, Error>(cpu)
                        })();
                        ready.send(prepared.is_ok()).unwrap();
                        let mut cpu = prepared?;
                        if gate.recv().is_err() {
                            return Ok(None);
                        }
                        cpu.run(
                            |_, _| 0,
                            |_, _| Ok(None),
                            &std::sync::atomic::AtomicBool::new(false),
                        )
                        .map(Some)
                    }));
                }
                drop(ready);
                let all_ready = (0..count).all(|_| {
                    prepared
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap_or(false)
                });
                let gic = all_ready.then(|| vm.init_gic());
                if matches!(gic, Some(Ok(()))) {
                    for release in &releases {
                        let _ = release.send(());
                    }
                }
                drop(releases);
                let results: Vec<_> = owners
                    .into_iter()
                    .map(std::thread::ScopedJoinHandle::join)
                    .collect();
                (all_ready, gic, results)
            });
            for (owner, result) in results.iter().enumerate() {
                eprintln!("KVM native operations owner {owner} exit: {result:?}");
            }
            probe.report("KVM");
            assert!(all_ready, "every native owner must admit before entry");
            gic.unwrap().unwrap();
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
        }
    }

    #[test]
    fn arm_v81_native_lor_and_owner_floor() {
        use dillo_machine::aarch64::Register;
        use vm_memory::{Bytes, GuestAddress};
        let backing = Arc::new(crate::memory::MappedMemory::test_backing(&[(0, 0x4000)]).unwrap());
        let memory = backing.guest_memory();
        let vm = Vm::new_with_gic(&crate::imp::Aarch64Substrate {
            dist_base: 0x0800_0000,
            redist_base: 0x080a_0000,
            spi_count: 64,
        })
        .expect("native ARM KVM is required");
        vm.attach_memory(backing).unwrap();
        for (base, instructions) in [(0, arm_v81::PROGRAM), (0xa00, arm_v81::SYNC_HANDLER)] {
            for (index, instruction) in instructions.iter().enumerate() {
                memory
                    .write_obj(*instruction, GuestAddress(base + index as u64 * 4))
                    .unwrap();
            }
        }
        let (ready, prepared) = std::sync::mpsc::channel();
        let mut owners = Vec::new();
        let mut releases = Vec::new();
        for index in 0..2 {
            let vm = vm.clone();
            let ready = ready.clone();
            let (release, gate) = std::sync::mpsc::channel();
            releases.push(release);
            owners.push(std::thread::spawn(move || {
                // This native instruction fixture starts both raw owners directly;
                // it does not replace production's guest PSCI AP startup policy.
                let mut cpu = vm.create_vcpu(index, "armv8.0-a").unwrap();
                cpu.initialize_bsp().unwrap();
                cpu.fd
                    .set_mp_state(kvm_bindings::kvm_mp_state {
                        mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
                    })
                    .unwrap();
                cpu.set_one_u64(core_reg(0), u64::from(index)).unwrap();
                let admitted = cpu.admit_arm_profile(pmi::aarch64::Profile::V8_0).unwrap();
                for register in Register::ALL {
                    eprintln!(
                        "KVM owner {index} {}: native/default effective={:#x?}",
                        register.name(),
                        admitted.value(register)
                    );
                }
                let v81 = cpu.admit_arm_profile(pmi::aarch64::Profile::V8_1);
                eprintln!("KVM owner {index} native v8.1 admission: {v81:?}");
                ready.send(()).unwrap();
                if gate.recv().is_err() {
                    return None;
                }
                let exit = cpu.run(
                    |_, _| 0,
                    |_, _| Ok(None),
                    &std::sync::atomic::AtomicBool::new(false),
                );
                Some((admitted.value(Register::Mmfr1).unwrap(), v81, exit))
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
        let gic = if ready == 2 {
            vm.init_gic()
        } else {
            Err(Error::UnhandledExit(
                "native owner preparation failed".into(),
            ))
        };
        if gic.is_ok() {
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
            std::array::from_fn(|word| {
                memory
                    .read_obj(GuestAddress(
                        arm_v81::RESULTS + index as u64 * arm_v81::RESULT_STRIDE + word as u64 * 8,
                    ))
                    .unwrap()
            })
        });
        for (index, observed) in observed.iter().enumerate() {
            eprintln!("KVM owner {index} guest LOR observations: {observed:#x?}");
        }
        gic.unwrap();
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
                // Probe refusal is evidence, not positive v8.1 qualification.
                assert!(matches!(error, Error::ArmAdmission(_)), "{error}");
                eprintln!("positive KVM v8.1 qualification remains outstanding: {error}");
            }
        }
    }

    #[test]
    fn arm_admitted_owner_matches_guest_mrs_reads() {
        use dillo_machine::aarch64::Register;
        use vm_memory::{Bytes, GuestAddress};
        let backing = Arc::new(crate::memory::MappedMemory::test_backing(&[(0, 0x2000)]).unwrap());
        let memory = backing.guest_memory();
        let vm = Vm::new_with_gic(&crate::imp::Aarch64Substrate {
            dist_base: 0x0800_0000,
            redist_base: 0x080a_0000,
            spi_count: 64,
        })
        .expect("native ARM KVM is required");
        vm.attach_memory(backing).unwrap();
        // Independent architectural opcodes: MRS X0, <register>; STR X0,[X1,#n].
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
        code.extend_from_slice(&0xf900_0040u32.to_le_bytes()); // STR X0,[X2]: MMIO exit.
        memory.write_slice(&code, GuestAddress(0)).unwrap();
        std::thread::spawn(move || {
            let mut cpu = vm.create_vcpu(0, "armv8.0-a").unwrap();
            cpu.initialize_bsp().unwrap();
            let admitted = cpu
                .admit_arm_profile(pmi::aarch64::Profile::V8_0)
                .expect("admit actual retained owner");
            let v82 = cpu.admit_arm_profile(pmi::aarch64::Profile::V8_2);
            eprintln!("KVM actual-owner armv8.2-a admission: {v82:?}");
            cpu.set_one_u64(core_reg(1), 0x1000).unwrap();
            cpu.set_one_u64(core_reg(2), 0x2_0000).unwrap();
            vm.init_gic().unwrap();
            let exit = cpu
                .run(
                    |_, _| 0,
                    |_, _| Ok(None),
                    &std::sync::atomic::AtomicBool::new(false),
                )
                .unwrap();
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
            let observed: [u64; 10] = std::array::from_fn(|index| {
                memory
                    .read_obj::<u64>(GuestAddress(0x1000 + index as u64 * 8))
                    .unwrap()
            });
            let saved_sctlr = cpu.native_register(sys_reg(3, 0, 1, 0, 0));
            // Retain every raw comparison even if the first assertion fails.
            for ((register, _), observed) in inputs.iter().zip(observed) {
                let expected = admitted.value(*register);
                eprintln!(
                    "KVM {}: guest={observed:#x}, admitted API={expected:#x?}, xor={:#x?}",
                    register.name(),
                    expected.as_ref().map(|value| observed ^ value)
                );
            }
            eprintln!("KVM SCTLR_EL1: post-run API={saved_sctlr:#x}");
            for ((register, _), observed) in inputs.into_iter().zip(observed) {
                let Ok(expected) = admitted.value(register) else {
                    continue;
                };
                if register == Register::Ctr {
                    // DDI0487 M.c D24.2.41: IVIPT consumes only L1Ip[15:14].
                    // Linux v6.12 cpufeature.c:ftr_ctr omits MTE2's TminLine;
                    // sys_regs.c:vcpu_set_hcr can leave CTR reads direct via
                    // TID4. Guest TminLine can then differ from GET_ONE_REG.
                    // Check the exact admission fact and retain both raw views.
                    assert_eq!(
                        (observed >> 14) & 3,
                        (expected >> 14) & 3,
                        "guest CTR_EL0.L1Ip; full guest={observed:#x}, API={expected:#x}"
                    );
                } else if register == Register::Sctlr {
                    // Linux v6.12 sys_regs.c exposes the literal reset context
                    // (0x00c50078) before entry. hyp/sysreg-sr.h restores it to
                    // hardware and saves hardware readback after execution.
                    // Arm DDI0601 SCTLR_EL1 gives LSMAOE/nTLSMD/EOS/SED/ITD/
                    // CP15BEN feature-dependent RES1/RES0 behavior, so the
                    // pre-entry raw context need not equal guest MRS readback.
                    // Preserve every admission and fixed-BSP fact, then compare
                    // the full register at the matching post-execution phase.
                    const EE_E0E_M_C_I: u64 =
                        (1 << 25) | (1 << 24) | (1 << 0) | (1 << 2) | (1 << 12);
                    assert_eq!(
                        observed & EE_E0E_M_C_I,
                        expected & EE_E0E_M_C_I,
                        "guest SCTLR_EL1 admission endianness and fixed BSP controls"
                    );
                    assert_eq!(observed & 0x0200_1005, 0, "guest fixed BSP M/C/I/EE");
                    assert_eq!(
                        observed, saved_sctlr,
                        "guest SCTLR_EL1 versus saved native state"
                    );
                } else {
                    assert_eq!(observed, expected, "guest MRS {}", register.name());
                }
            }
        })
        .join()
        .unwrap();
    }

    #[test]
    fn arm_fixed_bsp_state_matches_pmi_and_preserves_powered_off_ap() {
        let kvm = Kvm::new().expect("/dev/kvm is required for this native test");
        let native = kvm.create_vm().expect("create ARM VM");
        let vm = Vm::test_from_native(kvm, native);
        let mut init = kvm_vcpu_init::default();
        vm.fd()
            .get_preferred_target(&mut init)
            .expect("preferred ARM CPU");
        init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        let fd = vm.fd().create_vcpu(0).expect("create BSP");
        fd.vcpu_init(&init).expect("initialize BSP");
        let mut bsp = Vcpu {
            fd,
            _vm: vm.clone(),
            idx: 0,
        };
        init.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        let ap = vm.fd().create_vcpu(1).expect("create AP");
        ap.vcpu_init(&init).expect("initialize powered-off AP");
        for index in 0..=32 {
            bsp.set_one_u64(core_reg(index), 0x8000 + index * 16)
                .unwrap();
        }
        bsp.set_one_u64(core_reg(34), 0x9000).unwrap();
        let sctlr = sys_reg(3, 0, 1, 0, 0);
        let initial_sctlr = bsp.native_register(sctlr);
        bsp.set_one_u64(sctlr, initial_sctlr | 0x0200_1005).unwrap();
        let ap_before = ap.get_mp_state().expect("read AP power state");
        bsp.initialize_bsp()
            .expect("program complete fixed ARM BSP state");
        for index in 0..=32 {
            assert_eq!(
                bsp.native_register(core_reg(index)),
                0,
                "core register {index}"
            );
        }
        assert_eq!(bsp.native_register(core_reg(33)), 0x3c5);
        assert_eq!(bsp.native_register(core_reg(34)), 0);
        assert_eq!(bsp.native_register(sctlr) & 0x0200_1005, 0);
        assert_eq!(ap_before.mp_state, kvm_bindings::KVM_MP_STATE_STOPPED);
        assert_eq!(ap.get_mp_state().unwrap(), ap_before);
    }

    impl Vcpu {
        fn native_register(&self, id: u64) -> u64 {
            let mut bytes = [0; 8];
            self.fd
                .get_one_reg(id, &mut bytes)
                .expect("read native ARM register");
            u64::from_le_bytes(bytes)
        }
    }
}

#[cfg(test)]
mod memory_registration_tests {
    use super::*;
    use crate::memory::{MappedMemory, MappingProbe};

    #[test]
    fn partial_memslot_failure_retains_backing_and_refuses_replacement() {
        let kvm = Kvm::new().expect("native KVM is required");
        let native = kvm.create_vm().unwrap();
        let vm = Vm::test_from_native(kvm, native);
        let backing =
            Arc::new(MappedMemory::test_backing(&[(0, 0x1000), (0x2001, 0x1000)]).unwrap());
        let probe = MappingProbe::new(&backing);
        // Slot zero is valid; KVM rejects slot one's unaligned guest address.
        let error = vm.attach_memory(backing).unwrap_err();
        assert!(
            matches!(error, Error::SetMemRegion { slot: 1, .. }),
            "{error}"
        );
        assert!(vm.guest_memory().is_err());
        assert!(matches!(
            vm.create_vcpu(0, "x86-64-v1"),
            Err(Error::MemoryRegistration(_))
        ));
        let replacement = Arc::new(MappedMemory::test_backing(&[(0, 0x1000)]).unwrap());
        let replacement_probe = MappingProbe::new(&replacement);
        assert!(vm.attach_memory(replacement).is_err());
        assert_eq!(replacement_probe.mappings(), 0);
        assert!(probe.mappings() > 0);
        // A native service can outlive the failed visible VM, too. Its final
        // context close retires the partially installed slot before RAM frees.
        let window = dillo_machine::memory::AddressRange {
            base: 0x4000,
            size: 0x1000,
        };
        let registrar = crate::notification::Notifications::new(vm.clone(), vec![window]);
        let notification = registrar
            .register(window, 0x50, 0)
            .unwrap()
            .expect("ioeventfd support is required");
        drop(registrar);
        drop(vm);
        notification.write(3).unwrap();
        assert_eq!(notification.read().unwrap(), 3);
        assert!(probe.mappings() > 0);
        drop(notification);
        assert_eq!(probe.mappings(), 0);
    }

    #[test]
    fn ready_memory_cannot_be_replaced_or_enlarged() {
        let kvm = Kvm::new().expect("native KVM is required");
        let native = kvm.create_vm().unwrap();
        let vm = Vm::test_from_native(kvm, native);
        let backing = Arc::new(MappedMemory::test_backing(&[(0, 0x1000)]).unwrap());
        let probe = MappingProbe::new(&backing);
        vm.attach_memory(backing).unwrap();
        vm.write_guest(0, b"original backing").unwrap();
        let replacement = Arc::new(MappedMemory::test_backing(&[(0, 0x2000)]).unwrap());
        let replacement_probe = MappingProbe::new(&replacement);
        assert!(matches!(
            vm.attach_memory(replacement),
            Err(Error::MemoryRegistration(_))
        ));
        assert_eq!(replacement_probe.mappings(), 0);
        let memory = vm.guest_memory().unwrap();
        let mut data = [0; 16];
        vm_memory::Bytes::read_slice(&memory, &mut data, vm_memory::GuestAddress(0)).unwrap();
        assert_eq!(&data, b"original backing");
        drop(vm);
        assert!(probe.mappings() > 0);
        drop(memory);
        assert_eq!(probe.mappings(), 0);
    }
}
