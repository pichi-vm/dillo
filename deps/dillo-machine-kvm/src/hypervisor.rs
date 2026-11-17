// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! KVM-backed `Vm` and `Vcpu`.
//!
//! See `dillo/ARCHITECTURE.md` §9, §16–§17 (x86), §21–§22 (aarch64).

#![allow(clippy::cast_possible_truncation)]

use std::os::fd::AsRawFd;
use std::sync::Arc;
#[cfg(target_arch = "aarch64")]
use std::sync::atomic::{AtomicBool, Ordering};

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

    #[error("set user memory region: {0}")]
    SetMemRegion(std::io::Error),

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
    vm: std::sync::Arc<VmFd>,
    /// The declared controller model this VM realizes. The LAPIC base is
    /// per-vCPU, so it must outlive construction to reach every vCPU.
    #[cfg(target_arch = "x86_64")]
    intc: crate::intc_x86::X86Intc,
    #[cfg(target_arch = "aarch64")]
    vgic: Option<DeviceFd>,
    #[cfg(target_arch = "aarch64")]
    vgic_initialized: AtomicBool,
}

impl Vm {
    /// Borrow the underlying `Arc<VmFd>` for callers that need to wire
    /// KVM-specific facilities (ioeventfd, irqfd) directly. Cheap
    /// `Arc::clone` — both `Vm` and the returned handle share the fd.
    /// Only meaningful on Linux because `VmFd` is KVM-specific.
    pub(crate) fn vm_fd_arc(&self) -> std::sync::Arc<VmFd> {
        std::sync::Arc::clone(&self.inner.vm)
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
                vm: std::sync::Arc::new(vm),
                intc,
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
                vm: std::sync::Arc::new(vm),
                vgic: Some(vgic),
                vgic_initialized: AtomicBool::new(false),
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

    /// Register a userspace memory region.
    ///
    /// SAFETY caveat encoded by KVM's API: `host_addr` must remain valid
    /// for the lifetime of the slot. Caller holds the memfd
    /// mapping for the VM's entire lifetime.
    pub(crate) fn add_memslot(
        &self,
        slot: u32,
        gpa: u64,
        host_addr: u64,
        size: u64,
    ) -> Result<(), Error> {
        let region = kvm_userspace_memory_region {
            slot,
            flags: 0,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: host_addr,
        };
        // SAFETY: dillo keeps the underlying mmap of `host_addr`
        // alive for the VM's entire lifetime (the memfd + its mapping
        // are owned by the VM child process). KVM does not access this
        // memory after the slot is removed.
        #[allow(unsafe_code)]
        unsafe {
            self.inner
                .vm
                .set_user_memory_region(region)
                .map_err(io)
                .map_err(Error::SetMemRegion)?;
        }
        Ok(())
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
    fd: VcpuFd,
    idx: u32,
    #[cfg(target_arch = "x86_64")]
    xsave_size: usize,
}

impl Vcpu {
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
    /// `mmio_read(addr, &mut data)` returns `true` if the read was
    /// handled (`data` filled). `false` leaves the KVM-supplied
    /// zero-fill in place — equivalent to "device not present" /
    /// real-hardware all-zeros for unmapped MMIO.
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
        mmio_read: impl Fn(u64, &mut [u8]) -> bool,
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
            if !mmio_read(addr, data) {
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
        use vm_memory::{Bytes, GuestAddress, GuestMemory};
        let memory = vm_memory::GuestMemoryMmap::<()>::from_ranges(&[
            (GuestAddress(0x1000), 0x1000),
            (GuestAddress(0xffff_f000), 0x1000),
        ])
        .unwrap();
        let intc = crate::intc_x86::X86Intc::new(0xfee0_0000, 0x1000, 0xfec0_0000, 0x1000).unwrap();
        let vm = Vm::new_with_intc(intc).unwrap();
        for (slot, base) in [0x1000, 0xffff_f000].into_iter().enumerate() {
            vm.add_memslot(
                slot as u32,
                base,
                memory.get_host_address(GuestAddress(base)).unwrap() as u64,
                0x1000,
            )
            .unwrap();
        }
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
                |_, _| false,
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
mod arm_bsp_tests {
    use super::*;

    #[test]
    fn arm_fixed_bsp_state_matches_pmi_and_preserves_powered_off_ap() {
        let kvm = Kvm::new().expect("/dev/kvm is required for this native test");
        let vm = kvm.create_vm().expect("create ARM VM");
        let mut init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut init)
            .expect("preferred ARM CPU");
        init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        let fd = vm.create_vcpu(0).expect("create BSP");
        fd.vcpu_init(&init).expect("initialize BSP");
        let mut bsp = Vcpu { fd, idx: 0 };
        init.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        let ap = vm.create_vcpu(1).expect("create AP");
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
