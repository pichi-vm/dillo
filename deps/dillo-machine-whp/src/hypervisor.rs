// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows Hypervisor Platform backend.
//!
//! This starts with the narrow lifecycle that proves Dillo can own a WHP
//! partition through the same concrete `Vm` / `Vcpu` surface used by the
//! Linux and macOS backends. Register state, memory mapping, and exit
//! translation are added in later phases.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use dillo_machine::cpuid_x86::{Reg, cumulative_features, required_xcr0};
use pmi::x86_64::Profile;
use thiserror::Error;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_X64_FP_CONTROL_STATUS_REGISTER,
    WHV_X64_FP_CONTROL_STATUS_REGISTER_0, WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0,
    WHV_X64_TABLE_REGISTER, WHV_X64_XMM_CONTROL_STATUS_REGISTER,
    WHV_X64_XMM_CONTROL_STATUS_REGISTER_0, WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4,
    WHvX64RegisterCs, WHvX64RegisterDr6, WHvX64RegisterDr7, WHvX64RegisterDs, WHvX64RegisterEfer,
    WHvX64RegisterEs, WHvX64RegisterFpControlStatus, WHvX64RegisterFpMmx7, WHvX64RegisterFs,
    WHvX64RegisterGdtr, WHvX64RegisterGs, WHvX64RegisterIdtr, WHvX64RegisterLdtr,
    WHvX64RegisterPat, WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterSs, WHvX64RegisterTr,
    WHvX64RegisterXCr0, WHvX64RegisterXmm0, WHvX64RegisterXmmControlStatus,
};

use crate::VmExit;

#[derive(Debug, Error)]
pub enum Error {
    #[error("WHP guest address space: {0}")]
    AddressSpace(String),
    #[error("WHP capability HypervisorPresent query failed: {0}")]
    Capability(String),

    #[error("WHP query vCPU {idx} CPUID leaf {leaf:#010x} subleaf {subleaf:#x} failed: {hr}")]
    QueryVcpuCpuid {
        idx: u32,
        leaf: u32,
        subleaf: u32,
        hr: String,
    },

    #[error("WHP hypervisor is not present")]
    HypervisorNotPresent,

    #[error("WHP create partition failed: {0}")]
    CreatePartition(String),

    #[error("WHP set partition processor count failed: {0}")]
    SetProcessorCount(String),

    #[error("WHP set local APIC emulation mode failed: {0}")]
    SetLocalApicEmulation(String),

    #[error("parse DTB for WHP platform substrate: {0:?}")]
    ParseDtb(dillo_devtree::devtree::Error),

    #[error("DTB missing WHP platform substrate node `{0}`")]
    MissingSubstrate(&'static str),

    #[error("DTB property `{prop}` on `{node}` is malformed ({reason})")]
    BadSubstrateProperty {
        node: &'static str,
        prop: &'static str,
        reason: &'static str,
    },

    #[error("WHP set CPUID result list failed: {0}")]
    SetCpuidResults(String),

    #[error("WHP configure Hyper-V enlightenments failed: {0}")]
    SetHypervEnlightenments(String),

    #[error("WHP setup partition failed: {0}")]
    SetupPartition(String),

    #[error("{operation}. WHP partition deletion failed ({hr}) and resources were retained")]
    PartitionCleanup {
        #[source]
        operation: Box<Error>,
        hr: String,
    },

    #[error("WHP address-width probe partition deletion failed ({0}) and resources were retained")]
    DeleteProbePartition(String),

    #[error("WHP create vCPU {idx} failed: {hr}")]
    CreateVcpu { idx: u32, hr: String },

    #[error("WHP delete vCPU {idx} failed: {hr}")]
    DeleteVcpu { idx: u32, hr: String },

    #[error("{operation}. {retirement}")]
    VcpuCleanup {
        #[source]
        operation: Box<Error>,
        retirement: Box<Error>,
    },

    #[error("WHP set vCPU {idx} registers failed: {hr}")]
    SetRegisters { idx: u32, hr: String },

    #[error("WHP run vCPU {idx} failed: {hr}")]
    RunVcpu { idx: u32, hr: String },

    #[error("unhandled WHP vCPU exit: {0}")]
    UnhandledExit(String),

    #[error("WHP cancel vCPU {idx} failed: {hr}")]
    CancelVcpu { idx: u32, hr: String },

    #[error("WHP request interrupt failed: {0}")]
    RequestInterrupt(String),

    #[error("unsupported cpu:profile {0:?}")]
    UnsupportedCpuProfile(dillo_machine::CpuProfile),

    #[error("cpu:profile {profile:?} requires guest CPU feature {feature}")]
    HostMissingCpuFeature {
        profile: Profile,
        feature: &'static str,
    },

    #[error("WHP guest memory size must be non-zero")]
    EmptyMemoryRegion,

    #[error("WHP processor count must be non-zero")]
    EmptyProcessorCount,

    #[error("WHP allocate guest memory: {0}")]
    AllocateMemory(std::io::Error),

    #[error("WHP create guest memory: {0}")]
    CreateGuestMemory(String),

    #[error("WHP map GPA range [{gpa:#x}..{end:#x}) failed: {hr}")]
    MapGpa { gpa: u64, end: u64, hr: String },

    #[error("WHP guest memory has already been registered or attempted")]
    MemoryAlreadyRegistered,

    #[error("WHP guest memory is not ready")]
    MemoryNotReady,

    #[error("WHP guest memory host address for GPA {gpa:#x}: {source:?}")]
    GuestMemoryHostAddress {
        gpa: u64,
        source: vm_memory::GuestMemoryError,
    },

    #[error("WHP write guest memory at GPA {gpa:#x}: {source:?}")]
    WriteGuest {
        gpa: u64,
        source: vm_memory::GuestMemoryError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HResult(i32);

impl std::fmt::Display for HResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08X}", self.0 as u32)
    }
}

fn status(hr: HResult) -> String {
    hr.to_string()
}

#[derive(Clone, Debug)]
pub(crate) struct Vm {
    inner: Arc<VmInner>,
}

#[derive(Debug)]
struct VmInner {
    partition: raw::PartitionHandle,
    memory: Mutex<RamRegistration>,
}

#[derive(Debug, Default)]
struct RamRegistration {
    backing: Option<GuestMemoryMmap>,
    ready: bool,
}

impl RamRegistration {
    fn ready(&self) -> Result<&GuestMemoryMmap, Error> {
        self.backing
            .as_ref()
            .filter(|_| self.ready)
            .ok_or(Error::MemoryNotReady)
    }
}

impl Vm {
    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, Error> {
        Self::new_with_options(PartitionOptions::default())
    }

    pub(crate) fn new_x86_64_with_local_apic_count(processor_count: u32) -> Result<Self, Error> {
        Self::new_with_options(PartitionOptions {
            processor_count,
            local_apic: true,
            hyperv_enlightenments: true,
        })
    }

    fn new_with_options(options: PartitionOptions) -> Result<Self, Error> {
        ensure_hypervisor_present()?;

        if options.processor_count == 0 {
            return Err(Error::EmptyProcessorCount);
        }

        let inner = VmInner::new()?;
        let setup = inner
            .set_processor_count(options.processor_count)
            .and_then(|()| {
                if options.hyperv_enlightenments {
                    inner.set_hyperv_enlightenments()?;
                    inner.set_hyperv_cpuid_results()?;
                }
                if options.local_apic {
                    inner.set_local_apic_emulation()?;
                }
                inner.setup()
            });
        inner.finish_setup(setup)
    }

    #[cfg(test)]
    pub(crate) fn add_memory(&mut self, base: u64, size: u64) -> Result<(), Error> {
        if size == 0 {
            return Err(Error::EmptyMemoryRegion);
        }
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(base), size as usize)])
            .map_err(|source| Error::CreateGuestMemory(source.to_string()))?;
        self.set_memory(memory)
    }

    pub(crate) fn set_memory(&mut self, memory: GuestMemoryMmap) -> Result<(), Error> {
        let mut registration = self.inner.memory();
        if self.inner.partition == 0 || registration.backing.is_some() {
            return Err(Error::MemoryAlreadyRegistered);
        }
        if memory.num_regions() == 0 {
            return Err(Error::EmptyMemoryRegion);
        }

        // A failed map is terminal for this partition. Keep all candidate
        // regions alive before WHP can retain any of their addresses.
        let result = self.inner.map_memory(registration.backing.insert(memory));
        if result.is_ok() {
            registration.ready = true;
        }
        drop(registration);

        result.map_err(|operation| {
            // Escaped authorities may still own the partition. If they do,
            // retirement is deferred until the final owner drops.
            if let Some(inner) = Arc::get_mut(&mut self.inner) {
                inner.cleanup_error(operation)
            } else {
                operation
            }
        })
    }

    pub(crate) fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        self.inner
            .memory()
            .ready()?
            .write_slice(data, GuestAddress(gpa))
            .map_err(|source| Error::WriteGuest { gpa, source })
    }

    pub(crate) fn guest_memory(&self) -> Result<GuestMemoryMmap, Error> {
        self.inner.memory().ready().cloned()
    }

    #[cfg(test)]
    pub(crate) fn region_mappings(&self) -> Vec<(u64, u64, u64)> {
        let Ok(memory) = self.guest_memory() else {
            return Vec::new();
        };
        memory
            .iter()
            .filter_map(|region| {
                let base = region.start_addr();
                let host = memory.get_host_address(base).ok()?;
                Some((base.raw_value(), host as u64, region.len()))
            })
            .collect()
    }

    pub(crate) fn create_vcpu(&self, idx: u32, profile: Profile) -> Result<Vcpu, Error> {
        self.inner.memory().ready()?;
        self.create_vcpu_without_ram_check(idx, profile)
    }

    fn create_vcpu_without_ram_check(&self, idx: u32, profile: Profile) -> Result<Vcpu, Error> {
        raw::create_virtual_processor(self.inner.partition, idx).map_err(|hr| {
            Error::CreateVcpu {
                idx,
                hr: status(hr),
            }
        })?;
        let mut vcpu = Vcpu {
            partition: Arc::clone(&self.inner),
            idx,
            delete_pending: true,
        };
        if let Err(operation) = vcpu.validate_profile(profile) {
            return Err(vcpu.cleanup_error(operation));
        }
        Ok(vcpu)
    }

    pub(crate) fn interrupt_controller(&self) -> InterruptController {
        InterruptController {
            inner: Arc::clone(&self.inner),
        }
    }
}

pub(crate) fn guest_address_bits() -> Result<u32, Error> {
    // The probe uses the launch partition policy, but never maps RAM or runs.
    let mut vm = Vm::new_x86_64_with_local_apic_count(1)?;
    let width = vm
        .create_vcpu_without_ram_check(0, Profile::V1)
        .and_then(|mut vcpu| {
            let width = match raw::guest_physical_bits(vcpu.partition.partition, vcpu.idx) {
                Ok(physical) if (32..=52).contains(&physical) => Ok(physical),
                Ok(physical) => Err(Error::AddressSpace(format!(
                    "invalid guest width {physical}"
                ))),
                Err(hr) => Err(Error::AddressSpace(status(hr))),
            };
            match width {
                Ok(physical) => vcpu.retire().map(|()| physical),
                Err(operation) => Err(vcpu.cleanup_error(operation)),
            }
        });
    // The temporary vCPU has released its partition reference.
    let inner = Arc::get_mut(&mut vm.inner)
        .ok_or_else(|| Error::AddressSpace("probe partition is still shared".into()))?;
    match width {
        Ok(physical) => {
            inner
                .retire()
                .map_err(|hr| Error::DeleteProbePartition(status(hr)))?;
            Ok(physical)
        }
        Err(operation) => Err(inner.cleanup_error(operation)),
    }
}

#[derive(Clone, Copy, Debug)]
struct PartitionOptions {
    processor_count: u32,
    local_apic: bool,
    hyperv_enlightenments: bool,
}

impl Default for PartitionOptions {
    fn default() -> Self {
        Self {
            processor_count: 1,
            local_apic: false,
            hyperv_enlightenments: false,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InterruptController {
    inner: Arc<VmInner>,
}

impl InterruptController {
    pub(crate) fn request_fixed_interrupt(
        &self,
        destination: u32,
        vector: u8,
    ) -> Result<(), Error> {
        self.inner.memory().ready()?;
        raw::request_fixed_interrupt(self.inner.partition, destination, vector)
            .map_err(|hr| Error::RequestInterrupt(status(hr)))
    }
}

impl VmInner {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            partition: raw::create_partition().map_err(|hr| Error::CreatePartition(status(hr)))?,
            memory: Mutex::default(),
        })
    }

    fn finish_setup(mut self, setup: Result<(), Error>) -> Result<Vm, Error> {
        setup.map_err(|operation| self.cleanup_error(operation))?;
        Ok(Vm {
            inner: Arc::new(self),
        })
    }

    fn memory(&self) -> MutexGuard<'_, RamRegistration> {
        self.memory.lock().expect("WHP RAM registration poisoned")
    }

    fn map_memory(&self, memory: &GuestMemoryMmap) -> Result<(), Error> {
        for region in memory.iter() {
            let base = region.start_addr().raw_value();
            let size = region.len();
            let host_addr = memory
                .get_host_address(region.start_addr())
                .map_err(|source| Error::GuestMemoryHostAddress { gpa: base, source })?;
            raw::map_gpa_range(self.partition, host_addr.cast(), base, size).map_err(|hr| {
                Error::MapGpa {
                    gpa: base,
                    end: base.saturating_add(size),
                    hr: status(hr),
                }
            })?;
        }
        Ok(())
    }

    fn cleanup_error(&mut self, operation: Error) -> Error {
        match self.retire() {
            Ok(()) => operation,
            Err(hr) => Error::PartitionCleanup {
                operation: Box::new(operation),
                hr: status(hr),
            },
        }
    }

    fn retire(&mut self) -> Result<(), HResult> {
        // Retire at most once, including when setup or mapping fails.
        let partition = std::mem::take(&mut self.partition);
        if partition == 0 {
            return Ok(());
        }
        let deletion = raw::delete_partition(partition);
        let memory = self
            .memory
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let registration = std::mem::take(memory);
        if deletion.is_err() {
            // WHP may still address this backing. Keep the handle and all
            // attempted mappings for the remaining lifetime of the process.
            std::mem::forget((partition, registration));
        }
        deletion
    }

    fn set_processor_count(&self, count: u32) -> Result<(), Error> {
        raw::set_processor_count(self.partition, count)
            .map_err(|hr| Error::SetProcessorCount(status(hr)))
    }

    fn set_local_apic_emulation(&self) -> Result<(), Error> {
        raw::set_local_apic_emulation(self.partition)
            .map_err(|hr| Error::SetLocalApicEmulation(status(hr)))
    }

    fn set_hyperv_cpuid_results(&self) -> Result<(), Error> {
        let results = hyperv_cpuid_results();
        if results.common.is_empty() {
            return Ok(());
        }
        raw::set_cpuid_results(self.partition, &results.common)
            .map_err(|hr| Error::SetCpuidResults(status(hr)))?;
        raw::set_cpuid_exit_list(self.partition, &[1])
            .map_err(|hr| Error::SetCpuidResults(status(hr)))
    }

    fn set_hyperv_enlightenments(&self) -> Result<(), Error> {
        raw::set_hyperv_enlightenments(self.partition)
            .map_err(|hr| Error::SetHypervEnlightenments(status(hr)))
    }

    fn setup(&self) -> Result<(), Error> {
        raw::setup_partition(self.partition).map_err(|hr| Error::SetupPartition(status(hr)))
    }
}

struct HypervCpuidResults {
    common: Vec<raw::CpuidResult>,
}

#[cfg(target_arch = "x86_64")]
fn hyperv_cpuid_results() -> HypervCpuidResults {
    use core::arch::x86_64::__cpuid;

    hyperv_cpuid_results_from(|function| {
        let r = __cpuid(function);
        raw::CpuidResult {
            function,
            eax: r.eax,
            ebx: r.ebx,
            ecx: r.ecx,
            edx: r.edx,
        }
    })
}

#[cfg(target_arch = "x86_64")]
fn hyperv_cpuid_results_from(cpuid: impl Fn(u32) -> raw::CpuidResult) -> HypervCpuidResults {
    let basic_max = cpuid(0).eax;
    let hv_max = cpuid(0x4000_0000).eax;
    if hv_max < 0x4000_0000 {
        return HypervCpuidResults { common: Vec::new() };
    }

    let mut common = Vec::new();

    if basic_max >= 6 {
        let mut leaf6 = cpuid(6);
        // Do not expose CPU power-management features that require MSRs
        // Dillo does not virtualize, such as IA32_PERF_CTL.
        leaf6.eax &= !((1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 15));
        leaf6.ecx &= !1;
        common.push(leaf6);
    }

    let last = hv_max.min(0x4000_000c);
    for function in 0x4000_0000..=last {
        let mut result = cpuid(function);
        if function == 0x4000_0003 {
            result.ebx = 0;
            result.edx &= !(1 << 10);
        }
        common.push(result);
    }
    HypervCpuidResults { common }
}

#[cfg(not(target_arch = "x86_64"))]
fn hyperv_cpuid_results() -> HypervCpuidResults {
    HypervCpuidResults { common: Vec::new() }
}

fn hyperv_leaf1_cpuid(
    vp_index: u32,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
) -> (u64, u64, u64, u64) {
    let rbx = (rbx & 0x00ff_ffff) | (u64::from(vp_index) << 24);
    let rcx = (rcx & !(1 << 3)) | (1 << 31);
    (rax, rbx, rcx, rdx)
}

impl Drop for VmInner {
    fn drop(&mut self) {
        if let Err(hr) = self.retire() {
            log::error!("WHP partition deletion failed ({hr}), resources retained");
        }
    }
}

#[derive(Debug)]
pub(crate) struct Vcpu {
    partition: Arc<VmInner>,
    idx: u32,
    delete_pending: bool,
}

impl Vcpu {
    pub(crate) fn retire(&mut self) -> Result<(), Error> {
        // A failed native call leaves the deletion state uncertain.
        if !std::mem::take(&mut self.delete_pending) {
            return Ok(());
        }
        raw::delete_virtual_processor(self.partition.partition, self.idx).map_err(|hr| {
            Error::DeleteVcpu {
                idx: self.idx,
                hr: status(hr),
            }
        })
    }

    pub(crate) fn cancel_handle(&self) -> VcpuCancel {
        VcpuCancel {
            partition: Arc::clone(&self.partition),
            idx: self.idx,
        }
    }

    fn validate_profile(&self, profile: Profile) -> Result<(), Error> {
        let cpuid = |leaf, subleaf| {
            raw::vcpu_cpuid(self.partition.partition, self.idx, leaf, subleaf).map_err(|hr| {
                Error::QueryVcpuCpuid {
                    idx: self.idx,
                    leaf,
                    subleaf,
                    hr: status(hr),
                }
            })
        };
        let max_standard = cpuid(0, 0)?.Eax;
        let max_extended = cpuid(0x8000_0000, 0)?.Eax;
        for feat in cumulative_features(profile) {
            let max = if feat.function >= 0x8000_0000 {
                max_extended
            } else {
                max_standard
            };
            if feat.function > max {
                return Err(Error::HostMissingCpuFeature {
                    profile,
                    feature: feat.name,
                });
            }
            let value = cpuid(feat.function, feat.index)?;
            let word = match feat.reg {
                Reg::Eax => value.Eax,
                Reg::Ebx => value.Ebx,
                Reg::Ecx => value.Ecx,
                Reg::Edx => value.Edx,
            };
            if word & (1 << feat.bit) == 0 {
                return Err(Error::HostMissingCpuFeature {
                    profile,
                    feature: feat.name,
                });
            }
        }
        let xcr0 = required_xcr0(profile);
        if xcr0 != 0 && (max_standard < 0x0d || cpuid(0x0d, 0)?.Eax & xcr0 != xcr0) {
            return Err(Error::HostMissingCpuFeature {
                profile,
                feature: "XCR0 components",
            });
        }
        Ok(())
    }

    pub(crate) fn cleanup_error(&mut self, operation: Error) -> Error {
        match self.retire() {
            Ok(()) => operation,
            Err(retirement) => Error::VcpuCleanup {
                operation: Box::new(operation),
                retirement: Box::new(retirement),
            },
        }
    }

    /// Program every register fixed by PMI's x86 vm BSP contract.
    pub(crate) fn initialize_bsp(&self) -> Result<(), Error> {
        let mut registers = Vec::new();
        push_reg64(&mut registers, WHvX64RegisterRip, 0xffff_fff0);
        push_reg64(&mut registers, WHvX64RegisterRflags, 2);
        push_reg64(&mut registers, WHvX64RegisterCr0, 0x21);
        push_reg64(&mut registers, WHvX64RegisterCr3, 0);
        push_reg64(&mut registers, WHvX64RegisterCr4, 0x40);
        push_reg64(&mut registers, WHvX64RegisterEfer, 0x901);
        push_reg64(&mut registers, WHvX64RegisterDr6, 0xffff_0ff0);
        push_reg64(&mut registers, WHvX64RegisterDr7, 0x400);
        push_reg64(&mut registers, WHvX64RegisterPat, 0x0007_0406_0007_0406);
        push_reg64(&mut registers, WHvX64RegisterXCr0, 1);
        for (name, attributes, limit) in [
            (WHvX64RegisterCs, 0xc09b, u32::MAX),
            (WHvX64RegisterDs, 0xc093, u32::MAX),
            (WHvX64RegisterEs, 0xc093, u32::MAX),
            (WHvX64RegisterFs, 0xc093, u32::MAX),
            (WHvX64RegisterGs, 0xc093, u32::MAX),
            (WHvX64RegisterSs, 0xc093, u32::MAX),
            (WHvX64RegisterTr, 0x008b, 0xffff),
            (WHvX64RegisterLdtr, 0, 0),
        ] {
            registers.push((
                name,
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER {
                        Base: 0,
                        Limit: limit,
                        Selector: 0,
                        Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                            Attributes: attributes,
                        },
                    },
                },
            ));
        }
        for (name, limit) in [(WHvX64RegisterGdtr, 0xffff), (WHvX64RegisterIdtr, 0)] {
            registers.push((
                name,
                WHV_REGISTER_VALUE {
                    Table: WHV_X64_TABLE_REGISTER {
                        Pad: [0; 3],
                        Limit: limit,
                        Base: 0,
                    },
                },
            ));
        }
        // WHP exposes all eight x87/MMX and sixteen SSE registers individually.
        for name in WHvX64RegisterXmm0..=WHvX64RegisterFpMmx7 {
            registers.push((name, WHV_REGISTER_VALUE::default()));
        }
        registers.push((
            WHvX64RegisterFpControlStatus,
            WHV_REGISTER_VALUE {
                FpControlStatus: WHV_X64_FP_CONTROL_STATUS_REGISTER {
                    Anonymous: WHV_X64_FP_CONTROL_STATUS_REGISTER_0 {
                        FpControl: 0x37f,
                        ..Default::default()
                    },
                },
            },
        ));
        registers.push((
            WHvX64RegisterXmmControlStatus,
            WHV_REGISTER_VALUE {
                XmmControlStatus: WHV_X64_XMM_CONTROL_STATUS_REGISTER {
                    Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0 {
                        XmmStatusControl: 0x1f80,
                        ..Default::default()
                    },
                },
            },
        ));
        self.set_registers(registers)
    }

    fn set_registers(
        &self,
        registers: Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)>,
    ) -> Result<(), Error> {
        let (names, values): (Vec<_>, Vec<_>) = registers.into_iter().unzip();
        raw::set_virtual_processor_registers(self.partition.partition, self.idx, &names, &values)
            .map_err(|hr| Error::SetRegisters {
                idx: self.idx,
                hr: status(hr),
            })
    }

    pub(crate) fn run(
        &mut self,
        pio_read: impl Fn(u16, u8) -> u32,
        mmio_read: impl Fn(u64, &mut [u8]) -> bool,
    ) -> Result<VmExit, Error> {
        let exit =
            raw::run_virtual_processor(self.partition.partition, self.idx, &pio_read, &mmio_read)
                .map_err(|hr| Error::RunVcpu {
                idx: self.idx,
                hr: status(hr),
            })?;
        Ok(match exit {
            raw::RunExit::Halted => VmExit::Halted,
            raw::RunExit::PioRead { port, size } => VmExit::PioRead { port, size },
            raw::RunExit::PioWrite { port, data, size } => VmExit::PioWrite { port, data, size },
            raw::RunExit::MmioRead { addr, size } => VmExit::MmioRead { addr, size },
            raw::RunExit::MmioWrite { addr, data, size } => VmExit::MmioWrite { addr, data, size },
            raw::RunExit::Shutdown => VmExit::Shutdown,
            raw::RunExit::Canceled => VmExit::Interrupted,
            raw::RunExit::Unknown(reason) => VmExit::Unknown(reason),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VcpuCancel {
    partition: Arc<VmInner>,
    idx: u32,
}

impl VcpuCancel {
    pub(crate) fn cancel(&self) -> Result<(), Error> {
        raw::cancel_run_virtual_processor(self.partition.partition, self.idx).map_err(|hr| {
            Error::CancelVcpu {
                idx: self.idx,
                hr: status(hr),
            }
        })
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        if let Err(error) = self.retire() {
            log::error!("{error}");
        }
    }
}

fn ensure_hypervisor_present() -> Result<(), Error> {
    let present = raw::hypervisor_present().map_err(|hr| Error::Capability(status(hr)))?;
    if present == 0 {
        return Err(Error::HypervisorNotPresent);
    }
    Ok(())
}

const fn failed(hr: i32) -> bool {
    hr < 0
}

fn push_reg64(
    registers: &mut Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)>,
    name: WHV_REGISTER_NAME,
    value: u64,
) {
    registers.push((name, WHV_REGISTER_VALUE { Reg64: value }));
}

mod raw {
    #![allow(unsafe_code)]

    use std::ffi::c_void;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::ptr;

    use windows_sys::Win32::System::Hypervisor::{
        WHV_CAPABILITY_CODE, WHV_CPUID_OUTPUT, WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_IO_ACCESS_INFO,
        WHV_EMULATOR_MEMORY_ACCESS_INFO, WHV_EMULATOR_STATUS, WHV_INTERRUPT_CONTROL,
        WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
        WHV_RUN_VP_EXIT_CONTEXT, WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS, WHV_TRANSLATE_GVA_FLAGS,
        WHV_TRANSLATE_GVA_RESULT, WHV_TRANSLATE_GVA_RESULT_CODE, WHV_X64_CPUID_RESULT,
        WHvCancelRunVirtualProcessor, WHvCapabilityCodeHypervisorPresent,
        WHvCapabilityCodeInterruptClockFrequency, WHvCapabilityCodeProcessorClockFrequency,
        WHvCapabilityCodeSyntheticProcessorFeaturesBanks, WHvCreatePartition,
        WHvCreateVirtualProcessor, WHvDeletePartition, WHvDeleteVirtualProcessor,
        WHvEmulatorCreateEmulator, WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation,
        WHvEmulatorTryMmioEmulation, WHvGetCapability, WHvGetVirtualProcessorCpuidOutput,
        WHvGetVirtualProcessorRegisters, WHvMapGpaRange, WHvMapGpaRangeFlagExecute,
        WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite, WHvPartitionPropertyCodeCpuidExitList,
        WHvPartitionPropertyCodeCpuidResultList, WHvPartitionPropertyCodeInterruptClockFrequency,
        WHvPartitionPropertyCodeLocalApicEmulationMode,
        WHvPartitionPropertyCodeProcessorClockFrequency, WHvPartitionPropertyCodeProcessorCount,
        WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks, WHvRequestInterrupt,
        WHvRunVirtualProcessor, WHvRunVpExitReasonCanceled, WHvRunVpExitReasonMemoryAccess,
        WHvRunVpExitReasonUnrecoverableException, WHvRunVpExitReasonX64Cpuid,
        WHvRunVpExitReasonX64Halt, WHvRunVpExitReasonX64IoPortAccess, WHvSetPartitionProperty,
        WHvSetVirtualProcessorRegisters, WHvSetupPartition, WHvTranslateGva,
        WHvX64InterruptDestinationModePhysical, WHvX64InterruptTriggerModeEdge,
        WHvX64InterruptTypeFixed, WHvX64LocalApicEmulationModeXApic, WHvX64RegisterRax,
        WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRip,
    };

    use super::{HResult, failed, hyperv_leaf1_cpuid};

    pub(super) type PartitionHandle = WHV_PARTITION_HANDLE;

    pub(super) fn guest_physical_bits(
        partition: PartitionHandle,
        idx: u32,
    ) -> Result<u32, HResult> {
        #[cfg(test)]
        if FAIL_NEXT_GUEST_PHYSICAL_BITS.with(|fail| fail.replace(false)) {
            return Err(HResult(E_FAIL));
        }
        let output = vcpu_cpuid(partition, idx, 0x8000_0008, 0)?;
        let physical = output.Eax & 0xff;
        // WHvCapabilityCodePhysicalAddressWidth is newer than windows-sys's
        // headers. Older WHP versions expose their limit through guest CPUID.
        match get_capability_u32(0x100a) {
            Ok(bits) => Ok(physical.min(bits)),
            Err(HResult(windows_sys::Win32::Foundation::WHV_E_UNKNOWN_CAPABILITY)) => Ok(physical),
            Err(err) => Err(err),
        }
    }

    pub(super) fn vcpu_cpuid(
        partition: PartitionHandle,
        idx: u32,
        leaf: u32,
        subleaf: u32,
    ) -> Result<WHV_CPUID_OUTPUT, HResult> {
        let mut output = WHV_CPUID_OUTPUT::default();
        // SAFETY: the VP is live and the result buffer is initialized and writable.
        let hr = unsafe {
            WHvGetVirtualProcessorCpuidOutput(partition, idx, leaf, subleaf, &raw mut output)
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(output)
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) struct CpuidResult {
        pub function: u32,
        pub eax: u32,
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
    }

    pub(super) enum RunExit {
        Halted,
        PioRead { port: u16, size: u8 },
        PioWrite { port: u16, data: [u8; 4], size: u8 },
        MmioRead { addr: u64, size: u8 },
        MmioWrite { addr: u64, data: [u8; 8], size: u8 },
        Shutdown,
        Canceled,
        Unknown(String),
    }

    const EXIT_X64_HALT: i32 = WHvRunVpExitReasonX64Halt;
    const EXIT_X64_IO_PORT_ACCESS: i32 = WHvRunVpExitReasonX64IoPortAccess;
    const EXIT_MEMORY_ACCESS: i32 = WHvRunVpExitReasonMemoryAccess;
    const EXIT_UNRECOVERABLE_EXCEPTION: i32 = WHvRunVpExitReasonUnrecoverableException;
    const EXIT_X64_CPUID: i32 = WHvRunVpExitReasonX64Cpuid;
    const EXIT_CANCELED: i32 = WHvRunVpExitReasonCanceled;
    const S_OK: i32 = 0;
    const E_FAIL: i32 = 0x8000_4005u32.cast_signed();
    const ERROR_NOT_SUPPORTED: HResult = HResult(0x8007_0032u32.cast_signed());

    #[cfg(test)]
    std::thread_local! {
        pub(super) static FAIL_MAP_GPA: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
        pub(super) static FAIL_NEXT_DELETE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static FAIL_NEXT_VCPU_DELETE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static FAIL_NEXT_GUEST_PHYSICAL_BITS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        pub(super) static DELETED_PARTITIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    pub(super) fn hypervisor_present() -> Result<u32, HResult> {
        get_capability_u32(WHvCapabilityCodeHypervisorPresent)
    }

    pub(super) fn create_partition() -> Result<PartitionHandle, HResult> {
        let mut partition = 0;
        // SAFETY: WHP writes one partition handle to the provided out pointer.
        let hr = unsafe { WHvCreatePartition(&raw mut partition) };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(partition)
    }

    pub(super) fn delete_partition(partition: PartitionHandle) -> Result<(), HResult> {
        #[cfg(test)]
        if FAIL_NEXT_DELETE.with(|fail| fail.replace(false)) {
            return Err(HResult(E_FAIL));
        }
        // SAFETY: only the final owner of this live partition calls this.
        let hr = unsafe { WHvDeletePartition(partition) };
        if hr != S_OK {
            return Err(HResult(hr));
        }
        #[cfg(test)]
        DELETED_PARTITIONS.with(|count| count.set(count.get() + 1));
        Ok(())
    }

    pub(super) fn set_processor_count(
        partition: PartitionHandle,
        count: u32,
    ) -> Result<(), HResult> {
        let property = WHV_PARTITION_PROPERTY {
            ProcessorCount: count,
        };
        // SAFETY: `property` is initialized for the ProcessorCount property
        // code and the buffer size matches the WHP union size.
        let hr = unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeProcessorCount,
                ptr::from_ref(&property).cast::<c_void>(),
                size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn set_local_apic_emulation(partition: PartitionHandle) -> Result<(), HResult> {
        let property = WHV_PARTITION_PROPERTY {
            LocalApicEmulationMode: WHvX64LocalApicEmulationModeXApic,
        };
        // SAFETY: `property` is initialized for the LocalApicEmulationMode
        // property code and the buffer size matches the WHP union size.
        let hr = unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeLocalApicEmulationMode,
                ptr::from_ref(&property).cast::<c_void>(),
                size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn set_hyperv_enlightenments(partition: PartitionHandle) -> Result<(), HResult> {
        // Optional enlightenment: Ok -> applied(true), ERROR_NOT_SUPPORTED ->
        // skipped(false), any other failure -> hard error. Applied uniformly to
        // both the capability *query* and the property *set*, so a host that
        // can't even report a value skips cleanly instead of aborting.
        fn optional(r: Result<(), HResult>) -> Result<bool, HResult> {
            match r {
                Ok(()) => Ok(true),
                Err(ERROR_NOT_SUPPORTED) => Ok(false),
                Err(hr) => Err(hr),
            }
        }

        // REQUIRED. The synthetic processor feature banks expose the core
        // Hyper-V paravirt interface — the reference TSC page (enlightened
        // clocksource), the SynIC, and synthetic timers. Every enlightened
        // clock/timer/interrupt path the guest uses depends on it, so any
        // failure here (including ERROR_NOT_SUPPORTED) is fatal: we do not run a
        // guest on a host that can't provide it.
        set_synthetic_processor_features_banks(partition)?;

        // OPTIONAL. The processor/interrupt clock-frequency hints only let the
        // guest skip boot-time calibration; a nested/limited host (e.g. a CI
        // runner) may return ERROR_NOT_SUPPORTED. Skip those rather than fail —
        // the guest derives the frequencies another way, and the synthetic
        // timers above already cover the clock-event path.
        let processor_clock = optional(
            get_capability_u64(WHvCapabilityCodeProcessorClockFrequency)
                .and_then(|freq| set_processor_clock_frequency(partition, freq)),
        )?;
        let interrupt_clock = optional(
            get_capability_u64(WHvCapabilityCodeInterruptClockFrequency)
                .and_then(|freq| set_interrupt_clock_frequency(partition, freq)),
        )?;

        if processor_clock && interrupt_clock {
            log::info!(
                "WHP: fully enlightened (synthetic processor features + processor and \
                 interrupt clock frequencies applied)"
            );
        } else {
            log::warn!(
                "WHP: enlightened, optional clock hints skipped — \
                 processor_clock={processor_clock}, interrupt_clock={interrupt_clock} \
                 (host returned ERROR_NOT_SUPPORTED; required synthetic features applied; \
                 guest still boots)"
            );
        }
        Ok(())
    }

    fn set_synthetic_processor_features_banks(partition: PartitionHandle) -> Result<(), HResult> {
        let banks = get_capability_synthetic_processor_features_banks()?;
        let property = WHV_PARTITION_PROPERTY {
            SyntheticProcessorFeaturesBanks: banks,
        };
        // SAFETY: `property` is initialized for the SyntheticProcessorFeaturesBanks
        // property code and the buffer size matches the WHP union size.
        let hr = unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks,
                ptr::from_ref(&property).cast::<c_void>(),
                size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    fn set_processor_clock_frequency(
        partition: PartitionHandle,
        frequency: u64,
    ) -> Result<(), HResult> {
        let property = WHV_PARTITION_PROPERTY {
            ProcessorClockFrequency: frequency,
        };
        // SAFETY: `property` is initialized for the ProcessorClockFrequency
        // property code and the buffer size matches the WHP union size.
        let hr = unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeProcessorClockFrequency,
                ptr::from_ref(&property).cast::<c_void>(),
                size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    fn set_interrupt_clock_frequency(
        partition: PartitionHandle,
        frequency: u64,
    ) -> Result<(), HResult> {
        let property = WHV_PARTITION_PROPERTY {
            InterruptClockFrequency: frequency,
        };
        // SAFETY: `property` is initialized for the InterruptClockFrequency
        // property code and the buffer size matches the WHP union size.
        let hr = unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeInterruptClockFrequency,
                ptr::from_ref(&property).cast::<c_void>(),
                size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn set_cpuid_results(
        partition: PartitionHandle,
        results: &[CpuidResult],
    ) -> Result<(), HResult> {
        let whp_results: Vec<WHV_X64_CPUID_RESULT> = results
            .iter()
            .map(|r| WHV_X64_CPUID_RESULT {
                Function: r.function,
                Reserved: [0; 3],
                Eax: r.eax,
                Ebx: r.ebx,
                Ecx: r.ecx,
                Edx: r.edx,
            })
            .collect();
        if whp_results.is_empty() {
            return Ok(());
        }
        let size = whp_results
            .len()
            .checked_mul(size_of::<WHV_X64_CPUID_RESULT>())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(HResult(E_FAIL))?;
        // SAFETY: the slice points to initialized CPUID result entries and
        // WHP copies them before returning. The buffer size is exactly the
        // byte length of the slice.
        let hr = unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeCpuidResultList,
                whp_results.as_ptr().cast::<c_void>(),
                size,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn set_cpuid_exit_list(
        partition: PartitionHandle,
        exits: &[u32],
    ) -> Result<(), HResult> {
        if exits.is_empty() {
            return Ok(());
        }
        let size = exits
            .len()
            .checked_mul(size_of::<u32>())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(HResult(E_FAIL))?;
        // SAFETY: `exits` is an initialized array of CPUID function numbers
        // and WHP copies it before returning.
        let hr = unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeCpuidExitList,
                exits.as_ptr().cast::<c_void>(),
                size,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn setup_partition(partition: PartitionHandle) -> Result<(), HResult> {
        // SAFETY: the partition handle was returned by WHvCreatePartition and
        // required properties have been configured.
        let hr = unsafe { WHvSetupPartition(partition) };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn create_virtual_processor(
        partition: PartitionHandle,
        idx: u32,
    ) -> Result<(), HResult> {
        // SAFETY: the partition handle is valid and WHP owns vCPU state for
        // this partition/index after successful creation.
        let hr = unsafe { WHvCreateVirtualProcessor(partition, idx, 0) };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn delete_virtual_processor(
        partition: PartitionHandle,
        idx: u32,
    ) -> Result<(), HResult> {
        #[cfg(test)]
        if FAIL_NEXT_VCPU_DELETE.with(|fail| fail.replace(false)) {
            return Err(HResult(E_FAIL));
        }
        // SAFETY: the partition is live and the owner has finished running this vCPU.
        let hr = unsafe { WHvDeleteVirtualProcessor(partition, idx) };
        if hr != S_OK {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn set_virtual_processor_registers(
        partition: PartitionHandle,
        idx: u32,
        names: &[WHV_REGISTER_NAME],
        values: &[WHV_REGISTER_VALUE],
    ) -> Result<(), HResult> {
        debug_assert_eq!(names.len(), values.len());
        // SAFETY: `names` and `values` are same-length initialized arrays
        // valid for the duration of the call; WHP copies register values.
        let hr = unsafe {
            WHvSetVirtualProcessorRegisters(
                partition,
                idx,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr(),
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn request_fixed_interrupt(
        partition: PartitionHandle,
        destination: u32,
        vector: u8,
    ) -> Result<(), HResult> {
        let interrupt = WHV_INTERRUPT_CONTROL {
            _bitfield: (WHvX64InterruptTypeFixed as u64)
                | ((WHvX64InterruptDestinationModePhysical as u64) << 8)
                | ((WHvX64InterruptTriggerModeEdge as u64) << 12),
            Destination: destination,
            Vector: u32::from(vector),
        };
        // SAFETY: `interrupt` is an initialized WHV_INTERRUPT_CONTROL with a
        // fixed, edge-triggered local-APIC vector request.
        let hr = unsafe {
            WHvRequestInterrupt(
                partition,
                ptr::from_ref(&interrupt),
                size_of::<WHV_INTERRUPT_CONTROL>() as u32,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn cancel_run_virtual_processor(
        partition: PartitionHandle,
        idx: u32,
    ) -> Result<(), HResult> {
        // SAFETY: requests cancellation of the active or next WHP run for `idx`
        // in this partition; flags must be zero per the WHP API.
        let hr = unsafe { WHvCancelRunVirtualProcessor(partition, idx, 0) };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn run_virtual_processor(
        partition: PartitionHandle,
        idx: u32,
        pio_read: &dyn Fn(u16, u8) -> u32,
        mmio_read: &dyn Fn(u64, &mut [u8]) -> bool,
    ) -> Result<RunExit, HResult> {
        loop {
            let mut exit = WHV_RUN_VP_EXIT_CONTEXT::default();
            // SAFETY: `exit` points to writable storage of the exact WHP exit
            // context size for this ABI version.
            let hr = unsafe {
                WHvRunVirtualProcessor(
                    partition,
                    idx,
                    ptr::from_mut(&mut exit).cast::<c_void>(),
                    size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                )
            };
            if failed(hr) {
                return Err(HResult(hr));
            }

            match exit.ExitReason {
                EXIT_X64_CPUID => emulate_cpuid_exit(partition, idx, &exit)?,
                EXIT_X64_HALT => return Ok(RunExit::Halted),
                EXIT_X64_IO_PORT_ACCESS => {
                    return emulate_io_exit(partition, idx, &exit, pio_read, mmio_read);
                }
                EXIT_MEMORY_ACCESS => {
                    return emulate_mmio_exit(partition, idx, &exit, pio_read, mmio_read);
                }
                EXIT_UNRECOVERABLE_EXCEPTION => return Ok(RunExit::Shutdown),
                EXIT_CANCELED => return Ok(RunExit::Canceled),
                other => return Ok(RunExit::Unknown(format!("WHP exit reason {other}"))),
            }
        }
    }

    fn emulate_cpuid_exit(
        partition: PartitionHandle,
        idx: u32,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
    ) -> Result<(), HResult> {
        let cpuid = unsafe { exit.Anonymous.CpuidAccess };
        let mut rax = cpuid.DefaultResultRax;
        let mut rbx = cpuid.DefaultResultRbx;
        let mut rcx = cpuid.DefaultResultRcx;
        let mut rdx = cpuid.DefaultResultRdx;
        if cpuid.Rax as u32 == 1 {
            (rax, rbx, rcx, rdx) = hyperv_leaf1_cpuid(idx, rax, rbx, rcx, rdx);
        }

        let instruction_len = u64::from(exit.VpContext._bitfield & 0x0f);
        let names = [
            WHvX64RegisterRip,
            WHvX64RegisterRax,
            WHvX64RegisterRbx,
            WHvX64RegisterRcx,
            WHvX64RegisterRdx,
        ];
        let mut values = [WHV_REGISTER_VALUE::default(); 5];
        values[0].Reg64 = exit.VpContext.Rip + instruction_len;
        values[1].Reg64 = rax;
        values[2].Reg64 = rbx;
        values[3].Reg64 = rcx;
        values[4].Reg64 = rdx;
        set_virtual_processor_registers(partition, idx, &names, &values)
    }

    fn emulate_io_exit(
        partition: PartitionHandle,
        idx: u32,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
        pio_read: &dyn Fn(u16, u8) -> u32,
        mmio_read: &dyn Fn(u64, &mut [u8]) -> bool,
    ) -> Result<RunExit, HResult> {
        let emulator = Emulator::new()?;
        let mut context = EmulationContext {
            partition,
            idx,
            pio_read,
            mmio_read,
            exit: None,
        };
        let mut status = WHV_EMULATOR_STATUS::default();
        // SAFETY: IoPortAccess is valid for the active exit reason and all
        // pointers remain valid for the synchronous emulator call.
        let hr = unsafe {
            WHvEmulatorTryIoEmulation(
                emulator.handle,
                ptr::from_mut(&mut context).cast::<c_void>(),
                ptr::from_ref(&exit.VpContext),
                ptr::from_ref(&exit.Anonymous.IoPortAccess),
                &raw mut status,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(emulated_exit(status, context.exit))
    }

    fn emulate_mmio_exit(
        partition: PartitionHandle,
        idx: u32,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
        pio_read: &dyn Fn(u16, u8) -> u32,
        mmio_read: &dyn Fn(u64, &mut [u8]) -> bool,
    ) -> Result<RunExit, HResult> {
        let emulator = Emulator::new()?;
        let mut context = EmulationContext {
            partition,
            idx,
            pio_read,
            mmio_read,
            exit: None,
        };
        let mut status = WHV_EMULATOR_STATUS::default();
        // SAFETY: MemoryAccess is valid for the active exit reason and all
        // pointers remain valid for the synchronous emulator call.
        let hr = unsafe {
            WHvEmulatorTryMmioEmulation(
                emulator.handle,
                ptr::from_mut(&mut context).cast::<c_void>(),
                ptr::from_ref(&exit.VpContext),
                ptr::from_ref(&exit.Anonymous.MemoryAccess),
                &raw mut status,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(emulated_exit(status, context.exit))
    }

    fn emulated_exit(status: WHV_EMULATOR_STATUS, exit: Option<RunExit>) -> RunExit {
        // WHV_EMULATOR_STATUS bit 0 is EmulationSuccessful.
        let bits = unsafe { status.AsUINT32 };
        if (bits & 0x1) == 0 {
            return RunExit::Unknown(format!("WHP emulation failed, status={bits:#x}"));
        }
        exit.unwrap_or_else(|| {
            RunExit::Unknown("WHP emulation completed without device access".to_string())
        })
    }

    struct Emulator {
        handle: *const c_void,
    }

    impl Emulator {
        fn new() -> Result<Self, HResult> {
            let callbacks = WHV_EMULATOR_CALLBACKS {
                Size: size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
                Reserved: 0,
                WHvEmulatorIoPortCallback: Some(io_port_callback),
                WHvEmulatorMemoryCallback: Some(memory_callback),
                WHvEmulatorGetVirtualProcessorRegisters: Some(get_registers_callback),
                WHvEmulatorSetVirtualProcessorRegisters: Some(set_registers_callback),
                WHvEmulatorTranslateGvaPage: Some(translate_gva_callback),
            };
            let mut handle = ptr::null_mut();
            // SAFETY: callbacks points to a fully initialized callback table,
            // and WHP writes one emulator handle to `handle`.
            let hr =
                unsafe { WHvEmulatorCreateEmulator(ptr::from_ref(&callbacks), &raw mut handle) };
            if failed(hr) {
                return Err(HResult(hr));
            }
            Ok(Self { handle })
        }
    }

    impl Drop for Emulator {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: best-effort cleanup of an emulator handle returned
                // by WHvEmulatorCreateEmulator.
                let _ = unsafe { WHvEmulatorDestroyEmulator(self.handle) };
            }
        }
    }

    struct EmulationContext<'a> {
        partition: PartitionHandle,
        idx: u32,
        pio_read: &'a dyn Fn(u16, u8) -> u32,
        mmio_read: &'a dyn Fn(u64, &mut [u8]) -> bool,
        exit: Option<RunExit>,
    }

    unsafe extern "system" fn io_port_callback(
        context: *const c_void,
        io_access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> i32 {
        callback_guard(|| {
            let context = unsafe { &mut *(context.cast_mut().cast::<EmulationContext<'_>>()) };
            let io = unsafe { &mut *io_access };
            let size = (io.AccessSize as u8).min(4);
            if io.Direction == 0 {
                let value = (context.pio_read)(io.Port, size);
                io.Data = value;
                context.exit = Some(RunExit::PioRead {
                    port: io.Port,
                    size,
                });
            } else {
                let mut data = [0u8; 4];
                data[..size as usize].copy_from_slice(&io.Data.to_le_bytes()[..size as usize]);
                context.exit = Some(RunExit::PioWrite {
                    port: io.Port,
                    data,
                    size,
                });
            }
            S_OK
        })
    }

    unsafe extern "system" fn memory_callback(
        context: *const c_void,
        memory_access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> i32 {
        callback_guard(|| {
            let context = unsafe { &mut *(context.cast_mut().cast::<EmulationContext<'_>>()) };
            let memory = unsafe { &mut *memory_access };
            let size = memory.AccessSize.min(8);
            if memory.Direction == 0 {
                let data = &mut memory.Data[..size as usize];
                if !(context.mmio_read)(memory.GpaAddress, data) {
                    data.fill(0);
                }
                context.exit = Some(RunExit::MmioRead {
                    addr: memory.GpaAddress,
                    size,
                });
            } else {
                let mut data = [0u8; 8];
                data[..size as usize].copy_from_slice(&memory.Data[..size as usize]);
                context.exit = Some(RunExit::MmioWrite {
                    addr: memory.GpaAddress,
                    data,
                    size,
                });
            }
            S_OK
        })
    }

    unsafe extern "system" fn get_registers_callback(
        context: *const c_void,
        names: *const WHV_REGISTER_NAME,
        count: u32,
        values: *mut WHV_REGISTER_VALUE,
    ) -> i32 {
        callback_guard(|| {
            let context = unsafe { &*(context.cast::<EmulationContext<'_>>()) };
            let hr = unsafe {
                WHvGetVirtualProcessorRegisters(
                    context.partition,
                    context.idx,
                    names,
                    count,
                    values,
                )
            };
            if failed(hr) { hr } else { S_OK }
        })
    }

    unsafe extern "system" fn set_registers_callback(
        context: *const c_void,
        names: *const WHV_REGISTER_NAME,
        count: u32,
        values: *const WHV_REGISTER_VALUE,
    ) -> i32 {
        callback_guard(|| {
            let context = unsafe { &*(context.cast::<EmulationContext<'_>>()) };
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    context.partition,
                    context.idx,
                    names,
                    count,
                    values,
                )
            };
            if failed(hr) { hr } else { S_OK }
        })
    }

    unsafe extern "system" fn translate_gva_callback(
        context: *const c_void,
        gva: u64,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: *mut u64,
    ) -> i32 {
        callback_guard(|| {
            let context = unsafe { &*(context.cast::<EmulationContext<'_>>()) };
            let mut result = WHV_TRANSLATE_GVA_RESULT::default();
            let mut translated_gpa = 0;
            let hr = unsafe {
                WHvTranslateGva(
                    context.partition,
                    context.idx,
                    gva,
                    translate_flags,
                    &raw mut result,
                    &raw mut translated_gpa,
                )
            };
            if failed(hr) {
                return hr;
            }
            unsafe {
                *translation_result = result.ResultCode;
                *gpa = translated_gpa;
            }
            S_OK
        })
    }

    fn callback_guard(action: impl FnOnce() -> i32) -> i32 {
        match catch_unwind(AssertUnwindSafe(action)) {
            Ok(hr) => hr,
            Err(_) => E_FAIL,
        }
    }

    pub(super) fn map_gpa_range(
        partition: PartitionHandle,
        host: *mut c_void,
        gpa: u64,
        size: u64,
    ) -> Result<(), HResult> {
        #[cfg(test)]
        if FAIL_MAP_GPA.with(|fail| fail.get() == Some(gpa)) {
            FAIL_MAP_GPA.with(|fail| fail.set(None));
            return Err(HResult(E_FAIL));
        }
        let flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute;
        // SAFETY: `host` points into the live GuestMemoryMmap kept by `VmInner`
        // for at least as long as the GPA mapping.
        let hr = unsafe { WHvMapGpaRange(partition, host.cast_const(), gpa, size, flags) };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    fn get_capability_u32(code: WHV_CAPABILITY_CODE) -> Result<u32, HResult> {
        get_capability_value(code)
    }

    fn get_capability_u64(code: WHV_CAPABILITY_CODE) -> Result<u64, HResult> {
        get_capability_value(code)
    }

    fn get_capability_synthetic_processor_features_banks()
    -> Result<WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS, HResult> {
        get_capability_value(WHvCapabilityCodeSyntheticProcessorFeaturesBanks)
    }

    fn get_capability_value<T: Default>(code: WHV_CAPABILITY_CODE) -> Result<T, HResult> {
        let mut value = T::default();
        let mut written = 0u32;
        // SAFETY: WHP writes at most `size_of::<T>()` bytes to `value`, and
        // `written` is a valid out pointer for the reported byte count.
        let hr = unsafe {
            WHvGetCapability(
                code,
                ptr::from_mut(&mut value).cast::<c_void>(),
                size_of::<T>() as u32,
                &raw mut written,
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Vm, VmInner, guest_address_bits, raw};
    use crate::VmExit;
    use pmi::x86_64::Profile;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
    use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
    use windows_sys::Win32::System::Hypervisor::*;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_FREE, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, VirtualQuery,
    };

    #[test]
    fn hyperv_cpuid_does_not_expose_root_partition_privileges() {
        let mut leaves = BTreeMap::new();
        leaves.insert(
            1,
            raw::CpuidResult {
                function: 1,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );
        leaves.insert(
            0x4000_0000,
            raw::CpuidResult {
                function: 0x4000_0000,
                eax: 0x4000_000c,
                ebx: u32::from_le_bytes(*b"Micr"),
                ecx: u32::from_le_bytes(*b"osof"),
                edx: u32::from_le_bytes(*b"t Hv"),
            },
        );
        leaves.insert(
            0x4000_0001,
            raw::CpuidResult {
                function: 0x4000_0001,
                eax: u32::from_le_bytes(*b"Hv#1"),
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );
        leaves.insert(
            0x4000_0003,
            raw::CpuidResult {
                function: 0x4000_0003,
                eax: 0x0000_3fff,
                ebx: 0x002b_b9ff,
                ecx: 0,
                edx: 0,
            },
        );

        let results = super::hyperv_cpuid_results_from(|function| {
            leaves.get(&function).copied().unwrap_or(raw::CpuidResult {
                function,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            })
        });
        let feature_leaf = results
            .common
            .iter()
            .find(|r| r.function == 0x4000_0003)
            .expect("Hyper-V feature leaf");

        assert_eq!(
            feature_leaf.ebx, 0,
            "leaf 0x40000003 EBX advertises root/management partition privileges"
        );
        assert_eq!(
            feature_leaf.edx & (1 << 10),
            0,
            "leaf 0x40000003 EDX advertises guest crash MSRs"
        );
    }

    #[test]
    fn hyperv_cpuid_exposes_guest_initial_apic_id_per_vp() {
        let (_, vp0_rbx, vp0_rcx, _) = super::hyperv_leaf1_cpuid(0, 0, 0x0100_0000, 0, 0);
        let (_, vp1_rbx, vp1_rcx, _) = super::hyperv_leaf1_cpuid(1, 0, 0x0100_0000, 0, 0);

        assert_eq!(vp0_rbx >> 24, 0);
        assert_eq!(vp1_rbx >> 24, 1);
        assert_eq!(vp0_rcx & (1 << 31), 1 << 31);
        assert_eq!(vp1_rcx & (1 << 31), 1 << 31);
    }

    #[test]
    fn hyperv_cpuid_does_not_expose_pstate_power_management() {
        let mut leaves = BTreeMap::new();
        leaves.insert(
            0,
            raw::CpuidResult {
                function: 0,
                eax: 6,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );
        leaves.insert(
            1,
            raw::CpuidResult {
                function: 1,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );
        leaves.insert(
            6,
            raw::CpuidResult {
                function: 6,
                eax: (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 15),
                ebx: 0,
                ecx: 1,
                edx: 0,
            },
        );
        leaves.insert(
            0x4000_0000,
            raw::CpuidResult {
                function: 0x4000_0000,
                eax: 0x4000_0001,
                ebx: u32::from_le_bytes(*b"Micr"),
                ecx: u32::from_le_bytes(*b"osof"),
                edx: u32::from_le_bytes(*b"t Hv"),
            },
        );
        leaves.insert(
            0x4000_0001,
            raw::CpuidResult {
                function: 0x4000_0001,
                eax: u32::from_le_bytes(*b"Hv#1"),
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        );

        let results = super::hyperv_cpuid_results_from(|function| {
            leaves.get(&function).copied().unwrap_or(raw::CpuidResult {
                function,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            })
        });
        let power_leaf = results
            .common
            .iter()
            .find(|r| r.function == 6)
            .expect("thermal and power management leaf");

        assert_eq!(power_leaf.eax, 0);
        assert_eq!(power_leaf.ecx & 1, 0, "leaf 0x6 ECX advertises APERF/MPERF");
    }

    #[test]
    fn whp_partition_and_vcpu_lifecycle() {
        let _guard = whp_test_lock();
        let vm = Vm::new().expect("create WHP partition");
        assert!(matches!(
            vm.create_vcpu(0, Profile::V2),
            Err(Error::MemoryNotReady)
        ));
        vm.create_vcpu_without_ram_check(0, Profile::V2)
            .expect("create WHP vCPU");
    }

    #[test]
    fn whp_creates_multiple_vcpus_when_partition_count_allows_it() {
        let _guard = whp_test_lock();
        let vm = Vm::new_x86_64_with_local_apic_count(2).expect("create WHP partition");
        vm.create_vcpu_without_ram_check(0, Profile::V2)
            .expect("create WHP vCPU 0");
        vm.create_vcpu_without_ram_check(1, Profile::V2)
            .expect("create WHP vCPU 1");
    }

    #[test]
    fn whp_rejects_unavailable_cpu_profile_features() {
        let _guard = whp_test_lock();
        let vm = Vm::new().expect("create WHP partition");
        match vm.create_vcpu_without_ram_check(0, Profile::V4) {
            Ok(_) => {
                // This host exposes x86-64-v4; successful validation is the
                // correct result on newer AVX-512-capable instances.
            }
            Err(Error::HostMissingCpuFeature { profile, feature }) => {
                assert_eq!(profile, Profile::V4);
                assert!(!feature.is_empty());
            }
            Err(err) => panic!("unexpected v4 validation error: {err}"),
        }
    }

    #[test]
    fn whp_memory_map_and_write() {
        let _guard = whp_test_lock();
        let mut vm = Vm::new().expect("create WHP partition");
        vm.add_memory(0x1000_0000, 0x0020_0000)
            .expect("map guest memory");
        vm.write_guest(0x1000_1000, &[1, 2, 3, 4])
            .expect("write guest memory");
        let mappings = vm.region_mappings();
        assert_eq!(mappings, vec![(0x1000_0000, mappings[0].1, 0x0020_0000)]);
    }

    #[test]
    fn whp_partial_map_keeps_all_backing_until_the_last_native_owner() {
        if !native_test_child("whp_partial_map_keeps_all_backing_until_the_last_native_owner") {
            return;
        }
        let mut vm = Vm::new().unwrap();
        let service = vm.interrupt_controller();
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x10000), 0x1000),
            (GuestAddress(0x20000), 0x1000),
        ])
        .unwrap();
        memory.write_slice(&[0xf4], GuestAddress(0x10000)).unwrap();
        let first = AllocationProbe::new(&memory, 0);
        let second = AllocationProbe::new(&memory, 1);
        raw::FAIL_MAP_GPA.with(|fail| fail.set(Some(0x20000)));
        let error = vm.set_memory(memory).unwrap_err();
        assert!(
            matches!(error, Error::MapGpa { gpa: 0x20000, .. }),
            "expected failure at the second GPA, got {error:?}"
        );
        assert!(matches!(vm.guest_memory(), Err(Error::MemoryNotReady)));
        assert!(matches!(
            vm.create_vcpu(0, Profile::V1),
            Err(Error::MemoryNotReady)
        ));
        assert!(matches!(
            service.request_fixed_interrupt(0, 0x45),
            Err(Error::MemoryNotReady)
        ));
        assert!(matches!(
            vm.add_memory(0x30000, 0x1000),
            Err(Error::MemoryAlreadyRegistered)
        ));

        // Bypass readiness only in this fixture to prove the first real map
        // survives failure of the second map and the visible VM's destruction.
        let mut cpu = vm.create_vcpu_without_ram_check(0, Profile::V1).unwrap();
        let cancel = cpu.cancel_handle();
        drop(vm);
        set_real_mode(&cpu, 0x10000, 0);
        let exit = cpu.run(|_, _| 0, |_, _| false).unwrap();
        assert!(matches!(exit, VmExit::Halted), "{exit:?}");
        drop(cpu);
        first.assert_retained();
        second.assert_retained();
        drop(service);
        first.assert_retained();
        second.assert_retained();
        drop(cancel);
        first.assert_reclaimed();
        second.assert_reclaimed();
    }

    #[test]
    fn whp_setup_failure_reports_partition_cleanup_failure() {
        if !native_test_child("whp_setup_failure_reports_partition_cleanup_failure") {
            return;
        }
        let before = raw::DELETED_PARTITIONS.with(std::cell::Cell::get);
        for fail_delete in [false, true] {
            let inner = VmInner::new().unwrap();
            // The required ProcessorCount property has not been set.
            let setup = inner.setup();
            assert!(
                matches!(setup, Err(Error::SetupPartition(_))),
                "expected native setup failure, got {setup:?}"
            );
            raw::FAIL_NEXT_DELETE.with(|fail| fail.set(fail_delete));
            let error = inner.finish_setup(setup).unwrap_err();
            if fail_delete {
                let Error::PartitionCleanup { operation, hr } = error else {
                    panic!("expected setup and cleanup errors, got {error:?}");
                };
                assert!(matches!(*operation, Error::SetupPartition(_)));
                assert_eq!(hr, "0x80004005");
            } else {
                assert!(matches!(error, Error::SetupPartition(_)));
            }
            assert_eq!(
                raw::DELETED_PARTITIONS.with(std::cell::Cell::get),
                before + 1
            );
        }
    }

    #[test]
    fn whp_address_width_probe_reports_cleanup_failures() {
        if !native_test_child("whp_address_width_probe_reports_cleanup_failures") {
            return;
        }
        let deleted = || raw::DELETED_PARTITIONS.with(std::cell::Cell::get);
        let before = deleted();
        guest_address_bits().unwrap();
        assert_eq!(deleted(), before + 1);

        let failed = "0x80004005";
        raw::FAIL_NEXT_GUEST_PHYSICAL_BITS.with(|fail| fail.set(true));
        let error = guest_address_bits().unwrap_err();
        assert!(
            matches!(&error, Error::AddressSpace(hr) if hr == failed),
            "{error:?}"
        );
        assert_eq!(deleted(), before + 2);

        raw::FAIL_NEXT_DELETE.with(|fail| fail.set(true));
        let error = guest_address_bits().unwrap_err();
        assert!(
            matches!(&error, Error::DeleteProbePartition(hr) if hr == failed),
            "{error:?}"
        );
        assert_eq!(deleted(), before + 2);

        raw::FAIL_NEXT_GUEST_PHYSICAL_BITS.with(|fail| fail.set(true));
        raw::FAIL_NEXT_DELETE.with(|fail| fail.set(true));
        let error = guest_address_bits().unwrap_err();
        let Error::PartitionCleanup { operation, hr } = error else {
            panic!("expected query and cleanup errors, got {error:?}");
        };
        assert!(matches!(*operation, Error::AddressSpace(hr) if hr == failed));
        assert_eq!(hr, failed);
        assert_eq!(deleted(), before + 2);

        raw::FAIL_NEXT_VCPU_DELETE.with(|fail| fail.set(true));
        let error = guest_address_bits().unwrap_err();
        assert!(matches!(error, Error::DeleteVcpu { idx: 0, hr } if hr == failed));
        assert_eq!(deleted(), before + 3);

        raw::FAIL_NEXT_GUEST_PHYSICAL_BITS.with(|fail| fail.set(true));
        raw::FAIL_NEXT_VCPU_DELETE.with(|fail| fail.set(true));
        let error = guest_address_bits().unwrap_err();
        let Error::VcpuCleanup {
            operation,
            retirement,
        } = error
        else {
            panic!("expected query and vCPU cleanup errors, got {error:?}");
        };
        assert!(matches!(*operation, Error::AddressSpace(hr) if hr == failed));
        assert!(matches!(*retirement, Error::DeleteVcpu { idx: 0, hr } if hr == failed));
        assert_eq!(deleted(), before + 4);
    }

    #[test]
    fn whp_vcpu_retirement_checks_deletion_without_retry() {
        if !native_test_child("whp_vcpu_retirement_checks_deletion_without_retry") {
            return;
        }
        let mut vm = Vm::new_x86_64_with_local_apic_count(1).unwrap();
        let create = || vm.create_vcpu_without_ram_check(0, Profile::V1).unwrap();
        create().retire().unwrap();

        let mut vcpu = create();
        raw::FAIL_NEXT_VCPU_DELETE.with(|fail| fail.set(true));
        let error = vcpu.retire().unwrap_err();
        assert!(
            matches!(error, Error::DeleteVcpu { idx: 0, ref hr } if hr == "0x80004005"),
            "{error:?}"
        );
        drop(vcpu);
        // The injected failure left a live vCPU for the partition to reclaim.
        raw::guest_physical_bits(vm.inner.partition, 0).unwrap();
        Arc::get_mut(&mut vm.inner).unwrap().retire().unwrap();
    }

    #[test]
    fn whp_failed_partition_delete_retains_live_backing() {
        if native_test_child("whp_failed_partition_delete_retains_live_backing") {
            check_failed_partition_delete(false);
        }
    }

    #[test]
    fn whp_failed_map_and_delete_retains_attempted_backing() {
        if native_test_child("whp_failed_map_and_delete_retains_attempted_backing") {
            check_failed_partition_delete(true);
        }
    }

    fn check_failed_partition_delete(fail_map: bool) {
        let mut vm = Vm::new().unwrap();
        let partition = vm.inner.partition;
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x10000), 0x1000),
            (GuestAddress(0x20000), 0x1000),
        ])
        .unwrap();
        let probes = [
            AllocationProbe::new(&memory, 0),
            AllocationProbe::new(&memory, 1),
        ];
        raw::FAIL_NEXT_DELETE.with(|fail| fail.set(true));
        if fail_map {
            raw::FAIL_MAP_GPA.with(|fail| fail.set(Some(0x20000)));
            let error = vm.set_memory(memory).unwrap_err();
            let Error::PartitionCleanup { operation, hr } = error else {
                panic!("expected map and cleanup errors, got {error:?}");
            };
            assert!(
                matches!(*operation, Error::MapGpa { gpa: 0x20000, .. }),
                "expected failure at the second GPA, got {operation:?}"
            );
            assert_eq!(hr, "0x80004005");
            assert!(matches!(
                vm.add_memory(0x30000, 0x1000),
                Err(Error::MemoryAlreadyRegistered)
            ));
        } else {
            vm.set_memory(memory).unwrap();
        }
        drop(vm);
        for probe in probes {
            probe.assert_retained();
        }
        // Both the actual partition and its backing remain live after Drop.
        raw::create_virtual_processor(partition, 0).unwrap();
        raw::delete_virtual_processor(partition, 0).unwrap();
    }

    struct AllocationProbe {
        address: usize,
        original: Weak<vm_memory::mmap::MmapRegion<()>>,
    }

    impl AllocationProbe {
        fn new(memory: &GuestMemoryMmap, index: usize) -> Self {
            let region = memory.iter().nth(index).unwrap();
            let mmap = region.get_mmap();
            Self {
                address: mmap.as_ptr() as usize,
                original: Arc::downgrade(&mmap),
            }
        }

        fn query(&self) -> MEMORY_BASIC_INFORMATION {
            let mut information = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: VirtualQuery fills a VM information record and never
            // dereferences the allocation address being queried.
            #[allow(unsafe_code)]
            let length = unsafe {
                VirtualQuery(
                    self.address as *const _,
                    &raw mut information,
                    std::mem::size_of_val(&information),
                )
            };
            assert_eq!(
                length,
                std::mem::size_of_val(&information),
                "VirtualQuery failed: {}",
                std::io::Error::last_os_error()
            );
            information
        }

        fn assert_retained(&self) {
            let original = self.original.upgrade().expect("backing was released");
            assert_eq!(original.as_ptr() as usize, self.address);
            let information = self.query();
            assert_eq!(information.AllocationBase as usize, self.address);
            assert_eq!(information.State, MEM_COMMIT);
            assert_eq!(information.Type, MEM_PRIVATE);
        }

        fn assert_reclaimed(&self) {
            assert!(self.original.upgrade().is_none());
            assert_eq!(self.query().State, MEM_FREE);
        }
    }

    #[test]
    fn whp_runs_to_hlt_after_refusing_ram_replacement() {
        let _guard = whp_test_lock();
        let mut vm = Vm::new().expect("create WHP partition");
        let code_base = 0x1_0000;
        vm.add_memory(code_base, 0x1000).expect("map guest memory");
        vm.write_guest(code_base, &[0xF4]).expect("write hlt");
        assert!(matches!(
            vm.add_memory(code_base, 0x1000),
            Err(Error::MemoryAlreadyRegistered)
        ));

        let mut vcpu = vm.create_vcpu(0, Profile::V2).expect("create WHP vCPU");
        set_real_mode(&vcpu, code_base, 0);

        let exit = vcpu.run(|_, _| 0, |_, _| false).expect("run vCPU");
        assert!(matches!(exit, VmExit::Halted), "expected HLT, got {exit:?}");
    }

    #[test]
    fn whp_emulates_pio_write_and_advances_to_hlt() {
        let _guard = whp_test_lock();
        let mut vm = Vm::new().expect("create WHP partition");
        let code_base = 0x2_0000;
        vm.add_memory(code_base, 0x1000).expect("map guest memory");
        // out 0x42, al; hlt
        vm.write_guest(code_base, &[0xE6, 0x42, 0xF4])
            .expect("write code");

        let mut vcpu = vm.create_vcpu(0, Profile::V2).expect("create WHP vCPU");
        set_real_mode(&vcpu, code_base, 0x5A);

        let exit = vcpu.run(|_, _| 0, |_, _| false).expect("run out");
        match exit {
            VmExit::PioWrite { port, data, size } => {
                assert_eq!(port, 0x42);
                assert_eq!(size, 1);
                assert_eq!(data[0], 0x5A);
            }
            other => panic!("expected PIO write, got {other:?}"),
        }

        let exit = vcpu.run(|_, _| 0, |_, _| false).expect("run hlt");
        assert!(matches!(exit, VmExit::Halted), "expected HLT, got {exit:?}");
    }

    #[test]
    fn whp_emulates_mmio_write_and_advances_to_hlt() {
        let _guard = whp_test_lock();
        let mut vm = Vm::new().expect("create WHP partition");
        let code_base = 0x3_0000;
        vm.add_memory(code_base, 0x1000).expect("map guest memory");
        // mov byte ptr [0x2000], al; hlt. 0x2000 is intentionally unmapped
        // so WHP exits and WinHvEmulation decodes/completes the write.
        vm.write_guest(code_base, &[0xA2, 0x00, 0x20, 0xF4])
            .expect("write code");

        let mut vcpu = vm.create_vcpu(0, Profile::V2).expect("create WHP vCPU");
        set_real_mode(&vcpu, code_base, 0xA5);

        let exit = vcpu.run(|_, _| 0, |_, _| false).expect("run mmio write");
        match exit {
            VmExit::MmioWrite { addr, data, size } => {
                assert_eq!(addr, 0x2000);
                assert_eq!(size, 1);
                assert_eq!(data[0], 0xA5);
            }
            other => panic!("expected MMIO write, got {other:?}"),
        }

        let exit = vcpu.run(|_, _| 0, |_, _| false).expect("run hlt");
        assert!(matches!(exit, VmExit::Halted), "expected HLT, got {exit:?}");
    }

    fn set_real_mode(vcpu: &super::Vcpu, code_base: u64, rax: u64) {
        let mut registers = Vec::new();
        for (name, value) in [
            (WHvX64RegisterRip, 0),
            (WHvX64RegisterRflags, 2),
            (WHvX64RegisterCr0, 0x10),
            (WHvX64RegisterRax, rax),
        ] {
            super::push_reg64(&mut registers, name, value);
        }
        for (name, base, attributes) in [
            (WHvX64RegisterCs, code_base, 0x9b),
            (WHvX64RegisterDs, 0, 0x93),
            (WHvX64RegisterEs, 0, 0x93),
            (WHvX64RegisterFs, 0, 0x93),
            (WHvX64RegisterGs, 0, 0x93),
            (WHvX64RegisterSs, 0, 0x93),
            (WHvX64RegisterTr, 0, 0x8b),
            (WHvX64RegisterLdtr, 0, 0x82),
        ] {
            registers.push((
                name,
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER {
                        Base: base,
                        Limit: 0xffff,
                        Selector: 0,
                        Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                            Attributes: attributes,
                        },
                    },
                },
            ));
        }
        vcpu.set_registers(registers).unwrap();
    }

    fn whp_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn native_test_child(name: &str) -> bool {
        use std::time::{Duration, Instant};

        const CHILD_TEST: &str = "DILLO_WHP_NATIVE_TEST";
        if std::env::var_os(CHILD_TEST).as_deref() == Some(name.as_ref()) {
            return true;
        }

        // Isolate deliberately retained partitions and virtual address
        // reclamation checks from other tests in the same process.
        let _guard = whp_test_lock();
        let test = format!("hypervisor::tests::{name}");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([&test, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_TEST, name)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(
                        status.success(),
                        "{name} failed in its child process: {status}"
                    );
                    return false;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{name} did not complete within its child process: {result:?}");
                }
            }
        }
    }
}
