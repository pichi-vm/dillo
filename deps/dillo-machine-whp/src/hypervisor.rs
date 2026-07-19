// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows Hypervisor Platform backend.
//!
//! This starts with the narrow lifecycle that proves Dillo can own a WHP
//! partition through the same concrete `Vm` / `Vcpu` surface used by the
//! Linux and macOS backends. Register state, memory mapping, and exit
//! translation are added in later phases.

use std::sync::Arc;

use thiserror::Error;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0,
    WHV_X64_TABLE_REGISTER, WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4,
    WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEfer, WHvX64RegisterEs, WHvX64RegisterFs,
    WHvX64RegisterGdtr, WHvX64RegisterGs, WHvX64RegisterIdtr, WHvX64RegisterLdtr, WHvX64RegisterR8,
    WHvX64RegisterR9, WHvX64RegisterR10, WHvX64RegisterR11, WHvX64RegisterR12, WHvX64RegisterR13,
    WHvX64RegisterR14, WHvX64RegisterR15, WHvX64RegisterRax, WHvX64RegisterRbp, WHvX64RegisterRbx,
    WHvX64RegisterRcx, WHvX64RegisterRdi, WHvX64RegisterRdx, WHvX64RegisterRflags,
    WHvX64RegisterRip, WHvX64RegisterRsi, WHvX64RegisterRsp, WHvX64RegisterSs, WHvX64RegisterTr,
};

use crate::VmExit;
use crate::cpuid_x86;

#[derive(Debug, Error)]
pub enum Error {
    #[error("WHP capability HypervisorPresent query failed: {0}")]
    Capability(String),

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

    #[error("WHP create vCPU {idx} failed: {hr}")]
    CreateVcpu { idx: u32, hr: String },

    #[error("WHP delete vCPU {idx} failed: {hr}")]
    DeleteVcpu { idx: u32, hr: String },

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

    #[error("cpu:profile {profile:?} not recognized by dillo")]
    UnknownCpuProfile { profile: String },

    #[error(
        "cpu:profile {profile:?} requires host CPUID feature `{feature}` which is not available"
    )]
    HostMissingCpuFeature {
        profile: String,
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

    #[error("WHP guest address {0:#x} is not in any mapped region")]
    UnmappedGuestAddr(u64),

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

#[derive(Debug)]
pub(crate) struct Vm {
    regions: Vec<Region>,
    memory: Option<GuestMemoryMmap>,
    inner: Arc<VmInner>,
}

#[derive(Debug)]
struct VmInner {
    partition: raw::PartitionHandle,
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

        let partition = raw::create_partition().map_err(|hr| Error::CreatePartition(status(hr)))?;

        let inner = VmInner { partition };
        if options.processor_count == 0 {
            drop(inner);
            return Err(Error::EmptyProcessorCount);
        }

        let setup_result = inner
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
        if let Err(err) = setup_result {
            drop(inner);
            return Err(err);
        }

        Ok(Self {
            regions: Vec::new(),
            memory: None,
            inner: Arc::new(inner),
        })
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
        self.regions.clear();
        for region in memory.iter() {
            let base = region.start_addr().raw_value();
            let size = region.len();
            let host_addr = memory
                .get_host_address(region.start_addr())
                .map_err(|source| Error::GuestMemoryHostAddress { gpa: base, source })?;
            if let Err(hr) = raw::map_gpa_range(self.inner.partition, host_addr.cast(), base, size)
            {
                let end = base.saturating_add(size);
                self.regions.clear();
                return Err(Error::MapGpa {
                    gpa: base,
                    end,
                    hr: status(hr),
                });
            }
            self.regions.push(Region {
                base,
                size,
                partition: self.inner.partition,
            });
        }
        self.memory = Some(memory);
        Ok(())
    }

    pub(crate) fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        let memory = self.memory.as_ref().ok_or(Error::UnmappedGuestAddr(gpa))?;
        memory
            .write(data, GuestAddress(gpa))
            .map_err(|source| Error::WriteGuest { gpa, source })?;
        Ok(())
    }

    pub(crate) fn guest_memory(&self) -> Result<GuestMemoryMmap, Error> {
        self.memory.clone().ok_or(Error::UnmappedGuestAddr(0))
    }

    #[cfg(test)]
    pub(crate) fn region_mappings(&self) -> Vec<(u64, u64, u64)> {
        let Some(memory) = &self.memory else {
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

    pub(crate) fn create_vcpu(&self, idx: u32, cpu_profile: &str) -> Result<Vcpu, Error> {
        validate_cpu_profile(cpu_profile)?;
        raw::create_virtual_processor(self.inner.partition, idx).map_err(|hr| {
            Error::CreateVcpu {
                idx,
                hr: status(hr),
            }
        })?;
        Ok(Vcpu {
            partition: Arc::clone(&self.inner),
            idx,
        })
    }

    pub(crate) fn interrupt_controller(&self) -> InterruptController {
        InterruptController {
            inner: Arc::clone(&self.inner),
        }
    }
}

fn validate_cpu_profile(cpu_profile: &str) -> Result<(), Error> {
    let level =
        cpuid_x86::X86Level::parse(cpu_profile).ok_or_else(|| Error::UnknownCpuProfile {
            profile: cpu_profile.to_string(),
        })?;
    if let Some(missing) = cpuid_x86::first_missing_native(level) {
        return Err(Error::HostMissingCpuFeature {
            profile: level.as_str().to_string(),
            feature: missing,
        });
    }
    Ok(())
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
        raw::request_fixed_interrupt(self.inner.partition, destination, vector)
            .map_err(|hr| Error::RequestInterrupt(status(hr)))
    }
}

#[derive(Debug)]
struct Region {
    base: u64,
    size: u64,
    partition: raw::PartitionHandle,
}

impl Drop for Region {
    fn drop(&mut self) {
        raw::unmap_gpa_range(self.partition, self.base, self.size);
    }
}

impl VmInner {
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
        raw::delete_partition(self.partition);
    }
}

#[derive(Debug)]
pub(crate) struct Vcpu {
    partition: Arc<VmInner>,
    idx: u32,
}

impl Vcpu {
    pub(crate) fn cancel_handle(&self) -> VcpuCancel {
        VcpuCancel {
            partition: Arc::clone(&self.partition),
            idx: self.idx,
        }
    }

    pub(crate) fn set_x86_64_state(
        &mut self,
        state: &pmi::vm::vcpu::x86_64::CpuState,
    ) -> Result<(), Error> {
        let mut registers = Vec::with_capacity(34);

        push_reg64(&mut registers, WHvX64RegisterRip, state.rip);
        push_reg64(&mut registers, WHvX64RegisterRsp, state.rsp);
        push_reg64(
            &mut registers,
            WHvX64RegisterRflags,
            if state.rflags.get() == 0 {
                0x2
            } else {
                state.rflags.get()
            },
        );
        push_reg64(&mut registers, WHvX64RegisterRax, state.rax);
        push_reg64(&mut registers, WHvX64RegisterRbx, state.rbx);
        push_reg64(&mut registers, WHvX64RegisterRcx, state.rcx);
        push_reg64(&mut registers, WHvX64RegisterRdx, state.rdx);
        push_reg64(&mut registers, WHvX64RegisterRsi, state.rsi);
        push_reg64(&mut registers, WHvX64RegisterRdi, state.rdi);
        push_reg64(&mut registers, WHvX64RegisterRbp, state.rbp);
        push_reg64(&mut registers, WHvX64RegisterR8, state.r8);
        push_reg64(&mut registers, WHvX64RegisterR9, state.r9);
        push_reg64(&mut registers, WHvX64RegisterR10, state.r10);
        push_reg64(&mut registers, WHvX64RegisterR11, state.r11);
        push_reg64(&mut registers, WHvX64RegisterR12, state.r12);
        push_reg64(&mut registers, WHvX64RegisterR13, state.r13);
        push_reg64(&mut registers, WHvX64RegisterR14, state.r14);
        push_reg64(&mut registers, WHvX64RegisterR15, state.r15);
        push_reg64(&mut registers, WHvX64RegisterCr0, state.cr0);
        push_reg64(&mut registers, WHvX64RegisterCr3, state.cr3);
        push_reg64(&mut registers, WHvX64RegisterCr4, state.cr4);
        push_reg64(&mut registers, WHvX64RegisterEfer, state.efer);

        push_segment(&mut registers, WHvX64RegisterCs, &state.cs);
        push_segment(&mut registers, WHvX64RegisterDs, &state.ds);
        push_segment(&mut registers, WHvX64RegisterEs, &state.es);
        push_segment(&mut registers, WHvX64RegisterFs, &state.fs);
        push_segment(&mut registers, WHvX64RegisterGs, &state.gs);
        push_segment(&mut registers, WHvX64RegisterSs, &state.ss);
        push_table(&mut registers, WHvX64RegisterGdtr, &state.gdtr);
        push_table(&mut registers, WHvX64RegisterIdtr, &state.idtr);

        push_whp_segment(&mut registers, WHvX64RegisterTr, default_tr());
        push_whp_segment(&mut registers, WHvX64RegisterLdtr, default_ldtr());

        let (names, values): (Vec<_>, Vec<_>) = registers.into_iter().unzip();
        raw::set_virtual_processor_registers(self.partition.partition, self.idx, &names, &values)
            .map_err(|hr| Error::SetRegisters {
            idx: self.idx,
            hr: status(hr),
        })?;
        Ok(())
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
        raw::delete_virtual_processor(self.partition.partition, self.idx);
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

fn push_segment(
    registers: &mut Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)>,
    name: WHV_REGISTER_NAME,
    segment: &pmi::vm::vcpu::x86_64::SegReg,
) {
    // vm.md packs the AVL/L/D-B/G flags at bits 8-11; WHV_X64_SEGMENT_REGISTER
    // expects them at bits 12-15 (Available/Long/Default/Granularity), with
    // 8-11 reserved. Shift the flag nibble up while keeping type/S/DPL/P.
    let pmi_attr = segment.attributes.get();
    let whv_attr = (pmi_attr & 0x00FF) | ((pmi_attr & 0x0F00) << 4);
    push_whp_segment(
        registers,
        name,
        WHV_X64_SEGMENT_REGISTER {
            Base: segment.base,
            Limit: segment.limit,
            Selector: segment.selector,
            Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                Attributes: whv_attr,
            },
        },
    );
}

fn push_whp_segment(
    registers: &mut Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)>,
    name: WHV_REGISTER_NAME,
    segment: WHV_X64_SEGMENT_REGISTER,
) {
    registers.push((name, WHV_REGISTER_VALUE { Segment: segment }));
}

fn push_table(
    registers: &mut Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)>,
    name: WHV_REGISTER_NAME,
    table: &pmi::vm::vcpu::x86_64::Dtr,
) {
    registers.push((
        name,
        WHV_REGISTER_VALUE {
            Table: WHV_X64_TABLE_REGISTER {
                Pad: [0; 3],
                Limit: table.limit,
                Base: table.base,
            },
        },
    ));
}

fn default_tr() -> WHV_X64_SEGMENT_REGISTER {
    WHV_X64_SEGMENT_REGISTER {
        Base: 0,
        Limit: 0xFFFF,
        Selector: 0,
        Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x8B },
    }
}

fn default_ldtr() -> WHV_X64_SEGMENT_REGISTER {
    WHV_X64_SEGMENT_REGISTER {
        Base: 0,
        Limit: 0xFFFF,
        Selector: 0,
        Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0x82 },
    }
}

mod raw {
    #![allow(unsafe_code)]

    use std::ffi::c_void;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::ptr;

    use windows_sys::Win32::System::Hypervisor::{
        WHV_CAPABILITY_CODE, WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_IO_ACCESS_INFO,
        WHV_EMULATOR_MEMORY_ACCESS_INFO, WHV_EMULATOR_STATUS, WHV_INTERRUPT_CONTROL,
        WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
        WHV_RUN_VP_EXIT_CONTEXT, WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS, WHV_TRANSLATE_GVA_FLAGS,
        WHV_TRANSLATE_GVA_RESULT, WHV_TRANSLATE_GVA_RESULT_CODE, WHV_X64_CPUID_RESULT,
        WHvCancelRunVirtualProcessor, WHvCapabilityCodeHypervisorPresent,
        WHvCapabilityCodeInterruptClockFrequency, WHvCapabilityCodeProcessorClockFrequency,
        WHvCapabilityCodeSyntheticProcessorFeaturesBanks, WHvCreatePartition,
        WHvCreateVirtualProcessor, WHvDeletePartition, WHvDeleteVirtualProcessor,
        WHvEmulatorCreateEmulator, WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation,
        WHvEmulatorTryMmioEmulation, WHvGetCapability, WHvGetVirtualProcessorRegisters,
        WHvMapGpaRange, WHvMapGpaRangeFlagExecute, WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite,
        WHvPartitionPropertyCodeCpuidExitList, WHvPartitionPropertyCodeCpuidResultList,
        WHvPartitionPropertyCodeInterruptClockFrequency,
        WHvPartitionPropertyCodeLocalApicEmulationMode,
        WHvPartitionPropertyCodeProcessorClockFrequency, WHvPartitionPropertyCodeProcessorCount,
        WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks, WHvRequestInterrupt,
        WHvRunVirtualProcessor, WHvRunVpExitReasonCanceled, WHvRunVpExitReasonMemoryAccess,
        WHvRunVpExitReasonUnrecoverableException, WHvRunVpExitReasonX64Cpuid,
        WHvRunVpExitReasonX64Halt, WHvRunVpExitReasonX64IoPortAccess, WHvSetPartitionProperty,
        WHvSetVirtualProcessorRegisters, WHvSetupPartition, WHvTranslateGva, WHvUnmapGpaRange,
        WHvX64InterruptDestinationModePhysical, WHvX64InterruptTriggerModeEdge,
        WHvX64InterruptTypeFixed, WHvX64LocalApicEmulationModeXApic, WHvX64RegisterRax,
        WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRip,
    };

    use super::{HResult, failed, hyperv_leaf1_cpuid};

    pub(super) type PartitionHandle = WHV_PARTITION_HANDLE;

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

    pub(super) fn delete_partition(partition: PartitionHandle) {
        if partition != 0 {
            // SAFETY: best-effort cleanup of an owned WHP partition handle.
            let _ = unsafe { WHvDeletePartition(partition) };
        }
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

    pub(super) fn delete_virtual_processor(partition: PartitionHandle, idx: u32) {
        // SAFETY: best-effort cleanup for a vCPU index created on this
        // partition. WHP tolerates process teardown even if this fails.
        let _ = unsafe { WHvDeleteVirtualProcessor(partition, idx) };
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

    #[cfg(test)]
    pub(super) fn get_virtual_processor_register_u64(
        partition: PartitionHandle,
        idx: u32,
        name: WHV_REGISTER_NAME,
    ) -> Result<u64, HResult> {
        let names = [name];
        let mut values = [WHV_REGISTER_VALUE::default()];
        // SAFETY: `names` and `values` point to one initialized register
        // name/value slot, and WHP writes the result before returning.
        let hr = unsafe {
            WHvGetVirtualProcessorRegisters(
                partition,
                idx,
                names.as_ptr(),
                names.len() as u32,
                values.as_mut_ptr(),
            )
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        // SAFETY: caller requests only scalar u64 registers through this test
        // helper, so the Reg64 union member is the expected interpretation.
        Ok(unsafe { values[0].Reg64 })
    }

    pub(super) fn map_gpa_range(
        partition: PartitionHandle,
        host: *mut c_void,
        gpa: u64,
        size: u64,
    ) -> Result<(), HResult> {
        let flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute;
        // SAFETY: `host` points into the live GuestMemoryMmap kept by `Vm`
        // for at least as long as the GPA mapping.
        let hr = unsafe { WHvMapGpaRange(partition, host.cast_const(), gpa, size, flags) };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(())
    }

    pub(super) fn unmap_gpa_range(partition: PartitionHandle, gpa: u64, size: u64) {
        // SAFETY: best-effort cleanup of a GPA range that was previously
        // mapped on this partition.
        let _ = unsafe { WHvUnmapGpaRange(partition, gpa, size) };
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
    use super::{Error, Vm, raw};
    use crate::VmExit;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use windows_sys::Win32::System::Hypervisor::{
        WHvX64RegisterRax, WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterRsp,
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
        vm.create_vcpu(0, "x86-64-v2").expect("create WHP vCPU");
    }

    #[test]
    fn whp_creates_multiple_vcpus_when_partition_count_allows_it() {
        let _guard = whp_test_lock();
        let vm = Vm::new_x86_64_with_local_apic_count(2).expect("create WHP partition");
        vm.create_vcpu(0, "x86-64-v2").expect("create WHP vCPU 0");
        vm.create_vcpu(1, "x86-64-v2").expect("create WHP vCPU 1");
    }

    #[test]
    fn whp_rejects_unknown_cpu_profile_before_vcpu_creation() {
        let _guard = whp_test_lock();
        let vm = Vm::new().expect("create WHP partition");
        let err = vm
            .create_vcpu(0, "x86-64-v5")
            .expect_err("unknown profile must fail");
        assert!(matches!(err, Error::UnknownCpuProfile { .. }));
    }

    #[test]
    fn whp_rejects_unavailable_cpu_profile_features() {
        let _guard = whp_test_lock();
        let vm = Vm::new().expect("create WHP partition");
        match vm.create_vcpu(0, "x86-64-v4") {
            Ok(_) => {
                // This host exposes x86-64-v4; successful validation is the
                // correct result on newer AVX-512-capable instances.
            }
            Err(Error::HostMissingCpuFeature { profile, feature }) => {
                assert_eq!(profile, "x86-64-v4");
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
    fn whp_sets_pmi_x86_64_scalar_registers() {
        let _guard = whp_test_lock();
        let vm = Vm::new().expect("create WHP partition");
        let mut vcpu = vm.create_vcpu(0, "x86-64-v2").expect("create WHP vCPU");
        let state = pmi::vm::vcpu::x86_64::CpuState {
            rip: 0x1000,
            rsp: 0x8000,
            rax: 0x55AA,
            ..Default::default()
        };

        vcpu.set_x86_64_state(&state).expect("set WHP registers");

        assert_eq!(
            raw::get_virtual_processor_register_u64(
                vcpu.partition.partition,
                vcpu.idx,
                WHvX64RegisterRip,
            )
            .expect("read rip"),
            0x1000
        );
        assert_eq!(
            raw::get_virtual_processor_register_u64(
                vcpu.partition.partition,
                vcpu.idx,
                WHvX64RegisterRsp,
            )
            .expect("read rsp"),
            0x8000
        );
        assert_eq!(
            raw::get_virtual_processor_register_u64(
                vcpu.partition.partition,
                vcpu.idx,
                WHvX64RegisterRax,
            )
            .expect("read rax"),
            0x55AA
        );
        assert_eq!(
            raw::get_virtual_processor_register_u64(
                vcpu.partition.partition,
                vcpu.idx,
                WHvX64RegisterRflags,
            )
            .expect("read rflags"),
            0x2
        );
    }

    #[test]
    fn whp_runs_to_hlt_exit() {
        let _guard = whp_test_lock();
        let mut vm = Vm::new().expect("create WHP partition");
        let code_base = 0x1_0000;
        vm.add_memory(code_base, 0x1000).expect("map guest memory");
        vm.write_guest(code_base, &[0xF4]).expect("write hlt");

        let mut vcpu = vm.create_vcpu(0, "x86-64-v2").expect("create WHP vCPU");
        vcpu.set_x86_64_state(&real_mode_state(code_base, 0))
            .expect("set real-mode state");

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

        let mut vcpu = vm.create_vcpu(0, "x86-64-v2").expect("create WHP vCPU");
        let mut state = real_mode_state(code_base, 0);
        state.rax = 0x5A;
        vcpu.set_x86_64_state(&state).expect("set real-mode state");

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

        let mut vcpu = vm.create_vcpu(0, "x86-64-v2").expect("create WHP vCPU");
        let mut state = real_mode_state(code_base, 0);
        state.rax = 0xA5;
        vcpu.set_x86_64_state(&state).expect("set real-mode state");

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

    fn real_mode_state(code_base: u64, rip: u64) -> pmi::vm::vcpu::x86_64::CpuState {
        let code = pmi::vm::vcpu::x86_64::SegReg {
            selector: 0,
            attributes: pmi::vm::vcpu::x86_64::SegAttributes::new(0x9B).unwrap(),
            limit: 0xFFFF,
            base: code_base,
        };
        let data = pmi::vm::vcpu::x86_64::SegReg {
            selector: 0,
            attributes: pmi::vm::vcpu::x86_64::SegAttributes::new(0x93).unwrap(),
            limit: 0xFFFF,
            base: 0,
        };
        pmi::vm::vcpu::x86_64::CpuState {
            rip,
            rflags: pmi::vm::vcpu::x86_64::RFlags::new(0x2).unwrap(),
            cr0: 0x10,
            cs: code,
            ds: data.clone(),
            es: data.clone(),
            fs: data.clone(),
            gs: data.clone(),
            ss: data,
            ..Default::default()
        }
    }

    fn whp_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("WHP test lock poisoned")
    }
}
