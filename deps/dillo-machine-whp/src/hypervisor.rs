// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows Hypervisor Platform backend.
//!
//! This starts with the narrow lifecycle that proves Dillo can own a WHP
//! partition through the same concrete `Vm` / `Vcpu` surface used by the
//! Linux and macOS backends. Register state, memory mapping, and exit
//! translation are added in later phases.

use std::sync::{Arc, Mutex};

use dillo_mmio::{AccessError, MmioWriteOutcome};
use thiserror::Error;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use windows_sys::Win32::System::Hypervisor::{WHV_REGISTER_NAME, WHV_REGISTER_VALUE};

use crate::cpuid_x86;
use crate::{Memory, VmExit};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Mmio(#[from] AccessError),
    #[error("WHP guest address space: {0}")]
    AddressSpace(String),
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

    #[error("WHP RAM is already registered; replacement or enlargement is not allowed")]
    MemoryAlreadyRegistered,

    #[error("WHP RAM registration is not ready")]
    MemoryNotReady,

    #[error("WHP RAM registration failed after {attempts}/{regions} attempted maps")]
    MemoryRegistrationFailed { attempts: usize, regions: usize },

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
    inner: Arc<VmInner>,
}

#[derive(Debug)]
struct VmInner {
    partition: raw::PartitionHandle,
    memory: Mutex<RamRegistration>,
    #[cfg(test)]
    fail_map_at: Mutex<Option<usize>>,
    #[cfg(test)]
    fail_delete: bool,
}

#[derive(Debug)]
enum RamRegistration {
    Empty,
    Attempted { memory: Memory, attempts: usize },
    Ready(Memory),
}

impl RamRegistration {
    fn ready(&self) -> Result<&GuestMemoryMmap, Error> {
        match self {
            Self::Ready(memory) => Ok(memory.guest()),
            Self::Empty => Err(Error::MemoryNotReady),
            Self::Attempted { memory, attempts } => Err(Error::MemoryRegistrationFailed {
                attempts: *attempts,
                regions: memory.guest().num_regions(),
            }),
        }
    }
}

impl Vm {
    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, Error> {
        Self::new_with_options(PartitionOptions::default(), false)
    }

    pub(crate) fn new_x86_64_with_local_apic_count(processor_count: u32) -> Result<Self, Error> {
        Self::new_with_options(
            PartitionOptions {
                processor_count,
                local_apic: true,
                hyperv_enlightenments: true,
            },
            #[cfg(test)]
            false,
        )
    }

    fn new_with_options(
        options: PartitionOptions,
        #[cfg(test)] omit_processor_count: bool,
    ) -> Result<Self, Error> {
        ensure_hypervisor_present()?;

        let inner = VmInner::new()?;
        if options.processor_count == 0 {
            drop(inner);
            return Err(Error::EmptyProcessorCount);
        }

        let setup_result = (|| {
            // The native invalid-configuration fixture omits this required
            // property and must observe WHvSetupPartition's actual error.
            #[cfg(test)]
            if !omit_processor_count {
                inner.set_processor_count(options.processor_count)?;
            }
            #[cfg(not(test))]
            inner.set_processor_count(options.processor_count)?;
            if options.hyperv_enlightenments {
                inner.set_hyperv_enlightenments()?;
                inner.set_hyperv_cpuid_results()?;
            }
            if options.local_apic {
                inner.set_local_apic_emulation()?;
            }
            inner.setup()
        })();
        if let Err(err) = setup_result {
            drop(inner);
            return Err(err);
        }

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[cfg(test)]
    pub(crate) fn add_memory(&mut self, base: u64, size: u64) -> Result<(), Error> {
        let memory = <Memory as dillo_machine::Memory>::from_ranges(&[dillo_machine::RamRange {
            gpa: base,
            size,
        }])?;
        self.set_memory(memory)
    }

    pub(crate) fn set_memory(&mut self, memory: Memory) -> Result<(), Error> {
        self.inner.set_memory(memory)
    }

    pub(crate) fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        self.guest_memory()?
            .write_slice(data, GuestAddress(gpa))
            .map_err(|source| Error::WriteGuest { gpa, source })
    }

    pub(crate) fn guest_memory(&self) -> Result<GuestMemoryMmap, Error> {
        self.inner.guest_memory()
    }

    #[cfg(test)]
    pub(crate) fn allocation_probe(&self, index: usize) -> memory_tests::AllocationProbe {
        memory_tests::AllocationProbe::new(&self.guest_memory().unwrap(), index)
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

    pub(crate) fn cpu_creator(&self) -> Result<CpuCreator, Error> {
        self.inner.require_memory()?;
        Ok(CpuCreator {
            inner: Arc::clone(&self.inner),
        })
    }

    #[cfg(test)]
    pub(crate) fn create_vcpu(&self, idx: u32, cpu_profile: &str) -> Result<Vcpu, Error> {
        // Register-only native tests deliberately need no guest RAM.
        self.inner.create_vcpu(idx, cpu_profile)
    }

    pub(crate) fn interrupt_controller(&self) -> InterruptController {
        InterruptController {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CpuCreator {
    inner: Arc<VmInner>,
}
impl CpuCreator {
    pub(crate) fn create(self, idx: u32, cpu_profile: &str) -> Result<Vcpu, Error> {
        self.inner.create_vcpu(idx, cpu_profile)
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

pub(crate) fn guest_address_bits() -> Result<u32, Error> {
    // The probe uses the launch partition policy, but never maps RAM or runs.
    // Vcpu and Vm drops release the probe even when a query fails.
    let vm = Vm::new_x86_64_with_local_apic_count(1)?;
    let vcpu = vm.inner.create_vcpu(0, "x86-64-v1")?;
    let physical = raw::guest_physical_bits(vcpu.partition.partition, vcpu.idx)
        .map_err(|hr| Error::AddressSpace(status(hr)))?;
    if !(32..=52).contains(&physical) {
        return Err(Error::AddressSpace(format!(
            "invalid guest width {physical}"
        )));
    }
    Ok(physical)
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

impl VmInner {
    fn new() -> Result<Self, Error> {
        let partition = raw::create_partition().map_err(|hr| Error::CreatePartition(status(hr)))?;
        Ok(Self {
            partition,
            memory: Mutex::new(RamRegistration::Empty),
            #[cfg(test)]
            fail_map_at: Mutex::new(None),
            #[cfg(test)]
            fail_delete: false,
        })
    }

    fn require_memory(&self) -> Result<(), Error> {
        self.memory
            .lock()
            .expect("WHP RAM registration poisoned")
            .ready()
            .map(|_| ())
    }

    fn guest_memory(&self) -> Result<GuestMemoryMmap, Error> {
        self.memory
            .lock()
            .expect("WHP RAM registration poisoned")
            .ready()
            .cloned()
    }

    fn set_memory(&self, memory: Memory) -> Result<(), Error> {
        let mut registration = self.memory.lock().expect("WHP RAM registration poisoned");
        if !matches!(*registration, RamRegistration::Empty) {
            return Err(Error::MemoryAlreadyRegistered);
        }
        // Publish the actual allocation before the first native mapping. Any
        // attempted range remains backed until this partition is destroyed.
        *registration = RamRegistration::Attempted {
            memory,
            attempts: 0,
        };
        let RamRegistration::Attempted { memory, attempts } = &mut *registration else {
            unreachable!("WHP RAM registration was just installed");
        };
        for (index, region) in memory.guest().iter().enumerate() {
            let base = region.start_addr().raw_value();
            let size = region.len();
            let host = memory
                .guest()
                .get_host_address(region.start_addr())
                .map_err(|source| Error::GuestMemoryHostAddress { gpa: base, source })?;
            *attempts = index + 1;
            #[cfg(test)]
            if *self.fail_map_at.lock().unwrap() == Some(index) {
                return Err(Error::MapGpa {
                    gpa: base,
                    end: base.saturating_add(size),
                    hr: "injected map failure".into(),
                });
            }
            raw::map_gpa_range(self.partition, host.cast(), base, size).map_err(|hr| {
                Error::MapGpa {
                    gpa: base,
                    end: base.saturating_add(size),
                    hr: status(hr),
                }
            })?;
        }
        let RamRegistration::Attempted { memory, .. } =
            std::mem::replace(&mut *registration, RamRegistration::Empty)
        else {
            unreachable!("WHP RAM registration remained installed during mapping");
        };
        *registration = RamRegistration::Ready(memory);
        Ok(())
    }

    fn create_vcpu(self: &Arc<Self>, idx: u32, cpu_profile: &str) -> Result<Vcpu, Error> {
        validate_cpu_profile(cpu_profile)?;
        raw::create_virtual_processor(self.partition, idx).map_err(|hr| Error::CreateVcpu {
            idx,
            hr: status(hr),
        })?;
        Ok(Vcpu {
            partition: Arc::clone(self),
            idx,
        })
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
        // Whole-partition deletion retires every GPA registration. Native
        // failure cannot authorize dropping the still-accessible RAM fields.
        if raw::delete_partition(
            self.partition,
            #[cfg(test)]
            self.fail_delete,
        )
        .is_err()
        {
            std::process::abort();
        }
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

    /// Program every register fixed by PMI's x86 vm BSP contract.
    pub(crate) fn initialize_bsp(&mut self) -> Result<(), Error> {
        use windows_sys::Win32::System::Hypervisor::{
            WHV_REGISTER_VALUE, WHV_X64_FP_CONTROL_STATUS_REGISTER,
            WHV_X64_FP_CONTROL_STATUS_REGISTER_0, WHV_X64_SEGMENT_REGISTER,
            WHV_X64_SEGMENT_REGISTER_0, WHV_X64_TABLE_REGISTER,
            WHV_X64_XMM_CONTROL_STATUS_REGISTER, WHV_X64_XMM_CONTROL_STATUS_REGISTER_0,
            WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4, WHvX64RegisterCs,
            WHvX64RegisterDr6, WHvX64RegisterDr7, WHvX64RegisterDs, WHvX64RegisterEfer,
            WHvX64RegisterEs, WHvX64RegisterFpControlStatus, WHvX64RegisterFpMmx7,
            WHvX64RegisterFs, WHvX64RegisterGdtr, WHvX64RegisterGs, WHvX64RegisterIdtr,
            WHvX64RegisterLdtr, WHvX64RegisterPat, WHvX64RegisterR8, WHvX64RegisterR9,
            WHvX64RegisterR10, WHvX64RegisterR11, WHvX64RegisterR12, WHvX64RegisterR13,
            WHvX64RegisterR14, WHvX64RegisterR15, WHvX64RegisterRax, WHvX64RegisterRbp,
            WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdi, WHvX64RegisterRdx,
            WHvX64RegisterRflags, WHvX64RegisterRip, WHvX64RegisterRsi, WHvX64RegisterRsp,
            WHvX64RegisterSs, WHvX64RegisterTr, WHvX64RegisterXCr0, WHvX64RegisterXmm0,
            WHvX64RegisterXmmControlStatus,
        };
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
        push_reg64(&mut registers, WHvX64RegisterRax, 0);
        push_reg64(&mut registers, WHvX64RegisterRbx, 0);
        push_reg64(&mut registers, WHvX64RegisterRcx, 0);
        push_reg64(&mut registers, WHvX64RegisterRdx, 0);
        push_reg64(&mut registers, WHvX64RegisterRsi, 0);
        push_reg64(&mut registers, WHvX64RegisterRdi, 0);
        push_reg64(&mut registers, WHvX64RegisterRbp, 0);
        push_reg64(&mut registers, WHvX64RegisterRsp, 0);
        push_reg64(&mut registers, WHvX64RegisterR8, 0);
        push_reg64(&mut registers, WHvX64RegisterR9, 0);
        push_reg64(&mut registers, WHvX64RegisterR10, 0);
        push_reg64(&mut registers, WHvX64RegisterR11, 0);
        push_reg64(&mut registers, WHvX64RegisterR12, 0);
        push_reg64(&mut registers, WHvX64RegisterR13, 0);
        push_reg64(&mut registers, WHvX64RegisterR14, 0);
        push_reg64(&mut registers, WHvX64RegisterR15, 0);
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
        mmio_read: impl Fn(u64, &mut [u8]) -> Result<Option<()>, AccessError>,
        mmio_write: impl Fn(u64, &[u8]) -> Result<Option<MmioWriteOutcome>, AccessError>,
        termination: &dyn dillo_machine::CpuTermination,
    ) -> Result<VmExit, Error> {
        let exit = raw::run_virtual_processor(
            self.partition.partition,
            self.idx,
            &pio_read,
            &mmio_read,
            &mmio_write,
            termination,
        )?;
        Ok(match exit {
            raw::RunExit::Halted => VmExit::Halted,
            raw::RunExit::PioRead { port, size } => VmExit::PioRead { port, size },
            raw::RunExit::PioWrite { port, data, size } => VmExit::PioWrite { port, data, size },
            raw::RunExit::MmioRead { addr, size } => VmExit::MmioRead { addr, size },
            raw::RunExit::MmioWrite {
                addr,
                data,
                size,
                outcome,
            } => VmExit::MmioWrite {
                addr,
                data,
                size,
                outcome,
            },
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
        if let Err(error) = raw::delete_virtual_processor(self.partition.partition, self.idx) {
            log::error!(
                "WHP vCPU {} destruction failed ({error:?}); native retirement is unverified",
                self.idx
            );
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
    use dillo_mmio::{AccessError, MmioWriteOutcome};

    pub(super) type PartitionHandle = WHV_PARTITION_HANDLE;

    pub(super) fn guest_physical_bits(
        partition: PartitionHandle,
        idx: u32,
    ) -> Result<u32, HResult> {
        let mut output = WHV_CPUID_OUTPUT::default();
        // SAFETY: the partition/vCPU are live and output is a correctly sized
        // writable CPUID result. This queries the value exposed to the guest.
        let hr = unsafe {
            WHvGetVirtualProcessorCpuidOutput(partition, idx, 0x8000_0008, 0, &raw mut output)
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        let physical = output.Eax & 0xff;
        // WHvCapabilityCodePhysicalAddressWidth is newer than windows-sys's
        // headers. Older WHP versions expose their limit through guest CPUID.
        match get_capability_u32(0x100a) {
            Ok(bits) => Ok(physical.min(bits)),
            Err(HResult(windows_sys::Win32::Foundation::WHV_E_UNKNOWN_CAPABILITY)) => Ok(physical),
            Err(err) => Err(err),
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) struct CpuidResult {
        pub function: u32,
        pub eax: u32,
        pub ebx: u32,
        pub ecx: u32,
        pub edx: u32,
    }

    #[derive(Debug)]
    pub(super) enum RunExit {
        Halted,
        PioRead {
            port: u16,
            size: u8,
        },
        PioWrite {
            port: u16,
            data: [u8; 4],
            size: u8,
        },
        MmioRead {
            addr: u64,
            size: u8,
        },
        MmioWrite {
            addr: u64,
            data: [u8; 8],
            size: u8,
            outcome: MmioWriteOutcome,
        },
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

    #[cfg(test)]
    std::thread_local! {
        pub(super) static DELETED_PARTITIONS: std::cell::RefCell<Vec<PartitionHandle>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    pub(super) fn delete_partition(
        partition: PartitionHandle,
        #[cfg(test)] inject_failure: bool,
    ) -> Result<(), HResult> {
        #[cfg(test)]
        if inject_failure {
            return Err(HResult(E_FAIL));
        }
        // SAFETY: deletes this owned partition, including every GPA mapping.
        let hr = unsafe { WHvDeletePartition(partition) };
        if failed(hr) {
            return Err(HResult(hr));
        }
        #[cfg(test)]
        DELETED_PARTITIONS.with(|deleted| deleted.borrow_mut().push(partition));
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
        // SAFETY: this owner has returned from native entry and retired the
        // synchronized wake binding before deleting its processor.
        let hr = unsafe { WHvDeleteVirtualProcessor(partition, idx) };
        if failed(hr) { Err(HResult(hr)) } else { Ok(()) }
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
        // SAFETY: requests cancellation of an active WHP run for `idx` in
        // this live partition; flags must be zero per the WHP API. The runtime
        // repeats interrupts until completion to cover entry races.
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
        mmio_read: &dyn Fn(u64, &mut [u8]) -> Result<Option<()>, AccessError>,
        mmio_write: &dyn Fn(u64, &[u8]) -> Result<Option<MmioWriteOutcome>, AccessError>,
        termination: &dyn dillo_machine::CpuTermination,
    ) -> Result<RunExit, super::Error> {
        loop {
            if termination.is_requested() {
                return Ok(RunExit::Canceled);
            }
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
                return Err(super::Error::RunVcpu {
                    idx,
                    hr: super::status(HResult(hr)),
                });
            }

            match exit.ExitReason {
                EXIT_X64_CPUID => emulate_cpuid_exit(partition, idx, &exit).map_err(|hr| {
                    super::Error::RunVcpu {
                        idx,
                        hr: super::status(hr),
                    }
                })?,
                EXIT_X64_HALT => return Ok(RunExit::Halted),
                EXIT_X64_IO_PORT_ACCESS => {
                    return emulate_io_exit(partition, idx, &exit, pio_read, mmio_read, mmio_write);
                }
                EXIT_MEMORY_ACCESS => {
                    return emulate_mmio_exit(
                        partition, idx, &exit, pio_read, mmio_read, mmio_write,
                    );
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
        mmio_read: &dyn Fn(u64, &mut [u8]) -> Result<Option<()>, AccessError>,
        mmio_write: &dyn Fn(u64, &[u8]) -> Result<Option<MmioWriteOutcome>, AccessError>,
    ) -> Result<RunExit, super::Error> {
        let emulator = Emulator::new().map_err(|hr| super::Error::RunVcpu {
            idx,
            hr: super::status(hr),
        })?;
        let mut context = EmulationContext {
            partition,
            idx,
            pio_read,
            mmio_read,
            mmio_write,
            exit: None,
            failure: None,
        };
        #[cfg(test)]
        context.trace_exit(exit);
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
        context.finish(hr, status)
    }

    fn emulate_mmio_exit(
        partition: PartitionHandle,
        idx: u32,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
        pio_read: &dyn Fn(u16, u8) -> u32,
        mmio_read: &dyn Fn(u64, &mut [u8]) -> Result<Option<()>, AccessError>,
        mmio_write: &dyn Fn(u64, &[u8]) -> Result<Option<MmioWriteOutcome>, AccessError>,
    ) -> Result<RunExit, super::Error> {
        let emulator = Emulator::new().map_err(|hr| super::Error::RunVcpu {
            idx,
            hr: super::status(hr),
        })?;
        let mut context = EmulationContext {
            partition,
            idx,
            pio_read,
            mmio_read,
            mmio_write,
            exit: None,
            failure: None,
        };
        #[cfg(test)]
        context.trace_exit(exit);
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
        context.finish(hr, status)
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
        mmio_read: &'a dyn Fn(u64, &mut [u8]) -> Result<Option<()>, AccessError>,
        mmio_write: &'a dyn Fn(u64, &[u8]) -> Result<Option<MmioWriteOutcome>, AccessError>,
        exit: Option<RunExit>,
        failure: Option<super::Error>,
    }

    impl EmulationContext<'_> {
        #[cfg(test)]
        fn tracing() -> bool {
            std::env::var_os("DILLO_WHP_EMULATION_TRACE").is_some()
        }

        #[cfg(test)]
        fn trace_exit(&self, exit: &WHV_RUN_VP_EXIT_CONTEXT) {
            use windows_sys::Win32::System::Hypervisor::{
                WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4, WHvX64RegisterCs,
                WHvX64RegisterDs, WHvX64RegisterEfer, WHvX64RegisterRflags, WHvX64RegisterSs,
            };
            if !Self::tracing() {
                return;
            }
            let vp = &exit.VpContext;
            eprintln!(
                "WHP emulation trace vp={} exit={:#x} rip={:#x} rflags={:#x} execution={:#x} instruction_length={} cs=({:#x},{:#x},{:#x},{:#x})",
                self.idx,
                exit.ExitReason,
                vp.Rip,
                vp.Rflags,
                unsafe { vp.ExecutionState.AsUINT16 },
                vp._bitfield & 15,
                vp.Cs.Base,
                vp.Cs.Limit,
                vp.Cs.Selector,
                unsafe { vp.Cs.Anonymous.Attributes }
            );
            if exit.ExitReason == EXIT_MEMORY_ACCESS {
                let memory = unsafe { &exit.Anonymous.MemoryAccess };
                eprintln!(
                    "WHP emulation trace vp={} memory_exit gpa={:#x} gva={:#x} access_info={:#x} instruction_byte_count={} bytes={:02x?}",
                    self.idx,
                    memory.Gpa,
                    memory.Gva,
                    unsafe { memory.AccessInfo.AsUINT32 },
                    memory.InstructionByteCount,
                    &memory.InstructionBytes[..usize::from(memory.InstructionByteCount)
                        .min(memory.InstructionBytes.len())]
                );
            }
            let names = [
                WHvX64RegisterRip,
                WHvX64RegisterRflags,
                WHvX64RegisterCr0,
                WHvX64RegisterCr3,
                WHvX64RegisterCr4,
                WHvX64RegisterEfer,
                WHvX64RegisterCs,
                WHvX64RegisterDs,
                WHvX64RegisterSs,
            ];
            let mut values = [WHV_REGISTER_VALUE::default(); 9];
            let hr = unsafe {
                WHvGetVirtualProcessorRegisters(
                    self.partition,
                    self.idx,
                    names.as_ptr(),
                    names.len() as u32,
                    values.as_mut_ptr(),
                )
            };
            eprintln!(
                "WHP emulation trace vp={} diagnostic_readback hr={hr:#x}",
                self.idx
            );
            if hr == S_OK {
                self.trace_registers("diagnostic_readback", &names, &values);
            }
        }

        #[cfg(test)]
        fn trace_registers(
            &self,
            operation: &str,
            names: &[WHV_REGISTER_NAME],
            values: &[WHV_REGISTER_VALUE],
        ) {
            use windows_sys::Win32::System::Hypervisor::{
                WHvRegisterPendingInterruption, WHvX64RegisterDr7, WHvX64RegisterXCr0,
            };
            use windows_sys::Win32::System::Hypervisor::{
                WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4,
                WHvX64RegisterCr8, WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEfer,
                WHvX64RegisterEs, WHvX64RegisterFs, WHvX64RegisterGs, WHvX64RegisterR8,
                WHvX64RegisterR9, WHvX64RegisterR10, WHvX64RegisterR11, WHvX64RegisterR12,
                WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15, WHvX64RegisterRbp,
                WHvX64RegisterRdi, WHvX64RegisterRflags, WHvX64RegisterRsi, WHvX64RegisterRsp,
                WHvX64RegisterSs,
            };
            for (&name, value) in names.iter().zip(values) {
                // Interpret only known active union members, never output padding.
                if name == WHvRegisterPendingInterruption {
                    eprintln!(
                        "WHP emulation trace vp={} {operation} register={name:#x} pending_interruption={:#x}",
                        self.idx,
                        unsafe { value.PendingInterruption.AsUINT64 }
                    );
                } else if [
                    WHvX64RegisterCs,
                    WHvX64RegisterDs,
                    WHvX64RegisterEs,
                    WHvX64RegisterFs,
                    WHvX64RegisterGs,
                    WHvX64RegisterSs,
                ]
                .contains(&name)
                {
                    let segment = unsafe { value.Segment };
                    eprintln!(
                        "WHP emulation trace vp={} {operation} register={name:#x} segment=({:#x},{:#x},{:#x},{:#x})",
                        self.idx,
                        segment.Base,
                        segment.Limit,
                        segment.Selector,
                        unsafe { segment.Anonymous.Attributes }
                    );
                } else if [
                    WHvX64RegisterDr7,
                    WHvX64RegisterXCr0,
                    WHvX64RegisterCr0,
                    WHvX64RegisterCr2,
                    WHvX64RegisterCr3,
                    WHvX64RegisterCr4,
                    WHvX64RegisterCr8,
                    WHvX64RegisterEfer,
                    WHvX64RegisterRip,
                    WHvX64RegisterRflags,
                    WHvX64RegisterRax,
                    WHvX64RegisterRbx,
                    WHvX64RegisterRcx,
                    WHvX64RegisterRdx,
                    WHvX64RegisterRsp,
                    WHvX64RegisterRbp,
                    WHvX64RegisterRsi,
                    WHvX64RegisterRdi,
                    WHvX64RegisterR8,
                    WHvX64RegisterR9,
                    WHvX64RegisterR10,
                    WHvX64RegisterR11,
                    WHvX64RegisterR12,
                    WHvX64RegisterR13,
                    WHvX64RegisterR14,
                    WHvX64RegisterR15,
                ]
                .contains(&name)
                {
                    eprintln!(
                        "WHP emulation trace vp={} {operation} register={name:#x} value={:#x}",
                        self.idx,
                        unsafe { value.Reg64 }
                    );
                } else {
                    eprintln!(
                        "WHP emulation trace vp={} {operation} register={name:#x} (value not decoded)",
                        self.idx
                    );
                }
            }
        }

        #[cfg(test)]
        fn trace_callback(&self, name: &str, hr: i32) {
            // Diagnostics must retain the callback's C-ABI unwind boundary.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                if Self::tracing() {
                    eprintln!(
                        "WHP emulation trace vp={} {name} returned={hr:#x} failure={:?}",
                        self.idx, self.failure
                    );
                }
            }));
        }

        fn terminal(&self) -> bool {
            matches!(
                self.exit,
                Some(RunExit::MmioWrite {
                    outcome: MmioWriteOutcome::GuestPoweroff | MmioWriteOutcome::GuestReset,
                    ..
                })
            )
        }

        fn invoke(&mut self, action: impl FnOnce(&mut Self) -> Result<(), super::Error>) -> i32 {
            if self.failure.is_some() || self.terminal() {
                return E_FAIL;
            }
            let result = catch_unwind(AssertUnwindSafe(|| action(self)));
            match result {
                Ok(Ok(())) => S_OK,
                Ok(Err(error)) => {
                    self.failure = Some(error);
                    E_FAIL
                }
                Err(_) => {
                    self.failure = Some(super::Error::UnhandledExit(
                        "WHP emulator callback panicked".into(),
                    ));
                    E_FAIL
                }
            }
        }

        fn native_result(&self, hr: i32) -> Result<(), super::Error> {
            if failed(hr) {
                Err(super::Error::RunVcpu {
                    idx: self.idx,
                    hr: super::status(HResult(hr)),
                })
            } else {
                Ok(())
            }
        }

        fn finish(mut self, hr: i32, status: WHV_EMULATOR_STATUS) -> Result<RunExit, super::Error> {
            #[cfg(test)]
            if Self::tracing() {
                let bits = if hr == S_OK {
                    Some(unsafe { status.AsUINT32 })
                } else {
                    None
                };
                eprintln!(
                    "WHP emulation trace vp={} finish hr={hr:#x} status={bits:#x?} exit={:?} failure={:?}",
                    self.idx, self.exit, self.failure
                );
            }
            if let Some(error) = self.failure.take() {
                return Err(error);
            }
            // A device has accepted a terminal request. Later callbacks were
            // deliberately refused; do not resume or replay this instruction.
            if self.terminal() {
                return Ok(self.exit.take().unwrap());
            }
            // The extended emulator status is valid only for S_OK.
            if hr != S_OK {
                return Err(super::Error::RunVcpu {
                    idx: self.idx,
                    hr: super::status(HResult(hr)),
                });
            }
            Ok(emulated_exit(status, self.exit))
        }
    }

    unsafe extern "system" fn io_port_callback(
        context: *const c_void,
        io_access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> i32 {
        let context = unsafe { &mut *(context.cast_mut().cast::<EmulationContext<'_>>()) };
        context.invoke(|context| {
            let io = unsafe { &mut *io_access };
            if !matches!(io.AccessSize, 1 | 2 | 4) {
                return Err(super::Error::UnhandledExit(format!(
                    "WHP PIO width {} is unsupported",
                    io.AccessSize
                )));
            }
            let size = io.AccessSize as u8;
            if io.Direction == 0 {
                io.Data = (context.pio_read)(io.Port, size);
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
            Ok(())
        })
    }

    unsafe extern "system" fn memory_callback(
        context: *const c_void,
        memory_access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> i32 {
        let context = unsafe { &mut *(context.cast_mut().cast::<EmulationContext<'_>>()) };
        let callback_hr = context.invoke(|context| {
            let memory = unsafe { &mut *memory_access };
            let size = memory.AccessSize;
            #[cfg(test)]
            if EmulationContext::tracing() {
                eprintln!(
                    "WHP emulation trace vp={} memory_request gpa={:#x} direction={} size={size}",
                    context.idx, memory.GpaAddress, memory.Direction
                );
                if memory.Direction == 1 && usize::from(size) <= memory.Data.len() {
                    eprintln!(
                        "WHP emulation trace vp={} memory_write bytes={:02x?}",
                        context.idx,
                        &memory.Data[..usize::from(size)]
                    );
                }
            }
            if size == 0 || usize::from(size) > memory.Data.len() {
                return Err(super::Error::UnhandledExit(format!(
                    "WHP memory access at {:#x} has unsupported width {size}",
                    memory.GpaAddress
                )));
            }
            if memory.Direction == 0 {
                let data = &mut memory.Data[..size as usize];
                if (context.mmio_read)(memory.GpaAddress, data)?.is_none() {
                    data.fill(0);
                }
                #[cfg(test)]
                if EmulationContext::tracing() {
                    eprintln!(
                        "WHP emulation trace vp={} memory_read_reply gpa={:#x} bytes={data:02x?}",
                        context.idx, memory.GpaAddress
                    );
                }
                context.exit = Some(RunExit::MmioRead {
                    addr: memory.GpaAddress,
                    size,
                });
            } else {
                let outcome =
                    (context.mmio_write)(memory.GpaAddress, &memory.Data[..size as usize])?
                        .unwrap_or(MmioWriteOutcome::Continue);
                let mut data = [0; 8];
                data[..size as usize].copy_from_slice(&memory.Data[..size as usize]);
                context.exit = Some(RunExit::MmioWrite {
                    addr: memory.GpaAddress,
                    data,
                    size,
                    outcome,
                });
            }
            Ok(())
        });
        #[cfg(test)]
        context.trace_callback("memory_callback", callback_hr);
        callback_hr
    }

    unsafe extern "system" fn get_registers_callback(
        context: *const c_void,
        names: *const WHV_REGISTER_NAME,
        count: u32,
        values: *mut WHV_REGISTER_VALUE,
    ) -> i32 {
        let context = unsafe { &mut *(context.cast_mut().cast::<EmulationContext<'_>>()) };
        let callback_hr = context.invoke(|context| {
            #[cfg(test)]
            if EmulationContext::tracing() && count > 0 {
                let names = unsafe { std::slice::from_raw_parts(names, count as usize) };
                eprintln!(
                    "WHP emulation trace vp={} get_registers request names={names:#x?}",
                    context.idx
                );
            }
            let hr = unsafe {
                WHvGetVirtualProcessorRegisters(
                    context.partition,
                    context.idx,
                    names,
                    count,
                    values,
                )
            };
            #[cfg(test)]
            if EmulationContext::tracing() {
                eprintln!(
                    "WHP emulation trace vp={} get_registers native_hr={hr:#x}",
                    context.idx
                );
                if hr == S_OK && count > 0 {
                    let names = unsafe { std::slice::from_raw_parts(names, count as usize) };
                    let values = unsafe { std::slice::from_raw_parts(values, count as usize) };
                    context.trace_registers("get_registers_reply", names, values);
                }
            }
            context.native_result(hr)
        });
        #[cfg(test)]
        context.trace_callback("get_registers_callback", callback_hr);
        callback_hr
    }

    unsafe extern "system" fn set_registers_callback(
        context: *const c_void,
        names: *const WHV_REGISTER_NAME,
        count: u32,
        values: *const WHV_REGISTER_VALUE,
    ) -> i32 {
        let context = unsafe { &mut *(context.cast_mut().cast::<EmulationContext<'_>>()) };
        let callback_hr = context.invoke(|context| {
            #[cfg(test)]
            if EmulationContext::tracing() && count > 0 {
                let names = unsafe { std::slice::from_raw_parts(names, count as usize) };
                eprintln!(
                    "WHP emulation trace vp={} set_registers request names={names:#x?}",
                    context.idx
                );
                let values = unsafe { std::slice::from_raw_parts(values, count as usize) };
                context.trace_registers("set_registers_input", names, values);
            }
            let hr = unsafe {
                WHvSetVirtualProcessorRegisters(
                    context.partition,
                    context.idx,
                    names,
                    count,
                    values,
                )
            };
            #[cfg(test)]
            if EmulationContext::tracing() {
                eprintln!(
                    "WHP emulation trace vp={} set_registers native_hr={hr:#x}",
                    context.idx
                );
            }
            context.native_result(hr)
        });
        #[cfg(test)]
        context.trace_callback("set_registers_callback", callback_hr);
        callback_hr
    }

    unsafe extern "system" fn translate_gva_callback(
        context: *const c_void,
        gva: u64,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: *mut u64,
    ) -> i32 {
        let context = unsafe { &mut *(context.cast_mut().cast::<EmulationContext<'_>>()) };
        let callback_hr = context.invoke(|context| {
            #[cfg(test)]
            if EmulationContext::tracing() {
                eprintln!("WHP emulation trace vp={} translate_request gva={gva:#x} flags={translate_flags:#x}", context.idx);
            }
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
            #[cfg(test)]
            if EmulationContext::tracing() {
                eprintln!("WHP emulation trace vp={} translate_reply native_hr={hr:#x} result={} gpa={translated_gpa:#x}", context.idx, result.ResultCode);
            }
            context.native_result(hr)?;
            unsafe {
                *translation_result = result.ResultCode;
                *gpa = translated_gpa;
            }
            Ok(())
        });
        #[cfg(test)]
        context.trace_callback("translate_callback", callback_hr);
        callback_hr
    }

    #[cfg(test)]
    pub(super) fn get_virtual_processor_register_words(
        partition: PartitionHandle,
        idx: u32,
        name: WHV_REGISTER_NAME,
    ) -> Result<[u32; 4], HResult> {
        let names = [name];
        let mut values = [WHV_REGISTER_VALUE::default()];
        // SAFETY: WHP writes exactly one 16-byte register union into the
        // initialized output. Reading its integer words preserves all bits.
        let hr = unsafe {
            WHvGetVirtualProcessorRegisters(partition, idx, names.as_ptr(), 1, values.as_mut_ptr())
        };
        if failed(hr) {
            return Err(HResult(hr));
        }
        Ok(unsafe { values[0].Reg128.Dword })
    }

    pub(super) fn map_gpa_range(
        partition: PartitionHandle,
        host: *mut c_void,
        gpa: u64,
        size: u64,
    ) -> Result<(), HResult> {
        let flags = WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute;
        // SAFETY: the partition owner has already retained this actual
        // GuestMemoryMmap through successful whole-partition destruction.
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
    #[cfg(test)]
    mod callback_tests {
        use super::*;
        use dillo_machine::memory::AddressRange;
        use std::cell::Cell;

        #[test]
        fn first_callback_failure_prevents_later_effects_and_survives_status() {
            let effects = Cell::new(0);
            let write = |address, data: &[u8]| {
                effects.set(effects.get() + 1);
                Err(AccessError {
                    operation: "write",
                    address,
                    size: data.len(),
                    window: AddressRange {
                        base: 0x2000,
                        size: 0x1000,
                    },
                    source: dillo_mmio::MmioError::Device(Box::new(std::io::Error::other(
                        "first callback failure",
                    ))),
                })
            };
            let mut context = EmulationContext {
                partition: 0,
                idx: 0,
                pio_read: &|_, _| 0,
                mmio_read: &|_, _| Ok(None),
                mmio_write: &write,
                exit: None,
                failure: None,
            };
            let mut access = WHV_EMULATOR_MEMORY_ACCESS_INFO {
                GpaAddress: 0x2000,
                Direction: 1,
                AccessSize: 1,
                ..Default::default()
            };
            // Exercise the ABI callback itself, separately from native emulator tests.
            let result =
                unsafe { memory_callback(ptr::from_mut(&mut context).cast(), &raw mut access) };
            assert_eq!(result, E_FAIL);
            let result =
                unsafe { memory_callback(ptr::from_mut(&mut context).cast(), &raw mut access) };
            assert_eq!(result, E_FAIL);
            assert_eq!(effects.get(), 1);
            let error = context
                .finish(E_FAIL, WHV_EMULATOR_STATUS::default())
                .unwrap_err();
            assert!(
                error.to_string().contains("first callback failure"),
                "{error}"
            );
            assert!(matches!(error, super::super::Error::Mmio(_)));
        }

        #[test]
        fn accepted_terminal_callback_prevents_later_effects_and_retains_outcome() {
            for outcome in [
                MmioWriteOutcome::GuestPoweroff,
                MmioWriteOutcome::GuestReset,
            ] {
                let effects = Cell::new(0);
                let write = |_, _: &[u8]| {
                    effects.set(effects.get() + 1);
                    Ok(Some(outcome))
                };
                let mut context = EmulationContext {
                    partition: 0,
                    idx: 0,
                    pio_read: &|_, _| 0,
                    mmio_read: &|_, _| Ok(None),
                    mmio_write: &write,
                    exit: None,
                    failure: None,
                };
                let mut access = WHV_EMULATOR_MEMORY_ACCESS_INFO {
                    GpaAddress: 0x2000,
                    Direction: 1,
                    AccessSize: 1,
                    ..Default::default()
                };
                assert_eq!(
                    unsafe { memory_callback(ptr::from_mut(&mut context).cast(), &raw mut access) },
                    S_OK
                );
                assert_eq!(
                    unsafe { memory_callback(ptr::from_mut(&mut context).cast(), &raw mut access) },
                    E_FAIL
                );
                assert_eq!(effects.get(), 1);
                let exit = context
                    .finish(E_FAIL, WHV_EMULATOR_STATUS::default())
                    .unwrap();
                assert!(
                    matches!(exit, RunExit::MmioWrite { outcome: observed, .. } if observed == outcome)
                );
            }
        }
    }
}

#[cfg(test)]
pub(crate) use tests::whp_test_lock;

#[cfg(test)]
mod tests {
    use super::{Error, Vcpu, Vm, push_reg64, raw, status};
    use crate::VmExit;
    use dillo_machine::memory::{MappedSharedMemory, SharedAccess, SharedMemory, SharedRange};
    use std::collections::BTreeMap;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use windows_sys::Win32::System::Hypervisor::*;

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
        vm.write_guest(0x101f_ffff, &[0x55])
            .expect("last mapped byte fits");
        assert!(
            matches!(
                vm.write_guest(0x101f_ffff, &[0x66, 0x77]),
                Err(Error::WriteGuest { .. })
            ),
            "short native writes must not become successful launch operations"
        );
        let mappings = vm.region_mappings();
        assert_eq!(mappings, vec![(0x1000_0000, mappings[0].1, 0x0020_0000)]);
    }

    #[test]
    fn whp_fixed_bsp_state_matches_pmi_and_preserves_ap() {
        let _guard = whp_test_lock();
        let vm = Vm::new_x86_64_with_local_apic_count(2).expect("WHP is required for this test");
        let mut bsp = vm.create_vcpu(0, "x86-64-v1").expect("create BSP");
        let ap = vm.create_vcpu(1, "x86-64-v1").expect("create AP");
        let ap_before = ap.native_register_words(WHvX64RegisterRip);
        bsp.initialize_bsp().expect("prepare fixed BSP state");
        for (name, expected) in [
            (WHvX64RegisterRip, 0xffff_fff0),
            (WHvX64RegisterRflags, 2),
            (WHvX64RegisterCr0, 0x21),
            (WHvX64RegisterCr3, 0),
            (WHvX64RegisterCr4, 0x40),
            (WHvX64RegisterEfer, 0x901),
            (WHvX64RegisterDr6, 0xffff_0ff0),
            (WHvX64RegisterDr7, 0x400),
            (WHvX64RegisterPat, 0x0007_0406_0007_0406),
            (WHvX64RegisterXCr0, 1),
        ] {
            let words = bsp.native_register_words(name);
            let actual = u64::from(words[0]) | (u64::from(words[1]) << 32);
            if name == WHvX64RegisterCr0 {
                assert_eq!(
                    actual & !0x10,
                    expected,
                    "CR0 allows architectural ET normalization"
                );
            } else {
                assert_eq!(actual, expected, "register {name:#x}");
            }
        }
        for (name, attributes, limit) in [
            (WHvX64RegisterCs, 0xc09b_u32, u32::MAX),
            (WHvX64RegisterDs, 0xc093, u32::MAX),
            (WHvX64RegisterEs, 0xc093, u32::MAX),
            (WHvX64RegisterFs, 0xc093, u32::MAX),
            (WHvX64RegisterGs, 0xc093, u32::MAX),
            (WHvX64RegisterSs, 0xc093, u32::MAX),
            (WHvX64RegisterTr, 0x8b, 0xffff),
        ] {
            // Native layout: base[63:0], limit[31:0], selector[15:0], attributes[15:0].
            assert_eq!(
                bsp.native_register_words(name),
                [0, 0, limit, attributes << 16],
                "segment {name:#x}"
            );
        }
        assert_eq!(bsp.native_register_words(WHvX64RegisterLdtr)[3] & 0xffff, 0);
        assert_eq!(
            bsp.native_register_words(WHvX64RegisterGdtr),
            [0, 0xffff_0000, 0, 0]
        );
        assert_eq!(bsp.native_register_words(WHvX64RegisterIdtr), [0; 4]);
        assert_eq!(
            bsp.native_register_words(WHvX64RegisterFpControlStatus),
            [0x37f, 0, 0, 0]
        );
        // XMM control contains the native read-only mask in its last word;
        // PMI fixes MXCSR and the last-data pointer, which occupy words0..3.
        let xmm_control = bsp.native_register_words(WHvX64RegisterXmmControlStatus);
        assert_eq!(&xmm_control[..3], &[0, 0, 0x1f80]);
        for name in WHvX64RegisterXmm0..=WHvX64RegisterFpMmx7 {
            assert_eq!(
                bsp.native_register_words(name),
                [0; 4],
                "FP/SSE register {name:#x}"
            );
        }
        assert_eq!(ap.native_register_words(WHvX64RegisterRip), ap_before);
        assert_ne!(
            ap.native_register_words(WHvX64RegisterRip),
            [0xffff_fff0, 0, 0, 0],
            "AP keeps its reset state until guest startup"
        );
    }

    #[test]
    fn whp_runs_to_hlt_exit() {
        let _guard = whp_test_lock();
        let mut vm = Vm::new().expect("create WHP partition");
        let code_base = 0x1_0000;
        vm.add_memory(code_base, 0x1000).expect("map guest memory");
        let shared = MappedSharedMemory::for_guest_memory(
            vm.guest_memory().unwrap(),
            SharedAccess::ReadWrite,
        );
        let region = shared
            .region(SharedRange {
                gpa: code_base,
                size: 0x1000,
                access: SharedAccess::ReadWrite,
            })
            .unwrap();
        region.store_u16_le(0x100, 0x0100).unwrap();
        region.store_u32_le(0x108, 0x89ab_cdef).unwrap();
        // DS=0x1000; copy native guest halfword/word loads to neighboring
        // slots, then halt. These are the original partition's RAM bytes.
        vm.write_guest(
            code_base,
            &[
                0xb8, 0x00, 0x10, 0x8e, 0xd8, 0xa1, 0x00, 0x01, 0xa3, 0x02, 0x01, 0x66, 0xa1, 0x08,
                0x01, 0x66, 0xa3, 0x0c, 0x01, 0xf4,
            ],
        )
        .unwrap();

        let mut vcpu = vm.create_vcpu(0, "x86-64-v2").expect("create WHP vCPU");
        vcpu.initialize_test_real_mode(code_base, 0)
            .expect("set real-mode state");

        let exit = vcpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .expect("run vCPU");
        assert!(matches!(exit, VmExit::Halted), "expected HLT, got {exit:?}");
        assert_eq!(region.load_u16_le(0x102).unwrap(), 0x0100);
        assert_eq!(region.load_u32_le(0x10c).unwrap(), 0x89ab_cdef);
        assert_eq!(region.load_u64_le(0x108).unwrap(), 0x89ab_cdef_89ab_cdef);
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
        vcpu.initialize_test_real_mode(code_base, 0x5A)
            .expect("set real-mode state");

        let exit = vcpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .expect("run out");
        match exit {
            VmExit::PioWrite { port, data, size } => {
                assert_eq!(port, 0x42);
                assert_eq!(size, 1);
                assert_eq!(data[0], 0x5A);
            }
            other => panic!("expected PIO write, got {other:?}"),
        }

        let exit = vcpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .expect("run hlt");
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
        vcpu.initialize_test_real_mode(code_base, 0xA5)
            .expect("set real-mode state");

        let exit = vcpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .expect("run mmio write");
        match exit {
            VmExit::MmioWrite {
                addr, data, size, ..
            } => {
                assert_eq!(addr, 0x2000);
                assert_eq!(size, 1);
                assert_eq!(data[0], 0xA5);
            }
            other => panic!("expected MMIO write, got {other:?}"),
        }

        let exit = vcpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .expect("run hlt");
        assert!(matches!(exit, VmExit::Halted), "expected HLT, got {exit:?}");
    }

    #[test]
    fn whp_fixed_entry_emulation_diagnostic_matrix() {
        use dillo_machine::RamRange;
        use dillo_machine::memory::AddressRange;
        use dillo_mmio::{AccessError, MmioError};
        use std::cell::Cell;

        let _guard = whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            super::memory_tests::NativeMemoryTest::spawn(
                "hypervisor::tests::whp_fixed_entry_emulation_diagnostic_matrix",
            )
            .verify();
            return;
        }
        let high = 0xffff_f100u32;
        let low = 0x1_0100u32;
        let before_high = high - 5;
        let ram_value = 0xa55a_1234u32;
        // Same MMIO operand in all cases. Each access is followed by HLT,
        // although the callback deliberately fails before guest continuation.
        let read: &[u8] = &[0xa1, 0, 0, 0, 0x0b, 0xf4];
        let write: &[u8] = &[0xc7, 0x05, 0, 0, 0, 0x0b, 0x78, 0x56, 0x34, 0x12, 0xf4];
        for (label, efer, ds_selector, entry, code) in [
            ("fixed-read", 0x901, 0, high, read),
            ("read-after-native-ram", 0x901, 0, before_high, read),
            ("fixed-write", 0x901, 0, high, write),
            ("read-LME-clear", 0x801, 0, high, read),
            ("read-DS-selector-8", 0x901, 8, high, read),
            ("read-low-code", 0x901, 0, low, read),
        ] {
            eprintln!(
                "WHP entry experiment BEGIN {label}: efer={efer:#x} ds_selector={ds_selector:#x} code={entry:#x}"
            );
            // This diagnostic records all outcomes; the unchanged owner test
            // remains the failing acceptance gate for the required PMI state.
            let result = (|| -> Result<(), Error> {
                let mut vm = Vm::new()?;
                vm.set_memory(<crate::Memory as dillo_machine::Memory>::from_ranges(&[
                    RamRange {
                        gpa: 0x1_0000,
                        size: 0x1000,
                    },
                    RamRange {
                        gpa: 0xffff_f000,
                        size: 0x1000,
                    },
                ])?)?;
                // Seed both code locations in the same two RAM mappings.
                vm.write_guest(u64::from(low), code)?;
                vm.write_guest(u64::from(high), code)?;
                if entry == before_high {
                    // Native mov eax, moffs32 through the same DS to existing
                    // RAM. It ends exactly where the unchanged MMIO read begins.
                    vm.write_guest(0x1_0000, &ram_value.to_le_bytes())?;
                    vm.write_guest(u64::from(before_high), &[0xa1, 0, 0, 1, 0])?;
                }
                let mut trampoline = vec![0xe9];
                trampoline.extend_from_slice(&entry.wrapping_sub(0xffff_fff5).to_le_bytes());
                vm.write_guest(0xffff_fff0, &trampoline)?;
                let mut cpu = vm.create_vcpu(0, "x86-64-v1")?;
                cpu.initialize_bsp()?;
                if efer != 0x901 {
                    raw::set_virtual_processor_registers(
                        cpu.partition.partition,
                        cpu.idx,
                        &[WHvX64RegisterEfer],
                        &[WHV_REGISTER_VALUE { Reg64: efer }],
                    )
                    .map_err(|hr| Error::SetRegisters {
                        idx: cpu.idx,
                        hr: status(hr),
                    })?;
                }
                if ds_selector != 0 {
                    // Only the selector differs from initialize_bsp; cached
                    // base, limit, type, privilege and attributes are retained.
                    let ds = WHV_REGISTER_VALUE {
                        Segment: WHV_X64_SEGMENT_REGISTER {
                            Base: 0,
                            Limit: u32::MAX,
                            Selector: ds_selector,
                            Anonymous: WHV_X64_SEGMENT_REGISTER_0 { Attributes: 0xc093 },
                        },
                    };
                    raw::set_virtual_processor_registers(
                        cpu.partition.partition,
                        cpu.idx,
                        &[WHvX64RegisterDs],
                        &[ds],
                    )
                    .map_err(|hr| Error::SetRegisters {
                        idx: cpu.idx,
                        hr: status(hr),
                    })?;
                }
                let reads = Cell::new(0);
                let writes = Cell::new(0);
                let exit = cpu.run(
                    |_, _| 0,
                    |address, data| {
                        reads.set(reads.get() + 1);
                        eprintln!(
                            "WHP entry experiment {label}: read gpa={address:#x} size={}",
                            data.len()
                        );
                        if address != 0x0b00_0000 {
                            return Ok(None);
                        }
                        data.fill(0xa5);
                        Err(AccessError {
                            operation: "read",
                            address,
                            size: data.len(),
                            window: AddressRange {
                                base: 0x0b00_0000,
                                size: 0x1000,
                            },
                            source: MmioError::Device(Box::new(std::io::Error::other(
                                "diagnostic mapped read reached",
                            ))),
                        })
                    },
                    |address, data| {
                        writes.set(writes.get() + 1);
                        eprintln!(
                            "WHP entry experiment {label}: write gpa={address:#x} data={data:02x?}"
                        );
                        if address != 0x0b00_0000 {
                            return Ok(None);
                        }
                        Err(AccessError {
                            operation: "write",
                            address,
                            size: data.len(),
                            window: AddressRange {
                                base: 0x0b00_0000,
                                size: 0x1000,
                            },
                            source: MmioError::Device(Box::new(std::io::Error::other(
                                "diagnostic mapped write reached",
                            ))),
                        })
                    },
                    &std::sync::atomic::AtomicBool::new(false),
                );
                eprintln!(
                    "WHP entry experiment {label}: result={exit:?} read_callbacks={} write_callbacks={}",
                    reads.get(),
                    writes.get()
                );
                if entry == before_high {
                    let eax = cpu.native_register_words(WHvX64RegisterRax)[0];
                    eprintln!(
                        "WHP entry experiment {label}: EAX after exit={eax:#x}, RAM value={ram_value:#x}"
                    );
                }
                // No next run, even if emulation unexpectedly succeeds.
                Ok(())
            })();
            eprintln!("WHP entry experiment END {label}: setup_and_cleanup={result:?}");
        }
    }

    #[test]
    fn whp_native_split_and_rep_preserve_earlier_effects_on_later_failure() {
        use dillo_machine::memory::AddressRange;
        use dillo_mmio::{AccessError, MmioError, MmioWriteOutcome};
        use std::cell::RefCell;

        let _guard = whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            super::memory_tests::NativeMemoryTest::spawn("hypervisor::tests::whp_native_split_and_rep_preserve_earlier_effects_on_later_failure").verify();
            return;
        }
        for (label, code, expected) in [
            // mov dword ptr [0x2ffe], eax: the emulator splits at the page boundary.
            (
                "split store",
                vec![0x66, 0xa3, 0xfe, 0x2f],
                vec![(0x2ffe, 2), (0x3000, 2)],
            ),
            // mov di,0x2000; mov cx,3; rep stosb.
            (
                "REP store",
                vec![0xbf, 0x00, 0x20, 0xb9, 0x03, 0x00, 0xf3, 0xaa],
                vec![(0x2000, 1), (0x2001, 1), (0x2002, 1)],
            ),
        ] {
            let mut vm = Vm::new().expect("native WHP is required");
            let code_base = 0x3_0000;
            vm.add_memory(code_base, 0x1000).unwrap();
            let mut payload = code;
            // A marker in BL followed by HLT must never execute after failure.
            payload.extend_from_slice(&[0xb3, 0x77, 0xf4]);
            vm.write_guest(code_base, &payload).unwrap();
            let mut cpu = vm.create_vcpu(0, "x86-64-v1").unwrap();
            cpu.initialize_test_real_mode(code_base, 0x1234_5678)
                .unwrap();
            let attempts = RefCell::new(Vec::new());
            let failure_address = expected.last().unwrap().0;
            let write = |address, data: &[u8]| {
                attempts.borrow_mut().push((address, data.len()));
                if address == failure_address {
                    Err(AccessError {
                        operation: "write",
                        address,
                        size: data.len(),
                        window: AddressRange {
                            base: 0x2000,
                            size: 0x2000,
                        },
                        source: MmioError::Device(Box::new(std::io::Error::other(
                            "later native callback failure",
                        ))),
                    })
                } else {
                    Ok(Some(MmioWriteOutcome::Continue))
                }
            };
            let termination = std::sync::atomic::AtomicBool::new(false);
            let mut failure = None;
            for _ in 0..4 {
                match cpu.run(|_, _| 0, |_, _| Ok(None), write, &termination) {
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                    Ok(VmExit::MmioWrite { .. }) => {}
                    other => panic!("{label}: expected mapped callback failure, got {other:?}"),
                }
            }
            let failure = failure.expect("native emulator must reach the later failing access");
            assert!(
                failure
                    .to_string()
                    .contains("later native callback failure"),
                "{label}: {failure}"
            );
            assert_eq!(
                *attempts.borrow(),
                expected,
                "{label}: effects cannot be lost or replayed"
            );
            assert_eq!(
                cpu.native_register_words(WHvX64RegisterRbx)[0] & 0xff,
                0,
                "{label}: post-failure marker"
            );
            eprintln!(
                "WHP native {label}: accesses {:?}, retained failure {failure}, no post-failure marker",
                attempts.borrow()
            );
        }
    }

    impl Vcpu {
        fn native_register_words(&self, name: WHV_REGISTER_NAME) -> [u32; 4] {
            raw::get_virtual_processor_register_words(self.partition.partition, self.idx, name)
                .expect("read native register")
        }

        pub(crate) fn initialize_test_real_mode(
            &mut self,
            code_base: u64,
            rax: u64,
        ) -> Result<(), Error> {
            self.initialize_bsp()?;
            let mut registers = Vec::new();
            for (name, value) in [
                (WHvX64RegisterCr0, 0x10),
                (WHvX64RegisterCr4, 0),
                (WHvX64RegisterEfer, 0),
                (WHvX64RegisterRip, 0),
                (WHvX64RegisterRax, rax),
            ] {
                push_reg64(&mut registers, name, value);
            }
            for name in [
                WHvX64RegisterCs,
                WHvX64RegisterDs,
                WHvX64RegisterEs,
                WHvX64RegisterFs,
                WHvX64RegisterGs,
                WHvX64RegisterSs,
            ] {
                registers.push((
                    name,
                    WHV_REGISTER_VALUE {
                        Segment: WHV_X64_SEGMENT_REGISTER {
                            Base: if name == WHvX64RegisterCs {
                                code_base
                            } else {
                                0
                            },
                            Limit: 0xffff,
                            Selector: 0,
                            Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                                Attributes: if name == WHvX64RegisterCs { 0x9b } else { 0x93 },
                            },
                        },
                    },
                ));
            }
            let (names, values): (Vec<_>, Vec<_>) = registers.into_iter().unzip();
            raw::set_virtual_processor_registers(
                self.partition.partition,
                self.idx,
                &names,
                &values,
            )
            .map_err(|hr| Error::SetRegisters {
                idx: self.idx,
                hr: status(hr),
            })
        }
    }

    pub(crate) fn whp_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("WHP test lock poisoned")
    }
}

#[cfg(test)]
pub(crate) mod memory_tests {
    use std::sync::atomic::AtomicBool;

    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_FREE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, VirtualQuery,
    };

    use super::*;

    /// Observes the kernel's allocation base, type, extent and state without
    /// retaining the allocation or dereferencing an address after reclamation.
    pub(crate) struct AllocationProbe {
        address: usize,
        size: usize,
        original: std::sync::Weak<vm_memory::mmap::MmapRegion<()>>,
    }

    impl AllocationProbe {
        pub(crate) fn new(memory: &GuestMemoryMmap, index: usize) -> Self {
            Self::from_region(memory.iter().nth(index).unwrap())
        }

        pub(crate) fn from_region(region: &vm_memory::GuestRegionMmap) -> Self {
            let probe = Self {
                address: region.get_mmap().as_ptr() as usize,
                size: region.len() as usize,
                original: Arc::downgrade(&region.get_mmap()),
            };
            probe.assert_retained();
            probe
        }

        fn query(&self) -> MEMORY_BASIC_INFORMATION {
            let mut information = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: query only, with a writable SDK-sized output buffer. This
            // does not dereference the queried address or rely on its liveness.
            #[allow(unsafe_code)]
            let count = unsafe {
                VirtualQuery(
                    self.address as *const _,
                    &raw mut information,
                    std::mem::size_of_val(&information),
                )
            };
            assert_eq!(
                count,
                std::mem::size_of_val(&information),
                "VirtualQuery failed: {}",
                std::io::Error::last_os_error()
            );
            assert!(information.BaseAddress as usize <= self.address);
            assert!(
                self.size
                    <= information.RegionSize - (self.address - information.BaseAddress as usize)
            );
            information
        }

        pub(crate) fn assert_retained(&self) {
            let original = self
                .original
                .upgrade()
                .expect("original mapping owner was released");
            assert_eq!(original.as_ptr() as usize, self.address);
            let information = self.query();
            assert_eq!(information.State, MEM_COMMIT);
            assert_eq!(information.Type, MEM_MAPPED);
            assert_eq!(information.AllocationBase as usize, self.address);
        }

        pub(crate) fn assert_reclaimed(&self) {
            // A failed query, MEM_RESERVE or another live allocation never counts
            // as reclamation. AllocationBase/Type are undefined for MEM_FREE.
            // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery
            assert!(
                self.original.upgrade().is_none(),
                "original mapping still has a live owner"
            );
            assert_eq!(self.query().State, MEM_FREE);
        }
    }

    #[test]
    fn whp_replacement_refuses_before_mapping_and_preserves_guest_access() {
        let _guard = whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            NativeMemoryTest::spawn("hypervisor::memory_tests::whp_replacement_refuses_before_mapping_and_preserves_guest_access").verify();
            return;
        }
        let mut vm = Vm::new().expect("native WHP is required");
        vm.add_memory(0x10000, 0x1000).unwrap();
        // Read a byte from mapped data, store it next door, then halt.
        vm.write_guest(
            0x10000,
            &[
                0xb8, 0x00, 0x10, 0x8e, 0xd8, 0xa0, 0x00, 0x01, 0xa2, 0x01, 0x01, 0xf4,
            ],
        )
        .unwrap();
        vm.write_guest(0x10100, &[0x5a, 0, 0xee]).unwrap();
        let probe = vm.allocation_probe(0);
        let candidate =
            <Memory as dillo_machine::Memory>::from_ranges(&[dillo_machine::RamRange {
                gpa: 0x10000,
                size: 0x1000,
            }])
            .unwrap();
        assert!(matches!(
            vm.set_memory(candidate),
            Err(Error::MemoryAlreadyRegistered)
        ));
        let mut cpu = vm.create_vcpu(0, "x86-64-v1").unwrap();
        cpu.initialize_test_real_mode(0x10000, 0).unwrap();
        let exit = cpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(exit, VmExit::Halted), "{exit:?}");
        let mut bytes = [0; 3];
        vm.guest_memory()
            .unwrap()
            .read_slice(&mut bytes, GuestAddress(0x10100))
            .unwrap();
        assert_eq!(bytes, [0x5a, 0x5a, 0xee]);
        drop(vm);
        probe.assert_retained();
        drop(cpu);
        probe.assert_reclaimed();
    }

    #[test]
    fn whp_partial_mapping_retains_every_attempted_allocation() {
        let _guard = whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            NativeMemoryTest::spawn(
                "hypervisor::memory_tests::whp_partial_mapping_retains_every_attempted_allocation",
            )
            .verify();
            return;
        }
        let mut vm = Vm::new().expect("native WHP is required");
        let memory = <Memory as dillo_machine::Memory>::from_ranges(&[
            dillo_machine::RamRange {
                gpa: 0x10000,
                size: 0x1000,
            },
            dillo_machine::RamRange {
                gpa: 0x20000,
                size: 0x1000,
            },
        ])
        .unwrap();
        memory
            .guest()
            .write_slice(&[0xf4], GuestAddress(0x10000))
            .unwrap();
        let first = AllocationProbe::new(memory.guest(), 0);
        let second = AllocationProbe::new(memory.guest(), 1);
        *vm.inner.fail_map_at.lock().unwrap() = Some(1);
        assert!(matches!(
            vm.set_memory(memory),
            Err(Error::MapGpa { gpa: 0x20000, .. })
        ));
        assert!(matches!(
            vm.guest_memory(),
            Err(Error::MemoryRegistrationFailed {
                attempts: 2,
                regions: 2
            })
        ));
        assert!(
            vm.cpu_creator().is_err(),
            "normal CPU preparation must not escape failed registration"
        );
        assert!(matches!(
            vm.add_memory(0x30000, 0x1000),
            Err(Error::MemoryAlreadyRegistered)
        ));
        first.assert_retained();
        second.assert_retained();
        // Only this native test bypasses normal readiness: prove the real first
        // map is still usable after the injected second map failure.
        let mut cpu = vm.create_vcpu(0, "x86-64-v1").unwrap();
        cpu.initialize_test_real_mode(0x10000, 0).unwrap();
        let exit = cpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(exit, VmExit::Halted), "{exit:?}");
        let service = vm.interrupt_controller();
        drop(vm);
        drop(cpu);
        first.assert_retained();
        second.assert_retained();
        drop(service);
        first.assert_reclaimed();
        second.assert_reclaimed();
    }

    #[test]
    fn whp_constructor_rollback_deletes_the_created_partition() {
        let _guard = whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            NativeMemoryTest::spawn(
                "hypervisor::memory_tests::whp_constructor_rollback_deletes_the_created_partition",
            )
            .verify();
            return;
        }
        let before = raw::DELETED_PARTITIONS.with(|deleted| deleted.borrow().len());
        // This reaches the constructor's real native setup-error branch,
        // rather than its earlier Rust processor-count validation. Native CI
        // must establish that this incomplete configuration is rejected.
        let failure = Vm::new_with_options(PartitionOptions::default(), true);
        assert!(
            matches!(failure, Err(Error::SetupPartition(_))),
            "{failure:?}"
        );
        assert_eq!(
            raw::DELETED_PARTITIONS.with(|deleted| deleted.borrow().len()),
            before + 1,
            "successful native delete must precede constructor failure return"
        );
        let vm = Vm::new().expect("native reconstruction is required");
        drop(vm);
        assert_eq!(
            raw::DELETED_PARTITIONS.with(|deleted| deleted.borrow().len()),
            before + 2
        );
    }

    /// Owns/reaps isolated native assertions, including failure children, on unwind.
    pub(crate) struct NativeMemoryTest {
        child: std::process::Child,
        output: Option<std::thread::JoinHandle<std::io::Result<String>>>,
    }

    impl NativeMemoryTest {
        pub(crate) fn spawn(name: &str) -> Self {
            use std::io::Read as _;
            let mut test = Self {
                child: std::process::Command::new(std::env::current_exe().unwrap())
                    .args([name, "--exact", "--nocapture", "--test-threads=1"])
                    .env("DILLO_WHP_MEMORY_CHILD", "1")
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
                output: None,
            };
            let mut stdout = test.child.stdout.take().unwrap();
            test.output = Some(
                std::thread::Builder::new()
                    .spawn(move || {
                        let mut output = String::new();
                        stdout.read_to_string(&mut output)?;
                        Ok(output)
                    })
                    .unwrap(),
            );
            test
        }

        fn finish(&mut self) -> (std::process::ExitStatus, String) {
            use wait_timeout::ChildExt;
            let status = self
                .child
                .wait_timeout(std::time::Duration::from_secs(30))
                .unwrap()
                .expect("native memory assertion child exceeded 30 seconds");
            let output = self.output.take().unwrap().join().unwrap().unwrap();
            print!("{output}");
            (status, output)
        }

        pub(crate) fn verify(mut self) {
            let (status, output) = self.finish();
            assert!(
                status.success(),
                "native WHP memory assertions failed: {status}"
            );
            assert!(
                output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
                "the native child must execute exactly one assertion case"
            );
        }

        fn verify_abort(mut self) {
            let (status, _) = self.finish();
            // Rust's Windows abort uses __fastfail(FAST_FAIL_FATAL_APP_EXIT).
            // https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail
            assert_eq!(
                status.code().map(|code| code as u32),
                Some(0xc000_0409),
                "{status}"
            );
        }
    }

    impl Drop for NativeMemoryTest {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(output) = self.output.take() {
                let _ = output.join();
            }
        }
    }

    #[test]
    fn whp_failed_partition_delete_aborts_before_ram_release() {
        let _guard = whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            NativeMemoryTest::spawn(
                "hypervisor::memory_tests::whp_failed_partition_delete_aborts_before_ram_release",
            )
            .verify_abort();
            return;
        }
        let mut vm = Vm::new().expect("native WHP is required");
        vm.add_memory(0x10000, 0x1000).unwrap();
        vm.allocation_probe(0).assert_retained();
        // Inject only the existing native deletion boundary's error result. The
        // actual partition and its GPA mapping still exist when Drop must abort.
        Arc::get_mut(&mut vm.inner).unwrap().fail_delete = true;
        drop(vm);
        panic!("failed native partition destruction must not continue to RAM cleanup");
    }
}
