// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host-neutral machine boundary for dillo.
//!
//! This crate owns the narrow VM-facing traits shared by backend machine
//! implementations. Concrete backend crates implement this trait boundary, and
//! the top-level `dillo` launcher composes only through these APIs.

use std::sync::atomic::AtomicBool;

/// Architectural Arm guest feature admission shared by native Machine families.
pub mod aarch64;

/// x86_64 `cpu:profile` validation policy shared by KVM and WHP backends.
#[cfg(target_arch = "x86_64")]
pub mod cpuid_x86;

/// Selected-machine launch configuration derived by dillo from PMI and DTB.
#[derive(Debug)]
pub struct LaunchConfig {
    pub dtb: Vec<u8>,
    pub vcpus: u32,
    /// Required width of the declared platform and every planned RAM extent.
    pub min_addr_space_bits: u32,
}

/// One DTB/launch-derived guest RAM range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRange {
    pub gpa: u64,
    pub size: u64,
}

/// Architecture-typed ISA baseline selected by the PMI manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuProfile {
    X86_64(pmi::x86_64::Profile),
    Aarch64(pmi::aarch64::Profile),
}

impl CpuProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64(pmi::x86_64::Profile::V1) => "x86-64-v1",
            Self::X86_64(pmi::x86_64::Profile::V2) => "x86-64-v2",
            Self::X86_64(pmi::x86_64::Profile::V3) => "x86-64-v3",
            Self::X86_64(pmi::x86_64::Profile::V4) => "x86-64-v4",
            Self::Aarch64(pmi::aarch64::Profile::V8_0) => "armv8.0-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_1) => "armv8.1-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_2) => "armv8.2-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_3) => "armv8.3-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_4) => "armv8.4-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_5) => "armv8.5-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_6) => "armv8.6-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_7) => "armv8.7-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_8) => "armv8.8-a",
            Self::Aarch64(pmi::aarch64::Profile::V8_9) => "armv8.9-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_0) => "armv9.0-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_1) => "armv9.1-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_2) => "armv9.2-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_3) => "armv9.3-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_4) => "armv9.4-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_5) => "armv9.5-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_6) => "armv9.6-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_7) => "armv9.7-a",
            Self::Aarch64(pmi::aarch64::Profile::V9_8) => "armv9.8-a",
        }
    }
}

/// Host architecture exposed by the selected machine backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArchitecture {
    X86_64,

    Aarch64,
}

/// Decode the architectural ARM physical-address range, rejecting reserved
/// encodings instead of inventing a usable width.
pub fn aarch64_pa_bits(mmfr0: u64) -> Option<u32> {
    [32, 36, 40, 42, 44, 48, 52, 56]
        .get((mmfr0 & 0xf) as usize)
        .copied()
}

/// Host-level services exposed by the selected machine backend.
pub trait Host {
    type RawStdioGuard: 'static;
    type LaunchInput: LaunchInput;

    const ARCH: HostArchitecture;

    /// Host-provided CPU `compatible` string for DT overlay CPU nodes, when the
    /// selected machine can derive one without inventing guest-visible facts.
    fn cpu_compatible() -> Option<&'static str> {
        None
    }

    fn enter_raw_stdio_if_tty() -> Self::RawStdioGuard;

    fn install_panic_terminal_restore();

    fn install_signal_watchers(supervisor_shutdown: &'static AtomicBool);
}

/// An immutable, privately owned capture of a launch file.
///
/// Capture completes before validation. Later source-file writes, truncation or
/// pathname replacement must not change any view, and writable guest memory must
/// never alias this backing. Native implementations belong to the selected host
/// family; construction does not require a live machine.
pub trait LaunchInput: std::fmt::Debug + Sized + 'static {
    type View<'a>: AsRef<[u8]>
    where
        Self: 'a;

    /// Consume an opened file and capture its contents from offset zero. Capture
    /// may observe concurrent source changes, but its completed bytes must be
    /// immutable before returning. Partial capture is an error.
    fn capture(source: std::fs::File) -> std::io::Result<Self>;

    /// Borrow the same captured bytes on every call. Dropping a view may release
    /// its mapping; it must not discard or reread the retained source contents.
    fn view(&self) -> std::io::Result<Self::View<'_>>;
}

/// Backend-owned memory input constructed from DTB-derived RAM ranges.
pub trait Memory: 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn from_ranges(ranges: &[RamRange]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Read-only observation of runtime's monotonic termination request.
pub trait CpuTermination: Send + Sync {
    fn is_requested(&self) -> bool;
}

impl CpuTermination for std::sync::atomic::AtomicBool {
    fn is_requested(&self) -> bool {
        self.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Shareable native wake mechanism. An interrupt is not a stopped acknowledgement.
pub trait CpuInterrupt: Clone + Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn interrupt(&self) -> Result<(), Self::Error>;
}

/// Machine-bound input consumed on the CPU's owner thread.
pub trait CpuPreparation: Send + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type Interrupt: CpuInterrupt<Error = Self::Error>;
    type Runner: CpuRunner<Error = Self::Error>;

    fn interrupt(&self) -> Self::Interrupt;
    fn prepare(self) -> Result<Self::Runner, Self::Error>;
}

/// Owner-local execution state, operated and destroyed on its preparing thread.
pub trait CpuRunner: 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn run(&mut self, termination: &dyn CpuTermination) -> Result<VcpuStop, Self::Error>;
}

/// A constructed VM capable of accepting DTB-derived resources and vCPUs.
pub trait Machine: Sized + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type CpuPreparation: CpuPreparation<Error = Self::Error>;
    type Memory: Memory<Error = Self::Error>;

    /// Bind one CPU input to this machine without creating its native runner.
    fn cpu_preparation(
        &mut self,
        index: u32,
        profile: CpuProfile,
    ) -> Result<Self::CpuPreparation, Self::Error>;

    /// Maximum usable guest address width under this backend's CPU/VM policy.
    /// Intersects guest-visible physical width with backend GPA/IPA capacity.
    /// Does not allocate RAM or execute a guest.
    fn guest_address_bits() -> Result<u32, Self::Error>;

    /// Construct the backend VM from selected-machine launch facts.
    fn from_launch_config(config: LaunchConfig) -> Result<Self, Self::Error>;

    /// Write launch data into guest RAM through backend-owned memory access.
    fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Self::Error>;

    /// Explicitly zero an existing guest RAM range; allocation contents are
    /// not a substitute for this ordered launch operation.
    fn zero_guest(&mut self, gpa: u64, len: u64) -> Result<(), Self::Error>;

    /// Prepare backend-owned run state after all vCPUs have been created.
    fn prepare_vcpu_run(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Reset backend-owned state before replaying launch writes for a guest reboot.
    fn reset_for_reboot(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Successful vCPU lifecycle outcomes reported to the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuStop {
    /// The guest requested system poweroff.
    GuestPoweroff,

    /// The guest requested system reset.
    GuestReset,

    /// The supervisor requested that this vCPU stop running.
    Stopped,
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;
    use dillo_mmio::Attach;

    #[test]
    fn arm_physical_width_uses_parange_only() {
        for (encoding, bits) in [32, 36, 40, 42, 44, 48, 52, 56].into_iter().enumerate() {
            assert_eq!(aarch64_pa_bits(0xffff_fff0 | encoding as u64), Some(bits));
        }
        for encoding in 8..16 {
            assert_eq!(aarch64_pa_bits(encoding), None);
        }
    }

    #[derive(Debug)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test machine error")
        }
    }

    impl std::error::Error for TestError {}

    struct TestCpuState;

    #[derive(Clone)]
    struct TestInterrupt;
    impl CpuInterrupt for TestInterrupt {
        type Error = TestError;
        fn interrupt(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    impl CpuPreparation for TestCpuState {
        type Error = TestError;
        type Interrupt = TestInterrupt;
        type Runner = TestCpu;
        fn interrupt(&self) -> TestInterrupt {
            TestInterrupt
        }
        fn prepare(self) -> Result<TestCpu, TestError> {
            Ok(TestCpu {
                stop: VcpuStop::Stopped,
            })
        }
    }

    struct TestMemory;

    impl Memory for TestMemory {
        type Error = TestError;

        fn from_ranges(_ranges: &[RamRange]) -> Result<Self, Self::Error> {
            Ok(Self)
        }
    }

    struct TestCpu {
        stop: VcpuStop,
    }

    impl CpuRunner for TestCpu {
        type Error = TestError;
        fn run(&mut self, _: &dyn CpuTermination) -> Result<VcpuStop, Self::Error> {
            Ok(self.stop)
        }
    }

    struct TestMachine;

    impl Attach<TestMemory> for TestMachine {
        type Error = TestError;
        type Output = ();

        fn attach(&mut self, _item: TestMemory) -> Result<Self::Output, Self::Error> {
            Ok(())
        }
    }

    impl Machine for TestMachine {
        type Error = TestError;
        type CpuPreparation = TestCpuState;
        fn cpu_preparation(&mut self, _: u32, _: CpuProfile) -> Result<TestCpuState, Self::Error> {
            Ok(TestCpuState)
        }
        type Memory = TestMemory;

        fn guest_address_bits() -> Result<u32, Self::Error> {
            Ok(48)
        }

        fn from_launch_config(_config: LaunchConfig) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        fn write_guest(&mut self, _gpa: u64, _data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn zero_guest(&mut self, _gpa: u64, _len: u64) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn machine_uses_common_launch_ram_and_vcpu_api() {
        let mut machine = TestMachine;
        let memory = TestMemory::from_ranges(&[RamRange {
            gpa: 0x1000,
            size: 0x2000,
        }])
        .expect("memory constructed");
        Attach::attach(&mut machine, memory).expect("RAM attached");
        machine
            .write_guest(0x1000, b"boot")
            .expect("guest write accepted");
        let input = machine
            .cpu_preparation(0, CpuProfile::X86_64(pmi::x86_64::Profile::V1))
            .expect("bind CPU");
        input.interrupt().interrupt().expect("request progress");
        let mut runner = input.prepare().expect("CPU prepared on owner");
        assert_eq!(
            runner
                .run(&std::sync::atomic::AtomicBool::new(false))
                .expect("CPU ran"),
            VcpuStop::Stopped
        );
    }
}
