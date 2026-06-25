// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host-neutral machine boundary for dillo.
//!
//! This crate owns the narrow VM-facing traits shared by backend machine
//! implementations. Concrete backend crates implement this trait boundary, and
//! the top-level `dillo` launcher composes only through these APIs.

use std::sync::atomic::AtomicBool;

/// Selected-machine launch configuration derived by dillo from PMI and DTB.
#[derive(Debug)]
pub struct LaunchConfig {
    pub dtb: Vec<u8>,
    pub vcpus: u32,
    pub min_addr_space_bits: u32,
}

/// One DTB/launch-derived guest RAM range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRange {
    pub gpa: u64,
    pub size: u64,
}

/// Arch-erased view of the PMI boot vCPU state.
///
/// Backends pick the arm they support; dillo never constructs backend-specific
/// CPU input structs directly.
pub trait BootVcpuState {
    fn x86_64(&self) -> Option<&pmi::vm::vcpu::x86_64::CpuState> {
        None
    }

    fn aarch64(&self) -> Option<&pmi::vm::vcpu::aarch64::CpuState> {
        None
    }
}

/// Host architecture exposed by the selected machine backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArchitecture {
    X86_64,

    Aarch64,
}

/// Host-level services exposed by the selected machine backend.
pub trait Host {
    type RawStdioGuard: 'static;

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

/// Backend-owned memory input constructed from DTB-derived RAM ranges.
pub trait Memory: 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn from_ranges(ranges: &[RamRange]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Backend-owned CPU input constructed from PMI/DTB-derived launch facts.
pub trait CpuState: Send + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn new(
        index: u32,
        cpu_profile: &str,
        boot_state: Option<&dyn BootVcpuState>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Backend-owned CPU object attached to a machine.
pub trait Cpu: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Run this CPU on the current thread until guest or supervisor stop.
    fn run(&self) -> Result<VcpuStop, Self::Error>;

    /// Make a currently running `run()` call return as soon as the backend can.
    fn stop(&self) -> Result<(), Self::Error>;
}

/// A constructed VM capable of accepting DTB-derived resources and vCPUs.
pub trait Machine: Sized + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type Cpu: Cpu<Error = Self::Error> + Send;
    type CpuState: CpuState<Error = Self::Error>;
    type Memory: Memory<Error = Self::Error>;

    /// Construct the backend VM from selected-machine launch facts.
    fn from_launch_config(config: LaunchConfig) -> Result<Self, Self::Error>;

    /// Write launch data into guest RAM through backend-owned memory access.
    fn write_guest(&mut self, gpa: u64, data: &[u8]) -> Result<(), Self::Error>;

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
    use std::sync::Arc;

    use super::*;
    use dillo_mmio::Attach;

    #[derive(Debug)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test machine error")
        }
    }

    impl std::error::Error for TestError {}

    struct TestCpuState;

    impl CpuState for TestCpuState {
        type Error = TestError;

        fn new(
            _index: u32,
            _cpu_profile: &str,
            _boot_state: Option<&dyn BootVcpuState>,
        ) -> Result<Self, Self::Error> {
            Ok(Self)
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

    impl Cpu for TestCpu {
        type Error = TestError;

        fn run(&self) -> Result<VcpuStop, Self::Error> {
            Ok(self.stop)
        }

        fn stop(&self) -> Result<(), Self::Error> {
            Ok(())
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

    impl Attach<TestCpuState> for TestMachine {
        type Error = TestError;
        type Output = Arc<TestCpu>;

        fn attach(&mut self, _item: TestCpuState) -> Result<Self::Output, Self::Error> {
            Ok(Arc::new(TestCpu {
                stop: VcpuStop::Stopped,
            }))
        }
    }

    impl Machine for TestMachine {
        type Error = TestError;
        type Cpu = TestCpu;
        type CpuState = TestCpuState;
        type Memory = TestMemory;

        fn from_launch_config(_config: LaunchConfig) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        fn write_guest(&mut self, _gpa: u64, _data: &[u8]) -> Result<(), Self::Error> {
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
        let state = TestCpuState::new(0, "test-profile", None).expect("CPU state constructed");
        let cpu = Attach::attach(&mut machine, state).expect("CPU attached");

        cpu.stop().expect("CPU stopped");
        assert_eq!(cpu.run().expect("CPU ran"), VcpuStop::Stopped);
    }
}
