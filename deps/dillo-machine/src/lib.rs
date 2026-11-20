// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host-neutral machine boundary for dillo.
//!
//! This crate owns the narrow VM-facing traits shared by backend machine
//! implementations. Concrete backend crates implement this trait boundary, and
//! the top-level `dillo` launcher composes only through these APIs.

use std::sync::atomic::AtomicBool;

/// x86_64 `cpu:profile` validation policy shared by KVM and WHP backends.
#[cfg(target_arch = "x86_64")]
pub mod cpuid_x86;

/// Selected-machine launch configuration derived by dillo from PMI and DTB.
#[derive(Debug)]
pub struct LaunchConfig<'a, Platform> {
    /// The backend's surveyed platform, borrowed for native construction.
    pub platform: &'a Platform,
    pub vcpus: u32,
    /// The exact ordered RAM extents requested for this machine.
    pub ram: Vec<RamRange>,
}

/// One DTB/launch-derived guest RAM range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRange {
    pub gpa: u64,
    pub size: u64,
}

/// PMI ISA baseline for the architecture selected by the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuProfile {
    X86_64(pmi::x86_64::Profile),
    Aarch64(pmi::aarch64::Profile),
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

/// Mandatory Armv8.0-A features for an AArch64 guest (Arm 109697 §9.1).
/// Check the native guest-visible ID_AA64PFR0_EL1 and CTR_EL0 values.
pub fn armv8_0_missing_feature(pfr0: u64, ctr: u64) -> Option<&'static str> {
    if !matches!(pfr0 & 0xf, 1 | 2) {
        Some("FEAT_EL0")
    } else if !matches!((pfr0 >> 4) & 0xf, 1 | 2) {
        Some("FEAT_EL1")
    } else if !matches!((ctr >> 14) & 0x3, 2 | 3) {
        Some("FEAT_IVIPT")
    } else {
        None
    }
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

/// Machine-bound input consumed on a CPU's owner thread.
pub trait CpuPreparation: Send + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type Runner: CpuRunner<Error = Self::Error>;
    type Control: CpuControl<Error = Self::Error>;

    fn prepare(self) -> Result<(Self::Runner, Self::Control), Self::Error>;
}

/// Native execution state operated and destroyed by its preparing thread.
pub trait CpuRunner: 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn run(&mut self) -> Result<VcpuStop, Self::Error>;

    /// Release native execution state before the owner reports completion.
    fn retire(self) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        drop(self);
        Ok(())
    }
}

/// A shareable endpoint for requesting stop and waking the CPU's owner.
pub trait CpuControl: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Record the stop request and wake the owner if it is still live.
    fn stop(&self) -> Result<(), Self::Error>;
}

/// A constructed VM capable of accepting DTB-derived resources and vCPUs.
pub trait Machine: Sized + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Platform input accepted by this Machine's launch constructor.
    type Platform;
    type CpuPreparation: CpuPreparation<Error = Self::Error>;

    /// Bind launch CPU inputs to this machine without creating a native runner.
    fn cpu_preparation(
        &mut self,
        index: u32,
        profile: CpuProfile,
    ) -> Result<Self::CpuPreparation, Self::Error>;

    /// Maximum usable guest address width under this backend's CPU/VM policy.
    /// Intersects guest-visible physical width with backend GPA/IPA capacity.
    /// Does not allocate RAM or execute a guest.
    fn guest_address_bits() -> Result<u32, Self::Error>;

    /// Construct the backend VM with its admitted guest RAM registered.
    fn from_launch_config(config: LaunchConfig<'_, Self::Platform>) -> Result<Self, Self::Error>;

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
    use super::*;
    use std::fmt;

    #[test]
    fn arm_physical_width_uses_parange_only() {
        for (encoding, bits) in [32, 36, 40, 42, 44, 48, 52, 56].into_iter().enumerate() {
            assert_eq!(aarch64_pa_bits(0xffff_fff0 | encoding as u64), Some(bits));
        }
        for encoding in 8..16 {
            assert_eq!(aarch64_pa_bits(encoding), None);
        }
    }

    #[test]
    fn arm_floor_requires_each_guest_visible_feature() {
        assert_eq!(armv8_0_missing_feature(0x11, 3 << 14), None);
        assert_eq!(armv8_0_missing_feature(0x22, 2 << 14), None);
        assert_eq!(armv8_0_missing_feature(0x10, 3 << 14), Some("FEAT_EL0"));
        assert_eq!(armv8_0_missing_feature(0x01, 3 << 14), Some("FEAT_EL1"));
        assert_eq!(armv8_0_missing_feature(0x11, 1 << 14), Some("FEAT_IVIPT"));
    }

    #[derive(Debug)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test machine error")
        }
    }

    impl std::error::Error for TestError {}

    struct TestCpuPreparation;

    impl CpuPreparation for TestCpuPreparation {
        type Error = TestError;
        type Runner = TestCpu;
        type Control = TestCpuControl;

        fn prepare(self) -> Result<(Self::Runner, Self::Control), Self::Error> {
            Ok((TestCpu, TestCpuControl))
        }
    }

    struct TestCpu;

    impl CpuRunner for TestCpu {
        type Error = TestError;

        fn run(&mut self) -> Result<VcpuStop, Self::Error> {
            Ok(VcpuStop::Stopped)
        }
    }

    struct TestCpuControl;

    impl CpuControl for TestCpuControl {
        type Error = TestError;

        fn stop(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct TestMachine;

    impl Machine for TestMachine {
        type Error = TestError;
        type Platform = ();
        type CpuPreparation = TestCpuPreparation;

        fn cpu_preparation(
            &mut self,
            _index: u32,
            _profile: CpuProfile,
        ) -> Result<Self::CpuPreparation, Self::Error> {
            Ok(TestCpuPreparation)
        }

        fn guest_address_bits() -> Result<u32, Self::Error> {
            Ok(48)
        }

        fn from_launch_config(
            _config: LaunchConfig<'_, Self::Platform>,
        ) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        fn write_guest(&mut self, _gpa: u64, _data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn machine_uses_common_launch_ram_and_vcpu_api() {
        let mut machine = TestMachine::from_launch_config(LaunchConfig {
            platform: &(),
            vcpus: 1,
            ram: vec![RamRange {
                gpa: 0x1000,
                size: 0x2000,
            }],
        })
        .expect("machine constructed");
        machine
            .write_guest(0x1000, b"boot")
            .expect("guest write accepted");
        let preparation = machine
            .cpu_preparation(0, CpuProfile::X86_64(pmi::x86_64::Profile::V1))
            .unwrap();
        let (mut cpu, control) = preparation.prepare().unwrap();
        control.stop().expect("CPU stopped");
        assert_eq!(cpu.run().expect("CPU ran"), VcpuStop::Stopped);
    }
}
