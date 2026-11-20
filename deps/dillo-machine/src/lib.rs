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

/// Immutable ID register values exposed by an Armv8.0-A guest owner.
#[derive(Clone, Copy, Debug)]
pub struct ArmV8Evidence {
    pub pfr0: u64,
    pub isar0: u64,
    /// Required when PFR0 exposes AArch32.
    pub isar5: Option<u64>,
    pub mmfr0: u64,
    pub dfr0: u64,
    pub ctr: u64,
}

impl ArmV8Evidence {
    pub fn exposes_aarch32(&self) -> bool {
        self.pfr0 & 15 >= 2
    }

    /// Check the architectural minimum and its direct conditions (Arm DDI0487
    /// M.c A2.2.1, D7.3, D8.18.2, D24.1.3 and the individual ID registers).
    pub fn validate(self, sctlr: u64) -> Result<(), &'static str> {
        // D24.2.92: PFR0 uses unsigned monotonic fields. 1 supports AArch64
        // and 2 adds AArch32.
        let el0 = self.pfr0 & 15;
        let el1 = (self.pfr0 >> 4) & 15;
        let el2 = (self.pfr0 >> 8) & 15;
        let el3 = (self.pfr0 >> 12) & 15;
        if el0 == 0 {
            return Err("FEAT_EL0 is missing");
        }
        if el1 == 0 {
            return Err("FEAT_EL1 is missing");
        }
        if (el1 >= 2 && el0 < 2)
            || (el2 >= 2 && el1 < 2)
            || (el3 >= 2 && (el1 < 2 || (el2 != 0 && el2 < 2)))
        {
            return Err("AArch32 exception levels require support at lower levels");
        }
        let snsmem = (self.mmfr0 >> 12) & 15; // D24.2.87
        if el3 != 0 && snsmem == 0 {
            return Err("EL3 requires the Secure/Nonsecure memory distinction");
        }

        // D8.18.2 and D24.2.41: CTR.L1Ip must identify VIPT or PIPT.
        if !matches!((self.ctr >> 14) & 3, 2 | 3) {
            return Err("CTR_EL0.L1Ip does not establish FEAT_IVIPT");
        }
        // Both signed fields may report absence (0xf).
        if (self.pfr0 >> 16) & 15 != (self.pfr0 >> 20) & 15 {
            return Err("FP and AdvSIMD encodings must agree");
        }
        // The two ISAR registers encode these four baseline capabilities at
        // the same offsets. Later encodings can add features such as SHA512.
        let crypto = |isar: u64| {
            let aes = (isar >> 4) & 15;
            [
                aes >= 1,
                aes >= 2,
                (isar >> 8) & 15 != 0,
                (isar >> 12) & 15 != 0,
            ]
        };
        let aarch64_crypto = crypto(self.isar0);
        let [_, _, sha1, sha256] = aarch64_crypto;
        if sha1 != sha256 {
            return Err("SHA1 and SHA2 must agree on presence");
        }
        if self.exposes_aarch32() {
            let isar5 = self
                .isar5
                .ok_or("AArch32 crypto requires ID_ISAR5_EL1 evidence")?;
            if crypto(isar5) != aarch64_crypto {
                return Err("AES, PMULL, SHA1 and SHA256 must agree across AArch32 and AArch64");
            }
        }

        // D7.3 and D24.2.87: use live SCTLR for the fixed-endian condition.
        let mixed_el1 = (self.mmfr0 >> 8) & 15 != 0;
        let mixed_el0 = (self.mmfr0 >> 16) & 15 != 0;
        if mixed_el1 && mixed_el0 {
            return Err("MMFR0.BigEndEL0 must be zero with MMFR0.BigEnd");
        }
        let ee = (sctlr >> 25) & 1;
        let e0e = (sctlr >> 24) & 1;
        if !mixed_el1 && !mixed_el0 && ee != e0e {
            return Err("fixed-endian EL0 and EL1 must use the same endianness");
        }
        // D24.2.79: TraceVer describes guest trace system registers.
        if (self.dfr0 >> 4) & 15 != 0 {
            return Err("FEAT_TRC_SR requires guest trace system-register support");
        }
        Ok(())
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

    const ARM_MINIMUM: ArmV8Evidence = ArmV8Evidence {
        pfr0: 0x00ff_0011,
        isar0: 0,
        isar5: None,
        mmfr0: 0,
        dfr0: 0,
        ctr: 3 << 14,
    };

    #[test]
    fn arm_baseline_accepts_optional_and_monotonic_encodings() {
        ARM_MINIMUM.validate(0).unwrap();
        ArmV8Evidence {
            pfr0: 0x0022_0033,
            isar5: Some(0),
            ctr: 2 << 14,
            ..ARM_MINIMUM
        }
        .validate(0)
        .unwrap();
        ArmV8Evidence {
            pfr0: 0x00ff_2222,
            isar5: Some(0),
            mmfr0: 1 << 12,
            ..ARM_MINIMUM
        }
        .validate(0)
        .unwrap();
        ArmV8Evidence {
            isar0: (2 << 4) | (1 << 8) | (1 << 12),
            ..ARM_MINIMUM
        }
        .validate(0)
        .unwrap();
        for mmfr0 in [2 << 8, 2 << 16] {
            ArmV8Evidence {
                mmfr0,
                ..ARM_MINIMUM
            }
            .validate(1 << 25)
            .unwrap();
        }
    }

    #[test]
    fn arm_baseline_checks_dual_state_crypto() {
        let aarch64_crypto = (2 << 4) | (1 << 8) | (2 << 12);
        let aarch32_crypto = (2 << 4) | (1 << 8) | (1 << 12);
        let evidence = ArmV8Evidence {
            pfr0: 0x12,
            isar0: aarch64_crypto,
            isar5: Some(aarch32_crypto),
            ..ARM_MINIMUM
        };
        evidence.validate(0).unwrap();
        assert!(
            ArmV8Evidence {
                isar5: None,
                ..evidence
            }
            .validate(0)
            .unwrap_err()
            .contains("ID_ISAR5_EL1")
        );
        for isar5 in [
            aarch32_crypto & !(15 << 4),  // No AES or PMULL.
            aarch32_crypto - (1 << 4),    // AES without PMULL.
            aarch32_crypto & !(15 << 8),  // No SHA1.
            aarch32_crypto & !(15 << 12), // No SHA256.
        ] {
            assert!(
                ArmV8Evidence {
                    isar5: Some(isar5),
                    ..evidence
                }
                .validate(0)
                .unwrap_err()
                .contains("across AArch32 and AArch64")
            );
        }
    }

    #[test]
    fn arm_baseline_checks_each_direct_condition() {
        for (evidence, sctlr, reason) in [
            (
                ArmV8Evidence {
                    pfr0: 0x00ff_0010,
                    ..ARM_MINIMUM
                },
                0,
                "FEAT_EL0",
            ),
            (
                ArmV8Evidence {
                    pfr0: 0x00ff_0001,
                    ..ARM_MINIMUM
                },
                0,
                "FEAT_EL1",
            ),
            (
                ArmV8Evidence {
                    pfr0: 0x00ff_0021,
                    ..ARM_MINIMUM
                },
                0,
                "AArch32",
            ),
            (
                ArmV8Evidence {
                    pfr0: 0x00ff_0211,
                    ..ARM_MINIMUM
                },
                0,
                "AArch32",
            ),
            (
                ArmV8Evidence {
                    pfr0: 0x00ff_2011,
                    ..ARM_MINIMUM
                },
                0,
                "AArch32",
            ),
            (
                ArmV8Evidence {
                    pfr0: 0x00ff_1011,
                    ..ARM_MINIMUM
                },
                0,
                "EL3",
            ),
            (
                ArmV8Evidence {
                    pfr0: 0x00f0_0011,
                    ..ARM_MINIMUM
                },
                0,
                "AdvSIMD",
            ),
            (
                ArmV8Evidence {
                    ctr: 0,
                    ..ARM_MINIMUM
                },
                0,
                "FEAT_IVIPT",
            ),
            (
                ArmV8Evidence {
                    ctr: 1 << 14,
                    ..ARM_MINIMUM
                },
                0,
                "FEAT_IVIPT",
            ),
            (
                ArmV8Evidence {
                    isar0: 1 << 8,
                    ..ARM_MINIMUM
                },
                0,
                "SHA1 and SHA2",
            ),
            (
                ArmV8Evidence {
                    isar0: 1 << 12,
                    ..ARM_MINIMUM
                },
                0,
                "SHA1 and SHA2",
            ),
            (
                ArmV8Evidence {
                    mmfr0: (1 << 8) | (1 << 16),
                    ..ARM_MINIMUM
                },
                0,
                "BigEndEL0",
            ),
            (ARM_MINIMUM, 1 << 25, "endianness"),
            (
                ArmV8Evidence {
                    dfr0: 1 << 4,
                    ..ARM_MINIMUM
                },
                0,
                "FEAT_TRC_SR",
            ),
        ] {
            let error = evidence.validate(sctlr).unwrap_err();
            assert!(error.contains(reason), "{error:?} must mention {reason}");
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
