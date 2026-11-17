// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Arm architectural-minimum admission, DDI0487 M.c revision 1.
//!
//! A2.2.1 requires EL0, EL1 and IVIPT. Direct baseline conditions below use
//! D24.2.92 (PFR0), D24.2.83 (ISAR0), D24.2.87 (MMFR0), D24.2.41 (CTR),
//! D7.3 (endianness) and D24.1.3 (signed/unsigned ID interpretation).
//! Native AArch64 execution supplies inseparable base instructions; configurable
//! guest facts must come from the retained owner, including Dillo emulation.

use std::fmt;

/// Architectural inputs to baseline admission, never a native API discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    Pfr0,
    Isar0,
    Mmfr0,
    Dfr0,
    Ctr,
    Sctlr,
}
impl Register {
    pub const ALL: [Self; 6] = [
        Self::Pfr0,
        Self::Isar0,
        Self::Mmfr0,
        Self::Dfr0,
        Self::Ctr,
        Self::Sctlr,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Pfr0 => "ID_AA64PFR0_EL1",
            Self::Isar0 => "ID_AA64ISAR0_EL1",
            Self::Mmfr0 => "ID_AA64MMFR0_EL1",
            Self::Dfr0 => "ID_AA64DFR0_EL1",
            Self::Ctr => "CTR_EL0",
            Self::Sctlr => "SCTLR_EL1",
        }
    }
    /// Op0:Op1:CRn:CRm:Op2 encoding, also used by MRS and trapped ISS fields.
    pub const fn encoding(self) -> u16 {
        match self {
            Self::Pfr0 => 0xc020,
            Self::Isar0 => 0xc030,
            Self::Mmfr0 => 0xc038,
            Self::Dfr0 => 0xc028,
            Self::Ctr => 0xd801,
            Self::Sctlr => 0xc080,
        }
    }
    pub fn from_encoding(encoding: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|register| register.encoding() == encoding)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionError {
    UnsupportedProfile(pmi::aarch64::Profile),
    Unavailable { register: Register, reason: String },
    Missing(&'static str),
    Contradiction(&'static str),
    Unevidenced(&'static str),
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile(profile) => write!(
                f,
                "{} admission is not implemented",
                crate::CpuProfile::Aarch64(*profile).as_str()
            ),
            Self::Unavailable { register, reason } => write!(
                f,
                "guest {} evidence unavailable: {reason}",
                register.name()
            ),
            Self::Missing(feature) => write!(f, "guest lacks required Armv8.0 property: {feature}"),
            Self::Contradiction(rule) => write!(f, "contradictory guest Arm configuration: {rule}"),
            Self::Unevidenced(rule) => write!(f, "guest Arm condition is not evidenced: {rule}"),
        }
    }
}
impl std::error::Error for AdmissionError {}

/// Complete immutable owner evidence. A failed native read cannot become zero.
#[derive(Clone, Debug)]
pub struct CpuSnapshot {
    pfr0: u64,
    isar0: u64,
    mmfr0: u64,
    dfr0: u64,
    ctr: u64,
    sctlr: u64,
}
impl CpuSnapshot {
    pub fn capture(
        mut read: impl FnMut(Register) -> Result<u64, AdmissionError>,
    ) -> Result<Self, AdmissionError> {
        Ok(Self {
            pfr0: read(Register::Pfr0)?,
            isar0: read(Register::Isar0)?,
            mmfr0: read(Register::Mmfr0)?,
            dfr0: read(Register::Dfr0)?,
            ctr: read(Register::Ctr)?,
            sctlr: read(Register::Sctlr)?,
        })
    }
    pub const fn value(&self, register: Register) -> u64 {
        match register {
            Register::Pfr0 => self.pfr0,
            Register::Isar0 => self.isar0,
            Register::Mmfr0 => self.mmfr0,
            Register::Dfr0 => self.dfr0,
            Register::Ctr => self.ctr,
            Register::Sctlr => self.sctlr,
        }
    }
    pub fn admit(self, profile: pmi::aarch64::Profile) -> Result<AdmittedCpu, AdmissionError> {
        if profile != pmi::aarch64::Profile::V8_0 {
            return Err(AdmissionError::UnsupportedProfile(profile));
        }
        // PFR0 standard unsigned IDs: >=1 provides AArch64, >=2 adds AArch32.
        let el = [
            self.pfr0 & 15,
            (self.pfr0 >> 4) & 15,
            (self.pfr0 >> 8) & 15,
            (self.pfr0 >> 12) & 15,
        ];
        if el[0] == 0 {
            return Err(AdmissionError::Missing("FEAT_EL0 / AArch64 EL0"));
        }
        if el[1] == 0 {
            return Err(AdmissionError::Missing("FEAT_EL1 / AArch64 EL1"));
        }
        if (el[1] >= 2 && el[0] < 2)
            || (el[2] >= 2 && el[1] < 2)
            || (el[3] >= 2 && (el[1] < 2 || (el[2] != 0 && el[2] < 2)))
        {
            return Err(AdmissionError::Contradiction(
                "AArch32 exception-level support requires its lower execution states",
            ));
        }
        // D24.2.87 SNSMem: when EL3 exists, the absence of a Secure/Nonsecure
        // memory distinction is not permitted. No optional EL3 is required.
        let security_memory = (self.mmfr0 >> 12) & 15;
        if el[3] != 0 && security_memory == 0 {
            return Err(AdmissionError::Contradiction(
                "EL3 requires the MMFR0.SNSMem Secure/Nonsecure memory distinction",
            ));
        }
        // D8.18.2 R_XBHSB/R_XLZJK: only VIPT and PIPT implement IVIPT.
        match (self.ctr >> 14) & 3 {
            2 | 3 => {}
            1 => {
                return Err(AdmissionError::Missing(
                    "FEAT_IVIPT (AIVIVT is not permitted from Armv8.0)",
                ));
            }
            _ => {
                return Err(AdmissionError::Unevidenced(
                    "FEAT_IVIPT: reserved CTR_EL0.L1Ip encoding",
                ));
            }
        }
        // FP/AdvSIMD are signed IDs and optional. Their values must agree,
        // including 0xf (absent); neither FP16 nor RDM is a v8.0 requirement.
        if (self.pfr0 >> 16) & 15 != (self.pfr0 >> 20) & 15 {
            return Err(AdmissionError::Contradiction(
                "ID_AA64PFR0_EL1.FP and AdvSIMD must have equal values",
            ));
        }
        // PMULL=>AES is inherent in the shared AES field's monotonic levels.
        // D24.2.83 requires SHA1/SHA2 presence in both directions.
        let sha256 = (self.isar0 >> 12) & 15;
        let sha1 = (self.isar0 >> 8) & 15;
        if (sha256 == 0) != (sha1 == 0) {
            return Err(AdmissionError::Contradiction(
                "ID_AA64ISAR0_EL1.SHA1 and SHA2 must both be absent or both be present",
            ));
        }
        self.validate_endianness()?;
        // TraceVer is guest system-register trace, not merely external debug.
        // Its ETMv4/ETE realization cannot follow from a host trace capability.
        if (self.dfr0 >> 4) & 15 != 0 {
            return Err(AdmissionError::Unevidenced(
                "FEAT_TRC_SR requires guest ETMv4 or ETE system-register realization",
            ));
        }
        Ok(AdmittedCpu { snapshot: self })
    }
    fn validate_endianness(&self) -> Result<(), AdmissionError> {
        let mixed = (self.mmfr0 >> 8) & 15;
        let el0_mixed = (self.mmfr0 >> 16) & 15;
        // These follow D24.1.3's standard unsigned ID scheme: positive
        // extensions retain mixed-endian support, rather than being absence.
        match (mixed >= 1, el0_mixed >= 1) {
            (true, false) | (false, true) => Ok(()),
            (false, false) if ((self.sctlr >> 25) ^ (self.sctlr >> 24)) & 1 == 0 => Ok(()),
            (false, false) => Err(AdmissionError::Contradiction(
                "fixed-endian EL0 and EL1 must use matching endianness",
            )),
            (true, true) => Err(AdmissionError::Contradiction(
                "MMFR0.BigEndEL0 must be RES0 when BigEnd is set",
            )),
        }
    }
}

/// Evidence that the selected floor was checked on one retained native owner.
#[derive(Clone, Debug)]
pub struct AdmittedCpu {
    snapshot: CpuSnapshot,
}
impl AdmittedCpu {
    pub fn value(&self, register: Register) -> u64 {
        self.snapshot.value(register)
    }
}

#[cfg(test)]
mod tests;
