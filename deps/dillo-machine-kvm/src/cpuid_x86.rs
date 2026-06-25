// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `cpu:profile` → KVM CPUID validation for x86_64.
//!
//! Per `pmi/spec/cpu.md`, the VMM MUST refuse to launch if the host
//! cannot deliver every mandatory feature of the requested profile.
//! Per-feature CPUID check; the host's claimed vendor/family is not
//! trusted.
//!
//! Microarchitecture levels per the System V x86-64 psABI. Each level
//! is a strict superset of the one below.

use kvm_bindings::CpuId;

/// Microarchitecture level parsed from a `cpu:profile` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum X86Level {
    V1,
    V2,
    V3,
    V4,
}

impl X86Level {
    /// Parse `x86-64-vN` (N ∈ {1,2,3,4}). Returns `None` for any
    /// other string; caller produces a "profile not recognized"
    /// error so the message names the bad input.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "x86-64-v1" => Some(Self::V1),
            "x86-64-v2" => Some(Self::V2),
            "x86-64-v3" => Some(Self::V3),
            "x86-64-v4" => Some(Self::V4),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "x86-64-v1",
            Self::V2 => "x86-64-v2",
            Self::V3 => "x86-64-v3",
            Self::V4 => "x86-64-v4",
        }
    }

    /// Mandatory features at and below this level (cumulative).
    fn cumulative_features(self) -> &'static [CpuidFeature] {
        match self {
            Self::V1 => V1_FEATURES,
            Self::V2 => V1_V2_FEATURES,
            Self::V3 => V1_V2_V3_FEATURES,
            Self::V4 => V1_V2_V3_V4_FEATURES,
        }
    }
}

/// One mandatory feature bit identified by its CPUID location.
#[derive(Debug, Clone, Copy)]
struct CpuidFeature {
    function: u32,
    index: u32,
    reg: Reg,
    bit: u8,
    name: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum Reg {
    // EAX-bit features exist (e.g. CPUID 7.1's `lass`) but no x86-64-vN
    // level demands one today; included for symmetry / future leaves.
    #[allow(dead_code)]
    Eax,
    Ebx,
    Ecx,
    Edx,
}

impl Reg {
    fn extract(self, entry: &kvm_bindings::kvm_cpuid_entry2) -> u32 {
        match self {
            Reg::Eax => entry.eax,
            Reg::Ebx => entry.ebx,
            Reg::Ecx => entry.ecx,
            Reg::Edx => entry.edx,
        }
    }
}

// CPUID feature bits per Intel SDM Vol. 2A "CPUID—CPU Identification" and
// AMD APM Vol. 3 "CPUID Specification". Each entry pinned by spec; the
// name is what error messages quote.

// Leaf 1 (EDX): legacy x87/MMX/SSE/SSE2 flags.
const FPU: CpuidFeature = bit(0x0000_0001, 0, Reg::Edx, 0, "fpu");
const CX8: CpuidFeature = bit(0x0000_0001, 0, Reg::Edx, 8, "cx8"); // CMPXCHG8B
const CMOV: CpuidFeature = bit(0x0000_0001, 0, Reg::Edx, 15, "cmov");
const MMX: CpuidFeature = bit(0x0000_0001, 0, Reg::Edx, 23, "mmx");
const FXSR: CpuidFeature = bit(0x0000_0001, 0, Reg::Edx, 24, "fxsr");
const SSE: CpuidFeature = bit(0x0000_0001, 0, Reg::Edx, 25, "sse");
const SSE2: CpuidFeature = bit(0x0000_0001, 0, Reg::Edx, 26, "sse2");

// Leaf 1 (ECX): SSE3 family, POPCNT, AVX, FMA, MOVBE, F16C, XSAVE.
const SSE3: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 0, "sse3");
const SSSE3: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 9, "ssse3");
const FMA: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 12, "fma");
const CX16: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 13, "cmpxchg16b");
const SSE4_1: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 19, "sse4.1");
const SSE4_2: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 20, "sse4.2");
const MOVBE: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 22, "movbe");
const POPCNT: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 23, "popcnt");
// XSAVE is the hardware bit (ECX[26]); XSAVE (ECX[27]) is the
// OS-visibility bit set by the guest writing CR4.XSAVE=1 at boot.
// For host-floor validation we check XSAVE — the guest is responsible
// for enabling XSAVE itself.
const XSAVE: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 26, "xsave");
const AVX: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 28, "avx");
const F16C: CpuidFeature = bit(0x0000_0001, 0, Reg::Ecx, 29, "f16c");

// Leaf 7 sub-leaf 0 (EBX): BMI1/BMI2, AVX2, AVX-512 family.
const BMI1: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 3, "bmi1");
const AVX2: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 5, "avx2");
const BMI2: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 8, "bmi2");
const AVX512F: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 16, "avx512f");
const AVX512DQ: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 17, "avx512dq");
const AVX512CD: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 28, "avx512cd");
const AVX512BW: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 30, "avx512bw");
const AVX512VL: CpuidFeature = bit(0x0000_0007, 0, Reg::Ebx, 31, "avx512vl");

// Leaf 0x8000_0001 (ECX): LAHF, LZCNT.
const LAHF_LM: CpuidFeature = bit(0x8000_0001, 0, Reg::Ecx, 0, "lahf-lm");
const LZCNT: CpuidFeature = bit(0x8000_0001, 0, Reg::Ecx, 5, "lzcnt");

const fn bit(function: u32, index: u32, reg: Reg, bit: u8, name: &'static str) -> CpuidFeature {
    CpuidFeature {
        function,
        index,
        reg,
        bit,
        name,
    }
}

// Per psABI: each level is a strict superset. Tables are pre-flattened
// so the validator iterates one slice — no recursion, no allocation.

const V1_FEATURES: &[CpuidFeature] = &[FPU, CX8, CMOV, MMX, FXSR, SSE, SSE2];

const V2_ADDITIONS: &[CpuidFeature] = &[CX16, LAHF_LM, POPCNT, SSE3, SSSE3, SSE4_1, SSE4_2];

const V3_ADDITIONS: &[CpuidFeature] = &[AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE];

const V4_ADDITIONS: &[CpuidFeature] = &[AVX512F, AVX512BW, AVX512CD, AVX512DQ, AVX512VL];

// Pre-flattened cumulative tables (const concat would need nightly).
const V1_V2_FEATURES: &[CpuidFeature] = &[
    FPU, CX8, CMOV, MMX, FXSR, SSE, SSE2, CX16, LAHF_LM, POPCNT, SSE3, SSSE3, SSE4_1, SSE4_2,
];

const V1_V2_V3_FEATURES: &[CpuidFeature] = &[
    FPU, CX8, CMOV, MMX, FXSR, SSE, SSE2, CX16, LAHF_LM, POPCNT, SSE3, SSSE3, SSE4_1, SSE4_2, AVX,
    AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE,
];

const V1_V2_V3_V4_FEATURES: &[CpuidFeature] = &[
    FPU, CX8, CMOV, MMX, FXSR, SSE, SSE2, CX16, LAHF_LM, POPCNT, SSE3, SSSE3, SSE4_1, SSE4_2, AVX,
    AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE, AVX512F, AVX512BW, AVX512CD, AVX512DQ,
    AVX512VL,
];

// Static asserts keep the cumulative tables honest: the per-level
// addition slices above must sum to the cumulative table lengths.
const _: () = {
    assert!(
        V1_V2_FEATURES.len() == V1_FEATURES.len() + V2_ADDITIONS.len(),
        "V1_V2_FEATURES table drift"
    );
    assert!(
        V1_V2_V3_FEATURES.len() == V1_V2_FEATURES.len() + V3_ADDITIONS.len(),
        "V1_V2_V3_FEATURES table drift"
    );
    assert!(
        V1_V2_V3_V4_FEATURES.len() == V1_V2_V3_FEATURES.len() + V4_ADDITIONS.len(),
        "V1_V2_V3_V4_FEATURES table drift"
    );
};

/// Return the first mandatory feature the host's supported CPUID
/// doesn't expose, if any.
pub(crate) fn first_missing(level: X86Level, supported: &CpuId) -> Option<&'static str> {
    for feat in level.cumulative_features() {
        if !host_has_feature(supported, feat) {
            return Some(feat.name);
        }
    }
    None
}

fn host_has_feature(supported: &CpuId, feat: &CpuidFeature) -> bool {
    for entry in supported.as_slice() {
        if entry.function == feat.function && entry.index == feat.index {
            return (feat.reg.extract(entry) >> feat.bit) & 1 == 1;
        }
    }
    false
}

/// Return the first mandatory feature the current Windows/Linux host CPU
/// does not expose through the native CPUID instruction.
///
/// This is used by WHP, which does not have KVM's `GET_SUPPORTED_CPUID`
/// ioctl. It is still a per-feature check against concrete CPUID bits, not a
/// vendor/family/model shortcut.
#[cfg(all(target_arch = "x86_64", any(target_os = "windows", test)))]
pub(crate) fn first_missing_native(level: X86Level) -> Option<&'static str> {
    for feat in level.cumulative_features() {
        if !native_has_feature(feat) {
            return Some(feat.name);
        }
    }
    None
}

#[cfg(all(target_arch = "x86_64", any(target_os = "windows", test)))]
fn native_has_feature(feat: &CpuidFeature) -> bool {
    let max = if feat.function >= 0x8000_0000 {
        core::arch::x86_64::__cpuid(0x8000_0000).eax
    } else {
        core::arch::x86_64::__cpuid(0).eax
    };
    if feat.function > max {
        return false;
    }

    let cpuid = core::arch::x86_64::__cpuid_count(feat.function, feat.index);
    let value = match feat.reg {
        Reg::Eax => cpuid.eax,
        Reg::Ebx => cpuid.ebx,
        Reg::Ecx => cpuid.ecx,
        Reg::Edx => cpuid.edx,
    };
    (value >> feat.bit) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_levels() {
        assert_eq!(X86Level::parse("x86-64-v1"), Some(X86Level::V1));
        assert_eq!(X86Level::parse("x86-64-v2"), Some(X86Level::V2));
        assert_eq!(X86Level::parse("x86-64-v3"), Some(X86Level::V3));
        assert_eq!(X86Level::parse("x86-64-v4"), Some(X86Level::V4));
        assert_eq!(X86Level::parse("x86-64-v5"), None);
        assert_eq!(X86Level::parse("armv8.2-a"), None);
    }

    #[test]
    fn levels_are_supersets() {
        let v1: std::collections::HashSet<_> = X86Level::V1
            .cumulative_features()
            .iter()
            .map(|f| f.name)
            .collect();
        let v2: std::collections::HashSet<_> = X86Level::V2
            .cumulative_features()
            .iter()
            .map(|f| f.name)
            .collect();
        let v3: std::collections::HashSet<_> = X86Level::V3
            .cumulative_features()
            .iter()
            .map(|f| f.name)
            .collect();
        let v4: std::collections::HashSet<_> = X86Level::V4
            .cumulative_features()
            .iter()
            .map(|f| f.name)
            .collect();
        assert!(v1.is_subset(&v2));
        assert!(v2.is_subset(&v3));
        assert!(v3.is_subset(&v4));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_cpuid_supports_at_least_v1() {
        assert_eq!(first_missing_native(X86Level::V1), None);
    }
}
