// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn minimum() -> CpuSnapshot {
    CpuSnapshot {
        pfr0: 0x00ff_0011,
        isar0: 0,
        mmfr0: 0,
        mmfr1: 0,
        dfr0: 0,
        ctr: 3 << 14,
        sctlr: 0,
    }
}

#[test]
fn architectural_minimum_does_not_require_optional_instructions_or_levels() {
    minimum().admit(pmi::aarch64::Profile::V8_0).unwrap();
    let mut simd = minimum();
    simd.pfr0 &= !0x00ff_0000;
    simd.admit(pmi::aarch64::Profile::V8_0).unwrap();
    let mut advanced = minimum();
    advanced.pfr0 = 0x0022_0033; // unsigned and signed standard IDs permit extension.
    advanced.admit(pmi::aarch64::Profile::V8_0).unwrap();
}

#[test]
fn every_mandatory_property_is_checked_individually() {
    for (pfr0, ctr, expected) in [
        (0x00ff_0010, 3 << 14, "EL0"),
        (0x00ff_0001, 3 << 14, "EL1"),
        (0x00ff_0011, 0, "IVIPT"),
        (0x00ff_0011, 1 << 14, "IVIPT"),
    ] {
        let mut snapshot = minimum();
        snapshot.pfr0 = pfr0;
        snapshot.ctr = ctr;
        assert!(
            snapshot
                .admit(pmi::aarch64::Profile::V8_0)
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
    }
    let mut vipt = minimum();
    vipt.ctr = 2 << 14;
    vipt.admit(pmi::aarch64::Profile::V8_0).unwrap();
}

#[test]
fn direct_baseline_conditions_refuse_contradictions() {
    let mut cases = Vec::new();
    let mut snapshot = minimum();
    snapshot.pfr0 = 0x00ff_0021;
    cases.push(snapshot);
    let mut snapshot = minimum();
    snapshot.pfr0 = 0x00ff_0211;
    cases.push(snapshot);
    let mut snapshot = minimum();
    snapshot.pfr0 = 0x00ff_2011;
    cases.push(snapshot);
    let mut snapshot = minimum();
    snapshot.pfr0 = 0x00ff_1011;
    cases.push(snapshot);
    let mut snapshot = minimum();
    snapshot.pfr0 = 0x00f0_0011;
    cases.push(snapshot);
    let mut snapshot = minimum();
    snapshot.isar0 = 1 << 12;
    cases.push(snapshot);
    let mut snapshot = minimum();
    snapshot.sctlr = 1 << 25;
    cases.push(snapshot);
    let mut snapshot = minimum();
    snapshot.mmfr0 = (1 << 8) | (1 << 16);
    cases.push(snapshot);
    for snapshot in cases {
        assert!(matches!(
            snapshot.admit(pmi::aarch64::Profile::V8_0),
            Err(AdmissionError::Contradiction(_))
        ));
    }
}

#[test]
fn optional_crypto_endianness_and_aarch32_do_not_raise_the_floor() {
    let mut snapshot = minimum();
    snapshot.isar0 = (2 << 4) | (1 << 8) | (1 << 12);
    snapshot.pfr0 = 0x00ff_0022;
    snapshot.admit(pmi::aarch64::Profile::V8_0).unwrap();
    // EL2/EL3 do not import v8.1 VHE/LSE, and optional AArch32 remains valid.
    let mut higher_levels = minimum();
    higher_levels.pfr0 = 0x00ff_2222;
    higher_levels.mmfr0 = 1 << 12;
    higher_levels.admit(pmi::aarch64::Profile::V8_0).unwrap();
    for (mmfr0, sctlr) in [
        (0, 0x0300_0000),
        (1 << 16, 1 << 25),
        (1 << 8, 1 << 24),
        (2 << 8, 0x0300_0000),
        (2 << 16, 1 << 25),
    ] {
        let mut snapshot = minimum();
        snapshot.mmfr0 = mmfr0;
        snapshot.sctlr = sctlr;
        snapshot.admit(pmi::aarch64::Profile::V8_0).unwrap();
    }
}

#[test]
fn missing_native_reads_are_never_observed_zero() {
    for absent in Register::ALL {
        let result = CpuSnapshot::capture(|register| {
            if register == absent {
                Err(AdmissionError::Unavailable {
                    register,
                    reason: "native selector absent".into(),
                })
            } else {
                Ok(minimum().value(register))
            }
        });
        assert!(
            matches!(result, Err(AdmissionError::Unavailable { register, .. }) if register == absent)
        );
    }
}

#[test]
fn unresolved_context_and_higher_profiles_have_explicit_diagnostics() {
    let mut snapshot = minimum();
    snapshot.dfr0 = 1 << 4;
    assert!(matches!(
        snapshot.admit(pmi::aarch64::Profile::V8_0),
        Err(AdmissionError::Unevidenced(_))
    ));
    for profile in [
        pmi::aarch64::Profile::V8_2,
        pmi::aarch64::Profile::V9_0,
        pmi::aarch64::Profile::V9_8,
    ] {
        assert_eq!(
            minimum().admit(profile).unwrap_err(),
            AdmissionError::UnsupportedProfile(profile)
        );
    }
}

fn minimum_v81() -> CpuSnapshot {
    let mut snapshot = minimum();
    snapshot.isar0 = (1 << 16) | (2 << 20);
    snapshot.mmfr1 = (1 << 12) | (1 << 16) | (1 << 20);
    snapshot
}

#[test]
fn v81_minimum_keeps_simd_pmu_el2_and_table_extensions_optional() {
    minimum_v81().admit(pmi::aarch64::Profile::V8_1).unwrap();
    // In particular HAFDBS, VMIDBits, VHE, crypto and FP16 remain zero.
    assert_eq!(minimum_v81().mmfr1 & 0xfff, 0);
    let mut el3 = minimum_v81();
    el3.pfr0 |= 1 << 12; // EL3 does not require guest EL2/VHE.
    el3.mmfr0 |= 1 << 12; // Preserve the baseline Secure/Nonsecure condition.
    el3.admit(pmi::aarch64::Profile::V8_1).unwrap();
    let mut aarch32 = minimum_v81();
    aarch32.pfr0 = (aarch32.pfr0 & !0xff) | 0x22;
    aarch32.admit(pmi::aarch64::Profile::V8_1).unwrap();
    let mut future = minimum_v81();
    future.isar0 |= (15 << 16) | (15 << 20);
    future.mmfr1 |= (15 << 12) | (15 << 16) | (15 << 20);
    future.admit(pmi::aarch64::Profile::V8_1).unwrap();
}

#[test]
fn v81_each_mandatory_delta_requires_independent_evidence() {
    for (register, shift, feature) in [
        (Register::Isar0, 16, "FEAT_CRC32"),
        (Register::Isar0, 20, "FEAT_LSE"),
        (Register::Mmfr1, 12, "FEAT_HPDS"),
        (Register::Mmfr1, 16, "FEAT_LOR"),
        (Register::Mmfr1, 20, "FEAT_PAN"),
    ] {
        let mut snapshot = minimum_v81();
        match register {
            Register::Isar0 => snapshot.isar0 &= !(15 << shift),
            Register::Mmfr1 => snapshot.mmfr1 &= !(15 << shift),
            _ => unreachable!(),
        }
        assert_eq!(
            snapshot
                .clone()
                .admit(pmi::aarch64::Profile::V8_1)
                .unwrap_err(),
            AdmissionError::Missing(feature)
        );
        snapshot.admit(pmi::aarch64::Profile::V8_0).unwrap();
    }
    let mut reserved = minimum_v81();
    reserved.isar0 = (reserved.isar0 & !(15 << 20)) | (1 << 20);
    assert!(matches!(
        reserved.admit(pmi::aarch64::Profile::V8_1),
        Err(AdmissionError::Unevidenced(_))
    ));
}

#[test]
fn v81_signed_simd_presence_requires_rdm_without_requiring_fp16() {
    for simd in [0, 1, 7, 15] {
        let mut snapshot = minimum_v81();
        snapshot.pfr0 = (simd << 16) | (simd << 20) | 0x11;
        if simd == 15 {
            snapshot.admit(pmi::aarch64::Profile::V8_1).unwrap();
        } else {
            assert_eq!(
                snapshot
                    .clone()
                    .admit(pmi::aarch64::Profile::V8_1)
                    .unwrap_err(),
                AdmissionError::Missing("FEAT_RDM when AdvSIMD is present")
            );
            snapshot.isar0 |= 1 << 28;
            snapshot.admit(pmi::aarch64::Profile::V8_1).unwrap();
        }
    }
}

#[test]
fn v81_pmu_uses_architected_absence_and_monotonic_version_scheme() {
    for version in [0, 4, 5, 9, 14, 15] {
        let mut snapshot = minimum_v81();
        snapshot.dfr0 = version << 8;
        snapshot.admit(pmi::aarch64::Profile::V8_1).unwrap();
    }
    let mut old = minimum_v81();
    old.dfr0 = 1 << 8;
    assert_eq!(
        old.admit(pmi::aarch64::Profile::V8_1).unwrap_err(),
        AdmissionError::Missing("FEAT_PMUv3p1 when PMUv3 is present")
    );
    for version in [2, 3] {
        let mut snapshot = minimum_v81();
        snapshot.dfr0 = version << 8;
        assert!(matches!(
            snapshot.admit(pmi::aarch64::Profile::V8_1),
            Err(AdmissionError::Unevidenced(_))
        ));
    }
}

#[test]
fn v81_el2_vhe_and_debug_conditions_apply_only_when_exposed() {
    let mut snapshot = minimum_v81();
    snapshot.dfr0 = 6;
    snapshot.clone().admit(pmi::aarch64::Profile::V8_1).unwrap();
    snapshot.pfr0 |= 1 << 8;
    assert_eq!(
        snapshot
            .clone()
            .admit(pmi::aarch64::Profile::V8_1)
            .unwrap_err(),
        AdmissionError::Missing("FEAT_VHE when AArch64 EL2 is present")
    );
    snapshot.mmfr1 |= 1 << 8;
    assert_eq!(
        snapshot
            .clone()
            .admit(pmi::aarch64::Profile::V8_1)
            .unwrap_err(),
        AdmissionError::Missing("FEAT_Debugv8p1 when VHE is present")
    );
    for debug in [7, 8, 15] {
        snapshot.dfr0 = debug;
        snapshot.clone().admit(pmi::aarch64::Profile::V8_1).unwrap();
    }
    snapshot.pfr0 &= !(15 << 8);
    assert_eq!(
        snapshot.admit(pmi::aarch64::Profile::V8_1).unwrap_err(),
        AdmissionError::Contradiction("FEAT_VHE requires AArch64 EL2")
    );
}

#[test]
fn sha_presence_conditions_apply_in_both_directions() {
    for isar0 in [1 << 8, 1 << 12] {
        let mut snapshot = minimum();
        snapshot.isar0 = isar0;
        assert!(
            matches!(snapshot.admit(pmi::aarch64::Profile::V8_0), Err(AdmissionError::Contradiction(rule)) if rule.contains("SHA1 and SHA2"))
        );
    }
}
