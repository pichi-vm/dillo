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
        isar1: Ok(0),
        mmfr2: Ok(0),
        a32_mmfr4: None,
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
    for absent in Register::ALL.into_iter().take(7) {
        let result = CpuSnapshot::capture(|register| {
            if register == absent {
                Err(AdmissionError::Unavailable {
                    register,
                    reason: "native selector absent".into(),
                })
            } else {
                minimum().value(register)
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
        pmi::aarch64::Profile::V8_3,
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

fn minimum_v82() -> CpuSnapshot {
    let mut snapshot = minimum_v81();
    snapshot.isar1 = Ok(1);
    snapshot.dfr0 = 8;
    snapshot.mmfr1 = (snapshot.mmfr1 & !(15 << 20)) | (2 << 20);
    snapshot.pfr0 |= 1 << 28;
    snapshot.mmfr2 = Ok(0x11);
    snapshot
}

#[test]
fn v82_minimum_preserves_optional_features_and_unsigned_forward_levels() {
    minimum_v82().admit(pmi::aarch64::Profile::V8_2).unwrap();
    let mut future = minimum_v82();
    future.isar1 = Ok(15);
    future.mmfr2 = Ok(0xff);
    future.dfr0 = 15;
    future.pfr0 |= 15 << 28;
    future.mmfr1 |= 15 << 20;
    future.admit(pmi::aarch64::Profile::V8_2).unwrap();
}

#[test]
fn v82_each_mandatory_delta_requires_independent_evidence() {
    for feature in [
        "FEAT_DPB",
        "FEAT_Debugv8p2",
        "FEAT_PAN2",
        "FEAT_RAS",
        "FEAT_TTCNP",
        "FEAT_UAO",
    ] {
        let mut snapshot = minimum_v82();
        match feature {
            "FEAT_DPB" => snapshot.isar1 = Ok(0),
            "FEAT_Debugv8p2" => snapshot.dfr0 = 7,
            "FEAT_PAN2" => snapshot.mmfr1 = (snapshot.mmfr1 & !(15 << 20)) | (1 << 20),
            "FEAT_RAS" => snapshot.pfr0 &= !(15 << 28),
            "FEAT_TTCNP" => snapshot.mmfr2 = Ok(0x10),
            "FEAT_UAO" => snapshot.mmfr2 = Ok(1),
            _ => unreachable!(),
        }
        let (register, observed, minimum) = match feature {
            "FEAT_DPB" => (Register::Isar1, 0, 1),
            "FEAT_Debugv8p2" => (Register::Dfr0, 7, 8),
            "FEAT_PAN2" => (Register::Mmfr1, 1, 2),
            "FEAT_RAS" => (Register::Pfr0, 0, 1),
            "FEAT_TTCNP" | "FEAT_UAO" => (Register::Mmfr2, 0, 1),
            _ => unreachable!(),
        };
        assert_eq!(
            snapshot
                .clone()
                .admit(pmi::aarch64::Profile::V8_2)
                .unwrap_err(),
            AdmissionError::MissingField {
                feature,
                register,
                observed,
                minimum
            }
        );
        snapshot.admit(pmi::aarch64::Profile::V8_1).unwrap();
    }
}

#[test]
fn additional_unavailable_inputs_are_retained_without_raising_earlier_profiles() {
    for absent in [Register::Isar1, Register::Mmfr2] {
        let snapshot = CpuSnapshot::capture(|register| {
            if register == absent {
                Err(AdmissionError::Unavailable {
                    register,
                    reason: "native additional selector absent".into(),
                })
            } else {
                minimum_v82().value(register)
            }
        })
        .unwrap();
        let expected = snapshot.value(absent).unwrap_err();
        assert!(
            matches!(expected, AdmissionError::Unavailable { register, .. } if register == absent)
        );
        snapshot.clone().admit(pmi::aarch64::Profile::V8_0).unwrap();
        snapshot.clone().admit(pmi::aarch64::Profile::V8_1).unwrap();
        assert_eq!(
            snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap_err(),
            expected
        );
    }
}

#[test]
fn v82_xnx_and_el2_describe_implementation_levels_not_guest_privilege() {
    let mut snapshot = minimum_v82();
    snapshot.pfr0 |= 1 << 8;
    snapshot.mmfr1 |= 1 << 8; // inherited VHE requirement
    assert_eq!(
        snapshot
            .clone()
            .admit(pmi::aarch64::Profile::V8_2)
            .unwrap_err(),
        AdmissionError::Missing("FEAT_XNX when EL2 is present")
    );
    snapshot.mmfr1 |= 1 << 28;
    snapshot.clone().admit(pmi::aarch64::Profile::V8_2).unwrap();
    snapshot.pfr0 &= !(15 << 8);
    snapshot.mmfr1 &= !(15 << 8);
    assert_eq!(
        snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap_err(),
        AdmissionError::Contradiction("FEAT_XNX requires EL2")
    );
}

#[test]
fn v82_optional_sve_and_fhm_require_fp16_only_when_present() {
    for sve in [false, true] {
        let mut snapshot = minimum_v82();
        if sve {
            snapshot.pfr0 |= 1 << 32;
        } else {
            snapshot.isar0 |= 1 << 48;
        }
        for fp in [15, 0] {
            let mut absent = snapshot.clone();
            absent.pfr0 = (absent.pfr0 & !0x00ff_0000) | (fp << 16) | (fp << 20);
            absent.isar0 |= 1 << 28; // SIMD0 independently requires RDM
            assert_eq!(
                absent.admit(pmi::aarch64::Profile::V8_2).unwrap_err(),
                AdmissionError::Missing("FEAT_FP16 when SVE or FHM is present")
            );
        }
        snapshot.pfr0 = (snapshot.pfr0 & !0x00ff_0000) | (1 << 16) | (1 << 20);
        snapshot.isar0 |= 1 << 28;
        snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap();
    }
}

#[test]
fn v82_crypto_conditions_include_sm_pairs_and_the_aes_or_sha1_definition() {
    let mut aes_only = minimum_v82();
    aes_only.isar0 |= 1 << 4;
    assert!(
        matches!(aes_only.clone().admit(pmi::aarch64::Profile::V8_2), Err(AdmissionError::Missing(rule)) if rule.contains("Crypto in v8.2"))
    );
    aes_only.admit(pmi::aarch64::Profile::V8_1).unwrap();
    for crypto in [
        2 << 4,
        (1 << 8) | (1 << 12),
        (1 << 4) | (1 << 36) | (1 << 40),
    ] {
        let mut snapshot = minimum_v82();
        snapshot.isar0 |= crypto;
        snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap();
    }
    for sm in [1 << 36, 1 << 40, (1 << 36) | (1 << 40)] {
        let mut snapshot = minimum_v82();
        snapshot.isar0 |= sm;
        assert!(matches!(
            snapshot.admit(pmi::aarch64::Profile::V8_2),
            Err(AdmissionError::Contradiction(_))
        ));
    }
}

#[test]
fn aarch32_hpd_keeps_its_el1_and_hpds2_condition() {
    let mut base = minimum_v82();
    base.mmfr1 = (base.mmfr1 & !(15 << 12)) | (2 << 12); // HPDS2 alone must not require AArch32
    CpuSnapshot::capture(|register| {
        assert_ne!(register, Register::A32Mmfr4);
        base.value(register)
    })
    .unwrap()
    .admit(pmi::aarch64::Profile::V8_2)
    .unwrap();
    base.pfr0 = (base.pfr0 & !0xff) | 0x22;
    for hpds in [None, Some(0), Some(1)] {
        let snapshot = CpuSnapshot::capture(|register| {
            if register == Register::A32Mmfr4 {
                hpds.map(|value| (value << 16) | (1 << 12) | (1 << 4))
                    .ok_or_else(|| AdmissionError::Unavailable {
                        register,
                        reason: "conditional native selector absent".into(),
                    })
            } else {
                base.value(register)
            }
        })
        .unwrap();
        snapshot.clone().admit(pmi::aarch64::Profile::V8_1).unwrap();
        match hpds {
            None => assert!(matches!(
                snapshot.admit(pmi::aarch64::Profile::V8_2),
                Err(AdmissionError::Unavailable {
                    register: Register::A32Mmfr4,
                    ..
                })
            )),
            Some(0) => assert!(
                matches!(snapshot.admit(pmi::aarch64::Profile::V8_2), Err(AdmissionError::Missing(rule)) if rule.contains("AA32HPD"))
            ),
            _ => {
                snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap();
            }
        }
    }
}

#[test]
fn sha3_sha512_and_crypto_coupling_preserves_forward_levels() {
    for sha in [
        1 << 32,
        (1 << 8) | (2 << 12),
        (1 << 8) | (1 << 12) | (1 << 32),
    ] {
        let mut snapshot = minimum_v82();
        snapshot.isar0 |= sha;
        assert!(matches!(
            snapshot.admit(pmi::aarch64::Profile::V8_2),
            Err(AdmissionError::Contradiction(_))
        ));
    }
    for sha in [
        (1 << 8) | (2 << 12) | (1 << 32),
        (15 << 8) | (15 << 12) | (15 << 32),
    ] {
        let mut snapshot = minimum_v82();
        snapshot.isar0 |= sha;
        snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap();
    }
}

#[test]
fn every_exposed_aarch32_state_requires_mmfr4_cnp_ac2_and_el2_xnx() {
    let mut el0 = minimum_v82();
    el0.pfr0 = (el0.pfr0 & !15) | 2;
    for value in [None, Some(0), Some(1 << 12), Some(1 << 4), Some(0x1010)] {
        let snapshot = CpuSnapshot::capture(|register| {
            if register == Register::A32Mmfr4 {
                value.ok_or_else(|| AdmissionError::Unavailable {
                    register,
                    reason: "AArch32 EL0-only evidence absent".into(),
                })
            } else {
                el0.value(register)
            }
        })
        .unwrap();
        snapshot.clone().admit(pmi::aarch64::Profile::V8_0).unwrap();
        snapshot.clone().admit(pmi::aarch64::Profile::V8_1).unwrap();
        match value {
            None => assert!(matches!(
                snapshot.admit(pmi::aarch64::Profile::V8_2),
                Err(AdmissionError::Unavailable {
                    register: Register::A32Mmfr4,
                    ..
                })
            )),
            Some(0x1010) => {
                snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap();
            }
            _ => assert!(
                matches!(snapshot.admit(pmi::aarch64::Profile::V8_2), Err(AdmissionError::Missing(rule)) if rule.contains("CnP and AC2"))
            ),
        }
    }
    let mut el2 = minimum_v82();
    el2.pfr0 = (el2.pfr0 & !0xfff) | 0x222;
    el2.mmfr1 |= (1 << 8) | (1 << 28);
    el2.a32_mmfr4 = Some(Ok(0x1010));
    assert!(
        matches!(el2.clone().admit(pmi::aarch64::Profile::V8_2), Err(AdmissionError::Missing(rule)) if rule.contains("MMFR4.XNX"))
    );
    el2.a32_mmfr4 = Some(Ok(0x1110));
    el2.admit(pmi::aarch64::Profile::V8_2).unwrap();
}

#[test]
fn deficient_native_field_diagnostic_does_not_excuse_a_capable_context() {
    let mut deficient = minimum_v82();
    deficient.dfr0 = 6;
    let error = deficient.admit(pmi::aarch64::Profile::V8_2).unwrap_err();
    assert_eq!(
        error.to_string(),
        "guest lacks required Arm property: FEAT_Debugv8p2 (ID_AA64DFR0_EL1 observed=0x6, minimum=0x8)"
    );
    minimum_v82().admit(pmi::aarch64::Profile::V8_2).unwrap();
}

#[test]
fn v82_lsmaoc_requires_an_exposed_aarch32_state() {
    for level in [1, 15] {
        let mut snapshot = minimum_v82();
        snapshot.mmfr2 = Ok(snapshot.mmfr2.unwrap() | (level << 8));
        assert_eq!(
            snapshot
                .clone()
                .admit(pmi::aarch64::Profile::V8_2)
                .unwrap_err(),
            AdmissionError::Contradiction("FEAT_LSMAOC requires AArch32")
        );
        snapshot.pfr0 = (snapshot.pfr0 & !15) | 2;
        snapshot.a32_mmfr4 = Some(Ok(0x1010));
        snapshot.admit(pmi::aarch64::Profile::V8_2).unwrap();
    }
}
