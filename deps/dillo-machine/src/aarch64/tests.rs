// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn minimum() -> CpuSnapshot {
    CpuSnapshot {
        pfr0: 0x00ff_0011,
        isar0: 0,
        mmfr0: 0,
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
        pmi::aarch64::Profile::V8_1,
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
