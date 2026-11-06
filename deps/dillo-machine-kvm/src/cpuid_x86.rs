// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! KVM-typed CPUID validation glue over shared x86 profile policy.
//!
//! Profile parse, feature table, and native CPUID checks live in
//! [`dillo_machine::cpuid_x86`]. This module keeps the `CpuId` /
//! `kvm_cpuid_entry2` path local so `dillo-machine` stays free of
//! `kvm-bindings`.

use kvm_bindings::CpuId;

use dillo_machine::cpuid_x86::{CpuidFeature, Reg};

pub(crate) use dillo_machine::cpuid_x86::X86Level;

/// Match CPUID's APIC identifiers to the ID given to KVM_CREATE_VCPU.
pub(crate) fn set_apic_id(cpuid: &mut CpuId, id: u32) {
    for entry in cpuid.as_mut_slice() {
        match entry.function {
            1 => entry.ebx = (entry.ebx & 0x00ff_ffff) | (id << 24),
            0x0b | 0x1f => entry.edx = id,
            0x8000_001e => entry.eax = id,
            _ => {}
        }
    }
}

/// KVM reports guest MAXPHYADDR in EAX[7:0], and, with hardware second-stage
/// paging, its addressable GPA width in EAX[23:16]. The latter can be smaller
/// (e.g. 48-bit EPT with a 52-bit CPU). Zero means it supplies no extra bound.
pub(crate) fn guest_address_bits(supported: &CpuId) -> Option<u32> {
    let eax = supported
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0x8000_0008 && entry.index == 0)?
        .eax;
    let physical = eax & 0xff;
    let addressable = (eax >> 16) & 0xff;
    if !(32..=52).contains(&physical) || (addressable != 0 && !(32..=52).contains(&addressable)) {
        return None;
    }
    Some(if addressable == 0 {
        physical
    } else {
        physical.min(addressable)
    })
}

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
            return (extract(feat.reg, entry) >> feat.bit) & 1 == 1;
        }
    }
    false
}

fn extract(reg: Reg, entry: &kvm_bindings::kvm_cpuid_entry2) -> u32 {
    match reg {
        Reg::Eax => entry.eax,
        Reg::Ebx => entry.ebx,
        Reg::Ecx => entry.ecx,
        Reg::Edx => entry.edx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_bindings::kvm_cpuid_entry2;

    #[test]
    fn apic_ids_preserve_other_cpuid_fields() {
        let entries: Vec<_> = [
            (1, 0),
            (0x0b, 0),
            (0x0b, 1),
            (0x1f, 2),
            (0x8000_001e, 0),
            (7, 0),
        ]
        .into_iter()
        .map(|(function, index)| kvm_cpuid_entry2 {
            function,
            index,
            flags: 1,
            eax: 0x1234_5678,
            ebx: 0xabcd_ef01,
            ecx: 0x2345_6789,
            edx: 0x3456_789a,
            ..Default::default()
        })
        .collect();
        for id in [0, 1, 0x123] {
            let mut cpuid = CpuId::from_entries(&entries).unwrap();
            set_apic_id(&mut cpuid, id);
            for (before, after) in entries.iter().zip(cpuid.as_slice()) {
                assert_eq!(after.function, before.function);
                assert_eq!(after.index, before.index);
                assert_eq!(after.flags, before.flags);
                assert_eq!(after.ecx, before.ecx);
                assert_eq!(
                    after.eax,
                    if before.function == 0x8000_001e {
                        id
                    } else {
                        before.eax
                    }
                );
                assert_eq!(
                    after.ebx,
                    if before.function == 1 {
                        ((id & 0xff) << 24) | 0x00cd_ef01
                    } else {
                        before.ebx
                    }
                );
                assert_eq!(
                    after.edx,
                    if matches!(before.function, 0x0b | 0x1f) {
                        id
                    } else {
                        before.edx
                    }
                );
            }
        }
    }

    #[test]
    fn address_width_intersects_cpu_and_kvm_limits() {
        for (physical, addressable, expected) in [
            (52, 48, Some(48)),
            (48, 52, Some(48)),
            (36, 0, Some(36)),
            (0, 0, None),
            (53, 0, None),
            (48, 1, None),
        ] {
            let cpuid = CpuId::from_entries(&[kvm_cpuid_entry2 {
                function: 0x8000_0008,
                eax: physical | (addressable << 16),
                ..Default::default()
            }])
            .unwrap();
            assert_eq!(guest_address_bits(&cpuid), expected);
        }
        assert_eq!(guest_address_bits(&CpuId::from_entries(&[]).unwrap()), None);
    }

    #[test]
    fn first_missing_on_empty_cpuid_reports_fpu() {
        let empty = CpuId::from_entries(&[]).expect("empty CpuId");
        assert_eq!(first_missing(X86Level::V1, &empty), Some("fpu"));
    }

    #[test]
    fn first_missing_accepts_v1_when_leaf1_edx_bits_present() {
        // V1 demands only leaf-1 EDX bits; an entry with those set and
        // nothing else must clear first_missing for V1.
        let edx = (1 << 0) | (1 << 8) | (1 << 15) | (1 << 23) | (1 << 24) | (1 << 25) | (1 << 26);
        let entries = [kvm_cpuid_entry2 {
            function: 0x0000_0001,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx,
            padding: [0; 3],
        }];
        let supported = CpuId::from_entries(&entries).expect("leaf1 CpuId");
        assert_eq!(first_missing(X86Level::V1, &supported), None);
    }
}
