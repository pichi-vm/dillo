// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Realize invariant AMD TSC enumeration in the emulated HWCR register.

use kvm_bindings::{CpuId, Msrs, kvm_msr_entry};
use kvm_ioctls::VcpuFd;
use std::io;

const HWCR: u32 = 0xc001_0015;
const TSC_FREQ_SEL: u64 = 1 << 24;

pub(crate) trait AmdTsc {
    fn initialize_amd_tsc(&self, cpuid: &CpuId) -> io::Result<()>;
}

impl AmdTsc for VcpuFd {
    fn initialize_amd_tsc(&self, cpuid: &CpuId) -> io::Result<()> {
        if !InvariantTsc::advertised(cpuid) {
            return Ok(());
        }
        let mut registers = Msrs::from_entries(&[kvm_msr_entry {
            index: HWCR,
            ..Default::default()
        }])
        .map_err(io::Error::other)?;
        if self.get_msrs(&mut registers).map_err(io::Error::other)? != 1 {
            return Err(io::Error::other("KVM did not return AMD HWCR"));
        }
        // KVM owns the virtual TSC frequency. Describe its invariant-frequency
        // behavior without changing that frequency or other HWCR bits.
        registers.as_mut_slice()[0].data |= TSC_FREQ_SEL;
        if self.set_msrs(&registers).map_err(io::Error::other)? != 1 {
            return Err(io::Error::other("KVM did not accept AMD HWCR TscFreqSel"));
        }
        Ok(())
    }
}

struct InvariantTsc;

impl InvariantTsc {
    fn advertised(cpuid: &CpuId) -> bool {
        let entries = cpuid.as_slice();
        let amd = entries.iter().any(|entry| {
            entry.function == 0
                && entry.index == 0
                && entry.ebx == u32::from_le_bytes(*b"Auth")
                && entry.edx == u32::from_le_bytes(*b"enti")
                && entry.ecx == u32::from_le_bytes(*b"cAMD")
        });
        let has_frequency_select = entries.iter().any(|entry| {
            if entry.function != 1 || entry.index != 0 {
                return false;
            }
            let base_family = (entry.eax >> 8) & 0xf;
            let family = base_family
                + if base_family == 0xf {
                    (entry.eax >> 20) & 0xff
                } else {
                    0
                };
            let model = ((entry.eax >> 4) & 0xf) | ((entry.eax >> 12) & 0xf0);
            family > 0x10 || (family == 0x10 && model >= 2)
        });
        amd && has_frequency_select
            && entries.iter().any(|entry| {
                entry.function == 0x8000_0007 && entry.index == 0 && entry.edx & (1 << 8) != 0
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_bindings::kvm_cpuid_entry2;
    use kvm_ioctls::Kvm;

    #[test]
    fn requires_both_amd_vendor_and_invariant_tsc() {
        let mut entries = [
            kvm_cpuid_entry2 {
                function: 0,
                ebx: u32::from_le_bytes(*b"Auth"),
                edx: u32::from_le_bytes(*b"enti"),
                ecx: u32::from_le_bytes(*b"cAMD"),
                ..Default::default()
            },
            kvm_cpuid_entry2 {
                function: 0x8000_0007,
                edx: 1 << 8,
                ..Default::default()
            },
            kvm_cpuid_entry2 {
                function: 1,
                eax: 0x0080_0f10,
                ..Default::default()
            },
        ];
        assert!(InvariantTsc::advertised(
            &CpuId::from_entries(&entries).unwrap()
        ));
        entries[2].eax = 0x0000_0f10; // Family 0fh has no such frequency-selection contract.
        assert!(!InvariantTsc::advertised(
            &CpuId::from_entries(&entries).unwrap()
        ));
        entries[2].eax = 0x0080_0f10;
        entries[1].edx = 0;
        assert!(!InvariantTsc::advertised(
            &CpuId::from_entries(&entries).unwrap()
        ));
        entries[1].edx = 1 << 8;
        entries[0].ebx = u32::from_le_bytes(*b"Genu");
        assert!(!InvariantTsc::advertised(
            &CpuId::from_entries(&entries).unwrap()
        ));
        assert!(!InvariantTsc::advertised(
            &CpuId::from_entries(&[]).unwrap()
        ));
    }

    #[test]
    fn kvm_sets_hwcr_without_changing_tsc_frequency() {
        let kvm = Kvm::new().unwrap();
        let supported = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let vm = kvm.create_vm().unwrap();
        vm.create_irq_chip().unwrap();
        println!(
            "AMD invariant TSC advertised: {}",
            InvariantTsc::advertised(&supported)
        );
        for id in [0, 1] {
            let mut cpuid = supported.clone();
            crate::cpuid_x86::set_apic_id(&mut cpuid, id);
            let cpu = vm.create_vcpu(u64::from(id)).unwrap();
            cpu.set_cpuid2(&cpuid).unwrap();
            let mut registers = Msrs::from_entries(&[kvm_msr_entry {
                index: HWCR,
                ..Default::default()
            }])
            .unwrap();
            let amd = InvariantTsc::advertised(&cpuid);
            let before = if amd {
                assert_eq!(cpu.get_msrs(&mut registers).unwrap(), 1);
                registers.as_slice()[0].data
            } else {
                0
            };
            let frequency = cpu.get_tsc_khz().unwrap();
            cpu.initialize_amd_tsc(&cpuid).unwrap();
            assert_eq!(cpu.get_tsc_khz().unwrap(), frequency);
            if amd {
                assert_eq!(cpu.get_msrs(&mut registers).unwrap(), 1);
                assert_eq!(registers.as_slice()[0].data, before | TSC_FREQ_SEL);
            }
        }
    }
}
