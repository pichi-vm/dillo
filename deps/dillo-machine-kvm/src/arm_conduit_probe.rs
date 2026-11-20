// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native observations of the ordinary Arm KVM SMCCC API and guest behavior.

use super::{Cap, VcpuExit, Vm, core_reg, sys_reg};
use crate::imp::{Aarch64Substrate, run_arm_conduit_probe};
use crate::memory::MappedMemory;
use kvm_bindings::{
    KVM_ARM_VM_SMCCC_CTRL, KVM_ARM_VM_SMCCC_FILTER, kvm_device_attr, kvm_smccc_filter,
    kvm_smccc_filter_action_KVM_SMCCC_FILTER_FWD_TO_USER,
};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress};

const SMCCC_VERSION: u32 = 0x8000_0000;
const PSCI_VERSION: u32 = 0x8400_0000;
const RETURN_MARKER: u64 = 0x800;
const EXCEPTION_MARKER: u64 = 0x808;
const VECTOR_BASE: u64 = 0x1000;
const COMPLETE: u64 = 0x1_0000;
const EXCEPTION: u64 = COMPLETE + 8;
const UNWRITTEN: u64 = 0xdead_beef_dead_beef;

fn probe(conduit: &str, instruction: u32) -> anyhow::Result<bool> {
    let vm = Vm::new_with_gic(&Aarch64Substrate {
        dist_base: 0x0800_0000,
        redist_base: 0x080a_0000,
        spi_count: 32,
    })?;
    let kvm = &vm.inner.kvm;
    // Linux UAPI numbers for guest EL2 support are newer than our bindings.
    eprintln!(
        "KVM {conduit} capabilities: api={} PSCI_0_2={} IPA_SIZE={} ARM_EL2={} ARM_EL2_E2H0={}",
        kvm.get_api_version(),
        kvm.check_extension_int(Cap::ArmPsci02),
        kvm.check_extension_int(Cap::ArmVmIPASize),
        kvm.check_extension_raw(240),
        kvm.check_extension_raw(241),
    );

    let mut attr = kvm_device_attr {
        group: KVM_ARM_VM_SMCCC_CTRL,
        attr: u64::from(KVM_ARM_VM_SMCCC_FILTER),
        ..Default::default()
    };
    let has_filter = vm
        .fd()
        .has_device_attr(&attr)
        .map_err(kvm_ioctls::Error::errno);
    let [architecture_filter, control_filter] = [SMCCC_VERSION, PSCI_VERSION].map(|base| {
        let rule = kvm_smccc_filter {
            base,
            nr_functions: 1,
            action: kvm_smccc_filter_action_KVM_SMCCC_FILTER_FWD_TO_USER as u8,
            pad: [0; 15],
        };
        attr.addr = &raw const rule as u64;
        vm.fd()
            .set_device_attr(&attr)
            .map_err(kvm_ioctls::Error::errno)
    });
    eprintln!(
        "KVM {conduit} filters (errno on failure): HAS={has_filter:?} FWD_SMCCC_VERSION={architecture_filter:?} FWD_PSCI_VERSION={control_filter:?}"
    );

    let ram = Arc::new(MappedMemory::test_backing(&[(0, COMPLETE)])?);
    let memory = ram.guest_memory();
    vm.attach_memory(ram)?;
    let mut cpu = vm.create_vcpu(0, "armv8.0-a")?;
    vm.init_gic()?;

    let mut hcr = [0; 8];
    let hcr_id = sys_reg(3, 4, 1, 1, 0);
    let hcr = cpu
        .fd
        .get_one_reg(hcr_id, &mut hcr)
        .map(|_| u64::from_le_bytes(hcr))
        .map_err(kvm_ioctls::Error::errno);
    eprintln!(
        "KVM {conduit} ordinary EL1 GET_ONE_REG HCR_EL2 ({hcr_id:#x}, errno on failure): {hcr:#x?}"
    );
    if hcr.is_ok() || architecture_filter.is_ok() {
        eprintln!("KVM {conduit} unexpected API availability; inspect before drawing conclusions");
    }

    let code = [
        instruction, // hvc #0 or smc #0, x0 = SMCCC_VERSION on entry
        0xd281_0001, // mov x1, #0x800
        0xf900_0020, // str x0, [x1]
        0xd503_3f9f, // dsb sy (publish the RAM marker before the MMIO exit)
        0xd2a0_0022, // mov x2, #0x10000
        0xf900_0040, // str x0, [x2]
        0x1400_0000, // b .
    ];
    let vector = [
        0xd538_5200u32, // mrs x0, esr_el1
        0xd281_0101,    // mov x1, #0x808
        0xf900_0020,    // str x0, [x1]
        0xd503_3f9f,    // dsb sy
        0xd2a0_0022,    // mov x2, #0x10000
        0xf900_0440,    // str x0, [x2, #8]
        0x1400_0000,    // b .
    ];
    for (address, words) in [(0, code), (VECTOR_BASE + 0x200, vector)] {
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        memory.write_slice(&bytes, GuestAddress(address))?;
    }
    for address in [RETURN_MARKER, EXCEPTION_MARKER] {
        memory.write_obj(UNWRITTEN.to_le(), GuestAddress(address))?;
    }
    cpu.set_one_u64(core_reg(0), u64::from(SMCCC_VERSION))?;
    cpu.set_one_u64(core_reg(32), 0)?;
    cpu.set_one_u64(core_reg(33), 0x3c5)?; // EL1h with interrupts masked.
    cpu.set_one_u64(sys_reg(3, 0, 1, 0, 0), 0)?; // SCTLR_EL1, MMU off.
    cpu.set_one_u64(sys_reg(3, 0, 12, 0, 0), VECTOR_BASE)?; // VBAR_EL1.

    let (expired, exit) = run_arm_conduit_probe(&mut cpu.fd);
    let returned = u64::from_le(memory.read_obj(GuestAddress(RETURN_MARKER))?);
    let syndrome = u64::from_le(memory.read_obj(GuestAddress(EXCEPTION_MARKER))?);
    eprintln!(
        "KVM {conduit} SMCCC_VERSION guest: return={returned:#018x} esr_el1={syndrome:#018x} deadline={expired} exit={exit:?}"
    );
    let forwarded =
        matches!(&exit, Ok(VcpuExit::Hypercall(call)) if call.nr == u64::from(SMCCC_VERSION));
    let matched_marker = match exit {
        Ok(VcpuExit::MmioWrite(COMPLETE, bytes)) => {
            syndrome == UNWRITTEN && returned != UNWRITTEN && bytes == returned.to_le_bytes()
        }
        Ok(VcpuExit::MmioWrite(EXCEPTION, bytes)) => {
            returned == UNWRITTEN && syndrome != UNWRITTEN && bytes == syndrome.to_le_bytes()
        }
        _ => false,
    };
    if forwarded {
        // SAFETY: KVM_EXIT_HYPERCALL selects hypercall and Arm uses flags.
        #[allow(unsafe_code)]
        let flags = unsafe {
            cpu.fd
                .get_kvm_run()
                .__bindgen_anon_1
                .hypercall
                .__bindgen_anon_1
                .flags
        };
        eprintln!("KVM {conduit} forwarded SMCCC_VERSION: flags={flags:#x}");
    }
    Ok(!expired && (matched_marker || forwarded))
}

#[test]
#[ignore = "requires native Arm KVM and collects diagnostic evidence"]
fn ordinary_arm_kvm_conduits() {
    let results = [("HVC", 0xd400_0002), ("SMC", 0xd400_0003)].map(|(conduit, instruction)| {
        let result = probe(conduit, instruction);
        eprintln!("KVM {conduit} observation: {result:?}");
        result
    });
    assert!(results.into_iter().all(|result| matches!(result, Ok(true))));
}
