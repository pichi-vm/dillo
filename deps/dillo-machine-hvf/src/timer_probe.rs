// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{arm_timer_probe::*, *};
use applevisor::prelude::GicIntId;

#[derive(Clone, Copy, Debug)]
enum TimerRole {
    Physical = 0,
    Virtual = 1,
}

impl TimerRole {
    fn run(self, test_name: &str) {
        if std::env::var_os("DILLO_SIGNED_HVF_BSP_TEST").is_none() {
            tests::SignedNativeTest::spawn(test_name).verify();
            return;
        }
        let selectors = [GicIntId::EL1_PHYSICAL_TIMER, GicIntId::EL1_VIRTUAL_TIMER];
        let before = selectors.map(GicConfig::get_intid);
        eprintln!("HVF {self:?} [physical, virtual] reserved IDs before VM/GIC: {before:?}");
        let mut end = 0x0800_0000u64;
        let [dist, redist, msi] = [
            (
                GicConfig::get_distributor_size(),
                GicConfig::get_distributor_base_alignment(),
            ),
            (
                GicConfig::get_redistributor_region_size(),
                GicConfig::get_redistributor_base_alignment(),
            ),
            (
                GicConfig::get_msi_region_size(),
                GicConfig::get_msi_region_base_alignment(),
            ),
        ]
        .map(|(size, alignment)| {
            let base = end
                .checked_next_multiple_of(alignment.unwrap() as u64)
                .unwrap();
            end = base.checked_add(size.unwrap() as u64).unwrap();
            base
        });
        assert!(end <= STOP, "native GIC ranges overlap the report exit");
        let mut vm = Vm::new(
            &GicParams {
                dist_base: dist,
                redist_base: redist,
                msi_base: msi,
                msi_intid_base: 64,
                msi_intid_count: 32,
            },
            31,
        )
        .expect("create HVF native VM/GIC");
        let after = selectors.map(GicConfig::get_intid);
        eprintln!("HVF {self:?} [physical, virtual] reserved IDs after VM/GIC: {after:?}");

        vm.add_memory(0, RAM_SIZE).expect("map diagnostic RAM");
        let probe = TimerProbe::load(vm.guest_memory().unwrap());
        let cpu = Vcpu::prepare(&vm.cpu_instance(), pmi::aarch64::Profile::V8_0)
            .expect("prepare native HVF CPU");
        cpu.initialize_bsp().unwrap();
        cpu.prepare_affinity(0x8000_0000).unwrap();
        let bound_redist = cpu.inner.get_redistributor_base().unwrap();
        eprintln!(
            "HVF {self:?}: native GICD={dist:#x}, CPU GICR={bound_redist:#x}; entering guest"
        );
        for (index, value) in TimerProbe::arguments(0, dist, bound_redist, self as u64, 2)
            .into_iter()
            .enumerate()
        {
            cpu.set_gpr(index as u8, value).unwrap();
        }
        // Observe the native result without invoking the normal runner's
        // VTIMER mask or system-register RAZ/WI fallback. No reinjection.
        if let Err(error) = cpu.inner.run() {
            probe.report("HVF", 0);
            panic!("HVF {self:?}: native vCPU run failed: {error:?}");
        }
        let exit = cpu.inner.get_exit_info();
        let syndrome = exit.exception.syndrome;
        let pc = cpu.inner.get_reg(Reg::PC);
        eprintln!(
            "HVF {self:?}: reason={:?} PC={pc:#x?} ESR={syndrome:#x} FAR={:#x} IPA={:#x}",
            exit.reason, exit.exception.virtual_address, exit.exception.physical_address
        );
        if exit.reason == ExitReason::VTIMER_ACTIVATED {
            eprintln!(
                "HVF {self:?}: unexpected native VTIMER_ACTIVATED, mask={:?}",
                cpu.inner.get_vtimer_mask()
            );
        }
        if exit.reason == ExitReason::EXCEPTION && syndrome >> 26 == 0x18 {
            let iss = syndrome & 0x1ff_ffff;
            eprintln!(
                "HVF {self:?}: native sysreg trap S{}_{}_C{}_C{}_{} read={}",
                (iss >> 20) & 3,
                (iss >> 14) & 7,
                (iss >> 10) & 15,
                (iss >> 1) & 15,
                (iss >> 17) & 7,
                iss & 1 != 0
            );
        }
        let report = probe.report("HVF", 0);
        assert!(
            exit.reason == ExitReason::EXCEPTION
                && exit.exception.physical_address == STOP
                && syndrome >> 26 == 0x24
                && (syndrome >> 24) & 1 == 1
                && (syndrome >> 22) & 3 == 2
                && syndrome & (1 << 6) != 0,
            "expected terminal guest report, got {:?}, ESR={syndrome:#x}",
            exit.reason
        );
        let selected = self as usize;
        let id = *after[selected]
            .as_ref()
            .expect("read effective HVF timer INTID");
        if let Ok(prior) = before[selected].as_ref() {
            assert_eq!(*prior, id, "reserved ID changed at VM construction");
        }
        report.verify(&[id, id]);
    }
}

#[test]
fn native_hvf_el1_physical_timer() {
    TimerRole::Physical.run("hypervisor::timer_probe::native_hvf_el1_physical_timer");
}

#[test]
fn native_hvf_el1_virtual_timer() {
    TimerRole::Virtual.run("hypervisor::timer_probe::native_hvf_el1_virtual_timer");
}
