// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{arm_timer_probe::*, *};
use kvm_bindings::{
    KVM_ARM_VCPU_TIMER_CTRL, KVM_ARM_VCPU_TIMER_IRQ_PTIMER, KVM_ARM_VCPU_TIMER_IRQ_VTIMER,
    KVM_MP_STATE_RUNNABLE, kvm_mp_state,
};
use std::{sync::mpsc, time::Duration};

// kvm-ioctls 0.24 exposes VcpuFd SET/HAS but no GET_DEVICE_ATTR.
nix::ioctl_write_ptr!(
    get_vcpu_attribute,
    kvm_bindings::KVMIO,
    0xe2,
    kvm_device_attr
);

const INTIDS: [u32; 2] = [20, 21];
const ATTRS: [u32; 2] = [KVM_ARM_VCPU_TIMER_IRQ_PTIMER, KVM_ARM_VCPU_TIMER_IRQ_VTIMER];
const OWNER_DEADLINE: Duration = Duration::from_secs(5);

impl Vcpu {
    fn prepare_timer_probe(&mut self, args: [u64; 5]) {
        self.admit_arm_profile(pmi::aarch64::Profile::V8_0).unwrap();
        self.initialize_bsp().unwrap();
        // Bring up the two fixture owners directly. This is not guest PSCI.
        self.fd
            .set_mp_state(kvm_mp_state {
                mp_state: KVM_MP_STATE_RUNNABLE,
            })
            .unwrap();
        for (index, value) in args.into_iter().enumerate() {
            self.set_one_u64(core_reg(index as u64), value).unwrap();
        }
    }

    fn set_timer_probe_ppis(&self) {
        for (selector, intid) in ATTRS.into_iter().zip(INTIDS) {
            let value = i32::try_from(intid).unwrap();
            let attr = kvm_device_attr {
                group: KVM_ARM_VCPU_TIMER_CTRL,
                attr: u64::from(selector),
                addr: (&raw const value) as u64,
                flags: 0,
            };
            self.fd
                .has_device_attr(&attr)
                .expect("timer attribute support");
            let result = self.fd.set_device_attr(&attr);
            eprintln!(
                "KVM owner {} set timer selector {selector}, INTID {intid}: {result:?}",
                self.idx
            );
            result.expect("configure native timer");
        }
    }

    fn timer_probe_ppis(&self) -> [i32; 2] {
        ATTRS.map(|selector| {
            let mut value = -1i32;
            let attr = kvm_device_attr {
                group: KVM_ARM_VCPU_TIMER_CTRL,
                attr: u64::from(selector),
                addr: (&raw mut value) as u64,
                flags: 0,
            };
            // SAFETY: the owner holds this live vCPU fd. The ioctl and
            // indirect int destination match the native timer UAPI.
            #[allow(unsafe_code)]
            let status = unsafe { get_vcpu_attribute(self.fd.as_raw_fd(), &raw const attr) };
            eprintln!(
                "KVM owner {} get timer selector {selector}: {status:?}, INTID {value}",
                self.idx
            );
            status.expect("read effective native timer attribute");
            value
        })
    }
}

#[test]
fn native_kvm_relocated_el1_timer_ppis() {
    let gic = crate::imp::Aarch64Substrate::test_native(2, 128);
    let (dist, redist) = (gic.dist_base, gic.redist_base);
    let vm = Vm::new_with_gic(gic).expect("KVM native GIC");
    let backing = Arc::new(crate::memory::MappedMemory::test_backing(&[(0, RAM_SIZE)]).unwrap());
    vm.attach_memory(Arc::clone(&backing)).unwrap();
    let probe = TimerProbe::load(backing.guest_memory());
    std::thread::scope(|scope| {
        let (ready, readiness) = mpsc::channel();
        let (configured, configuration) = mpsc::channel();
        let mut owners = Vec::new();
        for index in 0..2u32 {
            let vm = vm.clone();
            let ready = ready.clone();
            let configured = configured.clone();
            let (release, gate) = mpsc::channel();
            let owner = scope.spawn(move || {
                let mut vcpu = vm.create_vcpu(index, "armv8.0-a").expect("native vCPU");
                // KVM counted GICR region has consecutive 128 KiB frames.
                vcpu.prepare_timer_probe(TimerProbe::arguments(
                    index,
                    dist,
                    redist + u64::from(index) * 0x2_0000,
                    0,
                    4,
                ));
                ready.send(index).unwrap();
                if index == 0 {
                    gate.recv_timeout(OWNER_DEADLINE)
                        .expect("release timer attributes");
                    vcpu.set_timer_probe_ppis();
                    configured.send(()).unwrap();
                }
                gate.recv_timeout(OWNER_DEADLINE)
                    .expect("release guest execution");
                assert_eq!(
                    vcpu.timer_probe_ppis(),
                    INTIDS.map(|id| i32::try_from(id).unwrap())
                );
                eprintln!("KVM owner {index}: entering guest");
                vcpu.run(|_, _| 0, |_, _| false, &AtomicBool::new(false))
            });
            owners.push((release, owner));
            // Match redistributor frames to vCPU creation order.
            let created = readiness
                .recv_timeout(OWNER_DEADLINE)
                .expect("native vCPU prepared");
            assert_eq!(created, index);
        }
        drop(ready);
        drop(configured);
        vm.init_gic()
            .expect("native GIC initialized with both vCPUs");
        // Configuration is made once through owner 0 after both vCPUs exist.
        owners[0].0.send(()).unwrap();
        configuration
            .recv_timeout(OWNER_DEADLINE)
            .expect("native timer configuration");
        // Run sequentially so GICD setup is not racing the other owner.
        for (index, (release, owner)) in owners.into_iter().enumerate() {
            release.send(()).unwrap();
            let exit = owner.join().expect("native owner panic");
            eprintln!("KVM owner {index}: {exit:?}");
            let report = probe.report("KVM", index as u32);
            assert!(
                matches!(
                    exit,
                    Ok(VmExit::MmioWrite {
                        addr: STOP,
                        size: 4,
                        ..
                    })
                ),
                "expected terminal guest report, got {exit:?}"
            );
            report.verify(&[INTIDS[0], INTIDS[0], INTIDS[1], INTIDS[1]]);
        }
    });
}
