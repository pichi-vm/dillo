// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared bare EL1 payload for the isolated KVM and HVF timer probes.

use dillo_machine::memory::MappedRam;
use dillo_virtio::test_support::TestGuestMemory;
use std::sync::Arc;
use vm_memory::GuestAddress;

// The assembly emits immutable guest bytes outside the host execution path.
#[allow(unsafe_code)]
mod payload {
    #[cfg(target_os = "linux")]
    core::arch::global_asm!(
        ".section .rodata.dillo_timer_probe,\"a\",%progbits",
        ".p2align 11",
        ".globl dillo_timer_probe_start",
        "dillo_timer_probe_start:",
        include_str!("arm_timer_probe.S"),
        ".globl dillo_timer_probe_end",
        "dillo_timer_probe_end:",
    );

    #[cfg(target_os = "macos")]
    core::arch::global_asm!(
        ".section __TEXT,__const",
        ".p2align 11",
        ".globl _dillo_timer_probe_start",
        "_dillo_timer_probe_start:",
        include_str!("arm_timer_probe.S"),
        ".globl _dillo_timer_probe_end",
        "_dillo_timer_probe_end:",
    );

    unsafe extern "C" {
        pub(super) static dillo_timer_probe_start: u8;
        pub(super) static dillo_timer_probe_end: u8;
    }
}

// One RAM extent aligned to each Arm host page granule (4/16/64 KiB).
pub(super) const RAM_SIZE: u64 = 0x1_0000;
pub(super) const STOP: u64 = 0x4000_0000;
const REPORT_BASE: u64 = 0x2000;
const REPORT_STRIDE: u64 = 0x100;
const HEADER_WORDS: usize = 12;
const RECORD_WORDS: usize = 4;

#[derive(Debug)]
pub(super) struct TimerProbe(TestGuestMemory);

impl TimerProbe {
    pub(super) fn load(memory: Arc<MappedRam>) -> Self {
        let start = &raw const payload::dillo_timer_probe_start;
        let end = &raw const payload::dillo_timer_probe_end;
        let len = end.addr().checked_sub(start.addr()).unwrap();
        assert_eq!(len, 0x1000, "entry page and aligned vector table");
        // SAFETY: both symbols delimit one linked, read-only assembly region.
        #[allow(unsafe_code)]
        let image = unsafe { std::slice::from_raw_parts(start, len) };
        let memory = TestGuestMemory::from_owner(memory);
        memory.write_slice(image, GuestAddress(0)).unwrap();
        Self(memory)
    }

    pub(super) fn arguments(
        owner: u32,
        dist: u64,
        redist: u64,
        first_timer: u64,
        trials: u64,
    ) -> [u64; 5] {
        [
            REPORT_BASE + u64::from(owner) * REPORT_STRIDE,
            dist,
            redist,
            first_timer,
            trials,
        ]
    }

    pub(super) fn report(&self, backend: &str, owner: u32) -> TimerReport {
        let gpa = REPORT_BASE + u64::from(owner) * REPORT_STRIDE;
        let word = |index: usize| {
            let mut value = [0; 8];
            self.0
                .read_slice(&mut value, GuestAddress(gpa + index as u64 * 8))
                .unwrap();
            u64::from_le_bytes(value)
        };
        let header: [u64; HEADER_WORDS] = std::array::from_fn(word);
        let records = std::array::from_fn(|trial| {
            std::array::from_fn(|index| word(HEADER_WORDS + trial * RECORD_WORDS + index))
        });
        let [
            outcome,
            stage,
            frequency,
            counter,
            dist,
            waker,
            enabled,
            config,
            count,
            esr,
            pc,
            far,
        ] = header;
        eprintln!(
            "{backend} owner {owner}: outcome={outcome} stage={stage:#x} CNTFRQ={frequency} \
             first_CNTVCT={counter:#x} GICD_CTLR={dist:#x} GICR_WAKER={waker:#x} \
             PPIs={enabled:#x} ICFGR1={config:#x} IRQs={count} fault={esr:#x}/{pc:#x}/{far:#x}"
        );
        eprintln!("{backend} owner {owner}: IRQ records [IAR, CTL, before, at_irq]={records:#x?}");
        TimerReport {
            outcome,
            frequency,
            count,
            records,
        }
    }
}

#[derive(Debug)]
pub(super) struct TimerReport {
    outcome: u64,
    frequency: u64,
    count: u64,
    records: [[u64; RECORD_WORDS]; 4],
}

impl TimerReport {
    pub(super) fn verify(self, expected_ids: &[u32]) {
        assert_eq!(
            self.outcome, 1,
            "guest did not complete (2=IRQ deadline, 3=sync fault, 4=GIC setup, \
             5=counter, 6=extra IRQ)"
        );
        assert_eq!(self.count, expected_ids.len() as u64, "timer IRQ count");
        assert!(self.frequency >= 100, "guest CNTFRQ");
        for (trial, (&expected, [iar, ctl, before, at_irq])) in
            expected_ids.iter().zip(self.records).enumerate()
        {
            assert_eq!(
                iar,
                u64::from(expected),
                "wrong timer INTID on trial {trial}"
            );
            assert_eq!(
                ctl & 7,
                5,
                "timer enabled, unmasked and asserting on trial {trial}"
            );
            assert!(
                at_irq.wrapping_sub(before) >= self.frequency / 100,
                "counter did not reach the programmed deadline on trial {trial}"
            );
        }
    }
}
