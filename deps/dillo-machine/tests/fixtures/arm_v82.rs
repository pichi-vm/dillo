// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Fixed native EL1 probe, DDI0487 M.c C5.2.30/C5.4.9/D8.16.3.4/C5.3.28/D20.
// X0 selects owner, X1 is owner count. One 4 KiB L1 table maps two 1 GiB blocks:
// privileged code/data at 0 and EL0-RW data at 0x40000000. Only small stage 2 RAM
// extents exist. Four-KiB support is a fixture prerequisite, never a CPU floor.
// Both owners enable the same CnP table before a bounded LDAR/STLR barrier.
// UAO/PAN faults retain exact ESR/PC/FAR; no last-fault-only acceptance.
// Forced CVAP/RAS must not reach an unsupported userspace RAZ/WI handler.
// This proves integration/operation routing, not physical persistence or errors.

use dillo_machine::{
    RamRange,
    aarch64::{AdmittedCpu, Register},
};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

pub(super) const RANGES: [RamRange; 2] = [
    RamRange {
        gpa: 0,
        size: 0x4000,
    },
    RamRange {
        gpa: 0x4000_0000,
        size: 0x4000,
    },
];
const RESULTS: u64 = 0x2000;
const STRIDE: u64 = 0x400;
const WORDS: usize = 35;

/// Owns the exact RAM used by the native owners and their observations.
/// Owners borrow entry arguments from this fixture; verification consumes it
/// only after the native threads have joined.
pub(super) struct NativeOperations {
    memory: GuestMemoryMmap,
    owners: u32,
}
impl NativeOperations {
    pub(super) fn new(memory: GuestMemoryMmap, owners: u32) -> Self {
        assert!((1..=2).contains(&owners));
        let fixture = Self { memory, owners };
        fixture.load();
        fixture
    }
    pub(super) fn entry_arguments(
        &self,
        owner: u32,
        admitted: &AdmittedCpu,
    ) -> Result<(u64, u64), &'static str> {
        assert!(owner < self.owners);
        let granule = (admitted.value(Register::Mmfr0).unwrap() >> 28) & 15;
        if granule >= 8 {
            return Err(
                "native operation fixture requires 4 KiB granule; not a profile requirement",
            );
        }
        Ok((u64::from(owner), u64::from(self.owners)))
    }
    fn load(&self) {
        for range in RANGES {
            self.memory
                .write_slice(&[0; 0x4000], GuestAddress(range.gpa))
                .unwrap();
        }
        for (base, instructions) in [(0, PROGRAM), (0xa00, SYNC_HANDLER)] {
            for (index, instruction) in instructions.iter().enumerate() {
                self.memory
                    .write_slice(
                        &instruction.to_le_bytes(),
                        GuestAddress(base + index as u64 * 4),
                    )
                    .unwrap();
            }
        }
        // L1 block: AF, Inner Shareable, normal MAIR0, privileged RW/UXN.
        self.memory
            .write_slice(
                &0x0040_0000_0000_0701u64.to_le_bytes(),
                GuestAddress(0x1000),
            )
            .unwrap();
        // Same attributes; second block is EL0/EL1 RW, data-only (PXN/UXN).
        self.memory
            .write_slice(
                &0x0060_0000_4000_0741u64.to_le_bytes(),
                GuestAddress(0x1008),
            )
            .unwrap();
    }

    fn word(&self, address: u64) -> u64 {
        let mut bytes = [0; 8];
        self.memory
            .read_slice(&mut bytes, GuestAddress(address))
            .unwrap();
        u64::from_le_bytes(bytes)
    }
    fn observation(&self, owner: u32) -> OwnerObservation {
        let words: [u64; WORDS] = std::array::from_fn(|index| {
            self.word(RESULTS + u64::from(owner) * STRIDE + index as u64 * 8)
        });
        OwnerObservation {
            owner,
            fault_count: words[0],
            last_esr: words[1],
            fault_overflow: words[2],
            uao_denied_load: words[3],
            uao_load: words[4],
            uao_store: words[5],
            pan_clear_read: words[6],
            pan_clear_write: words[7],
            pan_set_read: words[8],
            pan_set_read_permission: words[9],
            pan_set_write: words[10],
            pan_set_write_permission: words[11],
            ttbr0: words[12],
            pan_denied_load: words[13],
            cvap_before: words[14],
            cvap_after: words[15],
            erridr: words[16],
            disr: words[17],
            errselr: words[18],
            completion: words[19],
            uao_denied_store: words[20],
            pan_load: words[21],
            sctlr: words[22],
            tcr: words[23],
            unexpected_ec: words[33],
            mair: words[34],
            faults: std::array::from_fn(|index| FaultObservation {
                esr: words[24 + index * 3],
                pc: words[25 + index * 3],
                address: words[26 + index * 3],
            }),
            user_backing: self.word(0x4000_0000 + u64::from(owner) * 0x80),
        }
    }
    pub(super) fn report(&self, provider: &str) {
        for owner in 0..self.owners {
            eprintln!(
                "{provider} native v8.2 operations: {:#x?}",
                self.observation(owner)
            );
        }
    }
    pub(super) fn verify(self) {
        for owner in 0..self.owners {
            self.observation(owner).verify();
        }
    }
    #[cfg(target_os = "macos")]
    pub(super) fn verify_unexecuted(self) {
        for owner in 0..self.owners {
            assert_eq!(
                self.observation(owner).completion,
                0,
                "no peer entered after refusal"
            );
        }
    }
}
#[derive(Debug)]
struct FaultObservation {
    esr: u64,
    pc: u64,
    address: u64,
}
#[derive(Debug)]
struct OwnerObservation {
    owner: u32,
    fault_count: u64,
    last_esr: u64,
    fault_overflow: u64,
    uao_denied_load: u64,
    uao_load: u64,
    uao_store: u64,
    pan_clear_read: u64,
    pan_clear_write: u64,
    pan_set_read: u64,
    pan_set_read_permission: u64,
    pan_set_write: u64,
    pan_set_write_permission: u64,
    ttbr0: u64,
    pan_denied_load: u64,
    cvap_before: u64,
    cvap_after: u64,
    erridr: u64,
    disr: u64,
    errselr: u64,
    completion: u64,
    uao_denied_store: u64,
    pan_load: u64,
    sctlr: u64,
    tcr: u64,
    unexpected_ec: u64,
    mair: u64,
    faults: [FaultObservation; 3],
    user_backing: u64,
}
impl OwnerObservation {
    fn verify(self) {
        // Retain the latest raw ESR in diagnostics in addition to all fault records.
        assert_eq!((self.last_esr >> 26) & 63, 0x25, "last exception class");
        assert_eq!(self.completion, 0x184, "all operation phases completed");
        assert_eq!(self.fault_count, 3, "exact expected permission faults");
        assert_eq!(self.fault_overflow, 0, "no fault-record overflow");
        assert_eq!(
            self.unexpected_ec, 0,
            "no unexpected exception class was overwritten"
        );
        assert_eq!(
            self.uao_denied_load, 0,
            "UAO0 load fault preserves destination"
        );
        assert_eq!(
            self.uao_denied_store,
            0x1234 + u64::from(self.owner),
            "UAO0 store fault preserves data"
        );
        assert_eq!(
            self.uao_load,
            0x1234 + u64::from(self.owner),
            "UAO1 unprivileged load is privileged"
        );
        assert_eq!(
            self.uao_store,
            0x5678 + u64::from(self.owner),
            "UAO1 unprivileged store is privileged"
        );
        assert_eq!(
            self.pan_denied_load, 0,
            "PAN1 privileged user-page load faults"
        );
        assert_eq!(
            self.pan_load,
            0x9abc + u64::from(self.owner),
            "PAN0 user-page load succeeds"
        );
        for (operation, par) in [
            ("PAN clear RP", self.pan_clear_read),
            ("PAN clear WP", self.pan_clear_write),
            ("PAN set R", self.pan_set_read),
            ("PAN set W", self.pan_set_write),
        ] {
            assert_eq!(par & 1, 0, "successful AT {operation}");
            assert_eq!(par & 0xffff_f000, 0x4000_0000, "AT translated IPA");
        }
        for par in [self.pan_set_read_permission, self.pan_set_write_permission] {
            assert_eq!(par & 1, 1, "PAN-sensitive AT faults");
            assert_eq!((par >> 1) & 63, 0x0d, "L1 permission fault");
        }
        assert_eq!(self.ttbr0, 0x1001, "same CnP table/ASID 0");
        assert_eq!(
            self.sctlr & 0x0308_1007,
            0x1005,
            "explicit MMU/cache/endianness controls"
        );
        // TCR low controls plus IPS/AS; unrelated optional upper fields are ignored.
        assert_eq!(
            self.tcr & 0x0017_ffff_ffbf,
            0x8099_3519,
            "common translation regime"
        );
        assert_eq!(self.mair & 0xff, 0xff, "common normal memory attribute 0");
        assert_eq!(
            (self.cvap_before, self.cvap_after),
            (1, 2),
            "CVAP and DSB were reached/completed"
        );
        assert_eq!(
            self.erridr & !0xffff,
            0,
            "ERRIDR reserved bits; raw NUM is retained"
        );
        assert_eq!(self.disr, 0, "cleared DISR with no injected error");
        // D24.9.3 permits an UNDEFINED ERRSELR access when NUM=0.
        // The guest records a distinct not-applicable marker without accessing it.
        let records = self.erridr & 0xffff;
        if records == 0 {
            assert_eq!(self.errselr, u64::MAX, "ERRSELR phase not applicable");
        } else {
            assert_eq!(self.errselr & !0xffff, 0, "ERRSELR reserved bits");
            assert_eq!(
                self.errselr & 0xffff,
                0,
                "implemented RAS record selector 0"
            );
        }
        for (fault, (pc, address, write)) in [
            (0x104, 0x3000 + u64::from(self.owner) * 0x80, 0),
            (0x110, 0x3000 + u64::from(self.owner) * 0x80, 1),
            (0x1b4, 0x4000_0000 + u64::from(self.owner) * 0x80, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let record = &self.faults[fault];
            let esr = record.esr;
            assert_eq!((esr >> 26) & 63, 0x25, "same-EL data abort");
            assert_eq!(esr & 63, 0x0d, "L1 permission fault");
            assert_eq!((esr >> 6) & 1, write, "fault direction");
            assert_eq!(record.pc, pc, "exact faulting instruction");
            assert_eq!(record.address, address, "faulting data address");
        }
        assert_eq!(
            self.user_backing,
            0x9abc + u64::from(self.owner),
            "CnP translation reaches shared backing"
        );
    }
}

const PROGRAM: &[u32] = &[
    0xaa00_03f3, // mov x19, x0
    0xaa01_03f8, // mov x24, x1
    0xd284_0014, // mov x20, #0x2000
    0x8b13_2a94, // add x20, x20, x19, lsl #10
    0xd286_0017, // mov x23, #0x3000
    0x8b13_1ef7, // add x23, x23, x19, lsl #7
    0xd2a8_0015, // mov x21, #0x40000000
    0x8b13_1eb5, // add x21, x21, x19, lsl #7
    0xd280_0016, // mov x22, #0x0
    0xd281_0009, // mov x9, #0x800
    0xd518_c009, // msr VBAR_EL1, x9
    0xd280_1fe9, // mov x9, #0xff
    0xd518_a209, // msr MAIR_EL1, x9
    0xd286_a329, // mov x9, #0x3519
    0xf2b0_1329, // movk x9, #0x8099, lsl #16
    0xd518_2049, // msr TCR_EL1, x9
    0xd282_0029, // mov x9, #0x1001
    0xd518_2009, // msr TTBR0_EL1, x9
    0xd518_203f, // msr TTBR1_EL1, xzr
    0xd503_3a9f, // dsb ishst
    0xd508_831f, // tlbi vmalle1is
    0xd503_3b9f, // dsb ish
    0xd503_3fdf, // isb
    0xd538_1009, // mrs x9, SCTLR_EL1
    0x9266_f529, // and x9, x9, #0xfffffffffcffffff
    0x926c_f929, // and x9, x9, #0xfffffffffff7ffff
    0x9246_f929, // and x9, x9, #0xfdffffffffffffff
    0x927e_f929, // and x9, x9, #0xfffffffffffffffd
    0xb240_0129, // orr x9, x9, #0x1
    0xb27e_0129, // orr x9, x9, #0x4
    0xb274_0129, // orr x9, x9, #0x1000
    0xb269_0129, // orr x9, x9, #0x800000
    0xd518_1009, // msr SCTLR_EL1, x9
    0xd503_3fdf, // isb
    0xd538_1009, // mrs x9, SCTLR_EL1
    0xf900_5a89, // str x9, [x20, #0xb0]
    0xd538_2049, // mrs x9, TCR_EL1
    0xf900_5e89, // str x9, [x20, #0xb8]
    0xd538_2009, // mrs x9, TTBR0_EL1
    0xf900_3289, // str x9, [x20, #0x60]
    0xd287_0019, // mov x25, #0x3800
    0x8b13_0f3a, // add x26, x25, x19, lsl #3
    0xd280_0029, // mov x9, #0x1
    0xc89f_ff49, // stlr x9, [x26]
    0xd2a0_200a, // mov x10, #0x1000000
    0xc8df_ff29, // ldar x9, [x25]
    0xf100_053f, // cmp x9, #0x1
    0x5400_00e1, // b.ne 0xd8 <barrier_retry>
    0xf100_071f, // cmp x24, #0x1
    0x5400_0140, // b.eq 0xec <barrier_done>
    0x9100_233a, // add x26, x25, #0x8
    0xc8df_ff49, // ldar x9, [x26]
    0xf100_053f, // cmp x9, #0x1
    0x5400_00c0, // b.eq 0xec <barrier_done>
    0xf100_054a, // subs x10, x10, #0x1
    0x54ff_fec1, // b.ne 0xb4 <barrier_wait>
    0xd281_75a0, // mov x0, #0xbad
    0xf900_4e80, // str x0, [x20, #0x98]
    0x1400_0051, // b 0x22c <probe_exit>
    0xd500_409f, // msr PAN, #0x0
    0xd500_407f, // msr UAO, #0x0
    0xd282_4689, // mov x9, #0x1234
    0x8b13_0129, // add x9, x9, x19
    0xf900_02e9, // str x9, [x23]
    0xd280_0000, // mov x0, #0x0
    0xf840_0ae0, // ldtr x0, [x23]
    0xf900_0e80, // str x0, [x20, #0x18]
    0xd284_4449, // mov x9, #0x2222
    0xf800_0ae9, // sttr x9, [x23]
    0xf940_02e0, // ldr x0, [x23]
    0xf900_5280, // str x0, [x20, #0xa0]
    0xd500_417f, // msr UAO, #0x1
    0xf840_0ae0, // ldtr x0, [x23]
    0xf900_1280, // str x0, [x20, #0x20]
    0xd28a_cf09, // mov x9, #0x5678
    0x8b13_0129, // add x9, x9, x19
    0xf800_0ae9, // sttr x9, [x23]
    0xf940_02e0, // ldr x0, [x23]
    0xf900_1680, // str x0, [x20, #0x28]
    0xd500_407f, // msr UAO, #0x0
    0xd293_5789, // mov x9, #0x9abc
    0x8b13_0129, // add x9, x9, x19
    0xf900_02a9, // str x9, [x21]
    0xd508_7915, // at s1e1rp, x21
    0xd503_3fdf, // isb
    0xd538_7400, // mrs x0, PAR_EL1
    0xf900_1a80, // str x0, [x20, #0x30]
    0xd508_7935, // at s1e1wp, x21
    0xd503_3fdf, // isb
    0xd538_7400, // mrs x0, PAR_EL1
    0xf900_1e80, // str x0, [x20, #0x38]
    0xd500_419f, // msr PAN, #0x1
    0xd508_7815, // at s1e1r, x21
    0xd503_3fdf, // isb
    0xd538_7400, // mrs x0, PAR_EL1
    0xf900_2280, // str x0, [x20, #0x40]
    0xd508_7915, // at s1e1rp, x21
    0xd503_3fdf, // isb
    0xd538_7400, // mrs x0, PAR_EL1
    0xf900_2680, // str x0, [x20, #0x48]
    0xd508_7835, // at s1e1w, x21
    0xd503_3fdf, // isb
    0xd538_7400, // mrs x0, PAR_EL1
    0xf900_2a80, // str x0, [x20, #0x50]
    0xd508_7935, // at s1e1wp, x21
    0xd503_3fdf, // isb
    0xd538_7400, // mrs x0, PAR_EL1
    0xf900_2e80, // str x0, [x20, #0x58]
    0xd280_0000, // mov x0, #0x0
    0xf940_02a0, // ldr x0, [x21]
    0xf900_3680, // str x0, [x20, #0x68]
    0xd500_409f, // msr PAN, #0x0
    0xf940_02a0, // ldr x0, [x21]
    0xf900_5680, // str x0, [x20, #0xa8]
    0xd280_0020, // mov x0, #0x1
    0xf900_3a80, // str x0, [x20, #0x70]
    0xd50b_7c35, // dc cvap, x21
    0xd503_3f9f, // dsb sy
    0xd280_0040, // mov x0, #0x2
    0xf900_3e80, // str x0, [x20, #0x78]
    0xd518_c13f, // msr DISR_EL1, xzr
    0xd503_221f, // esb
    0xd538_5300, // mrs x0, ERRIDR_EL1
    0xf900_4280, // str x0, [x20, #0x80]
    0x9240_3c09, // and x9, x0, #0xffff
    0xd538_c120, // mrs x0, DISR_EL1
    0xf900_4680, // str x0, [x20, #0x88]
    0xb400_0089, // cbz x9, 0x20c <selector_unavailable>
    0xd518_533f, // msr ERRSELR_EL1, xzr
    0xd538_5320, // mrs x0, ERRSELR_EL1
    0x1400_0002, // b 0x210 <selector_recorded>
    0x9280_0000, // mov x0, #-0x1
    0xf900_4a80, // str x0, [x20, #0x90]
    0xd538_a200, // mrs x0, MAIR_EL1
    0xf900_8a80, // str x0, [x20, #0x110]
    0xd280_3080, // mov x0, #0x184
    0xf900_4e80, // str x0, [x20, #0x98]
    0xf900_0296, // str x22, [x20]
    0xd503_3f9f, // dsb sy
    0xd2a0_0049, // mov x9, #0x20000
    0xf900_0120, // str x0, [x9]
];

const SYNC_HANDLER: &[u32] = &[
    0xd538_521b, // mrs x27, ESR_EL1
    0xf900_069b, // str x27, [x20, #0x8]
    0xd35a_7f7a, // ubfx x26, x27, #26, #6
    0xf100_975f, // cmp x26, #0x25
    0x5400_0080, // b.eq 0x254 <sync_handler+0x20>
    0xf940_869a, // ldr x26, [x20, #0x108]
    0x9100_075a, // add x26, x26, #0x1
    0xf900_869a, // str x26, [x20, #0x108]
    0xf100_0edf, // cmp x22, #0x3
    0x5400_0122, // b.hs 0x27c <sync_handler+0x48>
    0xd538_403c, // mrs x28, ELR_EL1
    0xd538_601a, // mrs x26, FAR_EL1
    0x8b16_06dd, // add x29, x22, x22, lsl #1
    0x8b1d_0e9d, // add x29, x20, x29, lsl #3
    0xf900_63bb, // str x27, [x29, #0xc0]
    0xf900_67bc, // str x28, [x29, #0xc8]
    0xf900_6bba, // str x26, [x29, #0xd0]
    0x1400_0004, // b 0x288 <sync_handler+0x54>
    0xf940_0a9a, // ldr x26, [x20, #0x10]
    0x9100_075a, // add x26, x26, #0x1
    0xf900_0a9a, // str x26, [x20, #0x10]
    0x9100_06d6, // add x22, x22, #0x1
    0xf900_0296, // str x22, [x20]
    0xd538_403c, // mrs x28, ELR_EL1
    0x9100_139c, // add x28, x28, #0x4
    0xd518_403c, // msr ELR_EL1, x28
    0xd69f_03e0, // eret
];
