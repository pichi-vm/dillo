// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Concrete native guest fixture for DDI0487 M.c B2.4.3 and C6.2 LDLAR/STLLR.
// X0 selects publisher (0) or consumer (1). Both owners execute the LOR probe,
// then exchange 256 messages using STLLR publication and LDLAR acquisition.
// EL1h synchronous exceptions count faults, retain every non-UNDEF EC in a
// sticky counter, and resume the next instruction. Latest raw ESR is also kept.
// Code is loaded at 0, VBAR at 0x800 (SPx sync at 0xa00), results at 0x2000
// plus owner * 0x400, shared flag/payload/ack at 0x3000, scratch at 0x3800.
// The final store to unmapped 0x20000 reports completion to the host.

pub(super) const RESULT_WORDS: usize = 22;
pub(super) const RESULTS: u64 = 0x2000;
pub(super) const RESULT_STRIDE: u64 = 0x400;

pub(super) const PROGRAM: &[u32] = &[
    0xaa00_03f3, // mov x19, x0
    0xd284_0014, // mov x20, #0x2000
    0x8b13_2a94, // add x20, x20, x19, lsl #10
    0xd286_0015, // mov x21, #0x3000
    0xd281_0000, // mov x0, #0x800
    0xd518_c000, // msr vbar_el1, x0
    0xd503_3fdf, // isb
    0xd280_0016, // mov x22, #0x0
    0xd538_0720, // mrs x0, id_aa64mmfr1_el1
    0xf900_0a80, // str x0, [x20, #16]
    0xd280_0000, // mov x0, #0x0
    0xd538_a4e0, // mrs x0, lorid_el1
    0xf900_0e80, // str x0, [x20, #24]
    0xd280_0000, // mov x0, #0x0
    0xd538_a460, // mrs x0, lorc_el1
    0xf900_1280, // str x0, [x20, #32]
    0xd280_0000, // mov x0, #0x0
    0xd538_a440, // mrs x0, lorn_el1
    0xf900_1680, // str x0, [x20, #40]
    0xd280_0000, // mov x0, #0x0
    0xd538_a420, // mrs x0, lorea_el1
    0xf900_1a80, // str x0, [x20, #48]
    0xd280_0000, // mov x0, #0x0
    0xd538_a400, // mrs x0, lorsa_el1
    0xf900_1e80, // str x0, [x20, #56]
    0x9280_0009, // mov x9, #0xffffffffffffffff
    0xd518_a469, // msr lorc_el1, x9
    0xd518_a449, // msr lorn_el1, x9
    0xd518_a429, // msr lorea_el1, x9
    0xd518_a409, // msr lorsa_el1, x9
    0xd280_0000, // mov x0, #0x0
    0xd538_a460, // mrs x0, lorc_el1
    0xf900_2280, // str x0, [x20, #64]
    0xd280_0000, // mov x0, #0x0
    0xd538_a440, // mrs x0, lorn_el1
    0xf900_2680, // str x0, [x20, #72]
    0xd280_0000, // mov x0, #0x0
    0xd538_a420, // mrs x0, lorea_el1
    0xf900_2a80, // str x0, [x20, #80]
    0xd280_0000, // mov x0, #0x0
    0xd538_a400, // mrs x0, lorsa_el1
    0xf900_2e80, // str x0, [x20, #88]
    0xf900_3296, // str x22, [x20, #96]
    0xd518_a4e9, // msr lorid_el1, x9
    0xf900_3696, // str x22, [x20, #104]
    0xaa16_03f8, // mov x24, x22
    0xd287_0019, // mov x25, #0x3800
    0xd29b_de09, // mov x9, #0xdef0
    0xf2b3_5789, // movk x9, #0x9abc, lsl #16
    0xf2ca_cf09, // movk x9, #0x5678, lsl #32
    0xf2e2_4689, // movk x9, #0x1234, lsl #48
    0xd280_0000, // mov x0, #0x0
    0x089f_7f29, // stllrb w9, [x25]
    0x08df_7f20, // ldlarb w0, [x25]
    0xf900_3a80, // str x0, [x20, #112]
    0xd280_0000, // mov x0, #0x0
    0x489f_7f29, // stllrh w9, [x25]
    0x48df_7f20, // ldlarh w0, [x25]
    0xf900_3e80, // str x0, [x20, #120]
    0xd280_0000, // mov x0, #0x0
    0x889f_7f29, // stllr w9, [x25]
    0x88df_7f20, // ldlar w0, [x25]
    0xf900_4280, // str x0, [x20, #128]
    0xd280_0000, // mov x0, #0x0
    0xc89f_7f29, // stllr x9, [x25]
    0xc8df_7f20, // ldlar x0, [x25]
    0xf900_4680, // str x0, [x20, #136]
    0xf900_4a96, // str x22, [x20, #144]
    0xeb18_02df, // cmp x22, x24
    0x5400_0521, // b.ne 1b8 <done>
    0xf940_0a80, // ldr x0, [x20, #16]
    0xd350_4c00, // ubfx x0, x0, #16, #4
    0xb400_04c0, // cbz x0, 1b8 <done>
    0xd280_0029, // mov x9, #0x1
    0xd280_200a, // mov x10, #0x100
    0x9100_42ac, // add x12, x21, #0x10
    0xb500_01d3, // cbnz x19, 168 <consumer>
    0xf900_06a9, // str x9, [x21, #8]
    0xc89f_7ea9, // stllr x9, [x21]
    0xd2a0_200d, // mov x13, #0x1000000
    0xc8df_7d8b, // ldlar x11, [x12]
    0xeb09_017f, // cmp x11, x9
    0x5400_0080, // b.eq 158 <acknowledged>
    0xf100_05ad, // subs x13, x13, #0x1
    0x54ff_ff81, // b.ne 140 <wait_ack>
    0x1400_0017, // b 1b0 <timeout>
    0x9100_0529, // add x9, x9, #0x1
    0xeb0a_013f, // cmp x9, x10
    0x54ff_fea9, // b.ls 134 <publisher>
    0x1400_0011, // b 1a8 <success>
    0xd2a0_200d, // mov x13, #0x1000000
    0xc8df_7eab, // ldlar x11, [x21]
    0xeb09_017f, // cmp x11, x9
    0x5400_0080, // b.eq 184 <acquired>
    0xf100_05ad, // subs x13, x13, #0x1
    0x54ff_ff81, // b.ne 16c <wait_flag>
    0x1400_000c, // b 1b0 <timeout>
    0xf940_06ab, // ldr x11, [x21, #8]
    0xeb09_017f, // cmp x11, x9
    0x5400_0060, // b.eq 198 <payload_ok>
    0xd280_0020, // mov x0, #0x1
    0xf900_5280, // str x0, [x20, #160]
    0xc89f_7d89, // stllr x9, [x12]
    0x9100_0529, // add x9, x9, #0x1
    0xeb0a_013f, // cmp x9, x10
    0x54ff_fe29, // b.ls 168 <consumer>
    0xf900_4e8a, // str x10, [x20, #152]
    0x1400_0003, // b 1b8 <done>
    0xd280_0040, // mov x0, #0x2
    0xf900_5280, // str x0, [x20, #160]
    0xf900_0296, // str x22, [x20]
    0xd2a0_0042, // mov x2, #0x20000
    0xf900_0040, // str x0, [x2]
    0x1400_0000, // b 1c4 <done+0xc>
];

pub(super) const SYNC_HANDLER: &[u32] = &[
    0xd538_521a, // mrs x26, esr_el1
    0xf900_069a, // str x26, [x20, #8]
    0xd35a_7f5c, // ubfx x28, x26, #26, #6
    0xb400_009c, // cbz x28, 1c <undefined>
    0xf940_569c, // ldr x28, [x20, #168]
    0x9100_079c, // add x28, x28, #0x1
    0xf900_569c, // str x28, [x20, #168]
    0x9100_06d6, // add x22, x22, #0x1
    0xd538_403b, // mrs x27, elr_el1
    0x9100_137b, // add x27, x27, #0x4
    0xd518_403b, // msr elr_el1, x27
    0xd69f_03e0, // eret
];

pub(super) fn verify_lor(result: &[u64; RESULT_WORDS]) {
    let present = (result[2] >> 16) & 15 != 0;
    let legal_faults = result[12];
    let readonly_faults = result[13];
    let instruction_faults = result[18] - readonly_faults;
    assert_eq!(result[21], 0, "every guest exception must be UNDEF");
    assert_eq!(
        (result[1] >> 26) & 63,
        0,
        "latest guest exception must be UNDEF"
    );
    if present {
        assert_eq!(legal_faults, 0, "implemented LOR legal accesses");
        assert_eq!(readonly_faults, 1, "LORID must reject writes");
        if result[3] == 0 {
            // Zero regions and descriptors imply RES0 control registers.
            assert_eq!(&result[4..12], &[0; 8], "zero-region LOR model");
        }
        assert_eq!(
            instruction_faults, 0,
            "native LDLAR/STLLR instruction family"
        );
        assert_eq!(
            &result[14..18],
            &[0xf0, 0xdef0, 0x9abc_def0, 0x1234_5678_9abc_def0]
        );
        assert_eq!(
            result[19], 256,
            "both native owners completed publication/acquisition"
        );
        assert_eq!(
            result[20], 0,
            "acquiring flag must observe published payload"
        );
    } else {
        assert_eq!(legal_faults, 13, "absent LOR registers must be UNDEF");
        assert_eq!(readonly_faults, 14, "absent LORID write must be UNDEF");
        // Optional instruction execution may remain available behind filtered IDs.
        // Neither successful execution nor a negative probe promotes guest LO.
        assert_eq!(
            result[19], 0,
            "absent LO is not positive v8.1 qualification"
        );
    }
}
