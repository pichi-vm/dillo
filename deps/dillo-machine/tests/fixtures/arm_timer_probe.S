// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Fixed EL1 entry with the MMU off. X0 is the report GPA, X1/X2 are
// GICD/GICR, X3 is the first timer (0 physical, 1 virtual), X4 is the
// number of trials (two per timer). The IRQ handler only clobbers X0-X7.
// Enable all classic PPIs so unexpected native routing is observable.
.equ OUTCOME, 0
.equ STAGE, 8
.equ FREQUENCY, 16
.equ INITIAL_COUNTER, 24
.equ DISTRIBUTOR, 32
.equ WAKER, 40
.equ ENABLED_PPIS, 48
.equ IRQ_CONFIG, 56
.equ IRQ_COUNT, 64
.equ FAULT_ESR, 72
.equ FAULT_PC, 80
.equ FAULT_FAR, 88
.equ RECORDS, 96

    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x23, x3
    mov x24, x4
    mov x22, #0
    adr x8, .Ltimer_vectors
    msr vbar_el1, x8
    isb

    mov x8, #1
    str x8, [x19, #STAGE]
    mrs x26, cntfrq_el0
    str x26, [x19, #FREQUENCY]
    mov x9, #100
    udiv x27, x26, x9
    cbz x27, .Ltimer_bad_counter
    mrs x9, cntvct_el0
    str x9, [x19, #INITIAL_COUNTER]
    add x28, x9, x26       // one second for GIC setup

    mov x8, #2
    str x8, [x19, #STAGE]
    mov w8, #0x13           // GICD_CTLR.ARE_NS and Group 1 enables
    str w8, [x20]
.Ltimer_dist_ready:
    ldr w8, [x20]
    str x8, [x19, #DISTRIBUTOR]
    tbz w8, #31, .Ltimer_wake
    mrs x9, cntvct_el0
    cmp x9, x28
    b.lo .Ltimer_dist_ready
    b .Ltimer_bad_gic

.Ltimer_wake:
    mov x8, #3
    str x8, [x19, #STAGE]
    ldr w8, [x21, #0x14]    // GICR_WAKER
    bic w8, w8, #2           // clear ProcessorSleep
    str w8, [x21, #0x14]
.Ltimer_redist_ready:
    ldr w8, [x21, #0x14]
    str x8, [x19, #WAKER]
    tbz w8, #2, .Ltimer_prepare_ppis
    mrs x9, cntvct_el0
    cmp x9, x28
    b.lo .Ltimer_redist_ready
    b .Ltimer_bad_gic

.Ltimer_prepare_ppis:
    mov x8, #4
    str x8, [x19, #STAGE]
    add x11, x21, #0x10, lsl #12  // GICR SGI frame, 64 KiB above RD
    mov w8, #0xffff0000
    str w8, [x11, #0x80]           // IGROUPR0
    str wzr, [x11, #0xc04]         // ICFGR1: level PPIs
    mov w9, #0xa0a0
    movk w9, #0xa0a0, lsl #16
    str w9, [x11, #0x410]
    str w9, [x11, #0x414]
    str w9, [x11, #0x418]
    str w9, [x11, #0x41c]
    str w8, [x11, #0x100]          // ISENABLER0
    dsb sy
    ldr w9, [x11, #0x100]
    str x9, [x19, #ENABLED_PPIS]
    ldr w9, [x11, #0xc04]
    str x9, [x19, #IRQ_CONFIG]

    mov x8, #1
    msr icc_sre_el1, x8
    isb
    msr icc_ctlr_el1, xzr           // EOImode 0, EOIR also deactivates
    mrs x9, icc_ctlr_el1
    tbnz x9, #1, .Ltimer_bad_gic
    mov x9, #0xff
    msr icc_pmr_el1, x9
    msr icc_igrpen1_el1, x8
    isb

.Ltimer_trial:
    add x8, x22, #0x10
    str x8, [x19, #STAGE]
    add x25, x23, x22, lsr #1
    add x11, x19, #RECORDS
    add x11, x11, x22, lsl #5
    mrs x8, cntvct_el0
    add x28, x8, x26               // one second for this IRQ
    mov x10, #1
    cbnz x25, .Ltimer_arm_virtual
    mrs x8, cntpct_el0
    str x8, [x11, #16]
    msr cntp_tval_el0, x27
    msr cntp_ctl_el0, x10
    b .Ltimer_wait_irq
.Ltimer_arm_virtual:
    str x8, [x11, #16]
    msr cntv_tval_el0, x27
    msr cntv_ctl_el0, x10
.Ltimer_wait_irq:
    isb
    msr daifclr, #2
.Ltimer_wait_again:
    ldr x8, [x19, #IRQ_COUNT]
    cmp x8, x22
    b.hi .Ltimer_next
    mrs x8, cntvct_el0
    cmp x8, x28
    b.lo .Ltimer_wait_again
    mov w0, #2                     // configured, timer IRQ deadline elapsed
    b .Ltimer_stop
.Ltimer_next:
    msr daifset, #2
    add x22, x22, #1
    cmp x22, x24
    b.lo .Ltimer_trial
    mov w0, #1
    b .Ltimer_stop
.Ltimer_bad_gic:
    mov w0, #4
    b .Ltimer_stop
.Ltimer_bad_counter:
    mov w0, #5
.Ltimer_stop:
    msr daifset, #2
    str x0, [x19, #OUTCOME]
    dsb sy
    mov x1, #0x40000000          // terminal diagnostic MMIO store
    str w0, [x1]
    b .

.Ltimer_irq:
    mrs x0, icc_iar1_el1
    ldr x1, [x19, #IRQ_COUNT]
    cmp x1, #4
    b.hs .Ltimer_extra_irq
    add x2, x19, #RECORDS
    add x2, x2, x1, lsl #5
    str x0, [x2]
    cbnz x25, .Ltimer_clear_virtual
    mrs x3, cntp_ctl_el0
    mrs x4, cntpct_el0
    msr cntp_ctl_el0, xzr
    b .Ltimer_ack_irq
.Ltimer_clear_virtual:
    mrs x3, cntv_ctl_el0
    mrs x4, cntvct_el0
    msr cntv_ctl_el0, xzr
.Ltimer_ack_irq:
    str x3, [x2, #8]
    str x4, [x2, #24]
    isb
    msr icc_eoir1_el1, x0
    isb
    add x1, x1, #1
    str x1, [x19, #IRQ_COUNT]
    eret
.Ltimer_extra_irq:
    mov w0, #6
    b .Ltimer_stop

.Ltimer_fault:
    mrs x0, esr_el1
    mrs x1, elr_el1
    mrs x2, far_el1
    stp x0, x1, [x19, #FAULT_ESR]
    str x2, [x19, #FAULT_FAR]
    mov w0, #3
    b .Ltimer_stop

.p2align 11
.Ltimer_vectors:
    // Current EL, SP_EL0, then current EL, SP_EL1.
    .rept 4
    b .Ltimer_fault
    .p2align 7
    .endr
    b .Ltimer_fault
    .p2align 7
    b .Ltimer_irq
    .p2align 7
    .rept 10
    b .Ltimer_fault
    .p2align 7
    .endr
