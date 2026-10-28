// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! aarch64 finalization: entry stub, halt/debug, kernel handoff.
//! See ARCHITECTURE.md Part III.
//!
//! Unsafe lives where natural: entry asm, halt, MMIO debug write,
//! final kernel branch. Each block carries `// SAFETY:` (§7.1).

#![allow(unsafe_code)]

// ---------------------------------------------------------------------------
// Entry stub + BOOTINFO storage. Both live in this private
// submodule so `BOOTINFO` is referenced only by the asm `sym`
// below — no other Rust code can read or write it, and the
// optimizer can't fold through the asm boundary.
// ---------------------------------------------------------------------------

mod reset {
    use crate::bootinfo::TatuBootInfo;
    use crate::sections::STACK_SIZE;

    /// The `.tatu.bootinfo` section. Arma overwrites the
    /// placeholder zeros at PMI build time. **Never read from
    /// Rust by name** — see the matching note in arch_x86_64.
    #[used]
    #[unsafe(link_section = ".tatu.bootinfo")]
    static BOOTINFO: TatuBootInfo = TatuBootInfo::ZERO;

    /// Entry stub in `.tatu.reset.aarch64`, which the single
    /// `linker/tatu.ld` positions first inside `.tatu.text` so the
    /// `reset` symbol is the kernel-visible entry. (The x86 stub uses a
    /// distinct `.tatu.reset.x86_64` routed to the reset vector instead.)
    ///
    /// SAFETY: PC-relative adrp/add+:lo12: resolves STACK and
    /// BOOTINFO at link time; adding STACK_SIZE yields the top of
    /// the 64 KiB stack. rust_main is the cross-arch lifecycle
    /// entry; it never returns. AAPCS: first arg in X0, so
    /// rust_main receives `bootinfo: &TatuBootInfo`. Interrupts
    /// are masked (DAIF set by arma).
    /// `#[unsafe(no_mangle)]` is the keep-alive anchor — see
    /// the matching note in arch_x86_64.
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    #[unsafe(link_section = ".tatu.reset.aarch64")]
    extern "C" fn reset() -> ! {
        core::arch::naked_asm!(
            "adrp x0,  {bootinfo}",
            "add  x0,  x0,  :lo12:{bootinfo}",
            "adrp x16, {stack}",
            "add  x16, x16, :lo12:{stack}",
            "add  x16, x16, {size}",
            "mov  sp,  x16",
            "b    {main}",
            bootinfo = sym BOOTINFO,
            stack    = sym crate::sections::STACK,
            size     = const STACK_SIZE,
            main     = sym crate::rust_main,
        )
    }
}

// ---------------------------------------------------------------------------
// Halt: null VBAR_EL1 + UDF #0 → recursive synchronous abort →
// KVM_EXIT_FAIL_ENTRY (or equivalent).
// ---------------------------------------------------------------------------

#[inline(never)]
pub(crate) fn halt() -> ! {
    // SAFETY: writing xzr to VBAR_EL1 sets the exception vector
    // to address 0; UDF then raises a synchronous exception which
    // cannot be vectored anywhere valid. The vCPU cannot resume.
    unsafe {
        core::arch::asm!("msr vbar_el1, xzr", "udf #0", options(noreturn),);
    }
}

// ---------------------------------------------------------------------------
// KASLR: arm64 randomizes its virtual base from `/chosen/kaslr-seed` (a kernel
// built with CONFIG_RANDOMIZE_BASE reads it and self-relocates). The seed is
// guest-generated entropy, so it is NOT in the measured base DTB. tatu carries
// a trusted overlay (`crate::kaslr`) that adds `/chosen/kaslr-seed`; here we
// patch its placeholder with guest entropy and merge it onto the measured base
// *before* the host overlay. Entropy comes from the guest CPU (RNDR), never the
// host — and the host overlay is forbidden from contributing /chosen/kaslr-seed
// (validate_host_dtbo rejects it), so the seed stays guest-controlled (a
// confidential-computing requirement).
// ---------------------------------------------------------------------------

use devtree::{Overlay, Tree};

/// Prepare the DTB the host overlay will be merged onto. aarch64 injects a
/// guest-entropy `/chosen/kaslr-seed`: it patches the trusted kaslr overlay
/// template with fresh entropy and merges it onto the measured `base`, writing
/// the result into `scratch` and returning that slice. (The x86 counterpart is
/// a no-op that returns `base` unchanged — it randomizes via post-merge
/// relocations.) `scratch` must be large enough for the base plus the seed
/// property (the base is at most the `.tatu.dtb` reservation).
pub(crate) fn prepare_merge_base<'a>(
    base: &'a [u8],
    scratch: &'a mut [u8],
) -> Result<&'a [u8], ()> {
    // Copy the read-only template into a mutable buffer and patch the seed.
    let template = crate::kaslr::KASLR_OVERLAY_TEMPLATE;
    let mut tpl = [0u8; 512];
    let n = template.len();
    if n > tpl.len() {
        return Err(());
    }
    tpl[..n].copy_from_slice(template);
    if !crate::kaslr::patch_overlay_seed(&mut tpl[..n], rand_u64()) {
        return Err(());
    }

    let overlay = Overlay::parse(&tpl[..n]).map_err(|_| ())?;
    let base_tree = Tree::parse(base).map_err(|_| ())?;
    let written = crate::merge::merge_into(&base_tree, overlay, scratch).map_err(|_| ())?;
    Ok(&scratch[..written])
}

/// 64 bits of guest entropy. Prefers `RNDR` (FEAT_RNG); falls back to the
/// virtual counter when the CPU lacks it (weak, but avoids trapping on the MRS —
/// real confidential-computing hosts expose RNDR).
fn rand_u64() -> u64 {
    if cpu_has_rndr() {
        for _ in 0..100 {
            let val: u64;
            let fail: u64;
            // SAFETY: RNDR is `S3_3_C2_C4_0`; it reads a random value into the
            // destination and updates NZCV (Z set on failure). FEAT_RNG is
            // present (checked above), so the MRS does not trap.
            unsafe {
                core::arch::asm!(
                    "mrs {v}, S3_3_C2_C4_0",
                    "cset {f}, eq",
                    v = out(reg) val,
                    f = out(reg) fail,
                    options(nostack),
                );
            }
            if fail == 0 {
                return val;
            }
        }
    }
    let cnt: u64;
    // SAFETY: CNTVCT_EL1 is always readable at EL1; no memory or flag effects.
    unsafe {
        // CNTVCT_EL1 by raw encoding (S3_3_C14_C0_2) — the bare-target assembler
        // rejects the symbolic name here.
        core::arch::asm!("mrs {c}, S3_3_C14_C0_2", c = out(reg) cnt, options(nostack, nomem, preserves_flags));
    }
    // Spread the counter's low-entropy bits with a fixed odd multiplier.
    cnt.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Whether the CPU implements FEAT_RNG (`ID_AA64ISAR0_EL1.RNDR`, bits 63:60).
fn cpu_has_rndr() -> bool {
    let isar0: u64;
    // SAFETY: ID_AA64ISAR0_EL1 is readable at EL1; no memory or flag effects.
    unsafe {
        core::arch::asm!("mrs {r}, ID_AA64ISAR0_EL1", r = out(reg) isar0, options(nostack, nomem, preserves_flags));
    }
    (isar0 >> 60) & 0xf != 0
}

/// Guest IPA width in bits, from `ID_AA64MMFR0_EL1.PARange` (bits 3:0). Per pmi
/// spec bc7f581 this is the bound for host-supplied addresses in the merged DTB
/// — read from the architectural register, never a hardcoded constant.
pub(crate) fn guest_pa_bits() -> u32 {
    let mmfr0: u64;
    // SAFETY: ID_AA64MMFR0_EL1 is readable at EL1; no memory or flag effects.
    unsafe {
        core::arch::asm!("mrs {r}, ID_AA64MMFR0_EL1", r = out(reg) mmfr0, options(nostack, nomem, preserves_flags));
    }
    match mmfr0 & 0xf {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        6 => 52,
        7 => 56,
        // Reserved encodings: fall back to the AArch64 architectural maximum.
        _ => 48,
    }
}

// ---------------------------------------------------------------------------
// MergedDtb — typed handle for the merged DTB workspace, the
// argument to `boot_kernel` on aarch64.
// ---------------------------------------------------------------------------

#[derive(Debug, Copy, Clone)]
pub(crate) struct MergedDtb {
    pub gpa: u64,
}

// ---------------------------------------------------------------------------
// Kernel handoff. Loads x0 with the merged DTB GPA, branches to
// the kernel entry. Never returns.
// ---------------------------------------------------------------------------

pub(crate) fn boot_kernel(kernel_bytes: &[u8], dtb: MergedDtb) -> ! {
    let entry = kernel_bytes.as_ptr() as u64;
    // SAFETY: this is the final instruction tatu executes. Per
    // the aarch64 Linux boot protocol the kernel expects
    // `x0 = DTB GPA`, `x1 = x2 = x3 = 0` (reserved, MBZ), and PC at
    // the Image header (offset 0). Tatu's code no longer runs after
    // this branch. Zeroing x1–x3 silences the kernel's "x1-x3 nonzero
    // in violation of boot protocol" warning.
    unsafe {
        core::arch::asm!(
            "mov x0, {dtb}",
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "br  {entry}",
            dtb = in(reg) dtb.gpa,
            entry = in(reg) entry,
            options(noreturn),
        );
    }
}
