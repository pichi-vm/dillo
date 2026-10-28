// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! tatu — Linux boot stub for PMI.
//!
//! See `ARCHITECTURE.md` at the crate root for the full design.
//!
//! On bare metal (`target_os = "none"`): a `#![no_main]` binary
//! with the cross-arch lifecycle. The arch-specific entry stubs in
//! `arch_x86_64` / `arch_aarch64` set up the stack and jump to
//! `rust_main` defined here.
//!
//! On host (`target_os = linux/macos/...`): a stub `main()` that
//! prints a usage hint. `cargo test` builds this stub and runs the
//! `#[cfg(test)]` modules under `bootinfo` / `merge` / `validate`.
//!
//! The crate has no library: tatu is consumed only as a binary by
//! arma (which reads its ELF section table and entry point). Module
//! items use `pub(crate)` visibility so nothing escapes the crate.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
// `deny` so the default is unsafe-free; individual items opt in via
// `#[allow(unsafe_code)]` with a documented `// SAFETY:` block.
#![deny(unsafe_code)]

// Modules that the bare-metal lifecycle consumes. On host builds
// (cargo test), the bare-metal entry isn't compiled, so many items
// here look unused — silence dead_code in that configuration.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod bootinfo;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod merge;
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod validate;
// arm64 KASLR seed overlay: the committed template + the byte-level seed patch
// (host-tested). Compiled for aarch64 bare metal (where it's merged onto the
// base) and for host test builds; unused on x86 bare metal.
#[cfg(any(test, target_arch = "aarch64"))]
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod kaslr;

#[cfg(target_os = "none")]
mod workspace;

// The guest-memory layout: one typed static per output section. The linker
// script only orders them; sizes (and the few derived offsets) live here.
#[cfg(target_os = "none")]
mod sections;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod arch_x86_64;

// x86-only boot CPU tables (cr3/gdtr), baked into the binary as the
// `.tatu.pgt` / `.tatu.gdt` sections. dillo loads them before tatu runs.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod bootmem;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
mod arch_aarch64;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use arch_x86_64 as arch;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use arch_aarch64 as arch;

/// 4 KiB-aligned newtype. Wrapping a section's payload in `Paged`
/// rounds the type's size up to the 4 KiB PMI granularity, so each
/// section's size — and therefore its packed offset — is encoded in
/// the type itself (see `sections`). Also page-aligns outputs tatu
/// hands to Linux (e.g. the ACPI buffer's type-3 e820 entry).
#[cfg(target_os = "none")]
#[repr(C, align(4096))]
pub(crate) struct Paged<T>(pub T);

#[cfg(target_os = "none")]
impl<T: Default> Default for Paged<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!(
        "tatu is a bare-metal binary. Build with:\n\
         \tcargo build --release --target x86_64-unknown-none\n\
         \tcargo build --release --target aarch64-unknown-none"
    );
    std::process::exit(2);
}

// ---------------------------------------------------------------------------
// Cross-arch lifecycle.
// ---------------------------------------------------------------------------

#[cfg(target_os = "none")]
use crate::{
    bootinfo::{MAGIC, TatuBootInfo, base_dtb_bytes, host_dtbo_bytes},
    merge::merge_into,
    validate::{validate_host_dtbo, validate_merged},
};
#[cfg(target_os = "none")]
use devtree::{Overlay, Tree};

/// Maximum accepted host DTBO size. The `.tatu.dtbo` reservation is
/// exactly 64 KiB; a larger host-controlled `host_dtbo_size` would make
/// `host_dtbo_bytes` construct an out-of-bounds slice (pmi spec dt.md
/// §2 — the merger MUST reject an overlay beyond its accepted bound).
#[cfg(target_os = "none")]
const HOST_DTBO_MAX: u32 = 64 * 1024;

/// Cross-arch lifecycle entry. Called by the per-arch reset stub,
/// which loads `&BOOTINFO` into the first-argument register before
/// jumping here. The reference's bytes are arma's PMI-build-time
/// fill; the asm boundary keeps the optimizer from seeing the
/// `TatuBootInfo::ZERO` placeholder.
#[cfg(target_os = "none")]
extern "C" fn rust_main(bootinfo: &TatuBootInfo) -> ! {
    // 1. Sanity-check that arma actually filled the header (a
    //    stale, unfilled section is all-zero and fails here).
    if bootinfo.magic != MAGIC {
        panic_halt(b"bootinfo: bad magic");
    }

    // 2. Prepare the DTB the host overlay merges onto. On aarch64 this performs
    //    a first merge: a trusted kaslr overlay (with a fresh guest-entropy
    //    /chosen/kaslr-seed) is merged onto the measured base into a temporary
    //    stack buffer. The seed is guest-generated, so it never lives in the
    //    measured base DTB. On x86 this is a no-op (the base is used as-is;
    //    KASLR is applied via relocations after the merge). `kaslr_scratch` must
    //    outlive `base` — it backs the intermediate tree.
    let mut kaslr_scratch = [0u8; 16 * 1024];
    let base_blob: &[u8] =
        match arch::prepare_merge_base(base_dtb_bytes(bootinfo), &mut kaslr_scratch) {
            Ok(b) => b,
            Err(()) => panic_halt(b"kaslr overlay merge failed"),
        };
    let base: Tree<'_> = match Tree::parse(base_blob) {
        Ok(t) => t,
        Err(_) => panic_halt(b"base dtb: structural parse failed"),
    };

    // 3. Reject an oversized host overlay before parsing (resource-exhaustion
    //    defense; pmi spec dt.md §2 / commit 3d6753b — the merger MUST
    //    reject an overlay beyond its accepted bound). See `HOST_DTBO_MAX`.
    if bootinfo.host_dtbo_size > HOST_DTBO_MAX {
        panic_halt(b"host dtbo: oversized");
    }

    // 3b. Parse the host-supplied DTBO (adversarial; filled into the
    //     .dtbo section via the dt:dtbo fill kind).
    let overlay: Overlay<'static> = match Overlay::parse(host_dtbo_bytes(bootinfo)) {
        Ok(o) => o,
        Err(_) => panic_halt(b"host dtbo: structural parse failed"),
    };

    // 4. Enforce the merged-extension allowlist (pmi/spec/dt.md
    //    §2) on the host DTBO against the base DTB template.
    if validate_host_dtbo(&overlay, &base).is_err() {
        panic_halt(b"host dtbo: allowlist rejection");
    }

    // 5. Merge the host DTBO onto the measured base. The buffer is the
    //    `.tatu.dtbm` section (a static, not a stack frame) — a large
    //    stack allocation triggers Rust's __chkstk probe, which walks rsp
    //    down a page at a time until it underflows the STACK and
    //    triple-faults; a static avoids the probe. It is capped at base
    //    (.tatu.dtb 8 KiB) + overlay (.tatu.dtbo 64 KiB) = 72 KiB. Its GPA
    //    reaches Linux via x0 (aarch64) or stays addressable via
    //    boot_params (x86). See `sections::DTBM`.
    let dtb_buf = sections::dtbm_buf();
    let Ok(merged_size) = merge_into(&base, overlay, dtb_buf) else {
        panic_halt(b"dtbo merge failed")
    };

    // 6. Re-parse the merged tree.
    let merged_blob: &[u8] = &dtb_buf[..merged_size];
    let merged_gpa = dtb_buf.as_ptr() as u64;
    let merged: Tree<'_> = match Tree::parse(merged_blob) {
        Ok(t) => t,
        Err(_) => panic_halt(b"merged dtb: re-parse failed"),
    };

    // 7. Validate the merged tree (schema + semantic + maxima).
    //    PMI's dt.md §2 already requires the VMM to declare
    //    `/memory@*` covering every load/fill range and explicitly
    //    waives consumer-side validation — failures manifest as
    //    kernel boot DoS, observable to the host.
    // The address bound for host-supplied regions is the guest's physical
    // address width (pmi spec bc7f581) — read from the architectural ID
    // register, never a hardcoded constant.
    if validate_merged(&merged, arch::guest_pa_bits()).is_err() {
        panic_halt(b"merged dtb: validation failed");
    }

    // 8. Per-arch finalization + jump.
    finalize(&merged, bootinfo, merged_gpa, merged_size)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn finalize(
    merged: &Tree<'_>,
    bootinfo: &TatuBootInfo,
    _merged_gpa: u64,
    _merged_size: usize,
) -> ! {
    use arch::{AcpiTables, CmdLine, Initrd, apply_kaslr, boot_kernel, build_boot_params_elf};

    // a. Generate ACPI tables into the fixed .tatu.acpi workspace (the
    //    reserved [640K,1M) zone). Its GPA becomes the e820 entry and
    //    boot_params.acpi_rsdp_addr; Linux preserves it. OEM strings are
    //    hardcoded in arch_x86_64.
    let Ok(acpi) = AcpiTables::generate(merged, arch::acpi_workspace()) else {
        panic_halt(b"acpi generation failed")
    };

    // b. Read /chosen (§12.6 step 7c).
    let Some(cmdline) = CmdLine::from_dtb(merged) else {
        panic_halt(b"/chosen/bootargs missing")
    };
    let initrd = Initrd::from_dtb(merged);

    // c. Build boot_params on the stack — dtb2e820 writes the
    //    e820 table directly into the LinuxBootParams.e820_table
    //    field, no intermediate buffer. arma always hands tatu a flat ELF
    //    `vmlinux` image (it converts vmlinuz internally), so there is a
    //    single x86 boot path: synthesize boot_params, no setup-header copy.
    let Ok(bp) = build_boot_params_elf(&cmdline, &initrd, &acpi, merged) else {
        panic_halt(b"boot_params build failed")
    };

    // d. Apply x86 virtual KASLR: randomize the kernel's virtual base by
    //    patching the relocation tables in place (no-op without relocs). The
    //    physical entry is unaffected — the kernel self-derives `phys_base`.
    apply_kaslr(bootinfo);

    // e. Jump to the kernel's 64-bit entry. arma records its GPA (the ELF
    //    `e_entry`, which need not be the image base) (§12.6 step 7e).
    boot_kernel(bootinfo.kernel_entry_gpa, bp)
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn finalize(
    _merged: &Tree<'_>,
    bootinfo: &TatuBootInfo,
    merged_gpa: u64,
    _merged_size: usize,
) -> ! {
    use arch::{MergedDtb, boot_kernel};

    use crate::bootinfo::kernel_bytes;
    let dtb = MergedDtb { gpa: merged_gpa };
    boot_kernel(kernel_bytes(bootinfo), dtb)
}

// ---------------------------------------------------------------------------
// Panic handler + halt-with-message.
// ---------------------------------------------------------------------------

// Tatu has no console of its own — emulating a UART would bake guest
// hardware knowledge (device address + register layout) into the boot stub.
// A fatal error is signalled to dillo purely through the hypervisor-exit
// channel: `arch::halt()` raises an unrecoverable fault, which dillo observes
// as a non-zero VM exit. The static `&[u8]` context strings at the
// `panic_halt` call sites stay in the binary and are visible at the halt
// frame under a debugger — that is the supported way to see *why* tatu failed.

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    arch::halt()
}

#[cfg(target_os = "none")]
fn panic_halt(msg: &[u8]) -> ! {
    // `msg` is retained as call-site documentation / a debugger breadcrumb;
    // the fault from `halt()` is what actually signals the failure to dillo.
    let _ = msg;
    arch::halt()
}
