// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guest-memory layout — one typed static per output section.
//!
//! The linker script (`linker/tatu.ld`) only *orders* these sections;
//! every address falls out of their sizes by contiguous packing. Which
//! sections exist is controlled purely by `#[cfg]`, so the same linker
//! script yields the optimal layout on each architecture: the x86-only
//! legacy/padding sections vanish on aarch64 (an absent section's
//! placement evaporates — the linker drops it without perturbing the
//! location counter), and the rest pack tight from 0.
//!
//! Sizes live in the *types*, so `size_of_val` over the instances derives
//! the few offsets tatu needs (notably [`PGT_BASE`], the prefix sum to
//! `.tatu.pgt`). Change a section's type and the layout reflows; the
//! compile-time `assert!`s pin the x86 architectural boundaries (640 KiB,
//! 1 MiB) so a size change that would push ACPI out of the reserved zone
//! fails the build. Addresses are never hardcoded (ARCHITECTURE.md §6.3):
//! arma reads each section's GPA from tatu's ELF and cross-checks.

// `link_section` overrides trip the unsafe-code lint; this whole module is
// the documented placement contract for `linker/tatu.ld`, not a soundness
// hazard — same pattern as the other reserved input sections.
#![allow(unsafe_code)]

// Only the x86_64 layout arithmetic (flex stack, PGT_BASE) reads instance
// sizes; aarch64 packs with no derived offsets.
#[cfg(target_arch = "x86_64")]
use core::mem::size_of_val;

use crate::Paged;
use crate::workspace::PageCell;

// ---------------------------------------------------------------------------
// Shared sections (both architectures).
// ---------------------------------------------------------------------------

/// `.tatu.dtb` — measured base DTB. arma fills it at PMI build time; tatu
/// reads it via the bootinfo GPA. The static only reserves the section.
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.dtb")]
pub(crate) static DTB: PageCell<Paged<[u8; 8 * 1024]>> = PageCell::new(Paged([0; 8 * 1024]));

/// `.tatu.dtbo` — host overlay. dillo fills it at launch (the unmeasured
/// half); tatu reads it via the bootinfo GPA.
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.dtbo")]
pub(crate) static DTBO: PageCell<Paged<[u8; 64 * 1024]>> = PageCell::new(Paged([0; 64 * 1024]));

/// `.tatu.dtbm` — merged-DTB buffer. tatu writes the merge here. On aarch64
/// this is the output Linux reads via `x0`; on x86 it is throwaway scratch
/// (Linux only reads the cmdline pointer into it, early). Bounded by base
/// (`.tatu.dtb` 8 KiB) + overlay (`.tatu.dtbo` 64 KiB) = 72 KiB.
#[used]
#[unsafe(link_section = ".tatu.dtbm")]
pub(crate) static DTBM: PageCell<Paged<[u8; 72 * 1024]>> = PageCell::new(Paged([0; 72 * 1024]));

/// Unique `&'static mut` view of the merged-DTB buffer. Called once, from
/// `rust_main`.
pub(crate) fn dtbm_buf() -> &'static mut [u8] {
    // SAFETY: tatu runs on a single boot vCPU with no APs, so a mutable
    // static is sound for the same reason as STACK (see workspace.rs).
    let buf: &'static mut [u8; 72 * 1024] = unsafe { &mut (*DTBM.as_mut_ptr()).0 };
    buf
}

// ---------------------------------------------------------------------------
// x86_64-only sections: the legacy low-memory map. Each is a zero pad over
// an architectural scan window, or a fixed boot-CPU structure. All vanish
// on aarch64, so the shared sections above pack contiguously from 0 there.
// ---------------------------------------------------------------------------

/// `.tatu.guard` — 4 KiB at GPA 0. The MP/BDA scan window [0,1K) must read
/// zero; this keeps the stack off it. Absent on aarch64, so the stack
/// becomes the first section at GPA 0.
#[cfg(target_arch = "x86_64")]
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.guard")]
pub(crate) static GUARD: PageCell<Paged<[u8; 4 * 1024]>> = PageCell::new(Paged([0; 4 * 1024]));

/// `.tatu.scanpad` — covers the [639K,640K) MP scan window. Sized so ACPI
/// lands exactly at the 640 KiB reserved-zone boundary.
#[cfg(target_arch = "x86_64")]
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.scanpad")]
pub(crate) static SCANPAD: PageCell<Paged<[u8; 4 * 1024]>> = PageCell::new(Paged([0; 4 * 1024]));

#[cfg(target_arch = "x86_64")]
mod smbios {
    pub(super) const IMAGE_SIZE: usize = 4 * 1024;
    const ENTRY_OFFSET: usize = 0;
    const TABLE_OFFSET: usize = 0x20;
    const TABLE_GPA: u32 = 0xF0000 + TABLE_OFFSET as u32;
    const TABLE_LEN: u16 = 47;
    const STRUCT_COUNT: u16 = 2;
    const MAX_STRUCT_SIZE: u16 = 41;

    pub(super) const IMAGE: [u8; IMAGE_SIZE] = image();

    const fn image() -> [u8; IMAGE_SIZE] {
        let mut out = [0u8; IMAGE_SIZE];
        write_entry(&mut out);
        write_table(&mut out);
        out[ENTRY_OFFSET + 0x04] = checksum(&out, ENTRY_OFFSET, 0x1f);
        out[ENTRY_OFFSET + 0x15] = checksum(&out, ENTRY_OFFSET + 0x10, 0x0f);
        out
    }

    const fn write_entry(out: &mut [u8; IMAGE_SIZE]) {
        out[0x00] = b'_';
        out[0x01] = b'S';
        out[0x02] = b'M';
        out[0x03] = b'_';
        out[0x05] = 0x1f;
        out[0x06] = 2;
        out[0x07] = 8;
        write_u16(out, 0x08, MAX_STRUCT_SIZE);
        out[0x0a] = 0;
        out[0x10] = b'_';
        out[0x11] = b'D';
        out[0x12] = b'M';
        out[0x13] = b'I';
        out[0x14] = b'_';
        write_u16(out, 0x16, TABLE_LEN);
        write_u32(out, 0x18, TABLE_GPA);
        write_u16(out, 0x1c, STRUCT_COUNT);
        out[0x1e] = 0x28;
    }

    const fn write_table(out: &mut [u8; IMAGE_SIZE]) {
        let mut p = TABLE_OFFSET;

        out[p] = 0;
        out[p + 1] = 0x12;
        write_u16(out, p + 2, 0);
        out[p + 4] = 1;
        out[p + 5] = 2;
        write_u16(out, p + 6, 0);
        out[p + 8] = 3;
        out[p + 9] = 0;
        p += 0x12;

        p = write_str(out, p, b"TATU");
        p = write_str(out, p, b"Pichi");
        p = write_str(out, p, b"01/01/2020");
        out[p] = 0;
        p += 1;

        out[p] = 127;
        out[p + 1] = 4;
        write_u16(out, p + 2, 0x7f00);
        out[p + 4] = 0;
        out[p + 5] = 0;
    }

    const fn write_str(out: &mut [u8; IMAGE_SIZE], mut p: usize, s: &[u8]) -> usize {
        let mut i = 0;
        while i < s.len() {
            out[p] = s[i];
            p += 1;
            i += 1;
        }
        out[p] = 0;
        p + 1
    }

    const fn write_u16(out: &mut [u8; IMAGE_SIZE], p: usize, v: u16) {
        out[p] = v as u8;
        out[p + 1] = (v >> 8) as u8;
    }

    const fn write_u32(out: &mut [u8; IMAGE_SIZE], p: usize, v: u32) {
        out[p] = v as u8;
        out[p + 1] = (v >> 8) as u8;
        out[p + 2] = (v >> 16) as u8;
        out[p + 3] = (v >> 24) as u8;
    }

    const fn checksum(out: &[u8; IMAGE_SIZE], start: usize, len: usize) -> u8 {
        let mut sum = 0u8;
        let mut i = 0;
        while i < len {
            sum = sum.wrapping_add(out[start + i]);
            i += 1;
        }
        0u8.wrapping_sub(sum)
    }
}

/// `.tatu.dmi` — SMBIOS entry point + table in the [0xF0000,1M) DMI scan
/// window. Linux uses the BIOS release date to validate high ECAM windows.
#[cfg(target_arch = "x86_64")]
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.dmi")]
pub(crate) static DMI: PageCell<Paged<[u8; smbios::IMAGE_SIZE]>> =
    PageCell::new(Paged(smbios::IMAGE));

/// `.tatu.rompad` — covers the rest of the [0xF0000,1M) MP/DMI scan window
/// and pushes the code sections up to the 1 MiB floor.
#[cfg(target_arch = "x86_64")]
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.rompad")]
pub(crate) static ROMPAD: PageCell<Paged<[u8; 60 * 1024]>> = PageCell::new(Paged([0; 60 * 1024]));

/// `.tatu.reset.x86_64.pad` — 0xFF0 zero bytes that position the 16-byte
/// reset stub at the architectural reset vector 0xFFFFFFF0 (the stub
/// follows this pad in `.tatu.reset`). A static rather than a linker
/// `. = . + 0xFF0` so the whole `.tatu.reset` section is *genuinely* empty
/// on aarch64 (no nonzero location-counter advance to keep it alive) and
/// the linker drops it.
#[cfg(target_arch = "x86_64")]
#[used]
#[allow(dead_code)]
#[unsafe(link_section = ".tatu.reset.x86_64.pad")]
pub(crate) static RESET_PAD: PageCell<[u8; 0xFF0]> = PageCell::new([0; 0xFF0]);

// ---------------------------------------------------------------------------
// Stack — its own section on both arches, placed first (after the x86 guard)
// so an underflow walks toward GPA 0. On x86 its size is the flex filler
// that makes conventional RAM end exactly at 640 KiB (maximising the stack);
// aarch64 has no such boundary, so it is a plain fixed size.
// ---------------------------------------------------------------------------

/// x86 640 KiB conventional/reserved split — the only bare architectural
/// constant in the layout; everything else is a section size.
#[cfg(target_arch = "x86_64")]
const CONV_TOP: usize = 640 * 1024;

/// Stack size. x86: fills conventional RAM up to the 640 KiB barrier, so
/// the stack is as large as possible and ACPI starts exactly at 640 KiB.
#[cfg(target_arch = "x86_64")]
pub(crate) const STACK_SIZE: usize = CONV_TOP
    - (size_of_val(&GUARD)
        + core::mem::size_of::<crate::bootinfo::TatuBootInfo>()
        + size_of_val(&DTB)
        + size_of_val(&DTBO)
        + size_of_val(&DTBM)
        + crate::bootmem::PGT_SIZE
        + crate::bootmem::GDT_SIZE
        + size_of_val(&SCANPAD));

/// Stack size. aarch64: no legacy boundary, so a plain fixed size.
#[cfg(target_arch = "aarch64")]
pub(crate) const STACK_SIZE: usize = 456 * 1024;

/// `.tatu.stack` — the runtime stack (SP starts at the top, grows down).
#[used]
#[unsafe(link_section = ".tatu.stack")]
pub(crate) static STACK: PageCell<Paged<[u8; STACK_SIZE]>> = PageCell::new(Paged([0; STACK_SIZE]));

// ---------------------------------------------------------------------------
// Derived offsets + boundary assertions (x86_64).
// ---------------------------------------------------------------------------

/// Load GPA of `.tatu.pgt` — derived, not declared: the prefix sum of the
/// sections that precede it (guard, stack, bootinfo, dtb, dtbo, dtbm). The
/// page-table self-pointers (`bootmem`) embed this at const-eval time; arma
/// reads the actual section GPA from the ELF and cross-checks. Change any
/// preceding section's size and this follows.
#[cfg(target_arch = "x86_64")]
pub(crate) const PGT_BASE: u64 = (size_of_val(&GUARD)
    + size_of_val(&STACK)
    + core::mem::size_of::<crate::bootinfo::TatuBootInfo>()
    + size_of_val(&DTB)
    + size_of_val(&DTBO)
    + size_of_val(&DTBM)) as u64;

#[cfg(target_arch = "x86_64")]
const _: () = {
    // Boot CPU tables land at PGT_BASE; the self-pointers depend on it.
    assert!(PGT_BASE == 0x9_8000);
    // ACPI fills [640K,960K); DMI + rompad fill [960K,1M); code floor = 1 MiB.
    assert!(
        CONV_TOP
            + crate::arch_x86_64::ACPI_WORKSPACE_SIZE
            + size_of_val(&DMI)
            + size_of_val(&ROMPAD)
            == 0x10_0000
    );
};
