/*
 * tatu/linker/tatu.ld — single, architecture-agnostic linker script.
 *
 * This script only *orders* sections; it assigns no addresses (the lone
 * exception is `.tatu.reset`, see below). Every section is a typed Rust
 * static in `src/sections.rs` (or a per-arch module), so its size lives in
 * the type and its GPA falls out of contiguous packing from 0. Which
 * sections exist is decided entirely by `#[cfg]`:
 *
 *   - x86_64: the full legacy low-memory map packs to fixed offsets purely
 *     by size — guard@0, stack (fills to the 640K barrier), the DTB
 *     buffers, the boot CPU tables at PGT_BASE==0x98000, the scan-window
 *     pads, ACPI filling [640K,960K), DMI at 960K, the rompad, then code at
 *     the 1 MiB floor. The compile-time `assert!`s in `sections.rs` pin those
 *     boundaries.
 *   - aarch64: the x86-only sections (guard/pgt/gdt/scanpad/acpi/rompad,
 *     and `.tatu.reset.x86_64`) have no `#[cfg(aarch64)]` static, so their
 *     output sections are empty and the linker drops them *without*
 *     perturbing the location counter — the remaining sections pack tight
 *     from 0.
 *
 * NOLOAD = runtime-filled or zero (no file/PMI bytes): guard, stack, the
 * DTB buffers, the pads, ACPI, bss. PROGBITS = const-baked content that
 * must ship: pgt, gdt, rodata, text, the reset stub.
 *
 * arma reads every section's GPA from this ELF's section table and
 * cross-checks the layout; it never hardcodes an address.
 */

ENTRY(reset)

/* One PT_LOAD per section. This keeps each NOLOAD (NOBITS) section in its
 * own segment so it contributes no file bytes, and — critically — puts the
 * reset trampoline (~4 GiB above the image) in a *separate* segment so the
 * linker never stores the intervening gap as zeros (without this the file
 * balloons to ~4 GiB). Phdrs whose sections are dropped on aarch64 emit no
 * segment, so the same block serves both arches. */
PHDRS {
    guard_ph    PT_LOAD;
    stack_ph    PT_LOAD;
    bootinfo_ph PT_LOAD;
    dtb_ph      PT_LOAD;
    dtbo_ph     PT_LOAD;
    dtbm_ph     PT_LOAD;
    pgt_ph      PT_LOAD;
    gdt_ph      PT_LOAD;
    scanpad_ph  PT_LOAD;
    acpi_ph     PT_LOAD;
    dmi_ph      PT_LOAD;
    rompad_ph   PT_LOAD;
    rodata_ph   PT_LOAD;
    text_ph     PT_LOAD;
    reset_ph    PT_LOAD;
}

SECTIONS {
    /* --- internal --- */
    .tatu.guard (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.guard)) } :guard_ph  /* x86-only */
    .tatu.stack (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.stack)) } :stack_ph

    /* --- inputs (arma/dillo fill) --- */
    .tatu.bootinfo (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.bootinfo)) } :bootinfo_ph
    .tatu.dtb      (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.dtb)) }      :dtb_ph
    .tatu.dtbo     (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.dtbo)) }     :dtbo_ph

    /* --- output / scratch --- */
    .tatu.dtbm (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.dtbm)) } :dtbm_ph

    /* --- x86-only boot CPU tables (PROGBITS: const-baked) --- */
    .tatu.pgt : ALIGN(4K) { KEEP(*(.tatu.pgt)) } :pgt_ph
    .tatu.gdt : ALIGN(4K) { KEEP(*(.tatu.gdt)) } :gdt_ph

    /* --- x86-only scan pad + ACPI output (fills [640K,960K)) --- */
    .tatu.scanpad (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.scanpad)) } :scanpad_ph
    .tatu.acpi    (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.acpi)) }    :acpi_ph

    /* --- x86-only SMBIOS/DMI scan-window payload + rompad --- */
    .tatu.dmi : ALIGN(4K) { KEEP(*(.tatu.dmi)) } :dmi_ph
    .tatu.rompad (NOLOAD) : ALIGN(4K) { KEEP(*(.tatu.rompad)) } :rompad_ph

    /* --- code (PROGBITS) --- */
    .tatu.rodata : ALIGN(4K) {
        *(.got) *(.got.plt)
        *(.rodata .rodata.*)
        *(.tatu.rodata .tatu.rodata.*)
        . = ALIGN(4K);              /* PMI: SizeOfRawData % 4 KiB == 0 */
    } :rodata_ph
    .tatu.text : ALIGN(4K) {
        /* aarch64 entry stub first so `reset` is the earliest insn in
           .text; absent on x86 (which uses .tatu.reset.x86_64 below). */
        KEEP(*(.tatu.reset.aarch64))
        *(.text .text.*)
        *(.tatu.text .tatu.text.*)
        *(.data .data.*)
        . = ALIGN(4K);              /* PMI granularity pad */
    } :text_ph

    /* --- x86-only reset trampoline: the one explicitly-addressed section,
       at the architectural reset vector ~4 GiB from the image. Empty on
       aarch64 (no .tatu.reset.x86_64 input), so it drops and its address
       evaporates without perturbing the layout above. --- */
    .tatu.reset 0xFFFFF000 : {
        KEEP(*(.tatu.reset.x86_64.pad))   /* 0xFF0 zero pad (x86-only) */
        KEEP(*(.tatu.reset.x86_64))       /* 16-byte stub → 0xFFFFFFF0 */
    } :reset_ph

    /* Everything is an explicit section: .bss must be empty. */
    .tatu.bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }

    /DISCARD/ : {
        *(.comment)
        *(.note) *(.note.*)
        *(.eh_frame) *(.eh_frame_hdr)
        *(.plt) *(.plt.got)
        *(.dynamic) *(.dynsym) *(.dynstr)
        *(.hash) *(.gnu.hash) *(.gnu.version) *(.gnu.version_r)
        *(.rela.*) *(.rel.*) *(.interp)
    }
}

ASSERT(SIZEOF(.tatu.bss) == 0,
       "tatu .bss must be empty — every region is an explicit section in src/sections.rs");
ASSERT(ADDR(.tatu.text) + SIZEOF(.tatu.text) <= 0x200000,
       "tatu image (through .tatu.text) must fit one 2 MiB slab [0,2M)");
