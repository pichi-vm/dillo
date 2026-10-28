// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! x86_64 finalization: entry stub, e820, boot_params, ACPI
//! generation, halt/debug, kernel handoff. See ARCHITECTURE.md
//! Part II.
//!
//! Unsafe lives where natural: the reset-vector global_asm, the
//! halt sequence, the debug-port write, and the final kernel jmp.
//! Each block carries a `// SAFETY:` note (§7.1).

#![allow(unsafe_code)]

use devtree::{NodeView, TreeView};

use crate::validate::ValidationError;

/// Hardcoded OEM identity stamped into every emitted ACPI table.
/// Tatu doesn't accept per-image OEM strings; if a caller needs
/// vendor branding in dmesg, this is the lever.
const OEM: dtb2acpi::OemIdentity = dtb2acpi::OemIdentity {
    oem_id: *b"TATU  ",
    oem_table_id: *b"TATUOEM ",
    oem_revision: 1,
    creator_id: *b"TATU",
    creator_revision: 1,
};

/// Size of the ACPI output buffer (the `.tatu.acpi` section). It now owns
/// the entire reserved [640K,960K) zone — base 640K is the RSDP GPA, and
/// it ends at 960K, leaving only the [0xF0000,1M) rompad scan-window gap.
/// Far beyond the §4.5 maxima (2048 vCPUs + 32 NUMA domains ≈ 80 KiB); the
/// rest is unwritten zero tail. `AcpiBuffer<N>` is a transparent `[u8; N]`,
/// so `Paged<AcpiBuffer<N>>` is exactly `N` (N is a 4 KiB multiple).
pub(crate) const ACPI_WORKSPACE_SIZE: usize = 320 * 1024;

/// Page-aligned ACPI output buffer. `dtb2acpi::AcpiBuffer` is only
/// 16-byte aligned (RSDP requirement); the `Paged` wrapper bumps that
/// to 4 KiB so the e820 entry tatu emits starts on a page boundary.
pub(crate) type AcpiBuf = crate::Paged<dtb2acpi::AcpiBuffer<ACPI_WORKSPACE_SIZE>>;

/// The `.tatu.acpi` workspace. tatu generates the ACPI tables here and
/// hands the GPA to Linux via `boot_params.acpi_rsdp_addr`. Fixed at
/// link time in the reserved [640K,1M) zone (linker/x86_64.ld).
#[used]
#[unsafe(link_section = ".tatu.acpi")]
static ACPI_WORKSPACE: crate::workspace::PageCell<AcpiBuf> = crate::workspace::PageCell::new(
    crate::Paged(dtb2acpi::AcpiBuffer::<ACPI_WORKSPACE_SIZE>::new()),
);

/// The `.tatu.acpi` workspace as a unique `&'static mut`.
pub(crate) fn acpi_workspace() -> &'static mut AcpiBuf {
    // SAFETY: tatu runs on a single boot vCPU with no APs and no
    // concurrent access (see workspace.rs), so a single &mut to the
    // static is sound. Called once, from finalize.
    unsafe { &mut *ACPI_WORKSPACE.as_mut_ptr() }
}

// ---------------------------------------------------------------------------
// Reset vector + BOOTINFO storage. Both live in this private
// submodule so `BOOTINFO` is referenced only by the asm `sym`
// below — no other Rust code can read or write it, and the
// optimizer can't fold through the asm boundary.
// ---------------------------------------------------------------------------

mod reset {
    use crate::bootinfo::TatuBootInfo;
    use crate::sections::STACK_SIZE;

    /// The `.tatu.bootinfo` section. Arma overwrites the
    /// placeholder zeros at PMI build time. **Never read from
    /// Rust by name** — its address is materialized only through
    /// the asm `sym` below, and reaches the rest of tatu only via
    /// the `&TatuBootInfo` parameter to `rust_main`. Any direct
    /// read here would let the optimizer see the placeholder
    /// `TatuBootInfo::ZERO` and constant-fold the magic check to
    /// `false`.
    #[used]
    #[unsafe(link_section = ".tatu.bootinfo")]
    static BOOTINFO: TatuBootInfo = TatuBootInfo::ZERO;

    /// 16-byte reset trampoline placed at 0xFFFFFFF0 by the linker
    /// script. Its section is `.tatu.reset.x86_64` (not the shared
    /// `.tatu.reset`) so the single `linker/tatu.ld` can route the x86
    /// stub to the architectural reset vector while the aarch64 stub
    /// folds into `.tatu.text`.
    ///
    /// SAFETY: STACK, BOOTINFO, and rust_main all live in the low
    /// 4 GiB of address space (the main image is in the low 1 MiB).
    /// `mov esp/edi, imm32` zero-extends into RSP/RDI
    /// (a long-mode rule for 32-bit destination registers).
    /// `push imm32` in long mode sign-extends to 64 bits and
    /// pushes 8 bytes; the main image's top bit is clear, so
    /// sign-extension matches zero-extension. `ret` pops 8 bytes
    /// into RIP, transferring control to rust_main with RSP back
    /// where `mov esp` left it. System V x86_64 ABI: first arg in
    /// RDI, so rust_main receives `bootinfo: &TatuBootInfo`. The
    /// stub is exactly 5 + 5 + 5 + 1 = 16 bytes — no padding nops.
    /// `#[unsafe(no_mangle)]` is the keep-alive anchor: rustc
    /// drops unreachable naked fns in `#![no_main]` binaries
    /// regardless of `pub` visibility, and `#[used]` doesn't
    /// apply to functions. no_mangle exposes the symbol as an
    /// external linkage point, which both prevents DCE and
    /// makes the name available to the linker's `ENTRY()`.
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    #[unsafe(link_section = ".tatu.reset.x86_64")]
    extern "C" fn reset() -> ! {
        core::arch::naked_asm!(
            "mov  esp, offset {stack} + {size}",
            "mov  edi, offset {bootinfo}",
            "push offset {main}",
            "ret",
            stack    = sym crate::sections::STACK,
            size     = const STACK_SIZE,
            bootinfo = sym BOOTINFO,
            main     = sym crate::rust_main,
        )
    }
}

// ---------------------------------------------------------------------------
// Halt: load null IDT + ud2 → #UD → #DF → triple fault.
// ---------------------------------------------------------------------------

#[inline(never)]
pub(crate) fn halt() -> ! {
    // SAFETY: lidt with a zero-limit descriptor disables all
    // exception handlers; ud2 then triggers #UD which escalates
    // via #DF to triple-fault → KVM_EXIT_SHUTDOWN. The vCPU
    // cannot resume.
    unsafe {
        let null_idtr: [u8; 10] = [0; 10];
        core::arch::asm!(
            "lidt [{p}]",
            p = in(reg) &raw const null_idtr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("ud2", options(noreturn));
    }
}

// ---------------------------------------------------------------------------
// e820 entry list.
//
// DT→e820 translation (memory / reserved-memory / pci-host-ecam-generic)
// lives in `dtb2e820`; we re-export its types. tatu owns the storage
// (a stack-resident fixed array sized for §4.5 maxima) and prepends
// one ACPI-workspace entry (type 3) before delegating the rest of the
// slice to `ExtractE820::extract_e820`.
// ---------------------------------------------------------------------------

pub(crate) use dtb2e820::{E820Entry, E820Type, ExtractE820};

/// Cap on the number of e820 entries tatu ever emits. Sized for
/// `pmi/spec` §4.5 maxima (≤16 memory regions + a handful of reserved
/// + ECAM windows + 1 ACPI workspace entry).
pub(crate) const E820_MAX_ENTRIES: usize = 128;

// ---------------------------------------------------------------------------
// /chosen readers: CmdLine and Initrd are typed wrappers per
// ARCHITECTURE.md §12.6.
// ---------------------------------------------------------------------------

/// Kernel command-line pointer/length, derived from
/// `/chosen/bootargs`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct CmdLine {
    ptr: u64,
}

impl CmdLine {
    pub(crate) fn from_dtb<T: TreeView>(tree: &T) -> Option<Self> {
        let chosen = tree.find_path("/chosen")?;
        let bootargs = chosen.property("bootargs")?;
        Some(Self {
            ptr: bootargs.as_ref().as_ptr() as u64,
        })
    }

    pub(crate) fn ptr(self) -> u64 {
        self.ptr
    }
}

/// Initial-ramdisk region, derived from `/chosen/linux,initrd-{start,end}`.
/// Absent when those properties aren't present.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Initrd {
    gpa: u64,
    size: u64,
}

impl Initrd {
    pub(crate) fn from_dtb<T: TreeView>(tree: &T) -> Self {
        let Some(chosen) = tree.find_path("/chosen") else {
            return Self::none();
        };
        let (Some(start_p), Some(end_p)) = (
            chosen.property("linux,initrd-start"),
            chosen.property("linux,initrd-end"),
        ) else {
            return Self::none();
        };
        let (Some(start), Some(end)) = (read_uint(start_p.as_ref()), read_uint(end_p.as_ref()))
        else {
            return Self::none();
        };
        if end < start {
            return Self::none();
        }
        Self {
            gpa: start,
            size: end - start,
        }
    }

    pub(crate) const fn none() -> Self {
        Self { gpa: 0, size: 0 }
    }

    pub(crate) fn gpa(self) -> u64 {
        self.gpa
    }
    pub(crate) fn size(self) -> u64 {
        self.size
    }
}

fn read_uint(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u64::from(u32::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        8 => Some(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => None,
    }
}

fn map_e820_err(e: dtb2e820::Error) -> ValidationError {
    match e {
        dtb2e820::Error::BufferFull => ValidationError::TooManyMemoryRegions,
        dtb2e820::Error::BadRegShape => ValidationError::BadPropertyShape,
    }
}

// ---------------------------------------------------------------------------
// Typed mirror of Linux's `struct boot_params` (the "zero page") and
// its nested `struct setup_header`. Field offsets are pinned by sized
// `_pad*` arrays — there is no `[u8; 4096]` byte slice underneath,
// so all writes from `fill` are typed field assignments, and
// `dtb2e820::populate` writes directly into the [`e820_table`]
// field rather than into an intermediate buffer.
//
// Both structs are byte-for-byte wire-compatible with Linux's
// definitions; `static_assert!(size_of::<LinuxBootParams>() == 4096)`
// catches layout drift.
// ---------------------------------------------------------------------------

/// `struct setup_header` from `arch/x86/include/uapi/asm/bootparam.h`,
/// pinned to the protocol-2.15 layout tatu targets. Only the fields
/// tatu writes are typed; the rest are padding. Lives at offset
/// `0x1F1` within [`LinuxBootParams`]; total size 127 bytes.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub(crate) struct SetupHeader {
    pub setup_sects: u8,
    _pad_to_boot_flag: [u8; 0x0D - 0x01],
    pub boot_flag: u16,
    _pad_to_header: [u8; 0x11 - 0x0F],
    /// Setup magic — "HdrS".
    pub header: u32,
    _pad_to_type_of_loader: [u8; 0x1F - 0x15],
    pub type_of_loader: u8,
    pub loadflags: u8,
    _pad_to_code32_start: [u8; 0x23 - 0x21],
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    _pad_to_cmd_line_ptr: [u8; 0x37 - 0x2F],
    pub cmd_line_ptr: u32,
    _pad_to_end: [u8; 0x7F - 0x3B],
}

/// `struct boot_params` (Linux's "zero page"), 4096 bytes, with only
/// the fields tatu writes typed and the rest as named pads.
#[repr(C)]
pub(crate) struct LinuxBootParams {
    _pad_to_acpi_rsdp: [u8; 0x70],
    pub acpi_rsdp_addr: u64,
    _pad_to_e820_entries: [u8; 0x1E8 - 0x78],
    pub e820_entries: u8,
    _pad_to_setup_header: [u8; 0x1F1 - 0x1E9],
    pub setup_header: SetupHeader,
    _pad_to_e820_table: [u8; 0x2D0 - 0x270],
    pub e820_table: [E820Entry; E820_MAX_ENTRIES],
    _pad_to_end: [u8; 0x1000 - 0x2D0 - E820_MAX_ENTRIES * 20],
}

const _: () = assert!(core::mem::size_of::<LinuxBootParams>() == 4096);
const _: () = assert!(core::mem::size_of::<SetupHeader>() == 0x7F);

// Protocol constants stay associated with LinuxBootParams.
impl LinuxBootParams {
    pub(crate) const HEADER_MAGIC_VAL: u32 = 0x5372_6448; // "HdrS"
    pub(crate) const BOOT_FLAG_VAL: u16 = 0xAA55;
    pub(crate) const LOADED_HIGH: u8 = 0x01;
    pub(crate) const LOADER_TYPE_TATU: u8 = 0xE0; // unallocated loader-type tag for tatu

    pub(crate) fn zeroed() -> Self {
        // SAFETY: all-zero is a valid bit pattern for LinuxBootParams
        // (every field is a u8 array, scalar with `Default == 0`, or a
        // struct/array of the same). E820Entry's all-zero gives
        // `kind = Invalid`, which is the legal default.
        unsafe { core::mem::zeroed() }
    }

    pub(crate) fn as_ptr(&self) -> *const Self {
        core::ptr::from_ref(self)
    }

    /// Fill the e820 table from `tree` + `acpi`, writing directly
    /// into [`Self::e820_table`] with no intermediate buffer.
    pub(crate) fn fill_e820<T: TreeView>(
        &mut self,
        tree: &T,
        acpi: &AcpiTables,
    ) -> Result<(), ValidationError> {
        // Slot 0: ACPI workspace entry (type 3). Linux preserves
        // exactly this range; the surrounding stack reverts to
        // type-1 (reclaimable) once Linux processes the e820 map.
        *self
            .e820_table
            .get_mut(0)
            .ok_or(ValidationError::TooManyMemoryRegions)? = E820Entry {
            addr: acpi.rsdp_gpa(),
            size: acpi.size(),
            kind: E820Type::Acpi,
        };
        // dtb2e820 writes directly into the boot_params storage.
        let dt_slice = self
            .e820_table
            .get_mut(1..)
            .ok_or(ValidationError::TooManyMemoryRegions)?;
        let n = tree.extract_e820(dt_slice).map_err(map_e820_err)?;
        self.e820_entries =
            u8::try_from(n.saturating_add(1)).map_err(|_| ValidationError::TooManyMemoryRegions)?;
        Ok(())
    }

    /// Populate `boot_params` for an ELF `vmlinux` entered at `startup_64`.
    ///
    /// There is no real-mode setup header to copy — arma already lowered the
    /// ELF to a flat loaded image entered at its first byte. tatu sets only the
    /// fields the 64-bit boot protocol reads at `startup_64`: a well-formed zero
    /// page (boot magic + tatu loader id + `LOADED_HIGH`), the command line, the
    /// initrd, the ACPI RSDP, and the e820 map. `code32_start` / `setup_sects`
    /// are real-mode-only and stay zero.
    pub(crate) fn fill_elf<T: TreeView>(
        &mut self,
        cmdline: &CmdLine,
        initrd: &Initrd,
        acpi: &AcpiTables,
        tree: &T,
    ) -> Result<(), ValidationError> {
        let cmd_line_ptr =
            u32::try_from(cmdline.ptr()).map_err(|_| ValidationError::AddressOverflow)?;
        let ramdisk_image =
            u32::try_from(initrd.gpa()).map_err(|_| ValidationError::AddressOverflow)?;
        let ramdisk_size =
            u32::try_from(initrd.size()).map_err(|_| ValidationError::AddressOverflow)?;

        self.setup_header.boot_flag = Self::BOOT_FLAG_VAL;
        self.setup_header.header = Self::HEADER_MAGIC_VAL;
        self.setup_header.type_of_loader = Self::LOADER_TYPE_TATU;
        self.setup_header.loadflags = Self::LOADED_HIGH;
        self.setup_header.ramdisk_image = ramdisk_image;
        self.setup_header.ramdisk_size = ramdisk_size;
        self.setup_header.cmd_line_ptr = cmd_line_ptr;
        self.acpi_rsdp_addr = acpi.rsdp_gpa();

        self.fill_e820(tree, acpi)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AcpiTables — typed wrapper around the ACPI workspace after
// dtb2acpi has populated it. Carries the RSDP GPA.
// ---------------------------------------------------------------------------

pub(crate) struct AcpiTables {
    rsdp_gpa: u64,
}

impl AcpiTables {
    /// Populate the caller-supplied ACPI buffer (a stack-local in
    /// `finalize`). The buffer's GPA is page-aligned (via `Paged`);
    /// the returned `AcpiTables` records it so e820 + boot_params
    /// get the right RSDP address.
    pub(crate) fn generate<T: TreeView>(
        tree: &T,
        buf: &mut AcpiBuf,
    ) -> Result<Self, ValidationError> {
        let gpa = core::ptr::from_ref::<AcpiBuf>(buf) as u64;
        buf.0
            .populate(tree, &OEM, gpa)
            .map_err(|_| ValidationError::BadPropertyShape)?;
        Ok(Self { rsdp_gpa: gpa })
    }

    pub(crate) fn rsdp_gpa(&self) -> u64 {
        self.rsdp_gpa
    }

    // `&self` is kept for symmetry with `rsdp_gpa` and a uniform table API;
    // the workspace size is fixed by the reserved zone.
    #[allow(clippy::unused_self)]
    pub(crate) fn size(&self) -> u64 {
        ACPI_WORKSPACE_SIZE as u64
    }
}

// ---------------------------------------------------------------------------
// build_boot_params — composes LinuxBootParams from the typed inputs
// per ARCHITECTURE.md §12.6 step 8d.
// ---------------------------------------------------------------------------

pub(crate) fn build_boot_params_elf<T: TreeView>(
    cmdline: &CmdLine,
    initrd: &Initrd,
    acpi: &AcpiTables,
    tree: &T,
) -> Result<LinuxBootParams, ValidationError> {
    let mut bp = LinuxBootParams::zeroed();
    bp.fill_elf(cmdline, initrd, acpi, tree)?;
    Ok(bp)
}

// ---------------------------------------------------------------------------
// KASLR: randomize the kernel's *virtual* base by applying the relocation
// tables arma extracted (see arma `kernel::extract_relocs`). This mirrors the
// kernel decompressor's `handle_relocations` (arch/x86/boot/compressed/misc.c):
// a single virtual `delta` is added to every absolute reference into the image.
//
// The kernel runs at any *physical* base for free: `__startup_64`
// (arch/x86/boot/startup/map_kernel.c) derives `p2v_offset` at runtime from
// where it physically executes vs. its (now-relocated) link-time literal, and
// builds its own page tables. So tatu performs NO page-table work — it patches
// the image in place and jumps to the same physical entry as before.
//
// Entropy comes from the guest CPU (`RDRAND`), never the host — a hard
// requirement for confidential-computing guests (the host must not be able to
// predict the layout). With no relocation tables (a kernel built without
// `--emit-relocs`) this is a no-op and the kernel boots un-randomized.
// ---------------------------------------------------------------------------

use crate::bootinfo::TatuBootInfo;

/// The kernel's link-time virtual base offset within the high map
/// (`LOAD_PHYSICAL_ADDR`, = `CONFIG_PHYSICAL_START`, default 16 MiB) and the
/// high-map window the page tables cover (`KERNEL_IMAGE_SIZE`, 1 GiB for a KASLR
/// kernel). The virtual base may move anywhere in `[0, KERNEL_IMAGE_SIZE -
/// image)` that is `PMD`-aligned (`__startup_64` rejects a non-2 MiB delta).
const LOAD_PHYSICAL_ADDR: u64 = 0x100_0000;
const KERNEL_IMAGE_SIZE: u64 = 0x4000_0000;
const KASLR_ALIGN: u64 = 0x20_0000; // PMD (2 MiB)

/// x86 counterpart of the aarch64 kaslr-seed injection: a no-op that returns the
/// measured base unchanged. x86 randomizes the kernel's virtual base via applied
/// relocations ([`apply_kaslr`], post-merge), not a DTB seed — so there is no
/// first merge here. `scratch` is unused on x86.
//
// The `Result` is infallible here but mirrors the fallible aarch64 signature
// so the cross-arch caller in `main` stays uniform.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn prepare_merge_base<'a>(
    base: &'a [u8],
    _scratch: &'a mut [u8],
) -> Result<&'a [u8], ()> {
    Ok(base)
}

/// Guest physical-address width in bits, from `CPUID Fn8000_0008` `EAX[7:0]`.
/// Per pmi spec bc7f581 this is the bound for host-supplied addresses in the
/// merged DTB — read from the architectural leaf, never a hardcoded constant.
pub(crate) fn guest_pa_bits() -> u32 {
    // SAFETY: leaf 0x8000_0008 is architectural on any x86-64 CPU running in
    // long mode (where tatu executes); `__cpuid` has no memory/flag effects.
    // (`__cpuid` is safe to call on this target; the `unsafe` is kept for
    // toolchains that still mark it unsafe.)
    #[allow(unused_unsafe)]
    let leaf = unsafe { core::arch::x86_64::__cpuid(0x8000_0008) };
    leaf.eax & 0xFF
}

/// Apply x86 virtual KASLR to the loaded kernel image, in place. No-op when arma
/// supplied no relocation tables. Must run before [`boot_kernel`].
pub(crate) fn apply_kaslr(bootinfo: &TatuBootInfo) {
    let words = crate::bootinfo::relocs_words(bootinfo);
    if words.is_empty() {
        return;
    }
    let c64 = bootinfo.relocs64_count as usize;
    let c32n = bootinfo.relocs32neg_count as usize;
    let c32 = bootinfo.relocs32_count as usize;
    // Defensive: counts must match the section the words came from.
    if c64 + c32n + c32 != words.len() {
        return;
    }
    let relocs64 = &words[..c64];
    let relocs32neg = &words[c64..c64 + c32n];
    let relocs32 = &words[c64 + c32n..];

    // Choose a PMD-aligned virtual delta in the legal range. `slots` is at least
    // 1, so the modulo is always defined; `delta == 0` is a valid (un-shifted)
    // outcome that simply applies no movement.
    let headroom = KERNEL_IMAGE_SIZE
        .saturating_sub(bootinfo.kernel_alloc_size as u64)
        .saturating_sub(LOAD_PHYSICAL_ADDR);
    let slots = headroom / KASLR_ALIGN + 1;
    let delta = (rand_u64() % slots) * KASLR_ALIGN;
    if delta == 0 {
        return;
    }

    let img = crate::bootinfo::kernel_bytes_mut(bootinfo);
    // 64-bit absolute references: `*p += delta`.
    for &off in relocs64 {
        let o = off as usize;
        if let Some(s) = img.get_mut(o..o + 8) {
            let v = u64::from_le_bytes(s.try_into().unwrap()).wrapping_add(delta);
            s.copy_from_slice(&v.to_le_bytes());
        }
    }
    // Per-CPU PC-relative references: `*p -= delta` (inverse).
    for &off in relocs32neg {
        let o = off as usize;
        if let Some(s) = img.get_mut(o..o + 4) {
            let v = i32::from_le_bytes(s.try_into().unwrap()).wrapping_sub(delta as i32);
            s.copy_from_slice(&v.to_le_bytes());
        }
    }
    // 32-bit absolute references: `*p += delta`.
    for &off in relocs32 {
        let o = off as usize;
        if let Some(s) = img.get_mut(o..o + 4) {
            let v = u32::from_le_bytes(s.try_into().unwrap()).wrapping_add(delta as u32);
            s.copy_from_slice(&v.to_le_bytes());
        }
    }
}

/// Draw 64 bits of entropy from the guest CPU via `RDRAND`. Retries on the rare
/// transient failure (CF=0); if the instruction never succeeds the CPU has no
/// usable RNG, so we halt rather than silently boot without randomization.
fn rand_u64() -> u64 {
    for _ in 0..100 {
        let val: u64;
        let ok: u8;
        // SAFETY: RDRAND writes a random value to the destination and sets CF on
        // success. No memory operands, no stack effect.
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {c}",
                v = out(reg) val,
                c = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return val;
        }
    }
    halt()
}

// ---------------------------------------------------------------------------
// Kernel handoff. Loads rsi with &boot_params and jumps to the kernel's
// 64-bit entry (`startup_64`, the first byte of the loaded ELF image — arma
// enforces entry == image base). Never returns.
// ---------------------------------------------------------------------------

/// Architecturally final operation: load `&boot_params` into RSI
/// and jump to the kernel's 64-bit entry point. Never returns.
pub(crate) fn boot_kernel(entry: u64, bp: LinuxBootParams) -> ! {
    let bp_ptr = bp.as_ptr() as u64;

    // SAFETY: this is the architecturally final instruction tatu
    // executes. Per Linux x86 boot protocol the kernel receives
    // boot_params in `%rsi` and execution at the 64-bit entry
    // point. After this jmp, tatu's code is no longer running.
    unsafe {
        core::arch::asm!(
            "mov rsi, {bp}",
            "jmp {entry}",
            bp = in(reg) bp_ptr,
            entry = in(reg) entry,
            options(noreturn),
        );
    }
}
