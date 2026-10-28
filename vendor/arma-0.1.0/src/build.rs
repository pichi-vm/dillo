// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Top-level build pipeline.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::fs_ext::AtomicWrite;
use crate::{base_dtb, bootinfo, initrd, kconfig, kernel, manifest, pe, planner, tatu};

pub(crate) use crate::manifest::DtbMode;

/// Resolve `(mmio_slots, pci_slots)` (device-model.md §6 Slot composition).
/// With `--config`, infer/validate against kernel support; without it, honor
/// explicit slots, else default to a PCI bridge (TODO C5: embedded IKCONFIG).
/// Load the kernel build config used for slot inference (C4) AND the profile
/// floor clamp (C2): `--config` if given, else the kernel's embedded
/// CONFIG_IKCONFIG (C5), else error (device-model §6).
fn load_kernel_config(args: &BuildArgs, kernel: &[u8]) -> Result<kconfig::KernelConfig> {
    match &args.config_path {
        Some(p) => {
            let text =
                fs::read_to_string(p).with_context(|| format!("read --config: {}", p.display()))?;
            Ok(kconfig::KernelConfig::parse(text))
        }
        None => kconfig::KernelConfig::from_ikconfig(kernel).ok_or_else(|| {
            anyhow::anyhow!(
                "no --config given and the kernel has no embedded CONFIG_IKCONFIG; \
                 pass --config <kernel .config> for slot inference"
            )
        }),
    }
}

/// Inputs to a single `arma build` invocation. All caller-supplied —
/// arma carries no policy defaults.
pub(crate) struct BuildArgs {
    pub(crate) kernel_path: PathBuf,
    pub(crate) initrd_path: Option<PathBuf>,
    pub(crate) module_names: Vec<String>,
    pub(crate) module_tree: Option<PathBuf>,
    pub(crate) cmdline: String,
    /// vCPU ISA baseline; `None` ⇒ the per-arch RHEL 9 default (C2).
    pub(crate) profile: Option<String>,
    pub(crate) serial: bool,
    pub(crate) output_path: PathBuf,
    /// Kernel build config (text Kconfig); `None` ⇒ no config supplied.
    pub(crate) config_path: Option<PathBuf>,
    /// Explicit `--mmio-slots` / `--pci-slots` overrides (`None` ⇒ infer).
    pub(crate) mmio_slots: Option<u32>,
    pub(crate) pci_slots: Option<u32>,
    /// `--pci-window <B>` / `--min-addr-space <X>` (bits); `None` ⇒ per-arch
    /// defaults (C4b, device-model §6).
    pub(crate) pci_window: Option<u32>,
    pub(crate) min_addr_space: Option<u32>,
    /// Base-DTB channel mode (`dt` extension); defaults to optional.
    pub(crate) dtb_mode: manifest::DtbMode,
    /// Detached-mode output path for the generated base DTB (`Some` only when
    /// `dtb_mode` is [`manifest::DtbMode::Detached`]).
    pub(crate) dtb_out: Option<PathBuf>,
}

pub(crate) fn run(args: &BuildArgs) -> Result<()> {
    if args.module_tree.is_some() && args.module_names.is_empty() {
        bail!("--module-tree requires at least one --module selection");
    }
    if !args.module_names.is_empty() && args.initrd_path.is_none() {
        bail!("--module requires a static ELF --initrd");
    }
    for name in &args.module_names {
        crate::modules::validate_name(name)?;
    }
    // ---- Step 1: read inputs ----
    let kernel_bytes = fs::read(&args.kernel_path)
        .with_context(|| format!("read kernel: {}", args.kernel_path.display()))?;
    // Unwrap an arm64 EFI-zboot kernel to its raw Image (no-op for bzImage /
    // raw Image inputs) so everything downstream sees boot-ready bytes.
    let kernel_bytes = kernel::unwrap_zboot(kernel_bytes).context("kernel decompression")?;
    // Convert a bzImage (vmlinuz) to its embedded ELF vmlinux so tatu only ever
    // receives a flat ELF image (no-op for a raw vmlinux / arm64 Image).
    let kernel_bytes =
        kernel::extract_vmlinux(kernel_bytes).context("extract vmlinux from bzImage")?;
    let initrd_bytes = match args.initrd_path.as_ref() {
        Some(p) => Some(fs::read(p).with_context(|| format!("read initrd: {}", p.display()))?),
        None => None,
    };

    // ---- Step 2: arch inference + kernel validation ----
    let parsed_kernel = kernel::parse(&kernel_bytes).context("kernel format validation")?;
    let arch = parsed_kernel.arch;

    // An x86 ELF `vmlinux` is lowered here to its flat loaded-segment image so
    // everything downstream — sizing, the `.linux` section, tatu — sees
    // boot-ready bytes it can place at the kernel GPA and enter at offset 0,
    // exactly as for a bzImage / arm64 Image (which pass through unchanged).
    let kernel_image: std::borrow::Cow<'_, [u8]> = match parsed_kernel.elf {
        Some(_) => std::borrow::Cow::Owned(
            kernel::elf_load_image(&kernel_bytes).context("lower ELF vmlinux to loaded image")?,
        ),
        None => std::borrow::Cow::Borrowed(kernel_bytes.as_slice()),
    };

    // x86 KASLR relocation table — extracted from the ELF's `.rela.*` sections so
    // tatu can randomize the kernel's virtual base. Empty for aarch64 (which
    // randomizes via a DTB kaslr-seed instead) and for any x86 kernel built
    // without `--emit-relocs`.
    let relocs = match parsed_kernel.elf {
        Some(_) => {
            let r = kernel::extract_relocs(&kernel_bytes).context("extract KASLR relocations")?;
            if r.is_empty() {
                // An x86 kernel with no relocation data cannot be virtually
                // randomized — tatu would have to enter it at a fixed virtual
                // base. arma refuses to produce a non-KASLR image rather than
                // silently weaken the guest.
                bail!(
                    "x86 kernel has no relocation data (not built with --emit-relocs / \
                     CONFIG_X86_NEED_RELOCS); arma requires a KASLR-capable kernel"
                );
            }
            r
        }
        None => kernel::Relocs::default(),
    };
    let relocs_bytes = relocs.to_section_bytes();
    let relocs_size = (!relocs_bytes.is_empty()).then_some(relocs_bytes.len() as u64);

    // Per-arch device-model defaults (§6). TODO(C4/C4b): drive these from
    // `--mmio-slots`/`--pci-slots`/`--pci-window`/`--min-addr-space` + slot
    // inference. For now: emit the PCIe bridge, no virtio-mmio yet.
    // C4b: window/space bits from --pci-window/--min-addr-space, else per-arch
    // defaults (§6). The X ≥ B+2 invariant is enforced in base_dtb::build.
    let (def_x, def_b) = match arch {
        kernel::Arch::Aarch64 => (36u32, 34u32),
        kernel::Arch::X86_64 => (39u32, 37u32),
    };
    let addr_space_bits = args.min_addr_space.unwrap_or(def_x);
    let window_bits = args.pci_window.unwrap_or(def_b);
    let kcfg = load_kernel_config(args, &kernel_bytes)?;
    let (mmio_slots, pci_slots) = kcfg
        .infer_slots(arch, args.mmio_slots, args.pci_slots)
        .context("slot inference")?;

    // Poweroff drivability: Arma always emits the arch-appropriate poweroff
    // device, but a guest that can drive none of them will hang on `poweroff`
    // instead of exiting the VM. Warn (not fatal — the guest still boots and
    // runs; only clean shutdown is affected).
    if kcfg.poweroff_support(arch) == kconfig::PoweroffSupport::Unsupported {
        let needs = match arch {
            kernel::Arch::X86_64 => "CONFIG_ACPI or CONFIG_POWER_RESET_SYSCON_POWEROFF",
            kernel::Arch::Aarch64 => "CONFIG_ARM_PSCI_FW",
        };
        eprintln!(
            "arma: warning: the kernel config exposes no poweroff mechanism the \
             guest can drive (needs {needs}); the guest will not power off the VM \
             on shutdown"
        );
    }

    // ---- Step 3: cpio auto-detect / wrap ----
    let initrd_materialized = if args.module_names.is_empty() {
        initrd_bytes
            .as_deref()
            .map(initrd::materialize)
            .transpose()
            .context("materialize initrd")?
    } else {
        let input = initrd_bytes
            .as_deref()
            .context("module options require --initrd")?;
        initrd::check_module_init(input).context("materialize initrd with modules")?;
        let release = crate::kernel_release::detect(&kernel_bytes)
            .context("detect target kernel release for modules")?;
        let selection =
            crate::modules::resolve(&release, args.module_tree.as_deref(), &args.module_names)
                .context("resolve selected modules")?;
        eprintln!("arma: kernel release: {release}");
        eprintln!("arma: module tree: {}", selection.tree.display());
        for name in &selection.builtins {
            eprintln!("arma: built-in module: {name}");
        }
        for file in &selection.files {
            kcfg.check_module(&file.relative)
                .context("selected module kernel support")?;
            let kind = if file.is_root {
                "selected"
            } else {
                "dependency"
            };
            eprintln!("arma: {kind} module: {}", file.posix_relative());
        }
        let files: Vec<_> = selection
            .files
            .iter()
            .map(|file| initrd::Module {
                path: &file.relative,
                bytes: &file.bytes,
            })
            .collect();
        Some(std::borrow::Cow::Owned(
            initrd::materialize_modules(input, &release, &files)
                .context("materialize initrd with modules")?,
        ))
    };
    let initrd_size = initrd_materialized.as_ref().map(|v| v.len() as u64);

    // ---- Step 4: select embedded tatu ----
    let tatu_elf = native_tatu_elf(arch)?;

    // ---- Step 5: parse tatu ELF ----
    let tatu_img = tatu::parse(tatu_elf, arch).context("parse embedded tatu ELF")?;

    // ---- Step 6: kernel metadata for placement ----
    //
    // `kernel_file_size` is the loaded-image byte count. `kernel_alloc_size` is
    // the RAM footprint the kernel needs at runtime — the ELF segment span's
    // memsz (x86), or the aarch64 Image header's image_size.
    let kernel_file_size = kernel_image.len() as u64;
    let kernel_alloc_size = compute_kernel_alloc_size(
        kernel_file_size,
        parsed_kernel.aarch64_image_size,
        parsed_kernel.elf,
    );
    let kernel_alignment = 2 * 1024 * 1024;
    // x86: floor the load GPA to the ELF's lowest `p_paddr` (entering
    // `startup_64` below it underflows `phys_base`). 0 on aarch64 (the Image is
    // position-flexible).
    let kernel_pref_addr = parsed_kernel.elf.map_or(0, |e| e.min_paddr);

    // ---- Step 7: plan the guest-physical layout ----
    // The planner avoids tatu's fixed sections plus the architecture
    // fixed/specific devices (LAPIC/IOAPIC/syscon, GIC/v2m), and assigns the
    // kernel, initrd, and generic device MMIO (serial/virtio/ECAM/window).
    let mut reserved: Vec<core::ops::Range<u64>> = tatu_img.reserved().collect();
    reserved.extend(base_dtb::arch_reserved(arch));
    let lay = planner::Planner {
        args: planner::ArgsSpec {
            serial: args.serial,
            mmio_slots,
            pci_slots,
            window_bits,
            addr_space_bits,
        },
        reserved: &reserved,
        kernel: planner::KernelSpec {
            size: kernel_alloc_size,
            align: kernel_alignment,
            min_gpa: kernel_pref_addr,
        },
        initrd_size,
        relocs_size,
    }
    .plan()
    .context("plan guest-physical layout")?;

    // ---- Step 8: base DTB (single pass) ----
    // Device addresses and the initrd extent both come from the plan, so the
    // DTB is built once — no sizing/final two-pass dance.
    let cmdline = serial_earlycon_cmdline(args.serial, &args.cmdline);
    let initrd_extent = lay.initrd.as_ref().map(|r| (r.start, r.end - r.start));
    let dtb_bytes = base_dtb::build(&base_dtb::Inputs {
        arch,
        cmdline: &cmdline,
        initrd: initrd_extent,
        serial: lay.serial.clone(),
        virtio: &lay.virtio,
        ecam: lay.ecam.clone(),
        pci_window: lay.pci_window.clone(),
    })
    .context("build base DTB")?;
    let dtb_size = dtb_bytes.len() as u64;

    // `.tatu.dtb` / `.tatu.dtbo` are tatu-defined sections: arma fills
    // `.tatu.dtb` with the base DTB (must fit the reserved capacity) and dillo
    // fills `.tatu.dtbo` at launch. Their GPAs come from tatu's own layout.
    let dtb_sec = tatu_img
        .section(".tatu.dtb")
        .context("tatu ELF missing .tatu.dtb section")?;
    if dtb_size > dtb_sec.virtual_size {
        bail!(
            "base DTB ({dtb_size:#x} bytes) exceeds .tatu.dtb capacity ({:#x})",
            dtb_sec.virtual_size
        );
    }
    let dtb_gpa = dtb_sec.vaddr;
    let dtbo_sec = tatu_img
        .section(".tatu.dtbo")
        .context("tatu ELF missing .tatu.dtbo section")?;
    let dtbo_gpa = dtbo_sec.vaddr;
    let dtbo_size = dtbo_sec.virtual_size;

    // ---- Step 9: TatuBootInfo ----
    // kernel_size here is the FILE size — tatu reads it to find the setup
    // header, NOT the alloc size.
    // Kernel entry GPA: x86 ELF entry may sit anywhere in the loaded image, so
    // it is the load base plus the ELF entry offset; otherwise the base.
    let kernel_entry_gpa = lay.linux.start + parsed_kernel.elf.map_or(0, |e| e.entry_offset);
    let relocs_header = bootinfo::RelocsHeader {
        gpa: lay.relocs.as_ref().map_or(0, |r| r.start),
        relocs64_count: relocs.relocs64.len() as u32,
        relocs32neg_count: relocs.relocs32neg.len() as u32,
        relocs32_count: relocs.relocs32.len() as u32,
    };
    let bi = bootinfo::TatuBootInfo::new(
        dtb_gpa,
        dtb_size as u32,
        dtbo_gpa,
        dtbo_size as u32,
        lay.linux.start,
        kernel_file_size as u32,
        kernel_entry_gpa,
        kernel_alloc_size as u32,
        relocs_header,
    );
    let bootinfo_section_bytes = bi.to_section_bytes();

    // ---- Step 10: CBOR manifest ----
    // C2: --profile defaults to RHEL 9's baseline, then is clamped UP to the
    // kernel's ISA build floor (so a higher-built kernel can't get a profile
    // below what it requires); an explicit --profile may raise it further.
    let baseline = match arch {
        kernel::Arch::Aarch64 => "armv8.0-a",
        kernel::Arch::X86_64 => "x86-64-v2",
    };
    let chosen = args.profile.as_deref().unwrap_or(baseline);
    let cpu_profile = kconfig::raise_to_floor(chosen, kcfg.isa_floor(arch), arch);
    // Explicit action GPAs (pmi spec f6be1eb): the planner's placement for the
    // kernel/initrd/relocs; tatu sections and the dtbo fill carry their ELF
    // vaddr (resolved inside build_actions).
    let action_gpas = manifest::ActionGpas {
        linux: lay.linux.start,
        initrd: lay.initrd.as_ref().map(|r| r.start),
        relocs: lay.relocs.as_ref().map(|r| r.start),
    };
    let cbor = manifest::build_pmi_vm(arch, &tatu_img, action_gpas, &cpu_profile, args.dtb_mode)
        .context("build CBOR manifest")?;

    // Detached mode: the base DTB is delivered out-of-band, so write the
    // generated base to the caller's path instead of bundling it in the PMI.
    if let (manifest::DtbMode::Detached, Some(path)) = (args.dtb_mode, args.dtb_out.as_ref()) {
        path.atomic_write(&dtb_bytes)?;
    }

    // ---- Step 11: assemble PE section list ----
    let sections = assemble_sections(
        &tatu_img,
        &bootinfo_section_bytes,
        kernel_image.as_ref(),
        initrd_materialized.as_deref(),
        &relocs_bytes,
        &dtb_bytes,
        &lay,
        &cbor,
        args.dtb_mode,
    );

    // ---- Step 12: emit PE; atomic write ----
    let pe_bytes = pe::build_pe(arch.pe_machine(), &sections).context("emit PE")?;

    args.output_path.atomic_write(&pe_bytes)?;
    Ok(())
}

fn native_tatu_elf(arch: kernel::Arch) -> Result<&'static [u8]> {
    match arch {
        #[cfg(target_arch = "x86_64")]
        kernel::Arch::X86_64 => Ok(crate::TATU_X86_64),
        #[cfg(target_arch = "aarch64")]
        kernel::Arch::Aarch64 => Ok(crate::TATU_AARCH64),
        other => bail!(
            "arma is temporarily native-arch-only: this host can build {native}, \
             but the input kernel is {other:?}",
            native = native_arch_name()
        ),
    }
}

fn native_arch_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unsupported"
    }
}

fn serial_earlycon_cmdline(serial: bool, cmdline: &str) -> String {
    if !serial || has_earlycon(cmdline) {
        return cmdline.to_owned();
    }
    if cmdline.trim().is_empty() {
        "earlycon".to_owned()
    } else {
        format!("earlycon {cmdline}")
    }
}

fn has_earlycon(cmdline: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|arg| arg == "earlycon" || arg.starts_with("earlycon="))
}

#[cfg(test)]
mod tests {
    use super::serial_earlycon_cmdline;

    #[test]
    fn serial_prepends_plain_earlycon() {
        assert_eq!(
            serial_earlycon_cmdline(true, "console=hvc0 quiet"),
            "earlycon console=hvc0 quiet"
        );
    }

    #[test]
    fn serial_keeps_existing_earlycon() {
        assert_eq!(
            serial_earlycon_cmdline(true, "earlycon=acpi,spcr console=hvc0"),
            "earlycon=acpi,spcr console=hvc0"
        );
        assert_eq!(
            serial_earlycon_cmdline(true, "earlycon console=hvc0"),
            "earlycon console=hvc0"
        );
    }

    #[test]
    fn no_serial_leaves_cmdline_unchanged() {
        assert_eq!(
            serial_earlycon_cmdline(false, "console=hvc0"),
            "console=hvc0"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_sections<'a>(
    tatu_img: &'a tatu::TatuImage,
    bootinfo_bytes: &'a [u8],
    kernel_bytes: &'a [u8],
    initrd_bytes: Option<&'a [u8]>,
    relocs_bytes: &'a [u8],
    dtb_bytes: &'a [u8],
    lay: &planner::Layout,
    cbor: &'a [u8],
    dtb_mode: manifest::DtbMode,
) -> Vec<pe::Section<'a>> {
    use std::borrow::Cow;

    let mut out: Vec<pe::Section<'a>> = Vec::with_capacity(16);

    // Tatu sections in their ELF-resolved GPA order. arma overrides
    // tatu-defined zero sections with computed bytes: `.tatu.bootinfo`
    // (the header) always, and `.tatu.dtb` (the measured base DTB) only in
    // attached mode — where the base is bundled and delivered by a `load`.
    // In detached/optional mode `.tatu.dtb` is the `dt:dtb` fill target and
    // stays a Zero section; the base is delivered out-of-band, and in
    // optional mode a bundled fallback rides in `.dtb` (added below).
    // `.tatu.dtbo` always stays a zero section — dillo fills it at launch.
    let bundle_base = dtb_mode == manifest::DtbMode::Attached;
    for s in &tatu_img.sections {
        let data: Cow<'a, [u8]> = if s.is_bootinfo {
            // Tatu's section is 4 KiB virtual; arma fills the same 4 KiB
            // with header + zero pad.
            Cow::Borrowed(bootinfo_bytes)
        } else if s.is_dtb && bundle_base {
            // Fill the reserved .tatu.dtb section with the base DTB; the
            // rest of the section stays zero (virtual_size > dtb len).
            Cow::Borrowed(dtb_bytes)
        } else if s.is_dtb || s.is_nobits {
            // Zero section: reserved range, no image bytes (a fill target).
            Cow::Borrowed(&[])
        } else {
            Cow::Borrowed(s.data.as_slice())
        };
        out.push(pe::Section {
            name: s.name.clone(),
            vaddr: s.vaddr,
            virtual_size: s.virtual_size,
            data,
            characteristics: tatu_section_characteristics(&s.name, s.is_nobits),
            non_loaded: false,
        });
    }

    // Optional mode: the bundled fallback base DTB. It is named by the
    // `dt:dtb` attribute and read by the VMM only when it has no out-of-band
    // base; it is placed nowhere in guest memory, so it rides as a non-loaded
    // section (like `.pmi.vm`) with no GPA.
    if dtb_mode == manifest::DtbMode::Optional {
        out.push(pe::Section {
            name: manifest::SECTION_DTB_FALLBACK.into(),
            vaddr: 0,
            virtual_size: dtb_bytes.len() as u64,
            data: Cow::Borrowed(dtb_bytes),
            characteristics: pe::IMAGE_SCN_CNT_INITIALIZED_DATA
                | pe::IMAGE_SCN_MEM_READ
                | pe::IMAGE_SCN_MEM_DISCARDABLE,
            non_loaded: true,
        });
    }

    // .linux (LARGE) — borrowed from the caller's owned buffer. Sits
    // in its own 2 MiB-aligned file region per PMI granularity. The
    // virtual_size exceeds the file size on x86 to declare the bzImage
    // decompressor's scratch buffer (Padded shape per PMI §"Section
    // Shapes"); dillo's placement uses virtual_size when sizing
    // memslots, which is exactly the RAM the kernel will touch.
    out.push(pe::Section {
        name: manifest::SECTION_LINUX.into(),
        vaddr: lay.linux.start,
        virtual_size: lay.linux.end - lay.linux.start,
        data: Cow::Borrowed(kernel_bytes),
        characteristics: pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ,
        non_loaded: false,
    });

    // SMALL pool. Emitted in guest-VA order, with Data-shape sections
    // first and the Zero-shape `.dtbo` last (matches layout::compute).
    // File offsets follow declaration order in pe::build_pe, so the
    // Data SMALLs end up as one contiguous file run aligned with their
    // guest-VA run — letting a VMM mmap them as a single unit.

    // .initrd — borrowed.
    if let (Some(bytes), Some(r)) = (initrd_bytes, &lay.initrd) {
        out.push(pe::Section {
            name: manifest::SECTION_INITRD.into(),
            vaddr: r.start,
            virtual_size: r.end - r.start,
            data: Cow::Borrowed(bytes),
            characteristics: pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ,
            non_loaded: false,
        });
    }

    // .linux.relocs — the x86 KASLR relocation table (borrowed). tatu reads it
    // at boot, applies the relocations, and the region is then free.
    if let Some(r) = &lay.relocs {
        out.push(pe::Section {
            name: manifest::SECTION_RELOCS.into(),
            vaddr: r.start,
            virtual_size: r.end - r.start,
            data: Cow::Borrowed(relocs_bytes),
            characteristics: pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ,
            non_loaded: false,
        });
    }

    // The measured base DTB, the host-DTBO, and the x86 boot CPU tables
    // (`.tatu.pgt` / `.tatu.gdt`) are NOT synthesized here: they are all
    // tatu-defined sections. arma fills `.tatu.dtb` with the base DTB
    // bytes in the tatu-sections loop above (via `is_dtb`); `.tatu.dtbo`
    // is emitted as the tatu zero section that dillo fills; the boot CPU
    // tables ship as const-fn-baked PROGBITS straight from tatu's ELF.

    // .pmi.vm (non-loaded; CBOR manifest)
    out.push(pe::Section {
        name: manifest::SECTION_PMI_VM.into(),
        vaddr: 0,
        virtual_size: cbor.len() as u64,
        data: Cow::Borrowed(cbor),
        characteristics: pe::IMAGE_SCN_CNT_INITIALIZED_DATA
            | pe::IMAGE_SCN_MEM_READ
            | pe::IMAGE_SCN_MEM_DISCARDABLE,
        non_loaded: true,
    });

    out
}

fn tatu_section_characteristics(name: &str, is_nobits: bool) -> u32 {
    // Conservative mapping. Tatu's linker emits:
    //   .tatu.text   — code, RX
    //   .tatu.rodata — read-only data
    //   .tatu.data   — RW data (rare; tatu's release binary minimizes this)
    //   .tatu.bootinfo — RW (arma writes header at build time; tatu reads)
    //   .tatu.bss    — RW zero (BSS)
    //   .tatu.reset  — code, RX (x86 reset trampoline at 0xFFFF_F000;
    //                  on aarch64 it's collapsed into .tatu.text by
    //                  the linker and never appears here)
    if is_nobits {
        pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_WRITE
    } else if name.contains(".text") || name == ".tatu.reset" {
        pe::IMAGE_SCN_CNT_CODE | pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_EXECUTE
    } else if name.contains(".rodata") {
        pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ
    } else {
        pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_WRITE
    }
}

/// Compute the kernel section's RAM footprint.
///
/// x86 ELF vmlinux: the segment span's memsz extent (file-backed prefix + BSS),
/// computed from the program headers in [`kernel::ElfMeta`]. aarch64 Image: the
/// header's `image_size` (text + BSS), which exceeds the file when the BSS isn't
/// stored. Either way returns at least `file_size` so the section holds the
/// on-disk bytes.
fn compute_kernel_alloc_size(
    file_size: u64,
    aarch64_image_size: Option<u64>,
    elf: Option<kernel::ElfMeta>,
) -> u64 {
    if let Some(e) = elf {
        return e.alloc_size.max(file_size);
    }
    aarch64_image_size.unwrap_or(0).max(file_size)
}

#[cfg(test)]
mod tests_alloc {
    use super::*;

    #[test]
    fn aarch64_alloc_is_max_file_and_image_size() {
        // No image_size header info → file size.
        assert_eq!(compute_kernel_alloc_size(0x800000, None, None), 0x800000);
        // image_size > file (BSS not in file, the Firecracker case) → image_size.
        assert_eq!(
            compute_kernel_alloc_size(0xF84800, Some(0x1080000), None),
            0x1080000
        );
        // image_size < file (or padded equal) → file size.
        assert_eq!(
            compute_kernel_alloc_size(0x2110000, Some(0x2110000), None),
            0x2110000
        );
    }

    #[test]
    fn elf_alloc_is_segment_span_memsz() {
        let elf = kernel::ElfMeta {
            alloc_size: 0x123_4000,
            min_paddr: 0x100_0000,
            entry_offset: 0,
        };
        // ELF span dominates; file-backed image is never larger.
        assert_eq!(
            compute_kernel_alloc_size(0x100_0000, None, Some(elf)),
            0x123_4000
        );
    }

    #[test]
    fn alloc_never_smaller_than_file_size() {
        // ELF span smaller than the on-disk image → clamp up to file size.
        let elf = kernel::ElfMeta {
            alloc_size: 0x1000,
            min_paddr: 0x100_0000,
            entry_offset: 0,
        };
        let alloc = compute_kernel_alloc_size(0x10_000_000, None, Some(elf));
        assert_eq!(alloc, 0x10_000_000);
    }
}
