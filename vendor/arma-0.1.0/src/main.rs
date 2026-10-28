// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    trivial_casts,
    trivial_numeric_casts
)]
// Clippy lint policy (pedantic + curated allows) lives in the workspace
// `[lints]` table; this crate opts in via `[lints] workspace = true`.

mod base_dtb;
mod bootinfo;
mod build;
mod check;
mod cmdline;
mod fs_ext;
mod initrd;
mod kconfig;
mod kernel;
mod kernel_release;
mod manifest;
mod modules;
mod pe;
mod planner;
mod tatu;

// The native-arch tatu ELF comes from the artifact dependency declared in
// Cargo.toml. Cargo injects `CARGO_BIN_FILE_<DEP>_<bin>` for it.
#[cfg(target_arch = "x86_64")]
pub(crate) const TATU_X86_64: &[u8] = include_bytes!(env!("CARGO_BIN_FILE_TATU_tatu"));
#[cfg(target_arch = "aarch64")]
pub(crate) const TATU_AARCH64: &[u8] = include_bytes!(env!("CARGO_BIN_FILE_TATU_tatu"));

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "arma", version, about = "PMI builder for pichi-vm")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a PMI from a kernel, optional initrd, and cmdline.
    Build(Box<BuildArgs>),

    /// Lint a built PMI's guest-physical layout (read-only). Renders the map
    /// (device island, payload, the PCIe BAR window + burned buddy) and flags
    /// fragmentation, alignment, and the window invariants. See device-model §6.
    Check(CheckArgs),

    /// Read or rewrite the kernel command line (`/chosen/bootargs`) in a DTB.
    /// With no CMDLINE argument, prints the current command line; with one,
    /// rewrites it in place. Operates on a DTB file (e.g. a detached base).
    Cmdline(CmdlineArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// The PMI to inspect.
    pmi: PathBuf,
}

#[derive(Args)]
struct CmdlineArgs {
    /// The DTB file to read or modify.
    dtb: PathBuf,

    /// New command line. Omit to print `/chosen/bootargs`; provide to rewrite
    /// it in place (written verbatim).
    cmdline: Option<String>,
}

#[derive(Args)]
struct BuildArgs {
    /// Kernel image (bzImage on x86_64; raw arm64 Image on aarch64).
    #[arg(long)]
    kernel: PathBuf,

    /// Initramfs: complete cpio newc, uncompressed or gzip/zstd compressed,
    /// passed through unchanged (kernel needs CONFIG_RD_GZIP/ZSTD to unpack).
    /// A static ELF is wrapped in a cpio archive at /init.
    #[arg(long)]
    initrd: Option<PathBuf>,

    /// Module name to include with its hard dependencies when wrapping a static
    /// ELF init. Repeat to select more modules; aliases/paths are not accepted.
    #[arg(long = "module", requires = "initrd", value_parser = parse_module_name)]
    modules: Vec<String>,

    /// Release-specific module directory (not a rootfs). If omitted, discover
    /// /usr/lib/modules/<target-kernel-release> or /lib/modules/<release>.
    #[arg(long, requires = "modules")]
    module_tree: Option<PathBuf>,

    /// Kernel command line. Required — arma does not pick defaults
    /// (operator/test-harness chooses; arma is a faithful translator,
    /// not a policy maker).
    #[arg(long)]
    cmdline: String,

    /// vCPU ISA baseline written to `cpu:profile` (the VMM validates it
    /// against the host). Optional: defaults to the RHEL 9 baseline so a stock
    /// RHEL guest runs — `armv8.0-a` (aarch64) / `x86-64-v2` (x86-64).
    #[arg(long)]
    profile: Option<String>,

    /// Kernel build config (text Kconfig). Drives slot inference and
    /// drivability checks. If omitted, Arma falls back to a PCI-bridge
    /// default (TODO C5: extract the kernel's embedded CONFIG_IKCONFIG).
    #[arg(long)]
    config: Option<PathBuf>,

    /// virtio-mmio transport slot count. Default: inferred from `--config`
    /// (see device-model.md §6 Slot composition).
    #[arg(long = "mmio-slots")]
    mmio_slots: Option<u32>,

    /// PCIe slot count; `0` ⇒ no host bridge and no 64-bit window. Default:
    /// inferred from `--config`.
    #[arg(long = "pci-slots")]
    pci_slots: Option<u32>,

    /// 64-bit BAR window size in bits (window = `2^B` bytes). Default per-arch:
    /// 34 (aarch64) / 37 (x86-64). See device-model.md §6.
    #[arg(long = "pci-window")]
    pci_window: Option<u32>,

    /// Minimum guest-physical address bits `X` (the compatibility watermark).
    /// Default per-arch: 36 (aarch64) / 39 (x86-64). Invariant `X ≥ B+2`.
    #[arg(long = "min-addr-space")]
    min_addr_space: Option<u32>,

    /// Declare a canonical serial port in the DTB for early-boot debug
    /// output. Absent = no serial node, no UART emulation in the VMM,
    /// no ttyS0 in the guest (rely on virtio-console once it binds).
    /// Present = one MMIO `ns16550a` port at the per-arch canonical
    /// address: 0x09000000 IO-APIC pin 4 on x86_64; 0x0A110000 SPI 1
    /// on aarch64. Also declares `/aliases/serial0`, sets
    /// `/chosen/stdout-path = "serial0:115200n8"`, and prepends
    /// `earlycon` to the kernel command line. It does not choose the
    /// normal console; pass `console=...` explicitly if desired.
    #[arg(long = "serial")]
    serial: bool,

    /// Base-DTB channel mode (`dt` extension). Omit for optional mode (the
    /// default): the base is bundled as a fallback and the VMM may substitute
    /// an out-of-band base. Pass `attached` to bundle the base as the sole,
    /// loaded copy. Pass any other value as a path: arma writes the generated
    /// base DTB there for detached, out-of-band delivery and the PMI carries
    /// no bundled base.
    #[arg(long = "dtb", value_name = "attached|PATH")]
    dtb: Option<String>,

    /// Output PMI path (positional).
    #[arg(value_name = "OUTPUT")]
    output: PathBuf,
}

fn parse_module_name(value: &str) -> Result<String, String> {
    modules::validate_name(value).map_err(|e| e.to_string())?;
    Ok(value.to_owned())
}

/// Resolve `--dtb` into a channel mode and, for detached mode, the base-DTB
/// output path. `attached` is the only sentinel; any other value is a path.
fn resolve_dtb(dtb: Option<String>) -> (build::DtbMode, Option<PathBuf>) {
    match dtb {
        None => (build::DtbMode::Optional, None),
        Some(v) if v == "attached" => (build::DtbMode::Attached, None),
        Some(path) => (build::DtbMode::Detached, Some(PathBuf::from(path))),
    }
}

impl From<BuildArgs> for build::BuildArgs {
    fn from(a: BuildArgs) -> Self {
        let (dtb_mode, dtb_out) = resolve_dtb(a.dtb);
        build::BuildArgs {
            kernel_path: a.kernel,
            initrd_path: a.initrd,
            module_names: a.modules,
            module_tree: a.module_tree,
            cmdline: a.cmdline,
            profile: a.profile,
            serial: a.serial,
            output_path: a.output,
            config_path: a.config,
            mmio_slots: a.mmio_slots,
            pci_slots: a.pci_slots,
            pci_window: a.pci_window,
            min_addr_space: a.min_addr_space,
            dtb_mode,
            dtb_out,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Build(a) => build::run(&(*a).into()),
        Command::Check(a) => check::run(&a.pmi),
        Command::Cmdline(a) => cmdline::run(&a.dtb, a.cmdline.as_deref()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("arma: {e:#}");
            ExitCode::FAILURE
        }
    }
}
