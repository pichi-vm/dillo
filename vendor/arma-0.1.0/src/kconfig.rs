// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Kernel `.config` parsing + transport support / slot inference
//! (device-model.md §6 "Slot composition").
//!
//! A consumer of the kernel's build config: Arma reads which device
//! transports the kernel can drive and sizes the board's slot capacity
//! accordingly. It never presumes — a guest with no drivable transport is
//! rejected rather than shipped unusable.

use std::io::Read;

use thiserror::Error;

use crate::kernel::Arch;

/// A parsed kernel build config (text Kconfig — `CONFIG_x=y/m` / `# … is not
/// set` lines). Held verbatim; symbols are matched on demand.
#[derive(Debug)]
pub(crate) struct KernelConfig {
    text: String,
}

#[derive(Debug, Error)]
pub(crate) enum SlotError {
    #[error(
        "kernel supports neither virtio-mmio nor PCI \
         (no CONFIG_VIRTIO_MMIO, and no CONFIG_PCI+CONFIG_VIRTIO_PCI); \
         a guest with no device-attach surface cannot be used"
    )]
    NoTransport,

    #[error("--mmio-slots requested but the kernel lacks CONFIG_VIRTIO_MMIO")]
    MmioUnsupported,

    #[error(
        "the kernel builds no virtio transport in — a default board needs \
         built-in virtio-mmio (CONFIG_VIRTIO_MMIO=y) or virtio-pci \
         (CONFIG_PCI + CONFIG_VIRTIO_PCI=y, plus CONFIG_PCI_HOST_GENERIC=y on \
         aarch64). This kernel has a transport only as a module, which has no \
         attach surface until it is loaded. Pass --mmio-slots/--pci-slots \
         explicitly if the guest loads the transport module early (e.g. from \
         its initramfs)"
    )]
    NoBuiltinTransport,

    #[error(
        "--pci-slots requested but the kernel lacks PCI support \
         (needs CONFIG_PCI + CONFIG_VIRTIO_PCI, plus CONFIG_PCI_HOST_GENERIC on aarch64)"
    )]
    PciUnsupported,
}

/// How the guest kernel can drive the poweroff device Arma places in the
/// base DTB — the per-arch answer to "will `poweroff` actually stop the VM?".
/// Mirrors the node choice in [`crate::base_dtb`]: `/psci` on aarch64,
/// `syscon-poweroff` on x86.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoweroffSupport {
    /// aarch64: PSCI `SYSTEM_OFF` (the `/psci` node), handled by the VMM's
    /// SMC/HVC trap.
    Psci,

    /// x86: ACPI S5. tatu lowers the `syscon-poweroff` node into the FADT
    /// sleep register + DSDT `_S5`; the guest's ACPI writes it and the VMM's
    /// syscon device traps the write.
    Acpi,

    /// The kernel's own `syscon-poweroff` DT driver writes the register
    /// directly, with no ACPI (the embedded path).
    SysconDriver,

    /// The kernel can drive none of the emitted poweroff devices — `poweroff`
    /// will not stop the VM.
    Unsupported,
}

#[derive(Debug, Error)]
#[error("selected module {path} requires {option}=y")]
pub(crate) struct ModuleConfigError {
    path: std::path::PathBuf,
    option: &'static str,
}

impl KernelConfig {
    /// Corium passes compressed module bytes directly to `finit_module`.
    /// All decompression facilities must therefore be built in, not modules.
    pub(crate) fn check_module(&self, path: &std::path::Path) -> Result<(), ModuleConfigError> {
        let require = |option| {
            if self.is_builtin(option) {
                Ok(())
            } else {
                Err(ModuleConfigError {
                    path: path.to_owned(),
                    option,
                })
            }
        };
        require("CONFIG_MODULES")?;
        let compression = match path.extension().and_then(|ext| ext.to_str()) {
            Some("xz") => Some("CONFIG_MODULE_COMPRESS_XZ"),
            Some("gz") => Some("CONFIG_MODULE_COMPRESS_GZIP"),
            Some("zst") => Some("CONFIG_MODULE_COMPRESS_ZSTD"),
            _ => None,
        };
        if let Some(option) = compression {
            require("CONFIG_MODULE_DECOMPRESS")?;
            require(option)?;
        }
        Ok(())
    }

    pub(crate) fn parse(text: String) -> Self {
        Self { text }
    }

    /// C5: extract the kernel's embedded build config (`CONFIG_IKCONFIG`) — a
    /// gzip blob bracketed by `IKCFG_ST`/`IKCFG_ED` in the (decompressed)
    /// kernel image. Returns `None` if the kernel carries no embedded config.
    pub(crate) fn from_ikconfig(kernel: &[u8]) -> Option<Self> {
        const ST: &[u8] = b"IKCFG_ST";
        const ED: &[u8] = b"IKCFG_ED";
        let start = kernel.windows(ST.len()).position(|w| w == ST)? + ST.len();
        let end = start + kernel[start..].windows(ED.len()).position(|w| w == ED)?;
        let mut text = String::new();
        flate2::read::GzDecoder::new(&kernel[start..end])
            .read_to_string(&mut text)
            .ok()?;
        Some(Self::parse(text))
    }

    /// True iff `CONFIG_<sym>` is set to `y` or `m` (built-in or module).
    fn is_set(&self, sym: &str) -> bool {
        self.text.lines().any(|line| {
            line.trim_start()
                .strip_prefix(sym)
                .and_then(|rest| rest.strip_prefix('='))
                .is_some_and(|v| v == "y" || v == "m")
        })
    }

    /// True iff `CONFIG_<sym>=y` (built into the kernel — excludes `=m`).
    fn is_builtin(&self, sym: &str) -> bool {
        self.text.lines().any(|line| {
            line.trim_start()
                .strip_prefix(sym)
                .and_then(|rest| rest.strip_prefix('='))
                .is_some_and(|v| v == "y")
        })
    }

    /// The kernel's ISA build floor (C2 clamp) — the lowest `--profile` the
    /// kernel can run on. Upstream Kconfig carries no clean x86-64 microarch
    /// symbol (it's a distro `-march` build flag), and aarch64 ISA features are
    /// runtime-detected via alternatives, so for stock kernels the floor is the
    /// architecture baseline; a distro that marks a higher level
    /// (`CONFIG_X86_64_V{2,3,4}`) raises it. Conservative by design — it never
    /// reports a floor the kernel doesn't actually require.
    pub(crate) fn isa_floor(&self, arch: Arch) -> &'static str {
        match arch {
            Arch::X86_64 => {
                if self.is_set("CONFIG_X86_64_V4") {
                    "x86-64-v4"
                } else if self.is_set("CONFIG_X86_64_V3") {
                    "x86-64-v3"
                } else if self.is_set("CONFIG_X86_64_V2") {
                    "x86-64-v2"
                } else {
                    "x86-64-v1" // the x86-64 baseline
                }
            }
            // aarch64 features (LSE, PAN, MTE, …) are optional/runtime-detected,
            // not a build-time floor, so stock kernels require only v8.0-a.
            Arch::Aarch64 => "armv8.0-a",
        }
    }

    /// The kernel can drive virtio-mmio at all (built-in *or* module). Used to
    /// validate an explicit `--mmio-slots`, where the operator vouches that the
    /// module will be loaded before the devices are needed.
    fn supports_virtio_mmio(&self) -> bool {
        self.is_set("CONFIG_VIRTIO_MMIO")
    }

    /// virtio-mmio is built into the kernel (`=y`). Only a built-in transport
    /// has an attach surface from the first instruction, so this — not mere
    /// support — gates whether a *default* board emits virtio-mmio slots.
    fn builtin_virtio_mmio(&self) -> bool {
        self.is_builtin("CONFIG_VIRTIO_MMIO")
    }

    /// The kernel can drive virtio over PCI at all (built-in *or* module):
    /// `CONFIG_PCI` + `CONFIG_VIRTIO_PCI` (and, on aarch64, the ECAM host driver
    /// `CONFIG_PCI_HOST_GENERIC`). On x86 base config reaches the bridge through
    /// the architectural `0xcf8`/`0xcfc` ports regardless. Used to validate an
    /// explicit `--pci-slots`.
    fn supports_pci(&self, arch: Arch) -> bool {
        self.is_set("CONFIG_PCI")
            && self.is_set("CONFIG_VIRTIO_PCI")
            && (!matches!(arch, Arch::Aarch64) || self.is_set("CONFIG_PCI_HOST_GENERIC"))
    }

    /// virtio-over-PCI is usable from the first instruction — every piece is
    /// built in (`=y`), not a module. Like [`builtin_virtio_mmio`], this — not
    /// mere support — gates whether a *default* board emits a PCIe bridge: a
    /// modular virtio-pci (or, on aarch64, a modular ECAM host driver) leaves
    /// the bridge with no attach surface until the module loads.
    fn builtin_pci(&self, arch: Arch) -> bool {
        self.is_builtin("CONFIG_PCI")
            && self.is_builtin("CONFIG_VIRTIO_PCI")
            && (!matches!(arch, Arch::Aarch64) || self.is_builtin("CONFIG_PCI_HOST_GENERIC"))
    }

    /// Detect how the guest will drive the poweroff device Arma emits into the
    /// base DTB. Arma always places the arch-appropriate device (`/psci` on
    /// aarch64, `syscon-poweroff` on x86); this reports whether *this* kernel
    /// can actually consume it, so the build can warn when a guest would hang
    /// on `poweroff` instead of exiting the VM.
    ///
    /// On x86 the one `syscon-poweroff` node is reachable two ways: through
    /// ACPI (tatu lowers it into the FADT — the distro path, `CONFIG_ACPI`) or
    /// through the kernel's own syscon DT driver
    /// (`CONFIG_POWER_RESET_SYSCON_POWEROFF` — the embedded path). ACPI is
    /// preferred when both are present. On aarch64 the mechanism is PSCI
    /// (`CONFIG_ARM_PSCI_FW`), which stock arm64 kernels always build.
    pub(crate) fn poweroff_support(&self, arch: Arch) -> PoweroffSupport {
        match arch {
            Arch::Aarch64 => {
                if self.is_set("CONFIG_ARM_PSCI_FW") || self.is_set("CONFIG_ARM_PSCI") {
                    PoweroffSupport::Psci
                } else {
                    PoweroffSupport::Unsupported
                }
            }
            Arch::X86_64 => {
                if self.is_set("CONFIG_ACPI") {
                    PoweroffSupport::Acpi
                } else if self.is_set("CONFIG_POWER_RESET_SYSCON_POWEROFF") {
                    PoweroffSupport::SysconDriver
                } else {
                    PoweroffSupport::Unsupported
                }
            }
        }
    }

    /// Resolve `(mmio_slots, pci_slots)` per §6 Slot composition:
    ///
    /// - **Neither given** — 16 total, split across the transports the kernel
    ///   can use *without loading a module* — built-in virtio-mmio and/or
    ///   built-in virtio-pci (8/8 if both, else all 16 to the single one). A
    ///   transport built only as a module is deliberately excluded: it has no
    ///   attach surface until the guest loads it, so its default slots (or PCIe
    ///   bridge) would only be probed and rejected at boot. A kernel whose only
    ///   transports are modular has no default board
    ///   ([`SlotError::NoBuiltinTransport`]).
    /// - **Either given** — exactly what was asked (a missing flag is `0`),
    ///   failing if asked to declare a transport the kernel can't drive.
    ///   Explicit slots accept a modular transport: the operator vouches the
    ///   module is loaded before those devices are used.
    ///
    /// Either way, fail if the kernel supports neither transport at all.
    pub(crate) fn infer_slots(
        &self,
        arch: Arch,
        mmio_override: Option<u32>,
        pci_override: Option<u32>,
    ) -> Result<(u32, u32), SlotError> {
        let mmio_drivable = self.supports_virtio_mmio(); // =y or =m
        let mmio_builtin = self.builtin_virtio_mmio(); // =y only
        let pci_drivable = self.supports_pci(arch); // =y or =m
        let pci_builtin = self.builtin_pci(arch); // =y only
        if !mmio_drivable && !pci_drivable {
            return Err(SlotError::NoTransport);
        }

        match (mmio_override, pci_override) {
            // Default board: emit slots only for transports usable from the
            // first instruction. A transport that is drivable but built as a
            // module earns no default slots; route to whichever transport IS
            // built in, and reject a kernel whose transports are all modular.
            (None, None) => match (mmio_builtin, pci_builtin) {
                (true, true) => Ok((8, 8)),
                (true, false) => Ok((16, 0)),
                (false, true) => Ok((0, 16)),
                (false, false) => Err(SlotError::NoBuiltinTransport),
            },
            (m, p) => {
                let mmio = m.unwrap_or(0);
                let pci = p.unwrap_or(0);
                if mmio > 0 && !mmio_drivable {
                    return Err(SlotError::MmioUnsupported);
                }
                if pci > 0 && !pci_drivable {
                    return Err(SlotError::PciUnsupported);
                }
                Ok((mmio, pci))
            }
        }
    }
}

/// The ordered ISA levels for an arch (ascending), used to compare profiles.
fn isa_levels(arch: Arch) -> &'static [&'static str] {
    match arch {
        Arch::X86_64 => &["x86-64-v1", "x86-64-v2", "x86-64-v3", "x86-64-v4"],
        Arch::Aarch64 => &[
            "armv8.0-a",
            "armv8.1-a",
            "armv8.2-a",
            "armv8.3-a",
            "armv8.4-a",
            "armv8.5-a",
            "armv8.6-a",
        ],
    }
}

/// C2 clamp: raise `chosen` up to `floor` if the kernel's build floor is higher
/// — the emitted `cpu:profile` must not sit below what the kernel requires.
/// An explicit profile arma doesn't recognize is left exactly as set (the
/// operator may have a vocabulary arma doesn't model).
pub(crate) fn raise_to_floor(chosen: &str, floor: &str, arch: Arch) -> String {
    let levels = isa_levels(arch);
    let rank = |p: &str| levels.iter().position(|&l| l == p);
    match (rank(chosen), rank(floor)) {
        (Some(c), Some(f)) if f > c => floor.to_string(),
        _ => chosen.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_module_compression_requires_builtin_kernel_support() {
        let none = KernelConfig::parse(String::new());
        assert!(none.check_module(std::path::Path::new("test.ko")).is_err());
        let modules = KernelConfig::parse("CONFIG_MODULES=y\n".to_owned());
        assert!(
            modules
                .check_module(std::path::Path::new("test.ko"))
                .is_ok()
        );
        assert!(
            modules
                .check_module(std::path::Path::new("test.ko.zst"))
                .is_err()
        );
        for (suffix, symbol) in [("xz", "XZ"), ("gz", "GZIP"), ("zst", "ZSTD")] {
            let cfg = KernelConfig::parse(format!(
                "CONFIG_MODULES=y\nCONFIG_MODULE_DECOMPRESS=y\nCONFIG_MODULE_COMPRESS_{symbol}=y\n"
            ));
            assert!(
                cfg.check_module(std::path::Path::new(&format!("test.ko.{suffix}")))
                    .is_ok()
            );
            let modular = KernelConfig::parse(format!(
                "CONFIG_MODULES=y\nCONFIG_MODULE_DECOMPRESS=y\nCONFIG_MODULE_COMPRESS_{symbol}=m\n"
            ));
            assert!(
                modular
                    .check_module(std::path::Path::new(&format!("test.ko.{suffix}")))
                    .is_err()
            );
        }
    }

    fn cfg(s: &str) -> KernelConfig {
        KernelConfig::parse(s.to_string())
    }

    #[test]
    fn is_set_exact_and_module() {
        let c = cfg("CONFIG_PCI=y\nCONFIG_VIRTIO_MMIO=m\n# CONFIG_FOO is not set\n");
        assert!(c.is_set("CONFIG_PCI"));
        assert!(c.is_set("CONFIG_VIRTIO_MMIO")); // =m counts
        assert!(!c.is_set("CONFIG_FOO")); // "is not set"
        assert!(!c.is_set("CONFIG_PC")); // not a prefix match
        // is_builtin is stricter: =y only, never =m.
        assert!(c.is_builtin("CONFIG_PCI")); // =y
        assert!(!c.is_builtin("CONFIG_VIRTIO_MMIO")); // =m is not built-in
    }

    #[test]
    fn both_builtin_transports_split_8_8() {
        // Both transports built in: split evenly.
        let c = cfg(
            "CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_PCI_HOST_GENERIC=y\nCONFIG_VIRTIO_MMIO=y\n",
        );
        assert_eq!(c.infer_slots(Arch::Aarch64, None, None).unwrap(), (8, 8));
    }

    #[test]
    fn modular_mmio_not_emitted_by_default() {
        // Fedora-like: virtio-mmio is a module, PCI is built in. A default board
        // must route everything to PCI and emit NO (empty, boot-probed) mmio
        // slots — the module has no attach surface until the guest loads it.
        let c = cfg("CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_MMIO=m\n");
        assert_eq!(c.infer_slots(Arch::X86_64, None, None).unwrap(), (0, 16));
        // An explicit request is still honored (the guest loads the module).
        assert_eq!(c.infer_slots(Arch::X86_64, Some(2), None).unwrap(), (2, 0));
    }

    #[test]
    fn modular_virtio_pci_not_emitted_by_default() {
        // virtio-pci is a module, virtio-mmio is built in: the default board
        // must route to mmio and emit no (useless) PCIe bridge.
        let c = cfg("CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=m\nCONFIG_VIRTIO_MMIO=y\n");
        assert_eq!(c.infer_slots(Arch::X86_64, None, None).unwrap(), (16, 0));
        // Explicit --pci-slots still honored (guest loads virtio_pci early).
        assert_eq!(c.infer_slots(Arch::X86_64, None, Some(2)).unwrap(), (0, 2));
    }

    #[test]
    fn aarch64_modular_host_generic_not_builtin_pci() {
        // aarch64 with a modular ECAM host driver: PCI is drivable (module) but
        // not built-in, so it earns no default bridge; mmio (built in) takes all.
        let c = cfg(
            "CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_PCI_HOST_GENERIC=m\nCONFIG_VIRTIO_MMIO=y\n",
        );
        assert_eq!(c.infer_slots(Arch::Aarch64, None, None).unwrap(), (16, 0));
        // Explicit --pci-slots honored (the host driver loads early).
        assert_eq!(c.infer_slots(Arch::Aarch64, None, Some(4)).unwrap(), (0, 4));
    }

    #[test]
    fn all_modular_transports_have_no_default_board() {
        // Every transport is a module: no default board is possible, but each
        // explicit opt-in works (the operator vouches for early module load).
        let c = cfg("CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=m\nCONFIG_VIRTIO_MMIO=m\n");
        assert!(matches!(
            c.infer_slots(Arch::X86_64, None, None),
            Err(SlotError::NoBuiltinTransport)
        ));
        assert_eq!(c.infer_slots(Arch::X86_64, Some(4), None).unwrap(), (4, 0));
        assert_eq!(c.infer_slots(Arch::X86_64, None, Some(4)).unwrap(), (0, 4));
    }

    #[test]
    fn no_pci_all_to_mmio() {
        // Firecracker-like: no PCI, virtio-mmio only.
        let c = cfg("# CONFIG_PCI is not set\nCONFIG_VIRTIO_MMIO=y\n");
        assert_eq!(c.infer_slots(Arch::Aarch64, None, None).unwrap(), (16, 0));
    }

    #[test]
    fn aarch64_needs_host_generic_for_pci() {
        // PCI + virtio-pci but no ECAM host driver ⇒ not drivable on aarch64.
        let c = cfg("CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_MMIO=y\n");
        assert_eq!(c.infer_slots(Arch::Aarch64, None, None).unwrap(), (16, 0));
        // x86 needs no host-generic driver (cf8/cfc base config).
        assert_eq!(c.infer_slots(Arch::X86_64, None, None).unwrap(), (8, 8));
    }

    #[test]
    fn neither_transport_is_rejected() {
        let c = cfg("# CONFIG_PCI is not set\n# CONFIG_VIRTIO_MMIO is not set\n");
        assert!(matches!(
            c.infer_slots(Arch::Aarch64, None, None),
            Err(SlotError::NoTransport)
        ));
    }

    #[test]
    fn explicit_slots_honored_and_checked() {
        let c = cfg("# CONFIG_PCI is not set\nCONFIG_VIRTIO_MMIO=y\n");
        // Explicit mmio honored; pci omitted (None ⇒ 0).
        assert_eq!(c.infer_slots(Arch::Aarch64, Some(4), None).unwrap(), (4, 0));
        // Asking for PCI the kernel can't drive ⇒ error.
        assert!(matches!(
            c.infer_slots(Arch::Aarch64, None, Some(4)),
            Err(SlotError::PciUnsupported)
        ));
    }

    #[test]
    fn x86_poweroff_prefers_acpi() {
        // Both ACPI and the DT driver present: ACPI wins (the distro path).
        let c = cfg("CONFIG_ACPI=y\nCONFIG_POWER_RESET_SYSCON_POWEROFF=y\n");
        assert_eq!(c.poweroff_support(Arch::X86_64), PoweroffSupport::Acpi);
    }

    #[test]
    fn x86_poweroff_falls_back_to_syscon_driver() {
        // No ACPI, but the kernel builds its own syscon-poweroff driver.
        let c = cfg("# CONFIG_ACPI is not set\nCONFIG_POWER_RESET_SYSCON_POWEROFF=m\n");
        assert_eq!(
            c.poweroff_support(Arch::X86_64),
            PoweroffSupport::SysconDriver
        );
    }

    #[test]
    fn x86_poweroff_unsupported_when_neither() {
        // The Fedora-x86-without-ACPI trap: neither mechanism → the guest hangs.
        let c = cfg("# CONFIG_ACPI is not set\n");
        assert_eq!(
            c.poweroff_support(Arch::X86_64),
            PoweroffSupport::Unsupported
        );
    }

    #[test]
    fn aarch64_poweroff_is_psci() {
        let c = cfg("CONFIG_ARM_PSCI_FW=y\n");
        assert_eq!(c.poweroff_support(Arch::Aarch64), PoweroffSupport::Psci);
    }

    #[test]
    fn aarch64_poweroff_unsupported_without_psci() {
        // ACPI on aarch64 does not help — Arma emits `/psci` there, not syscon.
        let c = cfg("CONFIG_ACPI=y\n");
        assert_eq!(
            c.poweroff_support(Arch::Aarch64),
            PoweroffSupport::Unsupported
        );
    }

    #[test]
    fn from_ikconfig_extracts_embedded_config() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        e.write_all(b"CONFIG_PCI=y\nCONFIG_VIRTIO_MMIO=y\n")
            .unwrap();
        let gz = e.finish().unwrap();
        // Embed between markers with junk on both sides (as in a real image).
        let mut kernel = vec![0xABu8; 64];
        kernel.extend_from_slice(b"IKCFG_ST");
        kernel.extend_from_slice(&gz);
        kernel.extend_from_slice(b"IKCFG_ED");
        kernel.extend_from_slice(&[0xCDu8; 32]);

        let c = KernelConfig::from_ikconfig(&kernel).expect("extract IKCONFIG");
        assert!(c.is_set("CONFIG_PCI"));
        assert!(c.is_set("CONFIG_VIRTIO_MMIO"));
        // A kernel without the markers yields None (caller errors / asks for --config).
        assert!(KernelConfig::from_ikconfig(b"no ikconfig here").is_none());
    }

    #[test]
    fn isa_floor_and_clamp() {
        // x86: no marker ⇒ baseline v1 floor; the v2 default is not lowered.
        let c = cfg("CONFIG_PCI=y\n");
        assert_eq!(c.isa_floor(Arch::X86_64), "x86-64-v1");
        assert_eq!(
            raise_to_floor("x86-64-v2", c.isa_floor(Arch::X86_64), Arch::X86_64),
            "x86-64-v2"
        );
        // x86: a v3-marked kernel raises the v2 default to v3 (the clamp).
        let c3 = cfg("CONFIG_X86_64_V3=y\n");
        assert_eq!(c3.isa_floor(Arch::X86_64), "x86-64-v3");
        assert_eq!(
            raise_to_floor("x86-64-v2", c3.isa_floor(Arch::X86_64), Arch::X86_64),
            "x86-64-v3"
        );
        // An explicit higher profile is kept (operator may require more).
        assert_eq!(
            raise_to_floor("x86-64-v4", "x86-64-v2", Arch::X86_64),
            "x86-64-v4"
        );
        // aarch64 stock floor is the baseline; default stays.
        let a = cfg("CONFIG_ARM64_LSE_ATOMICS=y\n");
        assert_eq!(a.isa_floor(Arch::Aarch64), "armv8.0-a");
        // An unrecognized explicit profile is passed through unchanged.
        assert_eq!(
            raise_to_floor("vendor-custom", "x86-64-v3", Arch::X86_64),
            "vendor-custom"
        );
    }
}
