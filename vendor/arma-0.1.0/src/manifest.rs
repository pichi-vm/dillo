// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PMI CBOR manifest construction.
//!
//! Builds a `pmi::vm::Spec<V>` populated with arma's chosen layout
//! and serializes it via `ciborium`. The boot vCPU register map
//! varies per arch (x86_64 long-mode entry vs aarch64 EL1h entry).

use anyhow::{Context, Result};
use ciborium::ser::into_writer;
use pmi::Version;
use pmi::cpu::Profile;
use pmi::vm::{Action, Fill, FillKind, Load, LoadKind, Spec, vcpu};

use crate::kernel::Arch;
use crate::tatu::TatuImage;

/// Names assigned to arma's own PE sections (tatu's `.tatu.*` names
/// come straight from tatu's ELF).
pub(crate) const SECTION_LINUX: &str = ".linux";
pub(crate) const SECTION_INITRD: &str = ".initrd";
/// x86 KASLR relocation table (loaded for tatu to consume at boot).
pub(crate) const SECTION_RELOCS: &str = ".linux.relocs";
// The base DTB and host-DTBO are tatu-defined sections (arma fills
// `.tatu.dtb`, dillo fills `.tatu.dtbo`).
pub(crate) const SECTION_DTB: &str = ".tatu.dtb";
pub(crate) const SECTION_DTBO: &str = ".tatu.dtbo";
/// Bundled fallback base DTB for optional mode: carried in the PE and named by
/// the [`dt:dtb`](../../pmi/spec/dt.md) attribute, but placed nowhere in guest
/// memory. The `dt:dtb` fill target (`.tatu.dtb`) receives the launch base at
/// runtime, from an out-of-band source or from this fallback.
pub(crate) const SECTION_DTB_FALLBACK: &str = ".dtb";

/// How the base DTB is delivered to the guest (`dt` extension channel modes,
/// `pmi/spec/dt.md`). arma emits the `dt:dtb` attribute and the base action per
/// the selected mode.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum DtbMode {
    /// Bundled: the base travels in `.tatu.dtb` and reaches guest memory by a
    /// `default` load; the `dt:dtb` attribute names it. No `dt:dtb` fill.
    Attached,

    /// Detached: the base is delivered out-of-band and written by a `dt:dtb`
    /// fill into the reserved `.tatu.dtb` Zero section; no `dt:dtb` attribute.
    Detached,

    /// Optional (default): a `dt:dtb` fill delivers the launch base into
    /// `.tatu.dtb`, and the `dt:dtb` attribute names the bundled fallback
    /// (`.dtb`) the VMM uses when it has no out-of-band base.
    Optional,
}

impl DtbMode {
    /// The `dt:dtb` target attribute for this mode: the PE section holding the
    /// bundled base, or `None` in detached mode (no bundled base).
    fn attribute(self) -> Option<String> {
        match self {
            DtbMode::Attached => Some(SECTION_DTB.into()),
            DtbMode::Optional => Some(SECTION_DTB_FALLBACK.into()),
            DtbMode::Detached => None,
        }
    }
}
// The boot CPU tables are tatu-defined sections (const-fn-baked into the
// tatu binary); arma reads their GPAs from the ELF for cr3 / gdtr.base.
pub(crate) const SECTION_PGTABLE: &str = ".tatu.pgt";
pub(crate) const SECTION_GDT: &str = ".tatu.gdt";

/// `IMAGE_SCN_MEM_DISCARDABLE` per the PMI spec for the non-loaded
/// target spec section.
pub(crate) const SECTION_PMI_VM: &str = ".pmi.vm";

/// The guest-physical addresses each `load`/`fill` action places its section
/// at. Per `pmi/spec/granularity.md` (commit `f6be1eb`) every action carries an
/// explicit `gpa`; the VMM places bytes there verbatim and never consults the
/// PE `VirtualAddress`. arma's placement and PE `VirtualAddress` happen to
/// coincide, but the manifest now states the GPA outright. Tatu sections and
/// the `.tatu.dtbo` fill target are linked at absolute addresses (their GPA is
/// the ELF `vaddr`); the kernel/initrd/relocs GPAs come from the planner.
#[derive(Copy, Clone)]
pub(crate) struct ActionGpas {
    pub(crate) linux: u64,
    pub(crate) initrd: Option<u64>,
    pub(crate) relocs: Option<u64>,
}

/// Build the CBOR bytes for the `.pmi.vm` section. The placement GPAs come from
/// the planner; tatu-defined sections (`.tatu.*`, including the base DTB and the
/// `.tatu.dtbo` fill target) carry their ELF `vaddr` as the explicit action GPA.
pub(crate) fn build_pmi_vm(
    arch: Arch,
    tatu: &TatuImage,
    gpas: ActionGpas,
    cpu_profile: &str,
    dtb_mode: DtbMode,
) -> Result<Vec<u8>> {
    let profile = Profile::new(cpu_profile);
    match arch {
        Arch::X86_64 => {
            let spec = build_spec_x86(tatu, gpas, profile, dtb_mode)?;
            encode(&spec)
        }
        Arch::Aarch64 => {
            let spec = build_spec_aarch64(tatu, gpas, profile, dtb_mode)?;
            encode(&spec)
        }
    }
}

#[cfg(test)]
/// PE section name carrying the target spec (`.pmi.vm`).
pub(crate) fn target_section_name() -> &'static str {
    use pmi::Target;
    <Spec<vcpu::x86_64::CpuState> as Target>::SECTION
}

fn encode<T: pmi::Target>(t: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    into_writer(t, &mut buf).context("CBOR encode of .pmi.vm spec")?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Action list builder, shared between arches.
// ---------------------------------------------------------------------------

fn build_actions(tatu: &TatuImage, gpas: ActionGpas, dtb_mode: DtbMode) -> Vec<Action> {
    let mut out = Vec::with_capacity(16);

    // Tatu sections — one load per SHF_ALLOC section, in vaddr order
    // (already sorted by parse()). Two exceptions never load: `.tatu.dtbo`
    // is the unmeasured host-DTBO fill target, and `.tatu.dtb` is the base
    // DTB fill target in detached/optional mode (a `dt:dtb` fill delivers
    // it; see below). In attached mode `.tatu.dtb` loads like the rest. The
    // x86 boot CPU tables `.tatu.pgt` / `.tatu.gdt` (const-fn-baked by tatu)
    // always load. Each tatu section is linked at an absolute address, so
    // its `vaddr` is the explicit action GPA.
    for s in &tatu.sections {
        if s.name == SECTION_DTBO {
            continue;
        }
        if s.name == SECTION_DTB && dtb_mode != DtbMode::Attached {
            continue;
        }
        out.push(Action::Load(Load {
            gpa: s.vaddr,
            section: s.name.clone(),
            kind: LoadKind::default(),
        }));
    }

    // Kernel, then optional initrd / relocs, at their planner-assigned GPAs.
    // The base DTB (`.tatu.dtb`) is loaded by the tatu-sections loop above.
    out.push(Action::Load(Load {
        gpa: gpas.linux,
        section: SECTION_LINUX.into(),
        kind: LoadKind::default(),
    }));
    if let Some(gpa) = gpas.initrd {
        out.push(Action::Load(Load {
            gpa,
            section: SECTION_INITRD.into(),
            kind: LoadKind::default(),
        }));
    }
    if let Some(gpa) = gpas.relocs {
        out.push(Action::Load(Load {
            gpa,
            section: SECTION_RELOCS.into(),
            kind: LoadKind::default(),
        }));
    }

    // Base DTB fill (detached/optional) — the VMM delivers the measured base
    // into the reserved `.tatu.dtb` Zero section, from an out-of-band source or
    // (optional) the bundled `.dtb` fallback. Attached mode loads the base
    // instead (above) and has no `dt:dtb` fill.
    if dtb_mode != DtbMode::Attached {
        let dtb_gpa = tatu.section(SECTION_DTB).map_or(0, |s| s.vaddr);
        out.push(Action::Fill(Fill {
            gpa: dtb_gpa,
            section: SECTION_DTB.into(),
            kind: FillKind::DtDtb,
        }));
    }

    // Host-DTBO fill — the unmeasured half of the dt extension. Its fill
    // target is the tatu-defined `.tatu.dtbo` section, placed at its ELF vaddr.
    let dtbo_gpa = tatu.section(SECTION_DTBO).map_or(0, |s| s.vaddr);
    out.push(Action::Fill(Fill {
        gpa: dtbo_gpa,
        section: SECTION_DTBO.into(),
        kind: FillKind::DtDtbo,
    }));

    out
}

// ---------------------------------------------------------------------------
// x86_64 vm:vcpu.
// ---------------------------------------------------------------------------

fn build_spec_x86(
    tatu: &TatuImage,
    gpas: ActionGpas,
    cpu_profile: Profile,
    dtb_mode: DtbMode,
) -> Result<Spec<vcpu::x86_64::CpuState>> {
    // cr3 / gdtr.base come straight from tatu's ELF: the boot CPU tables
    // are tatu-defined sections, not arma-allocated. arma never assumes
    // their addresses — it reads them by name from the binary.
    let pgtable_gpa = tatu
        .section(SECTION_PGTABLE)
        .with_context(|| format!("tatu x86 ELF missing `{SECTION_PGTABLE}`"))?
        .vaddr;
    let gdt_gpa = tatu
        .section(SECTION_GDT)
        .with_context(|| format!("tatu x86 ELF missing `{SECTION_GDT}`"))?
        .vaddr;
    Ok(Spec {
        version: Version::default(),
        actions: build_actions(tatu, gpas, dtb_mode),
        vcpu: x86_vcpu(pgtable_gpa, gdt_gpa)?,
        cpu_profile,
        dt_dtb: dtb_mode.attribute(),
    })
}

fn x86_vcpu(pgtable_gpa: u64, gdt_gpa: u64) -> Result<vcpu::x86_64::CpuState> {
    use vcpu::x86_64::{CpuState, Dtr, RFlags, SegAttributes, SegReg};

    // Code descriptor at selector 0x08 — must match tatu's
    // bootmem::gdt_page() (0x9B / 0xAF). Attributes
    // encode P=1, S=1, type=Code/RX, L=1, G=1.
    // vm.md segment-attribute encoding: type[0:3], S[4], DPL[5:6], P[7],
    // AVL[8], L[9], D/B[10], G[11]; bits 12-15 reserved.
    let cs_attributes: u16 = 0x0A9B; // P, S, type=0xB(code R,A), L(9), G(11)
    // Data descriptor at selector 0x10.
    let ds_attributes: u16 = 0x0C93; // P, S, type=0x3(data RW,A), D/B(10), G(11)

    Ok(CpuState {
        rip: 0xFFFF_FFF0,
        rsp: 0,
        rflags: RFlags::new(0x2)?,
        cr0: 0x8000_0001, // PG | PE
        cr3: pgtable_gpa,
        cr4: 0x20,   // PAE
        efer: 0x500, // LME | LMA
        cs: SegReg {
            selector: 0x08,
            attributes: SegAttributes::new(cs_attributes)?,
            limit: 0xFFFF_FFFF,
            base: 0,
        },
        ds: data_seg(0x10, ds_attributes)?,
        es: data_seg(0x10, ds_attributes)?,
        fs: data_seg(0x10, ds_attributes)?,
        gs: data_seg(0x10, ds_attributes)?,
        ss: data_seg(0x10, ds_attributes)?,
        gdtr: Dtr {
            limit: 0x17, // 3 entries × 8 bytes - 1
            base: gdt_gpa,
        },
        idtr: Dtr { limit: 0, base: 0 },
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rbp: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
    })
}

fn data_seg(selector: u16, attributes: u16) -> Result<vcpu::x86_64::SegReg> {
    Ok(vcpu::x86_64::SegReg {
        selector,
        attributes: vcpu::x86_64::SegAttributes::new(attributes)?,
        limit: 0xFFFF_FFFF,
        base: 0,
    })
}

// ---------------------------------------------------------------------------
// aarch64 vm:vcpu.
// ---------------------------------------------------------------------------

fn build_spec_aarch64(
    tatu: &TatuImage,
    gpas: ActionGpas,
    cpu_profile: Profile,
    dtb_mode: DtbMode,
) -> Result<Spec<vcpu::aarch64::CpuState>> {
    Ok(Spec {
        version: Version::default(),
        actions: build_actions(tatu, gpas, dtb_mode),
        vcpu: aarch64_vcpu(tatu.entry)?,
        cpu_profile,
        dt_dtb: dtb_mode.attribute(),
    })
}

fn aarch64_vcpu(pc: u64) -> Result<vcpu::aarch64::CpuState> {
    use vcpu::aarch64::{CpuState, PState};

    Ok(CpuState {
        pc,
        pstate: PState::new(0x3C5)?, // EL1h, DAIF masked
        sctlr_el1: 0x00C5_0838,      // typical reset; MMU off, caches off
        // MMU is off at entry, so the translation/attribute registers are
        // zero; tatu programs them itself.
        tcr_el1: 0,
        ttbr0_el1: 0,
        ttbr1_el1: 0,
        mair_el1: 0,
        vbar_el1: 0,
        // FPEN=0b11 (bits 21:20): enable FP/SIMD at EL1/EL0 from reset.
        // The bare-metal tatu (and compiler-emitted memcpy/SIMD) uses FP
        // registers; leaving CPACR_EL1=0 traps the first such access to the
        // (zero) EL1 vector. Boot with FP/SIMD enabled.
        cpacr_el1: 0x30_0000,
        // sp_el1 = 0 (tatu's entry stub sets SP itself); all GPRs zeroed.
        sp_el1: 0,
        x0: 0,
        x1: 0,
        x2: 0,
        x3: 0,
        x4: 0,
        x5: 0,
        x6: 0,
        x7: 0,
        x8: 0,
        x9: 0,
        x10: 0,
        x11: 0,
        x12: 0,
        x13: 0,
        x14: 0,
        x15: 0,
        x16: 0,
        x17: 0,
        x18: 0,
        x19: 0,
        x20: 0,
        x21: 0,
        x22: 0,
        x23: 0,
        x24: 0,
        x25: 0,
        x26: 0,
        x27: 0,
        x28: 0,
        x29: 0,
        x30: 0,
    })
}

// Quiet warnings about unused fields/imports — pmi's Default is enough.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tatu::parse as parse_tatu;
    use ciborium::de::from_reader;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn x86_manifest_round_trips_via_strict_decoder() {
        use crate::TATU_X86_64;
        let tatu = parse_tatu(TATU_X86_64, Arch::X86_64).unwrap();
        let gpas = ActionGpas {
            linux: 0x20_0000,
            initrd: Some(0x100_0000),
            relocs: Some(0x200_0000),
        };
        let cbor = build_pmi_vm(Arch::X86_64, &tatu, gpas, "x86-64-v3", DtbMode::Attached).unwrap();
        let decoded: Spec<vcpu::x86_64::CpuState> =
            from_reader(cbor.as_slice()).expect("strict round-trip decode");
        assert_eq!(decoded.vcpu.rip, 0xFFFF_FFF0);
        // The kernel load carries its explicit planner GPA.
        let linux_gpa = decoded.actions.iter().find_map(|a| match a {
            Action::Load(l) if l.section == SECTION_LINUX => Some(l.gpa),
            _ => None,
        });
        assert_eq!(linux_gpa, Some(0x20_0000));
        // cr3 / gdtr.base must equal the tatu ELF's boot-CPU-table GPAs.
        let pgt = tatu
            .section(SECTION_PGTABLE)
            .expect(".tatu.pgt in tatu ELF");
        let gdt = tatu.section(SECTION_GDT).expect(".tatu.gdt in tatu ELF");
        assert_eq!(decoded.vcpu.cr3, pgt.vaddr);
        assert_eq!(decoded.vcpu.gdtr.base, gdt.vaddr);
        assert!(matches!(decoded.dt_dtb, Some(s) if s == ".tatu.dtb"));
        // Last action must be the fill for .dtbo.
        let last = decoded.actions.last().unwrap();
        match last {
            Action::Fill(f) => {
                assert_eq!(f.section, SECTION_DTBO);
                assert!(matches!(f.kind, pmi::vm::FillKind::DtDtbo));
            }
            Action::Load(_) => panic!("last action must be Fill"),
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn aarch64_manifest_pc_matches_tatu_entry() {
        use crate::TATU_AARCH64;
        let tatu = parse_tatu(TATU_AARCH64, Arch::Aarch64).unwrap();
        let gpas = ActionGpas {
            linux: 0x20_0000,
            initrd: None,
            relocs: None,
        };
        let cbor =
            build_pmi_vm(Arch::Aarch64, &tatu, gpas, "armv8.2-a", DtbMode::Optional).unwrap();
        let decoded: Spec<vcpu::aarch64::CpuState> =
            from_reader(cbor.as_slice()).expect("strict round-trip decode");
        assert_eq!(decoded.vcpu.pc, tatu.entry);
        assert_eq!(decoded.vcpu.pstate.get() & 0xF, 0x5); // EL1h
        assert_eq!((decoded.vcpu.pstate.get() >> 4) & 1, 0); // AArch64
    }

    #[test]
    fn target_section_name_is_pmi_vm() {
        assert_eq!(target_section_name(), SECTION_PMI_VM);
    }

    #[cfg(target_arch = "x86_64")]
    fn actions_of(mode: DtbMode) -> (Option<String>, Vec<Action>) {
        use crate::TATU_X86_64;
        let tatu = parse_tatu(TATU_X86_64, Arch::X86_64).unwrap();
        let gpas = ActionGpas {
            linux: 0x20_0000,
            initrd: None,
            relocs: None,
        };
        let cbor = build_pmi_vm(Arch::X86_64, &tatu, gpas, "x86-64-v3", mode).unwrap();
        let decoded: Spec<vcpu::x86_64::CpuState> = from_reader(cbor.as_slice()).unwrap();
        (decoded.dt_dtb, decoded.actions)
    }

    #[cfg(target_arch = "x86_64")]
    fn base_action(actions: &[Action]) -> Option<(&'static str, Option<FillKind>)> {
        actions.iter().find_map(|a| match a {
            Action::Load(l) if l.section == SECTION_DTB => Some(("load", None)),
            Action::Fill(f) if f.section == SECTION_DTB => Some(("fill", Some(f.kind))),
            _ => None,
        })
    }

    // Each channel mode emits the base-DTB action and `dt:dtb` attribute the
    // dt extension prescribes (pmi/spec/dt.md, VMM selection table).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attached_loads_base_and_names_it() {
        let (attr, actions) = actions_of(DtbMode::Attached);
        assert_eq!(attr.as_deref(), Some(SECTION_DTB)); // ".tatu.dtb"
        assert_eq!(base_action(&actions), Some(("load", None)));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn optional_fills_base_and_names_fallback() {
        let (attr, actions) = actions_of(DtbMode::Optional);
        assert_eq!(attr.as_deref(), Some(SECTION_DTB_FALLBACK)); // ".dtb"
        assert_eq!(base_action(&actions), Some(("fill", Some(FillKind::DtDtb))));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn detached_fills_base_with_no_attribute() {
        let (attr, actions) = actions_of(DtbMode::Detached);
        assert_eq!(attr, None);
        assert_eq!(base_action(&actions), Some(("fill", Some(FillKind::DtDtb))));
    }
}
