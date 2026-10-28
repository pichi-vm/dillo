// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tatu ELF ingest: parse tatu's per-arch ELF and materialize one
//! PE-section image per `SHF_ALLOC` ELF section.
//!
//! Tatu's binary is opaque to arma — arma reads only the section
//! table (for placement) and the ELF header's `e_entry` (for the
//! boot vCPU's entry point). Tatu's symbol table is not consulted.

use core::ops::Range;

use goblin::elf::{
    Elf,
    section_header::{SHF_ALLOC, SHT_NOBITS, SHT_PROGBITS},
};
use thiserror::Error;

use crate::kernel::Arch;

/// A single ELF section materialized for PE emission.
#[derive(Debug, Clone)]
pub(crate) struct TatuSection {
    /// Section name (e.g., `.tatu.text`, `.tatu.bootinfo`).
    pub(crate) name: String,
    /// Absolute load address resolved by tatu's linker.
    pub(crate) vaddr: u64,
    /// On-disk bytes for `SHT_PROGBITS`; empty for `SHT_NOBITS`.
    pub(crate) data: Vec<u8>,
    /// In-memory size. Equals `data.len()` for PROGBITS; may exceed
    /// it for NOBITS (BSS) sections.
    pub(crate) virtual_size: u64,
    /// `true` when this is a NOBITS (Zero-shape PE) section.
    pub(crate) is_nobits: bool,
    /// `true` for the `.tatu.bootinfo` section (which arma must
    /// override with computed bytes before emission).
    pub(crate) is_bootinfo: bool,
    /// `true` for the `.tatu.dtb` section (which arma fills with the
    /// measured base DTB bytes before emission, like `.tatu.bootinfo`).
    pub(crate) is_dtb: bool,
}

/// Parsed tatu ELF: the SHF_ALLOC sections to emit and the entry GPA.
///
/// tatu loads at its linked addresses (it is the immovable part of the
/// guest-physical map); [`TatuImage::reserved`] yields its section ranges
/// so the [`crate::planner`] places the kernel/initrd/devices around it.
#[derive(Debug)]
pub(crate) struct TatuImage {
    pub(crate) sections: Vec<TatuSection>,
    pub(crate) entry: u64,
}

impl TatuImage {
    /// Find a parsed section by exact name (e.g. `.tatu.pgt`). arma uses
    /// this to read tatu-defined sections' GPAs from the binary rather
    /// than recomputing them (the boot CPU tables, base DTB, etc.).
    pub(crate) fn section(&self, name: &str) -> Option<&TatuSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// tatu's immovable carve-outs: every allocated section as a GPA range
    /// (including the x86 reset stub at `0xFFFF_F000`). Fed to the planner
    /// as part of its `reserved` set.
    pub(crate) fn reserved(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.sections
            .iter()
            .map(|s| s.vaddr..s.vaddr + s.virtual_size)
    }
}

#[derive(Debug, Error)]
pub(crate) enum TatuError {
    #[error("failed to parse tatu ELF")]
    Parse(#[from] goblin::error::Error),
    #[error("tatu ELF e_machine = {0:#06x} does not match expected arch {1:#06x}")]
    WrongArch(u16, u16),
    #[error("tatu section `{0}` extends past end of ELF file")]
    TruncatedSection(String),
    #[error("tatu ELF missing required section `{0}`")]
    MissingSection(&'static str),
}

const ELF_MACHINE_X86_64: u16 = 0x3E; // EM_X86_64
const ELF_MACHINE_AARCH64: u16 = 0xB7; // EM_AARCH64

const BOOTINFO_SECTION: &str = ".tatu.bootinfo";
const DTB_SECTION: &str = ".tatu.dtb";

/// Parse and validate a tatu ELF for the given target arch.
pub(crate) fn parse(bytes: &[u8], arch: Arch) -> Result<TatuImage, TatuError> {
    let elf = Elf::parse(bytes)?;

    let expected_machine = match arch {
        Arch::X86_64 => ELF_MACHINE_X86_64,
        Arch::Aarch64 => ELF_MACHINE_AARCH64,
    };
    if elf.header.e_machine != expected_machine {
        return Err(TatuError::WrongArch(elf.header.e_machine, expected_machine));
    }

    let mut sections = Vec::new();
    let mut saw_bootinfo = false;

    for sh in &elf.section_headers {
        if sh.sh_flags & u64::from(SHF_ALLOC) == 0 {
            continue;
        }
        // Some toolchains emit zero-sized SHF_ALLOC sections (e.g.,
        // alignment padding); skip them — there's nothing to load.
        if sh.sh_size == 0 {
            continue;
        }

        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("<unnamed>")
            .to_string();

        let is_nobits = sh.sh_type == SHT_NOBITS;
        let is_progbits = sh.sh_type == SHT_PROGBITS;
        if !is_nobits && !is_progbits {
            // Skip other allocated section types (none expected from tatu's linker).
            continue;
        }

        let data = if is_progbits {
            let start = sh.sh_offset as usize;
            let end = start
                .checked_add(sh.sh_size as usize)
                .ok_or_else(|| TatuError::TruncatedSection(name.clone()))?;
            if end > bytes.len() {
                return Err(TatuError::TruncatedSection(name.clone()));
            }
            bytes[start..end].to_vec()
        } else {
            Vec::new()
        };

        let is_bootinfo = name == BOOTINFO_SECTION;
        let is_dtb = name == DTB_SECTION;
        saw_bootinfo |= is_bootinfo;

        sections.push(TatuSection {
            name,
            vaddr: sh.sh_addr,
            data,
            virtual_size: sh.sh_size,
            is_nobits,
            is_bootinfo,
            is_dtb,
        });
    }

    if !saw_bootinfo {
        return Err(TatuError::MissingSection(BOOTINFO_SECTION));
    }

    // Sort by vaddr so downstream walks sections in GPA order.
    sections.sort_by_key(|s| s.vaddr);

    Ok(TatuImage {
        sections,
        entry: elf.header.e_entry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn parses_x86_64_tatu_elf() {
        use crate::TATU_X86_64;
        let img = parse(TATU_X86_64, Arch::X86_64).unwrap();
        // Entry MUST be 0xFFFFFFF0 per tatu/x86_64.ld ENTRY(reset).
        assert_eq!(img.entry, 0xFFFF_FFF0);
        // .tatu.bootinfo MUST be present and exactly 4 KiB.
        let bi = img
            .sections
            .iter()
            .find(|s| s.is_bootinfo)
            .expect(".tatu.bootinfo section present");
        assert_eq!(bi.virtual_size, 4096);
        // .tatu.reset MUST end at 0x100000000.
        let rv = img
            .sections
            .iter()
            .find(|s| s.name == ".tatu.reset")
            .expect(".tatu.reset section present");
        assert_eq!(rv.vaddr + rv.virtual_size, 0x1_0000_0000);
        // Sections sorted by vaddr.
        for w in img.sections.windows(2) {
            assert!(w[0].vaddr <= w[1].vaddr);
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn parses_aarch64_tatu_elf() {
        use crate::TATU_AARCH64;
        let img = parse(TATU_AARCH64, Arch::Aarch64).unwrap();
        // Entry MUST be inside .tatu.text (which contains the
        // aarch64 reset stub from .tatu.reset, collapsed in by
        // the linker's KEEP(*(.tatu.reset)) inside .tatu.text).
        let text = img
            .sections
            .iter()
            .find(|s| s.name == ".tatu.text")
            .expect(".tatu.text section present");
        assert!(
            img.entry >= text.vaddr && img.entry < text.vaddr + text.virtual_size,
            "e_entry {:#x} must lie inside .tatu.text [{:#x}, {:#x})",
            img.entry,
            text.vaddr,
            text.vaddr + text.virtual_size
        );
        // .tatu.bootinfo present.
        assert!(img.sections.iter().any(|s| s.is_bootinfo));
        // The unified linker packs aarch64 from GPA 0 (stack first).
        let first = img.sections.first().unwrap();
        assert_eq!(first.vaddr, 0x0);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn reserved_covers_every_section() {
        use crate::TATU_X86_64;
        let img = parse(TATU_X86_64, Arch::X86_64).unwrap();
        let ranges: Vec<_> = img.reserved().collect();
        assert_eq!(ranges.len(), img.sections.len());
        // The x86 reset stub at 0xFFFF_F000 is reserved like the rest.
        assert!(
            ranges.iter().any(|r| r.contains(&0xFFFF_FFF0)),
            "reset vector must be a carve-out"
        );
        // Each range matches its section's [vaddr, vaddr+size).
        for (r, s) in ranges.iter().zip(&img.sections) {
            assert_eq!(r.start, s.vaddr);
            assert_eq!(r.end, s.vaddr + s.virtual_size);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rejects_wrong_arch() {
        use crate::TATU_X86_64;
        let r = parse(TATU_X86_64, Arch::Aarch64);
        assert!(matches!(r, Err(TatuError::WrongArch(_, _))));
    }

    /// Mutate a copy of the embedded x86 ELF so the first PROGBITS
    /// section's `sh_size` claims more bytes than the file holds.
    /// goblin's ELF header / section-header parse still succeeds; our
    /// own `end > bytes.len()` check fires.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rejects_truncated_section() {
        use crate::TATU_X86_64;
        let mut buf = TATU_X86_64.to_vec();
        let elf = Elf::parse(&buf).unwrap();

        // Find the first SHF_ALLOC PROGBITS section.
        let (idx, sh) = elf
            .section_headers
            .iter()
            .enumerate()
            .find(|(_, s)| s.sh_type == SHT_PROGBITS && s.sh_flags & u64::from(SHF_ALLOC) != 0)
            .expect("at least one PROGBITS SHF_ALLOC section");

        // Compute the byte offset of sh_size within the section
        // header table entry (Elf64_Shdr: sh_size is at offset 32).
        let entry_off = (elf.header.e_shoff as usize) + idx * (elf.header.e_shentsize as usize);
        let sh_size_off = entry_off + 32;
        // Sanity: verify we're pointing at the right field.
        let original = u64::from_le_bytes(buf[sh_size_off..sh_size_off + 8].try_into().unwrap());
        assert_eq!(original, sh.sh_size);

        // Inflate sh_size beyond the file end.
        let bogus = (buf.len() as u64) + 0x1_0000;
        buf[sh_size_off..sh_size_off + 8].copy_from_slice(&bogus.to_le_bytes());

        let r = parse(&buf, Arch::X86_64);
        assert!(
            matches!(r, Err(TatuError::TruncatedSection(_))),
            "got {r:?}"
        );
    }

    /// Mutate a copy of the embedded x86 ELF to rename `.tatu.bootinfo`
    /// in the string table so the bootinfo lookup fails.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rejects_missing_bootinfo_section() {
        use crate::TATU_X86_64;
        let mut buf = TATU_X86_64.to_vec();
        let elf = Elf::parse(&buf).unwrap();

        // Locate ".tatu.bootinfo" in .shstrtab and overwrite the
        // first byte so the name no longer matches.
        let shstrtab_idx = elf.header.e_shstrndx as usize;
        let shstrtab = &elf.section_headers[shstrtab_idx];
        let strtab_start = shstrtab.sh_offset as usize;
        let strtab_end = strtab_start + shstrtab.sh_size as usize;
        let needle = b".tatu.bootinfo";
        let pos = buf[strtab_start..strtab_end]
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("bootinfo name in strtab");
        buf[strtab_start + pos] = b'X'; // ".tatu.bootinfo" -> "Xtatu.bootinfo"

        let r = parse(&buf, Arch::X86_64);
        assert!(matches!(r, Err(TatuError::MissingSection(_))), "got {r:?}");
    }
}
