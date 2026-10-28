// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exact release detection on normalized target kernel bytes.

use goblin::elf::{
    Elf,
    program_header::PT_LOAD,
    section_header::{SHF_ALLOC, SHN_LORESERVE, SHT_DYNSYM, SHT_NOBITS, SHT_STRTAB},
    sym::{Sym, Symtab},
};
use goblin::{
    container::{Container, Ctx, Endian},
    strtab::Strtab,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ReleaseError {
    #[error("target kernel has no Linux release banner")]
    Missing,
    #[error("malformed target kernel release banner: {0}")]
    Malformed(&'static str),
    #[error("target kernel contains conflicting releases: {first:?} and {other:?}")]
    Conflicting { first: String, other: String },
}

const PREFIX: &[u8] = b"Linux version ";
// Linux's complete banner is normally a few hundred bytes; never search an
// unbounded string or borrow a terminator from unrelated data.
const MAX_BANNER: usize = 4096;
const MAX_RELEASE: usize = 255;

/// A literal target release must remain a single path component on every host.
/// Colons are excluded as Windows drive prefixes; other printable suffix bytes
/// are preserved rather than normalized or restricted to the module-name regex.
pub(crate) fn validate_component(release: &str) -> Result<(), ReleaseError> {
    if release.is_empty()
        || release.len() > MAX_RELEASE
        || matches!(release, "." | "..")
        || !release
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'\\' | b':'))
    {
        return Err(ReleaseError::Malformed(
            "unsafe release directory component",
        ));
    }
    Ok(())
}

pub(crate) fn detect(bytes: &[u8]) -> Result<String, ReleaseError> {
    let mut release = None;
    if bytes.starts_with(b"\x7fELF") {
        let elf = Elf::parse(bytes).map_err(|_| ReleaseError::Malformed("invalid ELF"))?;
        // goblin populates `dynsyms` from PT_DYNAMIC, not from SHT_DYNSYM.
        // Inspect section-only dynamic tables too rather than treating an
        // available but malformed linux_banner as a stripped-kernel fallback.
        let ctx = Ctx::new(
            if elf.is_64 {
                Container::Big
            } else {
                Container::Little
            },
            if elf.little_endian {
                Endian::Little
            } else {
                Endian::Big
            },
        );
        for section in &elf.section_headers {
            if section.sh_type != SHT_DYNSYM {
                continue;
            }
            let bad = || ReleaseError::Malformed("invalid ELF dynamic symbol section");
            let entry_size = if elf.is_64 { 24 } else { 16 };
            if section.sh_entsize != entry_size || section.sh_size % entry_size != 0 {
                return Err(bad());
            }
            let offset = usize::try_from(section.sh_offset).map_err(|_| bad())?;
            let count = usize::try_from(section.sh_size / entry_size).map_err(|_| bad())?;
            let symbols = Symtab::parse(bytes, offset, count, ctx).map_err(|_| bad())?;
            let names = elf
                .section_headers
                .get(section.sh_link as usize)
                .ok_or_else(bad)?;
            if names.sh_type != SHT_STRTAB {
                return Err(bad());
            }
            let strings = Strtab::parse(
                bytes,
                usize::try_from(names.sh_offset).map_err(|_| bad())?,
                usize::try_from(names.sh_size).map_err(|_| bad())?,
                0,
            )
            .map_err(|_| bad())?;
            for symbol in &symbols {
                if strings.get_at(symbol.st_name) == Some("linux_banner") {
                    merge(
                        &mut release,
                        parse_banner(symbol_bytes(bytes, &elf, &symbol)?)?,
                    )?;
                }
            }
        }
        for (symbols, strings) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
            for symbol in symbols {
                if strings.get_at(symbol.st_name) == Some("linux_banner") {
                    merge(
                        &mut release,
                        parse_banner(symbol_bytes(bytes, &elf, &symbol)?)?,
                    )?;
                }
            }
        }
    }
    for (offset, window) in bytes.windows(PREFIX.len()).enumerate() {
        if window == PREFIX && (offset == 0 || bytes[offset - 1] == 0) {
            merge(&mut release, parse_banner(&bytes[offset..])?)?;
        }
    }
    release.ok_or(ReleaseError::Missing)
}

/// Bound the symbol by both its allocated section and a consistent file-backed
/// load segment. In particular, a BSS address must never index unrelated bytes
/// at the same numeric file offset. Zero-sized linker symbols use these backing
/// bounds, not the rest of the file, as their string extent.
fn symbol_bytes<'a>(
    bytes: &'a [u8],
    elf: &Elf<'_>,
    symbol: &Sym,
) -> Result<&'a [u8], ReleaseError> {
    let bad = || ReleaseError::Malformed("linux_banner is not bounded file-backed ELF data");
    if symbol.st_shndx == 0 || symbol.st_shndx >= SHN_LORESERVE as usize {
        return Err(bad());
    }
    let section = elf.section_headers.get(symbol.st_shndx).ok_or_else(bad)?;
    if section.sh_type == SHT_NOBITS || section.sh_flags & u64::from(SHF_ALLOC) == 0 {
        return Err(bad());
    }
    section
        .sh_addr
        .checked_add(section.sh_size)
        .ok_or_else(bad)?;
    let section_end = section
        .sh_offset
        .checked_add(section.sh_size)
        .ok_or_else(bad)?;
    if section_end > bytes.len() as u64 {
        return Err(bad());
    }
    let relative = symbol
        .st_value
        .checked_sub(section.sh_addr)
        .ok_or_else(bad)?;
    let available = section
        .sh_size
        .checked_sub(relative)
        .filter(|&n| n > 0)
        .ok_or_else(bad)?;
    let length = if symbol.st_size == 0 {
        available
    } else {
        symbol.st_size
    };
    if length > available {
        return Err(bad());
    }
    let start = section.sh_offset.checked_add(relative).ok_or_else(bad)?;
    let mut backed = false;
    let mut length = length;
    for segment in &elf.program_headers {
        if segment.p_type != PT_LOAD {
            continue;
        }
        let Some(delta) = symbol.st_value.checked_sub(segment.p_vaddr) else {
            continue;
        };
        if delta >= segment.p_memsz {
            continue;
        }
        let remaining = segment
            .p_filesz
            .checked_sub(delta)
            .filter(|&n| n > 0)
            .ok_or_else(bad)?;
        if segment.p_filesz > segment.p_memsz
            || segment.p_vaddr.checked_add(segment.p_memsz).is_none()
            || segment
                .p_offset
                .checked_add(segment.p_filesz)
                .is_none_or(|end| end > bytes.len() as u64)
            || segment.p_offset.checked_add(delta) != Some(start)
            || (symbol.st_size != 0 && length > remaining)
        {
            return Err(bad());
        }
        length = length.min(remaining);
        backed = true;
    }
    if !backed {
        return Err(bad());
    }
    let end = start.checked_add(length).ok_or_else(bad)?;
    let start = usize::try_from(start).map_err(|_| bad())?;
    let end = usize::try_from(end).map_err(|_| bad())?;
    bytes.get(start..end).ok_or_else(bad)
}

fn merge(release: &mut Option<String>, candidate: String) -> Result<(), ReleaseError> {
    if let Some(first) = release {
        if *first != candidate {
            return Err(ReleaseError::Conflicting {
                first: first.clone(),
                other: candidate,
            });
        }
    } else {
        *release = Some(candidate);
    }
    Ok(())
}

fn parse_banner(bytes: &[u8]) -> Result<String, ReleaseError> {
    let bounded = &bytes[..bytes.len().min(MAX_BANNER + 1)];
    let end = bounded
        .iter()
        .position(|&b| b == 0)
        .ok_or(ReleaseError::Malformed("missing bounded NUL terminator"))?;
    let text = bounded[..end]
        .strip_suffix(b"\n")
        .unwrap_or(&bounded[..end]);
    let tail = text
        .strip_prefix(PREFIX)
        .ok_or(ReleaseError::Malformed("linux_banner has wrong prefix"))?;
    let split = tail
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ReleaseError::Malformed("missing build identity"))?;
    // Only UTS_RELEASE becomes a path component. Builder/compiler identity
    // comes from build-environment strings and need not be ASCII or UTF-8.
    let release = std::str::from_utf8(&tail[..split])
        .map_err(|_| ReleaseError::Malformed("release is not valid UTF-8"))?;
    validate_component(release)?;
    let identity = tail[split..]
        .strip_prefix(b" (")
        .ok_or(ReleaseError::Malformed(
            "missing parenthesized build identity",
        ))?;
    if identity
        .iter()
        .position(|&b| b == b')')
        .is_none_or(|n| n == 0)
    {
        return Err(ReleaseError::Malformed("incomplete build identity"));
    }
    Ok(release.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn banner(release: &str) -> Vec<u8> {
        format!("Linux version {release} (builder@host) (gcc) #1 SMP\n\0").into_bytes()
    }

    #[test]
    fn rejects_missing_malformed_unsafe_and_unbounded_banners() {
        let mut cases = vec![
            Vec::new(),
            b"6.18.0".to_vec(),
            b"Linux version 6.18 (builder)".to_vec(),
            b"Linux version 6.18 no-builder\0".to_vec(),
            b"Linux version 6.18 ()\0".to_vec(),
            b"prefix Linux version 6.18 (builder)\0".to_vec(),
            banner("."),
            banner(".."),
            banner("../6.18"),
            banner("6.18/evil"),
            banner("C:6.18"),
            banner("6.18\\evil"),
            banner("6.18\u{e9}"),
            banner(""),
            banner("6.18\tbad"),
            banner(&"x".repeat(256)),
        ];
        cases.push(format!("Linux version 6.18 ({})\0", "x".repeat(4096)).into_bytes());
        for bytes in cases {
            assert!(
                detect(&bytes).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    #[test]
    fn rejects_conflicting_candidates_but_accepts_identical_copies() {
        let mut bytes = banner("6.18-test");
        bytes.extend(banner("6.18-test"));
        assert_eq!(detect(&bytes).unwrap(), "6.18-test");
        bytes.extend(banner("6.19-other"));
        assert!(detect(&bytes).is_err());
    }

    #[test]
    fn malformed_candidate_cannot_hide_behind_valid_banner() {
        let mut bytes = banner("6.18");
        bytes.extend(b"Linux version ../unsafe (builder)\0");
        assert!(detect(&bytes).is_err());
    }

    const DATA: usize = 0x100;
    const SYMBOL: usize = 0x258;
    const SECTION: usize = 0x340;
    const VADDR: u64 = 0xffff_ffff_8100_0000;

    fn put64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn elf_banner() -> Vec<u8> {
        elf_with_banner(&banner("6.18.7-local+exact"))
    }

    fn elf_with_banner(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= 0x100);
        let mut bytes = vec![0; 0x400];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        put64(&mut bytes, 32, 64);
        put64(&mut bytes, 40, 0x300);
        for (at, value) in [(52, 64u16), (54, 56), (56, 1), (58, 64), (60, 4)] {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        for (at, value) in [
            (72, DATA as u64),
            (80, VADDR),
            (88, VADDR),
            (96, data.len() as u64),
            (104, data.len() as u64),
        ] {
            put64(&mut bytes, at, value);
        }
        bytes[DATA..DATA + data.len()].copy_from_slice(data);
        bytes[DATA - 1] = 0xff; // No raw fallback boundary: must consult symbol.
        bytes[0x200..0x20e].copy_from_slice(b"\0linux_banner\0");
        bytes[SYMBOL..SYMBOL + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[SYMBOL + 4] = 0x11; // STB_GLOBAL | STT_OBJECT
        bytes[SYMBOL + 6..SYMBOL + 8].copy_from_slice(&1u16.to_le_bytes());
        put64(&mut bytes, SYMBOL + 8, VADDR);
        put64(&mut bytes, SYMBOL + 16, data.len() as u64);
        for (section, kind, offset, size) in [
            (SECTION, 1u32, DATA, data.len()),
            (0x380, 3, 0x200, 14),
            (0x3c0, 2, 0x240, 48),
        ] {
            bytes[section + 4..section + 8].copy_from_slice(&kind.to_le_bytes());
            put64(&mut bytes, section + 24, offset as u64);
            put64(&mut bytes, section + 32, size as u64);
        }
        put64(&mut bytes, SECTION + 8, 2); // SHF_ALLOC
        put64(&mut bytes, SECTION + 16, VADDR);
        bytes[0x3e8..0x3ec].copy_from_slice(&2u32.to_le_bytes()); // sh_link
        put64(&mut bytes, 0x3f8, 24); // sh_entsize
        bytes
    }

    #[test]
    fn authoritative_elf_allows_non_ascii_build_metadata() {
        for data in [
            "Linux version 6.18.2-test (josé@builder) (compilateur é) #1 SMP\n\0".as_bytes(),
            b"Linux version 6.18.2-test (builder\xff@host) (gcc\xfe) #1 SMP\n\0".as_slice(),
        ] {
            let elf = elf_with_banner(data);
            // There is no NUL before the banner, so raw scanning cannot rescue
            // a broken authoritative-symbol path.
            assert_ne!(elf[DATA - 1], 0);
            assert_eq!(detect(&elf).unwrap(), "6.18.2-test");
        }
    }

    #[test]
    fn raw_fallback_allows_non_ascii_build_metadata() {
        for data in [
            "Linux version 6.18.2-test (josé@builder) (compilateur é) #1 SMP\n\0".as_bytes(),
            b"Linux version 6.18.2-test (builder\xff@host) (gcc\xfe) #1 SMP\n\0".as_slice(),
        ] {
            let mut raw = vec![0xff, 0];
            raw.extend_from_slice(data);
            assert_eq!(detect(&raw).unwrap(), "6.18.2-test");
        }
    }

    #[test]
    fn non_ascii_metadata_does_not_weaken_release_validation() {
        for release in [
            b"../escape".as_slice(),
            b"bad\xff",
            b"bad\xc3\xa9",
            b"bad\tname",
            b"C:drive",
        ] {
            let mut data = PREFIX.to_vec();
            data.extend_from_slice(release);
            data.extend_from_slice(b" (builder\xff@host) (gcc) #1 SMP\n\0");
            assert!(detect(&data).is_err());
            assert!(detect(&elf_with_banner(&data)).is_err());
        }
        for data in [
            b"Linux version 6.18.2-test (builder\xff@host)".as_slice(),
            b"Linux version 6.18.2-test builder\xff\0",
            b"Linux version 6.18.2-test (builder\xff\0",
        ] {
            assert!(detect(data).is_err());
            assert!(detect(&elf_with_banner(data)).is_err());
        }
    }

    #[test]
    fn reads_file_backed_authoritative_elf_symbol() {
        assert_eq!(detect(&elf_banner()).unwrap(), "6.18.7-local+exact");
    }

    #[test]
    fn rejects_malformed_authoritative_symbol_even_with_valid_fallback() {
        let original = elf_banner();
        let size = banner("6.18.7-local+exact").len() as u64;
        let mutations = [
            (SYMBOL + 8, VADDR - 1),
            (SYMBOL + 8, VADDR + size),
            (SYMBOL + 16, size - 1),
            (SYMBOL + 16, size + 1),
            (SYMBOL + 16, u64::MAX),
            (SECTION + 24, u64::MAX),
            (SECTION + 32, u64::MAX),
            (96, size - 1),
            (72, u64::MAX),
            (80, VADDR + 1),
        ];
        for (at, value) in mutations {
            let mut bytes = original.clone();
            put64(&mut bytes, at, value);
            bytes.extend(banner("6.18.7-local+exact"));
            assert!(
                detect(&bytes).is_err(),
                "accepted mutation {at:#x}={value:#x}"
            );
        }
        for index in [0u16, 4, 0xfff1, 0xffff] {
            let mut bytes = original.clone();
            bytes[SYMBOL + 6..SYMBOL + 8].copy_from_slice(&index.to_le_bytes());
            bytes.extend(banner("6.18.7-local+exact"));
            assert!(detect(&bytes).is_err(), "accepted section index {index}");
        }
        let mut bytes = original;
        bytes[SECTION + 4..SECTION + 8].copy_from_slice(&8u32.to_le_bytes()); // NOBITS
        bytes.extend(banner("6.18.7-local+exact"));
        assert!(detect(&bytes).is_err());
    }

    #[test]
    fn authoritative_symbol_rejects_wrong_banner_and_conflicting_fallback() {
        let mut bytes = elf_banner();
        bytes[DATA] = b'x';
        bytes.extend(banner("6.18.7-local+exact"));
        assert!(detect(&bytes).is_err());
        let mut bytes = elf_banner();
        bytes.extend(banner("different-release"));
        assert!(detect(&bytes).is_err());
    }

    #[test]
    fn malformed_elf_must_not_fall_back_to_scanning() {
        let mut bytes = b"\x7fELF\0".to_vec();
        bytes.extend(banner("6.18"));
        assert!(detect(&bytes).is_err());
    }

    #[test]
    fn authoritative_mapping_rejects_overflowing_segment_address_extent() {
        let mut bytes = elf_banner();
        put64(&mut bytes, 104, u64::MAX);
        bytes.extend(banner("6.18.7-local+exact"));
        assert!(detect(&bytes).is_err());
    }

    #[test]
    fn stripped_elf_and_zero_sized_symbol_remain_bounded() {
        let mut bytes = elf_banner();
        put64(&mut bytes, SYMBOL + 16, 0);
        assert_eq!(detect(&bytes).unwrap(), "6.18.7-local+exact");
        let len = banner("6.18.7-local+exact").len();
        bytes[DATA + len - 1] = b'x';
        assert!(
            detect(&bytes).is_err(),
            "zero size borrowed NUL outside section"
        );
        let mut bytes = elf_banner();
        // Strip the section table as a distro image can; only bounded fallback
        // is left, and therefore needs its own string-start boundary.
        put64(&mut bytes, 40, 0);
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
        bytes[DATA - 1] = 0;
        assert_eq!(detect(&bytes).unwrap(), "6.18.7-local+exact");
    }

    #[test]
    fn dynamic_symbol_table_is_authoritative_too() {
        let mut bytes = elf_banner();
        bytes[0x3c4..0x3c8].copy_from_slice(&11u32.to_le_bytes()); // SHT_DYNSYM
        assert_eq!(detect(&bytes).unwrap(), "6.18.7-local+exact");
        bytes[DATA] = b'x';
        bytes.extend(banner("6.18.7-local+exact"));
        assert!(detect(&bytes).is_err());
    }

    #[test]
    fn duplicate_symbols_must_all_be_valid_and_agree() {
        let mut bytes = elf_banner();
        let symbol = bytes[SYMBOL..SYMBOL + 24].to_vec();
        bytes[0x270..0x288].copy_from_slice(&symbol);
        put64(&mut bytes, 0x3e0, 72); // three entries including null symbol
        assert_eq!(detect(&bytes).unwrap(), "6.18.7-local+exact");
        put64(&mut bytes, 0x270 + 8, VADDR - 1);
        assert!(detect(&bytes).is_err());
    }

    #[test]
    fn release_accepts_safe_ascii_component_without_normalization() {
        let release = "6.18.0-arch1-1+local~test@build";
        assert_eq!(detect(&banner(release)).unwrap(), release);
        assert_eq!(detect(&banner(&"a".repeat(255))).unwrap(), "a".repeat(255));
    }

    #[test]
    fn truncated_elf_inputs_never_panic_or_guess() {
        let bytes = elf_banner();
        for end in 4..bytes.len() {
            assert!(
                detect(&bytes[..end]).is_err(),
                "accepted truncation at {end}"
            );
        }
    }

    // These opt-in tests fail on download errors; a network skip is never a pass.
    fn real_catalog(arch: &str) {
        let entries: Vec<_> = burrow::KERNELS.iter().filter(|e| e.arch == arch).collect();
        assert!(!entries.is_empty(), "catalog has no {arch} kernels");
        for entry in entries {
            let path = burrow::fetch(entry.url).expect("real-kernel download/cache required");
            let original = std::fs::read(path).unwrap();
            let normalized =
                crate::kernel::extract_vmlinux(crate::kernel::unwrap_zboot(original).unwrap())
                    .unwrap();
            let release = detect(&normalized).unwrap_or_else(|err| panic!("{}: {err}", entry.url));
            if entry.url.contains("vmlinux-6.1.155") {
                assert_eq!(release, "6.1.155+");
            } else if entry.url.contains("vmlinux-6.1.128") {
                assert_eq!(release, "6.1.128");
            } else if entry.url.contains("alpinelinux") {
                assert!(
                    release.ends_with("-virt"),
                    "unexpected Alpine release {release}"
                );
            } else if entry.url.contains("fedoraproject") {
                assert!(
                    release.ends_with(".fc44.aarch64"),
                    "unexpected Fedora release {release}"
                );
            }
            eprintln!("{} => {release}", entry.url);
        }
    }

    #[test]
    #[ignore = "requires real burrow kernel downloads/cache; download failures are failures"]
    fn real_x86_catalog_normalized_releases() {
        real_catalog("x86_64");
    }

    #[test]
    #[ignore = "requires real burrow kernel downloads/cache; download failures are failures"]
    fn real_arm64_catalog_normalized_releases() {
        real_catalog("aarch64");
    }

    #[test]
    fn raw_banner_preserves_exact_distro_release() {
        assert_eq!(
            detect(b"\0Linux version 6.18.2-200.fc44.x86_64+debug (builder@host) (gcc) #1 SMP\n\0")
                .unwrap(),
            "6.18.2-200.fc44.x86_64+debug"
        );
    }
}
