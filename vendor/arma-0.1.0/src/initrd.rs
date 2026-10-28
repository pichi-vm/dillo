// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Initrd input handling.
//!
//! Accepts two input shapes:
//!
//! 1. A complete cpio newc archive, uncompressed or gzip/zstd compressed —
//!    validated and passed through unchanged. Linux decompresses it at boot.
//! 2. A statically-linked ELF executable — wrapped in a single-entry
//!    cpio newc archive containing `/`, `/dev`, `/dev/console`, `/init`
//!    and `TRAILER!!!`.
//!
//! Any other input — including dynamically-linked ELF binaries — is
//! rejected. The kernel's PID 1 (`/init`) cannot resolve a dynamic
//! interpreter from an initramfs that ships only the executable, so
//! quietly wrapping such a file would produce a PMI that triple-faults
//! at guest boot. Surfacing the error at arma time makes the failure
//! mode legible.
//!
//! Detection:
//!   - cpio newc: first 6 bytes are the magic `070701`.
//!   - ELF: first 4 bytes are `\x7fELF`.
//!   - "static" means the ELF has no `PT_INTERP` program header.

use std::borrow::Cow;
use std::io::Read;

use goblin::elf::Elf;
use goblin::elf::program_header::PT_INTERP;
use thiserror::Error;

/// cpio newc magic prefix.
const NEWC_MAGIC: &[u8; 6] = b"070701";

/// ELF magic prefix.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// Errors from initrd materialization.
#[derive(Debug, Error)]
pub(crate) enum InitrdError {
    /// The input binary is too large to be representable in the
    /// cpio newc header (which uses 8 hex digits — 32 bits — for
    /// the filesize field).
    #[error(
        "init binary is {0} bytes; cpio newc filesize field is a 32-bit (8-hex-digit) value, max {max} bytes",
        max = u32::MAX as u64
    )]
    InitTooLarge(usize),

    /// The input is neither a cpio newc archive nor an ELF binary.
    #[error(
        "initrd input is neither a cpio newc archive (uncompressed, gzip or zstd) nor an ELF binary"
    )]
    UnsupportedFormat,

    #[error("module options require a static ELF init, not an existing initramfs")]
    ModulesRequireStatic,

    #[error("unsafe or conflicting module archive path: {0}")]
    ModulePath(String),

    #[error("initramfs entry exceeds newc field limits or addressable archive size")]
    ArchiveTooLarge,

    #[error("malformed or truncated cpio newc initramfs")]
    MalformedArchive,

    #[error("initramfs decompression failed: {0}")]
    Decompress(#[from] std::io::Error),

    /// The input is an ELF but failed to parse.
    #[error("failed to parse ELF initrd input")]
    ElfParse(#[from] goblin::error::Error),

    /// The input is an ELF but is dynamically linked (has a
    /// `PT_INTERP` program header naming a dynamic loader).
    #[error(
        "ELF init binary is dynamically linked (PT_INTERP = `{0}`); arma requires a static binary because the initramfs contains only the executable"
    )]
    DynamicallyLinked(String),
}

/// Determine whether `bytes` is already a cpio newc archive.
pub(crate) fn is_cpio(bytes: &[u8]) -> bool {
    bytes.len() >= NEWC_MAGIC.len() && &bytes[..NEWC_MAGIC.len()] == NEWC_MAGIC
}

/// Determine whether `bytes` starts with the ELF magic.
fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= ELF_MAGIC.len() && &bytes[..ELF_MAGIC.len()] == ELF_MAGIC
}

/// Verify that an ELF has no `PT_INTERP` program header. Returns the
/// interpreter path on failure so the error message names the
/// dependency the user would have to satisfy.
fn check_static_elf(bytes: &[u8]) -> Result<(), InitrdError> {
    let elf = Elf::parse(bytes)?;
    for ph in &elf.program_headers {
        if ph.p_type == PT_INTERP {
            let interp = elf.interpreter.unwrap_or("<unknown>").to_string();
            return Err(InitrdError::DynamicallyLinked(interp));
        }
    }
    Ok(())
}

/// Materialize an initramfs from the raw input. If the input is
/// already cpio, the original slice is returned borrowed (no copy —
/// large initrds can be many MiB). If the input is a static ELF, it
/// is wrapped in a single-entry cpio archive at `/init`. Any other
/// input is rejected.
///
/// Compressed archives are decoded only for validation; the original bytes
/// are preserved, so the kernel needs the matching CONFIG_RD_GZIP/ZSTD driver.
pub(crate) fn materialize(input: &[u8]) -> Result<Cow<'_, [u8]>, InitrdError> {
    if is_cpio(input) {
        validate_cpio(input).ok_or(InitrdError::MalformedArchive)?;
        return Ok(Cow::Borrowed(input));
    }
    if input.starts_with(&[0x1f, 0x8b]) {
        let mut remaining = input;
        let mut decoded = Vec::new();
        while !remaining.is_empty() {
            flate2::bufread::GzDecoder::new(&mut remaining).read_to_end(&mut decoded)?;
            remaining = skip_padding(remaining);
        }
        validate_cpio(&decoded).ok_or(InitrdError::MalformedArchive)?;
        return Ok(Cow::Borrowed(input));
    }
    if input.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let mut remaining = input;
        let mut decoded = Vec::new();
        while !remaining.is_empty() {
            // ruzstd does not reject the reserved frame-descriptor bit or
            // enforce declared content size; check both at this boundary.
            let descriptor = *remaining.get(4).ok_or(InitrdError::MalformedArchive)?;
            if descriptor & 0x08 != 0 {
                return Err(InitrdError::MalformedArchive);
            }
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(remaining)
                .map_err(std::io::Error::other)?;
            let before = decoded.len();
            decoder.read_to_end(&mut decoded)?;
            if (descriptor & 0xe0 != 0)
                && decoder.decoder.content_size() != (decoded.len() - before) as u64
            {
                return Err(InitrdError::MalformedArchive);
            }
            if let Some(expected) = decoder.decoder.get_checksum_from_data()
                && decoder.decoder.get_calculated_checksum() != Some(expected)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "zstd initramfs checksum mismatch",
                )
                .into());
            }
            remaining = skip_padding(decoder.into_inner());
        }
        validate_cpio(&decoded).ok_or(InitrdError::MalformedArchive)?;
        return Ok(Cow::Borrowed(input));
    }
    if is_elf(input) {
        check_static_elf(input)?;
        if input.len() > u32::MAX as usize {
            return Err(InitrdError::InitTooLarge(input.len()));
        }
        return Ok(Cow::Owned(wrap_as_cpio(input)));
    }
    Err(InitrdError::UnsupportedFormat)
}

/// A selected module, relative to the release-specific source tree.
#[derive(Debug)]
pub(crate) struct Module<'a> {
    pub(crate) path: &'a std::path::Path,
    pub(crate) bytes: &'a [u8],
}

pub(crate) fn check_module_init(input: &[u8]) -> Result<(), InitrdError> {
    if !is_elf(input) {
        return Err(InitrdError::ModulesRequireStatic);
    }
    check_static_elf(input)
}

pub(crate) fn materialize_modules(
    input: &[u8],
    release: &str,
    modules: &[Module<'_>],
) -> Result<Vec<u8>, InitrdError> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Component;

    check_module_init(input)?;
    checked_entry_size(0, "init".len(), input.len())?;
    if modules.is_empty() {
        return materialize(input).map(Cow::into_owned);
    }
    crate::kernel_release::validate_component(release)
        .map_err(|_| InitrdError::ModulePath(release.to_owned()))?;
    let mut directories = BTreeSet::from([".".to_string(), "dev".to_string()]);
    let mut files = BTreeMap::new();
    for module in modules {
        let mut parts = Vec::new();
        for component in module.path.components() {
            let Component::Normal(part) = component else {
                return Err(InitrdError::ModulePath(module.path.display().to_string()));
            };
            let part = part
                .to_str()
                .filter(|p| {
                    !p.is_empty()
                        && !p
                            .chars()
                            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
                })
                .ok_or_else(|| InitrdError::ModulePath(module.path.display().to_string()))?;
            parts.push(part);
        }
        if parts.is_empty() {
            return Err(InitrdError::ModulePath(module.path.display().to_string()));
        }
        let path = format!("usr/lib/modules/{release}/{}", parts.join("/"));
        let mut parent = std::path::Path::new(&path).parent();
        while let Some(dir) = parent.filter(|d| !d.as_os_str().is_empty()) {
            let name = dir
                .to_str()
                .ok_or_else(|| InitrdError::ModulePath(path.clone()))?;
            // Archive separators are POSIX even on Windows hosts.
            directories.insert(name.replace('\\', "/"));
            parent = dir.parent();
        }
        if let Some(previous) = files.insert(path.clone(), module.bytes)
            && previous != module.bytes
        {
            return Err(InitrdError::ModulePath(path));
        }
    }
    if files.keys().any(|name| directories.contains(name)) {
        return Err(InitrdError::ModulePath(
            "file/directory collision".to_string(),
        ));
    }
    let mut links = BTreeMap::new();
    for directory in &directories {
        if directory == "." {
            continue;
        }
        let parent = directory.rsplit_once('/').map_or(".", |(p, _)| p);
        let count = links.entry(parent).or_insert(2u32);
        *count = count.checked_add(1).ok_or(InitrdError::ArchiveTooLarge)?;
    }
    let mut out = Vec::new();
    let mut ino = 0u32;
    for directory in &directories {
        ino = ino.checked_add(1).ok_or(InitrdError::ArchiveTooLarge)?;
        let link_count = links.get(directory.as_str()).copied().unwrap_or(2);
        checked_entry(&mut out, ino, 0o040_755, link_count, directory, &[], None)?;
    }
    ino = ino.checked_add(1).ok_or(InitrdError::ArchiveTooLarge)?;
    checked_entry(
        &mut out,
        ino,
        0o020_666,
        1,
        "dev/console",
        &[],
        Some((5, 1)),
    )?;
    ino = ino.checked_add(1).ok_or(InitrdError::ArchiveTooLarge)?;
    checked_entry(&mut out, ino, 0o100_755, 1, "init", input, None)?;
    for (name, bytes) in files {
        ino = ino.checked_add(1).ok_or(InitrdError::ArchiveTooLarge)?;
        checked_entry(&mut out, ino, 0o100_644, 1, &name, bytes, None)?;
    }
    checked_entry(&mut out, 0, 0, 1, "TRAILER!!!", &[], None)?;
    Ok(out)
}

fn checked_entry_size(offset: usize, name_len: usize, size: usize) -> Result<usize, InitrdError> {
    let namesize = name_len
        .checked_add(1)
        .ok_or(InitrdError::ArchiveTooLarge)?;
    u32::try_from(namesize).map_err(|_| InitrdError::ArchiveTooLarge)?;
    u32::try_from(size).map_err(|_| InitrdError::ArchiveTooLarge)?;
    let end = offset
        .checked_add(110)
        .and_then(|n| n.checked_add(namesize))
        .and_then(|n| n.checked_add(3))
        .map(|n| n & !3)
        .and_then(|n| n.checked_add(size))
        .and_then(|n| n.checked_add(3))
        .map(|n| n & !3)
        .ok_or(InitrdError::ArchiveTooLarge)?;
    end.checked_sub(offset).ok_or(InitrdError::ArchiveTooLarge)
}

fn checked_entry(
    out: &mut Vec<u8>,
    ino: u32,
    mode: u32,
    nlink: u32,
    name: &str,
    bytes: &[u8],
    rdev: Option<(u32, u32)>,
) -> Result<(), InitrdError> {
    let additional = checked_entry_size(out.len(), name.len(), bytes.len())?;
    out.try_reserve(additional)
        .map_err(|_| InitrdError::ArchiveTooLarge)?;
    cpio_entry(out, ino, mode, nlink, name, bytes, rdev);
    Ok(())
}

/// Check complete newc records, including the trailer, before passing bytes
/// to Linux. Accept zero padding and concatenated archives as initramfs does.
/// No extraction or pathname interpretation is needed here.
fn validate_cpio(mut bytes: &[u8]) -> Option<()> {
    loop {
        loop {
            let header = bytes.get(..110)?;
            if !header.starts_with(NEWC_MAGIC) {
                return None;
            }
            let mut fields = [0u32; 13];
            for (field, hex) in fields.iter_mut().zip(header[6..].as_chunks::<8>().0) {
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                *field = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
            }
            let size = usize::try_from(fields[6]).ok()?;
            let namesize = usize::try_from(fields[11]).ok()?;
            let name_end = 110usize.checked_add(namesize)?;
            let name = bytes.get(110..name_end)?;
            if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) || fields[12] != 0 {
                return None;
            }
            let data_start = name_end.checked_add(3)? & !3;
            let data_end = data_start.checked_add(size)?;
            let next = data_end.checked_add(3)? & !3;
            bytes = bytes.get(next..)?;
            if name == b"TRAILER!!!\0" {
                if size != 0 {
                    return None;
                }
                break;
            }
        }
        bytes = skip_padding(bytes);
        if bytes.is_empty() {
            return Some(());
        }
    }
}

/// Linux initramfs permits NUL padding between complete components.
fn skip_padding(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len())..]
}

/// Emit a cpio newc entry with the given inode, mode, link count,
/// name, and data. Optionally a `(major, minor)` for character/block
/// device nodes.
fn cpio_entry(
    out: &mut Vec<u8>,
    ino: u32,
    mode: u32,
    nlink: u32,
    name: &str,
    data: &[u8],
    rdev: Option<(u32, u32)>,
) {
    let namesize = name.len() + 1; // includes NUL terminator
    let (rdevmajor, rdevminor) = rdev.unwrap_or((0, 0));
    let header = format!(
        "070701\
         {ino:08X}\
         {mode:08X}\
         {uid:08X}\
         {gid:08X}\
         {nlink:08X}\
         {mtime:08X}\
         {filesize:08X}\
         {devmajor:08X}\
         {devminor:08X}\
         {rdevmajor:08X}\
         {rdevminor:08X}\
         {namesize:08X}\
         {check:08X}",
        uid = 0,
        gid = 0,
        mtime = 0,
        filesize = data.len(),
        devmajor = 0,
        devminor = 0,
        check = 0,
    );

    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0); // NUL
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Wrap a single executable in a minimal cpio newc archive.
///
/// Layout:
///   /                    (dir, nlink=3)
///   /dev                 (dir, nlink=2)
///   /dev/console         (char device, major 5 minor 1, rw-rw-rw-)
///   /init                (executable, 0755, the input bytes)
///   TRAILER!!!           (sentinel)
fn wrap_as_cpio(init_binary: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(512 + init_binary.len());
    cpio_entry(&mut out, 1, 0o040_755, 3, ".", &[], None);
    cpio_entry(&mut out, 2, 0o040_755, 2, "dev", &[], None);
    cpio_entry(
        &mut out,
        3,
        0o020_666, // char device, rw-rw-rw-
        1,
        "dev/console",
        &[],
        Some((5, 1)),
    );
    cpio_entry(&mut out, 4, 0o100_755, 1, "init", init_binary, None);
    cpio_entry(&mut out, 0, 0, 1, "TRAILER!!!", &[], None);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_archive_contains_only_selected_bytes_and_normalized_metadata() {
        let binary = synth_elf(&[]);
        let payload = b"module payload";
        let files = [Module {
            path: std::path::Path::new("kernel/drivers/test.ko"),
            bytes: payload,
        }];
        let archive = materialize_modules(&binary, "7.2-test", &files).unwrap();
        assert!(validate_cpio(&archive).is_some());
        let entries = inspect_newc(&archive);
        assert_eq!(entries["init"].0, binary);
        assert_eq!(
            entries["usr/lib/modules/7.2-test/kernel/drivers/test.ko"].0,
            payload
        );
        assert_eq!(
            entries["usr/lib/modules/7.2-test/kernel/drivers/test.ko"].1,
            0o100_644
        );
        assert!(entries.contains_key("dev/console"));
        assert!(!entries.keys().any(|name| name.ends_with("modules.dep")));
    }

    #[test]
    fn module_archive_preserves_safe_local_release_suffix() {
        let binary = synth_elf(&[]);
        let modules = [Module {
            path: std::path::Path::new("a.ko"),
            bytes: b"x",
        }];
        let archive = materialize_modules(&binary, "6.18-local~test@build", &modules).unwrap();
        assert!(inspect_newc(&archive).contains_key("usr/lib/modules/6.18-local~test@build/a.ko"));
    }

    #[test]
    fn module_archive_is_order_independent_and_preserves_compression() {
        let binary = synth_elf(&[]);
        let a = Module {
            path: std::path::Path::new("kernel/a.ko.zst"),
            bytes: b"compressed bytes",
        };
        let b = Module {
            path: std::path::Path::new("extra/b.ko"),
            bytes: b"uncompressed bytes",
        };
        let first = materialize_modules(&binary, "7.2-test", &[a, b]).unwrap();
        let second = materialize_modules(
            &binary,
            "7.2-test",
            &[
                Module {
                    path: std::path::Path::new("extra/b.ko"),
                    bytes: b"uncompressed bytes",
                },
                Module {
                    path: std::path::Path::new("kernel/a.ko.zst"),
                    bytes: b"compressed bytes",
                },
                Module {
                    path: std::path::Path::new("kernel/a.ko.zst"),
                    bytes: b"compressed bytes",
                },
            ],
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            inspect_newc(&first)["usr/lib/modules/7.2-test/kernel/a.ko.zst"].0,
            b"compressed bytes"
        );
        assert_eq!(
            materialize_modules(&binary, "7.2-test", &[]).unwrap(),
            materialize(&binary).unwrap().as_ref()
        );
    }

    #[test]
    fn module_archive_rejects_unsafe_inputs_and_bounded_field_overflows() {
        let binary = synth_elf(&[]);
        for path in [
            "../escape.ko",
            "/absolute.ko",
            "C:\\escape.ko",
            "bad\nname.ko",
            "",
        ] {
            let modules = [Module {
                path: std::path::Path::new(path),
                bytes: b"x",
            }];
            assert!(
                materialize_modules(&binary, "7.2-test", &modules).is_err(),
                "{path:?}"
            );
        }
        let modules = [Module {
            path: std::path::Path::new("x.ko"),
            bytes: b"x",
        }];
        for release in ["", ".", "..", "../7", "7/escape", "7\n"] {
            assert!(materialize_modules(&binary, release, &modules).is_err());
        }
        for archive in [
            include_bytes!("../tests/data/initramfs.cpio").as_slice(),
            include_bytes!("../tests/data/initramfs.cpio.gz").as_slice(),
            b"not ELF",
        ] {
            assert!(matches!(
                materialize_modules(archive, "7.2-test", &modules),
                Err(InitrdError::ModulesRequireStatic)
            ));
        }
        let dynamic = synth_elf(&[(PT_INTERP, b"/ld.so\0")]);
        assert!(matches!(
            materialize_modules(&dynamic, "7.2-test", &modules),
            Err(InitrdError::DynamicallyLinked(_))
        ));
        assert!(checked_entry_size(usize::MAX, 1, 1).is_err());
        assert!(checked_entry_size(0, usize::MAX, 1).is_err());
        assert!(checked_entry_size(0, 1, usize::MAX).is_err());
        assert_eq!(checked_entry_size(0, 4, 3).unwrap(), 120);
        let collision = [
            Module {
                path: std::path::Path::new("a.ko"),
                bytes: b"x",
            },
            Module {
                path: std::path::Path::new("a.ko"),
                bytes: b"y",
            },
        ];
        assert!(materialize_modules(&binary, "7.2-test", &collision).is_err());
    }

    fn inspect_newc(mut bytes: &[u8]) -> std::collections::BTreeMap<String, (Vec<u8>, u32)> {
        let mut entries = std::collections::BTreeMap::new();
        loop {
            let number =
                |a, b| u32::from_str_radix(std::str::from_utf8(&bytes[a..b]).unwrap(), 16).unwrap();
            let mode = number(14, 22);
            assert_eq!(number(22, 30), 0);
            assert_eq!(number(30, 38), 0);
            assert_eq!(number(46, 54), 0);
            let size = number(54, 62) as usize;
            let namesize = number(94, 102) as usize;
            let name = std::str::from_utf8(&bytes[110..110 + namesize - 1])
                .unwrap()
                .to_string();
            let start = (110 + namesize + 3) & !3;
            if name == "TRAILER!!!" {
                break;
            }
            assert!(
                entries
                    .insert(name, (bytes[start..start + size].to_vec(), mode))
                    .is_none()
            );
            bytes = &bytes[(start + size + 3) & !3..];
        }
        entries
    }

    /// Build a minimal ELF64 little-endian header with the given
    /// program-header table. Used by tests to synthesize static and
    /// dynamically-linked inputs without shelling out to a compiler.
    fn synth_elf(program_headers: &[(u32, &[u8])]) -> Vec<u8> {
        // ELF64 header is 64 bytes; each PHDR is 56 bytes.
        const EHDR_SIZE: usize = 64;
        const PHDR_SIZE: usize = 56;
        let phnum = program_headers.len();
        let phoff = EHDR_SIZE;
        // Lay out PT_INTERP payloads after the program-header table.
        let mut payload_offset = phoff + phnum * PHDR_SIZE;
        let mut payloads: Vec<(usize, &[u8])> = Vec::new();
        for (_, payload) in program_headers {
            payloads.push((payload_offset, payload));
            payload_offset += payload.len();
        }
        let total_size = payload_offset;

        let mut out = vec![0u8; total_size];
        // e_ident
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        // e_type = ET_EXEC (2)
        out[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine = EM_X86_64 (0x3E)
        out[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        // e_version = 1
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry
        out[24..32].copy_from_slice(&0u64.to_le_bytes());
        // e_phoff
        out[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        // e_shoff = 0
        out[40..48].copy_from_slice(&0u64.to_le_bytes());
        // e_flags = 0
        out[48..52].copy_from_slice(&0u32.to_le_bytes());
        // e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
        out[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        out[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        out[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());
        out[58..60].copy_from_slice(&0u16.to_le_bytes());
        out[60..62].copy_from_slice(&0u16.to_le_bytes());
        out[62..64].copy_from_slice(&0u16.to_le_bytes());

        // Program headers
        for (i, (p_type, payload)) in program_headers.iter().enumerate() {
            let base = phoff + i * PHDR_SIZE;
            let (poff, _) = payloads[i];
            out[base..base + 4].copy_from_slice(&p_type.to_le_bytes());
            out[base + 4..base + 8].copy_from_slice(&0u32.to_le_bytes()); // p_flags
            out[base + 8..base + 16].copy_from_slice(&(poff as u64).to_le_bytes()); // p_offset
            out[base + 16..base + 24].copy_from_slice(&0u64.to_le_bytes()); // p_vaddr
            out[base + 24..base + 32].copy_from_slice(&0u64.to_le_bytes()); // p_paddr
            out[base + 32..base + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes()); // p_filesz
            out[base + 40..base + 48].copy_from_slice(&(payload.len() as u64).to_le_bytes()); // p_memsz
            out[base + 48..base + 56].copy_from_slice(&1u64.to_le_bytes()); // p_align
        }

        // Payloads
        for (offset, payload) in payloads {
            out[offset..offset + payload.len()].copy_from_slice(payload);
        }

        out
    }

    #[test]
    fn detects_cpio_by_magic() {
        assert!(is_cpio(b"070701ABCDEF"));
        assert!(!is_cpio(b"\x7fELF"));
        assert!(!is_cpio(b""));
    }

    #[test]
    fn detects_elf_by_magic() {
        assert!(is_elf(b"\x7fELFmore"));
        assert!(!is_elf(b"070701"));
        assert!(!is_elf(b"\x7fEL"));
        assert!(!is_elf(b""));
    }

    #[test]
    fn materialize_passes_cpio_through_unchanged() {
        let cpio = include_bytes!("../tests/data/initramfs.cpio").to_vec();
        let out = materialize(&cpio).unwrap();
        assert_eq!(out.as_ref(), cpio.as_slice());
    }

    #[test]
    fn materialize_borrows_cpio_input_without_copying() {
        let cpio = include_bytes!("../tests/data/initramfs.cpio").to_vec();
        let out = materialize(&cpio).unwrap();
        // The pass-through path MUST be Borrowed — for multi-MiB
        // initrds this avoids an extra full-buffer copy.
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn materialize_wraps_static_elf() {
        // PT_LOAD = 1; no PT_INTERP → static.
        let elf = synth_elf(&[(1, b"payload")]);
        let out = materialize(&elf).unwrap();
        assert!(matches!(out, Cow::Owned(_)));
        assert!(is_cpio(&out));
        assert!(out.windows(b"TRAILER!!!".len()).any(|w| w == b"TRAILER!!!"));
        assert!(
            out.windows(b"dev/console".len())
                .any(|w| w == b"dev/console")
        );
    }

    #[test]
    fn materialize_rejects_dynamic_elf() {
        // PT_INTERP = 3, payload is the interpreter path as a
        // NUL-terminated C string.
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        let elf = synth_elf(&[(3, interp)]);
        let err = materialize(&elf).unwrap_err();
        match err {
            InitrdError::DynamicallyLinked(path) => {
                assert_eq!(path, "/lib64/ld-linux-x86-64.so.2");
            }
            other => panic!("expected DynamicallyLinked, got {other:?}"),
        }
    }

    #[test]
    fn materialize_rejects_arbitrary_bytes() {
        // Not cpio, not ELF.
        let err = materialize(b"this is not an init binary").unwrap_err();
        assert!(matches!(err, InitrdError::UnsupportedFormat));
    }

    #[test]
    fn materialize_rejects_empty_input() {
        let err = materialize(b"").unwrap_err();
        assert!(matches!(err, InitrdError::UnsupportedFormat));
    }

    #[rstest::rstest]
    #[case(include_bytes!("../tests/data/initramfs.cpio").as_slice())]
    #[case(include_bytes!("../tests/data/initramfs.cpio.gz").as_slice())]
    #[case(include_bytes!("../tests/data/initramfs.cpio.zst").as_slice())]
    fn complete_archives_are_preserved(#[case] input: &[u8]) {
        let out = materialize(input).unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), input);
        assert!(materialize(&input[..input.len() / 2]).is_err());
        let joined = [input, input].concat();
        assert_eq!(materialize(&joined).unwrap().as_ref(), joined);
        let padded = [input, &[0; 16], input, &[0; 16]].concat();
        assert_eq!(materialize(&padded).unwrap().as_ref(), padded);
        let mut bad_second = joined;
        bad_second.pop();
        if !is_cpio(input) {
            assert!(materialize(&bad_second).is_err());
        }
    }

    #[test]
    fn validates_zstd_headers_with_and_without_content_size_or_checksum() {
        let frame = include_bytes!("../tests/data/initramfs.cpio.zst");
        for offset in [4, 5] {
            let mut bad = frame.to_vec();
            bad[offset] ^= if offset == 4 { 0x08 } else { 1 };
            assert!(materialize(&bad).is_err());
        }
        // A raw-block frame, 1 KiB window, no content size and no checksum.
        // This valid streaming form must not be mistaken for a zero-byte frame.
        let archive = include_bytes!("../tests/data/initramfs.cpio");
        let mut streaming = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0];
        let block_header = ((archive.len() as u32) << 3) | 1;
        streaming.extend_from_slice(&block_header.to_le_bytes()[..3]);
        streaming.extend_from_slice(archive);
        assert_eq!(materialize(&streaming).unwrap().as_ref(), streaming);
    }

    #[test]
    fn compressed_fixtures_decode_to_the_complete_archive() {
        let expected = include_bytes!("../tests/data/initramfs.cpio");
        let mut gzip = Vec::new();
        flate2::read::MultiGzDecoder::new(
            include_bytes!("../tests/data/initramfs.cpio.gz").as_slice(),
        )
        .read_to_end(&mut gzip)
        .unwrap();
        assert_eq!(gzip, expected);
        let mut zstd = Vec::new();
        ruzstd::decoding::StreamingDecoder::new(
            include_bytes!("../tests/data/initramfs.cpio.zst").as_slice(),
        )
        .unwrap()
        .read_to_end(&mut zstd)
        .unwrap();
        assert_eq!(zstd, expected);
    }

    #[test]
    fn rejects_truncated_records_and_invalid_name_or_size() {
        let archive = include_bytes!("../tests/data/initramfs.cpio");
        let trailer = archive
            .windows(10)
            .position(|w| w == b"TRAILER!!!")
            .unwrap();
        for end in 0..trailer + 10 {
            assert!(
                materialize(&archive[..end]).is_err(),
                "accepted prefix {end}"
            );
        }
        for (offset, replacement) in [(94, b"00000000"), (54, b"FFFFFFFF")] {
            let mut bad = archive.to_vec();
            bad[offset..offset + 8].copy_from_slice(replacement);
            assert!(materialize(&bad).is_err());
        }
        let mut bad_name = archive.to_vec();
        bad_name[114] = b'!';
        assert!(materialize(&bad_name).is_err());
        let wrapped = wrap_as_cpio(b"test executable");
        assert!(validate_cpio(&wrapped).is_some());
    }

    #[test]
    fn rejects_malformed_archives_and_compressed_non_archives() {
        use std::io::Write;

        assert!(materialize(b"070701FAKEDATA").is_err());
        let mut bad = include_bytes!("../tests/data/initramfs.cpio").to_vec();
        bad[14] = b'!'; // invalid mode field
        assert!(materialize(&bad).is_err());
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"not a cpio archive").unwrap();
        assert!(materialize(&gzip.finish().unwrap()).is_err());
        for input in [
            include_bytes!("../tests/data/initramfs.cpio.gz").as_slice(),
            include_bytes!("../tests/data/initramfs.cpio.zst").as_slice(),
        ] {
            assert!(materialize(&input[..input.len() - 1]).is_err());
            let mut corrupt = input.to_vec();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(materialize(&corrupt).is_err());
            let mut trailing = input.to_vec();
            trailing.extend_from_slice(b"garbage");
            assert!(materialize(&trailing).is_err());
        }
    }

    #[test]
    fn materialize_rejects_truncated_elf_header() {
        // Has ELF magic but truncated before the rest of the header
        // can be parsed.
        let err = materialize(b"\x7fELF").unwrap_err();
        // Goblin returns a parse error; we just confirm it's not one
        // of the "accept" branches.
        assert!(matches!(err, InitrdError::ElfParse(_)));
    }
}
