// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PE/COFF (PE32+) writer.
//!
//! Emits a valid Microsoft Portable Executable that can be consumed
//! by a PMI-aware VMM (which reads sections by name + CBOR manifest
//! from `.pmi.vm`) and by UEFI as an EFI application stub (subsystem
//! = `IMAGE_SUBSYSTEM_EFI_APPLICATION`, though the actual entry point
//! is opaque to PMI consumers).
//!
//! We define the header structs directly (via zerocopy) rather than
//! pulling a third-party writer; the surface is small and the
//! structure is documented in the Microsoft PE/COFF spec.

use std::borrow::Cow;

use thiserror::Error;
use zerocopy::{Immutable, IntoBytes, KnownLayout};

// ---------------------------------------------------------------------------
// Public types.
// ---------------------------------------------------------------------------

/// A single PE section to emit.
///
/// `data` is `Cow<'a, [u8]>` so callers can pass `Cow::Borrowed`
/// over multi-MiB kernel / initrd buffers without forcing an extra
/// allocation. Small sections that arma synthesizes (DTB, CBOR
/// manifest, tatu sections after override) still pass `Cow::Owned`.
#[derive(Clone)]
pub(crate) struct Section<'a> {
    /// Name as it appears in the section table (max 8 bytes; longer
    /// names use a string-table entry, but PMI's spec-defined names
    /// all fit in 8 chars so we reject names that don't).
    pub(crate) name: String,
    /// Guest physical address (becomes `VirtualAddress` in the PE
    /// header).
    pub(crate) vaddr: u64,
    /// In-memory size.
    pub(crate) virtual_size: u64,
    /// On-disk bytes (empty for Zero/NOBITS sections).
    pub(crate) data: Cow<'a, [u8]>,
    /// PE characteristics flags (IMAGE_SCN_*).
    pub(crate) characteristics: u32,
    /// True for non-loaded sections like `.pmi.vm` whose
    /// `VirtualAddress` is conventionally 0.
    pub(crate) non_loaded: bool,
}

impl Section<'_> {
    pub(crate) fn is_zero_shape(&self) -> bool {
        self.data.is_empty()
    }
}

// Manual Debug: derive(Debug) would print every byte of `data`,
// which for a multi-MiB kernel section is gigabytes of hex output.
// Print just the byte count.
impl core::fmt::Debug for Section<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Section")
            .field("name", &self.name)
            .field("vaddr", &format_args!("{:#x}", self.vaddr))
            .field("virtual_size", &self.virtual_size)
            .field("data_len", &self.data.len())
            .field(
                "characteristics",
                &format_args!("{:#x}", self.characteristics),
            )
            .field("non_loaded", &self.non_loaded)
            .finish()
    }
}

// IMAGE_SCN_* flags (subset arma uses).
pub(crate) const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub(crate) const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub(crate) const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub(crate) const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub(crate) const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub(crate) const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// FileHeader Characteristics.
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;

const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const PE32PLUS_MAGIC: u16 = 0x020B;

// PE/COFF spec: file alignment & section alignment must both be powers of two,
// with section alignment ≥ file alignment, and file alignment ≥ 512.
// PMI's small-section rule is 4 KiB; we use 4 KiB as the PE-level
// FileAlignment, then individually bump LARGE sections' PointerToRawData
// up to 2 MiB per PMI granularity rules (4 KiB divides 2 MiB, so a
// 2 MiB-aligned offset is trivially a multiple of FileAlignment too).
const FILE_ALIGNMENT: u32 = 0x1000;
const SECTION_ALIGNMENT: u32 = 0x1000;

/// PMI LARGE-section threshold: sections whose payload is ≥ 2 MiB must
/// have `VirtualAddress`, `PointerToRawData`, and `SizeOfRawData` all
/// 2 MiB-aligned (see pmi/spec/granularity.md).
const LARGE_THRESHOLD: u64 = 2 * 1024 * 1024;
const LARGE_ALIGNMENT: u32 = 2 * 1024 * 1024;

/// True when this section is loaded into the guest and its on-disk
/// payload reaches the PMI LARGE threshold. LARGE sections need 2 MiB
/// alignment on both ends; SMALL sections (and non-loaded / zero-shape
/// sections) use the default 4 KiB alignment.
fn is_large_payload(s: &Section<'_>) -> bool {
    !s.non_loaded && !s.is_zero_shape() && s.data.len() as u64 >= LARGE_THRESHOLD
}

fn alignment_for(s: &Section<'_>) -> u32 {
    if is_large_payload(s) {
        LARGE_ALIGNMENT
    } else {
        FILE_ALIGNMENT
    }
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub(crate) enum PeError {
    #[error("section count {0} exceeds u16::MAX")]
    TooManySections(usize),
    #[error("offset overflow during PE layout")]
    Overflow,
    #[error("section name `{0}` contains a NUL byte")]
    NulInName(String),
    #[error(
        "COFF string-table offset {0} exceeds 7 decimal digits (cannot fit in 8-byte section name)"
    )]
    StringTableOffsetTooLarge(usize),
}

// ---------------------------------------------------------------------------
// Headers (PE32+).
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Copy, Clone, IntoBytes, Immutable, KnownLayout)]
struct DosHeader {
    e_magic: u16,
    pad: [u8; 58],
    e_lfanew: u32,
}

const DOS_SIZE: usize = core::mem::size_of::<DosHeader>();

const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";

#[repr(C, packed)]
#[derive(Copy, Clone, IntoBytes, Immutable, KnownLayout)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

const COFF_SIZE: usize = core::mem::size_of::<CoffHeader>();

#[repr(C, packed)]
#[derive(Copy, Clone, IntoBytes, Immutable, KnownLayout)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

const NUM_DATA_DIRECTORIES: usize = 16;

#[repr(C, packed)]
#[derive(Copy, Clone, IntoBytes, Immutable, KnownLayout)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directories: [DataDirectory; NUM_DATA_DIRECTORIES],
}

const OPT_SIZE: usize = core::mem::size_of::<OptionalHeader64>();

#[repr(C, packed)]
#[derive(Copy, Clone, IntoBytes, Immutable, KnownLayout)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

const SECTION_HDR_SIZE: usize = core::mem::size_of::<SectionHeader>();

// ---------------------------------------------------------------------------
// Image-base selection.
//
// We make the PE's ImageBase = 0 so each section's RVA (which is a
// u32 in the section header) equals its absolute GPA. PMI section
// GPAs all live in the first 4 GiB on x86 and within the qemu/virt
// RAM window on aarch64; both fit in u32.
//
// Some sections may exceed u32 (e.g., aarch64 layouts could exceed
// 4 GiB in theory). We assert in the writer; the layout pass already
// enforces the 4 GiB ceiling on x86 and arma's MVP layout is well
// inside u32 on both arches.
// ---------------------------------------------------------------------------

const IMAGE_BASE: u64 = 0;

// ---------------------------------------------------------------------------
// Writer.
// ---------------------------------------------------------------------------

pub(crate) fn build_pe(machine: u16, sections: &[Section<'_>]) -> Result<Vec<u8>, PeError> {
    if sections.len() > u16::MAX as usize {
        return Err(PeError::TooManySections(sections.len()));
    }
    for s in sections {
        if s.name.as_bytes().contains(&0) {
            return Err(PeError::NulInName(s.name.clone()));
        }
    }

    // Build the COFF string table for long section names. Names ≤ 8
    // bytes go inline in the section header; longer names are stored
    // in the string table and the section header carries `/N` where N
    // is the decimal byte offset into the string table.
    //
    // Format:
    //   u32 LE total-size-of-string-table (includes this size field)
    //   sequence of NUL-terminated strings
    let mut strtab: Vec<u8> = Vec::new();
    strtab.extend_from_slice(&0u32.to_le_bytes()); // placeholder for size
    let mut name_fields: Vec<[u8; 8]> = Vec::with_capacity(sections.len());
    for s in sections {
        let n = s.name.as_bytes();
        let mut field = [0u8; 8];
        if n.len() <= 8 {
            field[..n.len()].copy_from_slice(n);
        } else {
            let off = strtab.len();
            strtab.extend_from_slice(n);
            strtab.push(0);
            let s = format!("/{off}");
            let sb = s.as_bytes();
            // Must fit in 8 bytes; offsets up to /9999999 (7 digits) do
            // — string table grows past 10 MB before that becomes an
            // issue, and arma never produces PMIs that large.
            if sb.len() > 8 {
                return Err(PeError::StringTableOffsetTooLarge(off));
            }
            field[..sb.len()].copy_from_slice(sb);
        }
        name_fields.push(field);
    }
    // Patch the size prefix.
    let strtab_len = strtab.len() as u32;
    strtab[..4].copy_from_slice(&strtab_len.to_le_bytes());
    let need_strtab = strtab.len() > 4;

    // Compute header size (e_lfanew + signature + coff + opt + section headers),
    // then round up to FILE_ALIGNMENT.
    let pe_offset: u32 = align_up_u32(DOS_SIZE as u32, 8).ok_or(PeError::Overflow)?;
    let headers_end = pe_offset as usize
        + PE_SIGNATURE.len()
        + COFF_SIZE
        + OPT_SIZE
        + sections.len() * SECTION_HDR_SIZE;
    let headers_end_u32 = u32::try_from(headers_end).map_err(|_| PeError::Overflow)?;
    let size_of_headers = align_up_u32(headers_end_u32, FILE_ALIGNMENT).ok_or(PeError::Overflow)?;

    // Assign on-disk offsets to sections in declaration order. Zero-shape
    // sections get PointerToRawData=0 and SizeOfRawData=0; non-loaded
    // sections (.pmi.vm) also need raw data written so the VMM can read
    // them from the file.
    let mut cursor: u32 = size_of_headers;
    let mut raw_offsets: Vec<u32> = Vec::with_capacity(sections.len());
    let mut raw_sizes: Vec<u32> = Vec::with_capacity(sections.len());

    for s in sections {
        if s.is_zero_shape() {
            raw_offsets.push(0);
            raw_sizes.push(0);
        } else {
            // Align the section *start* (PointerToRawData) to its required
            // boundary: 4 KiB for SMALLs / non-loaded, 2 MiB for LARGEs so a VMM
            // can hand whole 2 MiB chunks to the copy (PMI granularity). The
            // *size* (SizeOfRawData) follows FILE_ALIGNMENT only — the actual data
            // extent, never padded up to 2 MiB. The granularity spec constrains
            // only the start; a LARGE's sub-2 MiB tail loads at 4 KiB. Padding the
            // size would bloat the file with zeros the Padded shape already
            // supplies via VirtualSize.
            let align = alignment_for(s);
            cursor = align_up_u32(cursor, align).ok_or(PeError::Overflow)?;
            let data_len_u32: u32 = u32::try_from(s.data.len()).map_err(|_| PeError::Overflow)?;
            let raw_size = align_up_u32(data_len_u32, FILE_ALIGNMENT).ok_or(PeError::Overflow)?;
            raw_offsets.push(cursor);
            raw_sizes.push(raw_size);
            cursor = cursor.checked_add(raw_size).ok_or(PeError::Overflow)?;
        }
    }

    // String table (if needed) goes at the end of the file. Per
    // PE/COFF spec: when NumberOfSymbols = 0, the string table starts
    // at `PointerToSymbolTable` (interpreted as the string-table
    // offset since the symbol table is empty).
    let strtab_offset: u32 = if need_strtab {
        let off = cursor;
        let strtab_len_u32: u32 = u32::try_from(strtab.len()).map_err(|_| PeError::Overflow)?;
        cursor = cursor
            .checked_add(strtab_len_u32)
            .ok_or(PeError::Overflow)?;
        off
    } else {
        0
    };
    let file_size = cursor;

    // SizeOfImage = max(VirtualAddress + ceil(VirtualSize, SECTION_ALIGNMENT))
    // for all sections that are loaded. .pmi.vm is non_loaded so we skip it.
    //
    // PMI consumers walk per-section `VirtualAddress` and do NOT read
    // SizeOfImage. The field is informational here; we still compute
    // it best-effort and cap at u32::MAX when sections like x86's
    // reset trampoline (at GPA 0xFFFFF000) overflow the u32 the field
    // occupies in PE32+.
    let mut size_of_image: u64 = u64::from(size_of_headers);
    for s in sections {
        if s.non_loaded {
            continue;
        }
        let end = s
            .vaddr
            .saturating_add(align_up_u64(s.virtual_size, u64::from(SECTION_ALIGNMENT)));
        if end > size_of_image {
            size_of_image = end;
        }
    }
    let size_of_image: u32 = align_up_u64(size_of_image, u64::from(SECTION_ALIGNMENT))
        .min(u64::from(u32::MAX))
        .try_into()
        .unwrap_or(u32::MAX);

    // Compose the byte buffer.
    let mut buf = vec![0u8; file_size as usize];

    // DOS header.
    let dos = DosHeader {
        e_magic: 0x5A4D, // "MZ"
        pad: [0u8; 58],
        e_lfanew: pe_offset,
    };
    buf[..DOS_SIZE].copy_from_slice(dos.as_bytes());

    // PE signature.
    let mut off = pe_offset as usize;
    buf[off..off + 4].copy_from_slice(&PE_SIGNATURE);
    off += 4;

    // COFF header.
    let aligned_data_size = |s: &Section<'_>| -> Result<u32, PeError> {
        let len = u32::try_from(s.data.len()).map_err(|_| PeError::Overflow)?;
        align_up_u32(len, alignment_for(s)).ok_or(PeError::Overflow)
    };
    let mut size_of_code: u32 = 0;
    let mut size_of_init_data: u32 = 0;
    let mut size_of_uninit_data: u32 = 0;
    for s in sections {
        if s.characteristics & IMAGE_SCN_CNT_CODE != 0 {
            size_of_code = size_of_code
                .checked_add(aligned_data_size(s)?)
                .ok_or(PeError::Overflow)?;
        }
        if s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            size_of_init_data = size_of_init_data
                .checked_add(aligned_data_size(s)?)
                .ok_or(PeError::Overflow)?;
        }
        if s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            let vsz = u32::try_from(s.virtual_size).map_err(|_| PeError::Overflow)?;
            let aligned = align_up_u32(vsz, SECTION_ALIGNMENT).ok_or(PeError::Overflow)?;
            size_of_uninit_data = size_of_uninit_data
                .checked_add(aligned)
                .ok_or(PeError::Overflow)?;
        }
    }

    let coff = CoffHeader {
        machine,
        number_of_sections: sections.len() as u16,
        time_date_stamp: 0,
        pointer_to_symbol_table: strtab_offset, // string table when NumberOfSymbols=0
        number_of_symbols: 0,
        size_of_optional_header: OPT_SIZE as u16,
        characteristics: IMAGE_FILE_EXECUTABLE_IMAGE
            | IMAGE_FILE_LARGE_ADDRESS_AWARE
            | IMAGE_FILE_DEBUG_STRIPPED,
    };
    buf[off..off + COFF_SIZE].copy_from_slice(coff.as_bytes());
    off += COFF_SIZE;

    // Optional header.
    let opt = OptionalHeader64 {
        magic: PE32PLUS_MAGIC,
        major_linker_version: 1,
        minor_linker_version: 0,
        size_of_code,
        size_of_initialized_data: size_of_init_data,
        size_of_uninitialized_data: size_of_uninit_data,
        address_of_entry_point: 0, // Not used by PMI consumers.
        base_of_code: 0,
        image_base: IMAGE_BASE,
        section_alignment: SECTION_ALIGNMENT,
        file_alignment: FILE_ALIGNMENT,
        major_os_version: 0,
        minor_os_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 0,
        minor_subsystem_version: 0,
        win32_version_value: 0,
        size_of_image,
        size_of_headers,
        checksum: 0,
        subsystem: IMAGE_SUBSYSTEM_EFI_APPLICATION,
        dll_characteristics: 0,
        size_of_stack_reserve: 0,
        size_of_stack_commit: 0,
        size_of_heap_reserve: 0,
        size_of_heap_commit: 0,
        loader_flags: 0,
        number_of_rva_and_sizes: NUM_DATA_DIRECTORIES as u32,
        data_directories: [DataDirectory {
            virtual_address: 0,
            size: 0,
        }; NUM_DATA_DIRECTORIES],
    };
    buf[off..off + OPT_SIZE].copy_from_slice(opt.as_bytes());
    off += OPT_SIZE;

    // Section headers.
    for (i, s) in sections.iter().enumerate() {
        let name_bytes = name_fields[i];

        let vaddr32: u32 = if s.non_loaded {
            0
        } else {
            s.vaddr.try_into().map_err(|_| PeError::Overflow)?
        };
        // PMI core §"Section Shapes" allows three shapes for loaded
        // sections:
        //   Data    VirtualSize == SizeOfRawData
        //   Padded  VirtualSize >  SizeOfRawData
        //   Zero    SizeOfRawData == 0, VirtualSize > 0
        //
        // For a section with on-disk payload, the natural VirtualSize
        // (= data.len() pre-padding) is typically smaller than the
        // aligned SizeOfRawData. Bump VirtualSize up to SizeOfRawData
        // so the section is the spec-compliant Data shape — VMMs can
        // then mmap raw_size bytes from PointerToRawData and hand
        // them directly to KVM with no zero-fill work, enabling
        // effortless zero-copy huge-page mapping for LARGEs and
        // standard 4 KiB-page mapping for SMALLs.
        //
        // Non-loaded sections (.pmi.vm) and zero-shape sections
        // (.tatu.bss, .dtbo) are not constrained by the shape rules;
        // emit their natural VirtualSize as-is.
        let natural_vsize: u32 = s.virtual_size.try_into().map_err(|_| PeError::Overflow)?;
        let vsize32: u32 = if s.non_loaded || s.is_zero_shape() {
            natural_vsize
        } else {
            natural_vsize.max(raw_sizes[i])
        };

        let hdr = SectionHeader {
            name: name_bytes,
            virtual_size: vsize32,
            virtual_address: vaddr32,
            size_of_raw_data: raw_sizes[i],
            pointer_to_raw_data: raw_offsets[i],
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: s.characteristics,
        };
        buf[off..off + SECTION_HDR_SIZE].copy_from_slice(hdr.as_bytes());
        off += SECTION_HDR_SIZE;
    }

    // Section raw data.
    for (i, s) in sections.iter().enumerate() {
        if s.is_zero_shape() {
            continue;
        }
        let start = raw_offsets[i] as usize;
        let end = start + s.data.len();
        buf[start..end].copy_from_slice(&s.data);
        // Pad in buf is already zero from initial vec![0; ...].
    }

    // String table (if any).
    if need_strtab {
        let start = strtab_offset as usize;
        let end = start + strtab.len();
        buf[start..end].copy_from_slice(&strtab);
    }

    Ok(buf)
}

fn align_up_u32(v: u32, a: u32) -> Option<u32> {
    debug_assert!(a.is_power_of_two());
    let mask = a - 1;
    v.checked_add(mask).map(|x| x & !mask)
}

fn align_up_u64(v: u64, a: u64) -> u64 {
    debug_assert!(a.is_power_of_two());
    let mask = a - 1;
    v.saturating_add(mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pe_has_correct_magic_and_minimal_size() {
        let bytes = build_pe(0x8664, &[]).unwrap();
        assert_eq!(&bytes[..2], b"MZ");
        let e_lfanew = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
        assert_eq!(&bytes[e_lfanew..e_lfanew + 4], b"PE\0\0");
        let machine = u16::from_le_bytes(bytes[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
        assert_eq!(machine, 0x8664);
    }

    #[test]
    fn single_data_section_round_trip() {
        let payload = b"hello arma".to_vec();
        let sec = Section {
            name: ".test".into(),
            vaddr: 0x10_0000,
            virtual_size: payload.len() as u64,
            data: Cow::Owned(payload.clone()),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            non_loaded: false,
        };
        let bytes = build_pe(0x8664, &[sec]).unwrap();
        // Parse-back via goblin and confirm section contents.
        let pe = goblin::pe::PE::parse(&bytes).expect("parse PE");
        assert_eq!(pe.header.coff_header.machine, 0x8664);
        assert_eq!(pe.sections.len(), 1);
        let s = &pe.sections[0];
        assert_eq!(s.virtual_address, 0x10_0000);
        let raw_off = s.pointer_to_raw_data as usize;
        let raw_size = s.size_of_raw_data as usize;
        // The first `payload.len()` bytes of raw data equal the input.
        assert_eq!(&bytes[raw_off..raw_off + payload.len()], &payload[..]);
        // Remainder is alignment padding (zero).
        assert!(
            bytes[raw_off + payload.len()..raw_off + raw_size]
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn zero_shape_section_has_no_raw_data() {
        let sec = Section {
            name: ".dtbo".into(),
            vaddr: 0x20_0000,
            virtual_size: 0x10000,
            data: Cow::Borrowed(&[]),
            characteristics: IMAGE_SCN_CNT_UNINITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
            non_loaded: false,
        };
        let bytes = build_pe(0x8664, &[sec]).unwrap();
        let pe = goblin::pe::PE::parse(&bytes).expect("parse PE");
        let s = &pe.sections[0];
        assert_eq!(s.size_of_raw_data, 0);
        assert_eq!(s.pointer_to_raw_data, 0);
        assert_eq!(s.virtual_size, 0x10000);
    }

    /// A section whose virtual_size exceeds u32::MAX must reject
    /// cleanly via PeError::Overflow, not silently truncate to a
    /// nonsense PE.
    #[test]
    fn rejects_virtual_size_overflowing_u32() {
        let sec = Section {
            name: ".bigz".into(),
            vaddr: 0,
            virtual_size: u64::from(u32::MAX) + 1,
            data: Cow::Borrowed(&[]),
            characteristics: IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            non_loaded: false,
        };
        let r = build_pe(0x8664, &[sec]);
        assert!(matches!(r, Err(PeError::Overflow)));
    }

    #[test]
    fn rejects_section_name_with_nul_byte() {
        let sec = Section {
            name: "\0bad".into(),
            vaddr: 0,
            virtual_size: 0,
            data: Cow::Borrowed(&[]),
            characteristics: 0,
            non_loaded: false,
        };
        let r = build_pe(0x8664, &[sec]);
        assert!(matches!(r, Err(PeError::NulInName(_))));
    }

    #[test]
    fn non_loaded_section_has_zero_vaddr() {
        let payload = b"cbor data".to_vec();
        let sec = Section {
            name: ".pmi.vm".into(),
            vaddr: 0,
            virtual_size: payload.len() as u64,
            data: Cow::Owned(payload.clone()),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_DISCARDABLE,
            non_loaded: true,
        };
        let bytes = build_pe(0xAA64, &[sec]).unwrap();
        let pe = goblin::pe::PE::parse(&bytes).expect("parse PE");
        let s = &pe.sections[0];
        assert_eq!(s.virtual_address, 0);
        assert!(s.characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0);
    }
}
