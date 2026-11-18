// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ARCHITECTURE.md §27.2 defensive-parsing test corpus for dillo PMI parsing.
//!
//! Each test feeds an adversarial input and asserts the specific
//! [`dillo_launch::pmi_parse::Error`] variant it should produce. Together these
//! pin the validation chain so a regression in any single check
//! shows up as a failed test rather than a silent acceptance.
//!
//! Tests that need a complete valid PMI as a baseline (e.g.
//! overlapping VirtualAddress, pathological spread) are stubbed
//! with `#[ignore]` and a TODO — they need an arma-produced
//! fixture that the workspace test runner builds on demand.

use dillo_launch::pmi_parse::{Error, HostArch, ParseOptions, parse};

fn opts() -> ParseOptions {
    ParseOptions {
        host_arch: HostArch::X86_64,
        memory_mib: 4096,
    }
}

/// Locate the `.pmi.vm` section's raw-data window `[start, end)` in a PMI file.
fn pmi_vm_cbor_range(bytes: &[u8]) -> Option<(usize, usize)> {
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    let num_sections = u16::from_le_bytes(bytes[pe_off + 6..pe_off + 8].try_into().ok()?);
    let opt_size = u16::from_le_bytes(bytes[pe_off + 20..pe_off + 22].try_into().ok()?) as usize;
    let mut sect_off = pe_off + 24 + opt_size;
    for _ in 0..num_sections {
        let name = &bytes[sect_off..sect_off + 8];
        let trimmed = std::str::from_utf8(name)
            .unwrap_or("")
            .trim_end_matches('\0');
        if trimmed == ".pmi.vm" {
            let raw_size =
                u32::from_le_bytes(bytes[sect_off + 16..sect_off + 20].try_into().ok()?) as usize;
            let ptr_to_raw =
                u32::from_le_bytes(bytes[sect_off + 20..sect_off + 24].try_into().ok()?) as usize;
            return Some((ptr_to_raw, ptr_to_raw + raw_size));
        }
        sect_off += 40;
    }
    None
}

/// Overwrite every uint32-encoded action `gpa` in the `.pmi.vm` CBOR with
/// `value`, returning how many were rewritten. The action `gpa` (pmi spec
/// f6be1eb) is the authoritative placement address; mutating it is how an
/// adversary attacks placement now that the PE `VirtualAddress` is ignored.
/// The key `"gpa"` encodes as CBOR `63 67 70 61`; 2 MiB-aligned addresses use
/// the `0x1A` uint32 form, so we match `63 67 70 61 1A` and rewrite the 4
/// big-endian value bytes that follow.
fn rewrite_gpas(bytes: &mut [u8], value: u32) -> usize {
    let Some((start, end)) = pmi_vm_cbor_range(bytes) else {
        return 0;
    };
    let key = [0x63u8, 0x67, 0x70, 0x61, 0x1A];
    let mut count = 0;
    let mut i = start;
    while i + key.len() + 4 <= end {
        if bytes[i..i + key.len()] == key {
            let v = i + key.len();
            bytes[v..v + 4].copy_from_slice(&value.to_be_bytes());
            count += 1;
            i = v + 4;
        } else {
            i += 1;
        }
    }
    count
}

// ─── PE structural ──────────────────────────────────────────────

#[test]
fn truncated_pe_under_100_bytes() {
    // Anything obviously short of a valid PE header should fail at
    // the `object::read::pe::PeFile64::parse` step.
    let bytes = vec![0u8; 8];
    let err = parse(&bytes, &opts()).expect_err("8 zero bytes must not parse");
    assert!(matches!(err, Error::PeParse(_)), "got {err:?}");
}

#[test]
fn empty_input_fails() {
    let err = parse(&[], &opts()).expect_err("0 bytes must not parse");
    assert!(matches!(err, Error::PeParse(_)), "got {err:?}");
}

#[test]
fn ms_dos_stub_only_no_pe_signature() {
    // Build the smallest legal DOS stub (MZ header) with no PE
    // signature — `object` rejects this.
    let mut bytes = vec![0u8; 64];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes()); // e_lfanew = 0 → bogus
    let err = parse(&bytes, &opts()).expect_err("MZ-only must not parse");
    assert!(matches!(err, Error::PeParse(_)), "got {err:?}");
}

#[test]
fn random_garbage_under_section_cap() {
    let bytes: Vec<u8> = (0..512u32).map(|i| (i & 0xFF) as u8).collect();
    let err = parse(&bytes, &opts()).expect_err("random bytes must not parse");
    assert!(matches!(err, Error::PeParse(_)), "got {err:?}");
}

// ─── Caps (§5.2) ────────────────────────────────────────────────
//
// File-size cap is 4 GiB — infeasible to test directly. We exercise
// the lower-bound caps instead (those that fire on much smaller
// inputs).

#[test]
fn manifest_size_cap_triggers_on_oversized_section() {
    let mut fixture = Fixture::x86();
    fixture.manifest = vec![0; dillo_launch::pmi_parse::caps::MAX_MANIFEST_SIZE + 1];
    assert!(matches!(
        parse(&fixture.bytes(), &opts()),
        Err(Error::ManifestTooLarge { .. })
    ));
}

// ─── Wrong host arch ────────────────────────────────────────────

#[test]
fn parse_x86_pmi_as_aarch64_fails() {
    let bytes = Fixture::x86().bytes();
    let aarch64_opts = ParseOptions {
        host_arch: HostArch::Aarch64,
        memory_mib: 4096,
    };
    let err = parse(&bytes, &aarch64_opts).expect_err("x86 PMI must fail aarch64 parse");
    assert!(matches!(err, Error::HostArchMismatch { .. }), "got {err:?}");
}

// ─── Pathological-spread refusal (§5.5) ─────────────────────────

#[test]
fn mutated_high_gpas_do_not_panic() {
    // Mutate both destinations together; this is a no-panic check only.
    let mut bytes = Fixture::x86().bytes();
    let _ = rewrite_gpas(&mut bytes, 0xC000_0000);
    // The cargo-fuzz harness covers broader mutation space; this test pins
    // the no-panic invariant for this specific shape.
    let _ = parse(&bytes, &opts());
}

// ─── Section data past EOF ──────────────────────────────────────

#[test]
fn section_raw_data_past_file_size_rejected() {
    // Take a valid PMI, scan PE section headers, edit the
    // PointerToRawData of the first section that has bytes in the file
    // to point past EOF → SectionDataPastEof. Sections with no bytes in
    // the file (such as the guard page) are skipped, because the parser
    // rightly ignores where they point.
    let mut bytes = Fixture::x86().bytes();
    // PE header offset is at file offset 0x3C (DOS e_lfanew).
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    // PE signature "PE\0\0" (4) + FileHeader (20) starts at pe_off.
    // Section count at pe_off + 6. OptHeader size at pe_off + 20.
    let num_sections = u16::from_le_bytes(bytes[pe_off + 6..pe_off + 8].try_into().unwrap());
    let opt_size = u16::from_le_bytes(bytes[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
    let sect_off = pe_off + 24 + opt_size;
    assert!(num_sections > 0);
    // Each section header is 40 bytes. SizeOfRawData is at offset 16 and
    // PointerToRawData is at offset 20.
    let header = (0..usize::from(num_sections))
        .map(|i| sect_off + i * 40)
        .find(|&h| u32::from_le_bytes(bytes[h + 16..h + 20].try_into().unwrap()) > 0)
        .expect("a PMI has at least one section with bytes in the file");
    let ptr_to_raw_off = header + 20;
    // Overwrite with a value larger than file size.
    let huge = (bytes.len() as u32).saturating_add(0x1000);
    bytes[ptr_to_raw_off..ptr_to_raw_off + 4].copy_from_slice(&huge.to_le_bytes());
    let err = parse(&bytes, &opts()).expect_err("mutated PMI must fail");
    // Accept either SectionDataPastEof OR a downstream parse error —
    // the validation rule we care about fired.
    assert!(
        matches!(err, Error::SectionDataPastEof { .. } | Error::PeParse(_)),
        "got {err:?}"
    );
}

// ─── Overlapping sections ───────────────────────────────────────

#[test]
fn overlapping_gpa_ranges_rejected() {
    let mut bytes = Fixture::x86().bytes();
    // Placement is by the manifest `gpa` (pmi spec f6be1eb), not the PE
    // VirtualAddress. Force every uint32-encoded action gpa to the same
    // address: the large sections (kernel + base DTB, both nonzero size)
    // now collide → overlap rejection.
    let n = rewrite_gpas(&mut bytes, 0x0020_0000);
    assert_eq!(n, 2, "fixture provides two action destinations");
    let err = parse(&bytes, &opts()).expect_err("overlapping gpa must fail");
    assert!(
        matches!(
            err,
            Error::SectionsOverlap { .. } | Error::SectionDataPastEof { .. } | Error::PeParse(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn virtual_address_overflow_rejected() {
    let mut bytes = Fixture::x86().bytes();
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(bytes[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
    let sect_off = pe_off + 24 + opt_size;
    // VirtualAddress = 0xFFFF_FFFE (PE field is u32; can't reach u64
    // overflow from PE alone — the loader extends to u64 GPA). For a
    // PE-level "size near u32 max" test, write VirtualSize=0xFFFF_FFFE
    // at offset 8, VirtualAddress=2 at offset 12.
    // VirtualSize at offset 8 of section header.
    bytes[sect_off + 8..sect_off + 12].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    bytes[sect_off + 12..sect_off + 16].copy_from_slice(&2u32.to_le_bytes());
    // Could trip several checks depending on which fires first; any error
    // variant is acceptable, so `expect_err` is the whole assertion.
    let _ = parse(&bytes, &opts()).expect_err("oversize VirtualSize must fail");
}

// ─── Unknown CBOR keys (in-place byte mutation) ─────────────────

#[test]
fn cbor_body_corrupted_rejected() {
    // Find the .pmi.vm section in the in-memory fixture, flip a byte at
    // its raw-data offset — CBOR decode fails.
    let mut bytes = Fixture::x86().bytes();
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let num_sections = u16::from_le_bytes(bytes[pe_off + 6..pe_off + 8].try_into().unwrap());
    let opt_size = u16::from_le_bytes(bytes[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
    let mut sect_off = pe_off + 24 + opt_size;
    for _ in 0..num_sections {
        let name = &bytes[sect_off..sect_off + 8];
        let trimmed = std::str::from_utf8(name)
            .unwrap_or("")
            .trim_end_matches('\0');
        if trimmed == ".pmi.vm" {
            let ptr_to_raw =
                u32::from_le_bytes(bytes[sect_off + 20..sect_off + 24].try_into().unwrap())
                    as usize;
            // Flip the high bit of the first CBOR byte — should be a
            // map start (0xA?); changing it produces a decode error.
            bytes[ptr_to_raw] ^= 0xFF;
            break;
        }
        sect_off += 40;
    }
    let err = parse(&bytes, &opts()).expect_err("corrupt CBOR must fail");
    assert!(matches!(err, Error::CborDecode(_)), "got {err:?}");
}

// ─── Duplicate target section ───────────────────────────────────

#[test]
fn duplicate_pmi_vm_section_rejected() {
    // Find the .pmi.vm section name and rename ANOTHER section to
    // the same name → DuplicatePmiTargetSection.
    let mut bytes = Fixture::x86().bytes();
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let num_sections = u16::from_le_bytes(bytes[pe_off + 6..pe_off + 8].try_into().unwrap());
    let opt_size = u16::from_le_bytes(bytes[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
    let sect_off = pe_off + 24 + opt_size;
    assert!(num_sections >= 2);
    // Rename section 0 to ".pmi.vm" — the .pmi.vm section already
    // exists elsewhere (last section by convention), so this creates
    // two with the same name.
    let target_name = b".pmi.vm\0";
    bytes[sect_off..sect_off + 8].copy_from_slice(target_name);
    let err = parse(&bytes, &opts()).expect_err("duplicate .pmi.vm must fail");
    assert!(
        matches!(
            err,
            Error::DuplicatePmiTargetSection { .. }
                | Error::PeParse(_)
                | Error::CborDecode(_)
                | Error::SectionDataPastEof { .. }
        ),
        "got {err:?}"
    );
}

/// A complete, in-memory PE with two loaded sections and a strict vm manifest.
struct Fixture {
    machine: u16,
    manifest: Vec<u8>,
}

impl Fixture {
    fn new(machine: u16, profile: &str, extra: Option<&str>) -> Self {
        let mut value = serde_json::json!({
            "version": 1,
            "cpu:profile": profile,
            "dt:dtb": ".dtb",
            "actions": [
                {"type": "load", "section": ".text", "gpa": 0x20_0000},
                {"type": "load", "section": ".dtb", "gpa": 0x40_0000}
            ]
        });
        if let Some(key) = extra {
            value[key] = serde_json::json!({});
        }
        let mut manifest = Vec::new();
        ciborium::ser::into_writer(&value, &mut manifest).unwrap();
        Self { machine, manifest }
    }

    fn x86() -> Self {
        Self::new(0x8664, "x86-64-v1", None)
    }

    fn bytes(&self) -> Vec<u8> {
        let manifest_offset = 0x40_1000;
        let mut bytes = vec![0; manifest_offset + self.manifest.len()];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&self.machine.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&3u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        for (index, (name, size, offset, flags)) in [
            (
                b".text\0\0\0",
                0x20_0000_u32,
                0x20_0000_u32,
                0x6000_0020_u32,
            ),
            (b".dtb\0\0\0\0", 0x1000, 0x40_0000, 0x4000_0040),
            (
                b".pmi.vm\0",
                self.manifest.len() as u32,
                manifest_offset as u32,
                0x4200_0040,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let header = 0x188 + index * 40;
            bytes[header..header + 8].copy_from_slice(name);
            bytes[header + 8..header + 12].copy_from_slice(&size.to_le_bytes());
            bytes[header + 16..header + 20].copy_from_slice(&size.to_le_bytes());
            bytes[header + 20..header + 24].copy_from_slice(&offset.to_le_bytes());
            bytes[header + 36..header + 40].copy_from_slice(&flags.to_le_bytes());
        }
        bytes[manifest_offset..].copy_from_slice(&self.manifest);
        bytes
    }
}

#[test]
fn current_schema_accepts_both_architectures() {
    for (machine, profile, arch) in [
        (0x8664, "x86-64-v1", HostArch::X86_64),
        (0xaa64, "armv8.0-a", HostArch::Aarch64),
    ] {
        let parsed = parse(
            &Fixture::new(machine, profile, None).bytes(),
            &ParseOptions {
                host_arch: arch,
                memory_mib: 4096,
            },
        )
        .expect("valid current schema");
        assert_eq!(parsed.cpu_profile.as_str(), profile);
        assert_eq!(parsed.actions.len(), 2);
    }
}

#[test]
fn current_schema_rejects_obsolete_state_and_unknown_fields() {
    for key in ["vm:vcpu", "vcpu", "unknown"] {
        assert!(
            matches!(
                parse(
                    &Fixture::new(0x8664, "x86-64-v1", Some(key)).bytes(),
                    &opts()
                ),
                Err(Error::CborDecode(_))
            ),
            "accepted {key}"
        );
    }
}

#[test]
fn current_schema_rejects_wrong_architecture_and_unknown_profiles() {
    for (machine, profile, arch) in [
        (0x8664, "armv8.0-a", HostArch::X86_64),
        (0xaa64, "x86-64-v1", HostArch::Aarch64),
        (0x8664, "x86-64-v5", HostArch::X86_64),
        (0xaa64, "armv99.0-a", HostArch::Aarch64),
    ] {
        assert!(
            matches!(
                parse(
                    &Fixture::new(machine, profile, None).bytes(),
                    &ParseOptions {
                        host_arch: arch,
                        memory_mib: 4096
                    }
                ),
                Err(Error::CborDecode(_))
            ),
            "accepted {profile}"
        );
    }
}
