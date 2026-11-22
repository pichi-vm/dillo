// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Target-neutral launch support for the dillo binary.

pub mod pmi_parse {
    //! `PMI` loader for dillo.
    //!
    //! Parses a `PMI` file (PE + per-target CBOR manifest in `.pmi.<target>`),
    //! enforces dillo's defensive resource caps, validates spec-mandated and
    //! beyond-spec rules, and produces a [`ParsedPmi`] describing what to
    //! load and where.

    pub mod caps {

        /// Maximum PMI file size: 4 GiB.
        pub const MAX_FILE_SIZE: u64 = 4 << 30;

        /// Maximum `.pmi.<target>` manifest size: 4 KiB.
        pub const MAX_MANIFEST_SIZE: usize = 4 << 10;

        /// Maximum PE section count.
        pub const MAX_SECTION_COUNT: usize = 64;

        /// Maximum PE section name length (bytes).
        pub const MAX_SECTION_NAME_LEN: usize = 64;

        /// Absolute cap on sum of `load` action `VirtualSize` bytes.
        ///
        /// The effective cap is `min(memory_mib * MiB, MAX_TOTAL_LOADED_HARD)`.
        pub const MAX_TOTAL_LOADED_HARD: u64 = 16 << 30;

        /// `.dtbo` reservation: minimum size.
        pub const DTBO_MIN_SIZE: u64 = 4 << 10;

        /// `.dtbo` reservation: maximum size.
        pub const DTBO_MAX_SIZE: u64 = 64 << 10;

        /// CBOR maximum nesting depth.
        pub const CBOR_MAX_DEPTH: usize = 8;

        /// CBOR maximum entries in any array (e.g., `actions`).
        ///
        /// Enforced indirectly via [`MAX_MANIFEST_SIZE`] (a 4 KiB CBOR map cannot
        /// contain more than ~64 actions worth of payload). Also re-checked at
        /// the typed-Spec level.
        pub const CBOR_MAX_ARRAY_LEN: usize = 64;

        /// 2 MiB huge-page granularity (large-section alignment + backing).
        pub const HUGE_PAGE: u64 = 2 << 20;

        /// 4 KiB small-section alignment.
        pub const SMALL_PAGE: u64 = 4 << 10;

        /// Inflation-ratio multiplier for the pathological-spread refusal.
        ///
        /// `footprint_2mib * HUGE_PAGE > N * sum(load sizes)` triggers refusal.
        pub const SPREAD_INFLATION_RATIO: u64 = 4;
    }

    use thiserror::Error;

    /// Every failure mode dillo PMI parsing can produce. All errors map to exit
    /// code 10 (PMI parse / validation error) at the binary level.
    #[derive(Debug, Error)]
    pub enum Error {
        // ─── Resource caps (§5.2) ────────────────────────────────────
        #[error("PMI file size {actual} bytes exceeds cap of {cap} bytes")]
        FileTooLarge { actual: u64, cap: u64 },

        #[error("manifest size {actual} bytes exceeds cap of {cap} bytes for section `{section}`")]
        ManifestTooLarge {
            section: String,
            actual: usize,
            cap: usize,
        },

        #[error("PE has {actual} sections; cap is {cap}")]
        TooManySections { actual: usize, cap: usize },

        #[error("PE section name `{name}` ({len} bytes) exceeds cap of {cap} bytes")]
        SectionNameTooLong {
            name: String,
            len: usize,
            cap: usize,
        },

        #[error(
            "sum of loaded VirtualSize ({actual} bytes) exceeds cap of {cap} bytes \
             (effective cap = min(--memory, hard cap))"
        )]
        LoadedBytesExceedMemory { actual: u64, cap: u64 },

        #[error(
            ".dtbo section size {actual} bytes is outside the accepted range \
             [{min}, {max}]"
        )]
        DtboSizeOutOfRange { actual: u64, min: u64, max: u64 },

        // ─── PE structural ──────────────────────────────────────────
        #[error("PE parse failed: {0}")]
        PeParse(String),

        #[error("PE FileHeader.Machine {actual:#06x} does not match host arch {expected:#06x}")]
        HostArchMismatch { actual: u16, expected: u16 },

        #[error(
            "section `{name}` raw data range [{offset}..{end}) extends past file size {file_size}"
        )]
        SectionDataPastEof {
            name: String,
            offset: u64,
            end: u64,
            file_size: u64,
        },

        #[error("load section `{0}` requires 0 < VirtualSize and SizeOfRawData <= VirtualSize")]
        InvalidLoadSize(String),

        #[error("section `{name}`: guest backing range overflows u64")]
        VirtualAddressOverflow { name: String },

        #[error("sections `{a}` and `{b}` overlap in [gpa, gpa + VirtualSize)")]
        SectionsOverlap { a: String, b: String },

        #[error(
            "section `{name}` VirtualSize {virtual_size} fails alignment requirement \
             ({rule})"
        )]
        AlignmentViolation {
            name: String,
            virtual_size: u64,
            rule: &'static str,
        },

        #[error("multiple `{section}` PE sections found; expected exactly one")]
        DuplicatePmiTargetSection { section: String },

        // ─── Manifest semantic ──────────────────────────────────────
        #[error("`.pmi.<target>` section not found for target `{target}`")]
        TargetSectionMissing { target: String },

        #[error("manifest references PE section `{section}` which is not present")]
        ManifestReferencesMissingSection { section: String },

        #[error("invalid lbc:bootconfig fill: {0}")]
        BootconfigFill(&'static str),

        #[error("fill section `{0}` requires 0 < VirtualSize and SizeOfRawData = 0")]
        InvalidFillShape(String),

        #[error("CBOR decode failed: {0}")]
        CborDecode(String),

        #[error("no base DTB: neither a dt:dtb attribute nor a dt:dtb fill is present")]
        NoBaseDtb,

        #[error("dt:dtb attribute names section `{section}` which is not present")]
        DtDtbSectionMissing { section: String },

        // ─── Pathological-spread refusal (§5.5) ─────────────────────
        #[error(
            "loaded layout is pathologically spread: 2 MiB footprint {footprint} bytes \
             exceeds {ratio}× sum of load sizes ({sum})"
        )]
        SpreadRatioExceeded {
            footprint: u64,
            sum: u64,
            ratio: u64,
        },

        #[error("loaded layout's 2 MiB footprint {footprint} bytes exceeds memory cap {cap}")]
        SpreadAbsoluteExceeded { footprint: u64, cap: u64 },
    }

    use std::collections::BTreeMap;
    use std::io::Cursor;

    use dillo_machine::CpuProfile;
    use object::pe::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64};
    use object::read::pe::PeFile64;
    use object::{Object, ObjectSection, SectionFlags};
    use pmi::Target;
    use pmi::vm::{Action as ManifestAction, FillKind as PmiFillKind, Spec};
    use pmi::{aarch64, x86_64};

    /// Host architecture selector. The PMI's PE Machine field MUST match.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HostArch {
        X86_64,
        Aarch64,
    }

    impl HostArch {
        fn pe_machine(self) -> u16 {
            match self {
                HostArch::X86_64 => IMAGE_FILE_MACHINE_AMD64,
                HostArch::Aarch64 => IMAGE_FILE_MACHINE_ARM64,
            }
        }
    }

    /// Options the caller (the VM child) supplies to the loader.
    #[derive(Debug, Clone, Copy)]
    pub struct ParseOptions {
        /// Host architecture; must match PE FileHeader.Machine.
        pub host_arch: HostArch,
        /// Guest memory in MiB. Used to compute the effective total-loaded cap.
        pub memory_mib: u32,
    }

    /// Information about a PE section reachable from the active target.
    #[derive(Debug, Clone, Copy)]
    pub struct SectionInfo {
        /// On-disk offset (`PointerToRawData`).
        pub file_offset: u64,
        /// On-disk byte count (`SizeOfRawData`). Zero for Zero-shape sections.
        pub file_size: u64,
        /// In-guest byte count (`VirtualSize`).
        pub virtual_size: u64,
    }

    /// One step in the launch recipe.
    #[derive(Debug, Clone)]
    pub struct Action {
        /// Name of the referenced PE section.
        pub section: String,
        /// Absolute guest physical address declared by this action.
        pub gpa: u64,
        /// File metadata and extent of the referenced PE section.
        pub source: SectionInfo,
        pub kind: ActionKind,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ActionKind {
        Load,
        Fill(FillKind),
    }

    /// Fill kinds dillo recognizes (the PMI `dt` and `lbc` extensions).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FillKind {
        /// `dt:dtb` — the measured base DTB, delivered into a reserved Zero
        /// section (detached and optional channel modes).
        DtDtb,

        /// `dt:dtbo` — host-supplied, unmeasured DTB overlay.
        DtDtbo,

        /// `lbc:bootconfig` — native Linux bootconfig in a Zero reservation.
        LbcBootconfig,
    }

    /// Successfully-parsed PMI.
    #[derive(Debug)]
    pub struct ParsedPmi {
        pub arch: HostArch,
        /// Effective ISA baseline, including the architecture default.
        pub cpu_profile: CpuProfile,
        pub actions: Vec<Action>,
        /// The bundled base DTB named by the `dt:dtb` target attribute, as a
        /// read-only source. `Some` in bundled and optional modes (the image
        /// carries a base or fallback); `None` in detached mode, where the base
        /// is delivered out-of-band. Not placed in guest memory by itself.
        pub dt_dtb_source: Option<SectionInfo>,
    }

    /// Refuse oversized input before acquiring or parsing its bytes.
    pub fn check_file_size(file_size: u64) -> Result<(), Error> {
        if file_size > caps::MAX_FILE_SIZE {
            return Err(Error::FileTooLarge {
                actual: file_size,
                cap: caps::MAX_FILE_SIZE,
            });
        }
        Ok(())
    }

    /// Parse and validate a PMI file's bytes.
    ///
    /// See `dillo/ARCHITECTURE.md` §5.
    pub fn parse(bytes: &[u8], opts: &ParseOptions) -> Result<ParsedPmi, Error> {
        let file_size = bytes.len() as u64;
        check_file_size(file_size)?;

        // PE parse via `object`.
        let pe = PeFile64::parse(bytes).map_err(|e| Error::PeParse(e.to_string()))?;

        let actual = machine_value(&pe);
        let expected = opts.host_arch.pe_machine();
        if actual != expected {
            return Err(Error::HostArchMismatch { actual, expected });
        }

        // Enumerate sections once into a typed table.
        let raw_sections = collect_sections(&pe, file_size, bytes)?;

        // Locate `.pmi.vm` (MVP — only `vm` target is supported).
        let target_section_name = Spec::<x86_64::Profile>::SECTION;
        let target_section = raw_sections
            .get(target_section_name)
            .filter(|s| s.is_discardable)
            .ok_or_else(|| Error::TargetSectionMissing {
                target: target_section_name.to_string(),
            })?;

        // §5.2 manifest-size cap.
        if target_section.body.len() > caps::MAX_MANIFEST_SIZE {
            return Err(Error::ManifestTooLarge {
                section: target_section_name.to_string(),
                actual: target_section.body.len(),
                cap: caps::MAX_MANIFEST_SIZE,
            });
        }

        // Strict CBOR decode (depth-limited) into the architecture-specific profile.
        let (cpu_profile, actions_raw, dt_dtb_attr) =
            decode_manifest_bytes(&target_section.body, opts.host_arch)?;
        let actions = resolve_actions(actions_raw, &raw_sections)?;

        if dt_dtb_attr.is_none()
            && !actions
                .iter()
                .any(|a| a.kind == ActionKind::Fill(FillKind::DtDtb))
        {
            return Err(Error::NoBaseDtb);
        }
        let dt_dtb_source = dt_dtb_attr
            .map(|section| {
                raw_sections
                    .get(&section)
                    .map(|s| s.info)
                    .ok_or(Error::DtDtbSectionMissing { section })
            })
            .transpose()?;

        // Sort a view of the validated ranges, keeping actions in recipe order.
        let mut placements: Vec<_> = actions.iter().collect();
        placements.sort_by_key(|a| a.gpa);
        for pair in placements.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if a.gpa + a.source.virtual_size > b.gpa {
                return Err(Error::SectionsOverlap {
                    a: a.section.clone(),
                    b: b.section.clone(),
                });
            }
        }

        // §5.5 sum-of-loaded cap.
        let total_loaded = actions
            .iter()
            .filter(|a| a.kind == ActionKind::Load)
            .map(|a| a.source.virtual_size)
            .sum();
        let memory_cap = effective_memory_cap(opts.memory_mib);
        if total_loaded > memory_cap {
            return Err(Error::LoadedBytesExceedMemory {
                actual: total_loaded,
                cap: memory_cap,
            });
        }

        // §5.5 pathological-spread refusal (against all must-cover ranges,
        // not just loads — fills must be backed too).
        let must_cover: Vec<_> = actions
            .iter()
            .map(|a| (a.gpa, a.source.virtual_size))
            .collect();
        spread_check(&must_cover, total_loaded, memory_cap)?;

        Ok(ParsedPmi {
            arch: opts.host_arch,
            cpu_profile,
            actions,
            dt_dtb_source,
        })
    }

    // ─── internals ──────────────────────────────────────────────────

    struct RawSection {
        info: SectionInfo,
        raw_size: u64,
        is_discardable: bool,
        /// The on-disk bytes for non-loaded sections (e.g., the CBOR
        /// manifest). Empty for loaded sections — those are read by the
        /// caller via `file_offset` + `file_size`.
        body: Vec<u8>,
    }

    fn machine_value(pe: &PeFile64<'_>) -> u16 {
        use object::LittleEndian as LE;
        pe.nt_headers().file_header.machine.get(LE)
    }

    #[cfg(test)]
    #[test]
    fn arm64ec_is_not_a_pmi_machine_type() {
        use object::pe::IMAGE_FILE_MACHINE_ARM64EC;

        let mut bytes = vec![0u8; 240];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[84..86].copy_from_slice(&112u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        let opts = ParseOptions {
            host_arch: HostArch::Aarch64,
            memory_mib: 256,
        };

        bytes[68..70].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64EC.to_le_bytes());
        let result = parse(&bytes, &opts);
        assert!(
            matches!(
                result,
                Err(Error::HostArchMismatch {
                    actual: IMAGE_FILE_MACHINE_ARM64EC,
                    expected: IMAGE_FILE_MACHINE_ARM64,
                })
            ),
            "{result:?}"
        );

        bytes[68..70].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        assert!(matches!(
            parse(&bytes, &opts),
            Err(Error::TargetSectionMissing { .. })
        ));
    }

    fn collect_sections(
        pe: &PeFile64<'_>,
        file_size: u64,
        bytes: &[u8],
    ) -> Result<BTreeMap<String, RawSection>, Error> {
        let sections: Vec<_> = pe.sections().collect();
        if sections.len() > caps::MAX_SECTION_COUNT {
            return Err(Error::TooManySections {
                actual: sections.len(),
                cap: caps::MAX_SECTION_COUNT,
            });
        }

        let mut out: BTreeMap<String, RawSection> = BTreeMap::new();
        for section in sections {
            let name = section
                .name()
                .map_err(|e| Error::PeParse(format!("section name decode: {e}")))?
                .to_string();
            if name.len() > caps::MAX_SECTION_NAME_LEN {
                return Err(Error::SectionNameTooLong {
                    len: name.len(),
                    cap: caps::MAX_SECTION_NAME_LEN,
                    name,
                });
            }
            let virtual_size = section.size();
            let file_size_field = section.file_range().map_or(0, |(_, size)| size);
            let header = section.pe_section();
            let file_offset = u64::from(header.pointer_to_raw_data.get(object::LittleEndian));
            let raw_size = header.size_of_raw_data.get(object::LittleEndian);

            // §5.4 PE bytes-on-disk fit in file.
            if file_size_field > 0 {
                let end = file_offset.checked_add(file_size_field).ok_or_else(|| {
                    Error::SectionDataPastEof {
                        name: name.clone(),
                        offset: file_offset,
                        end: u64::MAX,
                        file_size,
                    }
                })?;
                if end > file_size {
                    return Err(Error::SectionDataPastEof {
                        name: name.clone(),
                        offset: file_offset,
                        end,
                        file_size,
                    });
                }
            }

            let characteristics = match section.flags() {
                SectionFlags::Coff { characteristics } => characteristics,
                _ => 0,
            };
            let is_discardable = (characteristics & object::pe::IMAGE_SCN_MEM_DISCARDABLE) != 0;

            // Capture body bytes only for non-loaded sections (small, currently
            // just the manifest). Loaded-section bytes stay in `bytes` and the
            // caller reads them via offset+size to avoid copies.
            let body = if is_discardable && file_size_field > 0 {
                let start = file_offset as usize;
                let end = start + file_size_field as usize;
                bytes[start..end].to_vec()
            } else {
                Vec::new()
            };

            if out.contains_key(&name) && name.starts_with(".pmi.") {
                return Err(Error::DuplicatePmiTargetSection { section: name });
            }

            out.insert(
                name,
                RawSection {
                    info: SectionInfo {
                        file_offset,
                        file_size: file_size_field,
                        virtual_size,
                    },
                    raw_size: u64::from(raw_size),
                    is_discardable,
                    body,
                },
            );
        }
        Ok(out)
    }

    #[allow(clippy::type_complexity)]
    fn decode_manifest_bytes(
        bytes: &[u8],
        arch: HostArch,
    ) -> Result<(CpuProfile, Vec<ManifestAction>, Option<String>), Error> {
        let cursor = Cursor::new(bytes);
        match arch {
            HostArch::X86_64 => {
                let spec: Spec<x86_64::Profile> =
                    ciborium::de::from_reader_with_recursion_limit(cursor, caps::CBOR_MAX_DEPTH)
                        .map_err(|e| Error::CborDecode(e.to_string()))?;
                check_actions_len(&spec.actions)?;
                Ok((
                    CpuProfile::X86_64(spec.cpu_profile),
                    spec.actions,
                    spec.dt_dtb,
                ))
            }
            HostArch::Aarch64 => {
                let spec: Spec<aarch64::Profile> =
                    ciborium::de::from_reader_with_recursion_limit(cursor, caps::CBOR_MAX_DEPTH)
                        .map_err(|e| Error::CborDecode(e.to_string()))?;
                check_actions_len(&spec.actions)?;
                Ok((
                    CpuProfile::Aarch64(spec.cpu_profile),
                    spec.actions,
                    spec.dt_dtb,
                ))
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn typed_architecture_profiles_default_and_refuse_old_fields() {
        use ciborium::value::Value;

        let manifest = |extra| {
            let mut entries = vec![
                (Value::Text("version".into()), 1u64.into()),
                (Value::Text("actions".into()), Value::Array(Vec::new())),
            ];
            entries.extend(extra);
            let mut bytes = Vec::new();
            ciborium::into_writer(&Value::Map(entries), &mut bytes).unwrap();
            bytes
        };
        for (arch, name, default, other) in [
            (
                HostArch::X86_64,
                "x86-64-v1",
                CpuProfile::X86_64(x86_64::Profile::V1),
                "armv8.0-a",
            ),
            (
                HostArch::Aarch64,
                "armv8.0-a",
                CpuProfile::Aarch64(aarch64::Profile::V8_0),
                "x86-64-v1",
            ),
        ] {
            assert_eq!(
                decode_manifest_bytes(&manifest(None), arch).unwrap().0,
                default
            );
            let profile = |name: &str| manifest(Some(("cpu:profile".into(), name.into())));
            assert_eq!(
                decode_manifest_bytes(&profile(name), arch).unwrap().0,
                default
            );
            for invalid in [
                profile(other),
                profile("unknown"),
                manifest(Some(("vm:vcpu".into(), Value::Map(Vec::new())))),
            ] {
                assert!(matches!(
                    decode_manifest_bytes(&invalid, arch),
                    Err(Error::CborDecode(_))
                ));
            }
        }
    }

    fn check_actions_len(actions: &[ManifestAction]) -> Result<(), Error> {
        if actions.len() > caps::CBOR_MAX_ARRAY_LEN {
            return Err(Error::CborDecode(format!(
                "actions array length {} exceeds cap of {}",
                actions.len(),
                caps::CBOR_MAX_ARRAY_LEN
            )));
        }
        Ok(())
    }

    fn resolve_actions(
        raw: Vec<ManifestAction>,
        sections: &BTreeMap<String, RawSection>,
    ) -> Result<Vec<Action>, Error> {
        let mut actions = Vec::with_capacity(raw.len());
        let mut has_bootconfig_fill = false;
        for a in raw {
            let (section, gpa, kind) = match a {
                ManifestAction::Load(load) => (load.section, load.gpa, ActionKind::Load),
                ManifestAction::Fill(fill) => (
                    fill.section,
                    fill.gpa,
                    ActionKind::Fill(translate_fill_kind(fill.kind)),
                ),
            };
            let Some(raw_section) = sections.get(&section) else {
                return Err(Error::ManifestReferencesMissingSection { section });
            };
            let source = raw_section.info;
            match kind {
                ActionKind::Load => {
                    if source.virtual_size == 0 || raw_section.raw_size > source.virtual_size {
                        return Err(Error::InvalidLoadSize(section));
                    }
                }
                ActionKind::Fill(fill) => {
                    if raw_section.raw_size != 0 || source.virtual_size == 0 {
                        return Err(Error::InvalidFillShape(section));
                    }
                    match fill {
                        FillKind::LbcBootconfig if has_bootconfig_fill => {
                            return Err(Error::BootconfigFill("duplicate fill"));
                        }
                        FillKind::LbcBootconfig => has_bootconfig_fill = true,
                        FillKind::DtDtbo
                            if !(caps::DTBO_MIN_SIZE..=caps::DTBO_MAX_SIZE)
                                .contains(&source.virtual_size) =>
                        {
                            return Err(Error::DtboSizeOutOfRange {
                                actual: source.virtual_size,
                                min: caps::DTBO_MIN_SIZE,
                                max: caps::DTBO_MAX_SIZE,
                            });
                        }
                        _ => {}
                    }
                }
            }
            validate_destination(&section, gpa, &source)?;
            actions.push(Action {
                section,
                gpa,
                source,
                kind,
            });
        }
        Ok(actions)
    }

    fn translate_fill_kind(k: PmiFillKind) -> FillKind {
        match k {
            PmiFillKind::DtDtb => FillKind::DtDtb,
            PmiFillKind::DtDtbo => FillKind::DtDtbo,
            PmiFillKind::LbcBootconfig => FillKind::LbcBootconfig,
        }
    }

    fn validate_destination(name: &str, gpa: u64, s: &SectionInfo) -> Result<(), Error> {
        // The section and the backing extent used by the spread check must fit.
        gpa.checked_add(s.virtual_size)
            .and_then(|end| end.checked_next_multiple_of(caps::HUGE_PAGE))
            .ok_or_else(|| Error::VirtualAddressOverflow {
                name: name.to_string(),
            })?;

        // The guest-address-width bound is no longer a hardcoded 2^48 (pmi
        // spec bc7f581): it is enforced post-survey in dillo-devtree's
        // `cross_validate_loads`, using the effective backend/guest width.
        // Parse-time validation here is width-agnostic.

        // Alignment per PMI granularity (`pmi/spec/granularity.md`, commits
        // 15768cf + 3b2260e): only a section's START is constrained — `gpa`
        // and `PointerToRawData`. `SizeOfRawData` follows PE `FileAlignment`
        // and carries no alignment requirement.
        if s.virtual_size >= caps::HUGE_PAGE {
            if !gpa.is_multiple_of(caps::HUGE_PAGE) {
                return Err(Error::AlignmentViolation {
                    name: name.to_string(),
                    virtual_size: s.virtual_size,
                    rule: "large section: gpa must be 2 MiB-aligned",
                });
            }
            if !s.file_offset.is_multiple_of(caps::HUGE_PAGE) {
                return Err(Error::AlignmentViolation {
                    name: name.to_string(),
                    virtual_size: s.virtual_size,
                    rule: "large section: PointerToRawData must be 2 MiB-aligned",
                });
            }
        } else {
            if !gpa.is_multiple_of(caps::SMALL_PAGE) {
                return Err(Error::AlignmentViolation {
                    name: name.to_string(),
                    virtual_size: s.virtual_size,
                    rule: "small section: gpa must be 4 KiB-aligned",
                });
            }
            if !s.file_offset.is_multiple_of(caps::SMALL_PAGE) {
                return Err(Error::AlignmentViolation {
                    name: name.to_string(),
                    virtual_size: s.virtual_size,
                    rule: "small section: PointerToRawData must be 4 KiB-aligned",
                });
            }
        }
        Ok(())
    }

    fn effective_memory_cap(memory_mib: u32) -> u64 {
        let memory_bytes = u64::from(memory_mib) * (1 << 20);
        std::cmp::min(memory_bytes, caps::MAX_TOTAL_LOADED_HARD)
    }

    fn spread_check(
        ranges: &[(u64, u64)],
        total_loaded: u64,
        memory_cap: u64,
    ) -> Result<(), Error> {
        if ranges.is_empty() {
            return Ok(());
        }
        let mut pages: Vec<(u64, u64)> = ranges
            .iter()
            .filter(|(_, size)| *size > 0)
            .map(|(gpa, size)| {
                let start = gpa & !(caps::HUGE_PAGE - 1);
                let end_inclusive = gpa.saturating_add(*size).saturating_sub(1);
                let end = ((end_inclusive / caps::HUGE_PAGE) + 1) * caps::HUGE_PAGE;
                (start, end)
            })
            .collect();
        if pages.is_empty() {
            return Ok(());
        }
        pages.sort_by_key(|&(s, _)| s);

        let mut footprint: u64 = 0;
        let mut cur_start = pages[0].0;
        let mut cur_end = pages[0].1;
        for &(s, e) in &pages[1..] {
            if s <= cur_end {
                cur_end = cur_end.max(e);
            } else {
                footprint = footprint.saturating_add(cur_end - cur_start);
                cur_start = s;
                cur_end = e;
            }
        }
        footprint = footprint.saturating_add(cur_end - cur_start);

        // Absolute cap fires regardless of total_loaded.
        if footprint > memory_cap {
            return Err(Error::SpreadAbsoluteExceeded {
                footprint,
                cap: memory_cap,
            });
        }

        // Ratio cap.
        let ratio_limit = total_loaded.saturating_mul(caps::SPREAD_INFLATION_RATIO);
        if footprint > ratio_limit {
            return Err(Error::SpreadRatioExceeded {
                footprint,
                sum: total_loaded,
                ratio: caps::SPREAD_INFLATION_RATIO,
            });
        }

        Ok(())
    }
}
