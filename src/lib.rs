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

        /// Maximum PMI file size: 4 GiB. Refused before any read.
        pub const MAX_FILE_SIZE: u64 = 4 << 30;

        /// Maximum `.pmi.<target>` manifest size: 4 KiB.
        pub const MAX_MANIFEST_SIZE: usize = 4 << 10;

        /// Maximum PE section count.
        pub const MAX_SECTION_COUNT: usize = 64;

        /// Maximum PE section name length (bytes).
        pub const MAX_SECTION_NAME_LEN: usize = 64;

        /// Absolute cap on the whole-page extents of `load` actions.
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
            "sum of loaded page extents ({actual} bytes) exceeds cap of {cap} bytes \
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

        #[error("action referencing `{name}`: page-rounded GPA range overflows u64")]
        VirtualAddressOverflow { name: String },

        #[error("actions referencing `{a}` and `{b}` overlap in guest memory")]
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

        #[error("section `{section}` has invalid shape: {reason}")]
        InvalidSectionShape {
            section: String,
            reason: &'static str,
        },

        #[error("invalid lbc:bootconfig fill: {0}")]
        BootconfigFill(&'static str),

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

    pub use dillo_machine::CpuProfile;
    use object::pe::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64};
    use object::read::pe::PeFile64;
    use object::{Object, ObjectSection, SectionFlags};
    use pmi::Target;
    use pmi::vm::{Action as ManifestAction, FillKind as PmiFillKind, Spec};

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
    #[derive(Debug, Clone)]
    pub struct SectionInfo {
        /// On-disk offset (`PointerToRawData`).
        pub file_offset: u64,
        /// On-disk byte count (`SizeOfRawData`). Zero for Zero-shape sections.
        pub file_size: u64,
        /// In-guest byte count (`VirtualSize`).
        pub virtual_size: u64,
    }

    /// A resolved action owns its destination independently of its PE source.
    /// Construction validates the complete page extent before it is exposed.
    #[derive(Debug, Clone)]
    pub struct Action {
        section: String,
        gpa: u64,
        memory_size: u64,
        source: SectionInfo,
        kind: ActionKind,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ActionKind {
        Load,
        Fill(FillKind),
    }

    impl Action {
        pub fn section(&self) -> &str {
            &self.section
        }
        pub fn gpa(&self) -> u64 {
            self.gpa
        }
        /// Bytes occupied by the action's whole 4 KiB guest pages.
        pub fn memory_size(&self) -> u64 {
            self.memory_size
        }
        pub fn source(&self) -> &SectionInfo {
            &self.source
        }
        pub fn kind(&self) -> ActionKind {
            self.kind
        }

        fn resolve(
            raw: ManifestActionOwned,
            sections: &BTreeMap<String, RawSection>,
        ) -> Result<Self, Error> {
            let (section, gpa, kind) = match raw {
                ManifestActionOwned::Load { section, gpa } => (section, gpa, ActionKind::Load),
                ManifestActionOwned::Fill { section, gpa, kind } => {
                    (section, gpa, ActionKind::Fill(kind.into()))
                }
            };
            let source =
                sections
                    .get(&section)
                    .ok_or_else(|| Error::ManifestReferencesMissingSection {
                        section: section.clone(),
                    })?;
            if let ActionKind::Fill(_) = kind {
                if source.file_size != 0 || source.virtual_size == 0 {
                    return Err(Error::InvalidSectionShape {
                        section,
                        reason: "fill requires a nonempty Zero section",
                    });
                }
            } else if source.file_size > source.virtual_size {
                return Err(Error::InvalidSectionShape {
                    section,
                    reason: "SizeOfRawData exceeds VirtualSize",
                });
            }
            let memory_size = source
                .virtual_size
                .checked_add(caps::SMALL_PAGE - 1)
                .map(|size| size & !(caps::SMALL_PAGE - 1))
                .and_then(|size| gpa.checked_add(size).map(|_| size))
                .ok_or_else(|| Error::VirtualAddressOverflow {
                    name: section.clone(),
                })?;
            let action = Self {
                section,
                gpa,
                memory_size,
                source: source.into(),
                kind,
            };
            action.validate_alignment()?;
            Ok(action)
        }

        fn validate_alignment(&self) -> Result<(), Error> {
            let page = if self.source.virtual_size >= caps::HUGE_PAGE {
                caps::HUGE_PAGE
            } else {
                caps::SMALL_PAGE
            };
            if self.source.virtual_size != 0 && !self.gpa.is_multiple_of(page) {
                return Err(Error::AlignmentViolation {
                    name: self.section.clone(),
                    virtual_size: self.source.virtual_size,
                    rule: if page == caps::HUGE_PAGE {
                        "large section: gpa must be 2 MiB-aligned"
                    } else {
                        "small section: gpa must be 4 KiB-aligned"
                    },
                });
            }
            if self.source.file_size != 0 && !self.source.file_offset.is_multiple_of(page) {
                return Err(Error::AlignmentViolation {
                    name: self.section.clone(),
                    virtual_size: self.source.virtual_size,
                    rule: if page == caps::HUGE_PAGE {
                        "large section: PointerToRawData must be 2 MiB-aligned"
                    } else {
                        "small section: PointerToRawData must be 4 KiB-aligned"
                    },
                });
            }
            Ok(())
        }
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
        /// `cpu:profile` target attribute (per `pmi/spec/cpu.md`). The
        /// architecture-typed baseline. Native CPU preparation must validate
        /// guest-visible capabilities before execution.
        pub cpu_profile: CpuProfile,
        pub actions: Vec<Action>,
        /// The bundled base DTB named by the `dt:dtb` target attribute, as a
        /// read-only source. `Some` in bundled and optional modes (the image
        /// carries a base or fallback); `None` in detached mode, where the base
        /// is delivered out-of-band. Not placed in guest memory by itself.
        pub dt_dtb_source: Option<SectionInfo>,
    }

    /// Parse and validate a PMI file's bytes.
    ///
    /// See `dillo/ARCHITECTURE.md` §5.
    pub fn parse(bytes: &[u8], opts: &ParseOptions) -> Result<ParsedPmi, Error> {
        // §5.2 file-size cap.
        let file_size = bytes.len() as u64;
        if file_size > caps::MAX_FILE_SIZE {
            return Err(Error::FileTooLarge {
                actual: file_size,
                cap: caps::MAX_FILE_SIZE,
            });
        }

        // PE parse via `object`.
        let pe = PeFile64::parse(bytes).map_err(|e| Error::PeParse(e.to_string()))?;

        // Host-arch match — pe.architecture() returns object::Architecture, but
        // we want the raw u16 to be explicit about the spec wording.
        let machine = match opts.host_arch {
            HostArch::X86_64 => {
                if !matches!(pe.architecture(), object::Architecture::X86_64) {
                    return Err(Error::HostArchMismatch {
                        actual: machine_value(&pe),
                        expected: opts.host_arch.pe_machine(),
                    });
                }
                IMAGE_FILE_MACHINE_AMD64
            }
            HostArch::Aarch64 => {
                if !matches!(pe.architecture(), object::Architecture::Aarch64) {
                    return Err(Error::HostArchMismatch {
                        actual: machine_value(&pe),
                        expected: opts.host_arch.pe_machine(),
                    });
                }
                IMAGE_FILE_MACHINE_ARM64
            }
        };
        let _ = machine;

        // Enumerate sections once into a typed table.
        let raw_sections = collect_sections(&pe, file_size)?;

        // Locate `.pmi.vm` (MVP — only `vm` target is supported).
        let target_section_name = pmi::vm::Spec::<pmi::x86_64::Profile>::SECTION;
        let target_section = raw_sections
            .get(target_section_name)
            .filter(|s| s.is_discardable)
            .ok_or_else(|| Error::TargetSectionMissing {
                target: target_section_name.to_string(),
            })?;

        // §5.2 manifest-size cap.
        if target_section.file_size as usize > caps::MAX_MANIFEST_SIZE {
            return Err(Error::ManifestTooLarge {
                section: target_section_name.to_string(),
                actual: target_section.file_size as usize,
                cap: caps::MAX_MANIFEST_SIZE,
            });
        }

        // Strict CBOR decode (depth-limited) into the arch-correct Spec<P>.
        let manifest = if target_section.file_size == 0 {
            &[][..]
        } else {
            let start = target_section.file_offset as usize;
            &bytes[start..start + target_section.file_size as usize]
        };
        let (cpu_profile, actions_raw, merged_dtb) =
            decode_manifest_bytes(manifest, opts.host_arch)?;

        let actions = actions_raw
            .into_iter()
            .map(|raw| Action::resolve(raw, &raw_sections))
            .collect::<Result<Vec<_>, _>>()?;
        if actions
            .iter()
            .filter(|a| a.kind() == ActionKind::Fill(FillKind::LbcBootconfig))
            .count()
            > 1
        {
            return Err(Error::BootconfigFill("duplicate fill"));
        }

        // dt extension channel resolution (pmi/spec/dt.md, VMM selection
        // table). A base DTB must be available through either the `dt:dtb`
        // attribute (bundled / optional fallback) or a `dt:dtb` fill (detached /
        // optional); with neither, no base exists and the VMM MUST refuse.
        // Whether delegated CPUs or memory require a `dt:dtbo` fill is checked
        // during launch preflight, after resolving and surveying the base.
        let has_dt_dtb_fill = actions
            .iter()
            .any(|a| a.kind() == ActionKind::Fill(FillKind::DtDtb));
        let dt_dtb_attr = merged_dtb;
        if dt_dtb_attr.is_none() && !has_dt_dtb_fill {
            return Err(Error::NoBaseDtb);
        }
        // A named bundled base must actually be present in the image.
        if let Some(section) = &dt_dtb_attr
            && !raw_sections.contains_key(section)
        {
            return Err(Error::DtDtbSectionMissing {
                section: section.clone(),
            });
        }

        // Compare individual placements, including repeated references to one
        // source. Sorting this borrowed view never changes execution order.
        let mut placements: Vec<_> = actions.iter().filter(|a| a.memory_size() != 0).collect();
        placements.sort_by_key(|a| a.gpa());
        for pair in placements.windows(2) {
            if pair[0].gpa() + pair[0].memory_size() > pair[1].gpa() {
                return Err(Error::SectionsOverlap {
                    a: pair[0].section().into(),
                    b: pair[1].section().into(),
                });
            }
        }
        let total_loaded: u64 = actions
            .iter()
            .filter(|a| a.kind() == ActionKind::Load)
            .map(Action::memory_size)
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
        let must_cover: Vec<_> = actions.iter().map(|a| (a.gpa(), a.memory_size())).collect();
        spread_check(&must_cover, total_loaded, memory_cap)?;

        // .dtbo size in [4 KiB, 64 KiB].
        for action in actions
            .iter()
            .filter(|a| a.kind() == ActionKind::Fill(FillKind::DtDtbo))
        {
            let size = action.source().virtual_size;
            if !(caps::DTBO_MIN_SIZE..=caps::DTBO_MAX_SIZE).contains(&size) {
                return Err(Error::DtboSizeOutOfRange {
                    actual: size,
                    min: caps::DTBO_MIN_SIZE,
                    max: caps::DTBO_MAX_SIZE,
                });
            }
        }

        // The bundled base the `dt:dtb` attribute names, as a read-only source
        // (file bytes). The attribute itself has no placement or coverage;
        // the VMM only reads it, to
        // load (bundled) or to fill the reserved base section (optional).
        let dt_dtb_source = dt_dtb_attr
            .as_ref()
            .map(|name| SectionInfo::from(&raw_sections[name]));

        Ok(ParsedPmi {
            arch: opts.host_arch,
            cpu_profile,
            actions,
            dt_dtb_source,
        })
    }

    // ─── internals ──────────────────────────────────────────────────

    struct RawSection {
        file_offset: u64,
        file_size: u64,
        virtual_size: u64,
        is_discardable: bool,
    }

    impl From<&RawSection> for SectionInfo {
        fn from(source: &RawSection) -> Self {
            Self {
                file_offset: source.file_offset,
                file_size: source.file_size,
                virtual_size: source.virtual_size,
            }
        }
    }

    fn machine_value(pe: &PeFile64<'_>) -> u16 {
        use object::LittleEndian as LE;
        pe.nt_headers().file_header.machine.get(LE)
    }

    fn collect_sections(
        pe: &PeFile64<'_>,
        file_size: u64,
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
            // ObjectSection::file_range truncates raw data to VirtualSize for
            // ordinary PE loading. PMI needs the exact source header fields.
            let header = section.pe_section();
            let file_offset = u64::from(header.pointer_to_raw_data.get(object::LittleEndian));
            let file_size_field = u64::from(header.size_of_raw_data.get(object::LittleEndian));

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

            if out.contains_key(&name) && name.starts_with(".pmi.") {
                return Err(Error::DuplicatePmiTargetSection { section: name });
            }

            out.insert(
                name,
                RawSection {
                    file_offset,
                    file_size: file_size_field,
                    virtual_size,
                    is_discardable,
                },
            );
        }
        Ok(out)
    }

    #[allow(clippy::type_complexity)]
    fn decode_manifest_bytes(
        bytes: &[u8],
        arch: HostArch,
    ) -> Result<(CpuProfile, Vec<ManifestActionOwned>, Option<String>), Error> {
        let cursor = Cursor::new(bytes);
        match arch {
            HostArch::X86_64 => {
                let spec: Spec<pmi::x86_64::Profile> =
                    ciborium::de::from_reader_with_recursion_limit(cursor, caps::CBOR_MAX_DEPTH)
                        .map_err(|e| Error::CborDecode(e.to_string()))?;
                check_actions_len(&spec.actions)?;
                let actions = spec
                    .actions
                    .into_iter()
                    .map(ManifestActionOwned::from)
                    .collect();
                Ok((CpuProfile::X86_64(spec.cpu_profile), actions, spec.dt_dtb))
            }
            HostArch::Aarch64 => {
                let spec: Spec<pmi::aarch64::Profile> =
                    ciborium::de::from_reader_with_recursion_limit(cursor, caps::CBOR_MAX_DEPTH)
                        .map_err(|e| Error::CborDecode(e.to_string()))?;
                check_actions_len(&spec.actions)?;
                let actions = spec
                    .actions
                    .into_iter()
                    .map(ManifestActionOwned::from)
                    .collect();
                Ok((CpuProfile::Aarch64(spec.cpu_profile), actions, spec.dt_dtb))
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

    #[derive(Debug, Clone)]
    enum ManifestActionOwned {
        Load {
            gpa: u64,
            section: String,
        },
        Fill {
            gpa: u64,
            section: String,
            kind: PmiFillKind,
        },
    }

    impl From<ManifestAction> for ManifestActionOwned {
        fn from(a: ManifestAction) -> Self {
            match a {
                ManifestAction::Load(l) => Self::Load {
                    gpa: l.gpa,
                    section: l.section,
                },
                ManifestAction::Fill(f) => Self::Fill {
                    gpa: f.gpa,
                    section: f.section,
                    kind: f.kind,
                },
            }
        }
    }

    impl From<PmiFillKind> for FillKind {
        fn from(kind: PmiFillKind) -> Self {
            match kind {
                PmiFillKind::DtDtb => Self::DtDtb,
                PmiFillKind::DtDtbo => Self::DtDtbo,
                PmiFillKind::LbcBootconfig => Self::LbcBootconfig,
            }
        }
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
                let end = gpa
                    .checked_add(*size)
                    .and_then(|end| end.checked_add(caps::HUGE_PAGE - 1))
                    .map(|end| end & !(caps::HUGE_PAGE - 1))
                    .ok_or_else(|| Error::VirtualAddressOverflow {
                        name: "2 MiB action coverage".into(),
                    })?;
                Ok((start, end))
            })
            .collect::<Result<_, Error>>()?;
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
