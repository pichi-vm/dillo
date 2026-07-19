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

        #[error("section `{name}`: gpa + VirtualSize overflows u64")]
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

        #[error("CBOR decode failed: {0}")]
        CborDecode(String),

        #[error(
            "vm:vcpu variant ({variant}) does not match PE FileHeader.Machine ({machine:#06x})"
        )]
        VcpuVariantMismatch { variant: &'static str, machine: u16 },

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

    use object::pe::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64};
    use object::read::pe::PeFile64;
    use object::{Object, ObjectSection, SectionFlags};
    use pmi::Target;
    use pmi::vm::vcpu::{aarch64 as vcpu_aarch64, x86_64 as vcpu_x86_64};
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

    /// The boot vCPU register map, in the form selected by the PE Machine.
    #[derive(Debug)]
    pub enum VcpuState {
        X86_64(vcpu_x86_64::CpuState),
        Aarch64(vcpu_aarch64::CpuState),
    }

    impl dillo_machine::BootVcpuState for VcpuState {
        fn x86_64(&self) -> Option<&vcpu_x86_64::CpuState> {
            match self {
                Self::X86_64(state) => Some(state),
                Self::Aarch64(_) => None,
            }
        }

        fn aarch64(&self) -> Option<&vcpu_aarch64::CpuState> {
            match self {
                Self::Aarch64(state) => Some(state),
                Self::X86_64(_) => None,
            }
        }
    }

    /// Information about a PE section reachable from the active target.
    #[derive(Debug, Clone)]
    pub struct SectionInfo {
        /// On-disk offset (`PointerToRawData`).
        pub file_offset: u64,
        /// On-disk byte count (`SizeOfRawData`). Zero for Zero-shape sections.
        pub file_size: u64,
        /// Guest physical address — the explicit `gpa` from the load/fill
        /// action (pmi spec f6be1eb), not the PE `VirtualAddress`.
        pub gpa: u64,
        /// In-guest byte count (`VirtualSize`).
        pub virtual_size: u64,
    }

    /// One step in the launch recipe.
    #[derive(Debug, Clone)]
    pub enum Action {
        /// `load` a PE section's bytes at its GPA.
        Load { section: String },
        /// `fill` a Zero-shape section at its GPA with kind-specific content.
        Fill { section: String, kind: FillKind },
    }

    /// Fill kinds dillo recognizes (the `dt` extension, `pmi/spec/dt.md`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FillKind {
        /// `dt:dtb` — the measured base DTB, delivered into a reserved Zero
        /// section (detached and optional channel modes).
        DtDtb,

        /// `dt:dtbo` — host-supplied, unmeasured DTB overlay.
        DtDtbo,
    }

    /// Successfully-parsed PMI.
    #[derive(Debug)]
    pub struct ParsedPmi {
        pub arch: HostArch,
        pub vcpu: VcpuState,
        /// `cpu:profile` target attribute (per `pmi/spec/cpu.md`). The
        /// raw profile name (e.g. `x86-64-v3`, `armv8.2-a`). The VMM
        /// validates it against host capabilities; this crate only
        /// carries the bytes faithfully.
        pub cpu_profile: pmi::cpu::Profile,
        pub actions: Vec<Action>,
        /// Every section placed in guest memory (named by a load or fill
        /// action). The bundled base named by `dt:dtb` is excluded — see
        /// `dt_dtb_source`.
        pub sections: BTreeMap<String, SectionInfo>,
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
        let mut raw_sections = collect_sections(&pe, file_size, bytes)?;

        // Locate `.pmi.vm` (MVP — only `vm` target is supported).
        let target_section_name = pmi::vm::Spec::<vcpu_x86_64::CpuState>::SECTION;
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

        // Strict CBOR decode (depth-limited) into the arch-correct Spec<V>.
        let (vcpu, cpu_profile, actions_raw, merged_dtb) =
            decode_manifest_bytes(&target_section.body, opts.host_arch)?;

        // pmi spec f6be1eb: each load/fill action carries an explicit `gpa`;
        // the VMM places bytes there verbatim and MUST NOT consult the PE
        // `VirtualAddress`. Stamp the action GPA over the provisional
        // PE-derived value so all downstream placement, overlap, and bounds
        // checks operate on the authoritative address. (Sections not named by
        // any action — e.g. `.pmi.vm` — keep their PE address and are unused.)
        for a in &actions_raw {
            let (name, gpa) = match a {
                ManifestActionOwned::Load { gpa, section }
                | ManifestActionOwned::Fill { gpa, section, .. } => (section, *gpa),
            };
            if let Some(s) = raw_sections.get_mut(name) {
                s.gpa = gpa;
            }
        }

        // Resolve actions against the section table.
        let (actions, active_section_names, fill_kinds) =
            resolve_actions(&actions_raw, &raw_sections)?;

        // dt extension channel resolution (pmi/spec/dt.md, VMM selection
        // table). A base DTB must be available through either the `dt:dtb`
        // attribute (bundled / optional fallback) or a `dt:dtb` fill (detached /
        // optional); with neither, no base exists and the VMM MUST refuse. The
        // `dt:dtbo` overlay fill is orthogonal — present only when the image
        // delegates a resource.
        let has_dt_dtb_fill = fill_kinds.iter().any(|k| matches!(k, FillKind::DtDtb));
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

        // Sections placed in guest memory are exactly those named by a load or
        // fill action. The `dt:dtb` attribute names a bundled base the VMM only
        // reads (in bundled mode it is separately loaded; in optional mode it is
        // an unplaced fallback), so it is NOT part of this set — including it
        // would false-overlap with the section it reserves.
        let all_active: Vec<String> = active_section_names.clone();

        // Validate every active-target section: alignment, GPA bounds.
        for name in &all_active {
            let s = &raw_sections[name];
            validate_section(name, s)?;
        }

        // No overlap among active-target sections.
        let mut overlap_pool: Vec<(String, &RawSection)> = all_active
            .iter()
            .map(|n| (n.clone(), &raw_sections[n]))
            .collect();
        overlap_pool.sort_by_key(|(_, s)| s.gpa);
        for w in overlap_pool.windows(2) {
            let (a_name, a) = &w[0];
            let (b_name, b) = &w[1];
            let a_end =
                a.gpa
                    .checked_add(a.virtual_size)
                    .ok_or_else(|| Error::VirtualAddressOverflow {
                        name: a_name.clone(),
                    })?;
            if a_end > b.gpa {
                return Err(Error::SectionsOverlap {
                    a: a_name.clone(),
                    b: b_name.clone(),
                });
            }
        }

        // §5.5 sum-of-loaded cap.
        let load_section_names: Vec<&String> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Load { section } => Some(section),
                Action::Fill { .. } => None,
            })
            .collect();
        let total_loaded: u64 = load_section_names
            .iter()
            .map(|n| raw_sections[*n].virtual_size)
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
        let must_cover: Vec<(u64, u64)> = all_active
            .iter()
            .map(|n| {
                let s = &raw_sections[n];
                (s.gpa, s.virtual_size)
            })
            .collect();
        spread_check(&must_cover, total_loaded, memory_cap)?;

        // .dtbo size in [4 KiB, 64 KiB].
        for name in actions.iter().filter_map(|a| match a {
            Action::Fill {
                section,
                kind: FillKind::DtDtbo,
            } => Some(section),
            _ => None,
        }) {
            let s = &raw_sections[name];
            if s.virtual_size < caps::DTBO_MIN_SIZE || s.virtual_size > caps::DTBO_MAX_SIZE {
                return Err(Error::DtboSizeOutOfRange {
                    actual: s.virtual_size,
                    min: caps::DTBO_MIN_SIZE,
                    max: caps::DTBO_MAX_SIZE,
                });
            }
        }

        // Build the public SectionInfo table.
        let mut sections = BTreeMap::new();
        for name in &all_active {
            let s = &raw_sections[name];
            sections.insert(
                name.clone(),
                SectionInfo {
                    file_offset: s.file_offset,
                    file_size: s.file_size,
                    gpa: s.gpa,
                    virtual_size: s.virtual_size,
                },
            );
        }

        // The bundled base the `dt:dtb` attribute names, as a read-only source
        // (file bytes). It is deliberately kept out of `sections` so it never
        // enters placement, overlap, or coverage — the VMM only reads it, to
        // load (bundled) or to fill the reserved base section (optional).
        let dt_dtb_source = dt_dtb_attr.as_ref().map(|name| {
            let s = &raw_sections[name];
            SectionInfo {
                file_offset: s.file_offset,
                file_size: s.file_size,
                gpa: s.gpa,
                virtual_size: s.virtual_size,
            }
        });

        Ok(ParsedPmi {
            arch: opts.host_arch,
            vcpu,
            cpu_profile,
            actions,
            sections,
            dt_dtb_source,
        })
    }

    // ─── internals ──────────────────────────────────────────────────

    struct RawSection {
        file_offset: u64,
        file_size: u64,
        gpa: u64,
        virtual_size: u64,
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
            let gpa = section.address();
            let virtual_size = section.size();
            let (file_offset, file_size_field) = section.file_range().unwrap_or((0, 0));

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
                    file_offset,
                    file_size: file_size_field,
                    gpa,
                    virtual_size,
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
    ) -> Result<
        (
            VcpuState,
            pmi::cpu::Profile,
            Vec<ManifestActionOwned>,
            Option<String>,
        ),
        Error,
    > {
        let cursor = Cursor::new(bytes);
        match arch {
            HostArch::X86_64 => {
                let spec: Spec<vcpu_x86_64::CpuState> =
                    ciborium::de::from_reader_with_recursion_limit(cursor, caps::CBOR_MAX_DEPTH)
                        .map_err(|e| Error::CborDecode(e.to_string()))?;
                check_actions_len(&spec.actions)?;
                let actions = spec
                    .actions
                    .into_iter()
                    .map(ManifestActionOwned::from)
                    .collect();
                Ok((
                    VcpuState::X86_64(spec.vcpu),
                    spec.cpu_profile,
                    actions,
                    spec.dt_dtb,
                ))
            }
            HostArch::Aarch64 => {
                let spec: Spec<vcpu_aarch64::CpuState> =
                    ciborium::de::from_reader_with_recursion_limit(cursor, caps::CBOR_MAX_DEPTH)
                        .map_err(|e| Error::CborDecode(e.to_string()))?;
                check_actions_len(&spec.actions)?;
                let actions = spec
                    .actions
                    .into_iter()
                    .map(ManifestActionOwned::from)
                    .collect();
                Ok((
                    VcpuState::Aarch64(spec.vcpu),
                    spec.cpu_profile,
                    actions,
                    spec.dt_dtb,
                ))
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

    fn resolve_actions(
        raw: &[ManifestActionOwned],
        sections: &BTreeMap<String, RawSection>,
    ) -> Result<(Vec<Action>, Vec<String>, Vec<FillKind>), Error> {
        let mut actions = Vec::with_capacity(raw.len());
        let mut names = Vec::with_capacity(raw.len());
        let mut fills = Vec::new();

        for a in raw {
            // The action GPA was already stamped into the section table by the
            // caller; here we only need the section name + fill kind. Placement
            // flows through `SectionInfo.gpa`.
            let (name, action) = match a {
                ManifestActionOwned::Load { section, .. } => (
                    section.clone(),
                    Action::Load {
                        section: section.clone(),
                    },
                ),
                ManifestActionOwned::Fill { section, kind, .. } => {
                    let translated = translate_fill_kind(*kind);
                    fills.push(translated);
                    (
                        section.clone(),
                        Action::Fill {
                            section: section.clone(),
                            kind: translated,
                        },
                    )
                }
            };
            if !sections.contains_key(&name) {
                return Err(Error::ManifestReferencesMissingSection { section: name });
            }
            names.push(name);
            actions.push(action);
        }
        Ok((actions, names, fills))
    }

    fn translate_fill_kind(k: PmiFillKind) -> FillKind {
        match k {
            PmiFillKind::DtDtb => FillKind::DtDtb,
            PmiFillKind::DtDtbo => FillKind::DtDtbo,
        }
    }

    fn validate_section(name: &str, s: &RawSection) -> Result<(), Error> {
        // gpa + VirtualSize doesn't overflow u64.
        s.gpa
            .checked_add(s.virtual_size)
            .ok_or_else(|| Error::VirtualAddressOverflow {
                name: name.to_string(),
            })?;

        // The guest-address-width bound is no longer a hardcoded 2^48 (pmi
        // spec bc7f581): it is enforced post-survey in dillo-devtree's
        // `cross_validate_loads`, which knows the image's declared
        // address-space width. Parse-time validation here is width-agnostic.

        // Alignment per PMI granularity (`pmi/spec/granularity.md`, commits
        // 15768cf + 3b2260e): only a section's START is constrained — `gpa`
        // and `PointerToRawData`. `SizeOfRawData` follows PE `FileAlignment`
        // and carries no alignment requirement.
        if s.virtual_size >= caps::HUGE_PAGE {
            if !s.gpa.is_multiple_of(caps::HUGE_PAGE) {
                return Err(Error::AlignmentViolation {
                    name: name.to_string(),
                    virtual_size: s.virtual_size,
                    rule: "large section: gpa must be 2 MiB-aligned",
                });
            }
            if s.file_size > 0 && !s.file_offset.is_multiple_of(caps::HUGE_PAGE) {
                return Err(Error::AlignmentViolation {
                    name: name.to_string(),
                    virtual_size: s.virtual_size,
                    rule: "large section: PointerToRawData must be 2 MiB-aligned",
                });
            }
        } else if s.virtual_size > 0 {
            if !s.gpa.is_multiple_of(caps::SMALL_PAGE) {
                return Err(Error::AlignmentViolation {
                    name: name.to_string(),
                    virtual_size: s.virtual_size,
                    rule: "small section: gpa must be 4 KiB-aligned",
                });
            }
            if s.file_size > 0 && !s.file_offset.is_multiple_of(caps::SMALL_PAGE) {
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

    pub use pmi::cpu::Profile;
}
