// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Standard-GPT byte synthesis for `dillo-virtio-blk-vgpt`.
//!
//! Synthesizes the in-RAM bytes of a UEFI-compliant GPT layout (protective MBR
//! at LBA 0 + primary header at LBA 1 + 32-LBA primary entry array + partition
//! data starting at LBA 34 + 32-LBA backup entry array + backup header at the
//! last LBA) using the `gpt 4.1.0` crate. Caller-supplied `PartitionSpec` fields
//! (PARTUUID / type GUID / label / 64-bit Attributes) are stamped verbatim per
//! the dumb-backend rule (Phase 48 D-vgpt-02 / D-vgpt-07).
//!
//! ## Pitfalls designed-out (Phase 48 RESEARCH §1 + §"Pitfalls A/B/C")
//!
//! - **Pitfall A** (random-access dispatch) — see [`crate::vgpt_backing`]; this
//!   module exposes `partition_lba_starts` / `partition_lba_ends` so the
//!   stateless backing can binary-search them on every `read_at`.
//! - **Pitfall B** (use ONE GPT API): this module calls `update_partitions`
//!   exactly once and never `add_partition` / `add_partition_at`. A test
//!   source-greps the file to enforce the invariant at every commit.
//! - **Pitfall C** (partition data overrun): every LBA arithmetic step uses
//!   `checked_add` / `checked_mul` / `div_ceil`; after `gdisk.write()` we
//!   re-parse the synthesized bytes via `gpt::GptConfig::open_from_device`
//!   defense-in-depth and bail with a typed error if the round-trip fails or
//!   the partition count differs from the input.
//!
//! ## Disk-GUID (Phase 49 D-run-AMEND)
//!
//! The 16-byte disk GUID is caller-supplied (Phase 49 D-run-AMEND) and stamped
//! verbatim into the GPT header.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow, bail};

use crate::PartitionSpec;

/// LBA / sector size used by all GPT math (Phase 48 D-vgpt-05).
pub const SECTOR_SIZE: u64 = 512;

/// Number of LBAs reserved at the front of the disk before partition data
/// (LBA 0 protective MBR + LBA 1 primary header + LBA 2..33 primary entry
/// array — 32 sectors covering up to 128 entries).
pub const FRONT_RESERVED_LBAS: u64 = 34;

/// Number of LBAs reserved at the back of the disk (32 entry-array sectors
/// plus 1 backup-header sector; per UEFI spec the backup header occupies
/// the last LBA `N-1`).
pub const BACK_RESERVED_LBAS: u64 = 33;

/// Maximum number of partitions supported. UEFI GPT spec hard upper bound.
pub const MAX_PARTITIONS: usize = 128;

/// Output of [`build`] — the synthesized GPT bytes plus the LBA / byte index
/// metadata needed by [`crate::vgpt_backing::VgptBacking`] to dispatch `read_at`.
#[derive(Debug)]
pub struct SynthResult {
    /// Bytes covering LBA 0..=33 inclusive (protective MBR + primary header +
    /// primary entry array). Length = `34 * 512 = 17408` bytes.
    pub primary_gpt_bytes: Arc<Vec<u8>>,
    /// Bytes covering LBA `(N-33)..=(N-1)` inclusive (backup entry array +
    /// backup header). Length = `33 * 512 = 16896` bytes.
    pub backup_gpt_bytes: Arc<Vec<u8>>,
    /// Exclusive byte offset where the primary GPT region ends and the
    /// partition-data region begins. Equal to `FRONT_RESERVED_LBAS * 512`.
    pub primary_gpt_end_bytes: u64,
    /// Inclusive byte offset where the backup GPT region begins. Equal to
    /// `(total_sectors - BACK_RESERVED_LBAS) * 512`.
    pub backup_gpt_start_bytes: u64,
    /// First LBA of partition `i` (1-indexed in GPT, 0-indexed here).
    pub partition_lba_starts: Vec<u64>,
    /// Last LBA of partition `i` (inclusive).
    pub partition_lba_ends: Vec<u64>,
    /// Total disk size in bytes (`total_sectors * 512`).
    pub total_size_bytes: u64,
}

/// Synthesize a standard GPT layout over `partitions` with byte sizes
/// `sizes_bytes`. The 16-byte `disk_guid` is stamped verbatim into the GPT
/// header (Phase 49 D-run-AMEND — caller-supplied; the backend has zero
/// derivation logic). `device_id` is unused by the synth itself but is
/// preserved in the signature so the caller can keep `T_GET_ID` and the
/// disk-GUID independent (the dillo-run orchestrator may derive both from
/// the same source hash, but the backend treats them as opaque).
///
/// # Errors
///
/// - `partitions.len() != sizes_bytes.len()` — the two slices index together.
/// - `partitions.is_empty()` — at least one partition required.
/// - `partitions.len() > MAX_PARTITIONS` — UEFI GPT max is 128 entries.
/// - any `sizes_bytes[i] == 0` — empty partitions are rejected at the API
///   boundary; the caller would synthesize a zero-sector range otherwise.
/// - LBA arithmetic overflows `u64` (Pitfall C overrun guard).
/// - the post-build re-parse via `gpt::GptConfig::open_from_device` fails or
///   reports a different partition count than the input (Pitfall C
///   defense-in-depth).
pub fn build(
    partitions: &[PartitionSpec],
    sizes_bytes: &[u64],
    _device_id: [u8; 20],
    disk_guid: [u8; 16],
) -> Result<SynthResult> {
    // ---- 1. Validate inputs -------------------------------------------------
    if partitions.len() != sizes_bytes.len() {
        bail!(
            "partition count mismatch: {} specs vs {} sizes",
            partitions.len(),
            sizes_bytes.len()
        );
    }
    if partitions.is_empty() {
        bail!("at least one partition required");
    }
    if partitions.len() > MAX_PARTITIONS {
        bail!(
            "partition count {} exceeds GPT max of {}",
            partitions.len(),
            MAX_PARTITIONS
        );
    }
    for (i, &size) in sizes_bytes.iter().enumerate() {
        if size == 0 {
            bail!("partition {i} has zero byte size");
        }
    }
    // WR-03: UEFI GPT spec §5.3.3 — partition_name is 72 bytes = 36 UTF-16
    // code units. Enforce here (not in the CLI parser) so direct lib
    // consumers also get the bound; the gpt crate's behavior on over-length
    // names is unspecified.
    for (i, spec) in partitions.iter().enumerate() {
        let units = spec.label.encode_utf16().count();
        if units > 36 {
            bail!(
                "partition {i} label exceeds UEFI 36 UTF-16 code-unit bound \
                 (got {units}): {:?}",
                spec.label
            );
        }
    }

    // ---- 2. Compute LBA layout (Pitfall C: checked arithmetic everywhere) --
    let mut partition_lba_starts: Vec<u64> = Vec::with_capacity(partitions.len());
    let mut partition_lba_ends: Vec<u64> = Vec::with_capacity(partitions.len());
    let mut next_first_lba: u64 = FRONT_RESERVED_LBAS;
    for (i, &size) in sizes_bytes.iter().enumerate() {
        let sectors = size.div_ceil(SECTOR_SIZE);
        let last_lba = next_first_lba
            .checked_add(sectors)
            .and_then(|v| v.checked_sub(1))
            .ok_or_else(|| anyhow!("Pitfall C: LBA overflow at partition {i}"))?;
        partition_lba_starts.push(next_first_lba);
        partition_lba_ends.push(last_lba);
        next_first_lba = last_lba
            .checked_add(1)
            .ok_or_else(|| anyhow!("Pitfall C: LBA overflow advancing past partition {i}"))?;
    }
    let total_sectors = next_first_lba
        .checked_add(BACK_RESERVED_LBAS)
        .ok_or_else(|| anyhow!("Pitfall C: total sector overflow (back-reserved region)"))?;
    let total_size_bytes = total_sectors
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| anyhow!("Pitfall C: total byte count would exceed u64::MAX"))?;

    // total_sectors must fit in usize for the in-RAM Cursor allocation.
    let total_size_usize = usize::try_from(total_size_bytes)
        .map_err(|_| anyhow!("Pitfall C: total byte count {total_size_bytes} exceeds usize"))?;

    // ---- 3. Use the caller-supplied disk GUID verbatim (D-run-AMEND) -------
    let disk_guid_uuid = uuid::Uuid::from_bytes(disk_guid);

    // ---- 4. Build the in-RAM Cursor + protective MBR + GPT layout ----------
    let cursor = Cursor::new(vec![0u8; total_size_usize]);

    // The protective MBR's `with_lb_size` argument is the disk size in LBAs
    // minus 1 (clamped to 0xFFFF_FFFF for disks >= 2TiB, per UEFI spec).
    let mbr_lb_size = u32::try_from(total_sectors - 1).unwrap_or(0xFFFF_FFFF);
    let mbr = gpt::mbr::ProtectiveMBR::with_lb_size(mbr_lb_size);
    let mut cursor = {
        let mut c = cursor;
        mbr.overwrite_lba0(&mut c)
            .map_err(|e| anyhow!("failed to write protective MBR: {e}"))?;
        c
    };
    // Reset the cursor position so `create_from_device` starts from offset 0
    // (it seeks internally, but be defensive against future gpt-crate changes).
    cursor
        .seek(SeekFrom::Start(0))
        .context("failed to rewind cursor before create_from_device")?;

    let mut gdisk = gpt::GptConfig::default()
        .writable(true)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .create_from_device(cursor, Some(disk_guid_uuid))
        .map_err(|e| anyhow!("failed to create_from_device: {e}"))?;

    // ---- 5. Populate partition entries via update_partitions (Pitfall B) ---
    let mut entries: BTreeMap<u32, gpt::partition::Partition> = BTreeMap::new();
    for (i, spec) in partitions.iter().enumerate() {
        let part_index =
            u32::try_from(i + 1).map_err(|_| anyhow!("partition index {i} overflow u32"))?;
        let part = gpt::partition::Partition {
            // Stamp the caller's typeguid verbatim. We deliberately do NOT call
            // `Type::from_name` (which is the only `Type` constructor in
            // gpt 4.1.0) because that would lose the caller's exact 16-byte
            // value. Struct-literal init keeps us in the "dumb backend" lane.
            part_type_guid: gpt::partition_types::Type {
                guid: spec.typeguid,
                os: gpt::partition_types::OperatingSystem::None,
            },
            part_guid: spec.partuuid,
            first_lba: partition_lba_starts[i],
            last_lba: partition_lba_ends[i],
            // D-vgpt-07: stamp the caller's 64-bit attrs into the GPT entry's
            // `flags` field verbatim. This includes any custom bits the caller
            // wants the guest to observe (e.g., dm-verity metadata flags).
            flags: spec.attrs,
            name: spec.label.clone(),
        };
        entries.insert(part_index, part);
    }
    gdisk
        .update_partitions(entries)
        .map_err(|e| anyhow!("update_partitions failed: {e}"))?;

    let mut written = gdisk
        .write()
        .map_err(|e| anyhow!("gdisk.write failed: {e}"))?;

    // ---- 6. Pitfall C defense-in-depth: re-parse the synthesized bytes -----
    written
        .seek(SeekFrom::Start(0))
        .context("failed to rewind cursor for re-parse")?;
    let parsed = gpt::GptConfig::default()
        .writable(false)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .open_from_device(&mut written)
        .map_err(|e| anyhow!("Pitfall C re-parse failed: {e}"))?;
    if parsed.partitions().len() != partitions.len() {
        bail!(
            "Pitfall C: re-parse partition count mismatch (input={}, parsed={})",
            partitions.len(),
            parsed.partitions().len()
        );
    }

    // ---- 7. Slice the in-memory disk into primary / backup GPT regions -----
    written
        .seek(SeekFrom::Start(0))
        .context("failed to rewind cursor for primary slice")?;
    let mut full = vec![0u8; total_size_usize];
    written
        .read_exact(&mut full)
        .context("failed to read synthesized disk bytes")?;

    let primary_end_usize = (FRONT_RESERVED_LBAS as usize) * (SECTOR_SIZE as usize);
    let backup_start_usize =
        ((total_sectors - BACK_RESERVED_LBAS) as usize) * (SECTOR_SIZE as usize);

    let primary_gpt_bytes = Arc::new(full[..primary_end_usize].to_vec());
    let backup_gpt_bytes = Arc::new(full[backup_start_usize..].to_vec());

    Ok(SynthResult {
        primary_gpt_bytes,
        backup_gpt_bytes,
        primary_gpt_end_bytes: primary_end_usize as u64,
        backup_gpt_start_bytes: backup_start_usize as u64,
        partition_lba_starts,
        partition_lba_ends,
        total_size_bytes,
    })
}

// ---------------------------------------------------------------------------
// Tests (Phase 48 VGPT-02 / VGPT-04 / D-vgpt-07 / Pitfalls B+C; Phase 49
// D-run-AMEND parameterizes `build` on a caller-supplied `disk_guid`.)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec(label: &str, partuuid: u128, typeguid: u128, attrs: u64) -> PartitionSpec {
        PartitionSpec {
            path: PathBuf::from(format!("/tmp/{label}.bin")),
            partuuid: uuid::Uuid::from_u128(partuuid),
            typeguid: uuid::Uuid::from_u128(typeguid),
            label: label.to_string(),
            attrs,
        }
    }

    fn make_specs() -> Vec<PartitionSpec> {
        vec![
            spec(
                "alpha",
                0x1111_1111_2222_2222_3333_3333_4444_4444,
                0x0FC6_3DAF_8483_4772_8E79_3D69_D843_30F1, // Linux filesystem
                0x0000_0000_0000_0001,
            ),
            spec(
                "beta",
                0x5555_5555_6666_6666_7777_7777_8888_8888,
                0xC12A_7328_F81F_11D2_BA4B_00A0_C93E_C93B, // EFI system
                0xC000_0000_0000_0000,
            ),
        ]
    }

    fn make_device_id() -> [u8; 20] {
        let mut id = [0u8; 20];
        id.copy_from_slice(b"dillo-test-id-------");
        id
    }

    /// `[0xAA; 16]` — visually distinct from the 20-byte device-id literal so
    /// stamping bugs that crossed the two values would surface obviously.
    fn make_disk_guid() -> [u8; 16] {
        [0xAAu8; 16]
    }

    /// Test 1: 2-partition build, exact LBA layout, and re-parse round-trip
    /// preserves PARTUUID / typeguid / label / attrs verbatim.
    #[test]
    fn build_two_partitions_round_trips() {
        let specs = make_specs();
        let sizes = [4096u64, 8192u64];
        let id = make_device_id();
        let dg = make_disk_guid();
        let synth = build(&specs, &sizes, id, dg).expect("build OK");

        // Layout: front 34 LBAs, p0 = 8 sectors (4096/512), p1 = 16 sectors (8192/512)
        assert_eq!(synth.partition_lba_starts, vec![34, 42]);
        assert_eq!(synth.partition_lba_ends, vec![41, 57]);
        assert_eq!(synth.primary_gpt_end_bytes, 34 * 512);
        // total_sectors = 34 + 8 + 16 + 33 = 91; backup_start = (91-33)*512 = 58*512
        assert_eq!(synth.backup_gpt_start_bytes, 58 * 512);
        assert_eq!(synth.total_size_bytes, 91 * 512);

        // Re-parse round-trip via gpt::GptConfig::open_from_device on a
        // reconstructed full-disk Cursor (primary | partition data | backup).
        let mut full = vec![0u8; synth.total_size_bytes as usize];
        full[..synth.primary_gpt_bytes.len()].copy_from_slice(&synth.primary_gpt_bytes);
        full[synth.backup_gpt_start_bytes as usize..].copy_from_slice(&synth.backup_gpt_bytes);
        let mut cursor = Cursor::new(full);
        let parsed = gpt::GptConfig::default()
            .writable(false)
            .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
            .open_from_device(&mut cursor)
            .expect("re-parse OK");
        let parts = parsed.partitions();
        assert_eq!(parts.len(), 2, "two partitions must round-trip");

        // Order from BTreeMap<u32, _> is insertion-stable on u32 keys 1, 2.
        let p1 = parts.get(&1).expect("partition 1 present");
        let p2 = parts.get(&2).expect("partition 2 present");

        assert_eq!(p1.part_guid, specs[0].partuuid, "p1 partuuid verbatim");
        assert_eq!(
            p1.part_type_guid.guid, specs[0].typeguid,
            "p1 typeguid verbatim"
        );
        assert_eq!(p1.name, specs[0].label, "p1 label verbatim");
        assert_eq!(p1.flags, specs[0].attrs, "p1 attrs verbatim (D-vgpt-07)");
        assert_eq!(p1.first_lba, 34);
        assert_eq!(p1.last_lba, 41);

        assert_eq!(p2.part_guid, specs[1].partuuid, "p2 partuuid verbatim");
        assert_eq!(
            p2.part_type_guid.guid, specs[1].typeguid,
            "p2 typeguid verbatim"
        );
        assert_eq!(p2.name, specs[1].label, "p2 label verbatim");
        assert_eq!(p2.flags, specs[1].attrs, "p2 attrs verbatim");
        assert_eq!(p2.first_lba, 42);
        assert_eq!(p2.last_lba, 57);
    }

    /// Different `disk_guid` values ⇒ different primary GPT bytes (the GPT
    /// header embeds the caller-supplied 16-byte disk GUID verbatim per
    /// D-run-AMEND). `device_id` is irrelevant to the synth; only `disk_guid`
    /// changes the header bytes.
    #[test]
    fn build_with_different_disk_guids_differs() {
        let specs = make_specs();
        let sizes = [4096u64, 8192u64];
        let id = make_device_id();

        let dg_a: [u8; 16] = [0xAAu8; 16];
        let dg_b: [u8; 16] = [0xBBu8; 16];
        assert_ne!(dg_a, dg_b, "test setup: disk_guids must differ");

        let a = build(&specs, &sizes, id, dg_a).expect("build OK");
        let b = build(&specs, &sizes, id, dg_b).expect("build OK");
        assert_ne!(
            *a.primary_gpt_bytes, *b.primary_gpt_bytes,
            "different disk_guid → different primary GPT bytes"
        );

        // Both runs must round-trip through the layout identically (the GPT
        // header just embeds a different disk_guid; the layout shape is
        // independent of the disk_guid bytes).
        assert_eq!(a.partition_lba_starts, b.partition_lba_starts);
        assert_eq!(a.partition_lba_ends, b.partition_lba_ends);
        assert_eq!(a.total_size_bytes, b.total_size_bytes);
    }

    /// Test 4: 64-bit attrs round-trip verbatim through the GPT entry's
    /// `flags` field (D-vgpt-07).
    #[test]
    fn build_attrs_stamped_verbatim() {
        let mut specs = make_specs();
        specs[0].attrs = 0xC000_0000_0000_0000;
        specs[1].attrs = 0x8000_0000_0000_0001;
        let sizes = [4096u64, 8192u64];
        let id = make_device_id();
        let dg = make_disk_guid();
        let synth = build(&specs, &sizes, id, dg).expect("build OK");

        let mut full = vec![0u8; synth.total_size_bytes as usize];
        full[..synth.primary_gpt_bytes.len()].copy_from_slice(&synth.primary_gpt_bytes);
        full[synth.backup_gpt_start_bytes as usize..].copy_from_slice(&synth.backup_gpt_bytes);
        let mut cursor = Cursor::new(full);
        let parsed = gpt::GptConfig::default()
            .writable(false)
            .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
            .open_from_device(&mut cursor)
            .expect("re-parse OK");
        assert_eq!(
            parsed.partitions().get(&1).unwrap().flags,
            0xC000_0000_0000_0000
        );
        assert_eq!(
            parsed.partitions().get(&2).unwrap().flags,
            0x8000_0000_0000_0001
        );
    }

    /// Test 5: Pitfall C overrun guard — `u64::MAX` size triggers the checked
    /// arithmetic to bail.
    #[test]
    fn build_pitfall_c_overrun_caught() {
        let specs = vec![spec("huge", 1, 2, 0)];
        let sizes = [u64::MAX];
        let id = make_device_id();
        let dg = make_disk_guid();
        let err = build(&specs, &sizes, id, dg).expect_err("must reject u64::MAX size");
        let msg = format!("{err}");
        assert!(
            msg.contains("Pitfall C") || msg.contains("overflow") || msg.contains("exceed"),
            "error must indicate overflow / Pitfall C: {msg}"
        );
    }

    /// Test 6: Pitfall B exclusivity — scan only the IMPLEMENTATION half of
    /// the file (everything before `#[cfg(test)]`) so the source-grep is not
    /// fooled by the test module's own diagnostic strings. The implementation
    /// half must contain at least one `update_partitions(` call and zero
    /// `add_partition(` / `add_partition_at(` calls outside `//` comments.
    #[test]
    fn build_pitfall_b_uses_update_partitions_exclusively() {
        let full = include_str!("synth_gpt.rs");
        // Take everything before the `#[cfg(test)]` marker — that's the
        // implementation half, which is what Pitfall B is about.
        let cutoff = full
            .find("#[cfg(test)]")
            .expect("synth_gpt.rs must have a #[cfg(test)] block");
        let src = &full[..cutoff];

        // Build the search tokens from concatenation so the grep doesn't
        // match its own literal string when scanning this file. The cutoff
        // above already excludes the test module, but defense-in-depth.
        let update_token: String = format!("{}{}", "update_partitions", "(");
        let add_token: String = format!("{}{}", "add_partition", "(");
        let add_at_token: String = format!("{}{}", "add_partition_at", "(");

        let mut update_count = 0usize;
        let mut add_count = 0usize;
        let mut add_at_count = 0usize;
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            // Strip inline `//` comments so a token in a comment doesn't count.
            let code = match trimmed.find("//") {
                Some(idx) => &trimmed[..idx],
                None => trimmed,
            };
            if code.contains(update_token.as_str()) {
                update_count += 1;
            }
            // `add_partition_at(` is a substring of nothing else of interest;
            // count it FIRST, then count `add_partition(` only when the line
            // does not also contain `add_partition_at(` (so we don't double-count).
            if code.contains(add_at_token.as_str()) {
                add_at_count += 1;
            }
            if code.contains(add_token.as_str()) && !code.contains(add_at_token.as_str()) {
                add_count += 1;
            }
        }
        assert!(
            update_count >= 1,
            "Pitfall B: update_partitions call must appear at least once in impl half \
             (found {update_count})"
        );
        assert_eq!(
            add_count, 0,
            "Pitfall B: add_partition call must NOT appear in impl half (found {add_count})"
        );
        assert_eq!(
            add_at_count, 0,
            "Pitfall B: add_partition_at call must NOT appear in impl half (found {add_at_count})"
        );
    }

    /// Test 7: 129-partition input rejected with "GPT max" diagnostic.
    #[test]
    fn build_partition_count_exceeds_max_caught() {
        let specs: Vec<PartitionSpec> = (0..129)
            .map(|i| spec(&format!("p{i}"), i as u128 + 1, i as u128 + 1000, 0))
            .collect();
        let sizes = vec![512u64; 129];
        let id = make_device_id();
        let dg = make_disk_guid();
        let err = build(&specs, &sizes, id, dg).expect_err("129 partitions must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("GPT max") || msg.contains("128"),
            "error must mention GPT max / 128: {msg}"
        );
    }
}
