// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Virtualized-GPT block backing.
//!
//! Synthesizes a standard GPT layout (protective MBR, primary header at LBA 1,
//! backup header at the last LBA) over a list of caller-supplied backing files
//! and exposes the assembly as a single [`BlockBacking`] (from
//! `dillo-virtio-blk`): one read-only virtio-blk disk whose partitions map to
//! distinct backing files.
//!
//! Ported from the dillo PoC `dillo-virtio-blk-vgpt` crate. The GPT synthesis
//! ([`synth_gpt`]) and the three-region read dispatch ([`VgptBacking`]) are
//! transport-agnostic — they only depend on the `BlockBacking` trait — so they
//! carry over unchanged. The PoC's vhost-user `run()`, seccomp filter, and
//! `PR_SET_PDEATHSIG` plumbing are dropped (the device now runs in-process); the
//! file-open + synth pipeline survives as [`assemble`].
//!
//! Partition metadata (PARTUUID, type GUID, label, 64-bit attributes) and the
//! 16-byte disk GUID + 20-byte device ID are all caller-supplied and stamped
//! verbatim — this crate has zero domain-specific knowledge.

pub mod synth_gpt;
pub mod vgpt_backing;

pub use synth_gpt::{SynthResult, build};
pub use vgpt_backing::VgptBacking;

use std::fs::File;
use std::path::PathBuf;

use anyhow::Context as _;

/// One partition's metadata + backing-file path. Fields are stamped verbatim
/// into the synthesized GPT entry.
#[derive(Debug, Clone)]
pub struct PartitionSpec {
    /// Path to the backing file whose contents become the partition's data.
    pub path: PathBuf,
    /// GPT entry's `Unique partition GUID` (PARTUUID).
    pub partuuid: uuid::Uuid,
    /// GPT entry's `Partition type GUID`.
    pub typeguid: uuid::Uuid,
    /// GPT entry's UTF-16 partition name (<=36 UTF-16 code units; UEFI bound).
    pub label: String,
    /// GPT entry's 64-bit `Attributes` field. Default 0.
    pub attrs: u64,
}

/// Open every backing file read-only, synthesize the GPT layout, and build a
/// [`VgptBacking`] ready to hand to `VirtioBlk::new(.., read_only = true)`.
///
/// # Errors
///
/// - empty partition list, or more than 128 partitions (GPT max);
/// - any backing file missing / unreadable / zero-size;
/// - GPT synthesis failure (see [`synth_gpt::build`]).
pub fn assemble(
    device_id: [u8; 20],
    disk_guid: [u8; 16],
    partitions: Vec<PartitionSpec>,
) -> anyhow::Result<VgptBacking> {
    anyhow::ensure!(!partitions.is_empty(), "at least one partition is required");
    anyhow::ensure!(
        partitions.len() <= synth_gpt::MAX_PARTITIONS,
        "partition count {} exceeds GPT max {}",
        partitions.len(),
        synth_gpt::MAX_PARTITIONS
    );

    let mut fds: Vec<File> = Vec::with_capacity(partitions.len());
    let mut sizes_bytes: Vec<u64> = Vec::with_capacity(partitions.len());
    for spec in &partitions {
        let f = File::open(&spec.path)
            .with_context(|| format!("failed to open backing file: {}", spec.path.display()))?;
        let len = f
            .metadata()
            .with_context(|| format!("failed to stat backing file: {}", spec.path.display()))?
            .len();
        anyhow::ensure!(len > 0, "zero-size backing file: {}", spec.path.display());
        sizes_bytes.push(len);
        fds.push(f);
    }

    let synth = synth_gpt::build(&partitions, &sizes_bytes, device_id, disk_guid)
        .context("failed to synthesize GPT layout")?;

    Ok(VgptBacking::new(fds, synth, device_id))
}
