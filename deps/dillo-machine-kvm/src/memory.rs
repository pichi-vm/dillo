// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Memfd + mmap plumbing for guest memory.

use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use nix::fcntl::{FallocateFlags, fallocate};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::unistd::ftruncate;
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{Bytes, FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap};

/// Whether to eagerly commit all guest RAM at creation. Default off:
/// pages commit lazily on first touch, which is faster to boot and lets
/// a warm pool pack more guests than the sum of their `--memory` maxima.
/// Enable via `--preallocate` (see [`set_preallocate`]) when the caller
/// wants OOM to surface cleanly at launch instead of a mid-run SIGBUS.
static PREALLOCATE: AtomicBool = AtomicBool::new(false);

/// Select eager guest-RAM commit. Called once from the entrypoint when
/// `--preallocate` is passed, before any VM is constructed.
pub fn set_preallocate(on: bool) {
    PREALLOCATE.store(on, Ordering::Relaxed);
}

/// Maps GPA → (host_addr, size). Used to translate guest-physical
/// writes (load-section copies, DTBO fill) into host-virtual writes.
#[derive(Debug)]
pub(crate) struct MappedRegion {
    gpa: u64,
    host_addr: u64,
    size: u64,
}

impl MappedRegion {
    pub(crate) fn gpa(&self) -> u64 {
        self.gpa
    }

    pub(crate) fn host_addr(&self) -> u64 {
        self.host_addr
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }
}

/// KVM-owned standard-VM guest memory backing.
#[derive(Debug)]
pub(crate) struct MappedMemory {
    regions: Vec<MappedRegion>,
    guest_memory: GuestMemoryMmap,
}

impl MappedMemory {
    pub(crate) fn new(regions: impl IntoIterator<Item = (u64, u64)>) -> Result<Self> {
        let requested = regions.into_iter().collect::<Vec<_>>();
        let total_bytes = requested.iter().try_fold(0u64, |total, (_, size)| {
            total.checked_add(*size).context("guest RAM size overflow")
        })?;
        // Preserve the existing hugepage and optional eager-commit policy.
        let fd = memfd_create(
            c"dillo-guest",
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_HUGETLB | MFdFlags::MFD_HUGE_2MB,
        )
        .context("memfd_create (need 2 MiB huge pages; check vm.nr_hugepages)")?;
        let len = i64::try_from(total_bytes).context("memfd size > i64::MAX")?;
        ftruncate(&fd, len).context("ftruncate memfd")?;
        if PREALLOCATE.load(Ordering::Relaxed) {
            fallocate(&fd, FallocateFlags::FALLOC_FL_KEEP_SIZE, 0, len)
                .context("fallocate memfd (2 MiB hugepage pool exhausted?)")?;
        }
        Self::map(requested, Arc::new(File::from(fd)))
    }

    #[cfg(test)]
    pub(crate) fn test_backing(regions: &[(u64, u64)]) -> Result<Self> {
        // Exercise production mapping and registration before CI provisions
        // hugepages; only this test allocation uses an ordinary memfd.
        let fd = memfd_create(c"dillo-test-guest", MFdFlags::MFD_CLOEXEC)?;
        ftruncate(
            &fd,
            i64::try_from(regions.iter().map(|(_, size)| *size).sum::<u64>())?,
        )?;
        Self::map(regions.to_vec(), Arc::new(File::from(fd)))
    }

    fn map(requested: Vec<(u64, u64)>, file: Arc<File>) -> Result<Self> {
        let mut views = Vec::with_capacity(requested.len());
        let mut regions = Vec::with_capacity(requested.len());
        let mut file_offset = 0u64;
        for (gpa, size) in requested {
            let size_usize = usize::try_from(size).context("guest RAM region exceeds usize")?;
            // This builder creates and owns its mapping. Cloned guest-memory
            // views retain the same owner; the final owner actually munmaps it.
            let region = MmapRegionBuilder::new(size_usize)
                .with_file_offset(FileOffset::from_arc(Arc::clone(&file), file_offset))
                .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
                .with_mmap_flags(libc::MAP_SHARED)
                .build()
                .with_context(|| format!("mmap memfd region at file offset {file_offset:#x}"))?;
            regions.push(MappedRegion {
                gpa,
                host_addr: region.as_ptr() as u64,
                size,
            });
            views.push(
                GuestRegionMmap::new(region, GuestAddress(gpa)).ok_or_else(|| {
                    anyhow!("GuestRegionMmap: gpa+size overflow for {gpa:#x}+{size}")
                })?,
            );
            file_offset = file_offset
                .checked_add(size)
                .context("memfd offset overflow")?;
        }
        let guest_memory = GuestMemoryMmap::from_regions(views)
            .map_err(|error| anyhow!("GuestMemoryMmap: {error:?}"))?;
        Ok(Self {
            regions,
            guest_memory,
        })
    }

    pub(crate) fn regions(&self) -> &[MappedRegion] {
        &self.regions
    }

    pub(crate) fn guest_memory(&self) -> GuestMemoryMmap {
        self.guest_memory.clone()
    }

    /// Copy through the owning guest-memory view, preserving the existing
    /// single-region range check and allowing concurrently mutable guest RAM.
    pub(crate) fn write(&self, gpa: u64, source: &[u8]) -> Result<()> {
        for region in &self.regions {
            if gpa >= region.gpa && gpa - region.gpa < region.size {
                if source.len() as u64 > region.size - (gpa - region.gpa) {
                    bail!(
                        "write spans region boundary: gpa={gpa:#x} len={} region={:#x}+{}",
                        source.len(),
                        region.gpa,
                        region.size
                    );
                }
                self.guest_memory.write_slice(source, GuestAddress(gpa))?;
                return Ok(());
            }
        }
        bail!("no region contains GPA {gpa:#x}")
    }
}

/// Keeps the backing file identity alive while observing real kernel mappings;
/// inode/device matching cannot mistake another allocation reusing an address.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct MappingProbe {
    file: Arc<File>,
    device: String,
    inode: u64,
}

#[cfg(test)]
impl MappingProbe {
    fn from_file(file: Arc<File>) -> Self {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().unwrap();
        Self {
            device: format!(
                "{:02x}:{:02x}",
                libc::major(metadata.dev()),
                libc::minor(metadata.dev())
            ),
            inode: metadata.ino(),
            file,
        }
    }

    pub(crate) fn new(memory: &MappedMemory) -> Self {
        Self::from_view(&memory.guest_memory)
    }

    pub(crate) fn from_view(memory: &GuestMemoryMmap) -> Self {
        use vm_memory::GuestMemory;
        let file = memory
            .iter()
            .next()
            .unwrap()
            .file_offset()
            .unwrap()
            .file()
            .try_clone()
            .unwrap();
        Self::from_file(Arc::new(file))
    }

    pub(crate) fn mappings(&self) -> usize {
        std::fs::read_to_string("/proc/self/maps")
            .unwrap()
            .lines()
            .filter(|line| {
                let mut fields = line.split_whitespace();
                fields.nth(3) == Some(self.device.as_str())
                    && fields.next().and_then(|inode| inode.parse::<u64>().ok()) == Some(self.inode)
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;

    #[test]
    fn owning_views_preserve_file_offsets_and_reclaim_after_last_region() {
        let memory = MappedMemory::test_backing(&[(0, 0x1000), (0x4000, 0x1000)]).unwrap();
        let probe = MappingProbe::new(&memory);
        let view = memory.guest_memory();
        memory.write(0x4000, b"shared without copying").unwrap();
        let mut bytes = [0u8; 22];
        probe.file.read_exact_at(&mut bytes, 0x1000).unwrap();
        assert_eq!(&bytes, b"shared without copying");
        let (_, region) = view.remove_region(GuestAddress(0x4000), 0x1000).unwrap();
        assert_eq!(region.file_offset().unwrap().start(), 0x1000);
        drop(memory);
        drop(view);
        assert!(probe.mappings() > 0);
        region
            .read_slice(&mut bytes, vm_memory::MemoryRegionAddress(0))
            .unwrap();
        assert_eq!(&bytes, b"shared without copying");
        drop(region);
        assert_eq!(probe.mappings(), 0);
    }

    #[test]
    fn mapping_failure_unmaps_successful_earlier_regions() {
        let file = Arc::new(tempfile::tempfile().unwrap());
        file.set_len(0x3000).unwrap();
        let probe = MappingProbe::from_file(Arc::clone(&file));
        let error = MappedMemory::map(vec![(0, 0x1001), (0x4000, 0x1000)], file).unwrap_err();
        // The second mapping's unaligned file offset fails after the first
        // native mmap succeeds; its contextual error identifies that branch.
        assert!(
            error.to_string().contains("file offset 0x1001"),
            "{error:#}"
        );
        assert_eq!(probe.mappings(), 0);
    }

    #[test]
    fn invalid_layout_reclaims_already_mapped_regions() {
        let file = Arc::new(tempfile::tempfile().unwrap());
        file.set_len(0x2000).unwrap();
        let probe = MappingProbe::from_file(Arc::clone(&file));
        let error = MappedMemory::map(vec![(0, 0x1000), (0, 0x1000)], file).unwrap_err();
        assert!(error.to_string().contains("GuestMemoryMmap"), "{error:#}");
        assert_eq!(probe.mappings(), 0);
    }

    #[test]
    fn writes_preserve_region_bounds_without_overflow() {
        let memory = MappedMemory::test_backing(&[(0, 0x1000), (0x1000, 0x1000)]).unwrap();
        assert!(memory.write(0xfff, &[1, 2]).is_err());
        assert!(memory.write(u64::MAX, &[1]).is_err());
        memory.write(0xfff, &[3]).unwrap();
        assert_eq!(
            memory
                .guest_memory()
                .read_obj::<u8>(GuestAddress(0xfff))
                .unwrap(),
            3
        );
    }
}
