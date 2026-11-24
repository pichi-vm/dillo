// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Memfd + mmap plumbing for guest memory.

use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, anyhow, ensure};
use nix::fcntl::{FallocateFlags, fallocate};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::unistd::ftruncate;
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{
    Bytes, FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestRegionMmap,
};

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

/// KVM-owned standard-VM guest memory backing.
#[derive(Debug)]
pub(crate) struct MappedMemory {
    guest_memory: GuestMemoryMmap,
}

impl MappedMemory {
    pub(crate) fn new(regions: impl IntoIterator<Item = (u64, u64)>) -> Result<Self> {
        // Linux's KVM_MEM_MAX_NR_PAGES limits each slot in host base pages.
        const MAX_SLOT_PAGES: u64 = (1 << 31) - 1;

        let requested = regions.into_iter().collect::<Vec<_>>();
        // Hugepage mmap rounds lengths up; munmap requires hugepage multiples.
        // Reject partial pages before allocating so cleanup uses the full extent.
        ensure!(
            requested
                .iter()
                .all(|(_, size)| *size > 0 && size.is_multiple_of(2 << 20)),
            "guest RAM regions must be nonzero multiples of 2 MiB"
        );
        // KVM requires GPA bases to align to the host's base page size.
        // SAFETY: sysconf reads a process-wide constant and takes no pointers.
        #[allow(unsafe_code)]
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = u64::try_from(page_size).context("invalid host page size")?;
        ensure!(page_size != 0, "host page size must be nonzero");
        ensure!(
            requested
                .iter()
                .all(|(gpa, _)| gpa.is_multiple_of(page_size)),
            "guest RAM bases must align to the host page size ({page_size})"
        );
        let total_bytes = requested.iter().try_fold(0u64, |total, &(gpa, size)| {
            ensure!(
                size / page_size <= MAX_SLOT_PAGES,
                "guest RAM region at {gpa:#x} with size {size:#x} exceeds the KVM slot limit of {MAX_SLOT_PAGES} host pages"
            );
            total.checked_add(size).context("guest RAM size overflow")
        })?;
        // Preserve the existing hugepage and optional eager-commit policy.
        let fd = memfd_create(
            c"dillo-guest",
            MFdFlags::MFD_CLOEXEC
                | MFdFlags::MFD_HUGETLB
                | MFdFlags::MFD_HUGE_2MB
                | MFdFlags::MFD_ALLOW_SEALING,
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
        let fd = memfd_create(
            c"dillo-test-guest",
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )?;
        ftruncate(
            &fd,
            i64::try_from(regions.iter().map(|(_, size)| *size).sum::<u64>())?,
        )?;
        Self::map(regions.to_vec(), Arc::new(File::from(fd)))
    }

    fn map(requested: Vec<(u64, u64)>, file: Arc<File>) -> Result<Self> {
        use nix::fcntl::{FcntlArg, SealFlag, fcntl};
        // Export grants writable mappings, never authority to shrink a native
        // VM's backing or change the seal policy. Writable mappings stay valid.
        fcntl(
            file.as_ref(),
            FcntlArg::F_ADD_SEALS(
                SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_SEAL,
            ),
        )?;
        let mut views = Vec::with_capacity(requested.len());
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
        Ok(Self { guest_memory })
    }

    pub(crate) fn regions(&self) -> impl Iterator<Item = &GuestRegionMmap> {
        self.guest_memory.iter()
    }

    pub(crate) fn guest_memory(&self) -> GuestMemoryMmap {
        self.guest_memory.clone()
    }

    /// Copy through the owning guest-memory view, preserving the existing
    /// single-region range check and allowing concurrently mutable guest RAM.
    pub(crate) fn write(&self, gpa: u64, source: &[u8]) -> Result<()> {
        self.guest_memory
            .get_slice(GuestAddress(gpa), source.len())?
            .write_slice(source, 0)?;
        Ok(())
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
    pub(crate) fn new(memory: &MappedMemory) -> Self {
        use std::os::unix::fs::MetadataExt;
        let file = Arc::clone(
            memory
                .guest_memory
                .iter()
                .next()
                .unwrap()
                .file_offset()
                .unwrap()
                .arc(),
        );
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
    fn hugepage_backing_rejects_partial_pages_before_mapping() {
        let error = MappedMemory::new([(0, 1 << 20), (2 << 20, 1 << 20)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "guest RAM regions must be nonzero multiples of 2 MiB"
        );
    }

    #[test]
    fn hugepage_backing_rejects_misaligned_guest_base_before_allocation() {
        let error = MappedMemory::new([(1, 2 << 20)]).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("guest RAM bases must align to the host page size")
        );
    }

    #[test]
    fn hugepage_backing_rejects_oversized_kvm_slot_before_allocation() {
        // SAFETY: sysconf reads a process-wide constant and takes no pointers.
        #[allow(unsafe_code)]
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let oversized = u64::try_from(page_size).unwrap() << 31;
        // The second extent makes the aggregate size overflow, so this fixture
        // cannot reach allocation even if the per-slot check regresses.
        let largest_hugepage_multiple = u64::MAX - ((2 << 20) - 1);
        let error = MappedMemory::new([(0, oversized), (oversized, largest_hugepage_multiple)])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "guest RAM region at 0x0 with size {oversized:#x} exceeds the KVM slot limit of 2147483647 host pages"
            )
        );
    }

    #[test]
    fn owning_views_preserve_file_offsets_and_reclaim_after_last_region() {
        let size = 0x10000;
        let second_gpa = 2 * size;
        let memory = MappedMemory::test_backing(&[(0, size), (second_gpa, size)]).unwrap();
        let probe = MappingProbe::new(&memory);
        let view = memory.guest_memory();
        memory.write(second_gpa, b"shared without copying").unwrap();
        let mut bytes = [0u8; 22];
        probe.file.read_exact_at(&mut bytes, size).unwrap();
        assert_eq!(&bytes, b"shared without copying");
        let (_, region) = view.remove_region(GuestAddress(second_gpa), size).unwrap();
        assert_eq!(region.file_offset().unwrap().start(), size);
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
}
