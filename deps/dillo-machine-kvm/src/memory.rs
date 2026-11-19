// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Memfd + mmap plumbing for guest memory.

use std::ffi::CString;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use std::os::fd::{AsRawFd, FromRawFd};

use anyhow::{Context, Result, anyhow, bail};
use nix::fcntl::{FallocateFlags, fallocate};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::mman::{MapFlags, ProtFlags, mmap};
use nix::unistd::ftruncate;
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryMmap, GuestRegionMmap};

/// Owned memfd.
#[derive(Debug)]
struct Memfd {
    fd: std::os::fd::OwnedFd,
}

impl AsFd for Memfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

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

/// Create a memfd and size it to `total_bytes`, committing pages eagerly
/// only when preallocation is enabled.
///
/// Per ARCHITECTURE.md §8.1, guest memory is backed by 2 MiB huge pages
/// exclusively (`MFD_HUGETLB | MFD_HUGE_2MB`). By default pages are
/// committed lazily on first touch — faster boot, denser warm pools —
/// which means an exhausted hugepage pool surfaces as a **SIGBUS in the
/// guest at run time**, not a launch error. With [`set_preallocate`] on,
/// every page is `fallocate`d up front (~22ms/256MB) so pool exhaustion
/// fails cleanly at boot; use it when you don't own the pool's capacity
/// math. Either way the pool must have enough pages, or `memfd_create`
/// (or the first fault) fails.
fn create_and_size(total_bytes: u64) -> Result<Memfd> {
    let name = CString::new("dillo-guest").expect("static C string");
    let fd = memfd_create(
        name.as_c_str(),
        MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_HUGETLB | MFdFlags::MFD_HUGE_2MB,
    )
    .context("memfd_create (need 2 MiB huge pages; check vm.nr_hugepages)")?;
    let len = i64::try_from(total_bytes).context("memfd size > i64::MAX")?;
    ftruncate(&fd, len).context("ftruncate memfd")?;
    if PREALLOCATE.load(Ordering::Relaxed) {
        fallocate(&fd, FallocateFlags::FALLOC_FL_KEEP_SIZE, 0, len)
            .context("fallocate memfd (2 MiB hugepage pool exhausted?)")?;
    }
    Ok(Memfd { fd })
}

/// mmap a contiguous range of the memfd into the process address space.
/// Leaks the mapping for the VM's lifetime.
fn mmap_range(memfd: &Memfd, fd_offset: u64, size: u64) -> Result<u64> {
    if size == 0 {
        bail!("mmap_range: size = 0");
    }
    let len = NonZeroUsize::new(size as usize).expect("size > 0 checked above");
    let off = i64::try_from(fd_offset).context("memfd offset > i64::MAX")?;
    // nix's mmap is unsafe (caller owns aliasing/lifetime). We leak the
    // mapping for the VM's lifetime — dropping while KVM holds the
    // memslot would be unsound. Cleanup at process exit.
    #[allow(unsafe_code)]
    let host = unsafe {
        mmap(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            memfd,
            off,
        )
        .context("mmap memfd")?
    };
    Ok(host.as_ptr() as u64)
}

/// Build a `vm_memory::GuestMemoryMmap` over the already-mmap'd memfd
/// regions. The returned regions are **non-owning** wrappers around
/// the raw pointers — the underlying mmap is owned by `mmap_range`'s
/// leaked allocation, alive for the VM's lifetime.
///
/// Used by virtio transports and device backends that need typed
/// guest-memory access.
fn build_guest_memory(
    memfd: &Memfd,
    regions: &[(u64, u64, u64)], // (gpa, host_addr, size)
) -> Result<GuestMemoryMmap> {
    let mut built: Vec<GuestRegionMmap> = Vec::with_capacity(regions.len());
    let mut file_offset: u64 = 0;
    for &(gpa, host_addr, size) in regions {
        // FileOffset wants an owned File; clone the memfd via dup() so
        // the FileOffset's Arc<File> doesn't double-close the underlying
        // descriptor on Drop. Stays alive for the GuestMemoryMmap's
        // lifetime.
        // SAFETY: dup returns a fresh OS file-descriptor pointing at the
        // same kernel object; from_raw_fd takes ownership of that fresh
        // fd. No aliasing.
        #[allow(unsafe_code)]
        let owned_dup = unsafe {
            let raw = libc::dup(memfd.fd.as_raw_fd());
            if raw < 0 {
                return Err(anyhow!("dup memfd: {}", std::io::Error::last_os_error()));
            }
            std::fs::File::from_raw_fd(raw)
        };
        let fo = FileOffset::new(owned_dup, file_offset);

        // Non-owning mmap region wrapped around our existing host
        // pointer. `with_raw_mmap_pointer` triggers MmapRegionBuilder's
        // owned=false path so Drop won't munmap.
        // SAFETY: the host_addr region is alive for the VM's lifetime —
        // mmap_range leaked it. Size matches what we mapped.
        #[allow(unsafe_code)]
        let region = unsafe {
            MmapRegionBuilder::new(size as usize).with_raw_mmap_pointer(host_addr as *mut u8)
        }
        .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
        .with_mmap_flags(libc::MAP_SHARED)
        .with_file_offset(fo)
        .build()
        .map_err(|e| anyhow!("MmapRegionBuilder: {e}"))?;

        let gr = GuestRegionMmap::new(region, GuestAddress(gpa))
            .ok_or_else(|| anyhow!("GuestRegionMmap: gpa+size overflow for {:#x}+{}", gpa, size))?;
        built.push(gr);

        file_offset += size;
    }
    GuestMemoryMmap::from_regions(built).map_err(|e| anyhow!("GuestMemoryMmap: {e:?}"))
}

/// KVM-owned standard-VM guest memory backing.
#[derive(Debug)]
pub(crate) struct MappedMemory {
    _memfd: Memfd,
    guest_memory: GuestMemoryMmap,
}

impl MappedMemory {
    pub(crate) fn new(regions: impl IntoIterator<Item = (u64, u64)>) -> Result<Self> {
        let requested = regions.into_iter().collect::<Vec<_>>();
        let total_bytes = requested.iter().map(|(_, size)| *size).sum();
        let memfd = create_and_size(total_bytes)?;
        let mut mapped = Vec::with_capacity(requested.len());
        let mut host_base = 0;
        for (gpa, size) in requested {
            let host_addr = mmap_range(&memfd, host_base, size)?;
            mapped.push((gpa, host_addr, size));
            host_base += size;
        }
        let guest_memory = build_guest_memory(&memfd, &mapped)?;
        Ok(Self {
            _memfd: memfd,
            guest_memory,
        })
    }

    pub(crate) fn regions(&self) -> impl Iterator<Item = &GuestRegionMmap> {
        self.guest_memory.iter()
    }

    pub(crate) fn guest_memory(&self) -> GuestMemoryMmap {
        self.guest_memory.clone()
    }

    /// Write through the guest-memory view while preserving the single-region bound.
    pub(crate) fn write(&self, gpa: u64, source: &[u8]) -> Result<()> {
        self.guest_memory
            .get_slice(GuestAddress(gpa), source.len())?
            .write_slice(source, 0)?;
        Ok(())
    }
}
