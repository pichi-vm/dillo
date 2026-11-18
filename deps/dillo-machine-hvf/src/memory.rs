// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Owning Darwin shared-memory objects for one native HVF machine.

use std::os::fd::FromRawFd;
use std::sync::Arc;

use dillo_machine::RamRange;
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{Bytes, FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap};

use crate::hypervisor::Error;

#[derive(Debug)]
pub(crate) struct MappedRegion {
    pub(crate) gpa: u64,
    pub(crate) address: u64,
    pub(crate) size: u64,
}

/// Every exported view clones the actual mmap owners, including their file offsets.
#[derive(Debug)]
pub(crate) struct MappedMemory {
    regions: Vec<MappedRegion>,
    guest: GuestMemoryMmap,
}

impl MappedMemory {
    pub(crate) fn new(ranges: &[RamRange]) -> Result<Self, Error> {
        Self::allocate(
            ranges,
            #[cfg(test)]
            |_, _| Ok(()),
        )
    }

    fn allocate(
        ranges: &[RamRange],
        #[cfg(test)] mut before_map: impl FnMut(usize, &[GuestRegionMmap]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        // SAFETY: sysconf has no pointer arguments or process state mutation.
        #[allow(unsafe_code)]
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = u64::try_from(page).map_err(|_| Error::Hv("invalid host page size".into()))?;
        if page == 0 || ranges.is_empty() {
            return Err(Error::Hv(
                "RAM requires nonempty, host-page-aligned extents".into(),
            ));
        }
        let mut total = 0u64;
        let mut previous_end = 0;
        for range in ranges {
            let end = range
                .gpa
                .checked_add(range.size)
                .ok_or_else(|| Error::Hv("RAM guest extent overflow".into()))?;
            if range.size == 0
                || range.gpa % page != 0
                || range.size % page != 0
                || range.gpa < previous_end
            {
                return Err(Error::Hv(
                    "RAM extents must be ordered, disjoint and host-page aligned".into(),
                ));
            }
            usize::try_from(range.size)
                .map_err(|_| Error::Hv("RAM extent exceeds usize".into()))?;
            total = total
                .checked_add(range.size)
                .ok_or_else(|| Error::Hv("RAM backing size overflow".into()))?;
            previous_end = end;
        }
        i64::try_from(total).map_err(|_| Error::Hv("RAM backing exceeds off_t".into()))?;
        // 120 random bits fit Darwin's 31-byte name limit as slash + hex.
        let mut random = [0u8; 15];
        // SAFETY: random is writable for its full length, below getentropy's limit.
        #[allow(unsafe_code)]
        if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
            return Err(Error::Hv(format!(
                "RAM name entropy: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut name = [0u8; 32];
        name[0] = b'/';
        for (index, byte) in random.into_iter().enumerate() {
            name[1 + index * 2] = b"0123456789abcdef"[usize::from(byte >> 4)];
            name[2 + index * 2] = b"0123456789abcdef"[usize::from(byte & 15)];
        }
        // SAFETY: name is NUL-terminated. Darwin atomically sets CLOEXEC on
        // shm descriptors; O_EXCL prevents opening a preexisting object.
        #[allow(unsafe_code)]
        let descriptor = unsafe {
            libc::shm_open(
                name.as_ptr().cast(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600 as libc::c_uint,
            )
        };
        if descriptor < 0 {
            return Err(Error::Hv(format!(
                "RAM shm_open: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: shm_open returned a new descriptor whose ownership is transferred.
        #[allow(unsafe_code)]
        let file = Arc::new(unsafe { std::fs::File::from_raw_fd(descriptor) });
        // Unlink before allocation or publication. Every later failure drops
        // the last unpublished reference; no RAM-sized regular file is needed.
        // SAFETY: name remains NUL-terminated and identifies the object just created.
        #[allow(unsafe_code)]
        if unsafe { libc::shm_unlink(name.as_ptr().cast()) } != 0 {
            return Err(Error::Hv(format!(
                "RAM shm_unlink: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Darwin permits this once per shm object, then rejects resizing even
        // through writable duplicates. No sizing authority is exported.
        file.set_len(total)
            .map_err(|e| Error::Hv(format!("RAM shared-memory size: {e}")))?;
        let mut offset = 0;
        let mut regions = Vec::with_capacity(ranges.len());
        let mut views = Vec::with_capacity(ranges.len());
        for range in ranges {
            #[cfg(test)]
            before_map(views.len(), &views)?;
            let mapping = MmapRegionBuilder::new(range.size as usize)
                .with_file_offset(FileOffset::from_arc(Arc::clone(&file), offset))
                .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
                .with_mmap_flags(libc::MAP_SHARED)
                .build()
                .map_err(|e| Error::Hv(format!("RAM mmap: {e}")))?;
            if !(mapping.as_ptr() as u64).is_multiple_of(page) {
                return Err(Error::Hv("RAM host mapping is not page aligned".into()));
            }
            regions.push(MappedRegion {
                gpa: range.gpa,
                address: mapping.as_ptr() as u64,
                size: range.size,
            });
            views.push(
                GuestRegionMmap::new(mapping, GuestAddress(range.gpa))
                    .ok_or_else(|| Error::Hv("RAM guest extent overflow".into()))?,
            );
            offset += range.size;
        }
        let guest = GuestMemoryMmap::from_regions(views)
            .map_err(|e| Error::Hv(format!("RAM regions: {e}")))?;
        Ok(Self { regions, guest })
    }

    pub(crate) fn regions(&self) -> &[MappedRegion] {
        &self.regions
    }

    pub(crate) fn guest_memory(&self) -> GuestMemoryMmap {
        self.guest.clone()
    }

    pub(crate) fn write(&self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        let count = data.len() as u64;
        if !self
            .regions
            .iter()
            .any(|r| gpa >= r.gpa && gpa - r.gpa <= r.size && count <= r.size - (gpa - r.gpa))
        {
            return Err(Error::UnmappedGuestAddr(gpa));
        }
        self.guest
            .write_slice(data, GuestAddress(gpa))
            .map_err(|e| Error::Hv(format!("RAM write: {e}")))
    }
}

/// Independent alias keeps the observed VM object alive without retaining the
/// original mapping. Object identity cannot be reused by freeing that object.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct MappingProbe {
    witness: vm_memory::mmap::MmapRegion,
    address: u64,
    size: u64,
}

#[cfg(test)]
impl MappingProbe {
    pub(crate) fn new(memory: &MappedMemory, index: usize) -> Self {
        use vm_memory::GuestMemory as _;
        Self::from_region(memory.guest.iter().nth(index).unwrap())
    }

    fn from_region(region: &GuestRegionMmap) -> Self {
        use vm_memory::GuestMemoryRegion as _;
        let witness = MmapRegionBuilder::new(region.size())
            .with_file_offset(region.file_offset().unwrap().clone())
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_SHARED)
            .build()
            .unwrap();
        Self {
            witness,
            address: region.as_ptr() as u64,
            size: region.size() as u64,
        }
    }

    pub(crate) fn alias(&self) -> vm_memory::mmap::MmapRegion {
        MmapRegionBuilder::new(self.size as usize)
            .with_file_offset(self.witness.file_offset().unwrap().clone())
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_SHARED)
            .build()
            .unwrap()
    }

    pub(crate) fn is_mapped(&self) -> bool {
        let expected = Self::identity_at(self.witness.as_ptr() as u64, self.size)
            .expect("retained independent alias must cover the original object");
        Self::identity_at(self.address, self.size) == Some(expected)
    }

    fn identity_at(address: u64, size: u64) -> Option<(u32, u64)> {
        // XNU bsd/sys/proc_info.h: proc_regioninfo, flavor7. This does not
        // require a vnode. pri_obj_id is an observational 32-bit identity hash,
        // not a capability; the alias keeps the underlying object from reuse.
        // https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h
        #[derive(Default)]
        #[repr(C)]
        struct RegionInfo {
            protection: [u32; 4],
            offset: u64,
            details: [u32; 12],
            object_id: u32,
            depth: u32,
            address: u64,
            size: u64,
        }
        assert_eq!(std::mem::size_of::<RegionInfo>(), 96);
        assert_eq!(std::mem::offset_of!(RegionInfo, object_id), 72);
        assert_eq!(std::mem::offset_of!(RegionInfo, address), 80);
        let mut result = RegionInfo::default();
        // SAFETY: result is writable for the exact PROC_PIDREGIONINFO layout.
        // No freed host pointer is dereferenced.
        #[allow(unsafe_code)]
        let count = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                7, /* PROC_PIDREGIONINFO */
                address,
                (&raw mut result).cast(),
                i32::try_from(std::mem::size_of::<RegionInfo>()).unwrap(),
            )
        };
        // Unsupported/failed queries never constitute reclamation evidence.
        assert_eq!(
            count as usize,
            std::mem::size_of::<RegionInfo>(),
            "native VM-object query failed: {}",
            std::io::Error::last_os_error()
        );
        if address < result.address
            || address - result.address >= result.size
            || size > result.size - (address - result.address)
        {
            return None;
        }
        assert_ne!(result.object_id, 0, "native object identity is unavailable");
        Some((
            result.object_id,
            result.offset.checked_add(address - result.address).unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use vm_memory::{GuestMemory as _, VolatileMemory as _};

    #[test]
    fn writable_shared_object_descriptor_cannot_resize_ram() {
        let memory = MappedMemory::new(&[RamRange {
            gpa: 0,
            size: 0x4000,
        }])
        .unwrap();
        let region = memory.guest.iter().next().unwrap();
        let backing = region.file_offset().unwrap().file();
        assert_eq!(backing.metadata().unwrap().permissions().mode() & 0o077, 0);
        // SAFETY: fcntl observes flags of a descriptor retained by backing.
        #[allow(unsafe_code)]
        let descriptor_flags = unsafe { libc::fcntl(backing.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(descriptor_flags, -1);
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
        // SAFETY: F_GETFL similarly observes the descriptor's access mode.
        #[allow(unsafe_code)]
        let access = unsafe { libc::fcntl(backing.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(access, -1);
        assert_eq!(access & libc::O_ACCMODE, libc::O_RDWR);
        let duplicate = backing.try_clone().unwrap();
        memory.write(8, &[0xa5, 0x5a]).unwrap();
        for size in [0, 0x4000, 0x8000] {
            let error = duplicate.set_len(size).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
            assert_eq!(backing.metadata().unwrap().len(), 0x4000);
            let mut bytes = [0; 2];
            memory
                .guest
                .read_slice(&mut bytes, GuestAddress(8))
                .unwrap();
            assert_eq!(bytes, [0xa5, 0x5a]);
        }
        let error = MmapRegionBuilder::<()>::new(0x4000)
            .with_file_offset(FileOffset::new(duplicate, 0x4000))
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_SHARED)
            .build()
            .unwrap_err();
        assert!(
            matches!(error, vm_memory::mmap::MmapRegionError::Mmap(e) if e.raw_os_error() == Some(libc::EINVAL))
        );
    }

    #[test]
    fn shared_object_views_keep_offsets_and_reclaim_real_mappings() {
        let memory = MappedMemory::new(&[
            RamRange {
                gpa: 0,
                size: 0x4000,
            },
            RamRange {
                gpa: 0x10000,
                size: 0x4000,
            },
        ])
        .unwrap();
        let first = MappingProbe::new(&memory, 0);
        let second = MappingProbe::new(&memory, 1);
        let export = memory.guest_memory();
        let region_export = export.iter().nth(1).unwrap().get_mmap();
        let alias = second.alias();
        assert_eq!(region_export.file_offset().unwrap().start(), 0x4000);
        memory.write(0x10003, &[0xa5, 0x5a]).unwrap();
        let mut bytes = [0; 2];
        alias.as_volatile_slice().read_slice(&mut bytes, 3).unwrap();
        assert_eq!(bytes, [0xa5, 0x5a]);
        alias.as_volatile_slice().write_slice(&[0x7b], 4).unwrap();
        export
            .read_slice(&mut bytes, GuestAddress(0x10003))
            .unwrap();
        assert_eq!(bytes, [0xa5, 0x7b]);
        assert!(first.is_mapped());
        assert!(second.is_mapped());
        drop(memory);
        drop(export);
        assert!(!first.is_mapped(), "first mapping has no remaining view");
        assert!(second.is_mapped(), "individual region export owns its mmap");
        drop(region_export);
        assert!(
            !second.is_mapped(),
            "final view really munmaps original address"
        );
        // The independent alias remains usable, but is a separate VM region.
        alias.as_volatile_slice().read_slice(&mut bytes, 3).unwrap();
        assert_eq!(bytes, [0xa5, 0x7b]);
    }

    #[test]
    fn later_host_map_failure_reclaims_earlier_shared_mapping() {
        let mut earlier = None;
        let mut descriptor = None;
        let result = MappedMemory::allocate(
            &[
                RamRange {
                    gpa: 0,
                    size: 0x4000,
                },
                RamRange {
                    gpa: 0x10000,
                    size: 0x4000,
                },
            ],
            |index, mapped| {
                if index == 1 {
                    descriptor = Some(Arc::downgrade(mapped[0].file_offset().unwrap().arc()));
                    let witness = MappingProbe::from_region(&mapped[0]);
                    assert!(
                        witness.is_mapped(),
                        "first real shared mapping exists before failure"
                    );
                    earlier = Some(witness);
                    return Err(Error::Hv("injected second host mmap failure".into()));
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        let earlier = earlier.expect("second mapping boundary must be reached");
        assert!(
            !earlier.is_mapped(),
            "constructor unwind must munmap earlier real mappings while the object witness remains"
        );
        drop(earlier);
        assert!(
            descriptor.unwrap().upgrade().is_none(),
            "failed allocation releases its descriptor after the independent witness"
        );
    }

    #[test]
    fn malformed_layout_refuses_before_native_registration() {
        for ranges in [
            vec![],
            vec![RamRange {
                gpa: 1,
                size: 0x4000,
            }],
            vec![RamRange { gpa: 0, size: 1 }],
            vec![RamRange { gpa: 0, size: 0 }],
            vec![RamRange {
                gpa: u64::MAX - 0x3fff,
                size: 0x4000,
            }],
            vec![
                RamRange {
                    gpa: 0,
                    size: 0x8000,
                },
                RamRange {
                    gpa: 0x4000,
                    size: 0x4000,
                },
            ],
        ] {
            assert!(MappedMemory::new(&ranges).is_err(), "{ranges:?}");
        }
    }
}
