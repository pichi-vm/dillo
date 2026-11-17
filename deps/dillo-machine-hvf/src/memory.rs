// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Owning, file-backed shared RAM for one native HVF machine.

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
                .ok_or_else(|| Error::Hv("RAM file size overflow".into()))?;
            previous_end = end;
        }
        i64::try_from(total).map_err(|_| Error::Hv("RAM file exceeds off_t".into()))?;
        let file =
            Arc::new(tempfile::tempfile().map_err(|e| Error::Hv(format!("RAM tempfile: {e}")))?);
        file.set_len(total)
            .map_err(|e| Error::Hv(format!("RAM file size: {e}")))?;
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

/// Native identity witness: keeps the vnode alive without retaining its mapping.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct MappingProbe {
    file: std::fs::File,
    address: u64,
    size: u64,
    offset: u64,
}

#[cfg(test)]
impl MappingProbe {
    pub(crate) fn new(memory: &MappedMemory, index: usize) -> Self {
        use vm_memory::GuestMemory as _;
        Self::from_region(memory.guest.iter().nth(index).unwrap())
    }

    fn from_region(region: &GuestRegionMmap) -> Self {
        use vm_memory::GuestMemoryRegion as _;
        let file = region.file_offset().unwrap();
        Self {
            file: file.file().try_clone().unwrap(),
            address: region.as_ptr() as u64,
            size: region.size() as u64,
            offset: file.start(),
        }
    }

    pub(crate) fn alias(&self) -> vm_memory::mmap::MmapRegion {
        MmapRegionBuilder::new(self.size as usize)
            .with_file_offset(FileOffset::new(self.file.try_clone().unwrap(), self.offset))
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_SHARED)
            .build()
            .unwrap()
    }

    pub(crate) fn is_mapped(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        // Bindings follow XNU bsd/sys/proc_info.h, proc_regioninfo,
        // vinfo_stat, vnode_info and proc_regionwithpathinfo. Sizes and the
        // returned byte count are asserted on the native SDK/OS lane.
        // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
        #[repr(C)]
        struct RegionInfo {
            protection: [u32; 4],
            offset: u64,
            details: [u32; 14],
            address: u64,
            size: u64,
        }
        #[repr(C)]
        struct VnodeStat {
            device: u32,
            mode: u16,
            links: u16,
            inode: u64,
            uid: u32,
            gid: u32,
            times_size_blocks: [i64; 10],
            blocksize_flags_gen_rdev: [u32; 4],
            spare: [i64; 2],
        }
        #[repr(C)]
        struct RegionPath {
            region: RegionInfo,
            stat: VnodeStat,
            vnode_type_pad_fsid: [u32; 4],
            path: [u8; 1024],
        }
        assert_eq!(std::mem::size_of::<RegionInfo>(), 96);
        assert_eq!(std::mem::size_of::<VnodeStat>(), 136);
        assert_eq!(std::mem::size_of::<RegionPath>(), 1272);
        // SAFETY: every field accepts zero, buffer is writable and exactly the
        // PROC_PIDREGIONPATHINFO layout. No guest/stale host pointer is read.
        #[allow(unsafe_code)]
        let mut result: RegionPath = unsafe { std::mem::zeroed() };
        #[allow(unsafe_code)]
        let count = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                8, /* PROC_PIDREGIONPATHINFO */
                self.address,
                (&raw mut result).cast(),
                i32::try_from(std::mem::size_of::<RegionPath>()).unwrap(),
            )
        };
        // A failed/unsupported query is never interpreted as reclamation.
        assert_eq!(
            count as usize,
            std::mem::size_of::<RegionPath>(),
            "native vnode mapping query failed: {}",
            std::io::Error::last_os_error()
        );
        let metadata = self.file.metadata().unwrap();
        let same_file =
            result.stat.device == metadata.dev() as u32 && result.stat.inode == metadata.ino();
        if !same_file || result.region.address > self.address {
            return false;
        }
        assert!(self.address - result.region.address < result.region.size);
        assert!(self.size <= result.region.size - (self.address - result.region.address));
        assert_eq!(
            result.region.offset + self.address - result.region.address,
            self.offset
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{GuestMemory as _, VolatileMemory as _};

    #[test]
    fn shared_file_views_keep_offsets_and_reclaim_real_mappings() {
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
    fn later_host_map_failure_reclaims_earlier_file_mapping() {
        let mut earlier = None;
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
                    let witness = MappingProbe::from_region(&mapped[0]);
                    assert!(
                        witness.is_mapped(),
                        "first real file mapping exists before failure"
                    );
                    earlier = Some(witness);
                    return Err(Error::Hv("injected second host mmap failure".into()));
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(
            !earlier
                .expect("second mapping boundary must be reached")
                .is_mapped(),
            "constructor unwind must munmap earlier real mappings while the vnode witness remains"
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
