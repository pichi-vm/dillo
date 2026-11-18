// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixed private section capabilities and their independently owning RAM views.

use std::os::windows::io::{AsHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

use dillo_machine::RamRange;
use vm_memory::{GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE, SEC_COMMIT};

use crate::hypervisor::Error;

/// Machine's fixed RAM layout, native views and private section capabilities.
#[derive(Debug)]
pub struct Memory {
    guest: GuestMemoryMmap,
    // A mapped view keeps storage alive by itself. Machine additionally retains
    // the original capability; byte-access exports never receive this handle.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "retains private section capabilities")
    )]
    sections: Vec<OwnedHandle>,
}

impl Memory {
    pub(crate) fn guest(&self) -> &GuestMemoryMmap {
        &self.guest
    }

    fn allocate(
        ranges: &[RamRange],
        #[cfg(test)] mut map: impl FnMut(
            BorrowedHandle<'_>,
            usize,
            &[GuestRegionMmap],
        ) -> Result<MmapRegion<()>, std::io::Error>,
    ) -> Result<Self, Error> {
        if ranges.is_empty() {
            return Err(Error::EmptyMemoryRegion);
        }
        let mut regions = Vec::with_capacity(ranges.len());
        let mut sections = Vec::with_capacity(ranges.len());
        for range in ranges {
            if range.size == 0 {
                return Err(Error::EmptyMemoryRegion);
            }
            let size = usize::try_from(range.size)
                .map_err(|_| Error::CreateGuestMemory("RAM view exceeds usize".into()))?;
            // SAFETY: an unnamed, non-inheritable, ordinary cacheable data
            // section. INVALID_HANDLE_VALUE selects pagefile backing. Its
            // fixed size is nonzero; all pages are committed read/write.
            #[allow(unsafe_code)]
            let raw = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_READWRITE | SEC_COMMIT,
                    (range.size >> 32) as u32,
                    range.size as u32,
                    std::ptr::null(),
                )
            };
            if raw.is_null() {
                return Err(Error::AllocateMemory(std::io::Error::last_os_error()));
            }
            // SAFETY: the successful create returned a new owned section handle.
            #[allow(unsafe_code)]
            let section = unsafe { OwnedHandle::from_raw_handle(raw) };
            #[cfg(test)]
            let view = map(section.as_handle(), size, &regions);
            #[cfg(not(test))]
            let view = Self::map(section.as_handle(), size);
            let view = view.map_err(Error::AllocateMemory)?;
            regions.push(
                GuestRegionMmap::new(view, GuestAddress(range.gpa))
                    .ok_or_else(|| Error::CreateGuestMemory("guest RAM extent overflow".into()))?,
            );
            sections.push(section);
        }
        let guest = GuestMemoryMmap::from_regions(regions)
            .map_err(|error| Error::CreateGuestMemory(error.to_string()))?;
        Ok(Self { guest, sections })
    }

    fn map(section: BorrowedHandle<'_>, size: usize) -> std::io::Result<MmapRegion<()>> {
        // SAFETY: only our private PAGE_READWRITE|SEC_COMMIT, cacheable ordinary
        // data sections reach this method. Every successful view remains fully
        // committed/writable; no code resizes, reprotects or independently
        // unmaps it. Host access, including overlapping exported views, uses
        // vm-memory's volatile/atomic interfaces rather than Rust references.
        #[allow(unsafe_code)]
        unsafe {
            MmapRegion::from_mapping_handle(section, 0, size)
        }
    }
}

impl dillo_machine::Memory for Memory {
    type Error = Error;

    fn from_ranges(ranges: &[RamRange]) -> Result<Self, Self::Error> {
        Self::allocate(
            ranges,
            #[cfg(test)]
            |handle, size, _| Self::map(handle, size),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    use dillo_machine::Memory as _;
    use vm_memory::{Bytes, GuestMemory, GuestMemoryRegion, VolatileMemory};
    use windows_sys::Win32::Foundation::{
        DuplicateHandle, GetHandleInformation, HANDLE_FLAG_INHERIT,
    };
    use windows_sys::Win32::System::Memory::FILE_MAP_WRITE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

    use super::*;
    use crate::hypervisor::memory_tests::{AllocationProbe, NativeMemoryTest};

    #[test]
    fn native_sections_share_exact_guest_extents_and_outlive_handles() {
        let _guard = crate::hypervisor::whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            NativeMemoryTest::spawn(
                "memory::tests::native_sections_share_exact_guest_extents_and_outlive_handles",
            )
            .verify();
            return;
        }
        let memory = Memory::from_ranges(&[
            RamRange {
                gpa: 0x1000,
                size: 0x1000,
            },
            RamRange {
                gpa: 0x9000,
                size: 0x2000,
            },
        ])
        .unwrap();
        let layout: Vec<_> = memory
            .guest
            .iter()
            .map(|region| (region.start_addr().0, region.len()))
            .collect();
        assert_eq!(layout, [(0x1000, 0x1000), (0x9000, 0x2000)]);
        for region in memory.guest.iter() {
            assert!(region.file_offset().is_none(), "sections are not files");
            let mut bytes = vec![0xff; region.len() as usize];
            memory
                .guest
                .read_slice(&mut bytes, region.start_addr())
                .unwrap();
            assert!(
                bytes.iter().all(|byte| *byte == 0),
                "fresh sections must be zeroed"
            );
        }
        let mut flags = 0;
        // SAFETY: query a live owned handle and duplicate only data-mapping
        // rights into a newly owned, non-inheritable handle. FILE_MAP_WRITE
        // grants a read/write view, not section extension or owner rights.
        #[allow(unsafe_code)]
        let data = unsafe {
            assert_ne!(
                GetHandleInformation(memory.sections[1].as_raw_handle(), &raw mut flags),
                0
            );
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            let process = GetCurrentProcess();
            let mut raw = std::ptr::null_mut();
            assert_ne!(
                DuplicateHandle(
                    process,
                    memory.sections[1].as_raw_handle(),
                    process,
                    &raw mut raw,
                    FILE_MAP_WRITE,
                    0,
                    0
                ),
                0
            );
            OwnedHandle::from_raw_handle(raw)
        };
        let alias = GuestRegionMmap::new(
            Memory::map(data.as_handle(), 0x2000).unwrap(),
            GuestAddress(0x9000),
        )
        .unwrap();
        assert_ne!(alias.as_ptr(), memory.guest.iter().nth(1).unwrap().as_ptr());
        let alias_probe = AllocationProbe::from_region(&alias);
        let alias = GuestMemoryMmap::from_regions(vec![alias]).unwrap();
        let original = AllocationProbe::new(&memory.guest, 1);
        memory
            .guest
            .write_slice(&[0xa5, 0x5a], GuestAddress(0x9100))
            .unwrap();
        let mut bytes = [0; 2];
        alias.read_slice(&mut bytes, GuestAddress(0x9100)).unwrap();
        assert_eq!(bytes, [0xa5, 0x5a]);
        alias.write_slice(&[0x63], GuestAddress(0x9101)).unwrap();
        memory
            .guest
            .read_slice(&mut bytes, GuestAddress(0x9100))
            .unwrap();
        assert_eq!(bytes, [0xa5, 0x63]);
        drop(data);
        let export = memory.guest.clone();
        drop(memory); // closes all original section handles
        original.assert_retained();
        alias_probe.assert_retained();
        alias.write_slice(&[0x77], GuestAddress(0x9100)).unwrap();
        export.read_slice(&mut bytes, GuestAddress(0x9100)).unwrap();
        assert_eq!(bytes, [0x77, 0x63]);
        drop(export);
        original.assert_reclaimed();
        alias_probe.assert_retained();
        alias.read_slice(&mut bytes, GuestAddress(0x9100)).unwrap();
        assert_eq!(bytes, [0x77, 0x63]);
        drop(alias);
        alias_probe.assert_reclaimed();
    }

    #[test]
    fn native_guest_accesses_an_independently_mapped_section() {
        let _guard = crate::hypervisor::whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            NativeMemoryTest::spawn(
                "memory::tests::native_guest_accesses_an_independently_mapped_section",
            )
            .verify();
            return;
        }
        let memory = Memory::from_ranges(&[
            RamRange {
                gpa: 0x10000,
                size: 0x1000,
            },
            RamRange {
                gpa: 0x11000,
                size: 0x1000,
            },
        ])
        .unwrap();
        let alias = GuestRegionMmap::new(
            Memory::map(memory.sections[1].as_handle(), 0x1000).unwrap(),
            GuestAddress(0x11000),
        )
        .unwrap();
        let alias_probe = AllocationProbe::from_region(&alias);
        alias
            .get_mmap()
            .as_volatile_slice()
            .write_slice(&[0x6d, 0, 0xee], 0)
            .unwrap();
        let original = AllocationProbe::new(&memory.guest, 1);
        let mut vm = crate::hypervisor::Vm::new().expect("native WHP is required");
        vm.set_memory(memory).unwrap();
        // DS=0x1000; read GPA0x11000, write GPA0x11001; halt.
        vm.write_guest(
            0x10000,
            &[
                0xb8, 0x00, 0x10, 0x8e, 0xd8, 0xa0, 0x00, 0x10, 0xa2, 0x01, 0x10, 0xf4,
            ],
        )
        .unwrap();
        let mut cpu = vm.create_vcpu(0, "x86-64-v1").unwrap();
        cpu.initialize_test_real_mode(0x10000, 0).unwrap();
        let exit = cpu
            .run(
                |_, _| 0,
                |_, _| Ok(None),
                |_, _| Ok(None),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(exit, crate::VmExit::Halted), "{exit:?}");
        let mut bytes = [0; 3];
        alias
            .get_mmap()
            .as_volatile_slice()
            .read_slice(&mut bytes, 0)
            .unwrap();
        assert_eq!(bytes, [0x6d, 0x6d, 0xee]);
        drop(vm);
        original.assert_retained();
        drop(cpu); // native partition retires before its view and handle owners
        original.assert_reclaimed();
        alias_probe.assert_retained();
        alias
            .get_mmap()
            .as_volatile_slice()
            .write_slice(&[0x42], 1)
            .unwrap();
        alias
            .get_mmap()
            .as_volatile_slice()
            .read_slice(&mut bytes, 0)
            .unwrap();
        assert_eq!(bytes, [0x6d, 0x42, 0xee]);
        drop(alias);
        alias_probe.assert_reclaimed();
    }

    #[test]
    fn native_later_view_failure_releases_earlier_sections() {
        let _guard = crate::hypervisor::whp_test_lock();
        if std::env::var_os("DILLO_WHP_MEMORY_CHILD").is_none() {
            NativeMemoryTest::spawn(
                "memory::tests::native_later_view_failure_releases_earlier_sections",
            )
            .verify();
            return;
        }
        let mut handles_before = 0;
        // SAFETY: query our process into a writable count. This isolated child
        // has no other allocating tests or native VM activity during the check.
        #[allow(unsafe_code)]
        unsafe {
            assert_ne!(
                GetProcessHandleCount(GetCurrentProcess(), &raw mut handles_before),
                0
            );
        }
        let mut earlier = None;
        let failed = Memory::allocate(
            &[
                RamRange {
                    gpa: 0x1000,
                    size: 0x1000,
                },
                RamRange {
                    gpa: 0x9000,
                    size: 0x1000,
                },
            ],
            |section, size, mapped| {
                if mapped.len() == 1 {
                    earlier = Some(AllocationProbe::from_region(&mapped[0]));
                    // Actual MapViewOfFile bounds error on a real second section.
                    // The constructor must unwind both section handles and the
                    // successful first native view, not just reject its layout.
                    return Memory::map(section, size + 0x1000);
                }
                Memory::map(section, size)
            },
        );
        assert!(
            matches!(failed, Err(Error::AllocateMemory(_))),
            "{failed:?}"
        );
        earlier
            .expect("the first section must actually be mapped")
            .assert_reclaimed();
        let mut handles_after = 0;
        // SAFETY: same process/output contract; a failed query is a failure,
        // never evidence that the section handles were closed.
        #[allow(unsafe_code)]
        unsafe {
            assert_ne!(
                GetProcessHandleCount(GetCurrentProcess(), &raw mut handles_after),
                0
            );
        }
        assert_eq!(
            handles_after, handles_before,
            "both section handles must close on error"
        );
        let fresh = Memory::from_ranges(&[RamRange {
            gpa: 0x1000,
            size: 0x1000,
        }])
        .unwrap();
        let probe = AllocationProbe::new(&fresh.guest, 0);
        drop(fresh);
        probe.assert_reclaimed();
    }

    #[test]
    fn invalid_guest_extents_are_rejected() {
        for ranges in [
            vec![],
            vec![RamRange { gpa: 0, size: 0 }],
            vec![RamRange {
                gpa: u64::MAX,
                size: 1,
            }],
            vec![
                RamRange {
                    gpa: 0x2000,
                    size: 0x2000,
                },
                RamRange {
                    gpa: 0x1000,
                    size: 0x1000,
                },
            ],
            vec![
                RamRange {
                    gpa: 0x1000,
                    size: 0x2000,
                },
                RamRange {
                    gpa: 0x2000,
                    size: 0x1000,
                },
            ],
        ] {
            assert!(Memory::from_ranges(&ranges).is_err(), "{ranges:?}");
        }
    }
}
