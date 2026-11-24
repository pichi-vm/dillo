// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};

use dillo_ipc::{MemoryExport, RamView};
use vm_memory::{Address, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE, SEC_COMMIT};

pub(crate) fn allocate(
    ranges: &[(GuestAddress, usize)],
) -> io::Result<(GuestMemoryMmap, MemoryExport)> {
    let mut export = MemoryExport {
        views: Vec::new(),
        resources: Vec::new(),
    };
    for &(gpa, len) in ranges {
        if len == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: unnamed, non-inheritable pagefile section with a checked
        // nonzero extent. Only this owner receives the returned handle.
        #[allow(unsafe_code)]
        let section = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE | SEC_COMMIT,
                ((len as u64) >> 32) as u32,
                len as u32,
                std::ptr::null(),
            )
        };
        if section.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileMappingW returned a fresh owning handle.
        #[allow(unsafe_code)]
        let section = unsafe { OwnedHandle::from_raw_handle(section) };
        export.views.push(RamView {
            gpa: gpa.raw_value(),
            len: len as u64,
            offset: 0,
            resource: export.resources.len() as u32,
        });
        export.resources.push(section);
    }
    Ok((map(&export)?, export))
}

pub(crate) fn map(export: &MemoryExport) -> io::Result<GuestMemoryMmap> {
    let mut regions = Vec::with_capacity(export.views.len());
    for view in &export.views {
        let section = export
            .resources
            .get(view.resource as usize)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let len = usize::try_from(view.len).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: the Machine created committed pagefile sections; no path
        // decommits or resizes them. All host accesses use vm-memory's volatile
        // or atomic operations. A child mapping is an external RAM accessor;
        // its lifetime cannot release the parent's view or the native backing.
        #[allow(unsafe_code)]
        let region =
            unsafe { MmapRegion::from_mapping_handle(section.as_handle(), view.offset, len) }
                .map_err(io::Error::other)?;
        regions.push(
            GuestRegionMmap::new(region, GuestAddress(view.gpa))
                .ok_or(io::ErrorKind::InvalidInput)?,
        );
    }
    GuestMemoryMmap::from_regions(regions).map_err(io::Error::other)
}
