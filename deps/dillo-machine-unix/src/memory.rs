// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::sync::Arc;

use dillo_machine::worker::{MAX_RESOURCES, MemoryExport, RamView};
use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::{
    Address, FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap,
};

pub fn export_memory(memory: &GuestMemoryMmap) -> io::Result<MemoryExport> {
    let mut export = MemoryExport {
        views: Vec::new(),
        resources: Vec::new(),
    };
    for region in memory.iter() {
        let offset = region
            .file_offset()
            .ok_or_else(|| io::Error::other("RAM has no shareable backing"))?;
        if export.resources.len() == MAX_RESOURCES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        export.views.push(RamView {
            gpa: region.start_addr().raw_value(),
            len: region.len(),
            offset: offset.start(),
            resource: export.resources.len() as u32,
        });
        export.resources.push(offset.file().try_clone()?.into());
    }
    Ok(export)
}

pub fn map_memory(export: MemoryExport) -> io::Result<GuestMemoryMmap> {
    let files = export
        .resources
        .into_iter()
        .map(|fd| Arc::new(File::from(fd)))
        .collect::<Vec<_>>();
    let mut regions = Vec::with_capacity(export.views.len());
    for view in export.views {
        let file = files
            .get(view.resource as usize)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let len = usize::try_from(view.len).map_err(|_| io::ErrorKind::InvalidInput)?;
        let file_len = file
            .metadata()
            .map_err(|e| io::Error::new(e.kind(), format!("RAM metadata: {e}")))?
            .len();
        if len == 0
            || view
                .offset
                .checked_add(view.len)
                .is_none_or(|end| end > file_len)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let map = MmapRegionBuilder::new(len)
            .with_file_offset(FileOffset::from_arc(Arc::clone(file), view.offset))
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_SHARED)
            .build()
            .map_err(|e| io::Error::other(format!("map shared RAM: {e}")))?;
        regions.push(
            GuestRegionMmap::new(map, GuestAddress(view.gpa)).ok_or(io::ErrorKind::InvalidInput)?,
        );
    }
    GuestMemoryMmap::from_regions(regions).map_err(io::Error::other)
}

/// Anonymous shared storage: unlink the POSIX name before mapping or exporting
/// it. The surviving descriptors and views, not a filesystem pathname, own it.
#[cfg(target_os = "macos")]
pub fn allocate_memory(ranges: &[(GuestAddress, usize)]) -> io::Result<GuestMemoryMmap> {
    use nix::fcntl::OFlag;
    use nix::sys::mman::{shm_open, shm_unlink};
    use nix::sys::stat::Mode;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "/dillo-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let fd = shm_open(
        name.as_str(),
        // POSIX shm_open sets FD_CLOEXEC itself.
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|e| io::Error::other(format!("create shared RAM: {e}")))?;
    shm_unlink(name.as_str()).map_err(|e| io::Error::other(format!("unlink shared RAM: {e}")))?;
    let file = File::from(fd);
    let mut views = Vec::with_capacity(ranges.len());
    let mut offset = 0u64;
    for &(gpa, len) in ranges {
        if len == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        views.push(RamView {
            gpa: gpa.raw_value(),
            len: len as u64,
            offset,
            resource: 0,
        });
        offset = offset
            .checked_add(len as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
    }
    file.set_len(offset)
        .map_err(|e| io::Error::new(e.kind(), format!("size shared RAM: {e}")))?;
    map_memory(MemoryExport {
        views,
        resources: vec![file.into()],
    })
}
