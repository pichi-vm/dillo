// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Filesystem backing behind a virtio-fs device.
//!
//! The FUSE protocol logic in [`crate::fuse`] is backend-agnostic: it manages
//! the nodeid/handle tables and the wire format, and delegates filesystem
//! operations to a [`FsBackend`]. [`Passthrough`] serves a host directory.
//! [`MapFs`] is an in-memory tree used by the unit tests so the protocol can
//! be exercised on any platform without touching the real filesystem.
//!
//! Read methods are required. Mutating methods default to `EROFS`, so a
//! read-only backing fails closed. A device configured read-only also rejects
//! mutating FUSE opcodes before any of those methods are called. Host
//! operations the OS cannot perform return an explicit errno (`EOPNOTSUPP` /
//! the host's error); they are not reported as success.

use std::io;
use std::path::{Component, Path, PathBuf};

/// `S_IFMT` mask and the type bits we care about (mirrors `libc`/`stat.h`).
pub(crate) const S_IFMT: u32 = 0o170_000;
pub(crate) const S_IFIFO: u32 = 0o010_000;
pub(crate) const S_IFCHR: u32 = 0o020_000;
pub(crate) const S_IFDIR: u32 = 0o040_000;
pub(crate) const S_IFBLK: u32 = 0o060_000;
pub(crate) const S_IFREG: u32 = 0o100_000;
pub(crate) const S_IFLNK: u32 = 0o120_000;
pub(crate) const S_IFSOCK: u32 = 0o140_000;

/// `getdents`/`fuse_dirent` `d_type` values.
pub(crate) const DT_UNKNOWN: u32 = 0;
pub(crate) const DT_FIFO: u32 = 1;
pub(crate) const DT_CHR: u32 = 2;
pub(crate) const DT_DIR: u32 = 4;
pub(crate) const DT_BLK: u32 = 6;
pub(crate) const DT_REG: u32 = 8;
pub(crate) const DT_LNK: u32 = 10;
pub(crate) const DT_SOCK: u32 = 12;

/// Linux `ENXIO`. The wire value when a non-Linux host's raw errno differs.
#[cfg(not(target_os = "linux"))]
pub(crate) const LINUX_ENXIO: i32 = 6;
/// Linux `ERANGE`. Used by the Unix xattr grow path. Windows xattr is
/// `EOPNOTSUPP` and never reports this number.
#[cfg(unix)]
pub(crate) const LINUX_ERANGE: i32 = 34;
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) const LINUX_ENODATA: i32 = 61;

/// Stat-like attributes for one filesystem node, in the subset virtio-fs needs.
#[derive(Debug, Clone, Copy)]
pub struct Attr {
    /// Backend inode number. FUSE retains its initial value for each cached node.
    pub ino: u64,
    /// Size in bytes.
    pub size: u64,
    /// 512-byte block count.
    pub blocks: u64,
    /// Full mode including the `S_IF*` type bits.
    pub mode: u32,
    /// Hard link count.
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Device id for special files (0 otherwise).
    pub rdev: u32,
    /// Modification time (seconds + nanoseconds).
    pub mtime: u64,
    pub mtime_nsec: u32,
}

impl Attr {
    /// `d_type` for readdir, derived from the mode's type bits.
    pub fn dirent_type(&self) -> u32 {
        match self.mode & S_IFMT {
            S_IFIFO => DT_FIFO,
            S_IFCHR => DT_CHR,
            S_IFDIR => DT_DIR,
            S_IFBLK => DT_BLK,
            S_IFREG => DT_REG,
            S_IFLNK => DT_LNK,
            S_IFSOCK => DT_SOCK,
            _ => DT_UNKNOWN,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// One directory entry surfaced by [`FsBackend::readdir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// The component name (no path separators).
    pub name: String,
    pub attr: Attr,
}

/// Attributes to change in [`FsBackend::setattr`]. Each `Some` field is applied;
/// `None` is left untouched. Ownership is not exposed here; FUSE rejects
/// ownership changes explicitly. Time updates are best-effort cross-platform.
#[derive(Debug, Clone, Default)]
pub struct SetAttr {
    /// Truncate/extend the regular file to this size.
    pub size: Option<u64>,
    /// New mode bits (honored on Unix; maps to the read-only bit elsewhere).
    pub mode: Option<u32>,
    /// New modification time (seconds, nanoseconds since the Unix epoch).
    pub mtime: Option<(u64, u32)>,
    /// New access time (seconds, nanoseconds since the Unix epoch).
    pub atime: Option<(u64, u32)>,
}

/// `errno` for a read-only filesystem, returned by the write-path default
/// methods so a read-only backing fails closed if the device ever reaches it
/// (the device also rejects writes up front when configured read-only).
fn read_only_error() -> io::Error {
    io::Error::from(io::ErrorKind::ReadOnlyFilesystem)
}

fn unsupported_error() -> io::Error {
    io::Error::from(io::ErrorKind::Unsupported)
}

/// A Linux errno carried explicitly so non-Linux hosts do not put their native
/// numbers on the FUSE wire. The FUSE dispatcher checks this before `ErrorKind`.
#[derive(Debug)]
pub(crate) struct LinuxErrno {
    pub linux: i32,
}

impl std::fmt::Display for LinuxErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "linux errno {}", self.linux)
    }
}

impl std::error::Error for LinuxErrno {}

pub(crate) fn linux_errno(linux: i32, kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, LinuxErrno { linux })
}

/// Filesystem backing for a virtio-fs share. Paths are relative to the share
/// root; the empty path is the root itself.
///
/// The read methods are required; the write methods default to `EROFS` so a
/// read-only backing needs to implement nothing. A device configured read-only
/// rejects mutating FUSE opcodes before any of these are called.
pub trait FsBackend: Send + Sync {
    /// `lstat` the node at `rel` (does not follow a trailing symlink).
    fn stat(&self, rel: &Path) -> io::Result<Attr>;

    /// List the directory at `rel`. `.`/`..` are synthesized by the caller.
    fn readdir(&self, rel: &Path) -> io::Result<Vec<DirEntry>>;

    /// Read up to `size` bytes at `offset` from the regular file at `rel`.
    fn read(&self, rel: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>>;

    /// Read the target of the symlink at `rel`.
    fn readlink(&self, rel: &Path) -> io::Result<Vec<u8>>;

    // --- write path (default: read-only) -----------------------------------

    /// Write `data` at `offset` to the regular file at `rel`; returns the number
    /// of bytes written.
    fn write(&self, rel: &Path, offset: u64, data: &[u8]) -> io::Result<u32> {
        let _ = (rel, offset, data);
        Err(read_only_error())
    }

    /// Create (or open) a regular file at `rel` with `mode`, returning its attr.
    fn create(&self, rel: &Path, mode: u32) -> io::Result<Attr> {
        let _ = (rel, mode);
        Err(read_only_error())
    }

    /// Create a directory at `rel` with `mode`, returning its attr.
    fn mkdir(&self, rel: &Path, mode: u32) -> io::Result<Attr> {
        let _ = (rel, mode);
        Err(read_only_error())
    }

    /// Remove the regular file (or symlink) at `rel`.
    fn unlink(&self, rel: &Path) -> io::Result<()> {
        let _ = rel;
        Err(read_only_error())
    }

    /// Remove the (empty) directory at `rel`.
    fn rmdir(&self, rel: &Path) -> io::Result<()> {
        let _ = rel;
        Err(read_only_error())
    }

    /// Rename `from` to `to`. `flags` uses Linux `RENAME_*` bits: `1` noreplace,
    /// `2` exchange, `4` whiteout. Whiteout is rejected; noreplace and exchange
    /// are performed when the host OS can do them.
    fn rename(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
        let _ = (from, to, flags);
        Err(read_only_error())
    }

    /// Create a hard link `to` referring to `from`.
    fn link(&self, from: &Path, to: &Path) -> io::Result<Attr> {
        let _ = (from, to);
        Err(read_only_error())
    }

    /// Create a special file. `mode` includes the `S_IF*` type bits.
    fn mknod(&self, rel: &Path, mode: u32, rdev: u32) -> io::Result<Attr> {
        let _ = (rel, mode, rdev);
        Err(read_only_error())
    }

    /// `fallocate`. `mode` uses Linux `FALLOC_FL_*` bits.
    fn fallocate(&self, rel: &Path, offset: u64, length: u64, mode: u32) -> io::Result<()> {
        let _ = (rel, offset, length, mode);
        Err(read_only_error())
    }

    /// Read one `user.*` extended attribute. Missing attributes are `ENODATA`.
    fn get_xattr(&self, rel: &Path, name: &str) -> io::Result<Vec<u8>> {
        let _ = (rel, name);
        Err(unsupported_error())
    }

    /// Set one `user.*` extended attribute. `flags` uses Linux `XATTR_CREATE` (1) and
    /// `XATTR_REPLACE` (2).
    fn set_xattr(&self, rel: &Path, name: &str, value: &[u8], flags: u32) -> io::Result<()> {
        let _ = (rel, name, value, flags);
        Err(read_only_error())
    }

    /// List `user.*` extended attribute names as NUL-terminated strings.
    fn list_xattr(&self, rel: &Path) -> io::Result<Vec<u8>> {
        let _ = rel;
        Err(unsupported_error())
    }

    /// Remove one `user.*` extended attribute. A missing attribute is `ENODATA`.
    fn remove_xattr(&self, rel: &Path, name: &str) -> io::Result<()> {
        let _ = (rel, name);
        Err(read_only_error())
    }

    /// `SEEK_DATA` (3) / `SEEK_HOLE` (4). Other `whence` values are `EINVAL`.
    fn lseek(&self, rel: &Path, offset: u64, whence: u32) -> io::Result<u64> {
        let _ = (rel, offset, whence);
        Err(unsupported_error())
    }

    /// Copy up to `len` bytes. `flags` must be zero. A short copy is a real
    /// byte count, not an error, so the guest can resume.
    fn copy_file_range(
        &self,
        src: &Path,
        src_off: u64,
        dst: &Path,
        dst_off: u64,
        len: u64,
        flags: u32,
    ) -> io::Result<u32> {
        let _ = (src, src_off, dst, dst_off, len, flags);
        Err(read_only_error())
    }

    /// Apply [`SetAttr`] to `rel`, returning the resulting attr.
    fn setattr(&self, rel: &Path, set: &SetAttr) -> io::Result<Attr> {
        let _ = (rel, set);
        Err(read_only_error())
    }

    /// Create a symlink at `rel` pointing at `target`, returning its attr.
    fn symlink(&self, rel: &Path, target: &[u8]) -> io::Result<Attr> {
        let _ = (rel, target);
        Err(read_only_error())
    }
}

/// Reject a relative path that tries to escape the share root: no absolute
/// components, no `..`, no root/prefix components. Plain `.` is dropped.
/// Returns the cleaned relative path on success.
pub(crate) fn sanitize_rel(rel: &Path) -> io::Result<PathBuf> {
    let mut clean = PathBuf::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
        }
    }
    Ok(clean)
}

// ---------------------------------------------------------------------------
// Passthrough — serves a host directory. Cross-platform: the FUSE
// attributes virtio-fs reports to the (always-Linux) guest are read from real
// Unix metadata on Unix hosts. On Windows the file index and link count come
// from `GetFileInformationByHandle`, so hard links share one inode.
// ---------------------------------------------------------------------------

mod passthrough {
    use super::{Attr, DirEntry, FsBackend, SetAttr, sanitize_rel};
    // The synthesized-attr path (non-Unix hosts) needs the type-bit constants;
    // on Unix the real mode is read straight from `MetadataExt`.
    #[cfg(not(unix))]
    use super::{S_IFDIR, S_IFLNK, S_IFREG};
    use std::fs::{self, File, FileTimes, Metadata, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, UNIX_EPOCH};

    /// Passthrough of a host directory subtree.
    #[derive(Debug)]
    pub struct Passthrough {
        root: PathBuf,
    }

    impl Passthrough {
        /// Create a passthrough rooted at `root`. The directory must exist.
        pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
            let root = root.into();
            let meta = fs::metadata(&root)?;
            if !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("virtio-fs source {} is not a directory", root.display()),
                ));
            }
            // Canonicalize so the per-request containment check compares against
            // a stable absolute root.
            let root = fs::canonicalize(&root)?;
            Ok(Self { root })
        }

        /// Resolve `rel` under the root with a symlink-escape guard. `sanitize_rel`
        /// already blocks lexical escapes (`..`, absolute/prefix). We then
        /// canonicalize the **deepest existing ancestor** of the target and
        /// confirm it stays within the root — this catches a symlink in any
        /// existing component for both reads and writes-to-not-yet-existing
        /// targets (e.g. CREATE inside a symlinked-out directory). A genuinely
        /// missing leaf surfaces later as `NotFound` from the stat/open.
        fn resolve(&self, rel: &Path) -> io::Result<PathBuf> {
            let clean = sanitize_rel(rel)?;
            let full = self.root.join(&clean);
            let mut probe = full.as_path();
            loop {
                match fs::canonicalize(probe) {
                    Ok(canon) => {
                        if !canon.starts_with(&self.root) {
                            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                        }
                        break;
                    }
                    // `probe` doesn't exist yet; check its parent instead.
                    Err(_) => match probe.parent() {
                        Some(parent) => probe = parent,
                        None => break,
                    },
                }
            }
            Ok(full)
        }
    }

    /// One positional read. Callers must loop: a short count is not EOF unless
    /// it is zero, and Linux FUSE treats a short `READ` as end-of-file.
    fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(file, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(file, buf, offset)
        }
    }

    /// One positional write. Callers must loop until the buffer is stored.
    fn write_at(file: &File, buf: &[u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::write_at(file, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_write(file, buf, offset)
        }
    }

    /// Fill `buf` from `offset`, retrying short reads. `Ok(n)` with `n < buf.len()`
    /// means real EOF after `n` bytes. A nonzero short read is continued so a
    /// large object is not truncated. Linux FUSE treats a short `READ` as EOF
    /// and shrinks `i_size`, which corrupts loose objects.
    fn read_full(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        read_until_full(|dst, off| read_at(file, dst, off), buf, offset)
    }

    pub(super) fn read_until_full(
        mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
        buf: &mut [u8],
        mut offset: u64,
    ) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match read_at(&mut buf[filled..], offset) {
                Ok(0) => break,
                Ok(n) => {
                    filled += n;
                    offset += u64::try_from(n).unwrap_or(0);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }

    /// Store all of `buf` at `offset`, retrying short writes.
    fn write_full(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match write_at(file, buf, offset) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short write made no progress",
                    ));
                }
                Ok(n) => {
                    buf = &buf[n..];
                    offset += u64::try_from(n).unwrap_or(0);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Build a `FileTimes` from optional (secs, nsec) access/modify stamps.
    fn file_times(atime: Option<(u64, u32)>, mtime: Option<(u64, u32)>) -> FileTimes {
        let mut times = FileTimes::new();
        if let Some((s, n)) = atime {
            times = times.set_accessed(UNIX_EPOCH + Duration::new(s, n));
        }
        if let Some((s, n)) = mtime {
            times = times.set_modified(UNIX_EPOCH + Duration::new(s, n));
        }
        times
    }

    /// Map host metadata to the FUSE [`Attr`] the Linux guest expects.
    fn meta_to_attr(meta: &Metadata, full: &Path) -> Attr {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = full;
            Attr {
                ino: meta.ino(),
                size: meta.size(),
                blocks: meta.blocks(),
                mode: meta.mode(),
                nlink: meta.nlink() as u32,
                uid: meta.uid(),
                gid: meta.gid(),
                rdev: meta.rdev() as u32,
                mtime: meta.mtime() as u64,
                mtime_nsec: meta.mtime_nsec() as u32,
            }
        }
        #[cfg(not(unix))]
        {
            use std::time::UNIX_EPOCH;
            let ft = meta.file_type();
            let (type_bits, perm) = if ft.is_dir() {
                (S_IFDIR, 0o755)
            } else if ft.is_symlink() {
                (S_IFLNK, 0o777)
            } else if meta.permissions().readonly() {
                (S_IFREG, 0o444)
            } else {
                (S_IFREG, 0o644)
            };
            let (mtime, mtime_nsec) = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or((0, 0), |d| (d.as_secs(), d.subsec_nanos()));
            // NTFS file index is shared by hard links. A path hash stands in
            // only when the host does not report one.
            let (ino, nlink) =
                file_id(full).unwrap_or((synth_ino(full), if ft.is_dir() { 2 } else { 1 }));
            Attr {
                ino,
                size: meta.len(),
                blocks: meta.len().div_ceil(512),
                mode: type_bits | perm,
                nlink,
                uid: 0,
                gid: 0,
                rdev: 0,
                mtime,
                mtime_nsec,
            }
        }
    }

    /// Volume, file index, and link count from `BY_HANDLE_FILE_INFORMATION`.
    #[cfg(windows)]
    struct HostId {
        volume: u32,
        index: u64,
        nlink: u32,
    }

    /// `std::os::windows::fs::MetadataExt::{file_index, number_of_links}` need
    /// the unstable `windows_by_handle` feature. This is the same Win32 query
    /// those methods wrap, and it stays available on the pinned nightly.
    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn host_id(path: &Path) -> Option<HostId> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            GetFileInformationByHandle,
        };
        // Access 0 would be enough, but `OpenOptions` has no public way to ask
        // for it. Read access plus backup semantics opens files and directories.
        // `FILE_FLAG_OPEN_REPARSE_POINT` matches `symlink_metadata` (do not follow).
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .ok()?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `file` owns a live handle, and `info` is a valid out-buffer
        // that outlives the call.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        if ok == 0 {
            return None;
        }
        let index = u64::from(info.nFileIndexLow) | (u64::from(info.nFileIndexHigh) << 32);
        (index != 0).then_some(HostId {
            volume: info.dwVolumeSerialNumber,
            index,
            nlink: info.nNumberOfLinks,
        })
    }

    /// File index and link count. The index is shared by every hard link.
    #[cfg(windows)]
    fn file_id(path: &Path) -> Option<(u64, u32)> {
        host_id(path).map(|id| (id.index, id.nlink))
    }

    /// True when both paths name the same file on the same volume.
    #[cfg(windows)]
    fn same_file(a: &Path, b: &Path) -> bool {
        match (host_id(a), host_id(b)) {
            (Some(a), Some(b)) => a.volume == b.volume && a.index == b.index,
            _ => false,
        }
    }

    /// Stable, nonzero cosmetic inode number derived from the full host path.
    #[cfg(not(unix))]
    fn synth_ino(path: &Path) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut hasher);
        hasher.finish() | 1
    }

    impl FsBackend for Passthrough {
        fn stat(&self, rel: &Path) -> io::Result<Attr> {
            let path = self.resolve(rel)?;
            // lstat: do not follow a trailing symlink.
            let meta = fs::symlink_metadata(&path)?;
            Ok(meta_to_attr(&meta, &path))
        }

        fn readdir(&self, rel: &Path) -> io::Result<Vec<DirEntry>> {
            let path = self.resolve(rel)?;
            let mut out = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                let Ok(name) = entry.file_name().into_string() else {
                    // Skip non-UTF-8 names — the guest probe and our wire format
                    // work in UTF-8; such names are rare in a build context.
                    continue;
                };
                let entry_path = entry.path();
                let meta = entry.metadata().or_else(|_| {
                    // Fall back to lstat-style metadata for dangling symlinks.
                    fs::symlink_metadata(&entry_path)
                })?;
                out.push(DirEntry {
                    name,
                    attr: meta_to_attr(&meta, &entry_path),
                });
            }
            Ok(out)
        }

        fn read(&self, rel: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
            let path = self.resolve(rel)?;
            let file = File::open(&path)?;
            let mut buf = vec![0u8; size as usize];
            let n = read_full(&file, &mut buf, offset)?;
            buf.truncate(n);
            Ok(buf)
        }

        fn readlink(&self, rel: &Path) -> io::Result<Vec<u8>> {
            let path = self.resolve(rel)?;
            let target = fs::read_link(&path)?;
            Ok(target.into_os_string().into_encoded_bytes())
        }

        fn write(&self, rel: &Path, offset: u64, data: &[u8]) -> io::Result<u32> {
            let path = self.resolve(rel)?;
            let file = OpenOptions::new().write(true).open(&path)?;
            write_full(&file, data, offset)?;
            Ok(data.len() as u32)
        }

        fn create(&self, rel: &Path, mode: u32) -> io::Result<Attr> {
            let path = self.resolve(rel)?;
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(mode & 0o777);
            }
            let _file = opts.open(&path)?;
            // On non-Unix the mode can't be honored beyond the read-only bit,
            // which `create` never sets; the file is created writable.
            #[cfg(not(unix))]
            let _ = mode;
            let meta = fs::symlink_metadata(&path)?;
            Ok(meta_to_attr(&meta, &path))
        }

        fn mkdir(&self, rel: &Path, mode: u32) -> io::Result<Attr> {
            let path = self.resolve(rel)?;
            fs::create_dir(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(mode & 0o777))?;
            }
            #[cfg(not(unix))]
            let _ = mode;
            let meta = fs::symlink_metadata(&path)?;
            Ok(meta_to_attr(&meta, &path))
        }

        fn unlink(&self, rel: &Path) -> io::Result<()> {
            let path = self.resolve(rel)?;
            fs::remove_file(&path)
        }

        fn rmdir(&self, rel: &Path) -> io::Result<()> {
            let path = self.resolve(rel)?;
            fs::remove_dir(&path)
        }

        fn rename(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
            let from = self.resolve(from)?;
            let to = self.resolve(to)?;
            rename_with(&from, &to, flags)
        }

        fn link(&self, from: &Path, to: &Path) -> io::Result<Attr> {
            let from = self.resolve(from)?;
            let to = self.resolve(to)?;
            fs::hard_link(&from, &to)?;
            let meta = fs::symlink_metadata(&to)?;
            Ok(meta_to_attr(&meta, &to))
        }

        fn mknod(&self, rel: &Path, mode: u32, rdev: u32) -> io::Result<Attr> {
            let path = self.resolve(rel)?;
            make_node(&path, mode, rdev)?;
            let meta = fs::symlink_metadata(&path)?;
            Ok(meta_to_attr(&meta, &path))
        }

        fn fallocate(&self, rel: &Path, offset: u64, length: u64, mode: u32) -> io::Result<()> {
            let path = self.resolve(rel)?;
            let file = OpenOptions::new().read(true).write(true).open(&path)?;
            allocate(&file, offset, length, mode)
        }

        fn get_xattr(&self, rel: &Path, name: &str) -> io::Result<Vec<u8>> {
            check_xattr_name(name)?;
            let path = self.resolve(rel)?;
            read_xattr(&path, name)
        }

        fn set_xattr(&self, rel: &Path, name: &str, value: &[u8], flags: u32) -> io::Result<()> {
            check_xattr_name(name)?;
            let path = self.resolve(rel)?;
            write_xattr(&path, name, value, flags)
        }

        fn list_xattr(&self, rel: &Path) -> io::Result<Vec<u8>> {
            let path = self.resolve(rel)?;
            list_xattrs(&path)
        }

        fn remove_xattr(&self, rel: &Path, name: &str) -> io::Result<()> {
            check_xattr_name(name)?;
            let path = self.resolve(rel)?;
            delete_xattr(&path, name)
        }

        fn lseek(&self, rel: &Path, offset: u64, whence: u32) -> io::Result<u64> {
            let path = self.resolve(rel)?;
            let file = File::open(&path)?;
            seek_data_hole(&file, offset, whence)
        }

        fn copy_file_range(
            &self,
            src: &Path,
            src_off: u64,
            dst: &Path,
            dst_off: u64,
            len: u64,
            flags: u32,
        ) -> io::Result<u32> {
            if flags != 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let src = self.resolve(src)?;
            let dst = self.resolve(dst)?;
            let src_file = File::open(&src)?;
            let dst_file = OpenOptions::new().write(true).open(&dst)?;
            copy_range(&src_file, src_off, &dst_file, dst_off, len)
        }

        fn setattr(&self, rel: &Path, set: &SetAttr) -> io::Result<Attr> {
            let path = self.resolve(rel)?;

            if let Some(size) = set.size {
                OpenOptions::new().write(true).open(&path)?.set_len(size)?;
            }

            if let Some(mode) = set.mode {
                set_mode(&path, mode)?;
            }

            if set.atime.is_some() || set.mtime.is_some() {
                // Times need an open handle; on a directory this may fail on some
                // platforms — best-effort, don't fail the whole setattr.
                if let Ok(file) = OpenOptions::new().write(true).open(&path) {
                    let _ = file.set_times(file_times(set.atime, set.mtime));
                } else if let Ok(file) = File::open(&path) {
                    let _ = file.set_times(file_times(set.atime, set.mtime));
                }
            }

            let meta = fs::symlink_metadata(&path)?;
            Ok(meta_to_attr(&meta, &path))
        }

        fn symlink(&self, rel: &Path, target: &[u8]) -> io::Result<Attr> {
            let path = self.resolve(rel)?;
            symlink_at(&path, target)?;
            let meta = fs::symlink_metadata(&path)?;
            Ok(meta_to_attr(&meta, &path))
        }
    }

    /// Apply mode bits where the platform supports it.
    fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
        }
        #[cfg(not(unix))]
        {
            // Map the owner-write bit to the read-only attribute.
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_readonly(mode & 0o200 == 0);
            fs::set_permissions(path, perms)
        }
    }

    /// Create a symlink. Supported on Unix; elsewhere reported unsupported.
    fn symlink_at(path: &Path, target: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            std::os::unix::fs::symlink(OsStr::from_bytes(target), path)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, target);
            // No portable symlink creation off Unix.
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// Linux `renameat2` / FUSE `RENAME_*` bits. Host flag values differ
    /// (macOS `RENAME_EXCL` is not bit 1), so map these explicitly.
    const RENAME_NOREPLACE: u32 = 1;
    const RENAME_EXCHANGE: u32 = 2;
    const RENAME_WHITEOUT: u32 = 4;
    const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
    const SEEK_DATA: u32 = 3;
    const SEEK_HOLE: u32 = 4;
    /// Cap one extended attribute. A larger value is `ERANGE`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const XATTR_MAX: usize = 1 << 20;

    fn rename_with(from: &Path, to: &Path, flags: u32) -> io::Result<()> {
        let known = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
        if flags & !known != 0 || (flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if flags & RENAME_WHITEOUT != 0 {
            // Whiteout is an overlayfs device node, not a directory share.
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        if flags & RENAME_EXCHANGE != 0
            && (from.starts_with(to) || to.starts_with(from))
            && from != to
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if flags == 0 {
            // Two names of one file stay in place. Win32 MoveFile would drop
            // the source name when the destination is another hard link.
            #[cfg(windows)]
            if same_file(from, to) {
                return Ok(());
            }
            return fs::rename(from, to);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mut host = rustix::fs::RenameFlags::empty();
            if flags & RENAME_NOREPLACE != 0 {
                host |= rustix::fs::RenameFlags::NOREPLACE;
            }
            if flags & RENAME_EXCHANGE != 0 {
                host |= rustix::fs::RenameFlags::EXCHANGE;
            }
            rustix::fs::renameat_with(rustix::fs::CWD, from, rustix::fs::CWD, to, host)
                .map_err(from_rustix)
        }
        #[cfg(windows)]
        {
            if flags & RENAME_EXCHANGE != 0 {
                return Err(io::Error::from(io::ErrorKind::Unsupported));
            }
            move_file(from, to, false)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (from, to);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn move_file(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MoveFileExW};
        let from_w: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to_w: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        let move_flags = if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
        // SAFETY: both paths are NUL-terminated UTF-16 and live for the call.
        let ok = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), move_flags) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn make_node(path: &Path, mode: u32, rdev: u32) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let kind = rustix::fs::FileType::from_raw_mode(mode);
            let perm = rustix::fs::Mode::from_raw_mode(mode);
            if !matches!(
                kind,
                rustix::fs::FileType::Fifo
                    | rustix::fs::FileType::Socket
                    | rustix::fs::FileType::CharacterDevice
                    | rustix::fs::FileType::BlockDevice
            ) {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            rustix::fs::mknodat(rustix::fs::CWD, path, kind, perm, u64::from(rdev))
                .map_err(from_rustix)
        }
        #[cfg(target_os = "macos")]
        {
            make_node_macos(path, mode, rdev)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (path, mode, rdev);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn make_node_macos(path: &Path, mode: u32, rdev: u32) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        let c_path = std::ffi::CString::new(bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `c_path` is a NUL-terminated path that outlives the call.
        let rc = unsafe { libc::mknod(c_path.as_ptr(), mode as libc::mode_t, rdev as libc::dev_t) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn allocate(file: &File, offset: u64, length: u64, mode: u32) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            const KNOWN: u32 =
                FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | 0x04 | 0x08 | 0x10 | 0x20 | 0x40;
            if mode & !KNOWN != 0 {
                return Err(io::Error::from(io::ErrorKind::Unsupported));
            }
            let flags = rustix::fs::FallocateFlags::from_bits_truncate(mode);
            rustix::fs::fallocate(file, flags, offset, length).map_err(from_rustix)
        }
        #[cfg(target_os = "macos")]
        {
            allocate_macos(file, offset, length, mode)
        }
        #[cfg(windows)]
        {
            allocate_windows(file, offset, length, mode)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (file, offset, length, mode);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn allocate_macos(file: &File, offset: u64, length: u64, mode: u32) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        if mode == FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE {
            let hole = libc::fpunchhole_t {
                fp_flags: 0,
                reserved: 0,
                fp_offset: offset as libc::off_t,
                fp_length: length as libc::off_t,
            };
            // SAFETY: `hole` is a valid `fpunchhole_t` for this fd.
            let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &hole) };
            return if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            };
        }
        if mode == 0 {
            return rustix::fs::fallocate(
                file,
                rustix::fs::FallocateFlags::empty(),
                offset,
                length,
            )
            .map_err(from_rustix);
        }
        if mode != FALLOC_FL_KEEP_SIZE {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        // `F_PREALLOCATE` rejects `SEEK_SET` with EINVAL. `F_PEOFPOSMODE`
        // reserves from the physical end of the file. Skip `ftruncate` so the
        // logical size stays put; rustix's Apple `fallocate` extends the file.
        let end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let current = file.metadata()?.len();
        if end <= current {
            return Ok(());
        }
        let alloc_len =
            libc::off_t::try_from(end).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut store = libc::fstore_t {
            fst_flags: libc::F_ALLOCATECONTIG,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: alloc_len,
            fst_bytesalloc: 0,
        };
        let fd = file.as_raw_fd();
        // SAFETY: `store` is a valid `fstore_t` for this fd.
        let rc = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &store) };
        if rc != 0 {
            store.fst_flags = libc::F_ALLOCATEALL;
            let rc = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &store) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn allocate_windows(file: &File, offset: u64, length: u64, mode: u32) -> io::Result<()> {
        // `FileAllocationInfo` grows the logical size, so KEEP_SIZE past EOF
        // and punch-hole have no honest Win32 equivalent.
        if mode == FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE
            || (mode != 0 && mode != FALLOC_FL_KEEP_SIZE)
        {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        let end = offset.saturating_add(length);
        let len = file.metadata()?.len();
        if mode == FALLOC_FL_KEEP_SIZE {
            return if end > len {
                Err(io::Error::from(io::ErrorKind::Unsupported))
            } else {
                Ok(())
            };
        }
        if end > len {
            file.set_len(end)?;
        }
        Ok(())
    }

    fn is_allowed_xattr_name(name: &[u8]) -> bool {
        name.strip_prefix(b"user.")
            .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains(&0))
    }

    fn check_xattr_name(name: &str) -> io::Result<()> {
        if is_allowed_xattr_name(name.as_bytes()) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn filter_xattr_names(names: &[u8]) -> Vec<u8> {
        names
            .split(|&byte| byte == 0)
            .filter(|name| is_allowed_xattr_name(name))
            .flat_map(|name| name.iter().copied().chain(Some(0)))
            .collect()
    }

    fn read_xattr(path: &Path, name: &str) -> io::Result<Vec<u8>> {
        check_xattr_name(name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            grow_xattr(|buf| rustix::fs::lgetxattr(path, name, rustix::buffer::spare_capacity(buf)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (path, name);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn write_xattr(path: &Path, name: &str, value: &[u8], flags: u32) -> io::Result<()> {
        check_xattr_name(name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let host = match flags {
                0 => rustix::fs::XattrFlags::empty(),
                1 => rustix::fs::XattrFlags::CREATE,
                2 => rustix::fs::XattrFlags::REPLACE,
                _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
            };
            rustix::fs::lsetxattr(path, name, value, host).map_err(from_rustix)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (path, name, value, flags);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn list_xattrs(path: &Path) -> io::Result<Vec<u8>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let names = grow_xattr(|buf| {
                rustix::fs::llistxattr(path, rustix::buffer::spare_capacity(buf))
            })?;
            Ok(filter_xattr_names(&names))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = path;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn delete_xattr(path: &Path, name: &str) -> io::Result<()> {
        check_xattr_name(name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            rustix::fs::lremovexattr(path, name).map_err(from_rustix)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (path, name);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn grow_xattr(
        mut call: impl FnMut(&mut Vec<u8>) -> Result<usize, rustix::io::Errno>,
    ) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        loop {
            if buf.capacity() == buf.len() {
                grow_xattr_buf(&mut buf)?;
            }
            match call(&mut buf) {
                Ok(_) => return Ok(buf),
                Err(rustix::io::Errno::RANGE) => {
                    buf.clear();
                    grow_xattr_buf(&mut buf)?;
                }
                Err(err) => return Err(from_rustix(err)),
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn grow_xattr_buf(buf: &mut Vec<u8>) -> io::Result<()> {
        if buf.capacity() >= XATTR_MAX {
            return Err(super::linux_errno(
                super::LINUX_ERANGE,
                io::ErrorKind::InvalidInput,
            ));
        }
        let next = buf.capacity().saturating_mul(2).clamp(64, XATTR_MAX);
        buf.reserve(next - buf.capacity());
        Ok(())
    }

    fn seek_data_hole(file: &File, offset: u64, whence: u32) -> io::Result<u64> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let pos = match whence {
                SEEK_DATA => rustix::fs::SeekFrom::Data(offset),
                SEEK_HOLE => rustix::fs::SeekFrom::Hole(offset),
                _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
            };
            rustix::fs::seek(file, pos).map_err(from_rustix)
        }
        #[cfg(windows)]
        {
            // NTFS sparse ranges are not a portable `SEEK_HOLE`. Report the
            // dense layout: the whole file is data and the only hole is EOF.
            if !matches!(whence, SEEK_DATA | SEEK_HOLE) {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let len = file.metadata()?.len();
            match whence {
                SEEK_DATA if offset >= len => Err(super::linux_errno(
                    super::LINUX_ENXIO,
                    io::ErrorKind::NotFound,
                )),
                SEEK_HOLE if offset > len => Err(super::linux_errno(
                    super::LINUX_ENXIO,
                    io::ErrorKind::NotFound,
                )),
                SEEK_DATA => Ok(offset),
                _ => Ok(len),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (file, offset, whence);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn copy_range(src: &File, src_off: u64, dst: &File, dst_off: u64, len: u64) -> io::Result<u32> {
        #[cfg(target_os = "linux")]
        {
            if let Some(copied) = copy_range_linux(src, src_off, dst, dst_off, len)? {
                return Ok(copied);
            }
        }
        copy_range_userspace(src, src_off, dst, dst_off, len)
    }

    /// `Some` is a finished copy (including a short count after a later error).
    /// `None` means the syscall cannot perform this copy and the caller should
    /// use a userspace read/write loop. That keeps `ENOSYS` off the FUSE wire:
    /// Linux caches it and stops asking.
    #[cfg(target_os = "linux")]
    fn copy_range_linux(
        src: &File,
        mut src_off: u64,
        dst: &File,
        mut dst_off: u64,
        mut len: u64,
    ) -> io::Result<Option<u32>> {
        let mut copied = 0u64;
        while len > 0 {
            let chunk = usize::try_from(len.min(1 << 20)).unwrap_or(1 << 20);
            match rustix::fs::copy_file_range(
                src,
                Some(&mut src_off),
                dst,
                Some(&mut dst_off),
                chunk,
            ) {
                Ok(0) => break,
                Ok(n) => {
                    copied += u64::try_from(n).unwrap_or(0);
                    len -= u64::try_from(n).unwrap_or(0);
                }
                Err(rustix::io::Errno::INTR) => continue,
                Err(
                    rustix::io::Errno::NOSYS
                    | rustix::io::Errno::OPNOTSUPP
                    | rustix::io::Errno::INVAL
                    | rustix::io::Errno::XDEV,
                ) if copied == 0 => return Ok(None),
                Err(_) if copied > 0 => break,
                Err(err) => return Err(from_rustix(err)),
            }
        }
        Ok(Some(u32::try_from(copied).unwrap_or(u32::MAX)))
    }

    fn copy_range_userspace(
        src: &File,
        mut src_off: u64,
        dst: &File,
        mut dst_off: u64,
        mut len: u64,
    ) -> io::Result<u32> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut copied = 0u64;
        while len > 0 {
            let chunk = usize::try_from(len.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = read_full(src, &mut buf[..chunk], src_off)?;
            if n == 0 {
                break;
            }
            write_full(dst, &buf[..n], dst_off)?;
            let n = u64::try_from(n).unwrap_or(0);
            src_off += n;
            dst_off += n;
            copied += n;
            len -= n;
        }
        Ok(u32::try_from(copied).unwrap_or(u32::MAX))
    }

    #[cfg(unix)]
    fn from_rustix(err: rustix::io::Errno) -> io::Error {
        #[cfg(not(target_os = "linux"))]
        if host_errno_needs_linux_number(err) {
            return linux_number(err);
        }
        io::Error::from(err)
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn host_errno_needs_linux_number(err: rustix::io::Errno) -> bool {
        missing_xattr(err) || err == rustix::io::Errno::RANGE || err == rustix::io::Errno::NXIO
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn missing_xattr(err: rustix::io::Errno) -> bool {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            err == rustix::io::Errno::NODATA || err == rustix::io::Errno::NOATTR
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            err == rustix::io::Errno::NODATA
        }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn linux_number(err: rustix::io::Errno) -> io::Error {
        if missing_xattr(err) {
            super::linux_errno(super::LINUX_ENODATA, io::ErrorKind::NotFound)
        } else if err == rustix::io::Errno::RANGE {
            super::linux_errno(super::LINUX_ERANGE, io::ErrorKind::InvalidInput)
        } else {
            super::linux_errno(super::LINUX_ENXIO, io::ErrorKind::NotFound)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const DISALLOWED_XATTR_NAMES: &[&str] = &[
            "security.capability",
            "security.selinux",
            "trusted.foo",
            "system.posix_acl_access",
            "",
            "user",
            "user.",
            "userx.foo",
            "User.foo",
            "user.foo\0",
            "user.\0foo",
            "\0user.foo",
        ];

        #[test]
        fn xattr_names_require_user_prefix_and_nonempty_suffix() {
            for name in DISALLOWED_XATTR_NAMES {
                assert!(!is_allowed_xattr_name(name.as_bytes()), "{name:?}");
            }
            for name in ["user.foo", "user.a", "user..", "user.user.foo", "user.é"] {
                assert!(is_allowed_xattr_name(name.as_bytes()), "{name:?}");
            }
        }

        #[test]
        fn disallowed_xattrs_are_rejected_before_host_access() {
            let dir = tempfile::tempdir().unwrap();
            let backend = Passthrough::new(dir.path()).unwrap();
            let rel = Path::new("missing");
            let path = dir.path().join(rel);
            for name in DISALLOWED_XATTR_NAMES {
                for result in [
                    read_xattr(&path, name).map(|_| ()),
                    write_xattr(&path, name, b"value", 0),
                    delete_xattr(&path, name),
                    backend.get_xattr(rel, name).map(|_| ()),
                    backend.set_xattr(rel, name, b"value", 0),
                    backend.remove_xattr(rel, name),
                ] {
                    assert_eq!(
                        result.unwrap_err().kind(),
                        io::ErrorKind::PermissionDenied,
                        "{name:?}"
                    );
                }
            }
            assert!(!path.exists());
        }

        #[test]
        fn xattr_list_buffer_contains_only_allowed_names() {
            let names = b"security.capability\0user.foo\0trusted.foo\0user\0user.\0\0system.posix_acl_access\0userx.foo\0security.selinux\0user.bar\0user.\xff\0";
            assert_eq!(
                filter_xattr_names(names),
                b"user.foo\0user.bar\0user.\xff\0"
            );
            assert!(filter_xattr_names(b"security.selinux\0trusted.foo\0").is_empty());
            assert!(filter_xattr_names(b"").is_empty());
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        #[test]
        fn user_xattr_roundtrip() {
            let dir = tempfile::tempdir().unwrap();
            let backend = Passthrough::new(dir.path()).unwrap();
            let rel = Path::new("file");
            let path = dir.path().join(rel);
            fs::write(&path, b"data").unwrap();
            backend.set_xattr(rel, "user.foo", b"first", 1).unwrap();
            assert_eq!(backend.get_xattr(rel, "user.foo").unwrap(), b"first");
            backend.set_xattr(rel, "user.foo", b"second", 2).unwrap();
            assert_eq!(read_xattr(&path, "user.foo").unwrap(), b"second");
            assert_eq!(backend.list_xattr(rel).unwrap(), b"user.foo\0");
            backend.remove_xattr(rel, "user.foo").unwrap();
            assert!(backend.list_xattr(rel).unwrap().is_empty());
            assert!(backend.get_xattr(rel, "user.foo").is_err());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn host_acl_is_hidden_and_cannot_be_read_changed_or_removed() {
            let dir = tempfile::tempdir().unwrap();
            let backend = Passthrough::new(dir.path()).unwrap();
            let rel = Path::new("file");
            let path = dir.path().join(rel);
            fs::write(&path, b"data").unwrap();
            // A valid Linux ACL with one named user, installed by the host.
            let mut acl = 2u32.to_le_bytes().to_vec();
            for (tag, perm, id) in [
                (1u16, 7u16, u32::MAX),
                (2, 4, 1000),
                (4, 5, u32::MAX),
                (16, 5, u32::MAX),
                (32, 5, u32::MAX),
            ] {
                acl.extend_from_slice(&tag.to_le_bytes());
                acl.extend_from_slice(&perm.to_le_bytes());
                acl.extend_from_slice(&id.to_le_bytes());
            }
            let name = "system.posix_acl_access";
            match rustix::fs::lsetxattr(&path, name, &acl, rustix::fs::XattrFlags::empty()) {
                Ok(()) => {}
                Err(err)
                    if matches!(
                        err,
                        rustix::io::Errno::INVAL
                            | rustix::io::Errno::OPNOTSUPP
                            | rustix::io::Errno::PERM
                    ) =>
                {
                    eprintln!("skipping host ACL preservation: cannot install {name}: {err}");
                    return;
                }
                Err(err) => panic!("failed to install host ACL: {err}"),
            }
            backend.set_xattr(rel, "user.foo", b"visible", 0).unwrap();
            assert_eq!(list_xattrs(&path).unwrap(), b"user.foo\0");
            assert_eq!(backend.list_xattr(rel).unwrap(), b"user.foo\0");
            for result in [
                backend.get_xattr(rel, name).map(|_| ()),
                backend.set_xattr(rel, name, b"replacement", 0),
                backend.remove_xattr(rel, name),
            ] {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            }
            let actual = grow_xattr(|buf| {
                rustix::fs::lgetxattr(&path, name, rustix::buffer::spare_capacity(buf))
            })
            .unwrap();
            assert_eq!(actual, acl);
            assert_eq!(fs::read(&path).unwrap(), b"data");
        }
    }
}

pub use passthrough::Passthrough;

// ---------------------------------------------------------------------------
// MapFs — an in-memory tree, for protocol unit tests on any platform.
// ---------------------------------------------------------------------------

/// In-memory read-only filesystem used by the unit tests. Built from a flat
/// list of `("rel/path", contents)` regular files; intermediate directories are
/// created implicitly. Inode numbers are assigned in insertion order.
#[derive(Debug, Default)]
pub struct MapFs {
    /// Directory rel-path → child names.
    dirs: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    /// Regular file rel-path → contents.
    files: std::collections::BTreeMap<String, Vec<u8>>,
    /// rel-path → inode number (root is "").
    inos: std::collections::BTreeMap<String, u64>,
}

impl MapFs {
    pub fn new() -> Self {
        let mut fs = Self::default();
        fs.dirs
            .insert(String::new(), std::collections::BTreeSet::new());
        fs.inos.insert(String::new(), 1);
        fs
    }

    fn next_ino(&self) -> u64 {
        (self.inos.len() as u64) + 1
    }

    /// Insert a regular file at `rel` with `contents`, creating parent dirs.
    #[must_use]
    pub fn with_file(mut self, rel: &str, contents: impl Into<Vec<u8>>) -> Self {
        let contents = contents.into();
        let rel = rel.trim_matches('/').to_string();
        let parts: Vec<&str> = rel.split('/').collect();
        let (dirs, last) = parts.split_at(parts.len() - 1);

        // Create the chain of parent directories.
        let mut parent = String::new();
        for part in dirs {
            let child = if parent.is_empty() {
                (*part).to_string()
            } else {
                format!("{parent}/{part}")
            };
            self.dirs
                .entry(parent.clone())
                .or_default()
                .insert((*part).to_string());
            self.dirs.entry(child.clone()).or_default();
            let ino = self.next_ino();
            self.inos.entry(child.clone()).or_insert(ino);
            parent = child;
        }

        // Insert the regular file itself.
        let name = last[0];
        let child = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        self.dirs
            .entry(parent.clone())
            .or_default()
            .insert(name.to_string());
        let ino = self.next_ino();
        self.inos.entry(child.clone()).or_insert(ino);
        self.files.insert(child, contents);
        self
    }

    fn key(rel: &Path) -> io::Result<String> {
        let clean = sanitize_rel(rel)?;
        Ok(clean.to_string_lossy().replace('\\', "/"))
    }

    fn attr_for(&self, key: &str) -> io::Result<Attr> {
        let ino = *self
            .inos
            .get(key)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if self.dirs.contains_key(key) {
            Ok(Attr {
                ino,
                size: 0,
                blocks: 0,
                mode: S_IFDIR | 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                mtime: 0,
                mtime_nsec: 0,
            })
        } else if let Some(data) = self.files.get(key) {
            Ok(Attr {
                ino,
                size: data.len() as u64,
                blocks: data.len().div_ceil(512) as u64,
                mode: S_IFREG | 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                mtime: 0,
                mtime_nsec: 0,
            })
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
}

impl FsBackend for MapFs {
    fn stat(&self, rel: &Path) -> io::Result<Attr> {
        let key = Self::key(rel)?;
        self.attr_for(&key)
    }

    fn readdir(&self, rel: &Path) -> io::Result<Vec<DirEntry>> {
        let key = Self::key(rel)?;
        let children = self
            .dirs
            .get(&key)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotADirectory))?;
        let mut out = Vec::new();
        for name in children {
            let child_key = if key.is_empty() {
                name.clone()
            } else {
                format!("{key}/{name}")
            };
            out.push(DirEntry {
                name: name.clone(),
                attr: self.attr_for(&child_key)?,
            });
        }
        Ok(out)
    }

    fn read(&self, rel: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let key = Self::key(rel)?;
        let data = self
            .files
            .get(&key)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(size as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn readlink(&self, _rel: &Path) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rejects_parent_escape() {
        assert!(sanitize_rel(Path::new("../etc/passwd")).is_err());
        assert!(sanitize_rel(Path::new("a/../../b")).is_err());
        assert!(sanitize_rel(Path::new("/abs")).is_err());
        assert_eq!(
            sanitize_rel(Path::new("a/./b")).unwrap(),
            PathBuf::from("a/b")
        );
    }

    #[test]
    fn mapfs_stat_and_read() {
        let fs = MapFs::new().with_file("hello.txt", "hi there");
        let root = fs.stat(Path::new("")).unwrap();
        assert!(root.is_dir());
        let f = fs.stat(Path::new("hello.txt")).unwrap();
        assert_eq!(f.size, 8);
        assert_eq!(f.dirent_type(), DT_REG);
        assert_eq!(fs.read(Path::new("hello.txt"), 0, 64).unwrap(), b"hi there");
        assert_eq!(fs.read(Path::new("hello.txt"), 3, 64).unwrap(), b"there");
    }

    #[test]
    fn read_until_full_retries_short_reads() {
        let mut calls = 0;
        let mut buf = [0u8; 10];
        let n = super::passthrough::read_until_full(
            |dst, _offset| {
                calls += 1;
                let n = dst.len().min(3);
                dst[..n].fill(7);
                Ok(n)
            },
            &mut buf,
            0,
        )
        .unwrap();
        assert_eq!(n, 10);
        assert!(calls >= 4);
        assert_eq!(buf, [7u8; 10]);
    }

    #[test]
    fn passthrough_serves_host_dir_cross_platform() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"hello").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        let pt = Passthrough::new(dir.path()).unwrap();

        let root = pt.stat(Path::new("")).unwrap();
        assert!(root.is_dir());

        let f = pt.stat(Path::new("f.txt")).unwrap();
        assert_eq!(f.size, 5);
        assert_eq!(f.dirent_type(), DT_REG);
        assert_eq!(f.mode & S_IFMT, S_IFREG);
        assert_eq!(pt.read(Path::new("f.txt"), 0, 64).unwrap(), b"hello");
        assert_eq!(pt.read(Path::new("f.txt"), 2, 64).unwrap(), b"llo");

        let names: Vec<String> = pt
            .readdir(Path::new(""))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"f.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));

        // Lexical escape is rejected before touching the filesystem.
        assert!(pt.stat(Path::new("../escape")).is_err());
        // A missing child is NotFound (a LOOKUP miss), not a containment error.
        assert_eq!(
            pt.stat(Path::new("nope")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn passthrough_write_path_cross_platform() {
        let dir = tempfile::tempdir().unwrap();
        let pt = Passthrough::new(dir.path()).unwrap();

        // create + write
        let attr = pt.create(Path::new("new.txt"), 0o644).unwrap();
        assert_eq!(attr.mode & S_IFMT, S_IFREG);
        assert_eq!(
            pt.write(Path::new("new.txt"), 0, b"hello world").unwrap(),
            11
        );
        assert_eq!(
            pt.read(Path::new("new.txt"), 0, 64).unwrap(),
            b"hello world"
        );
        // positional write (overwrite "world" -> "rust!")
        assert_eq!(pt.write(Path::new("new.txt"), 6, b"rust!").unwrap(), 5);
        assert_eq!(
            pt.read(Path::new("new.txt"), 0, 64).unwrap(),
            b"hello rust!"
        );
        assert_eq!(
            std::fs::read(dir.path().join("new.txt")).unwrap(),
            b"hello rust!"
        );

        // mkdir + nested create
        pt.mkdir(Path::new("d"), 0o755).unwrap();
        assert!(pt.stat(Path::new("d")).unwrap().is_dir());
        pt.create(Path::new("d/inner.txt"), 0o644).unwrap();
        pt.write(Path::new("d/inner.txt"), 0, b"x").unwrap();
        assert!(dir.path().join("d/inner.txt").exists());

        // setattr: truncate
        let a = pt
            .setattr(
                Path::new("new.txt"),
                &SetAttr {
                    size: Some(5),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(a.size, 5);
        assert_eq!(pt.read(Path::new("new.txt"), 0, 64).unwrap(), b"hello");

        // rename
        pt.rename(Path::new("new.txt"), Path::new("renamed.txt"), 0)
            .unwrap();
        assert!(!dir.path().join("new.txt").exists());
        assert_eq!(pt.read(Path::new("renamed.txt"), 0, 64).unwrap(), b"hello");

        // unlink + rmdir
        pt.unlink(Path::new("renamed.txt")).unwrap();
        assert!(!dir.path().join("renamed.txt").exists());
        pt.unlink(Path::new("d/inner.txt")).unwrap();
        pt.rmdir(Path::new("d")).unwrap();
        assert!(!dir.path().join("d").exists());

        // write escaping the share is rejected before touching the fs
        assert!(pt.write(Path::new("../escape"), 0, b"x").is_err());
        assert!(pt.create(Path::new("../evil.txt"), 0o644).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn passthrough_setattr_mode_and_symlink_unix() {
        let dir = tempfile::tempdir().unwrap();
        let pt = Passthrough::new(dir.path()).unwrap();
        pt.create(Path::new("f"), 0o644).unwrap();
        let a = pt
            .setattr(
                Path::new("f"),
                &SetAttr {
                    mode: Some(0o600),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(a.mode & 0o777, 0o600);

        let link = pt.symlink(Path::new("l"), b"f").unwrap();
        assert_eq!(link.mode & S_IFMT, S_IFLNK);
        assert_eq!(pt.readlink(Path::new("l")).unwrap(), b"f");
    }

    #[test]
    fn mapfs_readdir_lists_children() {
        let fs = MapFs::new()
            .with_file("a.txt", "a")
            .with_file("sub/b.txt", "b");
        let mut names: Vec<String> = fs
            .readdir(Path::new(""))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "sub".to_string()]);
        let sub = fs.readdir(Path::new("sub")).unwrap();
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].name, "b.txt");
    }
}
