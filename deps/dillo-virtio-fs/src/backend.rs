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

/// A backend path with an optional retained host object. Logical names remain
/// available for directory bookkeeping; host operations use the reference.
#[derive(Debug, Clone)]
pub struct NodePath {
    pub(crate) rel: PathBuf,
    pub(crate) file: Option<std::sync::Arc<std::fs::File>>,
    pub(crate) parent: Option<std::sync::Arc<std::fs::File>>,
    pub(crate) name: PathBuf,
    /// Windows only: the volume serial number and file index seen at lookup.
    /// A later reopen by path must find the same pair.
    #[cfg(windows)]
    pub(crate) id: Option<(u32, u64)>,
    /// Windows only: the same pair for the folder this name was joined to.
    #[cfg(windows)]
    pub(crate) parent_id: Option<(u32, u64)>,
}

impl NodePath {
    pub fn new(rel: impl Into<PathBuf>) -> Self {
        let rel = rel.into();
        Self {
            name: rel.clone(),
            rel,
            file: None,
            parent: None,
            #[cfg(windows)]
            id: None,
            #[cfg(windows)]
            parent_id: None,
        }
    }

    pub(crate) fn same_object(&self, other: &Self) -> bool {
        #[cfg(windows)]
        if let (Some(a), Some(b)) = (self.id, other.id) {
            return a == b;
        }
        match (&self.file, &other.file) {
            (Some(a), Some(b)) => passthrough::same_object(a, b).unwrap_or(false),
            _ => true,
        }
    }

    pub(crate) fn retarget(&mut self, rel: PathBuf) {
        self.name.clone_from(&rel);
        self.parent = None;
        #[cfg(windows)]
        {
            self.parent_id = None;
        }
        self.rel = rel;
    }

    /// The copy kept for later use, in the lookup cache and in open files.
    /// Windows cannot rename a folder while anything inside it is held
    /// open, so there it keeps only the path and the identity, and drops
    /// the host handles.
    pub(crate) fn for_cache(&self) -> Self {
        #[cfg(windows)]
        {
            Self {
                rel: self.rel.clone(),
                file: None,
                parent: None,
                name: self.rel.clone(),
                id: self.id,
                parent_id: None,
            }
        }
        #[cfg(not(windows))]
        {
            self.clone()
        }
    }

    pub(crate) fn join(&self, name: impl AsRef<Path>) -> Self {
        Self {
            rel: self.rel.join(name.as_ref()),
            file: None,
            parent: self.file.clone(),
            name: if self.file.is_some() {
                PathBuf::from(name.as_ref())
            } else {
                self.name.join(name.as_ref())
            },
            #[cfg(windows)]
            id: None,
            #[cfg(windows)]
            parent_id: self.id,
        }
    }
}

impl std::ops::Deref for NodePath {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.rel
    }
}

/// Filesystem backing for a virtio-fs share. Paths are relative to the share
/// root; the empty path is the root itself.
///
/// The read methods are required; the write methods default to `EROFS` so a
/// read-only backing needs to implement nothing. A device configured read-only
/// rejects mutating FUSE opcodes before any of these are called.
pub trait FsBackend: Send + Sync {
    /// Look up a node and retain its host reference when this backend has one.
    fn lookup(&self, rel: &NodePath) -> io::Result<(Attr, NodePath)> {
        Ok((self.stat(rel)?, rel.clone()))
    }

    /// `lstat` the node at `rel` (does not follow a trailing symlink).
    fn stat(&self, rel: &NodePath) -> io::Result<Attr>;

    /// List the directory at `rel`. `.`/`..` are synthesized by the caller.
    fn readdir(&self, rel: &NodePath) -> io::Result<Vec<DirEntry>>;

    /// Read up to `size` bytes at `offset` from the regular file at `rel`.
    fn read(&self, rel: &NodePath, offset: u64, size: u32) -> io::Result<Vec<u8>>;

    /// Read the target of the symlink at `rel`.
    fn readlink(&self, rel: &NodePath) -> io::Result<Vec<u8>>;

    // --- write path (default: read-only) -----------------------------------

    /// Write `data` at `offset` to the regular file at `rel`; returns the number
    /// of bytes written.
    fn write(&self, rel: &NodePath, offset: u64, data: &[u8]) -> io::Result<u32> {
        let _ = (rel, offset, data);
        Err(read_only_error())
    }

    /// Create (or open) a regular file at `rel` with `mode`, returning its attr.
    fn create(&self, rel: &NodePath, mode: u32) -> io::Result<Attr> {
        let _ = (rel, mode);
        Err(read_only_error())
    }

    /// Create a regular file and retain the object returned by the host open.
    fn create_open(&self, rel: &NodePath, mode: u32) -> io::Result<(Attr, NodePath)> {
        self.create(rel, mode)?;
        self.lookup(rel)
    }

    /// Create a directory at `rel` with `mode`, returning its attr.
    fn mkdir(&self, rel: &NodePath, mode: u32) -> io::Result<Attr> {
        let _ = (rel, mode);
        Err(read_only_error())
    }

    /// Remove the regular file (or symlink) at `rel`.
    fn unlink(&self, rel: &NodePath) -> io::Result<()> {
        let _ = rel;
        Err(read_only_error())
    }

    /// Remove the (empty) directory at `rel`.
    fn rmdir(&self, rel: &NodePath) -> io::Result<()> {
        let _ = rel;
        Err(read_only_error())
    }

    /// Rename `from` to `to`. `flags` uses Linux `RENAME_*` bits: `1` noreplace,
    /// `2` exchange, `4` whiteout. Whiteout is rejected; noreplace and exchange
    /// are performed when the host OS can do them.
    fn rename(&self, from: &NodePath, to: &NodePath, flags: u32) -> io::Result<()> {
        let _ = (from, to, flags);
        Err(read_only_error())
    }

    /// Create a hard link `to` referring to `from`.
    fn link(&self, from: &NodePath, to: &NodePath) -> io::Result<Attr> {
        let _ = (from, to);
        Err(read_only_error())
    }

    /// Create a special file. `mode` includes the `S_IF*` type bits.
    fn mknod(&self, rel: &NodePath, mode: u32, rdev: u32) -> io::Result<Attr> {
        let _ = (rel, mode, rdev);
        Err(read_only_error())
    }

    /// `fallocate`. `mode` uses Linux `FALLOC_FL_*` bits.
    fn fallocate(&self, rel: &NodePath, offset: u64, length: u64, mode: u32) -> io::Result<()> {
        let _ = (rel, offset, length, mode);
        Err(read_only_error())
    }

    /// Read one `user.*` extended attribute. Missing attributes are `ENODATA`.
    fn get_xattr(&self, rel: &NodePath, name: &str) -> io::Result<Vec<u8>> {
        let _ = (rel, name);
        Err(unsupported_error())
    }

    /// Set one `user.*` extended attribute. `flags` uses Linux `XATTR_CREATE` (1) and
    /// `XATTR_REPLACE` (2).
    fn set_xattr(&self, rel: &NodePath, name: &str, value: &[u8], flags: u32) -> io::Result<()> {
        let _ = (rel, name, value, flags);
        Err(read_only_error())
    }

    /// List `user.*` extended attribute names as NUL-terminated strings.
    fn list_xattr(&self, rel: &NodePath) -> io::Result<Vec<u8>> {
        let _ = rel;
        Err(unsupported_error())
    }

    /// Remove one `user.*` extended attribute. A missing attribute is `ENODATA`.
    fn remove_xattr(&self, rel: &NodePath, name: &str) -> io::Result<()> {
        let _ = (rel, name);
        Err(read_only_error())
    }

    /// `SEEK_DATA` (3) / `SEEK_HOLE` (4). Other `whence` values are `EINVAL`.
    fn lseek(&self, rel: &NodePath, offset: u64, whence: u32) -> io::Result<u64> {
        let _ = (rel, offset, whence);
        Err(unsupported_error())
    }

    /// Copy up to `len` bytes. `flags` must be zero. A short copy is a real
    /// byte count, not an error, so the guest can resume.
    fn copy_file_range(
        &self,
        src: &NodePath,
        src_off: u64,
        dst: &NodePath,
        dst_off: u64,
        len: u64,
        flags: u32,
    ) -> io::Result<u32> {
        let _ = (src, src_off, dst, dst_off, len, flags);
        Err(read_only_error())
    }

    /// Apply [`SetAttr`] to `rel`, returning the resulting attr.
    fn setattr(&self, rel: &NodePath, set: &SetAttr) -> io::Result<Attr> {
        let _ = (rel, set);
        Err(read_only_error())
    }

    /// Create a symlink at `rel` pointing at `target`, returning its attr.
    fn symlink(&self, rel: &NodePath, target: &[u8]) -> io::Result<Attr> {
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
    use super::{Attr, DirEntry, FsBackend, NodePath, SetAttr, sanitize_rel};
    // The synthesized-attr path (non-Unix hosts) needs the type-bit constants;
    // on Unix the real mode is read straight from `MetadataExt`.
    #[cfg(not(unix))]
    use super::{S_IFDIR, S_IFLNK, S_IFREG};
    #[cfg(unix)]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::fs::OpenOptions;
    use std::fs::{File, FileTimes, Metadata};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, UNIX_EPOCH};

    /// Passthrough of a host directory subtree.
    #[derive(Debug)]
    pub struct Passthrough {
        root: std::sync::Arc<File>,
    }

    #[derive(Debug)]
    struct Parent {
        file: std::sync::Arc<File>,
        name: PathBuf,
        #[cfg(windows)]
        guard: File,
    }

    impl Parent {
        fn new(file: std::sync::Arc<File>, name: PathBuf) -> io::Result<Self> {
            check_directory(&file)?;
            #[cfg(windows)]
            let guard = cap_primitives::fs::open_dir(&file, Path::new("."))?;
            Ok(Self {
                file,
                name,
                #[cfg(windows)]
                guard,
            })
        }
    }

    fn check_directory(file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::from(io::ErrorKind::NotADirectory));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(io::Error::from(io::ErrorKind::NotADirectory));
            }
        }
        Ok(())
    }

    impl Passthrough {
        /// Create a passthrough rooted at an open reference to `root`.
        pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
            let root = cap_primitives::fs::open_ambient_dir(
                &root.into(),
                cap_primitives::ambient_authority(),
            )?;
            Ok(Self {
                root: std::sync::Arc::new(root),
            })
        }

        fn parent(&self, rel: &NodePath) -> io::Result<Parent> {
            sanitize_rel(rel)?;
            let clean = sanitize_rel(&rel.name)?;
            let mut file = rel.parent.clone().unwrap_or_else(|| self.root.clone());
            let mut parts = clean.components().peekable();
            while let Some(part) = parts.next() {
                if parts.peek().is_none() {
                    #[cfg(windows)]
                    check_id(rel.parent_id, &file)?;
                    return Parent::new(file, PathBuf::from(part.as_os_str()));
                }
                file = std::sync::Arc::new(open_directory(&file, Path::new(part.as_os_str()))?);
            }
            Parent::new(file, PathBuf::from("."))
        }

        fn pin(&self, rel: &NodePath) -> io::Result<NodePath> {
            if rel.file.is_some() {
                return Ok(rel.clone());
            }
            let parent = self.parent(rel)?;
            let file = pin_child(&parent.file, &parent.name)?;
            #[cfg(windows)]
            check_id(rel.id, &file)?;
            Ok(NodePath {
                rel: rel.rel.clone(),
                #[cfg(windows)]
                id: Some(windows_id(&file)?),
                #[cfg(windows)]
                parent_id: None,
                file: Some(std::sync::Arc::new(file)),
                parent: Some(parent.file),
                name: parent.name,
            })
        }

        fn open(&self, rel: &NodePath, write: bool, create: Option<u32>) -> io::Result<File> {
            #[cfg(target_os = "linux")]
            if let Some(file) = &rel.file {
                use std::os::fd::AsRawFd;
                use std::os::unix::fs::OpenOptionsExt;
                if file.metadata()?.file_type().is_symlink() {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                // This is an owned descriptor, never a guest pathname. Keep
                // it alive until the kernel has opened the same object.
                let path = format!("/proc/self/fd/{}", file.as_raw_fd());
                return OpenOptions::new()
                    .read(!write)
                    .write(write)
                    .custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed())
                    .open(path);
            }
            #[cfg(windows)]
            if let Some(file) = &rel.file {
                return reopen_file(file, write);
            }
            self.open_checked(rel, write, create)
        }

        fn open_checked(
            &self,
            rel: &NodePath,
            write: bool,
            create: Option<u32>,
        ) -> io::Result<File> {
            let parent = self.parent(rel)?;
            #[cfg(windows)]
            let create = if rel.id.is_some() { None } else { create };
            let create = if rel.file.is_some() { None } else { create };
            let file = open_child(&parent.file, &parent.name, write, create)?;
            #[cfg(windows)]
            check_id(rel.id, &file)?;
            if let Some(expected) = &rel.file
                && !same_object(expected, &file)?
            {
                return Err(super::linux_errno(116, io::ErrorKind::NotFound));
            }
            Ok(file)
        }
    }

    #[cfg(unix)]
    fn open_child(
        parent: &File,
        name: &Path,
        write: bool,
        create: Option<u32>,
    ) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        let mut flags = OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        flags |= if write {
            OFlags::WRONLY
        } else {
            OFlags::RDONLY
        };
        let mode = if let Some(mode) = create {
            flags |= OFlags::CREATE;
            Mode::from_raw_mode((mode & 0o777) as _)
        } else {
            Mode::empty()
        };
        open_relative(parent, name, flags, mode).map(File::from)
    }

    #[cfg(windows)]
    fn open_child(
        parent: &File,
        name: &Path,
        write: bool,
        create: Option<u32>,
    ) -> io::Result<File> {
        use cap_primitives::fs::{OpenOptions, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        let mut options = OpenOptions::new();
        options
            .read(!write)
            .write(write)
            .create(create.is_some())
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let file = cap_primitives::fs::open(parent, name, &options)?;
        if file.metadata()?.file_type().is_symlink() {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(file)
    }

    #[cfg(unix)]
    fn open_directory(parent: &File, name: &Path) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        open_relative(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
    }

    #[cfg(windows)]
    fn open_directory(parent: &File, name: &Path) -> io::Result<File> {
        let file = pin_child(parent, name)?;
        check_directory(&file)?;
        Ok(file)
    }

    #[cfg(unix)]
    fn pin_child(parent: &File, name: &Path) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        #[cfg(target_os = "linux")]
        let flags = OFlags::PATH;
        #[cfg(target_os = "macos")]
        // A FIFO opened for reading waits for a writer unless O_NONBLOCK is set;
        // Linux O_PATH never waits.
        let flags =
            OFlags::from_bits_retain((libc::O_EVTONLY | libc::O_SYMLINK | libc::O_NONBLOCK) as _);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let flags = OFlags::RDONLY | OFlags::NONBLOCK;
        open_relative(parent, name, flags | OFlags::CLOEXEC, Mode::empty()).map(File::from)
    }

    /// Never follow a final symlink. macOS `O_SYMLINK` already opens the link
    /// itself, and adding `O_NOFOLLOW` to it makes that open fail with `ELOOP`.
    #[cfg(unix)]
    fn no_follow(flags: rustix::fs::OFlags) -> rustix::fs::OFlags {
        #[cfg(target_os = "macos")]
        if flags.contains(rustix::fs::OFlags::from_bits_retain(libc::O_SYMLINK as _)) {
            return flags;
        }
        flags | rustix::fs::OFlags::NOFOLLOW
    }

    #[cfg(windows)]
    fn pin_child(parent: &File, name: &Path) -> io::Result<File> {
        use cap_primitives::fs::{OpenOptions, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        };
        let mut options = OpenOptions::new();
        options
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        cap_primitives::fs::open(parent, name, &options)
    }

    #[cfg(unix)]
    fn open_relative(
        parent: &File,
        name: &Path,
        flags: rustix::fs::OFlags,
        mode: rustix::fs::Mode,
    ) -> io::Result<rustix::fd::OwnedFd> {
        let flags = no_follow(flags);
        open_with_fallback(parent, name, flags, mode, || {
            #[cfg(target_os = "linux")]
            {
                use rustix::fs::ResolveFlags;
                rustix::fs::openat2(
                    parent,
                    name,
                    flags,
                    mode,
                    ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(rustix::io::Errno::NOSYS)
            }
        })
    }

    #[cfg(unix)]
    fn open_with_fallback(
        parent: &File,
        name: &Path,
        flags: rustix::fs::OFlags,
        mode: rustix::fs::Mode,
        stronger: impl FnOnce() -> Result<rustix::fd::OwnedFd, rustix::io::Errno>,
    ) -> io::Result<rustix::fd::OwnedFd> {
        // The fallback has the same no-follow contract, one component at a
        // time. Errors from an available stronger helper are never weakened.
        if name != Path::new(".")
            && (sanitize_rel(name)?.components().count() != 1 || name.components().count() != 1)
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let flags = no_follow(flags);
        match stronger() {
            Err(rustix::io::Errno::NOSYS) => {
                rustix::fs::openat(parent, name, flags, mode).map_err(from_rustix)
            }
            result => result.map_err(from_rustix),
        }
    }

    pub(super) fn same_object(a: &File, b: &File) -> io::Result<bool> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let a = a.metadata()?;
            let b = b.metadata()?;
            Ok(a.dev() == b.dev() && a.ino() == b.ino())
        }
        #[cfg(windows)]
        {
            let (a_volume, a_index, _) = host_file_id(a)?;
            let (b_volume, b_index, _) = host_file_id(b)?;
            Ok(a_volume == b_volume && a_index == b_index)
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
            // file_attr replaces these defaults with handle identity.
            let (ino, nlink) = (synth_ino(full), if ft.is_dir() { 2 } else { 1 });
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

    /// Stable, nonzero cosmetic inode number derived from the full host path.
    #[cfg(not(unix))]
    fn synth_ino(path: &Path) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut hasher);
        hasher.finish() | 1
    }

    impl FsBackend for Passthrough {
        fn lookup(&self, rel: &NodePath) -> io::Result<(Attr, NodePath)> {
            let pinned = self.pin(rel)?;
            let attr = file_attr(pinned.file.as_ref().expect("pinned"))?;
            Ok((attr, pinned.for_cache()))
        }
        fn stat(&self, rel: &NodePath) -> io::Result<Attr> {
            self.lookup(rel).map(|(attr, _)| attr)
        }

        fn readdir(&self, rel: &NodePath) -> io::Result<Vec<DirEntry>> {
            let pinned = self.pin(rel)?;
            let dir = pinned.file.as_ref().expect("pinned");
            check_directory(dir)?;
            #[cfg(windows)]
            let guard = cap_primitives::fs::open_dir(dir, Path::new("."))?;
            #[cfg(windows)]
            let dir = &guard;
            let mut out = Vec::new();
            for entry in cap_primitives::fs::read_base_dir(dir)? {
                let entry = entry?;
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                let file = pin_child(dir, Path::new(&name))?;
                out.push(DirEntry {
                    name,
                    attr: file_attr(&file)?,
                });
            }
            Ok(out)
        }

        fn read(&self, rel: &NodePath, offset: u64, size: u32) -> io::Result<Vec<u8>> {
            let file = self.open(rel, false, None)?;
            let mut buf = vec![0u8; size as usize];
            let n = read_full(&file, &mut buf, offset)?;
            buf.truncate(n);
            Ok(buf)
        }

        fn readlink(&self, rel: &NodePath) -> io::Result<Vec<u8>> {
            #[cfg(target_os = "linux")]
            {
                let pinned = self.pin(rel)?;
                let target =
                    rustix::fs::readlinkat(pinned.file.as_ref().expect("pinned"), "", Vec::new())
                        .map_err(from_rustix)?;
                Ok(target.into_bytes())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let parent = self.parent(rel)?;
                let target = cap_primitives::fs::read_link_contents(&parent.file, &parent.name)?;
                Ok(target.into_os_string().into_encoded_bytes())
            }
        }

        fn write(&self, rel: &NodePath, offset: u64, data: &[u8]) -> io::Result<u32> {
            let file = self.open(rel, true, None)?;
            write_full(&file, data, offset)?;
            Ok(data.len() as u32)
        }

        fn create(&self, rel: &NodePath, mode: u32) -> io::Result<Attr> {
            file_attr(&self.open(rel, true, Some(mode))?)
        }

        fn create_open(&self, rel: &NodePath, mode: u32) -> io::Result<(Attr, NodePath)> {
            let parent = self.parent(rel)?;
            let file = open_child(&parent.file, &parent.name, true, Some(mode))?;
            let attr = file_attr(&file)?;
            let node = NodePath {
                rel: rel.rel.clone(),
                #[cfg(windows)]
                id: Some(windows_id(&file)?),
                #[cfg(windows)]
                parent_id: None,
                file: Some(std::sync::Arc::new(file)),
                parent: Some(parent.file),
                name: parent.name,
            };
            Ok((attr, node))
        }

        fn mkdir(&self, rel: &NodePath, mode: u32) -> io::Result<Attr> {
            let parent = self.parent(rel)?;
            #[cfg(unix)]
            rustix::fs::mkdirat(
                &parent.file,
                &parent.name,
                rustix::fs::Mode::from_raw_mode((mode & 0o777) as _),
            )
            .map_err(from_rustix)?;
            #[cfg(windows)]
            {
                let _ = mode;
                cap_primitives::fs::create_dir(
                    &parent.file,
                    &parent.name,
                    &cap_primitives::fs::DirOptions::new(),
                )?;
            }
            self.stat(rel)
        }

        fn unlink(&self, rel: &NodePath) -> io::Result<()> {
            let parent = self.parent(rel)?;
            cap_primitives::fs::remove_file(&parent.file, &parent.name)
        }

        fn rmdir(&self, rel: &NodePath) -> io::Result<()> {
            let parent = self.parent(rel)?;
            cap_primitives::fs::remove_dir(&parent.file, &parent.name)
        }

        fn rename(&self, from: &NodePath, to: &NodePath, flags: u32) -> io::Result<()> {
            let src = self.parent(from)?;
            let dst = self.parent(to)?;
            rename_with(&src, &dst, flags)
        }

        fn link(&self, from: &NodePath, to: &NodePath) -> io::Result<Attr> {
            let src = self.parent(from)?;
            let dst = self.parent(to)?;
            cap_primitives::fs::hard_link(&src.file, &src.name, &dst.file, &dst.name)?;
            self.stat(to)
        }

        fn mknod(&self, rel: &NodePath, mode: u32, rdev: u32) -> io::Result<Attr> {
            refuse_device_node(mode)?;
            let parent = self.parent(rel)?;
            make_node(&parent, mode, rdev)?;
            self.stat(rel)
        }

        fn fallocate(&self, rel: &NodePath, offset: u64, length: u64, mode: u32) -> io::Result<()> {
            allocate(&self.open(rel, true, None)?, offset, length, mode)
        }

        fn get_xattr(&self, rel: &NodePath, name: &str) -> io::Result<Vec<u8>> {
            check_xattr_name(name)?;
            read_xattr(&self.open(rel, false, None)?, name)
        }

        fn set_xattr(
            &self,
            rel: &NodePath,
            name: &str,
            value: &[u8],
            flags: u32,
        ) -> io::Result<()> {
            check_xattr_name(name)?;
            write_xattr(&self.open(rel, false, None)?, name, value, flags)
        }

        fn list_xattr(&self, rel: &NodePath) -> io::Result<Vec<u8>> {
            list_xattrs(&self.open(rel, false, None)?)
        }

        fn remove_xattr(&self, rel: &NodePath, name: &str) -> io::Result<()> {
            check_xattr_name(name)?;
            delete_xattr(&self.open(rel, false, None)?, name)
        }

        fn lseek(&self, rel: &NodePath, offset: u64, whence: u32) -> io::Result<u64> {
            seek_data_hole(&self.open(rel, false, None)?, offset, whence)
        }

        fn copy_file_range(
            &self,
            src: &NodePath,
            src_off: u64,
            dst: &NodePath,
            dst_off: u64,
            len: u64,
            flags: u32,
        ) -> io::Result<u32> {
            if flags != 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let src = self.open(src, false, None)?;
            let dst = self.open(dst, true, None)?;
            copy_range(&src, src_off, &dst, dst_off, len)
        }

        fn setattr(&self, rel: &NodePath, set: &SetAttr) -> io::Result<Attr> {
            #[cfg(not(windows))]
            let file = self.open(rel, set.size.is_some(), None)?;
            #[cfg(windows)]
            let file = {
                use windows_sys::Win32::Foundation::GENERIC_WRITE;
                use windows_sys::Win32::Storage::FileSystem::{
                    FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
                };
                let pinned = self.pin(rel)?;
                let access = FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | if set.size.is_some() { GENERIC_WRITE } else { 0 };
                reopen_with_access(pinned.file.as_ref().expect("pinned"), access)?
            };
            if let Some(size) = set.size {
                file.set_len(size)?;
            }
            if let Some(mode) = set.mode {
                set_mode(&file, mode)?;
            }
            if set.atime.is_some() || set.mtime.is_some() {
                file.set_times(file_times(set.atime, set.mtime))?;
            }
            file_attr(&file)
        }

        fn symlink(&self, rel: &NodePath, target: &[u8]) -> io::Result<Attr> {
            let parent = self.parent(rel)?;
            symlink_at(&parent, target)?;
            self.stat(rel)
        }
    }

    fn file_attr(file: &File) -> io::Result<Attr> {
        let attr = meta_to_attr(&file.metadata()?, Path::new(""));
        #[cfg(windows)]
        let attr = {
            let (volume, index, nlink) = host_file_id(file)?;
            let _ = volume;
            Attr {
                ino: index,
                nlink,
                ..attr
            }
        };
        Ok(attr)
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn host_file_id(file: &File) -> io::Result<(u32, u64, u32)> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `file` owns a live handle and `info` outlives the call.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            info.dwVolumeSerialNumber,
            u64::from(info.nFileIndexLow) | (u64::from(info.nFileIndexHigh) << 32),
            info.nNumberOfLinks,
        ))
    }

    #[cfg(windows)]
    fn windows_id(file: &File) -> io::Result<(u32, u64)> {
        let (volume, index, _) = host_file_id(file)?;
        Ok((volume, index))
    }

    /// Refuse a file or folder whose identity differs from the one seen
    /// earlier. Linux `ESTALE` tells the guest its cached entry is gone.
    #[cfg(windows)]
    fn check_id(expected: Option<(u32, u64)>, file: &File) -> io::Result<()> {
        if let Some(expected) = expected
            && windows_id(file)? != expected
        {
            return Err(super::linux_errno(116, io::ErrorKind::NotFound));
        }
        Ok(())
    }

    /// Apply mode bits where the platform supports it.
    fn set_mode(file: &File, mode: u32) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode & 0o777))
        }
        #[cfg(not(unix))]
        {
            // Map the owner-write bit to the read-only attribute.
            let mut perms = file.metadata()?.permissions();
            perms.set_readonly(mode & 0o200 == 0);
            file.set_permissions(perms)
        }
    }

    /// Create a symlink. Supported on Unix; elsewhere reported unsupported.
    fn symlink_at(parent: &Parent, target: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            rustix::fs::symlinkat(OsStr::from_bytes(target), &parent.file, &parent.name)
                .map_err(from_rustix)
        }
        #[cfg(not(unix))]
        {
            let _ = (parent, target);
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

    fn rename_with(from: &Parent, to: &Parent, flags: u32) -> io::Result<()> {
        let known = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
        if flags & !known != 0 || (flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if flags & RENAME_WHITEOUT != 0 {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        if flags == 0 {
            #[cfg(windows)]
            if let (Ok(a), Ok(b)) = (
                pin_child(&from.file, &from.name),
                pin_child(&to.file, &to.name),
            ) && same_object(&a, &b)?
            {
                return Ok(());
            }
            return cap_primitives::fs::rename(&from.file, &from.name, &to.file, &to.name);
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
            rustix::fs::renameat_with(&from.file, &from.name, &to.file, &to.name, host)
                .map_err(from_rustix)
        }
        #[cfg(windows)]
        {
            if flags & RENAME_EXCHANGE != 0 {
                return Err(io::Error::from(io::ErrorKind::Unsupported));
            }
            rename_noreplace(from, to)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (from, to);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn reopen_file(file: &File, write: bool) -> io::Result<File> {
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        reopen_with_access(file, if write { GENERIC_WRITE } else { GENERIC_READ })
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn reopen_with_access(file: &File, access: u32) -> io::Result<File> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
        };
        if file.metadata()?.file_type().is_symlink() {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        // SAFETY: the owned input handle is live. A successful result is a
        // new owned handle to the same object, without resolving a pathname.
        let handle = unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ReOpenFile returned a new owned, valid file handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn windows_path(parent: &Parent) -> io::Result<PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
        let mut buffer = vec![0u16; 512];
        loop {
            // SAFETY: the operation guard keeps this directory alive and
            // prevents its name from changing while the resulting path is used.
            let len = unsafe {
                GetFinalPathNameByHandleW(
                    parent.guard.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    0,
                )
            };
            if len == 0 {
                return Err(io::Error::last_os_error());
            }
            if (len as usize) < buffer.len() {
                buffer.truncate(len as usize);
                return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)).join(&parent.name));
            }
            buffer.resize(len as usize + 1, 0);
        }
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn rename_noreplace(from: &Parent, to: &Parent) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
        let from: Vec<u16> = windows_path(from)?
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let to: Vec<u16> = windows_path(to)?
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: both guarded paths are NUL-terminated and live for the call.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Device nodes can expose host devices, regardless of the share root.
    /// Reject them before resolving any host path or calling host mknod.
    fn refuse_device_node(mode: u32) -> io::Result<()> {
        if matches!(mode & super::S_IFMT, super::S_IFCHR | super::S_IFBLK) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(())
    }

    fn make_node(parent: &Parent, mode: u32, rdev: u32) -> io::Result<()> {
        refuse_device_node(mode)?;
        #[cfg(target_os = "linux")]
        {
            let kind = rustix::fs::FileType::from_raw_mode(mode);
            let perm = rustix::fs::Mode::from_raw_mode(mode);
            if !matches!(
                kind,
                rustix::fs::FileType::Fifo | rustix::fs::FileType::Socket
            ) {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            rustix::fs::mknodat(&parent.file, &parent.name, kind, perm, u64::from(rdev))
                .map_err(from_rustix)
        }
        #[cfg(target_os = "macos")]
        {
            make_node_macos(parent, mode, rdev)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (parent, mode, rdev);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn make_node_macos(parent: &Parent, mode: u32, rdev: u32) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        if mode & super::S_IFMT != super::S_IFIFO {
            let _ = rdev;
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        let bytes = parent.name.as_os_str().as_bytes();
        let c_path = std::ffi::CString::new(bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `c_path` is a NUL-terminated path that outlives the call.
        let rc = unsafe {
            libc::mkfifoat(
                std::os::fd::AsRawFd::as_raw_fd(parent.file.as_ref()),
                c_path.as_ptr(),
                mode as libc::mode_t,
            )
        };
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
                fp_offset: offset.cast_signed(),
                fp_length: length.cast_signed(),
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

    fn read_xattr(file: &File, name: &str) -> io::Result<Vec<u8>> {
        check_xattr_name(name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            grow_xattr(|buf| rustix::fs::fgetxattr(file, name, rustix::buffer::spare_capacity(buf)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (file, name);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn write_xattr(file: &File, name: &str, value: &[u8], flags: u32) -> io::Result<()> {
        check_xattr_name(name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let host = match flags {
                0 => rustix::fs::XattrFlags::empty(),
                1 => rustix::fs::XattrFlags::CREATE,
                2 => rustix::fs::XattrFlags::REPLACE,
                _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
            };
            rustix::fs::fsetxattr(file, name, value, host).map_err(from_rustix)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (file, name, value, flags);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn list_xattrs(file: &File) -> io::Result<Vec<u8>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let names = grow_xattr(|buf| {
                rustix::fs::flistxattr(file, rustix::buffer::spare_capacity(buf))
            })?;
            Ok(filter_xattr_names(&names))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = file;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn delete_xattr(file: &File, name: &str) -> io::Result<()> {
        check_xattr_name(name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            rustix::fs::fremovexattr(file, name).map_err(from_rustix)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (file, name);
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
            let rel = NodePath::new("missing");
            let path = dir.path().join(&*rel);
            let host = backend.root.clone();
            for name in DISALLOWED_XATTR_NAMES {
                for result in [
                    read_xattr(&host, name).map(|_| ()),
                    write_xattr(&host, name, b"value", 0),
                    delete_xattr(&host, name),
                    backend.get_xattr(&rel, name).map(|_| ()),
                    backend.set_xattr(&rel, name, b"value", 0),
                    backend.remove_xattr(&rel, name),
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
            let rel = NodePath::new("file");
            let path = dir.path().join(&*rel);
            fs::write(&path, b"data").unwrap();
            backend.set_xattr(&rel, "user.foo", b"first", 1).unwrap();
            assert_eq!(backend.get_xattr(&rel, "user.foo").unwrap(), b"first");
            backend.set_xattr(&rel, "user.foo", b"second", 2).unwrap();
            let host = File::open(&path).unwrap();
            assert_eq!(read_xattr(&host, "user.foo").unwrap(), b"second");
            assert_eq!(backend.list_xattr(&rel).unwrap(), b"user.foo\0");
            backend.remove_xattr(&rel, "user.foo").unwrap();
            assert!(backend.list_xattr(&rel).unwrap().is_empty());
            assert!(backend.get_xattr(&rel, "user.foo").is_err());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn host_acl_is_hidden_and_cannot_be_read_changed_or_removed() {
            let dir = tempfile::tempdir().unwrap();
            let backend = Passthrough::new(dir.path()).unwrap();
            let rel = NodePath::new("file");
            let path = dir.path().join(&*rel);
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
            backend.set_xattr(&rel, "user.foo", b"visible", 0).unwrap();
            let host = File::open(&path).unwrap();
            assert_eq!(list_xattrs(&host).unwrap(), b"user.foo\0");
            assert_eq!(backend.list_xattr(&rel).unwrap(), b"user.foo\0");
            for result in [
                backend.get_xattr(&rel, name).map(|_| ()),
                backend.set_xattr(&rel, name, b"replacement", 0),
                backend.remove_xattr(&rel, name),
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

    #[cfg(test)]
    mod handle_tests {
        use super::*;

        #[test]
        fn renamed_parent_keeps_creation_in_the_retained_directory() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("parent")).unwrap();
            let fs = Passthrough::new(dir.path()).unwrap();
            let (_, parent) = fs.lookup(&NodePath::new("parent")).unwrap();
            std::fs::rename(dir.path().join("parent"), dir.path().join("saved")).unwrap();
            std::fs::create_dir(dir.path().join("parent")).unwrap();
            let created = fs.create(&parent.join("child"), 0o600);
            #[cfg(not(windows))]
            {
                created.unwrap();
                assert!(dir.path().join("saved/child").is_file());
            }
            // Windows keeps no handle for a folder that was only looked up,
            // so it cannot follow the move. The identity check refuses the
            // new folder instead of creating the file there.
            #[cfg(windows)]
            {
                assert_eq!(created.unwrap_err().kind(), io::ErrorKind::NotFound);
                assert!(!dir.path().join("saved/child").exists());
            }
            assert!(!dir.path().join("parent/child").exists());
        }

        #[test]
        fn retained_file_permissions_can_be_updated() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("file"), b"data").unwrap();
            let fs = Passthrough::new(dir.path()).unwrap();
            let (_, file) = fs.lookup(&NodePath::new("file")).unwrap();
            fs.setattr(
                &file,
                &SetAttr {
                    mode: Some(0o444),
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(
                std::fs::metadata(dir.path().join("file"))
                    .unwrap()
                    .permissions()
                    .readonly()
            );
            fs.setattr(
                &file,
                &SetAttr {
                    mode: Some(0o644),
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(
                !std::fs::metadata(dir.path().join("file"))
                    .unwrap()
                    .permissions()
                    .readonly()
            );
        }

        #[test]
        fn checked_reopen_refuses_a_replaced_leaf() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("file"), b"original").unwrap();
            let fs = Passthrough::new(dir.path()).unwrap();
            let (_, file) = fs.lookup(&NodePath::new("file")).unwrap();
            std::fs::rename(dir.path().join("file"), dir.path().join("saved")).unwrap();
            std::fs::write(dir.path().join("file"), b"replacement").unwrap();
            let error = fs.open_checked(&file, true, None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            assert_eq!(
                std::fs::read(dir.path().join("file")).unwrap(),
                b"replacement"
            );
            assert_eq!(
                std::fs::read(dir.path().join("saved")).unwrap(),
                b"original"
            );
        }

        #[cfg(unix)]
        #[test]
        fn unavailable_stronger_open_uses_a_nofollow_fallback() {
            use rustix::fs::{Mode, OFlags};
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("file"), b"data").unwrap();
            std::os::unix::fs::symlink("file", dir.path().join("link")).unwrap();
            let parent = File::open(dir.path()).unwrap();
            let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let open = |name: &str| {
                open_with_fallback(&parent, Path::new(name), flags, Mode::empty(), || {
                    Err(rustix::io::Errno::NOSYS)
                })
            };
            assert!(open("file").is_ok());
            assert!(open("link").is_err());
            assert!(open("file/child").is_err());
            assert!(open("../file").is_err());
            let error =
                open_with_fallback(&parent, Path::new("file"), flags, Mode::empty(), || {
                    Err(rustix::io::Errno::PERM)
                })
                .unwrap_err();
            assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::PERM.raw_os_error())
            );
        }

        #[cfg(unix)]
        #[test]
        fn intermediate_symlinks_are_refused() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("parent")).unwrap();
            std::os::unix::fs::symlink("parent", dir.path().join("alias")).unwrap();
            let fs = Passthrough::new(dir.path()).unwrap();
            assert!(fs.create(&NodePath::new("alias/child"), 0o600).is_err());
            let (_, alias) = fs.lookup(&NodePath::new("alias")).unwrap();
            assert!(fs.create(&alias.join("child"), 0o600).is_err());
            assert!(!dir.path().join("parent/child").exists());
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
    fn stat(&self, rel: &NodePath) -> io::Result<Attr> {
        let key = Self::key(rel)?;
        self.attr_for(&key)
    }

    fn readdir(&self, rel: &NodePath) -> io::Result<Vec<DirEntry>> {
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

    fn read(&self, rel: &NodePath, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let key = Self::key(rel)?;
        let data = self
            .files
            .get(&key)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(size as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn readlink(&self, _rel: &NodePath) -> io::Result<Vec<u8>> {
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
        let root = fs.stat(&NodePath::new("")).unwrap();
        assert!(root.is_dir());
        let f = fs.stat(&NodePath::new("hello.txt")).unwrap();
        assert_eq!(f.size, 8);
        assert_eq!(f.dirent_type(), DT_REG);
        assert_eq!(
            fs.read(&NodePath::new("hello.txt"), 0, 64).unwrap(),
            b"hi there"
        );
        assert_eq!(
            fs.read(&NodePath::new("hello.txt"), 3, 64).unwrap(),
            b"there"
        );
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

        let root = pt.stat(&NodePath::new("")).unwrap();
        assert!(root.is_dir());

        let f = pt.stat(&NodePath::new("f.txt")).unwrap();
        assert_eq!(f.size, 5);
        assert_eq!(f.dirent_type(), DT_REG);
        assert_eq!(f.mode & S_IFMT, S_IFREG);
        assert_eq!(pt.read(&NodePath::new("f.txt"), 0, 64).unwrap(), b"hello");
        assert_eq!(pt.read(&NodePath::new("f.txt"), 2, 64).unwrap(), b"llo");

        let names: Vec<String> = pt
            .readdir(&NodePath::new(""))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"f.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));

        // Lexical escape is rejected before touching the filesystem.
        assert!(pt.stat(&NodePath::new("../escape")).is_err());
        // A missing child is NotFound (a LOOKUP miss), not a containment error.
        assert_eq!(
            pt.stat(&NodePath::new("nope")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn passthrough_write_path_cross_platform() {
        let dir = tempfile::tempdir().unwrap();
        let pt = Passthrough::new(dir.path()).unwrap();

        // create + write
        let attr = pt.create(&NodePath::new("new.txt"), 0o644).unwrap();
        assert_eq!(attr.mode & S_IFMT, S_IFREG);
        assert_eq!(
            pt.write(&NodePath::new("new.txt"), 0, b"hello world")
                .unwrap(),
            11
        );
        assert_eq!(
            pt.read(&NodePath::new("new.txt"), 0, 64).unwrap(),
            b"hello world"
        );
        // positional write (overwrite "world" -> "rust!")
        assert_eq!(pt.write(&NodePath::new("new.txt"), 6, b"rust!").unwrap(), 5);
        assert_eq!(
            pt.read(&NodePath::new("new.txt"), 0, 64).unwrap(),
            b"hello rust!"
        );
        assert_eq!(
            std::fs::read(dir.path().join("new.txt")).unwrap(),
            b"hello rust!"
        );

        // mkdir + nested create
        pt.mkdir(&NodePath::new("d"), 0o755).unwrap();
        assert!(pt.stat(&NodePath::new("d")).unwrap().is_dir());
        pt.create(&NodePath::new("d/inner.txt"), 0o644).unwrap();
        pt.write(&NodePath::new("d/inner.txt"), 0, b"x").unwrap();
        assert!(dir.path().join("d/inner.txt").exists());

        // setattr: truncate
        let a = pt
            .setattr(
                &NodePath::new("new.txt"),
                &SetAttr {
                    size: Some(5),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(a.size, 5);
        assert_eq!(pt.read(&NodePath::new("new.txt"), 0, 64).unwrap(), b"hello");

        // rename
        pt.rename(&NodePath::new("new.txt"), &NodePath::new("renamed.txt"), 0)
            .unwrap();
        assert!(!dir.path().join("new.txt").exists());
        assert_eq!(
            pt.read(&NodePath::new("renamed.txt"), 0, 64).unwrap(),
            b"hello"
        );

        // unlink + rmdir
        pt.unlink(&NodePath::new("renamed.txt")).unwrap();
        assert!(!dir.path().join("renamed.txt").exists());
        pt.unlink(&NodePath::new("d/inner.txt")).unwrap();
        pt.rmdir(&NodePath::new("d")).unwrap();
        assert!(!dir.path().join("d").exists());

        // write escaping the share is rejected before touching the fs
        assert!(pt.write(&NodePath::new("../escape"), 0, b"x").is_err());
        assert!(pt.create(&NodePath::new("../evil.txt"), 0o644).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn passthrough_setattr_mode_and_symlink_unix() {
        let dir = tempfile::tempdir().unwrap();
        let pt = Passthrough::new(dir.path()).unwrap();
        pt.create(&NodePath::new("f"), 0o644).unwrap();
        let a = pt
            .setattr(
                &NodePath::new("f"),
                &SetAttr {
                    mode: Some(0o600),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(a.mode & 0o777, 0o600);

        let link = pt.symlink(&NodePath::new("l"), b"f").unwrap();
        assert_eq!(link.mode & S_IFMT, S_IFLNK);
        assert_eq!(pt.readlink(&NodePath::new("l")).unwrap(), b"f");
    }

    #[test]
    fn mapfs_readdir_lists_children() {
        let fs = MapFs::new()
            .with_file("a.txt", "a")
            .with_file("sub/b.txt", "b");
        let mut names: Vec<String> = fs
            .readdir(&NodePath::new(""))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "sub".to_string()]);
        let sub = fs.readdir(&NodePath::new("sub")).unwrap();
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].name, "b.txt");
    }

    mod node_tests {
        use super::*;
        use std::fs;

        #[test]
        fn device_nodes_are_rejected_for_every_device_number() {
            let dir = tempfile::tempdir().unwrap();
            let backend = Passthrough::new(dir.path()).unwrap();
            for kind in [S_IFCHR, S_IFBLK] {
                for rdev in [0, 1, 0x103, 0xdead_beef, u32::MAX] {
                    let rel = PathBuf::from(format!("node-{kind}-{rdev}"));
                    let err = backend
                        .mknod(&NodePath::new(&rel), kind | 0o600, rdev)
                        .unwrap_err();
                    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
                    assert_eq!(err.raw_os_error(), None, "policy must reject before mknod");
                    assert_eq!(
                        fs::symlink_metadata(dir.path().join(&rel))
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::NotFound
                    );

                    // Even an unusable host path must be rejected by policy.
                    let missing = NodePath::new(Path::new("missing-parent").join(&rel));
                    let err = backend.mknod(&missing, kind | 0o600, rdev).unwrap_err();
                    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
                    assert_eq!(err.raw_os_error(), None, "policy must reject before mknod");
                }
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        #[test]
        fn fifo_creation_still_succeeds() {
            use crate::backend::{S_IFIFO, S_IFMT};
            use std::os::unix::fs::FileTypeExt;
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let dir = tempfile::tempdir().unwrap();
                let backend = Passthrough::new(dir.path()).unwrap();
                let attr = backend
                    .mknod(&NodePath::new("fifo"), S_IFIFO | 0o600, 0)
                    .unwrap();
                assert_eq!(attr.mode & S_IFMT, S_IFIFO);
                assert!(
                    fs::symlink_metadata(dir.path().join("fifo"))
                        .unwrap()
                        .file_type()
                        .is_fifo()
                );
                let entries = backend.readdir(&NodePath::new("")).unwrap();
                assert!(entries.iter().any(|entry| entry.name == "fifo"));
                tx.send(()).unwrap();
            });
            // Without O_NONBLOCK a FIFO lookup waits forever for a writer.
            // Fail after ten seconds instead of hanging the whole test run.
            match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(()) => worker.join().unwrap(),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    panic!("FIFO lookup blocked; is O_NONBLOCK missing?")
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    std::panic::resume_unwind(worker.join().unwrap_err())
                }
            }
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn socket_creation_still_succeeds() {
            use crate::backend::{S_IFMT, S_IFSOCK};
            use std::os::unix::fs::FileTypeExt;
            let dir = tempfile::tempdir().unwrap();
            let backend = Passthrough::new(dir.path()).unwrap();
            let attr = backend
                .mknod(&NodePath::new("socket"), S_IFSOCK | 0o600, 0)
                .unwrap();
            assert_eq!(attr.mode & S_IFMT, S_IFSOCK);
            assert!(
                fs::symlink_metadata(dir.path().join("socket"))
                    .unwrap()
                    .file_type()
                    .is_socket()
            );
        }
    }
}
