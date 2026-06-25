// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Filesystem backing behind a virtio-fs device.
//!
//! The FUSE protocol logic in [`crate::fuse`] is backend-agnostic: it manages
//! the nodeid/handle tables and the wire format, and delegates the actual
//! filesystem reads to a [`FsBackend`]. [`Passthrough`] (Unix only) serves a
//! host directory read-only; [`MapFs`] is an in-memory tree used by the unit
//! tests so the protocol can be exercised on any platform without touching the
//! real filesystem.
//!
//! Backends are **read-only by construction** — there is no write method, so a
//! confused-deputy write can never reach the host. The device rejects every
//! mutating FUSE opcode with `EROFS` before a backend is ever consulted.

use std::io;
use std::path::{Component, Path, PathBuf};

/// `S_IFMT` mask and the type bits we care about (mirrors `libc`/`stat.h`).
pub(crate) const S_IFMT: u32 = 0o170_000;
pub(crate) const S_IFDIR: u32 = 0o040_000;
pub(crate) const S_IFREG: u32 = 0o100_000;
pub(crate) const S_IFLNK: u32 = 0o120_000;

/// `getdents`/`fuse_dirent` `d_type` values.
pub(crate) const DT_UNKNOWN: u32 = 0;
pub(crate) const DT_DIR: u32 = 4;
pub(crate) const DT_REG: u32 = 8;
pub(crate) const DT_LNK: u32 = 10;

/// Stat-like attributes for one filesystem node, in the subset virtio-fs needs.
#[derive(Debug, Clone, Copy)]
pub struct Attr {
    /// Inode number reported to the guest (cosmetic; the guest keys on nodeid).
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
            S_IFDIR => DT_DIR,
            S_IFREG => DT_REG,
            S_IFLNK => DT_LNK,
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
/// `None` is left untouched. `uid`/`gid` are accepted but not applied (there is
/// no portable `chown` in `std`); everything else is best-effort cross-platform.
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
    // 30 = EROFS; stored verbatim and surfaced via `raw_os_error` on every
    // platform, so the FUSE layer maps it back to EROFS.
    io::Error::from_raw_os_error(30)
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

    /// Rename `from` to `to` (both relative to the share root).
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let _ = (from, to);
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
// Passthrough — serves a host directory read-only. Cross-platform: the FUSE
// attributes virtio-fs reports to the (always-Linux) guest are read from real
// Unix metadata on Unix hosts and synthesized from portable `std::fs` metadata
// on others (e.g. a Windows/WHP host sharing a directory into its Linux guest).
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

    /// Read-only passthrough of a host directory subtree.
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

    /// Cross-platform positional read (`pread`/`seek_read`), mirroring
    /// `dillo-virtio-blk`'s helper.
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

    /// Cross-platform positional write (`pwrite`/`seek_write`).
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
            Attr {
                // No host inode number is available; synthesize a stable,
                // nonzero cosmetic value from the path (the guest keys on
                // nodeid, not this).
                ino: synth_ino(full),
                size: meta.len(),
                blocks: meta.len().div_ceil(512),
                mode: type_bits | perm,
                nlink: if ft.is_dir() { 2 } else { 1 },
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
            let n = read_at(&file, &mut buf, offset)?;
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
            let n = write_at(&file, data, offset)?;
            Ok(n as u32)
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

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            let from = self.resolve(from)?;
            let to = self.resolve(to)?;
            fs::rename(&from, &to)
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
            // 95 = EOPNOTSUPP; no portable symlink creation off Unix.
            Err(io::Error::from_raw_os_error(95))
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
        pt.rename(Path::new("new.txt"), Path::new("renamed.txt"))
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
