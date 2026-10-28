// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! FUSE protocol: wire structs, the nodeid/handle tables, and opcode dispatch.
//!
//! virtio-fs carries the ordinary Linux FUSE protocol over virtqueues instead
//! of `/dev/fuse`. Each request is a descriptor chain whose device-readable
//! descriptors hold `fuse_in_header` + op-specific input, and whose
//! device-writable descriptors receive `fuse_out_header` + op-specific output.
//! [`dispatch`] consumes a flattened input buffer and returns the full reply
//! bytes (`None` for the few replyless ops: FORGET / BATCH_FORGET / INTERRUPT).
//!
//! Read-write operations are delegated to the backend. Read-only shares reject
//! mutations with `EROFS`. An operation the host OS cannot perform returns
//! `EOPNOTSUPP` (or the host errno), never `ENOSYS`: Linux caches `ENOSYS` per
//! opcode and then stops asking. `ENOSYS` remains only for DAX mapping, which
//! this server does not advertise. See tests/VIRTIOFS.md for guest coverage.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::backend::{Attr, FsBackend, LinuxErrno, SetAttr};

// --- protocol version we present ------------------------------------------
const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

// --- opcodes (subset; see include/uapi/linux/fuse.h) ----------------------
const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_SETATTR: u32 = 4;
const FUSE_READLINK: u32 = 5;
const FUSE_SYMLINK: u32 = 6;
const FUSE_MKNOD: u32 = 8;
const FUSE_MKDIR: u32 = 9;
const FUSE_UNLINK: u32 = 10;
const FUSE_RMDIR: u32 = 11;
const FUSE_RENAME: u32 = 12;
const FUSE_LINK: u32 = 13;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_STATFS: u32 = 17;
const FUSE_RELEASE: u32 = 18;
const FUSE_FSYNC: u32 = 20;
const FUSE_SETXATTR: u32 = 21;
const FUSE_GETXATTR: u32 = 22;
const FUSE_LISTXATTR: u32 = 23;
const FUSE_REMOVEXATTR: u32 = 24;
const FUSE_FLUSH: u32 = 25;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_FSYNCDIR: u32 = 30;
const FUSE_CREATE: u32 = 35;
const FUSE_INTERRUPT: u32 = 36;
const FUSE_DESTROY: u32 = 38;
const FUSE_BATCH_FORGET: u32 = 42;
const FUSE_FALLOCATE: u32 = 43;
const FUSE_RENAME2: u32 = 45;
const FUSE_LSEEK: u32 = 46;
const FUSE_COPY_FILE_RANGE: u32 = 47;
const FUSE_SETUPMAPPING: u32 = 48;
const FUSE_REMOVEMAPPING: u32 = 49;
const FUSE_SYNCFS: u32 = 50;
const FUSE_ACCESS: u32 = 34;

// --- errno values returned to the guest (negated on the wire) -------------
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EINVAL: i32 = 22;
const EROFS: i32 = 30;
const ERANGE: i32 = 34;
const ENOSYS: i32 = 38;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const ENOTEMPTY: i32 = 39;
const EOPNOTSUPP: i32 = 95;

const FUSE_IN_HEADER_LEN: usize = 40;
const FUSE_OUT_HEADER_LEN: usize = 16;
const FUSE_NAME_OFFSET: usize = 24; // offsetof(fuse_dirent, name)
const FUSE_ROOT_ID: u64 = 1;

/// `open(2)` access-mode mask; a nonzero masked value means write intent.
const O_ACCMODE: u32 = 0o3;
/// `open(2)` O_TRUNC.
const O_TRUNC: u32 = 0o1000;

// --- fuse_setattr_in `valid` bits -----------------------------------------
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;

/// Cap a single READ/READDIR payload so a hostile descriptor length can't make
/// us allocate without bound. Larger than any realistic FUSE max_read.
const MAX_PAYLOAD: u32 = 1 << 20;

// ---------------------------------------------------------------------------
// Little-endian readers + a growable reply writer.
// ---------------------------------------------------------------------------

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().expect("4 bytes")))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
}

#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn with_header() -> Self {
        // Reserve the out_header; filled in by `finish`.
        Self {
            buf: vec![0u8; FUSE_OUT_HEADER_LEN],
        }
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    fn pad(&mut self, n: usize) {
        let new_len = self.buf.len() + n;
        self.buf.resize(new_len, 0);
    }
    /// Stamp the out_header (len, error=0, unique) and return the buffer.
    fn finish(mut self, unique: u64) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_le_bytes());
        self.buf[4..8].copy_from_slice(&0i32.to_le_bytes());
        self.buf[8..16].copy_from_slice(&unique.to_le_bytes());
        self.buf
    }
}

/// A bare `fuse_out_header` carrying an error (negated errno) and no payload.
fn error_reply(unique: u64, errno: i32) -> Vec<u8> {
    let mut buf = vec![0u8; FUSE_OUT_HEADER_LEN];
    buf[0..4].copy_from_slice(&(FUSE_OUT_HEADER_LEN as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&(-errno).to_le_bytes());
    buf[8..16].copy_from_slice(&unique.to_le_bytes());
    buf
}

fn errno_of(e: &io::Error) -> i32 {
    if let Some(linux) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<LinuxErrno>())
    {
        return linux.linux;
    }
    #[cfg(target_os = "linux")]
    if let Some(raw) = e.raw_os_error() {
        return raw;
    }
    // Only Linux raw errnos belong on the FUSE wire. Map other host OS
    // errors (including BSD/macOS errnos) and synthesized errors by kind.
    match e.kind() {
        io::ErrorKind::NotFound => ENOENT,
        io::ErrorKind::PermissionDenied => EACCES,
        io::ErrorKind::AlreadyExists => EEXIST,
        io::ErrorKind::InvalidInput => EINVAL,
        io::ErrorKind::NotADirectory => ENOTDIR,
        io::ErrorKind::IsADirectory => EISDIR,
        io::ErrorKind::DirectoryNotEmpty => ENOTEMPTY,
        io::ErrorKind::ReadOnlyFilesystem => EROFS,
        io::ErrorKind::Unsupported => EOPNOTSUPP,
        _ => EIO,
    }
}

fn write_attr(w: &mut Writer, a: &Attr) {
    w.u64(a.ino);
    w.u64(a.size);
    w.u64(a.blocks);
    w.u64(0); // atime
    w.u64(a.mtime);
    w.u64(0); // ctime
    w.u32(0); // atimensec
    w.u32(a.mtime_nsec);
    w.u32(0); // ctimensec
    w.u32(a.mode);
    w.u32(a.nlink);
    w.u32(a.uid);
    w.u32(a.gid);
    w.u32(a.rdev);
    w.u32(4096); // blksize
    w.u32(0); // flags
}

/// Write a `fuse_entry_out` (nodeid + 1s timeouts + attr).
fn write_entry_out(w: &mut Writer, nodeid: u64, a: &Attr) {
    w.u64(nodeid); // nodeid
    w.u64(0); // generation
    w.u64(1); // entry_valid (seconds)
    w.u64(1); // attr_valid (seconds)
    w.u32(0); // entry_valid_nsec
    w.u32(0); // attr_valid_nsec
    write_attr(w, a);
}

/// Write a `fuse_attr_out` (1s timeout + attr).
fn write_attr_out(w: &mut Writer, a: &Attr) {
    w.u64(1); // attr_valid (seconds)
    w.u32(0); // attr_valid_nsec
    w.u32(0); // dummy
    write_attr(w, a);
}

// ---------------------------------------------------------------------------
// Server state: nodeid ↔ relative-path tables and open handles.
// ---------------------------------------------------------------------------

struct Node {
    /// Primary path. Hard links keep extra names in [`Node::aliases`].
    rel: PathBuf,
    /// Other directory entries that share this nodeid. Guest `st_ino` follows
    /// the nodeid, so every name of a hard link must resolve here.
    aliases: Vec<PathBuf>,
    lookups: u64,
    // Preserve the first reported inode even if backend identity is path-based.
    ino: u64,
}

enum Handle {
    File(PathBuf),
    Dir(Vec<DirentRec>),
}

struct DirentRec {
    ino: u64,
    name: String,
    dt: u32,
}

/// All mutable virtio-fs server state, guarded by one mutex in the device.
pub(crate) struct FsState {
    nodes: HashMap<u64, Node>,
    by_path: HashMap<PathBuf, u64>,
    next_node: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    /// When true, every mutating opcode is rejected with EROFS.
    readonly: bool,
}

impl FsState {
    pub(crate) fn new(readonly: bool) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            FUSE_ROOT_ID,
            Node {
                rel: PathBuf::new(),
                aliases: Vec::new(),
                lookups: 1,
                ino: FUSE_ROOT_ID,
            },
        );
        let mut by_path = HashMap::new();
        by_path.insert(PathBuf::new(), FUSE_ROOT_ID);
        Self {
            nodes,
            by_path,
            next_node: 2,
            handles: HashMap::new(),
            next_fh: 1,
            readonly,
        }
    }

    fn rel_of(&self, nodeid: u64) -> Option<PathBuf> {
        self.nodes.get(&nodeid).map(|n| n.rel.clone())
    }

    /// Return the nodeid for `rel`, allocating one on first lookup. Each call
    /// bumps the kernel-visible lookup count (balanced by FORGET).
    fn intern(&mut self, rel: PathBuf, ino: u64) -> u64 {
        if let Some(&id) = self.by_path.get(&rel) {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.lookups += 1;
            }
            return id;
        }
        let id = self.next_node;
        self.next_node += 1;
        self.by_path.insert(rel.clone(), id);
        self.nodes.insert(
            id,
            Node {
                rel,
                aliases: Vec::new(),
                lookups: 1,
                ino,
            },
        );
        id
    }

    /// Record another name for an existing node and count it as a lookup.
    /// `FUSE_LINK` replies with the original nodeid; it must not allocate one.
    fn attach_alias(&mut self, nodeid: u64, rel: PathBuf) {
        self.by_path.insert(rel.clone(), nodeid);
        if let Some(node) = self.nodes.get_mut(&nodeid) {
            if node.rel != rel && !node.aliases.iter().any(|alias| alias == &rel) {
                node.aliases.push(rel);
            }
            node.lookups = node.lookups.saturating_add(1);
        }
    }

    /// Keep stat/entry replies consistent with the identity first observed by
    /// Linux. Some backends synthesize inode numbers from paths, which change
    /// across rename even though the cached FUSE node remains the same.
    fn stable_attr(&self, nodeid: u64, mut attr: Attr) -> Attr {
        if let Some(node) = self.nodes.get(&nodeid) {
            attr.ino = node.ino;
        }
        attr
    }

    fn forget(&mut self, nodeid: u64, nlookup: u64) {
        if nodeid == FUSE_ROOT_ID {
            return;
        }
        if let Some(node) = self.nodes.get_mut(&nodeid) {
            node.lookups = node.lookups.saturating_sub(nlookup);
            if node.lookups == 0 {
                let rel = node.rel.clone();
                let aliases = node.aliases.clone();
                self.nodes.remove(&nodeid);
                self.by_path.remove(&rel);
                for alias in aliases {
                    self.by_path.remove(&alias);
                }
            }
        }
    }

    fn add_handle(&mut self, h: Handle) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, h);
        fh
    }

    /// Drop one directory entry. A hard link keeps the nodeid alive under its
    /// other names and file handles follow the surviving path. The last name
    /// drops the node, matching the previous full-node invalidate: an open of
    /// the overwritten nodeid returns `ENOENT`.
    fn detach_path(&mut self, rel: &Path) {
        let Some(id) = self.by_path.remove(rel) else {
            return;
        };
        let promoted = {
            let Some(node) = self.nodes.get_mut(&id) else {
                return;
            };
            if node.rel == rel {
                node.aliases.pop()
            } else {
                node.aliases.retain(|alias| alias != rel);
                return;
            }
        };
        if let Some(alias) = promoted {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.rel.clone_from(&alias);
            }
            for handle in self.handles.values_mut() {
                if let Handle::File(path) = handle
                    && path == rel
                {
                    path.clone_from(&alias);
                }
            }
        } else {
            self.nodes.remove(&id);
        }
    }

    /// Follow a successful rename without changing guest-visible nodeids or
    /// lookup counts. Cached children of a moved directory follow it too.
    /// Renaming a file onto its own hard link is a POSIX no-op: both names stay.
    fn remap(&mut self, from: &Path, to: &Path) {
        if from == to
            || (self.by_path.get(from) == self.by_path.get(to) && self.by_path.contains_key(from))
        {
            return;
        }
        // Only the overwritten destination loses its identity. A later FORGET
        // for that nodeid must not evict the source now mapped to this path.
        self.detach_path(to);
        self.retarget(from, to);
    }

    /// Swap two paths after `RENAME_EXCHANGE`. Nested paths are rejected by
    /// the backend before this runs; applying both rewrites from the original
    /// paths avoids swapping a path twice.
    fn exchange(&mut self, a: &Path, b: &Path) {
        if a == b {
            return;
        }
        let rewrite = |path: &Path| -> Option<PathBuf> {
            if let Ok(suffix) = path.strip_prefix(a) {
                Some(b.join(suffix))
            } else if let Ok(suffix) = path.strip_prefix(b) {
                Some(a.join(suffix))
            } else {
                None
            }
        };
        self.rewrite_paths(&rewrite);
    }

    fn retarget(&mut self, from: &Path, to: &Path) {
        let rewrite = |path: &Path| -> Option<PathBuf> {
            path.strip_prefix(from).ok().map(|suffix| to.join(suffix))
        };
        self.rewrite_paths(&rewrite);
    }

    fn rewrite_paths(&mut self, rewrite: &dyn Fn(&Path) -> Option<PathBuf>) {
        let mut moves = Vec::new();
        for (&id, node) in &self.nodes {
            if let Some(new) = rewrite(&node.rel) {
                moves.push((id, node.rel.clone(), new, false));
            }
            for alias in &node.aliases {
                if let Some(new) = rewrite(alias) {
                    moves.push((id, alias.clone(), new, true));
                }
            }
        }
        for (_, old, _, _) in &moves {
            self.by_path.remove(old);
        }
        for (id, _, new, _) in &moves {
            self.by_path.insert(new.clone(), *id);
        }
        for (id, old, new, is_alias) in moves {
            if let Some(node) = self.nodes.get_mut(&id) {
                if is_alias {
                    if let Some(slot) = node.aliases.iter_mut().find(|alias| *alias == &old) {
                        *slot = new;
                    }
                } else {
                    node.rel = new;
                }
            }
        }
        for handle in self.handles.values_mut() {
            if let Handle::File(rel) = handle
                && let Some(new) = rewrite(rel)
            {
                *rel = new;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

/// Parse one FUSE request from `input` and produce its reply bytes. Returns
/// `None` for replyless opcodes. `input` is the concatenation of the request's
/// device-readable descriptors (header + op input).
pub(crate) fn dispatch(
    state: &mut FsState,
    backend: &dyn FsBackend,
    input: &[u8],
) -> Option<Vec<u8>> {
    if input.len() < FUSE_IN_HEADER_LEN {
        // Can't even read a header → nothing addressable to reply to.
        return None;
    }
    let opcode = rd_u32(input, 4)?;
    let unique = rd_u64(input, 8)?;
    let nodeid = rd_u64(input, 16)?;
    let args = &input[FUSE_IN_HEADER_LEN..];
    log::trace!("FUSE opcode={opcode} nodeid={nodeid} unique={unique}");

    let reply = match opcode {
        FUSE_INIT => Some(handle_init(unique, args)),
        FUSE_GETATTR => Some(handle_getattr(state, backend, unique, nodeid)),
        FUSE_LOOKUP => Some(handle_lookup(state, backend, unique, nodeid, args)),
        FUSE_FORGET => {
            let nlookup = rd_u64(args, 0).unwrap_or(0);
            state.forget(nodeid, nlookup);
            None
        }
        FUSE_BATCH_FORGET => {
            handle_batch_forget(state, args);
            None
        }
        FUSE_OPEN => Some(handle_open(state, backend, unique, nodeid, args)),
        FUSE_READ => Some(handle_read(state, backend, unique, args)),
        FUSE_RELEASE | FUSE_RELEASEDIR => {
            let fh = rd_u64(args, 0).unwrap_or(0);
            state.handles.remove(&fh);
            Some(Writer::with_header().finish(unique))
        }
        FUSE_OPENDIR => Some(handle_opendir(state, backend, unique, nodeid)),
        FUSE_READDIR => Some(handle_readdir(state, unique, args)),
        FUSE_READLINK => Some(handle_readlink(state, backend, unique, nodeid)),
        FUSE_STATFS => Some(handle_statfs(unique)),
        // Nothing to do beyond acknowledging.
        FUSE_FLUSH | FUSE_FSYNC | FUSE_FSYNCDIR | FUSE_SYNCFS | FUSE_ACCESS | FUSE_DESTROY => {
            Some(Writer::with_header().finish(unique))
        }
        FUSE_INTERRUPT => None, // best-effort: we never leave a request pending
        FUSE_GETXATTR => Some(handle_getxattr(state, backend, unique, nodeid, args)),
        FUSE_LISTXATTR => Some(handle_listxattr(state, backend, unique, nodeid, args)),
        FUSE_LSEEK => Some(handle_lseek(state, backend, unique, args)),

        // --- write path: EROFS up front when the share is read-only ---------
        _ if state.readonly && is_write_opcode(opcode) => Some(error_reply(unique, EROFS)),
        FUSE_WRITE => Some(handle_write(state, backend, unique, args)),
        FUSE_CREATE => Some(handle_create(state, backend, unique, nodeid, args)),
        FUSE_SETATTR => Some(handle_setattr(state, backend, unique, nodeid, args)),
        FUSE_MKDIR => Some(handle_mkdir(state, backend, unique, nodeid, args)),
        FUSE_MKNOD => Some(handle_mknod(state, backend, unique, nodeid, args)),
        FUSE_UNLINK => Some(handle_unlink(state, backend, unique, nodeid, args)),
        FUSE_RMDIR => Some(handle_rmdir(state, backend, unique, nodeid, args)),
        FUSE_RENAME => Some(handle_rename(state, backend, unique, nodeid, args, 0)),
        FUSE_RENAME2 => Some(handle_rename(state, backend, unique, nodeid, args, 8)),
        FUSE_SYMLINK => Some(handle_symlink(state, backend, unique, nodeid, args)),
        FUSE_LINK => Some(handle_link(state, backend, unique, nodeid, args)),
        FUSE_SETXATTR => Some(handle_setxattr(state, backend, unique, nodeid, args)),
        FUSE_REMOVEXATTR => Some(handle_removexattr(state, backend, unique, nodeid, args)),
        FUSE_FALLOCATE => Some(handle_fallocate(state, backend, unique, args)),
        FUSE_COPY_FILE_RANGE => Some(handle_copy_file_range(state, backend, unique, args)),

        // DAX window was not negotiated in INIT, so these stay unsupported.
        // EROFS on a read-only share, otherwise ENOSYS.
        FUSE_SETUPMAPPING | FUSE_REMOVEMAPPING => Some(error_reply(
            unique,
            if state.readonly { EROFS } else { ENOSYS },
        )),
        _ => Some(error_reply(unique, ENOSYS)),
    };
    if let Some(raw) = reply.as_ref().and_then(|buf| buf.get(4..8)) {
        let err = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        log::trace!("FUSE result opcode={opcode} error={err}");
    }
    reply
}

/// Write opcodes this server implements (used for the read-only gate).
fn is_write_opcode(op: u32) -> bool {
    matches!(
        op,
        FUSE_WRITE
            | FUSE_CREATE
            | FUSE_SETATTR
            | FUSE_MKDIR
            | FUSE_MKNOD
            | FUSE_UNLINK
            | FUSE_RMDIR
            | FUSE_RENAME
            | FUSE_RENAME2
            | FUSE_SYMLINK
            | FUSE_LINK
            | FUSE_SETXATTR
            | FUSE_REMOVEXATTR
            | FUSE_FALLOCATE
            | FUSE_COPY_FILE_RANGE
            | FUSE_SETUPMAPPING
            | FUSE_REMOVEMAPPING
    )
}

fn handle_init(unique: u64, args: &[u8]) -> Vec<u8> {
    // fuse_init_in: major, minor, max_readahead, flags (we only need minor).
    let their_minor = rd_u32(args, 4).unwrap_or(FUSE_KERNEL_MINOR_VERSION);
    let minor = their_minor.min(FUSE_KERNEL_MINOR_VERSION);
    let max_readahead = rd_u32(args, 8).unwrap_or(0);

    let mut w = Writer::with_header();
    w.u32(FUSE_KERNEL_VERSION); // major
    w.u32(minor); // minor
    w.u32(max_readahead); // max_readahead (echo)
    w.u32(0); // flags (negotiate nothing extra)
    w.bytes(&0u16.to_le_bytes()); // max_background
    w.bytes(&0u16.to_le_bytes()); // congestion_threshold
    w.u32(MAX_PAYLOAD); // max_write
    w.u32(1); // time_gran (1 ns)
    w.bytes(&0u16.to_le_bytes()); // max_pages
    w.bytes(&0u16.to_le_bytes()); // map_alignment
    w.u32(0); // flags2
    w.pad(7 * 4); // unused[7]
    w.finish(unique)
}

fn handle_getattr(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
) -> Vec<u8> {
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    match backend.stat(&rel) {
        Ok(attr) => {
            let mut w = Writer::with_header();
            write_attr_out(&mut w, &state.stable_attr(nodeid, attr));
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_lookup(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    let Some(parent) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    // Name is a NUL-terminated string filling the rest of the request.
    let name_bytes = match args.iter().position(|&b| b == 0) {
        Some(end) => &args[..end],
        None => args,
    };
    let Ok(name) = std::str::from_utf8(name_bytes) else {
        return error_reply(unique, ENOENT);
    };
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return error_reply(unique, EINVAL);
    }
    let rel = parent.join(name);
    match backend.stat(&rel) {
        Ok(attr) => {
            let child = state.intern(rel, attr.ino);
            let mut w = Writer::with_header();
            write_entry_out(&mut w, child, &state.stable_attr(child, attr));
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

/// Extract a single NUL-terminated component name from `args` starting at
/// `offset`, rejecting empty, `/`-containing, and `.`/`..` names. Returns the
/// validated owned name and the index just past its NUL terminator.
fn read_name(args: &[u8], offset: usize) -> Option<(String, usize)> {
    let rest = args.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let name = std::str::from_utf8(&rest[..end]).ok()?;
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return None;
    }
    Some((name.to_owned(), offset + end + 1))
}

fn handle_batch_forget(state: &mut FsState, args: &[u8]) {
    let Some(count) = rd_u32(args, 0) else { return };
    // fuse_batch_forget_in is { count u32, dummy u32 }; entries follow.
    let mut off = 8;
    for _ in 0..count {
        let (Some(nodeid), Some(nlookup)) = (rd_u64(args, off), rd_u64(args, off + 8)) else {
            break;
        };
        state.forget(nodeid, nlookup);
        off += 16;
    }
}

fn handle_open(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_open_in { flags u32, open_flags u32 }. Reject write intent on a
    // read-only share.
    let flags = rd_u32(args, 0).unwrap_or(0);
    let wants_write = flags & O_ACCMODE != 0;
    if wants_write && state.readonly {
        return error_reply(unique, EROFS);
    }
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    match backend.stat(&rel) {
        Ok(attr) if attr.is_dir() => return error_reply(unique, EPERM),
        Ok(_) => {}
        Err(e) => return error_reply(unique, errno_of(&e)),
    }
    // O_TRUNC on a writable open: truncate to zero now.
    if wants_write && flags & O_TRUNC != 0 {
        let set = SetAttr {
            size: Some(0),
            ..Default::default()
        };
        if let Err(e) = backend.setattr(&rel, &set) {
            return error_reply(unique, errno_of(&e));
        }
    }
    let fh = state.add_handle(Handle::File(rel));
    open_reply(unique, fh)
}

fn handle_opendir(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
) -> Vec<u8> {
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    let self_ino = state.nodes.get(&nodeid).map_or(nodeid, |n| n.ino);
    let entries = match backend.readdir(&rel) {
        Ok(entries) => entries,
        Err(e) => return error_reply(unique, errno_of(&e)),
    };
    // Snapshot the listing so READDIR offsets are stable across calls. The
    // synthesized "." / ".." come first.
    let mut recs = vec![
        DirentRec {
            ino: self_ino,
            name: ".".to_string(),
            dt: crate::backend::DT_DIR,
        },
        DirentRec {
            ino: self_ino,
            name: "..".to_string(),
            dt: crate::backend::DT_DIR,
        },
    ];
    for e in entries {
        recs.push(DirentRec {
            ino: state
                .by_path
                .get(&rel.join(&e.name))
                .and_then(|id| state.nodes.get(id))
                .map_or(e.attr.ino, |n| n.ino),
            name: e.name,
            dt: e.attr.dirent_type(),
        });
    }
    let fh = state.add_handle(Handle::Dir(recs));
    open_reply(unique, fh)
}

fn open_reply(unique: u64, fh: u64) -> Vec<u8> {
    let mut w = Writer::with_header();
    w.u64(fh);
    w.u32(0); // open_flags
    w.u32(0); // padding
    w.finish(unique)
}

fn handle_read(state: &mut FsState, backend: &dyn FsBackend, unique: u64, args: &[u8]) -> Vec<u8> {
    // fuse_read_in { fh u64, offset u64, size u32, ... }.
    let (Some(fh), Some(offset), Some(size)) = (rd_u64(args, 0), rd_u64(args, 8), rd_u32(args, 16))
    else {
        return error_reply(unique, EINVAL);
    };
    let asked = size;
    let size = size.min(MAX_PAYLOAD);
    let rel = match state.handles.get(&fh) {
        Some(Handle::File(rel)) => rel.clone(),
        Some(Handle::Dir(_)) | None => return error_reply(unique, EBADF),
    };
    match backend.read(&rel, offset, size) {
        Ok(data) => {
            // A short READ is EOF to Linux and shrinks `i_size`. That truncates
            // a large loose object when the host returned a short `pread`
            // before the real end of the file. Fail the request instead.
            let got = u64::try_from(data.len()).unwrap_or(0);
            if got < u64::from(asked)
                && backend
                    .stat(&rel)
                    .is_ok_and(|attr| offset.saturating_add(got) < attr.size)
            {
                return error_reply(unique, EIO);
            }
            let mut w = Writer::with_header();
            w.bytes(&data);
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_readdir(state: &mut FsState, unique: u64, args: &[u8]) -> Vec<u8> {
    let (Some(fh), Some(offset), Some(size)) = (rd_u64(args, 0), rd_u64(args, 8), rd_u32(args, 16))
    else {
        return error_reply(unique, EINVAL);
    };
    let size = size.min(MAX_PAYLOAD) as usize;
    let Some(Handle::Dir(recs)) = state.handles.get(&fh) else {
        return error_reply(unique, EBADF);
    };
    let mut w = Writer::with_header();
    let mut emitted = 0usize;
    // Each entry's implicit offset is its 1-based index; the guest passes back
    // the last offset it consumed.
    for (i, rec) in recs.iter().enumerate() {
        let entry_off = (i as u64) + 1;
        if entry_off <= offset {
            continue;
        }
        let padded = dirent_size(rec.name.len());
        if emitted + padded > size {
            break;
        }
        push_dirent(&mut w, rec.ino, entry_off, rec.dt, &rec.name);
        emitted += padded;
    }
    w.finish(unique)
}

fn dirent_size(namelen: usize) -> usize {
    let total = FUSE_NAME_OFFSET + namelen;
    total.div_ceil(8) * 8
}

fn push_dirent(w: &mut Writer, ino: u64, off: u64, dt: u32, name: &str) {
    w.u64(ino);
    w.u64(off);
    w.u32(name.len() as u32);
    w.u32(dt);
    w.bytes(name.as_bytes());
    let pad = dirent_size(name.len()) - (FUSE_NAME_OFFSET + name.len());
    w.pad(pad);
}

fn handle_readlink(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
) -> Vec<u8> {
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    match backend.readlink(&rel) {
        Ok(target) => {
            let mut w = Writer::with_header();
            w.bytes(&target);
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

// ---------------------------------------------------------------------------
// Write-path handlers (reached only when the share is writable).
// ---------------------------------------------------------------------------

/// `fuse_write_in` fixed header length (data follows it).
const FUSE_WRITE_IN_LEN: usize = 40;

fn handle_write(state: &mut FsState, backend: &dyn FsBackend, unique: u64, args: &[u8]) -> Vec<u8> {
    // fuse_write_in { fh, offset, size, write_flags, lock_owner, flags, padding }.
    let (Some(fh), Some(offset), Some(size)) = (rd_u64(args, 0), rd_u64(args, 8), rd_u32(args, 16))
    else {
        return error_reply(unique, EINVAL);
    };
    let size = size.min(MAX_PAYLOAD) as usize;
    let available = args.len().saturating_sub(FUSE_WRITE_IN_LEN);
    let take = size.min(available);
    let data = &args[FUSE_WRITE_IN_LEN..FUSE_WRITE_IN_LEN + take];

    let rel = match state.handles.get(&fh) {
        Some(Handle::File(rel)) => rel.clone(),
        _ => return error_reply(unique, EBADF),
    };
    match backend.write(&rel, offset, data) {
        Ok(written) => {
            // fuse_write_out { size u32, padding u32 }.
            let mut w = Writer::with_header();
            w.u32(written);
            w.u32(0);
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_create(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_create_in { flags u32, mode u32, umask u32, open_flags u32 }, then name.
    let mode = rd_u32(args, 4).unwrap_or(0o644);
    let Some((name, _)) = read_name(args, 16) else {
        return error_reply(unique, EINVAL);
    };
    let Some(parent) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    let rel = parent.join(name);
    match backend.create(&rel, mode) {
        Ok(attr) => {
            let child = state.intern(rel.clone(), attr.ino);
            let fh = state.add_handle(Handle::File(rel));
            let mut w = Writer::with_header();
            write_entry_out(&mut w, child, &state.stable_attr(child, attr));
            // fuse_open_out { fh u64, open_flags u32, padding u32 }.
            w.u64(fh);
            w.u32(0);
            w.u32(0);
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_mkdir(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_mkdir_in { mode u32, umask u32 }, then name.
    let mode = rd_u32(args, 0).unwrap_or(0o755);
    let Some((name, _)) = read_name(args, 8) else {
        return error_reply(unique, EINVAL);
    };
    let Some(parent) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    let rel = parent.join(name);
    match backend.mkdir(&rel, mode) {
        Ok(attr) => {
            let child = state.intern(rel, attr.ino);
            let mut w = Writer::with_header();
            write_entry_out(&mut w, child, &state.stable_attr(child, attr));
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_unlink(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    let Some((name, _)) = read_name(args, 0) else {
        return error_reply(unique, EINVAL);
    };
    let Some(parent) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    let rel = parent.join(name);
    match backend.unlink(&rel) {
        Ok(()) => {
            state.detach_path(&rel);
            Writer::with_header().finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_rmdir(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    let Some((name, _)) = read_name(args, 0) else {
        return error_reply(unique, EINVAL);
    };
    let Some(parent) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    let rel = parent.join(name);
    match backend.rmdir(&rel) {
        Ok(()) => {
            state.detach_path(&rel);
            Writer::with_header().finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_rename(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
    extra: usize,
) -> Vec<u8> {
    // fuse_rename_in { newdir u64 } (RENAME) or fuse_rename2_in { newdir u64,
    // flags u32, padding u32 } (RENAME2, `extra` = 8); old/new names follow.
    let Some(newdir) = rd_u64(args, 0) else {
        return error_reply(unique, EINVAL);
    };
    let flags = if extra == 0 {
        0
    } else {
        rd_u32(args, 8).unwrap_or(0)
    };
    let name_off = 8 + extra;
    let Some((oldname, next)) = read_name(args, name_off) else {
        return error_reply(unique, EINVAL);
    };
    let Some((newname, _)) = read_name(args, next) else {
        return error_reply(unique, EINVAL);
    };
    let (Some(old_parent), Some(new_parent)) = (state.rel_of(nodeid), state.rel_of(newdir)) else {
        return error_reply(unique, ENOENT);
    };
    let from = old_parent.join(oldname);
    let to = new_parent.join(newname);
    match backend.rename(&from, &to, flags) {
        Ok(()) => {
            // `RENAME_EXCHANGE` is bit 2, matching Linux `renameat2`.
            if flags & 2 == 0 {
                state.remap(&from, &to);
            } else {
                state.exchange(&from, &to);
            }
            Writer::with_header().finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_symlink(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // args: name NUL-terminated, then the link target NUL-terminated. The
    // target is an arbitrary path, so it is read raw (not via `read_name`).
    let Some((name, next)) = read_name(args, 0) else {
        return error_reply(unique, EINVAL);
    };
    let Some(rest) = args.get(next..) else {
        return error_reply(unique, EINVAL);
    };
    let tend = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let target = &rest[..tend];
    let Some(parent) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    let rel = parent.join(name);
    match backend.symlink(&rel, target) {
        Ok(attr) => {
            let child = state.intern(rel, attr.ino);
            let mut w = Writer::with_header();
            write_entry_out(&mut w, child, &state.stable_attr(child, attr));
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_setattr(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_setattr_in: valid@0, fh@8, size@16, atime@32, mtime@40,
    // atimensec@56, mtimensec@60, mode@68.
    let valid = rd_u32(args, 0).unwrap_or(0);
    // The share runs as the launching user. Applying guest uid/gid would
    // either fail unprivileged or, as root, rewrite host ownership. There is
    // no idmap, so chown stays unsupported and no other field in the same
    // request is applied.
    if valid & (FATTR_UID | FATTR_GID) != 0 {
        return error_reply(unique, EOPNOTSUPP);
    }
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or((0, 0), |d| (d.as_secs(), d.subsec_nanos()))
    };

    let mut set = SetAttr::default();
    if valid & FATTR_SIZE != 0 {
        set.size = rd_u64(args, 16);
    }
    if valid & FATTR_MODE != 0 {
        set.mode = rd_u32(args, 68);
    }
    if valid & FATTR_MTIME != 0 {
        set.mtime = Some(if valid & FATTR_MTIME_NOW != 0 {
            now()
        } else {
            (rd_u64(args, 40).unwrap_or(0), rd_u32(args, 60).unwrap_or(0))
        });
    }
    if valid & FATTR_ATIME != 0 {
        set.atime = Some(if valid & FATTR_ATIME_NOW != 0 {
            now()
        } else {
            (rd_u64(args, 32).unwrap_or(0), rd_u32(args, 56).unwrap_or(0))
        });
    }

    match backend.setattr(&rel, &set) {
        Ok(attr) => {
            let mut w = Writer::with_header();
            write_attr_out(&mut w, &state.stable_attr(nodeid, attr));
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_mknod(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_mknod_in { mode, rdev, umask, padding } at protocol minor >= 12.
    let mode = rd_u32(args, 0).unwrap_or(0);
    let rdev = rd_u32(args, 4).unwrap_or(0);
    let Some((name, _)) = read_name(args, 16) else {
        return error_reply(unique, EINVAL);
    };
    let Some(parent) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    let rel = parent.join(name);
    match backend.mknod(&rel, mode, rdev) {
        Ok(attr) => entry_reply(state, unique, rel, attr),
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_link(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_link_in { oldnodeid u64 } + name. The reply reuses oldnodeid.
    let Some(oldnodeid) = rd_u64(args, 0) else {
        return error_reply(unique, EINVAL);
    };
    let Some((name, _)) = read_name(args, 8) else {
        return error_reply(unique, EINVAL);
    };
    let (Some(parent), Some(from)) = (state.rel_of(nodeid), state.rel_of(oldnodeid)) else {
        return error_reply(unique, ENOENT);
    };
    let to = parent.join(name);
    match backend.link(&from, &to) {
        Ok(attr) => {
            state.attach_alias(oldnodeid, to);
            let mut w = Writer::with_header();
            write_entry_out(&mut w, oldnodeid, &state.stable_attr(oldnodeid, attr));
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_setxattr(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_setxattr_in is 8 bytes below minor 33: size, flags. Name, then value.
    let Some(size) = rd_u32(args, 0) else {
        return error_reply(unique, EINVAL);
    };
    let flags = rd_u32(args, 4).unwrap_or(0);
    let Some((name, next)) = read_name(args, 8) else {
        return error_reply(unique, EINVAL);
    };
    let Some(value) = args.get(next..next + size as usize) else {
        return error_reply(unique, EINVAL);
    };
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    match backend.set_xattr(&rel, &name, value, flags) {
        Ok(()) => Writer::with_header().finish(unique),
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_getxattr(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    let Some((name, _)) = read_name(args, 8) else {
        return error_reply(unique, EINVAL);
    };
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    xattr_reply(
        unique,
        rd_u32(args, 0).unwrap_or(0),
        backend.get_xattr(&rel, &name),
    )
}

fn handle_listxattr(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_getxattr_in only; LISTXATTR has no name.
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    xattr_reply(
        unique,
        rd_u32(args, 0).unwrap_or(0),
        backend.list_xattr(&rel),
    )
}

/// `size == 0` replies with `fuse_getxattr_out`. A short buffer is `ERANGE`.
fn xattr_reply(unique: u64, size: u32, loaded: io::Result<Vec<u8>>) -> Vec<u8> {
    match loaded {
        Ok(value) => {
            if size == 0 {
                let mut w = Writer::with_header();
                w.u32(u32::try_from(value.len()).unwrap_or(u32::MAX));
                w.u32(0);
                return w.finish(unique);
            }
            if value.len() > size as usize {
                return error_reply(unique, ERANGE);
            }
            let mut w = Writer::with_header();
            w.bytes(&value);
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_removexattr(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    nodeid: u64,
    args: &[u8],
) -> Vec<u8> {
    let Some((name, _)) = read_name(args, 0) else {
        return error_reply(unique, EINVAL);
    };
    let Some(rel) = state.rel_of(nodeid) else {
        return error_reply(unique, ENOENT);
    };
    match backend.remove_xattr(&rel, &name) {
        Ok(()) => Writer::with_header().finish(unique),
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_fallocate(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_fallocate_in { fh, offset, length, mode, padding }.
    let (Some(fh), Some(offset), Some(length), Some(mode)) = (
        rd_u64(args, 0),
        rd_u64(args, 8),
        rd_u64(args, 16),
        rd_u32(args, 24),
    ) else {
        return error_reply(unique, EINVAL);
    };
    let rel = match state.handles.get(&fh) {
        Some(Handle::File(rel)) => rel.clone(),
        _ => return error_reply(unique, EBADF),
    };
    match backend.fallocate(&rel, offset, length, mode) {
        Ok(()) => Writer::with_header().finish(unique),
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_lseek(state: &mut FsState, backend: &dyn FsBackend, unique: u64, args: &[u8]) -> Vec<u8> {
    // fuse_lseek_in { fh, offset, whence, padding }; out { offset }.
    let (Some(fh), Some(offset), Some(whence)) =
        (rd_u64(args, 0), rd_u64(args, 8), rd_u32(args, 16))
    else {
        return error_reply(unique, EINVAL);
    };
    let rel = match state.handles.get(&fh) {
        Some(Handle::File(rel)) => rel.clone(),
        _ => return error_reply(unique, EBADF),
    };
    match backend.lseek(&rel, offset, whence) {
        Ok(pos) => {
            let mut w = Writer::with_header();
            w.u64(pos);
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn handle_copy_file_range(
    state: &mut FsState,
    backend: &dyn FsBackend,
    unique: u64,
    args: &[u8],
) -> Vec<u8> {
    // fuse_copy_file_range_in { fh_in, off_in, nodeid_out, fh_out, off_out, len, flags }.
    let (Some(fh_in), Some(off_in), Some(fh_out), Some(off_out), Some(len), Some(flags)) = (
        rd_u64(args, 0),
        rd_u64(args, 8),
        rd_u64(args, 24),
        rd_u64(args, 32),
        rd_u64(args, 40),
        rd_u64(args, 48),
    ) else {
        return error_reply(unique, EINVAL);
    };
    if flags != 0 {
        return error_reply(unique, EINVAL);
    }
    let Some(Handle::File(src)) = state.handles.get(&fh_in) else {
        return error_reply(unique, EBADF);
    };
    let src = src.clone();
    let Some(Handle::File(dst)) = state.handles.get(&fh_out) else {
        return error_reply(unique, EBADF);
    };
    let dst = dst.clone();
    // A short count is resumable. Cap one reply so a huge request cannot
    // allocate an unbounded userspace buffer in the fallback path.
    let len = len.min(u64::from(MAX_PAYLOAD));
    match backend.copy_file_range(&src, off_in, &dst, off_out, len, 0) {
        Ok(copied) => {
            let mut w = Writer::with_header();
            w.u32(copied);
            w.u32(0);
            w.finish(unique)
        }
        Err(e) => error_reply(unique, errno_of(&e)),
    }
}

fn entry_reply(state: &mut FsState, unique: u64, rel: PathBuf, attr: Attr) -> Vec<u8> {
    let child = state.intern(rel, attr.ino);
    let mut w = Writer::with_header();
    write_entry_out(&mut w, child, &state.stable_attr(child, attr));
    w.finish(unique)
}

fn handle_statfs(unique: u64) -> Vec<u8> {
    // fuse_statfs_out wraps a kstatfs { blocks, bfree, bavail, files, ffree u64;
    // bsize, namelen, frsize u32; padding u32; spare[6] u32 }. Plausible values
    // for a read-only share.
    let mut w = Writer::with_header();
    w.u64(0); // blocks
    w.u64(0); // bfree
    w.u64(0); // bavail
    w.u64(0); // files
    w.u64(0); // ffree
    w.u32(4096); // bsize
    w.u32(255); // namelen
    w.u32(4096); // frsize
    w.u32(0); // padding
    w.pad(6 * 4); // spare[6]
    w.finish(unique)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DT_DIR, DT_REG, MapFs, Passthrough, S_IFMT, S_IFREG};

    /// Build a minimal `fuse_in_header` + args input buffer.
    fn request(opcode: u32, unique: u64, nodeid: u64, args: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        let len = (FUSE_IN_HEADER_LEN + args.len()) as u32;
        b.extend_from_slice(&len.to_le_bytes());
        b.extend_from_slice(&opcode.to_le_bytes());
        b.extend_from_slice(&unique.to_le_bytes());
        b.extend_from_slice(&nodeid.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // uid
        b.extend_from_slice(&0u32.to_le_bytes()); // gid
        b.extend_from_slice(&0u32.to_le_bytes()); // pid
        b.extend_from_slice(&0u32.to_le_bytes()); // total_extlen + padding
        b.extend_from_slice(args);
        b
    }

    fn out_error(reply: &[u8]) -> i32 {
        i32::from_le_bytes(reply[4..8].try_into().unwrap())
    }

    #[test]
    fn init_returns_our_version() {
        let mut state = FsState::new(true);
        let fs = MapFs::new();
        // fuse_init_in: major=7, minor=99, max_readahead=0, flags=0.
        let mut args = Vec::new();
        args.extend_from_slice(&7u32.to_le_bytes());
        args.extend_from_slice(&99u32.to_le_bytes());
        args.extend_from_slice(&0u32.to_le_bytes());
        args.extend_from_slice(&0u32.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_INIT, 1, 0, &args)).unwrap();
        assert_eq!(out_error(&reply), 0);
        let major = rd_u32(&reply, FUSE_OUT_HEADER_LEN).unwrap();
        let minor = rd_u32(&reply, FUSE_OUT_HEADER_LEN + 4).unwrap();
        assert_eq!(major, FUSE_KERNEL_VERSION);
        // Negotiated down to ours.
        assert_eq!(minor, FUSE_KERNEL_MINOR_VERSION);
    }

    #[test]
    fn getattr_root_is_directory() {
        let mut state = FsState::new(true);
        let fs = MapFs::new().with_file("a.txt", "a");
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_GETATTR, 2, FUSE_ROOT_ID, &[]),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        // attr starts after out_header + fuse_attr_out preamble (16 bytes).
        let mode = rd_u32(&reply, FUSE_OUT_HEADER_LEN + 16 + 8 * 6 + 4 * 3).unwrap();
        assert_eq!(mode & S_IFMT, crate::backend::S_IFDIR);
    }

    #[test]
    fn lookup_then_open_then_read_roundtrips() {
        let mut state = FsState::new(true);
        let fs = MapFs::new().with_file("hello.txt", "hi there");

        // LOOKUP "hello.txt" under root.
        let mut name = b"hello.txt".to_vec();
        name.push(0);
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_LOOKUP, 3, FUSE_ROOT_ID, &name),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        let child = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();
        assert!(child >= 2);
        // attr.mode lives after the 40-byte fuse_entry_out preamble.
        let mode = rd_u32(&reply, FUSE_OUT_HEADER_LEN + 40 + 8 * 6 + 4 * 3).unwrap();
        assert_eq!(mode & S_IFMT, S_IFREG);

        // OPEN it read-only.
        let mut open_in = Vec::new();
        open_in.extend_from_slice(&0u32.to_le_bytes()); // flags = O_RDONLY
        open_in.extend_from_slice(&0u32.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_OPEN, 4, child, &open_in)).unwrap();
        assert_eq!(out_error(&reply), 0);
        let fh = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();

        // READ the whole file.
        let mut read_in = Vec::new();
        read_in.extend_from_slice(&fh.to_le_bytes());
        read_in.extend_from_slice(&0u64.to_le_bytes()); // offset
        read_in.extend_from_slice(&64u32.to_le_bytes()); // size
        read_in.extend_from_slice(&0u32.to_le_bytes()); // read_flags
        read_in.extend_from_slice(&0u64.to_le_bytes()); // lock_owner
        read_in.extend_from_slice(&0u32.to_le_bytes()); // flags
        read_in.extend_from_slice(&0u32.to_le_bytes()); // padding
        let reply = dispatch(&mut state, &fs, &request(FUSE_READ, 5, child, &read_in)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(&reply[FUSE_OUT_HEADER_LEN..], b"hi there");
    }

    #[test]
    fn lookup_missing_is_enoent() {
        let mut state = FsState::new(true);
        let fs = MapFs::new();
        let mut name = b"nope".to_vec();
        name.push(0);
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_LOOKUP, 6, FUSE_ROOT_ID, &name),
        )
        .unwrap();
        assert_eq!(out_error(&reply), -ENOENT);
    }

    #[test]
    fn opendir_readdir_lists_entries() {
        let mut state = FsState::new(true);
        let fs = MapFs::new().with_file("a.txt", "a").with_file("b.txt", "b");
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_OPENDIR, 7, FUSE_ROOT_ID, &[]),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        let fh = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();

        let mut read_in = Vec::new();
        read_in.extend_from_slice(&fh.to_le_bytes());
        read_in.extend_from_slice(&0u64.to_le_bytes()); // offset
        read_in.extend_from_slice(&4096u32.to_le_bytes()); // size
        read_in.extend_from_slice(&[0u8; 12]); // rest of fuse_read_in
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_READDIR, 8, FUSE_ROOT_ID, &read_in),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);

        // Walk the dirent stream and collect names.
        let mut names = Vec::new();
        let mut off = FUSE_OUT_HEADER_LEN;
        while off + FUSE_NAME_OFFSET <= reply.len() {
            let namelen = rd_u32(&reply, off + 16).unwrap() as usize;
            let dt = rd_u32(&reply, off + 20).unwrap();
            let name = std::str::from_utf8(
                &reply[off + FUSE_NAME_OFFSET..off + FUSE_NAME_OFFSET + namelen],
            )
            .unwrap()
            .to_string();
            names.push((name, dt));
            off += dirent_size(namelen);
        }
        assert!(names.iter().any(|(n, dt)| n == "." && *dt == DT_DIR));
        assert!(names.iter().any(|(n, dt)| n == "a.txt" && *dt == DT_REG));
        assert!(names.iter().any(|(n, _)| n == "b.txt"));
    }

    #[test]
    fn open_for_write_is_erofs() {
        let mut state = FsState::new(true);
        let fs = MapFs::new().with_file("a.txt", "a");
        let mut name = b"a.txt".to_vec();
        name.push(0);
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_LOOKUP, 9, FUSE_ROOT_ID, &name),
        )
        .unwrap();
        let child = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();
        let mut open_in = Vec::new();
        open_in.extend_from_slice(&2u32.to_le_bytes()); // O_RDWR
        open_in.extend_from_slice(&0u32.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_OPEN, 10, child, &open_in)).unwrap();
        assert_eq!(out_error(&reply), -EROFS);
    }

    #[test]
    fn write_opcode_is_erofs() {
        let mut state = FsState::new(true);
        let fs = MapFs::new();
        // FUSE_WRITE = 16.
        let reply = dispatch(&mut state, &fs, &request(16, 11, FUSE_ROOT_ID, &[0u8; 40])).unwrap();
        assert_eq!(out_error(&reply), -EROFS);
    }

    #[test]
    fn unknown_opcode_is_enosys() {
        let mut state = FsState::new(true);
        let fs = MapFs::new();
        let reply = dispatch(&mut state, &fs, &request(9999, 12, FUSE_ROOT_ID, &[])).unwrap();
        assert_eq!(out_error(&reply), -ENOSYS);
    }

    #[test]
    fn forget_is_replyless() {
        let mut state = FsState::new(true);
        let fs = MapFs::new();
        let args = 1u64.to_le_bytes();
        assert!(
            dispatch(
                &mut state,
                &fs,
                &request(FUSE_FORGET, 13, FUSE_ROOT_ID, &args)
            )
            .is_none()
        );
    }

    // --- write path (writable share) ---------------------------------------

    /// `fuse_create_in` { flags, mode, umask, open_flags } + NUL-terminated name.
    fn create_in(flags: u32, mode: u32, name: &str) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&flags.to_le_bytes());
        a.extend_from_slice(&mode.to_le_bytes());
        a.extend_from_slice(&0u32.to_le_bytes()); // umask
        a.extend_from_slice(&0u32.to_le_bytes()); // open_flags
        a.extend_from_slice(name.as_bytes());
        a.push(0);
        a
    }

    /// `fuse_write_in` { fh, offset, size, write_flags, lock_owner, flags, padding } + data.
    fn write_in(fh: u64, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&fh.to_le_bytes());
        a.extend_from_slice(&offset.to_le_bytes());
        a.extend_from_slice(&(data.len() as u32).to_le_bytes());
        a.extend_from_slice(&[0u8; 20]); // write_flags/lock_owner/flags/padding
        a.extend_from_slice(data);
        a
    }

    fn writable() -> (FsState, Passthrough, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pt = Passthrough::new(dir.path()).unwrap();
        (FsState::new(false), pt, dir)
    }

    #[test]
    fn create_write_read_roundtrip() {
        let (mut state, fs, dir) = writable();

        // CREATE hi.txt (O_RDWR), get child nodeid + fh.
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_CREATE, 1, FUSE_ROOT_ID, &create_in(2, 0o644, "hi.txt")),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        let child = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();
        // fuse_open_out follows the 128-byte fuse_entry_out.
        let fh = rd_u64(&reply, FUSE_OUT_HEADER_LEN + 128).unwrap();

        // WRITE "hello" at offset 0.
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_WRITE, 2, child, &write_in(fh, 0, b"hello")),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(rd_u32(&reply, FUSE_OUT_HEADER_LEN), Some(5)); // fuse_write_out.size

        // It actually hit the host.
        assert_eq!(std::fs::read(dir.path().join("hi.txt")).unwrap(), b"hello");

        // READ it back through the same fh.
        let mut read_in = Vec::new();
        read_in.extend_from_slice(&fh.to_le_bytes());
        read_in.extend_from_slice(&0u64.to_le_bytes());
        read_in.extend_from_slice(&64u32.to_le_bytes());
        read_in.extend_from_slice(&[0u8; 16]);
        let reply = dispatch(&mut state, &fs, &request(FUSE_READ, 3, child, &read_in)).unwrap();
        assert_eq!(&reply[FUSE_OUT_HEADER_LEN..], b"hello");
    }

    #[test]
    fn mkdir_then_create_inside() {
        let (mut state, fs, dir) = writable();
        // fuse_mkdir_in { mode, umask } + name.
        let mut mk = Vec::new();
        mk.extend_from_slice(&0o755u32.to_le_bytes());
        mk.extend_from_slice(&0u32.to_le_bytes());
        mk.extend_from_slice(b"sub");
        mk.push(0);
        let reply = dispatch(&mut state, &fs, &request(FUSE_MKDIR, 1, FUSE_ROOT_ID, &mk)).unwrap();
        assert_eq!(out_error(&reply), 0);
        let sub = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();
        assert!(dir.path().join("sub").is_dir());

        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_CREATE, 2, sub, &create_in(2, 0o644, "f")),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert!(dir.path().join("sub/f").exists());
    }

    #[test]
    fn setattr_truncate() {
        let (mut state, fs, dir) = writable();
        std::fs::write(dir.path().join("f"), b"hello world").unwrap();
        // LOOKUP to get a nodeid.
        let mut name = b"f".to_vec();
        name.push(0);
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_LOOKUP, 1, FUSE_ROOT_ID, &name),
        )
        .unwrap();
        let node = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();

        // SETATTR with FATTR_SIZE = 4.
        let mut sa = vec![0u8; 88];
        sa[0..4].copy_from_slice(&FATTR_SIZE.to_le_bytes()); // valid
        sa[16..24].copy_from_slice(&4u64.to_le_bytes()); // size
        let reply = dispatch(&mut state, &fs, &request(FUSE_SETATTR, 2, node, &sa)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), b"hell");
    }

    #[test]
    fn rename_then_immediate_open() {
        for opcode in [FUSE_RENAME, FUSE_RENAME2] {
            let (mut state, fs, dir) = writable();
            std::fs::create_dir(dir.path().join("blobs")).unwrap();
            let destination = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "blobs");

            // Stage bytes under a temporary name, as with NamedTempFile::persist.
            let reply = dispatch(
                &mut state,
                &fs,
                &request(FUSE_CREATE, 1, FUSE_ROOT_ID, &create_in(2, 0o644, ".tmp")),
            )
            .unwrap();
            assert_eq!(out_error(&reply), 0);
            let node = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();
            let fh = rd_u64(&reply, FUSE_OUT_HEADER_LEN + 128).unwrap();
            let reply = dispatch(
                &mut state,
                &fs,
                &request(FUSE_WRITE, 2, node, &write_in(fh, 0, b"staged blob")),
            )
            .unwrap();
            assert_eq!(out_error(&reply), 0);
            let reply = dispatch(
                &mut state,
                &fs,
                &request(
                    opcode,
                    3,
                    FUSE_ROOT_ID,
                    &rename_in(opcode, destination, ".tmp", "sha256"),
                ),
            )
            .unwrap();
            assert_eq!(out_error(&reply), 0);
            assert!(!dir.path().join(".tmp").exists());
            assert_eq!(
                std::fs::read(dir.path().join("blobs/sha256")).unwrap(),
                b"staged blob"
            );

            // The kernel can reuse CREATE's nodeid without another LOOKUP.
            let reopened = open_node(&mut state, &fs, node);
            assert_read(&mut state, &fs, node, reopened, b"staged blob");
            assert_eq!(lookup_node(&mut state, &fs, destination, "sha256"), node);
            let reopened = open_node(&mut state, &fs, node);
            assert_read(&mut state, &fs, node, reopened, b"staged blob");
            // The handle returned by CREATE must follow the rename too.
            assert_read(&mut state, &fs, node, fh, b"staged blob");
        }
    }

    fn lookup_node(state: &mut FsState, fs: &dyn FsBackend, parent: u64, name: &str) -> u64 {
        let mut name = name.as_bytes().to_vec();
        name.push(0);
        let reply = dispatch(state, fs, &request(FUSE_LOOKUP, 1, parent, &name)).unwrap();
        assert_eq!(out_error(&reply), 0);
        rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap()
    }

    fn open_node(state: &mut FsState, fs: &dyn FsBackend, node: u64) -> u64 {
        let reply = dispatch(state, fs, &request(FUSE_OPEN, 1, node, &[0; 8])).unwrap();
        assert_eq!(out_error(&reply), 0);
        rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap()
    }

    fn assert_read(state: &mut FsState, fs: &dyn FsBackend, node: u64, fh: u64, bytes: &[u8]) {
        let mut args = Vec::new();
        args.extend_from_slice(&fh.to_le_bytes());
        args.extend_from_slice(&0u64.to_le_bytes());
        args.extend_from_slice(&64u32.to_le_bytes());
        args.extend_from_slice(&[0; 20]);
        let reply = dispatch(state, fs, &request(FUSE_READ, 1, node, &args)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(&reply[FUSE_OUT_HEADER_LEN..], bytes);
    }

    fn rename_in(opcode: u32, newdir: u64, from: &str, to: &str) -> Vec<u8> {
        let mut args = newdir.to_le_bytes().to_vec();
        if opcode == FUSE_RENAME2 {
            args.extend_from_slice(&[0; 8]); // flags + padding
        }
        args.extend_from_slice(from.as_bytes());
        args.push(0);
        args.extend_from_slice(to.as_bytes());
        args.push(0);
        args
    }

    #[test]
    fn rename_directory_preserves_cached_descendants() {
        let (mut state, fs, dir) = writable();
        std::fs::create_dir_all(dir.path().join("d/sub")).unwrap();
        std::fs::create_dir(dir.path().join("d-other")).unwrap();
        std::fs::write(dir.path().join("d/sub/f"), b"nested").unwrap();
        std::fs::write(dir.path().join("d-other/f"), b"sibling").unwrap();
        let parent = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "d");
        let sub = lookup_node(&mut state, &fs, parent, "sub");
        let child = lookup_node(&mut state, &fs, sub, "f");
        let fh = open_node(&mut state, &fs, child);
        let sibling_parent = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "d-other");
        let sibling = lookup_node(&mut state, &fs, sibling_parent, "f");
        let sibling_fh = open_node(&mut state, &fs, sibling);

        let reply = dispatch(
            &mut state,
            &fs,
            &request(
                FUSE_RENAME,
                1,
                FUSE_ROOT_ID,
                &rename_in(FUSE_RENAME, FUSE_ROOT_ID, "d", "moved"),
            ),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(lookup_node(&mut state, &fs, FUSE_ROOT_ID, "moved"), parent);
        assert_eq!(lookup_node(&mut state, &fs, parent, "sub"), sub);
        assert_eq!(lookup_node(&mut state, &fs, sub, "f"), child);
        let reply = dispatch(&mut state, &fs, &request(FUSE_OPENDIR, 2, parent, &[])).unwrap();
        assert_eq!(out_error(&reply), 0);

        // Reusing the old path must not redirect cached nodes or file handles.
        std::fs::create_dir_all(dir.path().join("d/sub")).unwrap();
        std::fs::write(dir.path().join("d/sub/f"), b"different inode").unwrap();
        let reopened = open_node(&mut state, &fs, child);
        assert_read(&mut state, &fs, child, reopened, b"nested");
        assert_read(&mut state, &fs, child, fh, b"nested");
        assert_read(&mut state, &fs, sibling, sibling_fh, b"sibling");
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_WRITE, 3, child, &write_in(fh, 0, b"N")),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(
            std::fs::read(dir.path().join("moved/sub/f")).unwrap(),
            b"Nested"
        );

        // Mutations through the original directory nodeids use the new paths.
        for (opcode, node, name) in [
            (FUSE_UNLINK, sub, b"f\0".as_slice()),
            (FUSE_RMDIR, parent, b"sub\0".as_slice()),
            (FUSE_RMDIR, FUSE_ROOT_ID, b"moved\0".as_slice()),
        ] {
            let reply = dispatch(&mut state, &fs, &request(opcode, 4, node, name)).unwrap();
            assert_eq!(out_error(&reply), 0);
        }
        assert!(!dir.path().join("moved").exists());
        assert_eq!(
            std::fs::read(dir.path().join("d/sub/f")).unwrap(),
            b"different inode"
        );
    }

    #[test]
    fn rename_replaces_destination_and_preserves_lookup_counts() {
        let (mut state, fs, dir) = writable();
        std::fs::write(dir.path().join("a"), b"source").unwrap();
        std::fs::write(dir.path().join("b"), b"destination").unwrap();
        let source = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "a");
        let destination = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "b");
        let fh = open_node(&mut state, &fs, source);
        let reply = dispatch(
            &mut state,
            &fs,
            &request(
                FUSE_RENAME,
                1,
                FUSE_ROOT_ID,
                &rename_in(FUSE_RENAME, FUSE_ROOT_ID, "a", "b"),
            ),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(lookup_node(&mut state, &fs, FUSE_ROOT_ID, "b"), source);
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_OPEN, 2, destination, &[0; 8]),
        )
        .unwrap();
        assert_eq!(out_error(&reply), -ENOENT);
        assert_read(&mut state, &fs, source, fh, b"source");

        // FORGET for the overwritten destination cannot remove the new mapping.
        forget_node(&mut state, &fs, destination, 1);
        // Source had one LOOKUP before rename and one afterwards.
        forget_node(&mut state, &fs, source, 1);
        let reopened = open_node(&mut state, &fs, source);
        assert_read(&mut state, &fs, source, reopened, b"source");
        forget_node(&mut state, &fs, source, 1);
        let fresh = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "b");
        assert_ne!(fresh, source);
        let reopened = open_node(&mut state, &fs, fresh);
        assert_read(&mut state, &fs, fresh, reopened, b"source");
    }

    fn forget_node(state: &mut FsState, fs: &dyn FsBackend, node: u64, count: u64) {
        assert!(
            dispatch(
                state,
                fs,
                &request(FUSE_FORGET, 1, node, &count.to_le_bytes()),
            )
            .is_none()
        );
    }

    #[test]
    fn rename_same_path_and_failure_preserve_identity() {
        let (mut state, fs, dir) = writable();
        std::fs::write(dir.path().join("a"), b"unchanged").unwrap();
        std::fs::create_dir(dir.path().join("directory")).unwrap();
        let node = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "a");
        let directory = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "directory");
        let fh = open_node(&mut state, &fs, node);
        for to in ["a", "directory"] {
            let reply = dispatch(
                &mut state,
                &fs,
                &request(
                    FUSE_RENAME,
                    1,
                    FUSE_ROOT_ID,
                    &rename_in(FUSE_RENAME, FUSE_ROOT_ID, "a", to),
                ),
            )
            .unwrap();
            if to == "a" {
                assert_eq!(out_error(&reply), 0);
            } else {
                assert_ne!(out_error(&reply), 0);
            }
            assert_eq!(lookup_node(&mut state, &fs, FUSE_ROOT_ID, "a"), node);
            assert_eq!(
                lookup_node(&mut state, &fs, FUSE_ROOT_ID, "directory"),
                directory
            );
            let reopened = open_node(&mut state, &fs, node);
            assert_read(&mut state, &fs, node, reopened, b"unchanged");
            assert_read(&mut state, &fs, node, fh, b"unchanged");
        }
    }

    #[test]
    fn rename_unlink_rmdir() {
        let (mut state, fs, dir) = writable();
        std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
        // RENAME a.txt -> b.txt under root (newdir = root).
        let mut rn = Vec::new();
        rn.extend_from_slice(&FUSE_ROOT_ID.to_le_bytes()); // newdir
        rn.extend_from_slice(b"a.txt\0b.txt\0");
        let reply = dispatch(&mut state, &fs, &request(FUSE_RENAME, 1, FUSE_ROOT_ID, &rn)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert!(!dir.path().join("a.txt").exists());
        assert!(dir.path().join("b.txt").exists());

        // UNLINK b.txt.
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_UNLINK, 2, FUSE_ROOT_ID, b"b.txt\0"),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert!(!dir.path().join("b.txt").exists());

        // mkdir then RMDIR.
        std::fs::create_dir(dir.path().join("d")).unwrap();
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_RMDIR, 3, FUSE_ROOT_ID, b"d\0"),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert!(!dir.path().join("d").exists());
    }

    #[test]
    fn readonly_share_rejects_create_and_open_write() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), b"x").unwrap();
        let fs = Passthrough::new(dir.path()).unwrap();
        let mut state = FsState::new(true); // read-only

        // CREATE -> EROFS, and nothing created on the host.
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_CREATE, 1, FUSE_ROOT_ID, &create_in(2, 0o644, "new")),
        )
        .unwrap();
        assert_eq!(out_error(&reply), -EROFS);
        assert!(!dir.path().join("new").exists());

        // OPEN existing file O_RDWR -> EROFS.
        let mut name = b"f".to_vec();
        name.push(0);
        let look = dispatch(
            &mut state,
            &fs,
            &request(FUSE_LOOKUP, 2, FUSE_ROOT_ID, &name),
        )
        .unwrap();
        let node = rd_u64(&look, FUSE_OUT_HEADER_LEN).unwrap();
        let mut open_in = Vec::new();
        open_in.extend_from_slice(&2u32.to_le_bytes()); // O_RDWR
        open_in.extend_from_slice(&0u32.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_OPEN, 3, node, &open_in)).unwrap();
        assert_eq!(out_error(&reply), -EROFS);
    }

    #[test]
    fn readonly_backend_errno_is_portable() {
        let mut state = FsState::new(false);
        let fs = MapFs::new();
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_CREATE, 1, FUSE_ROOT_ID, &create_in(2, 0o644, "file")),
        )
        .unwrap();
        assert_eq!(out_error(&reply), -EROFS);
    }

    #[test]
    fn rename_preserves_path_derived_inode_attributes() {
        // Model the Windows backend on every test host so its identity
        // regression does not depend on having a Windows runner available.
        struct PathInodes(Passthrough);
        impl FsBackend for PathInodes {
            fn stat(&self, rel: &Path) -> io::Result<Attr> {
                use std::hash::{Hash, Hasher};
                let mut hash = std::collections::hash_map::DefaultHasher::new();
                rel.hash(&mut hash);
                let mut attr = self.0.stat(rel)?;
                attr.ino = hash.finish();
                Ok(attr)
            }
            fn readdir(&self, rel: &Path) -> io::Result<Vec<crate::backend::DirEntry>> {
                let mut entries = self.0.readdir(rel)?;
                for entry in &mut entries {
                    entry.attr = self.stat(&rel.join(&entry.name))?;
                }
                Ok(entries)
            }
            fn read(&self, rel: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
                self.0.read(rel, offset, size)
            }
            fn readlink(&self, rel: &Path) -> io::Result<Vec<u8>> {
                self.0.readlink(rel)
            }
            fn rename(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
                self.0.rename(from, to, flags)
            }
            fn setattr(&self, rel: &Path, set: &SetAttr) -> io::Result<Attr> {
                self.0.setattr(rel, set)?;
                self.stat(rel)
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("tree")).unwrap();
        std::fs::write(tmp.path().join("tree/file"), b"data").unwrap();
        let fs = PathInodes(Passthrough::new(tmp.path()).unwrap());
        let mut state = FsState::new(false);
        let parent = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "tree");
        let child = lookup_node(&mut state, &fs, parent, "file");
        let ino = fs.stat(Path::new("tree/file")).unwrap().ino;
        let reply = dispatch(
            &mut state,
            &fs,
            &request(
                FUSE_RENAME,
                1,
                FUSE_ROOT_ID,
                &rename_in(FUSE_RENAME, FUSE_ROOT_ID, "tree", "moved"),
            ),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_ne!(fs.stat(Path::new("moved/file")).unwrap().ino, ino);
        let reply = dispatch(&mut state, &fs, &request(FUSE_GETATTR, 2, child, &[])).unwrap();
        assert_eq!(rd_u64(&reply, FUSE_OUT_HEADER_LEN + 16), Some(ino));
        let reply = dispatch(&mut state, &fs, &request(FUSE_LOOKUP, 3, parent, b"file\0")).unwrap();
        assert_eq!(rd_u64(&reply, FUSE_OUT_HEADER_LEN), Some(child));
        assert_eq!(rd_u64(&reply, FUSE_OUT_HEADER_LEN + 40), Some(ino));
        let mut args = vec![0; 88];
        args[..4].copy_from_slice(&FATTR_SIZE.to_le_bytes());
        args[16..24].copy_from_slice(&2u64.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_SETATTR, 4, child, &args)).unwrap();
        assert_eq!(rd_u64(&reply, FUSE_OUT_HEADER_LEN + 16), Some(ino));
        assert_eq!(std::fs::read(tmp.path().join("moved/file")).unwrap(), b"da");
        let reply = dispatch(&mut state, &fs, &request(FUSE_OPENDIR, 5, parent, &[])).unwrap();
        let fh = rd_u64(&reply, FUSE_OUT_HEADER_LEN).unwrap();
        let Some(Handle::Dir(entries)) = state.handles.get(&fh) else {
            panic!("no directory handle")
        };
        assert_eq!(entries.iter().find(|e| e.name == "file").unwrap().ino, ino);
    }

    // Linux virtiofs enforces ACCESS locally and sends individual FORGETs.
    // INTERRUPT needs an outstanding request, which this synchronous server
    // never retains. Keep their wire contracts covered here.
    #[test]
    fn kernel_controlled_bookkeeping() {
        let mut state = FsState::new(true);
        let fs = MapFs::new().with_file("file", "data");
        let node = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "file");
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_ACCESS, 1, node, &[4, 0, 0, 0]),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert!(dispatch(&mut state, &fs, &request(FUSE_INTERRUPT, 2, node, &[0; 8])).is_none());
        let mut batch = vec![0u8; 24];
        batch[..4].copy_from_slice(&1u32.to_le_bytes());
        batch[8..16].copy_from_slice(&node.to_le_bytes());
        batch[16..24].copy_from_slice(&1u64.to_le_bytes());
        assert!(dispatch(&mut state, &fs, &request(FUSE_BATCH_FORGET, 3, 0, &batch)).is_none());
        assert!(state.rel_of(node).is_none());
        assert!(state.rel_of(FUSE_ROOT_ID).is_some());
    }

    #[test]
    fn ownership_setattr_is_explicitly_unsupported() {
        let (mut state, fs, tmp) = writable();
        std::fs::write(tmp.path().join("file"), b"keep").unwrap();
        let node = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "file");
        for ownership in [FATTR_UID, FATTR_GID, FATTR_UID | FATTR_GID] {
            let mut args = vec![0u8; 88];
            args[..4].copy_from_slice(&(ownership | FATTR_SIZE).to_le_bytes());
            // A rejected mixed request must not partially truncate the file.
            let reply = dispatch(&mut state, &fs, &request(FUSE_SETATTR, 1, node, &args)).unwrap();
            assert_eq!(out_error(&reply), -EOPNOTSUPP);
            assert_eq!(std::fs::read(tmp.path().join("file")).unwrap(), b"keep");
        }
    }

    #[test]
    fn rename2_noreplace_exchange_and_rejected_flags() {
        let (mut state, fs, tmp) = writable();
        std::fs::write(tmp.path().join("a"), b"source").unwrap();
        std::fs::write(tmp.path().join("b"), b"destination").unwrap();
        for (flags, errno) in [(8u32, EINVAL), (4, EOPNOTSUPP), (1, EEXIST)] {
            let mut args = rename_in(FUSE_RENAME2, FUSE_ROOT_ID, "a", "b");
            args[8..12].copy_from_slice(&flags.to_le_bytes());
            let reply = dispatch(
                &mut state,
                &fs,
                &request(FUSE_RENAME2, 1, FUSE_ROOT_ID, &args),
            )
            .unwrap();
            assert_eq!(out_error(&reply), -errno, "flags {flags}");
            assert_eq!(std::fs::read(tmp.path().join("a")).unwrap(), b"source");
            assert_eq!(std::fs::read(tmp.path().join("b")).unwrap(), b"destination");
        }

        let mut created = rename_in(FUSE_RENAME2, FUSE_ROOT_ID, "a", "c");
        created[8..12].copy_from_slice(&1u32.to_le_bytes());
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_RENAME2, 2, FUSE_ROOT_ID, &created),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(std::fs::read(tmp.path().join("c")).unwrap(), b"source");

        let mut exchange = rename_in(FUSE_RENAME2, FUSE_ROOT_ID, "c", "b");
        exchange[8..12].copy_from_slice(&2u32.to_le_bytes());
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_RENAME2, 3, FUSE_ROOT_ID, &exchange),
        )
        .unwrap();
        // Win32 has no rename exchange. Both names stay where NOREPLACE left them.
        #[cfg(windows)]
        {
            assert_eq!(out_error(&reply), -EOPNOTSUPP);
            assert_eq!(std::fs::read(tmp.path().join("c")).unwrap(), b"source");
            assert_eq!(std::fs::read(tmp.path().join("b")).unwrap(), b"destination");
        }
        #[cfg(not(windows))]
        {
            assert_eq!(out_error(&reply), 0);
            assert_eq!(std::fs::read(tmp.path().join("c")).unwrap(), b"destination");
            assert_eq!(std::fs::read(tmp.path().join("b")).unwrap(), b"source");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_errors_map_to_linux_errno() {
        assert_eq!(errno_of(&io::Error::from_raw_os_error(5)), EACCES);
        assert_eq!(errno_of(&io::Error::from_raw_os_error(183)), EEXIST);
        assert_eq!(errno_of(&io::Error::from_raw_os_error(2)), ENOENT);
        assert_eq!(
            errno_of(&io::Error::from(io::ErrorKind::Unsupported)),
            EOPNOTSUPP
        );
    }

    #[test]
    fn dax_mapping_is_enosys_without_a_window() {
        let (mut state, fs, _dir) = writable();
        // INIT does not advertise a DAX cache window, so these stay ENOSYS.
        for op in [FUSE_SETUPMAPPING, FUSE_REMOVEMAPPING] {
            let reply =
                dispatch(&mut state, &fs, &request(op, 1, FUSE_ROOT_ID, &[0u8; 16])).unwrap();
            assert_eq!(out_error(&reply), -ENOSYS, "opcode {op}");
            let mut readonly = FsState::new(true);
            let reply = dispatch(
                &mut readonly,
                &fs,
                &request(op, 1, FUSE_ROOT_ID, &[0u8; 16]),
            )
            .unwrap();
            assert_eq!(out_error(&reply), -EROFS, "readonly opcode {op}");
        }
    }

    #[test]
    fn hard_link_keeps_one_nodeid_after_unlink() {
        let (mut state, fs, dir) = writable();
        std::fs::write(dir.path().join("a"), b"same").unwrap();
        let node = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "a");
        let mut args = node.to_le_bytes().to_vec();
        args.extend_from_slice(b"b\0");
        let reply = dispatch(&mut state, &fs, &request(FUSE_LINK, 1, FUSE_ROOT_ID, &args)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(rd_u64(&reply, FUSE_OUT_HEADER_LEN), Some(node));
        let nlink = rd_u32(&reply, FUSE_OUT_HEADER_LEN + 40 + 64).unwrap();
        assert!(nlink >= 2, "nlink {nlink}");
        assert_eq!(lookup_node(&mut state, &fs, FUSE_ROOT_ID, "b"), node);

        // Renaming a name onto its own hard link leaves both names in place.
        let reply = dispatch(
            &mut state,
            &fs,
            &request(
                FUSE_RENAME,
                2,
                FUSE_ROOT_ID,
                &rename_in(FUSE_RENAME, FUSE_ROOT_ID, "a", "b"),
            ),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(std::fs::read(dir.path().join("a")).unwrap(), b"same");
        assert_eq!(std::fs::read(dir.path().join("b")).unwrap(), b"same");

        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_UNLINK, 3, FUSE_ROOT_ID, b"a\0"),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        let fh = open_node(&mut state, &fs, node);
        assert_read(&mut state, &fs, node, fh, b"same");
    }

    #[test]
    fn short_read_before_eof_is_eio() {
        struct ShortRead(Passthrough);
        impl FsBackend for ShortRead {
            fn stat(&self, rel: &Path) -> io::Result<Attr> {
                self.0.stat(rel)
            }
            fn readdir(&self, rel: &Path) -> io::Result<Vec<crate::backend::DirEntry>> {
                self.0.readdir(rel)
            }
            fn read(&self, rel: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
                let mut data = self.0.read(rel, offset, size.min(3))?;
                data.truncate(3);
                Ok(data)
            }
            fn readlink(&self, rel: &Path) -> io::Result<Vec<u8>> {
                self.0.readlink(rel)
            }
        }
        let (mut state, fs, dir) = writable();
        std::fs::write(dir.path().join("big"), vec![1u8; 64]).unwrap();
        let short = ShortRead(fs);
        let node = lookup_node(&mut state, &short, FUSE_ROOT_ID, "big");
        let fh = open_node(&mut state, &short, node);
        let mut args = Vec::new();
        args.extend_from_slice(&fh.to_le_bytes());
        args.extend_from_slice(&0u64.to_le_bytes());
        args.extend_from_slice(&64u32.to_le_bytes());
        args.extend_from_slice(&[0u8; 20]);
        let reply = dispatch(&mut state, &short, &request(FUSE_READ, 1, node, &args)).unwrap();
        assert_eq!(out_error(&reply), -EIO);
    }

    #[test]
    fn large_object_read_is_complete() {
        let (mut state, fs, dir) = writable();
        let len: usize = 2 * 1024 * 1024 + 137;
        let bytes: Vec<u8> = (0..len)
            .map(|i| (i.wrapping_mul(131).wrapping_add(17)) as u8)
            .collect();
        std::fs::write(dir.path().join("loose"), &bytes).unwrap();
        let node = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "loose");
        let fh = open_node(&mut state, &fs, node);
        // One reply cannot carry the whole object (MAX_PAYLOAD). A short
        // success would be EOF to Linux, so an oversize READ is EIO.
        let mut oversize = Vec::new();
        oversize.extend_from_slice(&fh.to_le_bytes());
        oversize.extend_from_slice(&0u64.to_le_bytes());
        oversize.extend_from_slice(&(len as u32).to_le_bytes());
        oversize.extend_from_slice(&[0u8; 20]);
        let reply = dispatch(&mut state, &fs, &request(FUSE_READ, 1, node, &oversize)).unwrap();
        assert_eq!(out_error(&reply), -EIO);

        let mut got = Vec::new();
        let mut offset = 0u64;
        while offset < len as u64 {
            let mut args = Vec::new();
            args.extend_from_slice(&fh.to_le_bytes());
            args.extend_from_slice(&offset.to_le_bytes());
            args.extend_from_slice(&MAX_PAYLOAD.to_le_bytes());
            args.extend_from_slice(&[0u8; 20]);
            let reply = dispatch(&mut state, &fs, &request(FUSE_READ, 2, node, &args)).unwrap();
            assert_eq!(out_error(&reply), 0);
            let chunk = &reply[FUSE_OUT_HEADER_LEN..];
            assert!(!chunk.is_empty() || offset as usize == len);
            got.extend_from_slice(chunk);
            offset += chunk.len() as u64;
        }
        assert_eq!(got, bytes);

        let mut mid = Vec::new();
        mid.extend_from_slice(&fh.to_le_bytes());
        mid.extend_from_slice(&1_000_003u64.to_le_bytes());
        mid.extend_from_slice(&64u32.to_le_bytes());
        mid.extend_from_slice(&[0u8; 20]);
        let reply = dispatch(&mut state, &fs, &request(FUSE_READ, 3, node, &mid)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(&reply[FUSE_OUT_HEADER_LEN..], &bytes[1_000_003..1_000_067]);
    }

    #[cfg(unix)]
    #[test]
    fn xattr_fallocate_lseek_and_copy_roundtrip() {
        let (mut state, fs, dir) = writable();
        std::fs::write(dir.path().join("f"), b"abc").unwrap();
        let node = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "f");
        let fh = open_node(&mut state, &fs, node);

        let mut set = Vec::new();
        set.extend_from_slice(&14u32.to_le_bytes());
        set.extend_from_slice(&1u32.to_le_bytes()); // XATTR_CREATE
        set.extend_from_slice(b"user.dillo\0virtiofs-xattr");
        let reply = dispatch(&mut state, &fs, &request(FUSE_SETXATTR, 1, node, &set)).unwrap();
        assert_eq!(out_error(&reply), 0);
        let mut get = Vec::new();
        get.extend_from_slice(&64u32.to_le_bytes());
        get.extend_from_slice(&0u32.to_le_bytes());
        get.extend_from_slice(b"user.dillo\0");
        let reply = dispatch(&mut state, &fs, &request(FUSE_GETXATTR, 2, node, &get)).unwrap();
        assert_eq!(&reply[FUSE_OUT_HEADER_LEN..], b"virtiofs-xattr");
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_LISTXATTR, 3, node, &[0u8; 8]),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        let listed = u32::from_le_bytes(
            reply[FUSE_OUT_HEADER_LEN..FUSE_OUT_HEADER_LEN + 4]
                .try_into()
                .unwrap(),
        );
        assert!(listed >= b"user.dillo\0".len() as u32);

        let mut falloc = Vec::new();
        falloc.extend_from_slice(&fh.to_le_bytes());
        falloc.extend_from_slice(&0u64.to_le_bytes());
        falloc.extend_from_slice(&(1024u64 * 1024).to_le_bytes());
        falloc.extend_from_slice(&1u32.to_le_bytes()); // KEEP_SIZE
        falloc.extend_from_slice(&0u32.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_FALLOCATE, 4, node, &falloc)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(std::fs::metadata(dir.path().join("f")).unwrap().len(), 3);

        std::fs::write(dir.path().join("sparse"), vec![0u8; 12288]).unwrap();
        let sparse = lookup_node(&mut state, &fs, FUSE_ROOT_ID, "sparse");
        let sparse_fh = open_node(&mut state, &fs, sparse);
        let mut punch = Vec::new();
        punch.extend_from_slice(&sparse_fh.to_le_bytes());
        punch.extend_from_slice(&4096u64.to_le_bytes());
        punch.extend_from_slice(&4096u64.to_le_bytes());
        punch.extend_from_slice(&0x03u32.to_le_bytes()); // PUNCH_HOLE | KEEP_SIZE
        punch.extend_from_slice(&0u32.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_FALLOCATE, 5, sparse, &punch)).unwrap();
        assert_eq!(out_error(&reply), 0, "punch hole");
        let mut seek = Vec::new();
        seek.extend_from_slice(&sparse_fh.to_le_bytes());
        seek.extend_from_slice(&0u64.to_le_bytes());
        seek.extend_from_slice(&4u32.to_le_bytes()); // SEEK_HOLE
        seek.extend_from_slice(&0u32.to_le_bytes());
        let reply = dispatch(&mut state, &fs, &request(FUSE_LSEEK, 6, sparse, &seek)).unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(rd_u64(&reply, FUSE_OUT_HEADER_LEN), Some(4096));

        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_CREATE, 7, FUSE_ROOT_ID, &create_in(2, 0o644, "dst")),
        )
        .unwrap();
        let dst_fh = rd_u64(&reply, FUSE_OUT_HEADER_LEN + 128).unwrap();
        let mut copy = Vec::new();
        copy.extend_from_slice(&fh.to_le_bytes());
        copy.extend_from_slice(&0u64.to_le_bytes());
        copy.extend_from_slice(&0u64.to_le_bytes()); // nodeid_out
        copy.extend_from_slice(&dst_fh.to_le_bytes());
        copy.extend_from_slice(&0u64.to_le_bytes());
        copy.extend_from_slice(&3u64.to_le_bytes());
        copy.extend_from_slice(&0u64.to_le_bytes());
        let reply = dispatch(
            &mut state,
            &fs,
            &request(FUSE_COPY_FILE_RANGE, 8, node, &copy),
        )
        .unwrap();
        assert_eq!(out_error(&reply), 0);
        assert_eq!(rd_u32(&reply, FUSE_OUT_HEADER_LEN), Some(3));
        assert_eq!(std::fs::read(dir.path().join("dst")).unwrap(), b"abc");
    }
}
