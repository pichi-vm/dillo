// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! POSIX checks on real virtiofs mounts. Every error is reported to the host,
//! including mount/umount failures. Operations the host OS cannot perform
//! assert that errno; everything else must succeed.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use rustix::fs::{self as sys, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use rustix::mount::{MountFlags, UnmountFlags, mount, unmount};
use snuffler::{
    FsCheck, FsSuite, VIRTIOFS_LARGE_FILE, VIRTIOFS_LARGE_GUEST_FILE, VIRTIOFS_LARGE_LEN,
    VIRTIOFS_PROBE_CONTENT, VIRTIOFS_PROBE_FILE, virtiofs_large_byte,
};

pub(super) fn probe(cmdline: &str) -> Option<FsSuite> {
    let token = |key: &str| cmdline.split_whitespace().find_map(|t| t.strip_prefix(key));
    let tag = token("dillo.virtiofs_suite=")?;
    let windows = token("dillo.virtiofs_host=") == Some("windows");
    let rw = Path::new("/mnt-virtiofs");
    let ro = Path::new("/mnt-virtiofs-ro");
    let mut suite = Recorder(FsSuite::default());
    if suite.check("mount_rw", || mount_share(tag, rw)) {
        writable(&mut suite, rw, windows);
        suite.check("unmount_rw", || Ok(unmount(rw, UnmountFlags::empty())?));
    }
    if suite.check("mount_ro", || {
        let tag = token("dillo.virtiofs_ro_tag=")
            .ok_or_else(|| io::Error::other("missing readonly mount tag"))?;
        mount_share(tag, ro)
    }) {
        suite.check("readonly_read", || {
            ensure(
                fs::read(ro.join("locked.txt"))? == b"do not touch",
                "readonly read",
            )
        });
        suite.check("readonly_mutations", || readonly(ro));
        suite.check("unmount_ro", || Ok(unmount(ro, UnmountFlags::empty())?));
    }
    Some(suite.0)
}

struct Recorder(FsSuite);

impl Recorder {
    fn check(&mut self, name: &str, run: impl FnOnce() -> io::Result<()>) -> bool {
        let error = run().err().map(|e| e.to_string());
        let passed = error.is_none();
        self.0.checks.push(FsCheck {
            name: name.into(),
            error,
        });
        passed
    }
}

fn ensure(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn errno<T, E: Into<io::Error>>(result: Result<T, E>, expected: Errno) -> io::Result<()> {
    match result {
        Err(e) => {
            let e = e.into();
            ensure(
                e.raw_os_error() == Some(expected.raw_os_error()),
                &format!("expected {expected}, got {e}"),
            )
        }
        Ok(_) => Err(io::Error::other(format!(
            "expected {expected}, operation succeeded"
        ))),
    }
}

fn mount_share(tag: &str, path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    // Intentionally no MS_RDONLY: the server must enforce readonly itself.
    mount(tag, path, "virtiofs", MountFlags::empty(), None).map_err(|e| {
        io::Error::other(format!(
            "mount -t virtiofs {tag}: {e}; use the pinned kernel in tests/VIRTIOFS.md"
        ))
    })
}

fn writable(s: &mut Recorder, root: &Path, windows: bool) {
    s.check("host_read_readdir", || {
        let names: io::Result<Vec<_>> = fs::read_dir(root)?
            .map(|e| e.map(|e| e.file_name()))
            .collect();
        let names = names?;
        ensure(
            names.iter().any(|n| n == "hello.txt") && names.iter().any(|n| n == "readme.md"),
            "host directory entries",
        )?;
        ensure(
            fs::read(root.join("hello.txt"))? == b"virtiofs host fixture",
            "host file content",
        )?;
        errno(File::open(root.join("missing")), Errno::NOENT)
    });
    s.check("create_read_write_close", || {
        let path = root.join(VIRTIOFS_PROBE_FILE);
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        file.write_all(b"wrong")?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(VIRTIOFS_PROBE_CONTENT.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        ensure(
            bytes == VIRTIOFS_PROBE_CONTENT.as_bytes(),
            "read after positional write",
        )?;
        drop(file); // close drives FLUSH and RELEASE, then reopen the file.
        ensure(fs::read(&path)? == bytes, "reopen after close")?;
        errno(
            OpenOptions::new().write(true).create_new(true).open(path),
            Errno::EXIST,
        )
    });
    s.check("mkdir_rmdir_unlink", || {
        let dir = root.join("scratch");
        fs::create_dir(&dir)?;
        // Exceed one READDIR buffer and verify enumeration resumes correctly.
        for i in 0..180 {
            fs::write(dir.join(format!("file-{i:03}")), b"x")?;
        }
        let mut names: Vec<_> = fs::read_dir(&dir)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<_>>()?;
        names.sort();
        let expected: Vec<_> = (0..180)
            .map(|i| std::ffi::OsString::from(format!("file-{i:03}")))
            .collect();
        ensure(
            names == expected,
            "paginated readdir lost or duplicated entries",
        )?;
        errno(fs::remove_dir(&dir), Errno::NOTEMPTY)?;
        for name in names {
            fs::remove_file(dir.join(name))?;
        }
        ensure(fs::read_dir(&dir)?.next().is_none(), "empty directory")?;
        fs::remove_dir(&dir)?;
        errno(fs::metadata(dir), Errno::NOENT)
    });
    s.check("rename_immediate_open", || {
        let from = root.join(".staged");
        let to = root.join("renamed.txt");
        fs::write(&from, b"staged")?;
        // Populate inode caches before the rename regression's immediate open.
        let ino = fs::metadata(&from)?.ino();
        fs::rename(&from, &to)?;
        ensure(
            fs::read(&to)? == b"staged",
            "immediate open/read after rename",
        )?;
        ensure(fs::metadata(&to)?.ino() == ino, "rename changed inode")?;
        errno(File::open(from), Errno::NOENT)
    });
    s.check("rename_cross_directory", || {
        let a = root.join("from-dir");
        let b = root.join("to-dir");
        fs::create_dir(&a)?;
        fs::create_dir(&b)?;
        fs::write(a.join("file"), b"cross-dir")?;
        fs::rename(a.join("file"), b.join("file"))?;
        ensure(
            fs::read(b.join("file"))? == b"cross-dir",
            "cross-directory rename",
        )?;
        errno(File::open(a.join("file")), Errno::NOENT)?;
        fs::remove_file(b.join("file"))?;
        fs::remove_dir(a)?;
        fs::remove_dir(b)
    });
    s.check("rename_replace_existing", || {
        let a = root.join("replacement");
        let b = root.join("replace.txt");
        fs::write(&a, b"new")?;
        fs::write(&b, b"old")?;
        ensure(fs::read(&b)? == b"old", "cache replacement destination")?;
        let ino = fs::metadata(&a)?.ino();
        fs::rename(&a, &b)?;
        ensure(fs::read(&b)? == b"new", "replace-existing content")?;
        ensure(fs::metadata(&b)?.ino() == ino, "replacement inode")
    });
    s.check("rename_directory_cached_descendants", || {
        let a = root.join("tree");
        let b = root.join("moved");
        fs::create_dir_all(a.join("sub"))?;
        fs::write(a.join("sub/file"), b"cached")?;
        let dir = sys::open(
            a.join("sub"),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        let mut cached = OpenOptions::new()
            .read(true)
            .write(true)
            .open(a.join("sub/file"))?;
        let ino = cached.metadata()?.ino();
        fs::rename(&a, &b)?;
        let mut content = String::new();
        cached.read_to_string(&mut content)?;
        ensure(
            content == "cached",
            "cached descendant read after directory rename",
        )?;
        cached.seek(SeekFrom::Start(0))?;
        cached.write_all(b"C")?;
        cached.sync_all()?;
        drop(cached);
        ensure(
            fs::read(b.join("sub/file"))? == b"Cached",
            "cached descendant write",
        )?;
        ensure(
            fs::metadata(b.join("sub/file"))?.ino() == ino,
            "cached descendant inode",
        )?;
        // Resolve through the directory fd cached before rename (not a fresh
        // lookup of the moved parent), then exercise its nodeid for CREATE.
        let fd = sys::openat(
            &dir,
            "new",
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY,
            Mode::RUSR | Mode::WUSR,
        )?;
        rustix::io::write(&fd, b"relative")?;
        drop(fd);
        ensure(
            fs::read(b.join("sub/new"))? == b"relative",
            "cached parent create",
        )?;
        sys::fsync(&dir)?;
        drop(dir);
        fs::remove_file(b.join("sub/file"))?;
        fs::remove_file(b.join("sub/new"))?;
        fs::remove_dir(b.join("sub"))?;
        fs::remove_dir(b)?;
        errno(fs::metadata(a), Errno::NOENT)
    });
    s.check("rename_same_path_and_failure", || {
        let a = root.join("same");
        fs::write(&a, b"same")?;
        fs::rename(&a, &a)?;
        errno(fs::rename(root.join("absent"), &a), Errno::NOENT)?;
        ensure(
            fs::read(&a)? == b"same",
            "failed rename changed destination",
        )?;
        fs::remove_file(a)
    });
    s.check("rename2_noreplace_exchange", || rename_flags(root, windows));
    s.check("symlink_readlink", || {
        let link = root.join("link");
        if windows {
            errno(symlink("hello.txt", link), Errno::OPNOTSUPP)
        } else {
            symlink("hello.txt", &link)?;
            ensure(
                fs::symlink_metadata(&link)?.file_type().is_symlink(),
                "lstat symlink",
            )?;
            ensure(
                fs::read_link(&link)? == Path::new("hello.txt"),
                "readlink target",
            )?;
            ensure(
                fs::read(&link)? == b"virtiofs host fixture",
                "follow relative symlink",
            )?;
            fs::remove_file(link)
        }
    });
    s.check("getattr_setattr", || attributes(root, windows));
    s.check("chown_unsupported", || {
        errno(
            sys::chown(
                root.join("attrs.txt"),
                Some(rustix::process::Uid::from_raw(12345)),
                Some(rustix::process::Gid::from_raw(12345)),
            ),
            Errno::OPNOTSUPP,
        )
    });
    s.check("fsync_flush_syncfs", || {
        let file = OpenOptions::new()
            .write(true)
            .open(root.join(VIRTIOFS_PROBE_FILE))?;
        file.sync_all()?;
        file.sync_data()?;
        sys::syncfs(&file)?;
        drop(file);
        let dir = File::open(root)?;
        dir.sync_all()?;
        drop(dir);
        Ok(())
    });
    s.check("statfs_access_lseek", || {
        let stat = sys::statfs(root)?;
        ensure(
            stat.f_type == 0x6573_5546 && stat.f_bsize == 4096 && stat.f_namelen == 255,
            "virtiofs statfs geometry",
        )?;
        let path = root.join(VIRTIOFS_PROBE_FILE);
        sys::access(&path, sys::Access::READ_OK)?;
        let file = File::open(&path)?;
        if windows {
            let len = file.metadata()?.len();
            ensure(sys::seek(&file, sys::SeekFrom::Data(0))? == 0, "SEEK_DATA")?;
            ensure(
                sys::seek(&file, sys::SeekFrom::Hole(0))? == len,
                "dense SEEK_HOLE",
            )?;
            return errno(sys::seek(&file, sys::SeekFrom::Data(len)), Errno::NXIO);
        }
        // A hole in the middle cannot be the kernel's ENOSYS fallback, which
        // reports the whole file as data and the only hole at EOF.
        drop(file);
        let sparse = root.join("sparse.bin");
        let mut created = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&sparse)?;
        created.set_len(12288)?;
        created.write_all(&[1u8; 4096])?;
        created.seek(SeekFrom::Start(8192))?;
        created.write_all(&[2u8; 4096])?;
        sys::fallocate(
            &created,
            sys::FallocateFlags::PUNCH_HOLE | sys::FallocateFlags::KEEP_SIZE,
            4096,
            4096,
        )?;
        ensure(
            sys::seek(&created, sys::SeekFrom::Hole(0))? == 4096,
            "SEEK_HOLE inside the file",
        )?;
        ensure(
            sys::seek(&created, sys::SeekFrom::Data(4096))? == 8192,
            "SEEK_DATA after the hole",
        )?;
        errno(sys::seek(&created, sys::SeekFrom::Data(12288)), Errno::NXIO)?;
        drop(created);
        fs::remove_file(sparse)
    });
    let path = root.join("attrs.txt");
    s.check("xattr_get", || xattr_get(&path, windows));
    s.check("xattr_set", || xattr_set(&path, windows));
    s.check("xattr_list", || xattr_list(&path, windows));
    s.check("xattr_remove", || xattr_remove(&path, windows));
    s.check("hard_link", || hard_link(root));
    s.check("mknod_fifo", || mknod_fifo(root, windows));
    s.check("fallocate", || allocate(root, windows));
    s.check("copy_file_range", || copy_range(&path, root));
    s.check("large_object_read", || large_object(root));
}

fn rename_flags(root: &Path, windows: bool) -> io::Result<()> {
    let src = root.join("noreplace-src");
    let dst = root.join("noreplace-dst");
    fs::write(&src, b"moved")?;
    fs::write(&dst, b"noreplace")?;
    errno(
        sys::renameat_with(sys::CWD, &src, sys::CWD, &dst, sys::RenameFlags::NOREPLACE),
        Errno::EXIST,
    )?;
    ensure(
        fs::read(&src)? == b"moved" && fs::read(&dst)? == b"noreplace",
        "noreplace changed an existing file",
    )?;
    let created = root.join("noreplace-created");
    sys::renameat_with(
        sys::CWD,
        &src,
        sys::CWD,
        &created,
        sys::RenameFlags::NOREPLACE,
    )?;
    ensure(fs::read(&created)? == b"moved", "noreplace of a new name")?;
    errno(fs::metadata(&src), Errno::NOENT)?;
    if windows {
        errno(
            sys::renameat_with(
                sys::CWD,
                &created,
                sys::CWD,
                &dst,
                sys::RenameFlags::EXCHANGE,
            ),
            Errno::OPNOTSUPP,
        )?;
    } else {
        sys::renameat_with(
            sys::CWD,
            &created,
            sys::CWD,
            &dst,
            sys::RenameFlags::EXCHANGE,
        )?;
        ensure(
            fs::read(&created)? == b"noreplace" && fs::read(&dst)? == b"moved",
            "exchange",
        )?;
        sys::renameat_with(
            sys::CWD,
            &created,
            sys::CWD,
            &dst,
            sys::RenameFlags::EXCHANGE,
        )?;
    }
    ensure(fs::read(&dst)? == b"noreplace", "exchange witness")?;
    ensure(fs::read(&created)? == b"moved", "exchange source")?;
    errno(
        sys::renameat_with(
            sys::CWD,
            &created,
            sys::CWD,
            &dst,
            sys::RenameFlags::WHITEOUT,
        ),
        Errno::OPNOTSUPP,
    )?;
    fs::remove_file(created)
}

fn xattr_get(path: &Path, windows: bool) -> io::Result<()> {
    let got = sys::getxattr(path, "user.dillo", &mut [0u8; 64]);
    if windows {
        errno(got, Errno::OPNOTSUPP)
    } else {
        errno(got, Errno::NODATA)
    }
}

fn xattr_set(path: &Path, windows: bool) -> io::Result<()> {
    let set = sys::setxattr(
        path,
        "user.dillo",
        b"virtiofs-xattr",
        sys::XattrFlags::empty(),
    );
    if windows {
        return errno(set, Errno::OPNOTSUPP);
    }
    set?;
    let mut buf = [0u8; 64];
    let n = sys::getxattr(path, "user.dillo", &mut buf)?;
    ensure(&buf[..n] == b"virtiofs-xattr", "xattr value")
}

fn xattr_list(path: &Path, windows: bool) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    let listed = sys::listxattr(path, &mut buf);
    if windows {
        return errno(listed, Errno::OPNOTSUPP);
    }
    let n = listed?;
    ensure(
        buf[..n]
            .split(|byte| *byte == 0)
            .any(|name| name == b"user.dillo"),
        "listxattr missing user.dillo",
    )
}

fn xattr_remove(path: &Path, windows: bool) -> io::Result<()> {
    let removed = sys::removexattr(path, "user.dillo");
    if windows {
        return errno(removed, Errno::OPNOTSUPP);
    }
    removed?;
    errno(
        sys::getxattr(path, "user.dillo", &mut [0u8; 8]),
        Errno::NODATA,
    )?;
    // Put it back so the host witness still sees the attribute.
    sys::setxattr(
        path,
        "user.dillo",
        b"virtiofs-xattr",
        sys::XattrFlags::empty(),
    )?;
    Ok(())
}

fn hard_link(root: &Path) -> io::Result<()> {
    let from = root.join("hello.txt");
    let to = root.join("hello-link");
    fs::hard_link(&from, &to)?;
    let a = fs::metadata(&from)?;
    let b = fs::metadata(&to)?;
    ensure(
        a.ino() == b.ino() && a.nlink() >= 2 && fs::read(&to)? == b"virtiofs host fixture",
        "hard link identity",
    )
}

fn mknod_fifo(root: &Path, windows: bool) -> io::Result<()> {
    let fifo = root.join("fifo");
    let created = sys::mknodat(
        sys::CWD,
        &fifo,
        sys::FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    );
    if windows {
        return errno(created, Errno::OPNOTSUPP);
    }
    created?;
    ensure(
        fs::symlink_metadata(&fifo)?.mode() & 0o170_000 == 0o010_000,
        "fifo type",
    )?;
    fs::remove_file(fifo)
}

fn allocate(root: &Path, windows: bool) -> io::Result<()> {
    let path = root.join("alloc.bin");
    fs::write(&path, b"xyz")?;
    let file = OpenOptions::new().read(true).write(true).open(&path)?;
    let allocated = sys::fallocate(&file, sys::FallocateFlags::KEEP_SIZE, 0, 1024 * 1024);
    if windows {
        errno(allocated, Errno::OPNOTSUPP)?;
    } else {
        allocated?;
    }
    ensure(
        file.metadata()?.len() == 3,
        "fallocate changed the file size",
    )
}

fn copy_range(path: &Path, root: &Path) -> io::Result<()> {
    let source = File::open(path)?;
    let to = root.join("copy-target");
    let dest = File::create(&to)?;
    ensure(
        sys::copy_file_range(&source, None, &dest, None, 3)? == 3,
        "copy_file_range length",
    )?;
    drop(dest);
    ensure(fs::read(&to)? == b"abc", "copy_file_range contents")?;
    fs::remove_file(to)
}

fn large_object(root: &Path) -> io::Result<()> {
    let host = root.join(VIRTIOFS_LARGE_FILE);
    ensure(
        fs::metadata(&host)?.len() == VIRTIOFS_LARGE_LEN as u64,
        "large object size",
    )?;
    let bytes = fs::read(&host)?;
    ensure(bytes.len() == VIRTIOFS_LARGE_LEN, "large object short read")?;
    if let Some((index, _)) = bytes
        .iter()
        .enumerate()
        .find(|(index, byte)| **byte != virtiofs_large_byte(*index))
    {
        return Err(io::Error::other(format!("large object byte {index}")));
    }
    let mut file = File::open(&host)?;
    file.seek(SeekFrom::Start(1_000_003))?;
    let mut window = [0u8; 64];
    file.read_exact(&mut window)?;
    ensure(
        window
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == virtiofs_large_byte(1_000_003 + index)),
        "large object window",
    )?;
    let guest_path = root.join(VIRTIOFS_LARGE_GUEST_FILE);
    let mut guest = File::create(&guest_path)?;
    let mut offset = 0usize;
    let mut chunk = [0u8; 64 * 1024];
    while offset < VIRTIOFS_LARGE_LEN {
        let n = (VIRTIOFS_LARGE_LEN - offset).min(chunk.len());
        for (index, slot) in chunk[..n].iter_mut().enumerate() {
            *slot = virtiofs_large_byte(offset + index);
        }
        guest.write_all(&chunk[..n])?;
        offset += n;
    }
    guest.sync_all()
}

fn attributes(root: &Path, windows: bool) -> io::Result<()> {
    let path = root.join("attrs.txt");
    fs::write(&path, b"abcdef")?;
    let file = OpenOptions::new().read(true).write(true).open(&path)?;
    ensure(file.metadata()?.len() == 6, "getattr size")?;
    file.set_len(4)?;
    ensure(fs::read(&path)? == b"abcd", "ftruncate")?;
    drop(file);
    let fd = sys::open(&path, OFlags::WRONLY | OFlags::TRUNC, Mode::empty())?;
    rustix::io::write(&fd, b"abcdef")?;
    drop(fd);
    let file = OpenOptions::new().write(true).open(&path)?;
    file.set_len(3)?;
    let mode = if windows { 0o444 } else { 0o600 };
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    ensure(fs::metadata(&path)?.mode() & 0o777 == mode, "chmod mode")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    let times = sys::Timestamps {
        last_access: sys::Timespec {
            tv_sec: 1_700_000_000,
            tv_nsec: 0,
        },
        last_modification: sys::Timespec {
            tv_sec: 1_700_000_001,
            tv_nsec: 123_456_700,
        },
    };
    sys::utimensat(sys::CWD, &path, &times, AtFlags::empty())?;
    let stat = fs::metadata(path)?;
    ensure(
        stat.len() == 3
            && stat.mtime() == times.last_modification.tv_sec
            && stat.mtime_nsec() == times.last_modification.tv_nsec,
        "truncate/utimens metadata",
    )
}

fn readonly(root: &Path) -> io::Result<()> {
    let path = root.join("locked.txt");
    errno(OpenOptions::new().write(true).open(&path), Errno::ROFS)?;
    errno(fs::write(root.join("new"), b"no"), Errno::ROFS)?;
    errno(fs::create_dir(root.join("new-dir")), Errno::ROFS)?;
    errno(fs::remove_file(&path), Errno::ROFS)?;
    errno(fs::remove_dir(root.join("directory")), Errno::ROFS)?;
    errno(fs::rename(&path, root.join("renamed")), Errno::ROFS)?;
    errno(symlink("locked.txt", root.join("link")), Errno::ROFS)?;
    errno(
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)),
        Errno::ROFS,
    )?;
    errno(
        sys::setxattr(&path, "user.dillo", b"no", sys::XattrFlags::empty()),
        Errno::ROFS,
    )?;
    ensure(
        fs::read(&path)? == b"do not touch",
        "readonly contents changed",
    )
}
