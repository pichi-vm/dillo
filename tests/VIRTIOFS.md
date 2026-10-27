# Guest virtiofs correctness suite

Run the ongoing suite with:

```sh
cargo test -p dillo --features vm-tests --test boot virtiofs_filesystem_ops -- --nocapture
```

`tests/boot/virtiofs.rs` builds a PMI containing the real Linux kernel and
snuffler initramfs. Dillo exposes separate writable and readonly host directories.
`deps/snuffler/src/virtiofs.rs` mounts both with `mount(..., "virtiofs", ...)`,
runs named POSIX checks, and unmounts both without lazy/forced teardown. The host
requires every check in `snuffler::VIRTIOFS_CHECKS`, no errors, the expected FUSE
opcodes in the server trace, and byte-exact host witnesses. Failed mounts,
unmounts, unavailable kernels, missing hypervisors, and missing checks fail;
there are no skip-as-pass paths. Ordinary tests without `vm-tests` need no VM.
CI's existing boot step runs this test on Linux x86_64/arm64, macOS arm64 and
Windows x86_64, using KVM, HVF and WHP respectively.

## Kernel and prerequisites

The default Firecracker boot-test kernel has `CONFIG_FUSE_FS` disabled. This
suite instead uses Cloud Hypervisor's published Linux 6.12.8 release
[`ch-release-v6.12.8-20250613`](https://github.com/cloud-hypervisor/linux/releases/tag/ch-release-v6.12.8-20250613).
The release workflow builds `ch_defconfig` from the same tag on both architectures:

| Guest | Asset | SHA-256 |
| --- | --- | --- |
| x86_64 | `bzImage-x86_64` | `d4af401aa859e4659d4b08a153ac608eb6a315c6918e567daa46981af5d2e5ef` |
| aarch64 | `Image-arm64` | `bec084018bfdea2ccf619166ea4af3fdfecb00a801ae578da14e6cbdba172109` |

The test verifies the image digest. The checked-in required builtin fragments
(`tests/boot/virtiofs-{x86_64,aarch64}.config`) were verified against the tagged
[`arch/x86/configs/ch_defconfig`](https://github.com/cloud-hypervisor/linux/blob/ch-release-v6.12.8-20250613/arch/x86/configs/ch_defconfig)
or [`arch/arm64/configs/ch_defconfig`](https://github.com/cloud-hypervisor/linux/blob/ch-release-v6.12.8-20250613/arch/arm64/configs/ch_defconfig)
for built-in FUSE_FS, VIRTIO_FS, PCI, VIRTIO_PCI and VIRTIO_CONSOLE. The fragments
are paired with the image digest pins and passed to arma for slot/poweroff
inference. Actual guest mounts assert the driver is present in the pinned image.
Only image downloads are needed at runtime, using the existing burrow cache;
config verification requires no extra network request. Nothing is built or
published outside this repository.

If blocked: restore access to the release assets, or update the
asset/config-fragment/digest pins together to another verified published
kernel with those builtins. An `ENODEV` mount error is a failure, never a reason
to skip. Local Linux runs require read/write `/dev/kvm` and sufficient reserved
2 MiB hugepages (512 MiB for this guest). CI provisions these before the boot
step. Install the pinned Rust toolchain and musl target from
`rust-toolchain.toml`; the standard artifact dependencies build snuffler and arma.

## POSIX checks and FUSE mapping

Opcode numbers refer to `deps/dillo-virtio-fs/src/fuse.rs`. The host checks the
actual opcode trace for every operation below except the explicitly described
kernel-controlled cases. It enables tracing only in its child Dillo process.

| Named check | Guest operations / assertions | FUSE opcodes |
| --- | --- | --- |
| `mount_rw`, `mount_ro` | Required real mounts; readonly share mounted without MS_RDONLY so server enforcement is tested | INIT (26), GETATTR (3) |
| `host_read_readdir` | Enumerate host fixtures, read bytes, ENOENT on missing file | LOOKUP (1), OPEN (14), READ (15), OPENDIR (27), READDIR (28), RELEASEDIR (29) |
| `create_read_write_close` | Exclusive create, positional overwrite, readback, close/reopen; EEXIST on repeated exclusive create | CREATE (35), WRITE (16), READ (15), FLUSH (25), RELEASE (18), OPEN (14), FSYNC (20) |
| `mkdir_rmdir_unlink` | 180 files force paginated readdir; exact sorted contents; ENOTEMPTY; unlink all files, remove dir, ENOENT afterwards | MKDIR (9), CREATE (35), OPENDIR (27), READDIR (28), RELEASEDIR (29), UNLINK (10), RMDIR (11), FORGET (2) |
| `rename_immediate_open` | Create, cache inode, rename, immediately open/read; same inode, old name ENOENT | RENAME (12), LOOKUP (1), OPEN (14), READ (15) |
| `rename_cross_directory` | Move across directories, read new path, old path absent, cleanup | RENAME (12), MKDIR (9), UNLINK (10), RMDIR (11) |
| `rename_replace_existing` | Cache destination, replace it, assert new bytes and source inode | RENAME (12), GETATTR (3), OPEN (14), READ (15) |
| `rename_directory_cached_descendants` | Cache child file and directory fds; rename ancestor; read/write through cached file, create relative to cached directory fd, verify new paths/inodes, remove descendants | RENAME (12), READ (15), WRITE (16), CREATE (35), FSYNCDIR (30), UNLINK (10), RMDIR (11) |
| `rename_same_path_and_failure` | Same-path success; missing-source ENOENT preserves destination | RENAME (12) |
| `rename2_flags_unsupported` | NOREPLACE rejected with EINVAL, neither path modified; backend supports only zero flags | RENAME2 (45) |
| `symlink_readlink` | Unix: create relative symlink, lstat/readlink, follow and read, unlink. Windows: explicit EOPNOTSUPP (server does not create symlinks there) | SYMLINK (6), READLINK (5, Unix only), GETATTR (3), UNLINK (10) |
| `getattr_setattr` | ftruncate, O_TRUNC, chmod, utimensat; verify size/mode/mtime and host metadata | GETATTR (3), SETATTR (4), OPEN (14) |
| `chown_unsupported` | Explicit EOPNOTSUPP; host ownership is not delegated | SETATTR (4) |
| `fsync_flush_syncfs` | fsync, fdatasync, close (Linux flush/release), syncfs, directory fsync | FSYNC (20), FLUSH (25), RELEASE (18), SYNCFS (50), FSYNCDIR (30) |
| `statfs_access_lseek` | FUSE magic, bsize=4096, namelen=255; access readable file; SEEK_DATA=0, SEEK_HOLE=length via Linux ENOSYS fallback | STATFS (17), LSEEK (46); ACCESS (34) handled locally by Linux |
| `xattr_get_unsupported` | getxattr explicitly returns EOPNOTSUPP | GETXATTR (22): server ENOSYS, translated by Linux |
| `xattr_set_unsupported` | setxattr explicitly returns EOPNOTSUPP | SETXATTR (21): ENOSYS translated by Linux |
| `xattr_list_unsupported` | listxattr explicitly returns EOPNOTSUPP | LISTXATTR (23): ENOSYS translated by Linux |
| `xattr_remove_unsupported` | removexattr explicitly returns EOPNOTSUPP | REMOVEXATTR (24): ENOSYS translated by Linux |
| `link_mknod_fallocate_unsupported` | hard link and FIFO creation return ENOSYS; fallocate returns EOPNOTSUPP | LINK (13), MKNOD (8), FALLOCATE (43) |
| `copy_file_range_fallback` | copy_file_range copies exactly 3 bytes via Linux generic fallback | COPY_FILE_RANGE (47): ENOSYS triggers Linux generic copy |
| `readonly_read` | Existing host file readable and unchanged | LOOKUP (1), OPEN (14), READ (15) |
| `readonly_mutations` | Write-open, create, mkdir, unlink, rmdir, rename, symlink, chmod, setxattr all explicitly fail EROFS; host verifies contents and directory entries unchanged | OPEN (14), CREATE (35), MKDIR (9), UNLINK (10), RMDIR (11), RENAME (12), SYMLINK (6), SETATTR (4), SETXATTR (21) |
| `unmount_rw`, `unmount_ro` | Normal unmount succeeds with no open handles left | RELEASE (18), RELEASEDIR (29), FORGET (2), DESTROY (38) |

The backend acknowledges sync/flush without performing host fsync; this suite
checks the supported guest API behavior and host-visible contents, not crash
persistence. Unix chmod checks Unix permission bits. Windows checks the backend's
read-only attribute mapping (0444 then 0644). utimensat submits both timestamps;
only mtime is exposed in the current wire attributes (atime/ctime are zero), so
mtime is asserted in guest and host with a Windows-representable nanosecond value.
Ownership changes return EOPNOTSUPP before any other fields can be applied.

Linux virtiofs always enables `default_permissions`, so `access(2)` is checked
by Linux and does not issue ACCESS (34). Its transport sends individual FORGET
(2), rather than BATCH_FORGET (42). INTERRUPT (36) requires an outstanding
request; the synchronous server retains none, so it cannot be induced reliably
by POSIX calls. `kernel_controlled_bookkeeping` tests those three wire contracts
explicitly in the existing FUSE unit suite. It also verifies batch forget really
removes the inode while retaining the root. Existing rename FUSE tests remain.
Zero-flag RENAME2 is likewise retained in the existing protocol rename regression;
Linux emits RENAME for ordinary rename and RENAME2 for the flags rejection case.
SETUPMAPPING (48) / REMOVEMAPPING (49) require DAX negotiation, which the server
does not advertise, so Linux does not expose a guest POSIX path to them. They
remain explicitly unsupported in the dispatcher.
