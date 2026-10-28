<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause -->

# Passthrough path references

The share root is opened once. A successful lookup returns a `NodePath`
with an owned host reference, not just a pathname (Windows keeps an
identity instead; see below). FUSE cached nodes and
file handles share that reference. FORGET and RELEASE drop their respective
owners. A later lookup that finds a replacement allocates a new node ID.
CREATE retains the file returned by the creating open, and obtains its
attributes from that file.

Directory operations open parent components one at a time, retaining each
opened directory until the next one is open. Cached directory references
also anchor child lookup, create, mknod, unlink, link, and rename. No operation
checks a canonical pathname and then opens that pathname again. Namespace
operations act on a single directory entry in each retained parent; another
writer can still change that entry before the host syscall. Creation of a
directory, symlink, or special node and its following lookup are separate
syscalls, so the reported entry can already have changed.

The backend refuses intermediate symlinks. FUSE returns final symlinks with
lstat/readlink semantics so the guest can resolve them in its own namespace.
A direct backend read or write through a symlink is refused. File mutations,
allocation, copying, and Unix xattrs use opened files. Attribute replies come
from those same files. This does not add device-type or xattr-name policy.

## Linux

Each component open uses `openat2` with `RESOLVE_BENEATH` and
`RESOLVE_NO_MAGICLINKS`, plus `O_NOFOLLOW`. Lookup keeps an `O_PATH` descriptor,
including for symlinks and special nodes. Subsequent data and xattr access
reopens the owned descriptor through `/proc/self/fd`, keeping it alive during
the open; no guest-supplied path is used there. A missing or inaccessible
procfs causes an error, not a pathname retry. Readlink uses the retained
symlink descriptor directly.

Only `ENOSYS` selects the `openat` fallback. The fallback still opens exactly
one sanitized component with `O_NOFOLLOW` relative to the retained parent.
It never follows an intermediate symlink. Permission, containment, and
concurrent-rename errors from `openat2` are returned without weakening the
request. Mount boundaries are allowed; these helpers do not isolate host
mounts or prevent an authorized host process from moving an already-open
object outside the export. An open reference continues to name that object.

## macOS

macOS retains directory and file references too. It uses
`O_EVTONLY`/`O_SYMLINK` with `O_NONBLOCK` for lookup (so looking up a FIFO
never waits for a writer) and component-relative no-follow `openat` for
access. Before any data or metadata mutation, the opened file's device
and inode must match the retained reference. Reopening never truncates or
creates an existing cached node. If an external rename or replacement makes
that reopen impossible, access fails with a host error or Linux `ESTALE`;
it never mutates the replacement. Guest renames update fallback locators.
macOS has no `mknodat`: FIFO creation uses `mkfifoat`, and other special-node
creation returns `EOPNOTSUPP` because there is no supported parent-relative
helper here.

## Windows

Windows cannot rename a folder while any file or folder inside it is held
open, even when the handle allows deletion. If Dillo kept handles for the
files the guest looks up or opens, the guest could not rename a folder
that holds them. So on Windows the only handle Dillo keeps is the share
root. Cached nodes and open files keep only the path and the file's
identity: its volume serial number and file index, read through a
short-lived handle that is closed before the request returns. A name
joined to a cached folder also records that folder's identity.

Each read, write, or change opens the path again, one component at a time
from the share root, and compares the identity of what it opened with the
recorded one before going on. A mismatch fails with Linux `ESTALE`, and an
existing cached node is never created or truncated. This stands in for the
retained handle and leaves the same small window macOS has: between the
check and the operation, another host writer can still swap the entry.
Guest renames update the recorded paths, so open files keep working after
the guest renames a folder that holds them. A file or folder moved or
replaced outside the guest is not followed; its use is refused instead.

Directory-relative operations use `cap-primitives`, with temporary
directory handles held only while a path-based Windows helper uses their
names. Intermediate reparse points are refused. Windows xattrs and symlink
creation remain unsupported.

## Verification

Unit tests replace a looked-up file and rename/replace a looked-up parent,
then check that use either reaches the retained object or refuses the new
entry. On Windows, a test checks that a folder holding an open file can be
renamed, and that the open file is refused once it is swapped on the host. They also check reference release and inject `ENOSYS` to exercise the
no-follow fallback, including symlink refusal. A separate injected permission
error checks that available-kernel failures do not select the fallback.
macOS and Windows can be cross-checked with `cargo check` on their targets;
these compile checks do not replace the native host CI tests.
