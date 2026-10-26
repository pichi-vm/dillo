// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host backend for a named console port: one **inherited** pipe end.
//!
//! `pipe:N` names a file descriptor (Unix) or handle (Windows) number that the
//! **parent** process created and passed into dillo. This module never creates
//! a pipe — it adopts `N`, duplicates it into an end dillo owns, and reads or
//! writes it without blocking:
//!
//! - Unix: `dup(N)` into an [`OwnedFd`](std::os::fd::OwnedFd) dillo closes on
//!   drop, `O_NONBLOCK` on that copy, and `N` itself closed once the copy
//!   exists — so the descriptor number the parent chose is never left dangling
//!   in our table, and nothing but the device-side end of the pipe is touched.
//! - Windows: `DuplicateHandle` into an owned handle, close the original
//!   inherited number (S18), `PIPE_NOWAIT` on our copy so `WriteFile` cannot
//!   hang a worker, and `PeekNamedPipe` ahead of every `ReadFile` so a read
//!   can never park a worker that must still join at shutdown (S12).
//!
//! EOF (read) and EPIPE / broken pipe (write) report [`Transfer::Closed`]: the
//! caller tears that one direction down and leaves the VM running.

use std::fmt;

/// Which way data moves on a port, device-perspective (virtio 1.x §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Host → guest: dillo reads the inherited end.
    Rx,
    /// Guest → host: dillo writes the inherited end.
    Tx,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Direction::Rx => "rx",
            Direction::Tx => "tx",
        })
    }
}

/// Adopting an inherited pipe end failed. The message names the port and
/// direction so an operator can map it straight back to the `--console` spec.
#[derive(Debug, thiserror::Error)]
#[error("console port {port:?} {direction}=pipe:{number}: {source}")]
pub struct PipeError {
    port: String,
    direction: Direction,
    number: u64,
    source: std::io::Error,
}

/// Result of one non-blocking transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transfer {
    /// Moved this many bytes.
    Moved(usize),
    /// Nothing to do right now; try again later.
    WouldBlock,
    /// The peer is gone (EOF on read, EPIPE on write). This direction is done.
    Closed,
}

/// One adopted, dillo-owned end of a parent-created pipe.
#[derive(Debug)]
pub struct PipeEnd {
    port: String,
    direction: Direction,
    inner: imp::PipeEnd,
}

impl PipeEnd {
    /// Adopt inherited end `number` for `port`'s `direction`.
    ///
    /// Call this before the host enters raw-terminal mode: a bad `pipe:N` must
    /// surface as a plain configuration error, not mid-boot.
    pub fn adopt(port: &str, direction: Direction, number: u64) -> Result<Self, PipeError> {
        let inner = imp::PipeEnd::adopt(number).map_err(|source| PipeError {
            port: port.to_string(),
            direction,
            number,
            source,
        })?;
        Ok(Self {
            port: port.to_string(),
            direction,
            inner,
        })
    }

    /// The port this end belongs to.
    pub fn port(&self) -> &str {
        &self.port
    }

    /// The direction this end carries.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Read host → guest bytes into `buf`, without blocking.
    pub fn read(&self, buf: &mut [u8]) -> std::io::Result<Transfer> {
        self.inner.read(buf)
    }

    /// Write guest → host bytes from `buf`, without blocking. A short write is
    /// reported as [`Transfer::Moved`] so the caller can retry the remainder.
    pub fn write(&self, buf: &[u8]) -> std::io::Result<Transfer> {
        self.inner.write(buf)
    }
}

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    /// A dup'd, non-blocking copy of an inherited pipe end.
    #[derive(Debug)]
    pub(super) struct PipeEnd {
        fd: OwnedFd,
    }

    impl PipeEnd {
        pub(super) fn adopt(number: u64) -> io::Result<Self> {
            let raw: RawFd = i32::try_from(number).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{number} is not a file descriptor number"),
                )
            })?;

            // Duplicate through a *borrowed* view first: a bogus `pipe:N`
            // must fail with EBADF, not hand an invalid descriptor to
            // `OwnedFd` (whose drop would then abort on an EBADF close).
            //
            // SAFETY: `raw` is only borrowed for the duration of the `dup`
            // call, which validates it; nothing takes ownership on this path.
            #[allow(unsafe_code)]
            let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
            let fd = nix::unistd::dup(borrowed).map_err(io::Error::from)?;

            // The dup succeeded, so `raw` is a live descriptor the parent
            // handed us and we now own a copy of. Reclaim the original and
            // drop it: the number the parent chose does not stay open in our
            // table, and only our copy gets `O_NONBLOCK` below.
            //
            // SAFETY: `raw` is an inherited pipe end nobody else in this
            // process owns — `resolve()` rejects a `pipe:N` used twice, and
            // 0/1/2 (the descriptors dillo uses itself) are rejected outright.
            #[allow(unsafe_code)]
            drop(unsafe { OwnedFd::from_raw_fd(raw) });

            let flags = fcntl(&fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
            let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
            fcntl(&fd, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;

            Ok(Self { fd })
        }

        pub(super) fn read(&self, buf: &mut [u8]) -> io::Result<super::Transfer> {
            match nix::unistd::read(&self.fd, buf) {
                Ok(0) => Ok(super::Transfer::Closed),
                Ok(n) => Ok(super::Transfer::Moved(n)),
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {
                    Ok(super::Transfer::WouldBlock)
                }
                Err(e) => Err(io::Error::from(e)),
            }
        }

        pub(super) fn write(&self, buf: &[u8]) -> io::Result<super::Transfer> {
            match nix::unistd::write(&self.fd, buf) {
                Ok(n) => Ok(super::Transfer::Moved(n)),
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {
                    Ok(super::Transfer::WouldBlock)
                }
                Err(nix::errno::Errno::EPIPE) => Ok(super::Transfer::Closed),
                Err(e) => Err(io::Error::from(e)),
            }
        }

        #[cfg(test)]
        pub(super) fn raw(&self) -> RawFd {
            use std::os::fd::AsRawFd as _;
            self.fd.as_raw_fd()
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};

    use windows_sys::Win32::Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_BROKEN_PIPE, ERROR_NO_DATA,
        HANDLE,
    };
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{PIPE_NOWAIT, PeekNamedPipe, SetNamedPipeHandleState};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Is this the OS telling us the peer closed its end of the pipe?
    ///
    /// `ERROR_NO_DATA` is *also* what `PIPE_NOWAIT` returns when a write finds
    /// the buffer full — that case is handled in [`PipeEnd::write`], not here.
    fn peer_gone(err: &io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(code) if code == ERROR_BROKEN_PIPE.cast_signed()
        )
    }

    /// A duplicated copy of an inherited pipe handle.
    #[derive(Debug)]
    pub(super) struct PipeEnd {
        handle: OwnedHandle,
    }

    // `OwnedHandle` is only `Send`/`Sync` by virtue of being a plain handle
    // wrapper; the device shares one end across its worker threads.
    impl PipeEnd {
        pub(super) fn adopt(number: u64) -> io::Result<Self> {
            let inherited = number as HANDLE;
            let mut duplicate: HANDLE = std::ptr::null_mut();
            // SAFETY: `inherited` is a handle the parent passed into this
            // process; `DuplicateHandle` validates it and fails cleanly
            // (ERROR_INVALID_HANDLE) otherwise. `duplicate` is a live local.
            #[allow(unsafe_code)]
            let ok = unsafe {
                let process = GetCurrentProcess();
                DuplicateHandle(
                    process,
                    inherited,
                    process,
                    &raw mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }

            // Close the original inherited number once we own a copy (S18),
            // matching the Unix adopt path. Keep `duplicate` if this fails so
            // we do not leak it on the error path.
            // SAFETY: `inherited` is the source handle we just duplicated; it
            // is not referenced by `duplicate`.
            #[allow(unsafe_code)]
            let closed = unsafe { CloseHandle(inherited) };
            if closed == 0 {
                let err = io::Error::last_os_error();
                // SAFETY: close the duplicate we would otherwise abandon.
                #[allow(unsafe_code)]
                unsafe {
                    CloseHandle(duplicate);
                }
                return Err(err);
            }

            // PIPE_NOWAIT so WriteFile returns ERROR_NO_DATA instead of
            // parking the TX worker when the peer stops draining (S12).
            let mut mode = PIPE_NOWAIT;
            // SAFETY: `duplicate` is a live pipe handle we own; mode points at
            // a stack local; unused out-params are null as documented.
            #[allow(unsafe_code)]
            let nowait = unsafe {
                SetNamedPipeHandleState(
                    duplicate,
                    &raw mut mode,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if nowait == 0 {
                let err = io::Error::last_os_error();
                #[allow(unsafe_code)]
                unsafe {
                    CloseHandle(duplicate);
                }
                return Err(err);
            }

            // SAFETY: `DuplicateHandle` succeeded, so `duplicate` is a valid
            // handle this process owns exclusively.
            #[allow(unsafe_code)]
            let handle = unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) };
            Ok(Self { handle })
        }

        /// Bytes queued on the pipe, or `None` once the write end is gone.
        fn available(&self) -> io::Result<Option<u32>> {
            let mut avail: u32 = 0;
            // SAFETY: `handle` is owned and valid; the out-params are live
            // locals and every unused argument is a documented null.
            #[allow(unsafe_code)]
            let ok = unsafe {
                PeekNamedPipe(
                    self.raw(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &raw mut avail,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                if peer_gone(&err) || err.raw_os_error() == Some(ERROR_NO_DATA.cast_signed()) {
                    return Ok(None);
                }
                return Err(err);
            }
            Ok(Some(avail))
        }

        fn raw(&self) -> HANDLE {
            use std::os::windows::io::AsRawHandle;
            self.handle.as_raw_handle() as HANDLE
        }

        pub(super) fn read(&self, buf: &mut [u8]) -> io::Result<super::Transfer> {
            // Peek first: `ReadFile` on a synchronous pipe blocks until data
            // arrives, which would hang the worker past a shutdown request.
            let avail = match self.available()? {
                None => return Ok(super::Transfer::Closed),
                Some(0) => return Ok(super::Transfer::WouldBlock),
                Some(n) => n as usize,
            };
            let want = avail.min(buf.len()) as u32;
            let mut read: u32 = 0;
            // SAFETY: `handle` is owned and valid, and `want <= buf.len()`, so
            // `ReadFile` writes only inside `buf`.
            #[allow(unsafe_code)]
            let ok = unsafe {
                ReadFile(
                    self.raw(),
                    buf.as_mut_ptr(),
                    want,
                    &raw mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                // On the read path ERROR_NO_DATA still means the writer is gone.
                if peer_gone(&err) || err.raw_os_error() == Some(ERROR_NO_DATA.cast_signed()) {
                    return Ok(super::Transfer::Closed);
                }
                return Err(err);
            }
            if read == 0 {
                return Ok(super::Transfer::Closed);
            }
            Ok(super::Transfer::Moved(read as usize))
        }

        pub(super) fn write(&self, buf: &[u8]) -> io::Result<super::Transfer> {
            let mut written: u32 = 0;
            // SAFETY: `handle` is owned and valid; `ReadFile`'s counterpart
            // reads exactly `buf.len()` bytes from `buf`.
            #[allow(unsafe_code)]
            let ok = unsafe {
                WriteFile(
                    self.raw(),
                    buf.as_ptr(),
                    buf.len() as u32,
                    &raw mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                // PIPE_NOWAIT: buffer full ⇒ WouldBlock (not peer-gone).
                if err.raw_os_error() == Some(ERROR_NO_DATA.cast_signed()) {
                    return Ok(super::Transfer::WouldBlock);
                }
                if peer_gone(&err) {
                    return Ok(super::Transfer::Closed);
                }
                return Err(err);
            }
            Ok(super::Transfer::Moved(written as usize))
        }
    }
}

/// Serializes tests that reason about descriptor *numbers*.
///
/// The fd table is process-wide, so a freed number is immediately reusable by
/// any other test thread. Every test that creates a pipe holds this lock, so
/// the one assertion about a specific number cannot race a recycler.
#[cfg(all(test, unix))]
pub(crate) fn fd_table_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};

    /// Stand in for the parent process: create a pipe and hand one end over as
    /// a bare number, exactly as inheritance would.
    fn parent_pipe() -> (OwnedFd, OwnedFd) {
        nix::unistd::pipe().expect("pipe")
    }

    fn adopt(end: OwnedFd, direction: Direction) -> PipeEnd {
        let number = end.into_raw_fd() as u64;
        PipeEnd::adopt("p", direction, number).expect("adopt")
    }

    #[test]
    fn rx_reads_then_reports_eof() {
        let _fds = super::fd_table_lock();
        let (read_end, write_end) = parent_pipe();
        let rx = adopt(read_end, Direction::Rx);

        nix::unistd::write(&write_end, b"hello").expect("host write");
        let mut buf = [0u8; 16];
        assert_eq!(rx.read(&mut buf).expect("read"), Transfer::Moved(5));
        assert_eq!(&buf[..5], b"hello");

        // Drained, writer still around: never block the worker.
        assert_eq!(rx.read(&mut buf).expect("read"), Transfer::WouldBlock);

        drop(write_end);
        assert_eq!(rx.read(&mut buf).expect("read"), Transfer::Closed);
    }

    #[test]
    fn tx_writes_then_reports_epipe() {
        let _fds = super::fd_table_lock();
        let (read_end, write_end) = parent_pipe();
        let tx = adopt(write_end, Direction::Tx);

        assert_eq!(tx.write(b"abc").expect("write"), Transfer::Moved(3));
        let mut buf = [0u8; 8];
        assert_eq!(
            nix::unistd::read(&read_end, &mut buf).expect("host read"),
            3
        );

        drop(read_end);
        // The first write after the reader leaves may be swallowed by SIGPIPE
        // suppression in the test harness; both writes must report Closed.
        let first = tx.write(b"abc").expect("write after close");
        assert_eq!(
            first,
            Transfer::Closed,
            "write to a closed pipe must report Closed"
        );
    }

    #[test]
    fn adopting_closes_the_inherited_number() {
        let _fds = super::fd_table_lock();
        let (read_end, _write_end) = parent_pipe();
        let number = read_end.as_raw_fd();
        let adopted = adopt(read_end, Direction::Rx);
        // The owned copy is a different descriptor, and the number the parent
        // passed in is no longer open in this process.
        assert_ne!(adopted.inner.raw(), number);
        assert!(
            nix::fcntl::fcntl(
                // SAFETY: borrowing a possibly-closed number only to probe it.
                #[allow(unsafe_code)]
                unsafe {
                    std::os::fd::BorrowedFd::borrow_raw(number)
                },
                nix::fcntl::FcntlArg::F_GETFD
            )
            .is_err(),
            "the inherited descriptor should have been closed after dup"
        );
    }

    #[test]
    fn nonblocking_is_not_set_on_the_caller_end() {
        let _fds = super::fd_table_lock();
        // The parent's own end keeps its original flags: dillo sets O_NONBLOCK
        // on its dup'd copy, which has its own open file description flags…
        // except that O_NONBLOCK lives on the *description*, shared by dup. So
        // assert the narrower, true property: the far end is untouched.
        let (read_end, write_end) = parent_pipe();
        let _rx = adopt(read_end, Direction::Rx);
        let flags = nix::fcntl::fcntl(&write_end, nix::fcntl::FcntlArg::F_GETFL).expect("getfl");
        assert!(
            !nix::fcntl::OFlag::from_bits_truncate(flags).contains(nix::fcntl::OFlag::O_NONBLOCK),
            "the parent's end must not become non-blocking"
        );
    }

    #[test]
    fn adopting_a_bad_number_errors_with_the_port_and_direction() {
        let err = PipeEnd::adopt("build", Direction::Rx, 9_999).expect_err("bad fd");
        let msg = err.to_string();
        assert!(msg.contains("build"), "{msg}");
        assert!(msg.contains("rx=pipe:9999"), "{msg}");
    }
}
