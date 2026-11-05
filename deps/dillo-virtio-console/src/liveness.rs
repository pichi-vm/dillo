// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Optional process lifetime tied to the ordinary console input pipe.
//! Observations never consume input or depend on the guest draining a queue.
//! Named guest API ports have their own lifetime and are not observed here.

use std::{
    fs::File,
    io,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

/// A duplicate of the console read end, used only for native hangup queries.
#[derive(Debug)]
pub struct InputLifetime(File);

impl InputLifetime {
    /// Request the existing VM shutdown path when stdin's last writer closes.
    /// Call before starting console workers; non-pipe stdin is rejected.
    pub fn watch_stdin(shutdown: &'static AtomicBool) -> io::Result<()> {
        #[cfg(unix)]
        let handle = {
            use std::os::fd::AsFd;
            io::stdin().as_fd().try_clone_to_owned()?
        };
        #[cfg(windows)]
        let handle = {
            use std::os::windows::io::AsHandle;
            io::stdin().as_handle().try_clone_to_owned()?
        };
        let input = Self::new(File::from(handle))?;
        input.watch(shutdown).map(drop)
    }

    fn new(file: File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if !file.metadata()?.file_type().is_fifo() {
                return Err(io::Error::other(
                    "console lifetime requires a pipe on stdin",
                ));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle;
            use winx::file::{FileModeInformation, query_mode_information};
            let mode = query_mode_information(file.as_handle())?;
            if !mode.intersects(
                FileModeInformation::FILE_SYNCHRONOUS_IO_ALERT
                    | FileModeInformation::FILE_SYNCHRONOUS_IO_NONALERT,
            ) {
                return Err(io::Error::other(
                    "console lifetime requires a synchronous stdin pipe",
                ));
            }
        }
        let input = Self(file);
        input.disconnected()?;
        Ok(input)
    }

    fn watch(self, shutdown: &'static AtomicBool) -> io::Result<thread::JoinHandle<()>> {
        thread::Builder::new()
            .name("console-lifetime".into())
            .spawn(move || {
                while !shutdown.load(Ordering::Acquire) {
                    match self.disconnected() {
                        Ok(false) => thread::sleep(Duration::from_millis(20)),
                        Ok(true) => {
                            log::info!("console input closed; stopping VM");
                            shutdown.store(true, Ordering::Release);
                            break;
                        }
                        Err(error) => {
                            log::error!(
                                "console lifetime observation failed: {error}; stopping VM"
                            );
                            shutdown.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            })
    }

    #[cfg(unix)]
    fn disconnected(&self) -> io::Result<bool> {
        use nix::poll::{PollFd, PollFlags, poll};
        use std::os::fd::AsFd;
        // macOS ignores an entry with no requested events. Ask for read
        // readiness, but only hangup changes lifetime; never consume input.
        let mut descriptors = [PollFd::new(
            self.0.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLHUP,
        )];
        match poll(&mut descriptors, 0u8) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        let events = descriptors[0]
            .revents()
            .ok_or_else(|| io::Error::other("missing pipe readiness"))?;
        if events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
            return Err(io::Error::other("console lifetime pipe is invalid"));
        }
        Ok(events.contains(PollFlags::POLLHUP))
    }

    #[cfg(windows)]
    fn disconnected(&self) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::{
            Wdk::Storage::FileSystem::{
                FILE_PIPE_CLOSING_STATE, FILE_PIPE_CONNECTED_STATE, FILE_PIPE_DISCONNECTED_STATE,
                FILE_PIPE_LOCAL_INFORMATION, FilePipeLocalInformation, NtQueryInformationFile,
            },
            Win32::{
                Foundation::{STATUS_PIPE_BROKEN, STATUS_PIPE_DISCONNECTED},
                System::IO::IO_STATUS_BLOCK,
            },
        };
        let mut status = IO_STATUS_BLOCK::default();
        let mut information = FILE_PIPE_LOCAL_INFORMATION::default();
        // SAFETY: new() requires a synchronous handle, so the query completes
        // before returning. Both output buffers have the documented type/size,
        // remain live through the call, and the borrowed handle remains owned.
        // This dillo platform operation is not a dependency of madrillo.
        #[allow(unsafe_code)]
        let result = unsafe {
            NtQueryInformationFile(
                self.0.as_raw_handle(),
                &raw mut status,
                (&raw mut information).cast(),
                std::mem::size_of::<FILE_PIPE_LOCAL_INFORMATION>() as u32,
                FilePipeLocalInformation,
            )
        };
        if result == STATUS_PIPE_BROKEN || result == STATUS_PIPE_DISCONNECTED {
            return Ok(true);
        }
        if result != 0 {
            return Err(io::Error::other(format!(
                "query console pipe state: NTSTATUS {result:#x}"
            )));
        }
        // PeekNamedPipe alone keeps returning queued bytes after writer death.
        // The native closing state observes death without draining those bytes.
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_pipe_local_information
        match information.NamedPipeState {
            FILE_PIPE_CLOSING_STATE | FILE_PIPE_DISCONNECTED_STATE => Ok(true),
            FILE_PIPE_CONNECTED_STATE => Ok(false),
            state => Err(io::Error::other(format!(
                "stdin pipe is not connected: {state}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn unread_pipe_input_does_not_hide_writer_loss() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        let (reader, mut writer, keep_listener) = {
            use nix::fcntl::{FcntlArg, OFlag, fcntl};
            let (reader, writer) = io::pipe()?;
            fcntl(&writer, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            let owned: std::os::fd::OwnedFd = reader.into();
            (File::from(owned), writer, ())
        };
        #[cfg(windows)]
        let (reader, mut writer, keep_listener) = {
            use interprocess::os::windows::named_pipe::{PipeListenerOptions, pipe_mode::Bytes};
            let name = format!(r"\\.\pipe\dillo-liveness-{}", std::process::id());
            let wide = widestring::U16CString::from_str(&name)?;
            let listener = PipeListenerOptions::new()
                .path(wide.as_ucstr())
                .nonblocking(true)
                .output_buffer_size_hint(65536)
                .create_send_only::<Bytes>()?;
            let reader = File::options().read(true).open(&name)?;
            let writer = listener.accept()?;
            (reader, writer, listener)
        };
        let mut remaining = reader.try_clone()?;
        let input = InputLifetime::new(reader)?;
        assert!(!input.disconnected()?);
        let mut count = 0;
        for _ in 0..256 {
            match writer.write(&[0xff; 8192]) {
                Ok(0) => break,
                Ok(bytes) => count += bytes,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        assert!(count > 0);
        assert!(!input.disconnected()?, "buffered data is not hangup");
        let shutdown = Box::leak(Box::new(AtomicBool::new(false)));
        let watch = input.watch(shutdown)?;
        #[cfg(windows)]
        writer.assume_flushed();
        drop(writer);
        #[cfg(windows)]
        drop(keep_listener);
        #[cfg(unix)]
        let () = keep_listener;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !shutdown.load(Ordering::Acquire) {
            if std::time::Instant::now() >= deadline {
                return Err("full-buffer hangup missed".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        watch.join().map_err(|_| "watcher panicked")?;
        let mut received = 0;
        loop {
            match remaining.read(&mut [0; 8192]) {
                Ok(0) => break,
                Ok(bytes) => received += bytes,
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(received, count, "liveness must not consume input");
        println!("console lifetime observed with {count} unread bytes");
        Ok(())
    }

    #[test]
    fn ordinary_input_does_not_request_shutdown_and_empty_eof_does()
    -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = io::pipe()?;
        #[cfg(unix)]
        let owned: std::os::fd::OwnedFd = reader.into();
        #[cfg(windows)]
        let owned: std::os::windows::io::OwnedHandle = reader.into();
        let mut reader = File::from(owned);
        let input = InputLifetime::new(reader.try_clone()?)?;
        writer.write_all(b"input")?;
        assert!(!input.disconnected()?);
        let mut bytes = [0; 5];
        reader.read_exact(&mut bytes)?;
        assert_eq!(&bytes, b"input");
        assert!(!input.disconnected()?);
        drop(writer);
        assert!(input.disconnected()?);
        Ok(())
    }

    #[test]
    fn regular_file_is_not_a_lifetime_pipe() -> io::Result<()> {
        assert!(InputLifetime::new(File::open("Cargo.toml")?).is_err());
        Ok(())
    }
}
