// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use dillo_ipc::{BorrowedResource, Channel, MAX_MESSAGE, MAX_RESOURCES, Message, Process};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

#[derive(Debug)]
struct Connection {
    socket: UnixStream,
    receive_resources: bool,
}

impl Channel for Connection {
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()> {
        if bytes.len() > MAX_MESSAGE
            || resources.len() > MAX_RESOURCES
            || (self.receive_resources && !resources.is_empty())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        header[4..].copy_from_slice(&(resources.len() as u32).to_le_bytes());
        let fds = resources.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let controls = if fds.is_empty() {
            Vec::new()
        } else {
            vec![ControlMessage::ScmRights(&fds)]
        };
        let sent = sendmsg::<()>(
            self.socket.as_raw_fd(),
            &[IoSlice::new(&header)],
            &controls,
            MsgFlags::empty(),
            None,
        )?;
        if sent == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.socket.write_all(&header[sent..])?;
        self.socket.write_all(bytes)
    }

    fn receive(&mut self) -> io::Result<Message> {
        let mut header = [0u8; 8];
        let mut resources = Vec::new();
        let mut controls = nix::cmsg_space!([i32; MAX_RESOURCES]);
        let (count, truncated) = {
            let mut slices = [IoSliceMut::new(&mut header)];
            let received = recvmsg::<()>(
                self.socket.as_raw_fd(),
                &mut slices,
                self.receive_resources.then_some(&mut controls),
                MsgFlags::empty(),
            )?;
            // Parent receive supplies no ancillary buffer: the kernel discards
            // unsolicited child handles, without installing them in the parent.
            // Only the trusted parent's bootstrap can transfer resources.
            for message in received.cmsgs()? {
                if let ControlMessageOwned::ScmRights(fds) = message {
                    for fd in fds {
                        // SAFETY: SCM_RIGHTS installed a new owned descriptor.
                        #[allow(unsafe_code)]
                        resources.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
            }
            (
                received.bytes,
                received.flags.contains(MsgFlags::MSG_CTRUNC),
            )
        };
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.socket.read_exact(&mut header[count..])?;
        let len = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let expected = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        if truncated || len > MAX_MESSAGE || expected > MAX_RESOURCES || expected != resources.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid worker frame",
            ));
        }
        for resource in &resources {
            nix::fcntl::fcntl(
                resource,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )?;
        }
        let mut bytes = vec![0; len];
        self.socket.read_exact(&mut bytes)?;
        Ok(Message { bytes, resources })
    }

    fn try_clone(&self) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Self {
            socket: self.socket.try_clone()?,
            receive_resources: self.receive_resources,
        }))
    }
}

#[derive(Debug)]
struct Worker(Child);

impl Process for Worker {
    fn terminate(&mut self) -> io::Result<()> {
        self.0.kill()
    }
    fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.0.wait()
    }
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.0.try_wait()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // A failed bootstrap must not leave a worker or a RAM view behind.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

pub fn spawn(executable: &Path) -> io::Result<(Box<dyn Process>, Box<dyn Channel>)> {
    let (parent, child) = UnixStream::pair()?;
    parent.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    let child = OwnedFd::from(child);
    let process = Command::new(executable)
        .arg("--dillo-block-worker")
        .env_clear()
        .stdin(Stdio::from(child))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok((
        Box::new(Worker(process)),
        Box::new(Connection {
            socket: parent,
            receive_resources: false,
        }),
    ))
}

pub fn bootstrap() -> io::Result<Box<dyn Channel>> {
    static ADOPTED: AtomicBool = AtomicBool::new(false);
    if ADOPTED.swap(true, Ordering::AcqRel) {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    // The private entry point executes before any other threads or file opens.
    // Discard every ambient descriptor except the explicit standard streams.
    #[allow(unsafe_code)]
    unsafe {
        #[cfg(target_os = "linux")]
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) < 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "macos")]
        {
            let limit = libc::sysconf(libc::_SC_OPEN_MAX);
            if limit < 0 {
                return Err(io::Error::last_os_error());
            }
            for fd in 3..limit {
                libc::close(fd as i32);
            }
        }
        // stdin is the unique socket transferred by spawn; this function can
        // adopt it only once, and the worker never uses std::io::stdin.
        Ok(Box::new(Connection {
            socket: UnixStream::from_raw_fd(0),
            receive_resources: true,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{pipe, write};

    #[test]
    fn parent_rejects_reverse_descriptors_without_retaining_them() {
        let (parent, child) = UnixStream::pair().unwrap();
        let (reader, writer) = pipe().unwrap();
        let header = [0u8; 8];
        sendmsg::<()>(
            child.as_raw_fd(),
            &[IoSlice::new(&header)],
            &[ControlMessage::ScmRights(&[reader.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(reader);
        let mut parent = Connection {
            socket: parent,
            receive_resources: false,
        };
        assert!(parent.receive().is_err());
        // A leaked installed descriptor would keep this pipe readable.
        assert_eq!(write(&writer, b"x"), Err(nix::errno::Errno::EPIPE));
    }

    #[test]
    fn oversized_frame_is_refused_before_reading_its_body() {
        let (parent, mut child) = UnixStream::pair().unwrap();
        child
            .write_all(&((MAX_MESSAGE as u32) + 1).to_le_bytes())
            .unwrap();
        child.write_all(&0u32.to_le_bytes()).unwrap();
        let mut parent = Connection {
            socket: parent,
            receive_resources: false,
        };
        assert_eq!(
            parent.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
