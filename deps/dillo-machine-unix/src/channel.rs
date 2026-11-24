// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use dillo_ipc::{BorrowedResource, Channel, MAX_MESSAGE, MAX_RESOURCES, Message, Process};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

#[derive(Debug)]
enum Endpoint {
    Resources(UnixStream),
    Bytes(File),
}

impl Endpoint {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Resources(socket) => Ok(Self::Resources(socket.try_clone()?)),
            Self::Bytes(pipe) => Ok(Self::Bytes(pipe.try_clone()?)),
        }
    }

    fn reader(&mut self) -> &mut dyn Read {
        match self {
            Self::Resources(socket) => socket,
            Self::Bytes(pipe) => pipe,
        }
    }
}

#[derive(Debug)]
struct Connection {
    input: Endpoint,
    output: Endpoint,
}

impl Channel for Connection {
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()> {
        if bytes.len() > MAX_MESSAGE
            || resources.len() > MAX_RESOURCES
            || (matches!(self.output, Endpoint::Bytes(_)) && !resources.is_empty())
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
        match &mut self.output {
            Endpoint::Resources(socket) => {
                let sent = sendmsg::<()>(
                    socket.as_raw_fd(),
                    &[IoSlice::new(&header)],
                    &controls,
                    MsgFlags::empty(),
                    None,
                )?;
                if sent == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                socket.write_all(&header[sent..])?;
                socket.write_all(bytes)
            }
            Endpoint::Bytes(pipe) => {
                pipe.write_all(&header)?;
                pipe.write_all(bytes)
            }
        }
    }

    fn receive(&mut self) -> io::Result<Message> {
        let mut header = [0u8; 8];
        let mut resources = Vec::new();
        let mut controls = nix::cmsg_space!([i32; MAX_RESOURCES]);
        let (count, truncated) = if let Endpoint::Resources(socket) = &mut self.input {
            let mut slices = [IoSliceMut::new(&mut header)];
            let received = recvmsg::<()>(
                socket.as_raw_fd(),
                &mut slices,
                Some(&mut controls),
                MsgFlags::empty(),
            )?;
            // Only the trusted parent sends on this socket. The reverse
            // direction is a pipe, which cannot transfer descriptors.
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
        } else {
            (self.input.reader().read(&mut header)?, false)
        };
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.input.reader().read_exact(&mut header[count..])?;
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
        self.input.reader().read_exact(&mut bytes)?;
        Ok(Message { bytes, resources })
    }

    fn try_clone(&self) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Self {
            input: self.input.try_clone()?,
            output: self.output.try_clone()?,
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
    // Make resource transfer unidirectional in the kernel, including for a
    // compromised child. Replies use a pipe rather than an SCM_RIGHTS socket.
    parent.shutdown(Shutdown::Read)?;
    child.shutdown(Shutdown::Write)?;
    let (replies, output) = std::io::pipe()?;
    let child = OwnedFd::from(child);
    let process = Command::new(executable)
        .arg("--dillo-block-worker")
        .env_clear()
        .stdin(Stdio::from(child))
        .stdout(Stdio::from(output))
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok((
        Box::new(Worker(process)),
        Box::new(Connection {
            input: Endpoint::Bytes(File::from(OwnedFd::from(replies))),
            output: Endpoint::Resources(parent),
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
            input: Endpoint::Resources(UnixStream::from_raw_fd(0)),
            output: Endpoint::Bytes(File::from_raw_fd(1)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_cannot_transfer_resources_to_parent() {
        let (socket, peer) = UnixStream::pair().unwrap();
        socket.shutdown(Shutdown::Read).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let (reader, writer) = std::io::pipe().unwrap();
        assert_eq!(
            sendmsg::<()>(
                writer.as_raw_fd(),
                &[IoSlice::new(&[0u8; 8])],
                &[ControlMessage::ScmRights(&[socket.as_raw_fd()])],
                MsgFlags::empty(),
                None,
            ),
            Err(nix::errno::Errno::ENOTSOCK)
        );
        assert_eq!(
            nix::unistd::write(&peer, b"x"),
            Err(nix::errno::Errno::EPIPE)
        );
        drop(reader);
    }

    #[test]
    fn oversized_frame_is_refused_before_reading_its_body() {
        let (parent, child) = UnixStream::pair().unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer
            .write_all(&((MAX_MESSAGE as u32) + 1).to_le_bytes())
            .unwrap();
        writer.write_all(&0u32.to_le_bytes()).unwrap();
        let mut parent = Connection {
            input: Endpoint::Bytes(File::from(OwnedFd::from(reader))),
            output: Endpoint::Resources(parent),
        };
        assert_eq!(
            parent.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(child);
    }
}
