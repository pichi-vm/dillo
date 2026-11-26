// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Standard vhost-user stream framing and SCM_RIGHTS ownership.

use std::io::{self, IoSlice, IoSliceMut, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use dillo_machine::worker::{BorrowedResource, Channel, MAX_MESSAGE, Message};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

const HEADER: usize = 12;
const MAX_FDS: usize = 8;

#[derive(Debug)]
struct Connection(UnixStream);

pub fn pair() -> io::Result<(Box<dyn Channel>, OwnedFd)> {
    let (local, remote) = UnixStream::pair()?;
    local.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    remote.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    Ok((Box::new(Connection(local)), remote.into()))
}

pub fn adopt(resource: OwnedFd) -> Box<dyn Channel> {
    Box::new(Connection(resource.into()))
}

impl Connection {
    fn read_exact(&mut self, mut bytes: &mut [u8], resources: &mut Vec<OwnedFd>) -> io::Result<()> {
        while !bytes.is_empty() {
            #[cfg(target_os = "linux")]
            let flags = MsgFlags::MSG_CMSG_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let flags = MsgFlags::empty();
            // Receive the kernel maximum before enforcing the protocol's eight
            // descriptors. Darwin externalizes all rights before truncating the
            // ancillary buffer, so a smaller buffer can lose installed FDs.
            // XNU bounds this to 512; Linux SCM_MAX_FD is 253.
            let mut controls = nix::cmsg_space!([RawFd; 512]);
            let mut iov = [IoSliceMut::new(bytes)];
            let message =
                match recvmsg::<()>(self.0.as_raw_fd(), &mut iov, Some(&mut controls), flags) {
                    Err(nix::errno::Errno::EINTR) => continue,
                    result => result?,
                };
            let count = message.bytes;
            for control in message.cmsgs()? {
                if let ControlMessageOwned::ScmRights(fds) = control {
                    for fd in fds {
                        // SAFETY: recvmsg installed a new descriptor owned by
                        // this message. Adopt it exactly once, also on refusal.
                        #[allow(unsafe_code)]
                        resources.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
            }
            if resources.len() > MAX_FDS {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
}

impl Channel for Connection {
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()> {
        if !(HEADER..=MAX_MESSAGE).contains(&bytes.len())
            || resources.len() > MAX_FDS
            || u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len() - HEADER
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fds = resources.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let controls = if fds.is_empty() {
            Vec::new()
        } else {
            vec![ControlMessage::ScmRights(&fds)]
        };
        let sent = loop {
            match sendmsg::<()>(
                self.0.as_raw_fd(),
                &[IoSlice::new(bytes)],
                &controls,
                MsgFlags::empty(),
                None,
            ) {
                Err(nix::errno::Errno::EINTR) => continue,
                result => break result?,
            }
        };
        if sent == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.0.write_all(&bytes[sent..])
    }

    fn receive(&mut self) -> io::Result<Message> {
        let mut bytes = vec![0; HEADER];
        let mut resources = Vec::new();
        self.read_exact(&mut bytes, &mut resources)?;
        let size = u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if size > MAX_MESSAGE - HEADER {
            return Err(io::ErrorKind::InvalidData.into());
        }
        bytes.resize(HEADER + size, 0);
        self.read_exact(&mut bytes[HEADER..], &mut resources)?;
        #[cfg(not(target_os = "linux"))]
        for resource in &resources {
            nix::fcntl::fcntl(
                resource,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )?;
        }
        Ok(Message { bytes, resources })
    }

    fn try_clone(&self) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Self(self.0.try_clone()?)))
    }

    fn pair(&self) -> io::Result<(Box<dyn Channel>, OwnedFd)> {
        pair()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsFd;

    #[test]
    fn header_has_no_private_envelope() {
        let (mut channel, remote) = pair().unwrap();
        let wire = [1u32, 1, 0]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect::<Vec<_>>();
        channel.send(&wire, &[]).unwrap();
        let mut peer = UnixStream::from(remote);
        let mut actual = [0; HEADER];
        peer.read_exact(&mut actual).unwrap();
        assert_eq!(actual.as_slice(), wire);
    }

    #[test]
    fn oversized_header_does_not_wait_for_body() {
        let (mut channel, remote) = pair().unwrap();
        let mut peer = UnixStream::from(remote);
        for value in [1u32, 1, u32::MAX] {
            peer.write_all(&value.to_ne_bytes()).unwrap();
        }
        // Keep the peer open without sending a body: framing must reject the
        // claimed size before allocating it or waiting for more input.
        assert_eq!(
            channel.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn resources_belong_to_their_frame() {
        let (mut channel, remote) = pair().unwrap();
        let mut peer = adopt(remote);
        let (read, mut write) = std::io::pipe().unwrap();
        let wire = [12u32, 1, 8, 0, 0]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect::<Vec<_>>();
        channel.send(&wire, &[read.as_fd()]).unwrap();
        drop(read);
        let received = peer.receive().unwrap();
        assert_eq!(received.bytes, wire);
        assert_eq!(received.resources.len(), 1);
        let mut read = std::fs::File::from(received.resources.into_iter().next().unwrap());
        write.write_all(b"x").unwrap();
        let mut byte = [0];
        read.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
    }

    #[test]
    fn excess_rights_are_closed() {
        let (mut channel, remote) = pair().unwrap();
        let (read, write) = std::io::pipe().unwrap();
        let wire = [1u32, 1, 0]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect::<Vec<_>>();
        sendmsg::<()>(
            remote.as_raw_fd(),
            &[IoSlice::new(&wire)],
            &[ControlMessage::ScmRights(&[read.as_raw_fd(); 64])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(read);
        assert_eq!(
            channel.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // Even a rejected message must close every installed duplicate.
        assert_eq!(
            nix::unistd::write(&write, b"x"),
            Err(nix::errno::Errno::EPIPE)
        );
    }
}
