// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Standard vhost-user stream framing and SCM_RIGHTS ownership.

use std::io::{self, IoSlice, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use dillo_machine::worker::{BorrowedResource, Channel, MAX_MESSAGE, Message};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

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
            let flags = libc::MSG_CMSG_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let flags = 0;
            // nix's cmsgs iterator refuses MSG_CTRUNC before yielding the
            // descriptors that were installed and still need closing.
            let mut controls = [0usize; 32];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: all buffers are aligned, initialized and live for recvmsg.
            // The kernel supplies ancillary headers within msg_control. Each
            // installed descriptor is adopted once, including on truncation.
            #[allow(unsafe_code)]
            let (count, truncated) = unsafe {
                let mut message: libc::msghdr = std::mem::zeroed();
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = controls.as_mut_ptr().cast();
                message.msg_controllen = std::mem::size_of_val(&controls) as _;
                let count = libc::recvmsg(self.0.as_raw_fd(), &mut message, flags);
                if count < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                let mut control = libc::CMSG_FIRSTHDR(&message);
                while !control.is_null() {
                    if (*control).cmsg_level == libc::SOL_SOCKET
                        && (*control).cmsg_type == libc::SCM_RIGHTS
                    {
                        let length = (*control).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                        let data = libc::CMSG_DATA(control).cast::<i32>();
                        for index in 0..length / std::mem::size_of::<i32>() {
                            resources.push(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
                        }
                    }
                    control = libc::CMSG_NXTHDR(&message, control);
                }
                (count as usize, message.msg_flags & libc::MSG_CTRUNC != 0)
            };
            if truncated || resources.len() > MAX_FDS {
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
    fn truncated_rights_are_closed() {
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
        // Every installed duplicate must be closed on rejection, including
        // those preceding the truncated ancillary tail.
        assert_eq!(
            nix::unistd::write(&write, b"x"),
            Err(nix::errno::Errno::EPIPE)
        );
    }
}
