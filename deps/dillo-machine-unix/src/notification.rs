// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pipe notifications for hosts without eventfd. A local wake interrupts a
//! receiver during cancellation without giving it the sender's endpoint.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;

use dillo_machine::worker::{NotificationRole, WriteNotification};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = std::io::pipe()?;
    fcntl(&write, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    Ok((read.into(), write.into()))
}

#[derive(Debug)]
struct Notification {
    file: File,
    wake: Option<(File, File)>,
}

pub fn adopt(resource: OwnedFd, role: NotificationRole) -> io::Result<Arc<dyn WriteNotification>> {
    let wake = match role {
        NotificationRole::Wait => {
            let (read, write) = pair()?;
            Some((read.into(), write.into()))
        }
        NotificationRole::Signal => None,
    };
    Ok(Arc::new(Notification {
        file: resource.into(),
        wake,
    }))
}

impl WriteNotification for Notification {
    fn read(&self) -> io::Result<u64> {
        let (wake, _) = self.wake.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        let mut events = [
            PollFd::new(self.file.as_fd(), PollFlags::POLLIN),
            PollFd::new(wake.as_fd(), PollFlags::POLLIN),
        ];
        loop {
            match poll(&mut events, PollTimeout::NONE) {
                Err(nix::errno::Errno::EINTR) => continue,
                result => {
                    result?;
                }
            }
            for (event, mut file) in events.iter().zip([&self.file, wake]) {
                if event.revents().is_some_and(|flags| !flags.is_empty()) {
                    // Drain ready counters together so a burst causes one
                    // ring scan or interrupt, rather than one per pipe word.
                    let mut bytes = [0; 256];
                    let n = match file.read(&mut bytes) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        result => result?,
                    };
                    if n == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    let end = n.div_ceil(8) * 8;
                    file.read_exact(&mut bytes[n..end])?;
                    return Ok(bytes[..end]
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .fold(0u64, |sum, word| {
                            sum.saturating_add(u64::from_ne_bytes(*word))
                        }));
                }
            }
        }
    }

    fn write(&self, count: u64) -> io::Result<()> {
        let mut file = self.wake.as_ref().map_or(&self.file, |(_, write)| write);
        match file.write_all(&count.to_ne_bytes()) {
            // A full pipe already contains a wake. Ring state determines work.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_and_cancel_a_receiver() {
        let (read, write) = pair().unwrap();
        let receiver = adopt(read, NotificationRole::Wait).unwrap();
        let sender = adopt(write, NotificationRole::Signal).unwrap();
        sender.write(3).unwrap();
        assert_eq!(receiver.read().unwrap(), 3);
        receiver.write(1).unwrap();
        assert_eq!(receiver.read().unwrap(), 1);
        drop(sender);
        assert_eq!(
            receiver.read().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn queued_signals_share_one_wake() {
        let (read, write) = pair().unwrap();
        let receiver = adopt(read, NotificationRole::Wait).unwrap();
        let sender = adopt(write, NotificationRole::Signal).unwrap();
        for n in 1..=32 {
            sender.write(n).unwrap();
        }
        assert_eq!(receiver.read().unwrap(), (1..=32).sum::<u64>());
        receiver.write(1).unwrap();
        assert_eq!(receiver.read().unwrap(), 1);
    }
}
