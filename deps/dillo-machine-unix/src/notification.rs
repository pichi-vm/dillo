// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pipe notifications for hosts without eventfd. A local wake interrupts a
//! receiver during cancellation without giving it the sender's endpoint.

use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(not(target_os = "macos"))]
use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use dillo_machine::worker::{NotificationRole, WriteNotification};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
#[cfg(not(target_os = "macos"))]
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
#[cfg(target_os = "macos")]
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;

pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = std::io::pipe()?;
    fcntl(&write, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    Ok((read.into(), write.into()))
}

#[derive(Debug)]
struct Notification {
    file: File,
    wake: Option<(File, File)>,
    #[cfg(target_os = "macos")]
    ready: Option<Kqueue>,
}

pub fn adopt(resource: OwnedFd, role: NotificationRole) -> io::Result<Arc<dyn WriteNotification>> {
    let file = File::from(resource);
    let wake = match role {
        NotificationRole::Wait => {
            let (read, write) = pair()?;
            Some((read.into(), write.into()))
        }
        NotificationRole::Signal => None,
    };
    #[cfg(target_os = "macos")]
    let ready = if let Some((wake, _)) = &wake {
        let ready = Kqueue::new()?;
        fcntl(&ready, FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
        let changes = [&file, wake].map(|file| {
            KEvent::new(
                file.as_raw_fd() as usize,
                EventFilter::EVFILT_READ,
                EvFlags::EV_ADD,
                FilterFlag::empty(),
                0,
                0,
            )
        });
        ready.kevent(
            &changes,
            &mut [],
            Some(libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )?;
        Some(ready)
    } else {
        None
    };
    Ok(Arc::new(Notification {
        file,
        wake,
        #[cfg(target_os = "macos")]
        ready,
    }))
}

impl Notification {
    #[cfg(not(target_os = "macos"))]
    fn readable(&self, wake: &File) -> io::Result<[bool; 2]> {
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
            return Ok(events.map(|event| event.revents().is_some_and(|flags| !flags.is_empty())));
        }
    }

    #[cfg(target_os = "macos")]
    fn readable(&self, wake: &File) -> io::Result<[bool; 2]> {
        let ready = self.ready.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        let empty = KEvent::new(
            0,
            EventFilter::EVFILT_READ,
            EvFlags::empty(),
            FilterFlag::empty(),
            0,
            0,
        );
        let mut events = [empty; 2];
        loop {
            let n = match ready.kevent(&[], &mut events, None) {
                Err(nix::errno::Errno::EINTR) => continue,
                result => result?,
            };
            for event in &events[..n] {
                if event.flags().contains(EvFlags::EV_ERROR) {
                    return Err(io::Error::from_raw_os_error(event.data() as i32));
                }
            }
            // Level readiness remains registered across reads, including a
            // partial drain and EOF. Cancellation keeps its separate pipe.
            return Ok([&self.file, wake].map(|file| {
                events[..n]
                    .iter()
                    .any(|event| event.ident() == file.as_raw_fd() as usize)
            }));
        }
    }
}

impl WriteNotification for Notification {
    fn read(&self) -> io::Result<u64> {
        let (wake, _) = self.wake.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        loop {
            for (ready, mut file) in self.readable(wake)?.into_iter().zip([&self.file, wake]) {
                if ready {
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
    fn queued_signals_are_drained_in_batches() {
        let (read, write) = pair().unwrap();
        let receiver = adopt(read, NotificationRole::Wait).unwrap();
        let sender = adopt(write, NotificationRole::Signal).unwrap();
        for n in 1..=64 {
            sender.write(n).unwrap();
        }
        assert_eq!(receiver.read().unwrap(), (1..=32).sum::<u64>());
        assert_eq!(receiver.read().unwrap(), (33..=64).sum::<u64>());
        receiver.write(1).unwrap();
        assert_eq!(receiver.read().unwrap(), 1);
    }
}
