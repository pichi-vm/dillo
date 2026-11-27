// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pipe notifications for hosts without eventfd. A local wake interrupts a
//! receiver during cancellation without giving it the sender's endpoint.

use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(not(target_os = "macos"))]
use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

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
    counters: Mutex<[Counter; 2]>,
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
        counters: Mutex::default(),
        #[cfg(target_os = "macos")]
        ready,
    }))
}

#[derive(Debug, Default)]
struct Counter {
    bytes: [u8; 8],
    filled: usize,
}

impl Counter {
    fn append(&mut self, bytes: &[u8]) -> Option<u64> {
        let mut sum: Option<u64> = None;
        for byte in bytes {
            self.bytes[self.filled] = *byte;
            self.filled += 1;
            if self.filled == self.bytes.len() {
                sum = Some(
                    sum.unwrap_or(0)
                        .saturating_add(u64::from_ne_bytes(self.bytes)),
                );
                self.filled = 0;
            }
        }
        sum
    }
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
        let mut counters = self.counters.lock().unwrap();
        loop {
            for ((ready, mut file), counter) in self
                .readable(wake)?
                .into_iter()
                .zip([&self.file, wake])
                .zip(counters.iter_mut())
            {
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
                    // Keep fragments across waits and cancellation. Completing
                    // a word must not block outside the cancellable wait.
                    if let Some(sum) = counter.append(&bytes[..n]) {
                        return Ok(sum);
                    }
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

    #[test]
    fn cancellation_preserves_a_partial_counter() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (read, write) = pair().unwrap();
        let receiver = adopt(read, NotificationRole::Wait).unwrap();
        let mut write = File::from(write);
        let bytes = 5u64.to_ne_bytes();
        write.write_all(&bytes[..3]).unwrap();
        let waiting = Arc::clone(&receiver);
        let (done, completed) = mpsc::channel();
        let thread = std::thread::spawn(move || done.send(waiting.read()).unwrap());
        receiver.write(1).unwrap();
        let result = completed.recv_timeout(Duration::from_secs(1));
        // Closing the external writer also releases the old, uncancellable
        // read_exact path if this regression fails, so cleanup cannot hang.
        if result.is_err() {
            drop(write);
            thread.join().unwrap();
            panic!("partial notification blocked cancellation: {result:?}");
        }
        thread.join().unwrap();
        assert_eq!(result.unwrap().unwrap(), 1);
        write.write_all(&bytes[3..]).unwrap();
        drop(write);
        assert_eq!(receiver.read().unwrap(), 5);
    }
}
