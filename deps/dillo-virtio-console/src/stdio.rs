// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host terminal I/O stays outside the confined device. Only byte-stream pipe
//! ends cross into the worker; the bridge never sees guest memory or queues.

#[cfg(unix)]
use std::os::fd::OwnedFd as Resource;
#[cfg(windows)]
use std::os::windows::io::OwnedHandle as Resource;
use std::{
    collections::VecDeque,
    fs::File,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

use crate::pipe::{Direction, PipeEnd, Transfer};

#[derive(Debug)]
pub struct Bridge {
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Return worker stdin/stdout and the owner of their host-side pump.
    pub fn new() -> io::Result<(Self, File, File)> {
        let (input, input_writer) = io::pipe()?;
        let (output_reader, output) = io::pipe()?;
        let input_writer = PipeEnd::nonblocking(
            "stdio",
            Direction::Tx,
            File::from(Resource::from(input_writer)),
        )?;
        let output_reader = PipeEnd::nonblocking(
            "stdio",
            Direction::Rx,
            File::from(Resource::from(output_reader)),
        )?;
        let stopped = Arc::new(AtomicBool::new(false));
        let token = Arc::clone(&stopped);
        let thread = std::thread::Builder::new()
            .name("console-host-io".into())
            .spawn(move || {
                let mut pending = VecDeque::new();
                let mut output_buf = [0; 8192];
                while !token.load(Ordering::Acquire) {
                    if pending.is_empty()
                        && let Ok(Some(bytes)) = crate::input::next()
                    {
                        pending.extend(bytes);
                    }
                    if !pending.is_empty() {
                        match input_writer.write(pending.make_contiguous()) {
                            Ok(Transfer::Moved(count)) => {
                                pending.drain(..count);
                            }
                            Ok(Transfer::WouldBlock) => {}
                            Ok(Transfer::Closed) | Err(_) => pending.clear(),
                        }
                    }
                    match output_reader.read(&mut output_buf) {
                        Ok(Transfer::Moved(count)) => {
                            crate::enqueue_output(output_buf[..count].to_vec());
                        }
                        Ok(Transfer::Closed) | Err(_) => break,
                        Ok(Transfer::WouldBlock) => {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                    }
                }
                // The backend flushes to its pipe before RESET_DEVICE completes.
                // Drain those bytes before releasing the host adapter.
                while let Ok(Transfer::Moved(count)) = output_reader.read(&mut output_buf) {
                    crate::enqueue_output(output_buf[..count].to_vec());
                }
                crate::flush_output();
            })?;
        Ok((
            Self {
                stopped,
                thread: Some(thread),
            },
            File::from(Resource::from(input)),
            File::from(Resource::from(output)),
        ))
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
