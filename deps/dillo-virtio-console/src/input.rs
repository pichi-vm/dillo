// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One process-wide stdin reader, with bounded buffering and no VM references.
//! A blocked native stdin read must not hold up a device worker's shutdown.

use std::{
    io::{self, Read},
    sync::{Mutex, OnceLock, mpsc},
    thread,
};

static FAILURE: OnceLock<String> = OnceLock::new();

pub(super) fn check_failure() -> io::Result<()> {
    match FAILURE.get() {
        Some(error) => Err(io::Error::other(error.clone())),
        None => Ok(()),
    }
}

const CHUNK: usize = 8192;
const QUEUED_CHUNKS: usize = 8;
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Input {
    Data(Vec<u8>),
    Closed,
}
enum ReaderState {
    Reading(mpsc::Receiver<io::Result<Input>>),
    Closed,
    Failed(String),
}
static INPUT: OnceLock<io::Result<Mutex<ReaderState>>> = OnceLock::new();

pub(super) fn next() -> io::Result<Option<Input>> {
    let receiver = INPUT
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel(QUEUED_CHUNKS);
            thread::Builder::new()
                .name("console-stdin".into())
                .spawn(move || {
                    produce(
                        io::stdin().lock(),
                        &sender,
                        &FAILURE,
                        super::liveness::input_closed,
                    );
                })?;
            Ok(Mutex::new(ReaderState::Reading(receiver)))
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.to_string()))?;
    receiver
        .lock()
        .map_err(|_| io::Error::other("console input lock poisoned"))?
        .next()
}

impl ReaderState {
    fn next(&mut self) -> io::Result<Option<Input>> {
        let result = match self {
            Self::Closed => return Ok(Some(Input::Closed)),
            Self::Failed(error) => return Err(io::Error::other(error.clone())),
            Self::Reading(receiver) => match receiver.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => return Ok(None),
                Err(mpsc::TryRecvError::Disconnected) => Err(io::Error::other(
                    "console input producer disconnected without an endpoint result",
                )),
            },
        };
        match &result {
            Ok(Input::Closed) => *self = Self::Closed,
            Err(error) => *self = Self::Failed(error.to_string()),
            Ok(Input::Data(_)) => {}
        }
        result.map(Some)
    }
}

// Publish observed read failure before requesting shutdown or waiting for space
// in the data queue. Attached RX may be parked waiting for a guest buffer.
fn produce(
    reader: impl Read,
    sender: &mpsc::SyncSender<io::Result<Input>>,
    failure: &OnceLock<String>,
    closed: impl FnOnce(),
) {
    let result = copy(reader, sender);
    if let Err(error) = &result {
        let _ = failure.set(error.to_string());
    }
    closed();
    let _ = sender.send(result.map(|()| Input::Closed));
}

fn copy(mut reader: impl Read, sender: &mpsc::SyncSender<io::Result<Input>>) -> io::Result<()> {
    let mut bytes = [0; CHUNK];
    loop {
        match reader.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                sender
                    .send(Ok(Input::Data(bytes[..count].to_vec())))
                    .map_err(|_| io::Error::other("console input consumer disconnected"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_input_has_bounded_chunks_and_survives_backpressure() {
        let bytes: Vec<_> = (0..CHUNK * (QUEUED_CHUNKS + 2) + 3)
            .map(|n| n as u8)
            .collect();
        let sent = bytes.clone();
        let (sender, receiver) = mpsc::sync_channel(QUEUED_CHUNKS);
        let writer = thread::spawn(move || copy(io::Cursor::new(sent), &sender));
        let mut received = Vec::new();
        while let Ok(Ok(Input::Data(chunk))) = receiver.recv() {
            assert!(chunk.len() <= CHUNK);
            received.extend_from_slice(&chunk);
        }
        writer.join().unwrap().unwrap();
        assert_eq!(received, bytes);
    }

    #[test]
    fn endpoint_eof_and_read_failure_remain_distinct_across_worker_reactivation() {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected stdin read failure"))
            }
        }
        for fails in [false, true] {
            let (sender, receiver) = mpsc::sync_channel(1);
            let result = if fails {
                copy(FailedRead, &sender)
            } else {
                copy(io::empty(), &sender)
            };
            sender.send(result.map(|()| Input::Closed)).unwrap();
            drop(sender);
            let mut state = ReaderState::Reading(receiver);
            for _ in 0..2 {
                let next = state.next();
                if fails {
                    assert!(
                        next.unwrap_err()
                            .to_string()
                            .contains("injected stdin read failure")
                    );
                } else {
                    assert_eq!(next.unwrap(), Some(Input::Closed));
                }
            }
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        assert!(
            ReaderState::Reading(receiver)
                .next()
                .unwrap_err()
                .to_string()
                .contains("without an endpoint result")
        );
    }

    #[test]
    fn observed_read_failure_stops_before_terminal_delivery_to_a_full_queue() {
        struct DataThenError(bool);
        impl Read for DataThenError {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    bytes[0] = 42;
                    Ok(1)
                } else {
                    Err(io::Error::other("observed input failure"))
                }
            }
        }
        let failure = OnceLock::new();
        let (sender, receiver) = mpsc::sync_channel(1);
        let (closed, stopped) = mpsc::channel();
        thread::scope(|scope| {
            let worker = scope.spawn(|| {
                produce(DataThenError(true), &sender, &failure, || {
                    // This is the existing CLI shutdown path; it must run before
                    // terminal delivery can wait for guest-controlled buffering.
                    closed.send(()).unwrap();
                });
            });
            let shutdown = stopped.recv_timeout(std::time::Duration::from_secs(2));
            let observed = failure.get().cloned();
            // Rescue any blocked send before asserting, without consuming the
            // evidence used to require shutdown ahead of terminal delivery.
            drop(receiver);
            worker.join().unwrap();
            assert!(shutdown.is_ok());
            assert_eq!(observed.as_deref(), Some("observed input failure"));
        });
    }
}
