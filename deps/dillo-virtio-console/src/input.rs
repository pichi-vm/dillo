// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One process-wide stdin reader, with bounded buffering and no VM references.
//! A blocked native stdin read must not hold up a device worker's shutdown.

use std::{
    io::{self, Read},
    sync::{Mutex, OnceLock, mpsc},
    thread,
};

const CHUNK: usize = 8192;
const QUEUED_CHUNKS: usize = 8;
static INPUT: OnceLock<io::Result<Mutex<mpsc::Receiver<Vec<u8>>>>> = OnceLock::new();

pub(super) fn next() -> io::Result<Option<Vec<u8>>> {
    let receiver = INPUT
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel(QUEUED_CHUNKS);
            thread::Builder::new()
                .name("console-stdin".into())
                .spawn(move || {
                    if let Err(error) = copy(io::stdin().lock(), sender) {
                        log::debug!("console stdin reader: {error}");
                    }
                })?;
            Ok(Mutex::new(receiver))
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.to_string()))?;
    match receiver
        .lock()
        .map_err(|_| io::Error::other("console input lock poisoned"))?
        .try_recv()
    {
        Ok(bytes) => Ok(Some(bytes)),
        Err(mpsc::TryRecvError::Empty) => Ok(None),
        Err(mpsc::TryRecvError::Disconnected) => Err(io::ErrorKind::UnexpectedEof.into()),
    }
}

fn copy(mut reader: impl Read, sender: mpsc::SyncSender<Vec<u8>>) -> io::Result<()> {
    let mut bytes = [0; CHUNK];
    loop {
        match reader.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                if sender.send(bytes[..count].to_vec()).is_err() {
                    return Ok(());
                }
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
        let writer = thread::spawn(move || copy(io::Cursor::new(sent), sender));
        let mut received = Vec::new();
        while let Ok(chunk) = receiver.recv() {
            assert!(chunk.len() <= CHUNK);
            received.extend_from_slice(&chunk);
        }
        writer.join().unwrap().unwrap();
        assert_eq!(received, bytes);
    }
}
