// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Materialize a native Linux bootconfig reservation. Linux owns text parsing.

use std::{fs::File, io::Read, path::Path};
use thiserror::Error;

const MAGIC: &[u8; 12] = b"#BOOTCONFIG\n";
const FOOTER_SIZE: usize = 8 + MAGIC.len();

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("--bootconfig supplied without a lbc:bootconfig fill")]
    Undeclared,

    #[error("bootconfig does not fit the reservation or native framing bounds")]
    Bounds,

    #[error("allocate bootconfig reservation: {0}")]
    Allocate(#[from] std::collections::TryReserveError),

    #[error("read bootconfig {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

pub(super) struct Reservation {
    pub(super) bytes: Vec<u8>,
}

impl Reservation {
    /// Snapshot the input once, after PMI memory bounds have been validated.
    /// The complete buffer is retained as a launch write for reboot replay.
    pub(super) fn read(capacity: u64, path: Option<&Path>) -> Result<Self, Error> {
        let capacity = usize::try_from(capacity).map_err(|_| Error::Bounds)?;
        // One extra byte detects oversized input without reading an unbounded
        // file. Use the reservation itself as the read buffer, then move the
        // text to its final position without a second allocation.
        let limit = capacity.checked_add(1).ok_or(Error::Bounds)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(limit)?;
        bytes.resize(limit, 0);
        let len = if let Some(path) = path {
            let read_error = |source| Error::Read {
                path: path.to_path_buf(),
                source,
            };
            let mut file = File::open(path).map_err(read_error)?.take(limit as u64);
            std::io::copy(&mut file, &mut bytes.as_mut_slice()).map_err(read_error)? as usize
        } else {
            0
        };
        bytes.truncate(capacity);
        Self::frame(&mut bytes, len)?;
        Ok(Self { bytes })
    }

    fn frame(bytes: &mut [u8], len: usize) -> Result<(), Error> {
        if len == 0 {
            return Ok(());
        }
        // Include the terminating NUL and pad to Linux's four-byte alignment.
        // Only wire-field and reservation bounds apply here, not parser limits.
        let size = len.checked_add(4).ok_or(Error::Bounds)? & !3;
        let wire_size = u32::try_from(size).map_err(|_| Error::Bounds)?;
        let footer = bytes.len().checked_sub(FOOTER_SIZE).ok_or(Error::Bounds)?;
        let start = footer.checked_sub(size).ok_or(Error::Bounds)?;
        if !bytes.len().is_multiple_of(4) {
            return Err(Error::Bounds);
        }
        let checksum = bytes[..len]
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
        bytes.copy_within(..len, start);
        bytes[..start].fill(0);
        bytes[footer..footer + 4].copy_from_slice(&wire_size.to_le_bytes());
        bytes[footer + 4..footer + 8].copy_from_slice(&checksum.to_le_bytes());
        bytes[footer + 8..].copy_from_slice(MAGIC);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &[u8], capacity: u64) -> Result<Reservation, Error> {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), text).unwrap();
        Reservation::read(capacity, Some(file.path()))
    }

    #[test]
    fn native_frame_preserves_bytes_and_zero_slack() {
        for text in [
            b"a".as_slice(),
            b"a=",
            b"a=x",
            b"a=x;",
            b"invalid } syntax\0hidden",
        ] {
            let bytes = read(text, 4096).unwrap().bytes;
            assert_eq!(bytes, read(text, 4096).unwrap().bytes);
            assert_eq!(&bytes[4084..], MAGIC);
            let size = u32::from_le_bytes(bytes[4076..4080].try_into().unwrap()) as usize;
            assert_eq!(size, (text.len() + 4) & !3);
            let start = 4076 - size;
            assert_eq!(&bytes[start..start + text.len()], text);
            assert!(bytes[..start].iter().all(|b| *b == 0));
            assert!(bytes[start + text.len()..4076].iter().all(|b| *b == 0));
            assert_eq!(
                u32::from_le_bytes(bytes[4080..4084].try_into().unwrap()),
                text.iter().map(|b| u32::from(*b)).sum::<u32>()
            );
        }
    }

    #[test]
    fn empty_is_zero_and_explicit_unreadable_input_is_an_error() {
        for capacity in [1, 23, 4096, 4 * 1024 * 1024] {
            let absent = Reservation::read(capacity, None).unwrap().bytes;
            assert_eq!(absent.len() as u64, capacity);
            assert!(absent.iter().all(|b| *b == 0));
            assert_eq!(absent, read(b"", capacity).unwrap().bytes);
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Reservation::read(4096, Some(&dir.path().join("missing"))),
            Err(Error::Read { .. })
        ));
    }

    #[test]
    fn framing_bounds_are_independent_of_linux_parser_limits() {
        assert!(read(&vec![b'x'; 4075], 4096).is_ok());
        assert!(matches!(read(&vec![b'x'; 4076], 4096), Err(Error::Bounds)));
        assert!(matches!(read(&vec![b'x'; 8192], 4096), Err(Error::Bounds)));
        for capacity in [0, 20, 23, 4095] {
            assert!(matches!(read(b"a", capacity), Err(Error::Bounds)));
        }
        let text = vec![b'x'; 65536];
        assert!(read(&text, 128 * 1024).is_ok());
        assert!(read(&text, 4 * 1024 * 1024).is_ok());
        assert!(matches!(
            Reservation::frame(&mut [0; 24], usize::MAX),
            Err(Error::Bounds)
        ));
    }

    #[test]
    fn checksum_wraps_at_native_field_width() {
        let text = vec![255; (u32::MAX as u64 / 255 + 2) as usize];
        let capacity = (text.len() + 4 + FOOTER_SIZE + 3) & !3;
        let bytes = read(&text, capacity as u64).unwrap().bytes;
        let checksum = u32::from_le_bytes(bytes[capacity - 16..capacity - 12].try_into().unwrap());
        assert_eq!(checksum, 509);
    }
}
