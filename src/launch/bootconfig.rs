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
    pub(super) zero_prefix: u64,
}

impl Reservation {
    /// Read the input once and retain its framed bytes for reboot replay.
    pub(super) fn read(capacity: u64, path: Option<&Path>) -> Result<Self, Error> {
        let capacity = usize::try_from(capacity).map_err(|_| Error::Bounds)?;
        // One extra byte detects oversized input while bounding the read.
        let limit = capacity.checked_add(1).ok_or(Error::Bounds)?;
        let mut bytes = Vec::new();
        if let Some(path) = path {
            let read_error = |source| Error::Read {
                path: path.to_path_buf(),
                source,
            };
            File::open(path)
                .map_err(read_error)?
                .take(limit as u64)
                .read_to_end(&mut bytes)
                .map_err(read_error)?;
        }
        let zero_prefix = if bytes.is_empty() {
            capacity
        } else {
            Self::frame(&mut bytes, capacity)?
        };
        Ok(Self {
            bytes,
            zero_prefix: zero_prefix as u64,
        })
    }

    fn frame(bytes: &mut Vec<u8>, capacity: usize) -> Result<usize, Error> {
        // Include the terminating NUL and pad to Linux's four-byte alignment.
        // Only wire-field and reservation bounds apply here, not parser limits.
        let size = bytes.len().checked_add(4).ok_or(Error::Bounds)? & !3;
        let wire_size = u32::try_from(size).map_err(|_| Error::Bounds)?;
        let frame_size = size.checked_add(FOOTER_SIZE).ok_or(Error::Bounds)?;
        let zero_prefix = capacity.checked_sub(frame_size).ok_or(Error::Bounds)?;
        if !capacity.is_multiple_of(4) {
            return Err(Error::Bounds);
        }
        let checksum = bytes
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
        bytes.try_reserve_exact(frame_size - bytes.len())?;
        bytes.resize(size, 0);
        bytes.extend_from_slice(&wire_size.to_le_bytes());
        bytes.extend_from_slice(&checksum.to_le_bytes());
        bytes.extend_from_slice(MAGIC);
        Ok(zero_prefix)
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
            let reservation = read(text, 4096).unwrap();
            let bytes = reservation.bytes;
            assert_eq!(bytes, read(text, 4096).unwrap().bytes);
            assert_eq!(reservation.zero_prefix + bytes.len() as u64, 4096);
            let footer = bytes.len() - FOOTER_SIZE;
            assert_eq!(&bytes[footer + 8..], MAGIC);
            let size = u32::from_le_bytes(bytes[footer..footer + 4].try_into().unwrap()) as usize;
            assert_eq!(size, (text.len() + 4) & !3);
            assert_eq!(size, footer);
            assert_eq!(&bytes[..text.len()], text);
            assert!(bytes[text.len()..footer].iter().all(|b| *b == 0));
            assert_eq!(
                u32::from_le_bytes(bytes[footer + 4..footer + 8].try_into().unwrap()),
                text.iter().map(|b| u32::from(*b)).sum::<u32>()
            );
        }
    }

    #[test]
    fn empty_is_zero_and_explicit_unreadable_input_is_an_error() {
        for capacity in [1, 23, 4096, 4 * 1024 * 1024] {
            for reservation in [
                Reservation::read(capacity, None).unwrap(),
                read(b"", capacity).unwrap(),
            ] {
                assert_eq!(reservation.zero_prefix, capacity);
                assert!(reservation.bytes.is_empty());
            }
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
    }

    #[test]
    fn checksum_wraps_at_native_field_width() {
        let text = vec![255; (u32::MAX as u64 / 255 + 2) as usize];
        let capacity = (text.len() + 4 + FOOTER_SIZE + 3) & !3;
        let bytes = read(&text, capacity as u64).unwrap().bytes;
        let end = bytes.len();
        let checksum = u32::from_le_bytes(bytes[end - 16..end - 12].try_into().unwrap());
        assert_eq!(checksum, 509);
    }
}
