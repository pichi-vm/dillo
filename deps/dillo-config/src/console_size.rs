// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Dillo's console-resize endpoint accepts columns then rows as two LE u16s.
//! Each connection sends one four-byte update; there is no response or backlog.

#![forbid(unsafe_code)]

use std::num::NonZeroU16;

/// A nonempty terminal size. The endpoint is a private caller–Dillo contract;
/// it is independent of any process monitor or guest command protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConsoleSize {
    pub cols: NonZeroU16,
    pub rows: NonZeroU16,
}

const _: () = assert!(std::mem::size_of::<ConsoleSize>() == 4);

impl TryFrom<(u16, u16)> for ConsoleSize {
    type Error = &'static str;

    fn try_from((cols, rows): (u16, u16)) -> Result<Self, Self::Error> {
        Ok(Self {
            cols: NonZeroU16::new(cols).ok_or("console columns must be nonzero")?,
            rows: NonZeroU16::new(rows).ok_or("console rows must be nonzero")?,
        })
    }
}

impl From<ConsoleSize> for [u8; 4] {
    fn from(size: ConsoleSize) -> Self {
        let cols = size.cols.get().to_le_bytes();
        let rows = size.rows.get().to_le_bytes();
        [cols[0], cols[1], rows[0], rows[1]]
    }
}

impl TryFrom<[u8; 4]> for ConsoleSize {
    type Error = &'static str;

    fn try_from(bytes: [u8; 4]) -> Result<Self, Self::Error> {
        (
            u16::from_le_bytes([bytes[0], bytes[1]]),
            u16::from_le_bytes([bytes[2], bytes[3]]),
        )
            .try_into()
    }
}
