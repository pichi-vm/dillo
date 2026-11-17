// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Read, Seek};

/// A launch file read once and retained independently of its original file.
/// This host currently uses owned memory; no source-file reread is permitted.
pub struct CapturedLaunchInput {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for CapturedLaunchInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedLaunchInput")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl dillo_machine::LaunchInput for CapturedLaunchInput {
    type View<'a> = &'a [u8];

    fn capture(mut source: File) -> io::Result<Self> {
        let len = source.metadata()?.len();
        let capacity = usize::try_from(len)
            .map_err(|_| io::Error::other("launch input exceeds host address space"))?;
        source.rewind()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        source.take(len).read_to_end(&mut bytes)?;
        if bytes.len() != capacity {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "launch input truncated during capture",
            ));
        }
        Ok(Self { bytes })
    }

    fn view(&self) -> io::Result<Self::View<'_>> {
        Ok(&self.bytes)
    }
}
