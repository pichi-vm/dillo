// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Filesystem helpers.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Atomic whole-file replacement, as an extension method on [`Path`].
pub(crate) trait AtomicWrite {
    /// Write `bytes` to a sibling temp file and rename it over `self`, so a
    /// reader never observes a half-written file. The temp lives in the
    /// destination's own directory to keep the rename on one filesystem.
    fn atomic_write(&self, bytes: &[u8]) -> Result<()>;
}

impl AtomicWrite for Path {
    fn atomic_write(&self, bytes: &[u8]) -> Result<()> {
        let dir = self
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let tmp_name = format!(
            ".{}.arma.tmp",
            self.file_name()
                .map_or_else(|| "out".to_string(), |n| n.to_string_lossy().into_owned())
        );
        let tmp = dir.join(tmp_name);
        fs::write(&tmp, bytes).with_context(|| format!("write tmp: {}", tmp.display()))?;
        fs::rename(&tmp, self)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.display()))?;
        Ok(())
    }
}
