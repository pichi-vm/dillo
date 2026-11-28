// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Temporary benchmark control. This module is absent from production builds.

use super::{Arc, Backing, File, VirtioDevice, io};

pub(super) fn selected(kind: u32) -> io::Result<bool> {
    let selected = match std::env::var("DILLO_BENCH_LOCAL").as_deref() {
        Err(std::env::VarError::NotPresent) => return Ok(false),
        Ok("block") => 2,
        Ok("net") => 1,
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    Ok(kind == selected)
}

pub(super) fn device<H: dillo_machine::worker::WorkerHost>(
    value: serde_json::Value,
    files: Vec<File>,
) -> io::Result<Box<dyn VirtioDevice>> {
    match serde_json::from_value(value.clone()).map_err(io::Error::other)? {
        Backing::Raw { .. } => super::device::<H>(None, value, files, None)
            .map(|b| Box::new(dillo_virtio::lifecycle::Local::new(b)) as Box<dyn VirtioDevice>),
        Backing::UserNet { mac, forwards } if files.is_empty() => {
            let backend = dillo_virtio_net::UserNetBackend::with_resources(
                forwards,
                Arc::new(dillo_virtio_net::HostNetwork),
            )?;
            Ok(Box::new(dillo_virtio_net::VirtioNet::new(
                mac,
                Arc::new(backend),
            )))
        }
        _ => Err(io::ErrorKind::Unsupported.into()),
    }
}
