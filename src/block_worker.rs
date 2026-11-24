// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The executable chooses backing implementations; workers receive open files.

use std::fs::File;
use std::io;
use std::sync::Arc;

use dillo_virtio::VirtioDevice;
use dillo_virtio_blk::{RawImageBacking, VirtioBlk};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum Backing {
    Raw {
        readonly: bool,
    },
    Qcow2 {
        readonly: bool,
    },
    Gpt {
        device_id: [u8; 20],
        disk_guid: [u8; 16],
        partitions: Vec<Partition>,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Partition {
    pub partuuid: [u8; 16],
    pub typeguid: [u8; 16],
    pub label: String,
    pub attrs: u64,
}

pub(crate) fn device(
    value: serde_json::Value,
    mut files: Vec<File>,
) -> io::Result<Box<dyn VirtioDevice>> {
    let backing: Backing = serde_json::from_value(value).map_err(io::Error::other)?;
    let device = match backing {
        Backing::Raw { readonly } => {
            if files.len() != 1 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            VirtioBlk::new(
                Arc::new(RawImageBacking::new(files.remove(0), readonly)?),
                readonly,
            )
        }
        Backing::Qcow2 { readonly } => {
            if files.len() != 1 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let storage = imago::file::File::from_open_file(
                files.remove(0),
                imago::StorageOpenOptions::new().write(!readonly),
            )?;
            VirtioBlk::new(
                Arc::new(dillo_storage::Qcow2Backing::open(storage, readonly)?),
                readonly,
            )
        }
        Backing::Gpt {
            device_id,
            disk_guid,
            partitions,
        } => {
            if files.len() != partitions.len() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let sizes = files
                .iter()
                .map(|file| file.metadata().map(|m| m.len()))
                .collect::<io::Result<Vec<_>>>()?;
            let specs = partitions
                .into_iter()
                .map(|part| dillo_virtio_gpt::PartitionSpec {
                    path: Default::default(),
                    partuuid: uuid::Uuid::from_bytes(part.partuuid),
                    typeguid: uuid::Uuid::from_bytes(part.typeguid),
                    label: part.label,
                    attrs: part.attrs,
                })
                .collect::<Vec<_>>();
            let synth = dillo_virtio_gpt::build(&specs, &sizes, device_id, disk_guid)
                .map_err(io::Error::other)?;
            VirtioBlk::new(
                Arc::new(dillo_virtio_gpt::VgptBacking::new(files, synth, device_id)),
                true,
            )
        }
    };
    Ok(Box::new(device))
}

pub(crate) enum Device {
    Local(Box<dyn VirtioDevice>),
    Block(dillo_worker::Prepared),
}

impl Device {
    pub(crate) fn num_queues(&self) -> usize {
        match self {
            Self::Local(device) => device.num_queues(),
            Self::Block(_) => 1,
        }
    }

    pub(crate) fn bind<M: dillo_machine::Machine>(
        self,
        machine: &M,
        controls: &mut Vec<dillo_worker::Control>,
        shutdown: &'static std::sync::atomic::AtomicBool,
    ) -> io::Result<Box<dyn VirtioDevice>> {
        match self {
            Self::Local(device) => Ok(device),
            Self::Block(prepared) => {
                let (proxy, control) = prepared.start::<crate::machine::worker::Worker>(
                    machine.worker_memory()?,
                    move || {
                        shutdown.store(true, std::sync::atomic::Ordering::Release);
                    },
                )?;
                controls.push(control);
                Ok(Box::new(proxy))
            }
        }
    }
}
