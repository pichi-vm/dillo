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
    Console {
        ports: Vec<Port>,
        resize: bool,
    },
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
pub(crate) struct Port {
    pub name: String,
    pub rx: bool,
    pub tx: bool,
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
        Backing::Console { ports, resize } => {
            use dillo_virtio_console::{
                NamedPort, VirtioConsole,
                pipe::{Direction, PipeEnd},
            };
            if files.len()
                != 2 + usize::from(resize)
                    + ports
                        .iter()
                        .map(|p| usize::from(p.rx) + usize::from(p.tx))
                        .sum::<usize>()
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut files = files.into_iter();
            dillo_virtio_console::worker_stdio(files.next().unwrap(), files.next().unwrap());
            let size_pipe = resize.then(|| files.next().unwrap());
            let ports = ports
                .into_iter()
                .map(|port| {
                    let rx = port.rx.then(|| {
                        PipeEnd::from_file(&port.name, Direction::Rx, files.next().unwrap())
                    });
                    let tx = port.tx.then(|| {
                        PipeEnd::from_file(&port.name, Direction::Tx, files.next().unwrap())
                    });
                    NamedPort::new(port.name, rx, tx)
                })
                .collect();
            let console = VirtioConsole::with_ports(ports);
            return Ok(Box::new(if let Some(pipe) = size_pipe {
                console.with_size_pipe(pipe)
            } else {
                console
            }));
        }
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
                    path: std::path::PathBuf::new(),
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
    Process(dillo_worker::Prepared),
}

impl Device {
    pub(crate) fn num_queues(&self) -> usize {
        match self {
            Self::Local(device) => device.num_queues(),
            Self::Process(prepared) => prepared.num_queues(),
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
            Self::Process(prepared) => {
                let (proxy, control) =
                    prepared.start::<M::Worker>(machine.worker_memory()?, move || {
                        shutdown.store(true, std::sync::atomic::Ordering::Release);
                    })?;
                controls.push(control);
                Ok(Box::new(proxy))
            }
        }
    }
}

pub(crate) fn block_info() -> dillo_worker::DeviceInfo {
    dillo_worker::DeviceInfo {
        kind: 2,
        queues: vec![256],
        config_len: 48,
    }
}
