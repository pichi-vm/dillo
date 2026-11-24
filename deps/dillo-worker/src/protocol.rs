// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use dillo_ipc::RamView;
use dillo_virtio::queue::Queue;
use vm_memory::{Address, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

pub(crate) const QUEUE_MAX: u16 = 256;
pub(crate) const CONFIG_LEN: usize = 48;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Init {
    pub version: u32,
    pub memory: Vec<RamView>,
    pub files: usize,
    pub backend: serde_json::Value,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Geometry {
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
}

impl Geometry {
    pub(crate) fn from_queue(queue: &Queue) -> Self {
        Self {
            size: queue.size,
            desc: queue.desc_table.raw_value(),
            avail: queue.avail_ring.raw_value(),
            used: queue.used_ring.raw_value(),
        }
    }

    pub(crate) fn into_queue(self, memory: &GuestMemoryMmap) -> std::io::Result<Queue> {
        let mut queue = Queue::new(QUEUE_MAX);
        queue.size = self.size;
        queue.ready = true;
        queue.desc_table = GuestAddress(self.desc);
        queue.avail_ring = GuestAddress(self.avail);
        queue.used_ring = GuestAddress(self.used);
        if !queue.is_valid(u64::MAX)
            || ![
                (self.desc, 16 * usize::from(self.size)),
                (self.avail, 6 + 2 * usize::from(self.size)),
                (self.used, 6 + 8 * usize::from(self.size)),
            ]
            .into_iter()
            .all(|(gpa, len)| memory.check_range(GuestAddress(gpa), len))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "queue lies outside exported RAM",
            ));
        }
        Ok(queue)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum Command {
    Activate {
        epoch: u64,
        features: u64,
        queue: Geometry,
    },
    Kick {
        epoch: u64,
    },
    Reset {
        epoch: u64,
    },
    Shutdown,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub id: u64,
    pub command: Command,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum Response {
    Ready { features: u64, config: Vec<u8> },
    Reply { id: u64, error: Option<String> },
    Used { epoch: u64 },
    Failed(String),
}
