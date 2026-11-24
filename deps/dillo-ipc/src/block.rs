// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use dillo_machine::worker::RamView;

pub const QUEUE_MAX: u16 = 256;
pub const CONFIG_LEN: usize = 48;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Init {
    pub version: u32,
    pub memory: Vec<RamView>,
    pub files: usize,
    pub backend: serde_json::Value,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Geometry {
    pub size: u16,
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum Command {
    Activate {
        epoch: u64,
        features: u64,
        queue: Geometry,
        native_kick: bool,
    },
    Kick {
        epoch: u64,
    },
    Reset {
        epoch: u64,
    },
    Quiesce {
        epoch: u64,
    },
    Resume {
        epoch: u64,
    },
    Shutdown,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: u64,
    pub command: Command,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum Response {
    Ready { features: u64, config: Vec<u8> },
    Reply { id: u64, error: Option<String> },
    Used { epoch: u64 },
    Failed(String),
}
