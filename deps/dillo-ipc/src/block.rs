// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

pub const QUEUE_MAX: u16 = 256;
pub const CONFIG_LEN: usize = 48;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Init {
    pub version: u32,
    pub files: usize,
    pub backend: serde_json::Value,
    pub policy: dillo_machine::worker::Policy,
}

#[derive(Clone, Debug, Default)]
pub struct Geometry {
    pub size: u16,
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
}
