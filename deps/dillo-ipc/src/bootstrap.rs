// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Init {
    pub version: u32,
    pub files: usize,
    pub backend: serde_json::Value,
    pub policy: dillo_machine::worker::Policy,
}
