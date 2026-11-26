// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Versioned worker controls over Machine-owned channels and resources.

use dillo_machine::worker::{MAX_MESSAGE, Message};
use std::io;

pub mod block;
pub mod vhost_user;

pub fn decode<T: serde::de::DeserializeOwned>(message: &Message) -> io::Result<T> {
    serde_json::from_slice(&message.bytes).map_err(io::Error::other)
}

pub fn encode(value: &impl serde::Serialize) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker message too large",
        ));
    }
    Ok(bytes)
}
