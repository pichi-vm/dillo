// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vhost-user's native-endian header. Native attachments are carried separately.

use dillo_machine::worker::MAX_MESSAGE;
use std::io;

pub const HEADER_LEN: usize = 12;
pub const VERSION: u32 = 1;
pub const REPLY: u32 = 1 << 2;
pub const NEED_REPLY: u32 = 1 << 3;

pub const PROTOCOL_FEATURES: u64 = 1 << 30;
pub const MQ: u64 = 1 << 0;
pub const REPLY_ACK: u64 = 1 << 3;
pub const CONFIG: u64 = 1 << 9;
pub const RESET_DEVICE: u64 = 1 << 13;
pub const CONFIGURE_MEM_SLOTS: u64 = 1 << 15;
pub const GPA_ADDRESSES: u64 = 1 << 21;

// Unassigned experimental values, confined to the MMIO measurement branch.
pub const EXPERIMENT_SHARED_ISR: u64 = 1 << 63;
pub const EXPERIMENT_SET_ISR: u32 = 0xffff_0001;

pub mod request {
    pub const GET_FEATURES: u32 = 1;
    pub const SET_FEATURES: u32 = 2;
    pub const SET_OWNER: u32 = 3;
    pub const RESET_OWNER: u32 = 4;
    pub const SET_MEM_TABLE: u32 = 5;
    pub const SET_VRING_NUM: u32 = 8;
    pub const SET_VRING_ADDR: u32 = 9;
    pub const SET_VRING_BASE: u32 = 10;
    pub const GET_VRING_BASE: u32 = 11;
    pub const SET_VRING_KICK: u32 = 12;
    pub const SET_VRING_CALL: u32 = 13;
    pub const SET_VRING_ERR: u32 = 14;
    pub const GET_PROTOCOL_FEATURES: u32 = 15;
    pub const SET_PROTOCOL_FEATURES: u32 = 16;
    pub const GET_QUEUE_NUM: u32 = 17;
    pub const SET_VRING_ENABLE: u32 = 18;
    pub const GET_CONFIG: u32 = 24;
    pub const SET_CONFIG: u32 = 25;
    pub const RESET_DEVICE: u32 = 34;
    pub const GET_MAX_MEM_SLOTS: u32 = 36;
    pub const ADD_MEM_REG: u32 = 37;
    pub const REM_MEM_REG: u32 = 38;
}

pub fn state(index: u32, value: u32) -> Vec<u8> {
    [index, value]
        .into_iter()
        .flat_map(u32::to_ne_bytes)
        .collect()
}

pub fn take_u32(bytes: &mut &[u8]) -> io::Result<u32> {
    let (value, rest) = bytes
        .split_at_checked(4)
        .ok_or(io::ErrorKind::InvalidData)?;
    *bytes = rest;
    Ok(u32::from_ne_bytes(value.try_into().unwrap()))
}

pub fn take_u64(bytes: &mut &[u8]) -> io::Result<u64> {
    let (value, rest) = bytes
        .split_at_checked(8)
        .ok_or(io::ErrorKind::InvalidData)?;
    *bytes = rest;
    Ok(u64::from_ne_bytes(value.try_into().unwrap()))
}

pub fn scalar(bytes: &[u8]) -> io::Result<u64> {
    bytes
        .try_into()
        .map(u64::from_ne_bytes)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub request: u32,
    pub flags: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn request(request: u32, payload: Vec<u8>) -> Self {
        Self {
            request,
            flags: VERSION,
            payload,
        }
    }

    #[must_use]
    pub fn reply(&self, payload: Vec<u8>) -> Self {
        Self {
            request: self.request,
            flags: VERSION | REPLY,
            payload,
        }
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < HEADER_LEN || bytes.len() > MAX_MESSAGE {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let request = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
        let flags = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        let size = u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if flags & 3 != VERSION
            || flags & !(3 | REPLY | NEED_REPLY) != 0
            || size != bytes.len() - HEADER_LEN
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self {
            request,
            flags,
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.payload.len() > MAX_MESSAGE - HEADER_LEN {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.payload.len());
        bytes.extend(self.request.to_ne_bytes());
        bytes.extend(self.flags.to_ne_bytes());
        bytes.extend((self.payload.len() as u32).to_ne_bytes());
        bytes.extend(&self.payload);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_features_wire_message() {
        let request = Frame::request(1, Vec::new());
        let wire = [1u32, 1, 0]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect::<Vec<_>>();
        assert_eq!(request.encode().unwrap(), wire);
        let reply = request.reply((1u64 << 32).to_ne_bytes().to_vec());
        assert_eq!(Frame::decode(&reply.encode().unwrap()).unwrap(), reply);
    }

    #[test]
    fn reject_invalid_header_and_extent() {
        for words in [[1u32, 0, 0], [1, 17, 0], [1, 1, 8], [1, 1, u32::MAX]] {
            let wire = words
                .into_iter()
                .flat_map(u32::to_ne_bytes)
                .collect::<Vec<_>>();
            assert!(Frame::decode(&wire).is_err());
        }
        assert!(Frame::decode(&[0; 11]).is_err());
        assert!(Frame::request(1, vec![0; MAX_MESSAGE]).encode().is_err());
    }
}
