// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vhost-user's native-endian header. Native attachments are carried separately.

use dillo_machine::worker::MAX_MESSAGE;
use std::io;

pub const HEADER_LEN: usize = 12;
pub const VERSION: u32 = 1;
pub const REPLY: u32 = 1 << 2;
pub const NEED_REPLY: u32 = 1 << 3;

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
