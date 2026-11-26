// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Private native-resource grants, separate from the vhost-user connection.

use std::io;

use dillo_machine::worker::{Channel, Message};

const MAGIC: u32 = u32::from_ne_bytes(*b"DGR1");

fn header(status: i32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12 + payload.len());
    bytes.extend(MAGIC.to_ne_bytes());
    bytes.extend(status.to_ne_bytes());
    bytes.extend((payload.len() as u32).to_ne_bytes());
    bytes.extend(payload);
    bytes
}

fn decode(message: &mut Message) -> io::Result<i32> {
    let bytes = &message.bytes;
    if bytes.len() < 12
        || bytes[..4] != MAGIC.to_ne_bytes()
        || u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len() - 12
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let status = i32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    message.bytes.drain(..12);
    Ok(status)
}

/// A single resource authority selected by the launcher. Requests carry no
/// guest memory and cannot select a different service or native process.
#[derive(Debug)]
pub struct Client(Box<dyn Channel>);

impl Client {
    pub(crate) fn new(channel: Box<dyn Channel>) -> Self {
        Self(channel)
    }

    /// Adopt the returned native objects before acknowledging their transfer.
    pub fn request<T>(
        &mut self,
        payload: &[u8],
        adopt: impl FnOnce(Message) -> io::Result<T>,
    ) -> io::Result<T> {
        self.0.send(&header(0, payload), &[])?;
        let mut message = self.0.receive()?;
        let status = decode(&mut message)?;
        let result = if status == 0 {
            adopt(message)
        } else {
            if !message.resources.is_empty() || !message.bytes.is_empty() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Err(io::Error::from_raw_os_error(status))
        };
        self.0.send(&header(0, &[]), &[])?;
        result
    }
}

pub(crate) type Service = Box<dyn FnMut(&[u8]) -> io::Result<Message> + Send>;

pub(crate) fn serve(mut channel: Box<dyn Channel>, mut service: Service) -> io::Result<()> {
    loop {
        let mut request = channel.receive()?;
        if decode(&mut request)? != 0 || !request.resources.is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (status, response) = match service(&request.bytes) {
            Ok(response) => (0, response),
            Err(error) => (
                error.raw_os_error().unwrap_or(-1),
                Message {
                    bytes: Vec::new(),
                    resources: Vec::new(),
                },
            ),
        };
        let resources = super::parent::borrow_resources(&response.resources);
        channel.send(&header(status, &response.bytes), &resources)?;
        // Keep the grant alive until its receiver has adopted it. In particular,
        // Darwin may collect a Unix socket held only by in-flight SCM_RIGHTS.
        let mut ack = channel.receive()?;
        if decode(&mut ack)? != 0 || !ack.bytes.is_empty() || !ack.resources.is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
}
