// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Standard vhost-user bytes with RPC-owned Windows resource attachments.

use std::io;
use std::os::windows::io::{AsHandle, OwnedHandle};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use dillo_machine::worker::{BorrowedResource, Channel, MAX_MESSAGE, Message};
use dillo_windows_channel::{Connection as NativeConnection, Listener};

const HEADER: usize = 12;

#[derive(Debug)]
struct Pending {
    listener: Mutex<Option<Listener>>,
    connection: OnceLock<io::Result<NativeConnection>>,
}

impl Pending {
    fn get(&self) -> io::Result<&NativeConnection> {
        self.connection
            .get_or_init(|| {
                self.listener
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .accept_timeout(Duration::from_secs(30))
            })
            .as_ref()
            .map_err(|error| {
                error.raw_os_error().map_or_else(
                    || io::Error::new(error.kind(), error.to_string()),
                    io::Error::from_raw_os_error,
                )
            })
    }
}

#[derive(Clone, Debug)]
enum Endpoint {
    Listening(Arc<Pending>),
    Connected(NativeConnection),
}

impl Endpoint {
    fn get(&self) -> io::Result<&NativeConnection> {
        match self {
            Self::Listening(pending) => pending.get(),
            Self::Connected(connection) => Ok(connection),
        }
    }
}

#[derive(Debug)]
struct Connection {
    endpoint: Endpoint,
    // Only the separate Winsock grant uses the supervised process identity.
    // RPC resource transfer never reads or writes a peer's handle table.
    backend: Option<Arc<OwnedHandle>>,
}

pub(super) fn pair(backend: Arc<OwnedHandle>) -> io::Result<(Box<dyn Channel>, OwnedHandle)> {
    let listener = Listener::bind(dillo_windows_channel::identity(backend.as_handle())?)?;
    let descriptor = listener.descriptor()?;
    Ok((
        Box::new(Connection {
            endpoint: Endpoint::Listening(Arc::new(Pending {
                listener: Mutex::new(Some(listener)),
                connection: OnceLock::new(),
            })),
            backend: Some(backend),
        }),
        descriptor,
    ))
}

pub(super) fn adopt(descriptor: OwnedHandle) -> io::Result<Box<dyn Channel>> {
    Ok(Box::new(Connection {
        endpoint: Endpoint::Connected(NativeConnection::connect(descriptor.as_handle())?),
        backend: None,
    }))
}

fn valid(bytes: &[u8]) -> bool {
    (HEADER..=MAX_MESSAGE).contains(&bytes.len())
        && u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize == bytes.len() - HEADER
}

impl Channel for Connection {
    fn share_socket(
        &self,
        socket: dillo_machine::worker::BorrowedSocket<'_>,
    ) -> io::Result<Message> {
        let peer = self.backend.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        super::socket::export(socket, peer.as_handle())
    }

    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()> {
        if !valid(bytes) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.endpoint.get()?.send(bytes, resources)
    }

    fn receive(&mut self) -> io::Result<Message> {
        let connection = self.endpoint.get()?;
        let message = connection.receive()?;
        if !valid(&message.bytes) {
            connection.shutdown();
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Message {
            bytes: message.bytes,
            resources: message.resources,
        })
    }

    fn try_clone(&self) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Self {
            endpoint: self.endpoint.clone(),
            backend: self.backend.clone(),
        }))
    }

    fn pair(&self) -> io::Result<(Box<dyn Channel>, OwnedHandle)> {
        pair(Arc::clone(
            self.backend.as_ref().ok_or(io::ErrorKind::Unsupported)?,
        ))
    }
}
