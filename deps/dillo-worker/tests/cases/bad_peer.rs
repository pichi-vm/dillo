// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Alter protocol replies on the actual connection after confinement.

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use dillo_machine::worker::{
    BorrowedResource, Channel, MemoryExport, Message, NotificationRole, Policy, Process, Resource,
    WorkerHost, WriteNotification,
};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsHandle;

static MODE: OnceLock<&str> = OnceLock::new();
static RETURNED: OnceLock<File> = OnceLock::new();

pub(super) fn configure(mode: &str, files: &mut Vec<File>) -> bool {
    let mode = match mode {
        "bad-flags" => "bad-flags",
        "bad-request" => "bad-request",
        "no-shared-isr" => "no-shared-isr",
        "reply-resource" => {
            RETURNED.set(files.remove(0)).unwrap();
            "reply-resource"
        }
        _ => return false,
    };
    MODE.set(mode).unwrap();
    mode != "no-shared-isr"
}

#[derive(Debug)]
struct Peer(Box<dyn Channel>);

impl Channel for Peer {
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()> {
        let mut bytes = bytes.to_vec();
        match MODE.get().copied() {
            Some("bad-flags") => bytes[4..8].copy_from_slice(&0u32.to_ne_bytes()),
            Some("bad-request") => bytes[..4].copy_from_slice(&u32::MAX.to_ne_bytes()),
            Some("no-shared-isr") => {
                use dillo_ipc::vhost_user::{self as wire, Frame};
                let mut frame = Frame::decode(&bytes)?;
                if frame.request == wire::request::GET_PROTOCOL_FEATURES {
                    frame.payload = (wire::scalar(&frame.payload)? & !wire::EXPERIMENT_SHARED_ISR)
                        .to_ne_bytes()
                        .to_vec();
                    bytes = frame.encode()?;
                }
            }
            Some("reply-resource") => {
                #[cfg(unix)]
                let resource = RETURNED.get().unwrap().as_fd();
                #[cfg(windows)]
                let resource = RETURNED.get().unwrap().as_handle();
                return self.0.send(&bytes, &[resource]);
            }
            _ => {}
        }
        self.0.send(&bytes, resources)
    }
    fn receive(&mut self) -> io::Result<Message> {
        self.0.receive()
    }
    fn try_clone(&self) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Self(self.0.try_clone()?)))
    }
}

pub(super) struct Host;

impl WorkerHost for Host {
    #[allow(unsafe_code)]
    unsafe fn adopt_notification_state(
        resource: Resource,
    ) -> io::Result<Arc<dillo_machine::worker::NotificationState>> {
        // SAFETY: the fixture forwards its parent's private atomic status grant.
        unsafe { super::Worker::adopt_notification_state(resource) }
    }

    fn import_socket(message: Message) -> io::Result<dillo_machine::worker::Socket> {
        super::Worker::import_socket(message)
    }
    fn spawn(_: &Path, _: Policy) -> io::Result<(Box<dyn Process>, Box<dyn Channel>)> {
        Err(io::ErrorKind::Unsupported.into())
    }
    #[allow(unsafe_code)]
    unsafe fn bootstrap() -> io::Result<Box<dyn Channel>> {
        // SAFETY: this fixture keeps the native host's dedicated entry contract.
        unsafe { super::Worker::bootstrap() }
    }
    fn channel(resource: Resource) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Peer(super::Worker::channel(resource)?)))
    }
    #[allow(unsafe_code)]
    unsafe fn map_memory(memory: MemoryExport) -> io::Result<vm_memory::GuestMemoryMmap> {
        // SAFETY: the fixture passes through the caller's stable RAM grant.
        unsafe { super::Worker::map_memory(memory) }
    }
    fn notification_endpoint(
        resource: Resource,
        role: NotificationRole,
    ) -> io::Result<Arc<dyn WriteNotification>> {
        super::Worker::notification_endpoint(resource, role)
    }
    fn confine(files: &[BorrowedResource<'_>], policy: Policy) -> io::Result<()> {
        super::Worker::confine(files, policy)
    }
}
