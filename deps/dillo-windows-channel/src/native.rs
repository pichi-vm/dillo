// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Owned ports and resource adoption at the private Windows native boundary.
#![allow(unsafe_code)]

use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::sync::{Arc, Mutex};
use std::{ffi::c_void, io, ptr, slice};
use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE,
    SECTION_MAP_READ, SECTION_QUERY, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, SetEvent};

use super::{Address, MAX_MESSAGE, MAX_RESOURCES, Message};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Header {
    length: u16,
    total: u16,
    kind: u16,
    offset: u16,
    client: [usize; 2],
    id: u32,
    padding: u32,
    callback: usize,
}
#[repr(C)]
struct Packet {
    header: Header,
    bytes: [u8; MAX_MESSAGE],
    handles: [HANDLE; MAX_RESOURCES],
    count: u32,
    context: usize,
    attached: u32,
}

unsafe extern "C" {
    fn wm_process_sid(process: HANDLE, sid: *mut *mut u8, length: *mut u32) -> u32;
    fn wm_peer_sid(port: HANDLE, header: *mut Header, sid: *mut *mut u8, length: *mut u32) -> u32;
    fn wm_free(value: *mut c_void);
    fn wm_listen(name: *const u16, sid: *const u8, length: u32, port: *mut HANDLE) -> u32;
    fn wm_connect(name: *const u16, port: *mut HANDLE) -> u32;
    fn wm_accept(
        port: HANDLE,
        header: *mut Header,
        context: usize,
        allow: u8,
        peer: *mut HANDLE,
    ) -> u32;
    fn wm_disconnect(port: HANDLE);
    fn wm_send(
        port: HANDLE,
        bytes: *const u8,
        size: u32,
        handles: *const HANDLE,
        count: u32,
    ) -> u32;
    fn wm_receive(port: HANDLE, stopped: HANDLE, packet: *mut Packet) -> u32;
}

fn check(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.cast_signed()))
    }
}
fn bool_result(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn sid(query: impl FnOnce(*mut *mut u8, *mut u32) -> u32) -> io::Result<Vec<u8>> {
    let mut bytes = ptr::null_mut();
    let mut len = 0;
    let status = query(&raw mut bytes, &raw mut len);
    // SAFETY: the native query supplies a bounded SID allocation on success;
    // any output allocation is released on both success and failure.
    unsafe {
        let value = if status == 0 {
            slice::from_raw_parts(bytes, len as usize).to_vec()
        } else {
            Vec::new()
        };
        wm_free(bytes.cast());
        check(status)?;
        Ok(value)
    }
}

pub(super) fn identity(process: BorrowedHandle<'_>) -> io::Result<Vec<u8>> {
    // SAFETY: the process is borrowed only for querying its token.
    sid(|bytes, len| unsafe { wm_process_sid(process.as_raw_handle(), bytes, len) })
}

fn endpoint(address: &Address) -> io::Result<Vec<u16>> {
    let name = &address.endpoint;
    if name.is_empty()
        || name.len() > 63
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(name.encode_utf16().chain(Some(0)).collect())
}

#[derive(Debug)]
pub(super) struct Event(OwnedHandle);
impl Event {
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: creates one unnamed, noninheritable manual-reset event.
        unsafe {
            let handle = CreateEventW(ptr::null(), 1, 0, ptr::null());
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(OwnedHandle::from_raw_handle(handle)))
        }
    }
    pub(super) fn set(&self) {
        // SAFETY: the event remains owned throughout the call.
        unsafe {
            SetEvent(self.0.as_raw_handle());
        }
    }
}

#[derive(Debug)]
pub(super) struct Port {
    handle: Mutex<Option<Arc<OwnedHandle>>>,
    stopped: Option<Event>,
}

pub(super) enum Received {
    Connect(Header, bool),
    Data(usize, Message),
    Closed(usize),
    Cancelled,
}

impl Port {
    fn new(handle: OwnedHandle, waitable: bool) -> io::Result<Self> {
        Ok(Self {
            handle: Mutex::new(Some(Arc::new(handle))),
            stopped: waitable.then(Event::new).transpose()?,
        })
    }
    fn handle(&self) -> io::Result<Arc<OwnedHandle>> {
        self.handle
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
    pub(super) fn listen(address: &Address, identity: &[u8]) -> io::Result<Self> {
        let name = endpoint(address)?;
        let mut handle = ptr::null_mut();
        let len = u32::try_from(identity.len()).map_err(io::Error::other)?;
        // SAFETY: the native boundary validates the SID extent before SID APIs,
        // copies the name/ACL and returns a newly owned port.
        unsafe {
            check(wm_listen(
                name.as_ptr(),
                identity.as_ptr(),
                len,
                &raw mut handle,
            ))?;
            Self::new(OwnedHandle::from_raw_handle(handle), true)
        }
    }
    pub(super) fn connect(address: &Address) -> io::Result<Self> {
        let name = endpoint(address)?;
        let mut handle = ptr::null_mut();
        // SAFETY: a bounded, terminated name; successful output is newly owned.
        unsafe {
            check(wm_connect(name.as_ptr(), &raw mut handle))?;
            Self::new(OwnedHandle::from_raw_handle(handle), true)
        }
    }
    pub(super) fn peer_identity(&self, header: &mut Header) -> io::Result<Vec<u8>> {
        let handle = self.handle()?;
        // SAFETY: the header is an unmodified kernel connection request on this
        // listener. Native code queries only that sender's process identity.
        sid(|bytes, len| unsafe { wm_peer_sid(handle.as_raw_handle(), header, bytes, len) })
    }
    pub(super) fn accept(
        &self,
        header: &mut Header,
        context: usize,
        allow: bool,
    ) -> io::Result<Option<Self>> {
        let listener = self.handle()?;
        let mut handle = ptr::null_mut();
        // SAFETY: the request came from this port. The numeric context is never
        // dereferenced; it is returned only for routing this accepted peer.
        unsafe {
            check(wm_accept(
                listener.as_raw_handle(),
                header,
                context,
                u8::from(allow),
                &raw mut handle,
            ))?;
            allow
                .then(|| Self::new(OwnedHandle::from_raw_handle(handle), false))
                .transpose()
        }
    }
    pub(super) fn disconnect(&self) {
        if let Some(stopped) = &self.stopped {
            stopped.set();
        }
        if let Some(handle) = self.handle.lock().unwrap().take() {
            // SAFETY: disconnection interrupts local operations. Each in-flight
            // call retains the handle, so closing it cannot race handle reuse.
            // Final close also notifies the peer, even while Session lives on.
            unsafe {
                wm_disconnect(handle.as_raw_handle());
            }
        }
    }
    pub(super) fn send(&self, bytes: &[u8], handles: &[BorrowedHandle<'_>]) -> io::Result<()> {
        if bytes.len() > MAX_MESSAGE || handles.len() > MAX_RESOURCES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let handle = self.handle()?;
        let handles: Vec<_> = handles.iter().map(AsRawHandle::as_raw_handle).collect();
        // SAFETY: inputs remain borrowed for the call; the kernel retains its
        // transfer references independently before successful return.
        unsafe {
            check(wm_send(
                handle.as_raw_handle(),
                bytes.as_ptr(),
                bytes.len() as u32,
                handles.as_ptr(),
                handles.len() as u32,
            ))
        }
    }
    pub(super) fn receive(&self) -> io::Result<Received> {
        let stopped = self.stopped.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        let handle = self.handle()?;
        let mut packet = Box::<Packet>::new_uninit();
        // SAFETY: native code bounds lengths/counts, obtains owned handles, and
        // releases the native continuation. On error it closes partial imports.
        unsafe {
            let status = wm_receive(
                handle.as_raw_handle(),
                stopped.0.as_raw_handle(),
                packet.as_mut_ptr(),
            );
            // Native code initializes the output even on failure and closes
            // partial imports. A message-bound error retires only that peer.
            let packet = packet.assume_init();
            if status != 0 && packet.context != 0 {
                return Ok(Received::Closed(packet.context));
            }
            check(status)?;
            let resources = packet.handles[..packet.count as usize]
                .iter()
                .map(|h| OwnedHandle::from_raw_handle(*h))
                .collect();
            let message = Message {
                bytes: packet.bytes[..packet.header.length as usize].to_vec(),
                resources,
            };
            match packet.header.kind & 0xff {
                3 => Ok(Received::Data(packet.context, message)),
                10 => Ok(Received::Connect(
                    packet.header,
                    message.bytes.is_empty() && packet.attached == 0,
                )),
                5 | 6 => Ok(Received::Closed(packet.context)),
                12 => Ok(Received::Cancelled),
                _ if packet.context != 0 => Ok(Received::Closed(packet.context)),
                _ => Err(io::ErrorKind::InvalidData.into()),
            }
        }
    }
}

const DESCRIPTOR_SIZE: usize = 8 + 128;
const MAGIC: &[u8; 8] = b"WMALPC1\0";

pub(super) fn descriptor(address: &Address) -> io::Result<OwnedHandle> {
    let endpoint = endpoint(address)?;
    let mut bytes = [0u8; DESCRIPTOR_SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    for (out, value) in bytes[8..].as_chunks_mut::<2>().0.iter_mut().zip(endpoint) {
        out.copy_from_slice(&value.to_le_bytes());
    }
    // SAFETY: initialize before publishing only a read-only section handle.
    unsafe {
        let section = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            ptr::null(),
            PAGE_READWRITE,
            0,
            DESCRIPTOR_SIZE as u32,
            ptr::null(),
        );
        if section.is_null() {
            return Err(io::Error::last_os_error());
        }
        let section = OwnedHandle::from_raw_handle(section);
        let view = MapViewOfFile(
            section.as_raw_handle(),
            FILE_MAP_WRITE,
            0,
            0,
            DESCRIPTOR_SIZE,
        );
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), view.Value.cast(), bytes.len());
        UnmapViewOfFile(view);
        let mut read_only = ptr::null_mut();
        bool_result(DuplicateHandle(
            GetCurrentProcess(),
            section.as_raw_handle(),
            GetCurrentProcess(),
            &raw mut read_only,
            SECTION_MAP_READ | SECTION_QUERY,
            0,
            0,
        ))?;
        Ok(OwnedHandle::from_raw_handle(read_only))
    }
}

pub(super) fn read_descriptor(descriptor: BorrowedHandle<'_>) -> io::Result<Address> {
    let mut bytes = [0u8; DESCRIPTOR_SIZE];
    // SAFETY: use the OS to copy a potentially hostile section into owned
    // storage, including handling in-page faults before parsing its contents.
    unsafe {
        let view = MapViewOfFile(
            descriptor.as_raw_handle(),
            FILE_MAP_READ,
            0,
            0,
            DESCRIPTOR_SIZE,
        );
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        let result = bool_result(ReadProcessMemory(
            GetCurrentProcess(),
            view.Value,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            ptr::null_mut(),
        ));
        UnmapViewOfFile(view);
        result?;
    }
    if &bytes[..8] != MAGIC {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let units: Vec<_> = bytes[8..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect();
    let end = units
        .iter()
        .position(|v| *v == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    let address = Address {
        endpoint: String::from_utf16(&units[..end]).map_err(io::Error::other)?,
    };
    endpoint(&address)?;
    Ok(address)
}
