// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The native boundary. RPC stubs supply bounded packets and keep borrowed input
//! handles live through callbacks. Output arrays use the stub's allocator.
#![allow(unsafe_code)]

use std::os::windows::io::{
    AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
};
use std::sync::{OnceLock, RwLock};
use std::{ffi::c_void, io, mem::size_of, ptr, slice};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

use super::{Envelope, Id, MAX_MESSAGE, MAX_RESOURCES};

#[repr(C)]
struct Resource {
    kind: u32,
    handle: HANDLE,
}
#[repr(C)]
#[derive(Default)]
struct Packet {
    length: u32,
    bytes: *mut u8,
    count: u32,
    resources: *mut Resource,
}

unsafe extern "C" {
    fn wm_start(endpoint: *const u16) -> u32;
    fn wm_bind(endpoint: *const u16, object: *const Id, binding: *mut usize) -> u32;
    fn wm_unbind(binding: *mut usize);
    fn wm_call(
        operation: u32,
        binding: usize,
        context: *mut Id,
        lifetime: *mut HANDLE,
        packet: *mut Packet,
        cancel: HANDLE,
        timeout: u32,
    ) -> u32;
    fn wm_lifetime_pipe(reader: *mut HANDLE, writer: *mut HANDLE) -> u32;
    fn wm_watch_lifetime(reader: HANDLE, stopped: HANDLE);
    fn wm_process_sid(process: HANDLE, sid: *mut *mut u8, length: *mut u32) -> u32;
    fn wm_kind(handle: HANDLE, kind: *mut u32) -> u32;
    fn wm_allocate(size: usize) -> *mut c_void;
    fn wm_free(value: *mut c_void);
    fn wm_packet_free(packet: *mut Packet, handles: i32);
}

fn check(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn bool_result(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn identity(process: BorrowedHandle<'_>) -> io::Result<Vec<u8>> {
    let mut bytes = ptr::null_mut();
    let mut len = 0;
    // SAFETY: the process is borrowed, output allocation is released once copied.
    unsafe {
        check(wm_process_sid(
            process.as_raw_handle(),
            &mut bytes,
            &mut len,
        ))?;
        let result = slice::from_raw_parts(bytes, len as usize).to_vec();
        wm_free(bytes.cast());
        Ok(result)
    }
}

pub(super) fn server_endpoint() -> io::Result<&'static [u16]> {
    static ENDPOINT: OnceLock<Result<Vec<u16>, u32>> = OnceLock::new();
    match ENDPOINT.get_or_init(|| {
        let name = format!("vhost-local-{}", uuid::Uuid::new_v4().simple());
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: RPC copies the terminated endpoint name during registration.
        let result = unsafe { wm_start(name.as_ptr()) };
        if result == 0 { Ok(name) } else { Err(result) }
    }) {
        Ok(name) => Ok(name),
        Err(error) => Err(io::Error::from_raw_os_error(*error as i32)),
    }
}

#[derive(Debug)]
pub(super) struct Event(OwnedHandle);
impl Event {
    pub(super) fn new(set: bool) -> io::Result<Self> {
        // SAFETY: creates one unnamed, non-inheritable event with no external pointers.
        unsafe {
            let handle = CreateEventW(ptr::null(), 1, i32::from(set), ptr::null());
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(OwnedHandle::from_raw_handle(handle)))
        }
    }
    pub(super) fn set(&self) -> io::Result<()> {
        // SAFETY: this owns a live event.
        unsafe { bool_result(SetEvent(self.0.as_raw_handle())) }
    }
    pub(super) fn reset(&self) -> io::Result<()> {
        // SAFETY: this owns a live event.
        unsafe { bool_result(ResetEvent(self.0.as_raw_handle())) }
    }
    pub(super) fn wait(&self, closed: &Self, cancelled: &[BorrowedHandle<'_>]) -> io::Result<()> {
        let handles: Vec<_> = std::iter::once(closed.0.as_raw_handle())
            .chain(cancelled.iter().map(AsRawHandle::as_raw_handle))
            .chain(Some(self.0.as_raw_handle()))
            .collect();
        // SAFETY: all handles stay borrowed through the wait; no array is retained.
        match unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, INFINITE) }
        {
            WAIT_FAILED => Err(io::Error::last_os_error()),
            index if index == WAIT_OBJECT_0 + handles.len() as u32 - 1 => Ok(()),
            _ => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

#[derive(Debug)]
pub(super) struct Handle {
    pub(super) kind: u32,
    pub(super) handle: OwnedHandle,
}

pub(super) fn lifetime_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: failure closes partial construction; success returns two owned handles.
    unsafe {
        check(wm_lifetime_pipe(&mut reader, &mut writer))?;
        Ok((
            OwnedHandle::from_raw_handle(reader),
            OwnedHandle::from_raw_handle(writer),
        ))
    }
}

pub(super) fn watch_lifetime(reader: OwnedHandle, stopped: &Event) {
    // SAFETY: both handles remain live; the native wrapper drains its pending read.
    unsafe { wm_watch_lifetime(reader.as_raw_handle(), stopped.0.as_raw_handle()) };
}

impl Handle {
    pub(super) fn copy(handle: BorrowedHandle<'_>) -> io::Result<Self> {
        let mut kind = 0;
        // SAFETY: query only this borrowed native handle; no remote process access.
        unsafe {
            check(wm_kind(handle.as_raw_handle(), &mut kind))?;
        }
        Ok(Self {
            kind,
            handle: handle.try_clone_to_owned()?,
        })
    }
}

#[derive(Debug)]
pub(super) struct Remote {
    binding: usize,
    id: Id,
    // Shutdown drains calls before closing the connection's last pipe writer.
    lifetime: RwLock<Option<OwnedHandle>>,
    cancelled: Event,
}

impl Remote {
    pub(super) fn connect(descriptor: BorrowedHandle<'_>) -> io::Result<Self> {
        let (endpoint, id) = read_descriptor(descriptor)?;
        Self::connect_to(&endpoint, id)
    }

    pub(super) fn connect_at(address: &super::Address) -> io::Result<Self> {
        if address.endpoint.is_empty()
            || address.endpoint.len() >= 64
            || !address
                .endpoint
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let endpoint: Vec<_> = address.endpoint.encode_utf16().chain(Some(0)).collect();
        Self::connect_to(&endpoint, address.listener.to_bytes_le())
    }

    fn connect_to(endpoint: &[u16], id: Id) -> io::Result<Self> {
        let mut binding = 0;
        let cancelled = Event::new(false)?;
        // SAFETY: terminated name and writable output; binding is newly owned.
        unsafe {
            check(wm_bind(endpoint.as_ptr(), &id, &mut binding))?;
        }
        let mut remote = Self {
            binding,
            id: [0; 16],
            lifetime: RwLock::new(None),
            cancelled,
        };
        let mut lifetime = ptr::null_mut();
        // SAFETY: call drains completion/cancellation before returning; all arguments live.
        let result = unsafe {
            wm_call(
                0,
                binding,
                &mut remote.id,
                &mut lifetime,
                ptr::null_mut(),
                ptr::null_mut(),
                5000,
            )
        };
        if !lifetime.is_null() {
            // SAFETY: successful RPC output transfers one owned pipe handle.
            *remote.lifetime.get_mut().unwrap() =
                Some(unsafe { OwnedHandle::from_raw_handle(lifetime) });
        }
        check(result)?;
        if remote.lifetime.get_mut().unwrap().is_none() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(remote)
    }

    pub(super) fn shutdown(&self) {
        let _ = self.cancelled.set();
        self.lifetime.write().unwrap().take();
    }

    fn call(&self, operation: u32, packet: &mut Packet, timeout: u32) -> io::Result<()> {
        let borrowed = self.lifetime.read().unwrap();
        let mut context = self.id;
        if borrowed.is_none() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        // SAFETY: read guard retains the context, binding and packet through native completion.
        unsafe {
            check(wm_call(
                operation,
                self.binding,
                &mut context,
                ptr::null_mut(),
                packet,
                self.cancelled.0.as_raw_handle(),
                timeout,
            ))
        }
    }

    pub(super) fn send(&self, bytes: &[u8], handles: &[BorrowedHandle<'_>]) -> io::Result<()> {
        let mut resources = Vec::with_capacity(handles.len());
        for handle in handles {
            let mut kind = 0;
            // SAFETY: handles are borrowed for the entire call, including cancellation.
            unsafe {
                check(wm_kind(handle.as_raw_handle(), &mut kind))?;
            }
            resources.push(Resource {
                kind,
                handle: handle.as_raw_handle(),
            });
        }
        let mut packet = Packet {
            length: bytes.len() as u32,
            bytes: bytes.as_ptr().cast_mut(),
            count: resources.len() as u32,
            resources: resources.as_mut_ptr(),
        };
        self.call(1, &mut packet, 5000)
    }

    pub(super) fn receive(&self) -> io::Result<Envelope> {
        let mut packet = Packet::default();
        self.call(2, &mut packet, INFINITE)?;
        // SAFETY: successful NDR output transfers owned resources and allocations to us.
        unsafe {
            let result = import(&packet, true);
            wm_packet_free(&mut packet, i32::from(result.is_err()));
            result
        }
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        self.shutdown();
        // SAFETY: last owner; every operation drained before binding release.
        unsafe {
            wm_unbind(&mut self.binding);
        }
    }
}

unsafe fn bytes<'a, T>(pointer: *const T, length: usize) -> &'a [T] {
    if length == 0 {
        &[]
    } else {
        // SAFETY: caller receives a validated NDR array of this element count.
        unsafe { slice::from_raw_parts(pointer, length) }
    }
}

unsafe fn import(packet: &Packet, owned: bool) -> io::Result<Envelope> {
    if packet.length as usize > MAX_MESSAGE
        || packet.count as usize > MAX_RESOURCES
        || (packet.length != 0 && packet.bytes.is_null())
        || (packet.count != 0 && packet.resources.is_null())
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: the stub supplied complete bounded arrays with runtime-owned input
    // handles or newly owned successful output handles, as selected by the caller.
    unsafe {
        let wire = bytes(packet.resources, packet.count as usize);
        if wire.iter().any(|r| {
            !(1..=4).contains(&r.kind) || r.handle.is_null() || r.handle == INVALID_HANDLE_VALUE
        }) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut resources = Vec::with_capacity(wire.len());
        for resource in wire {
            let handle = if owned {
                OwnedHandle::from_raw_handle(resource.handle)
            } else {
                BorrowedHandle::borrow_raw(resource.handle).try_clone_to_owned()?
            };
            resources.push(Handle {
                kind: resource.kind,
                handle,
            });
        }
        Ok(Envelope {
            bytes: bytes(packet.bytes, packet.length as usize).to_vec(),
            resources,
        })
    }
}

unsafe fn export(value: Envelope, packet: &mut Packet) -> io::Result<()> {
    // SAFETY: output allocations use the same allocator as generated stubs. Once
    // committed, RPC owns both allocations and each dedicated output handle.
    unsafe {
        let data = wm_allocate(value.bytes.len().max(1)).cast::<u8>();
        let resources =
            wm_allocate((value.resources.len() * size_of::<Resource>()).max(1)).cast::<Resource>();
        if data.is_null() || resources.is_null() {
            wm_free(data.cast());
            wm_free(resources.cast());
            return Err(io::Error::from_raw_os_error(ERROR_NOT_ENOUGH_MEMORY as i32));
        }
        ptr::copy_nonoverlapping(value.bytes.as_ptr(), data, value.bytes.len());
        *packet = Packet {
            length: value.bytes.len() as u32,
            bytes: data,
            count: value.resources.len() as u32,
            resources,
        };
        for (i, object) in value.resources.into_iter().enumerate() {
            resources.add(i).write(Resource {
                kind: object.kind,
                handle: object.handle.into_raw_handle(),
            });
        }
    }
    Ok(())
}

fn callback(action: impl FnOnce() -> io::Result<()> + std::panic::UnwindSafe) -> u32 {
    match std::panic::catch_unwind(action) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => error
            .raw_os_error()
            .map(|e| e as u32)
            .unwrap_or(match error.kind() {
                io::ErrorKind::PermissionDenied => ERROR_ACCESS_DENIED,
                io::ErrorKind::BrokenPipe => ERROR_BROKEN_PIPE,
                io::ErrorKind::WouldBlock => ERROR_BUSY,
                _ => ERROR_INVALID_DATA,
            }),
        Err(_) => ERROR_UNHANDLED_EXCEPTION,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wm_authorize_sid(id: *const Id, sid: *const u8, len: u32) -> u32 {
    callback(|| {
        // SAFETY: the RPC callback supplies kernel-derived SID data and a UUID.
        let (id, sid) = unsafe { (*id, bytes(sid, len as usize)) };
        let endpoint = super::endpoint(id).ok_or(io::ErrorKind::PermissionDenied)?;
        if endpoint.identity != sid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wm_context_matches(id: *const Id, context: *const Id) -> u32 {
    callback(|| {
        let contexts = super::CONTEXTS
            .get_or_init(std::sync::Mutex::default)
            .lock()
            .unwrap();
        // SAFETY: the manager supplies a complete connection identifier.
        let context = contexts
            .get(unsafe { &*context })
            .ok_or(io::ErrorKind::BrokenPipe)?;
        // SAFETY: the manager supplies the binding object's UUID for this call.
        if context.endpoint.id != unsafe { *id } {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wm_server_open(id: *const Id, context: *mut Id, lifetime: *mut HANDLE) -> u32 {
    callback(|| {
        // SAFETY: the manager supplies valid input/output pointers for this call.
        unsafe {
            let (connection, writer) = super::open(*id)?;
            *context = connection;
            *lifetime = writer.into_raw_handle();
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wm_server_send(
    context: *const Id,
    packet: *const Packet,
    cancel: HANDLE,
    disconnect: HANDLE,
) -> u32 {
    callback(|| {
        // SAFETY: the manager owns the connection identifier for this call.
        let state = super::state(unsafe { *context })?;
        // SAFETY: the manager owns packet parameters and notification events until return.
        let result = unsafe {
            import(&*packet, false).and_then(|value| {
                state.inbound.push(
                    value,
                    &state,
                    &[
                        BorrowedHandle::borrow_raw(cancel),
                        BorrowedHandle::borrow_raw(disconnect),
                    ],
                )
            })
        };
        if result.is_err() {
            state.close();
        }
        result
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn wm_server_receive(
    context: *const Id,
    packet: *mut Packet,
    cancel: HANDLE,
    disconnect: HANDLE,
) -> u32 {
    callback(|| {
        // SAFETY: the manager owns the connection identifier for this call.
        let state = super::state(unsafe { *context })?;
        // SAFETY: the manager retains output storage and notification handles.
        let result = unsafe {
            state
                .outbound
                .pop(
                    &state,
                    &[
                        BorrowedHandle::borrow_raw(cancel),
                        BorrowedHandle::borrow_raw(disconnect),
                    ],
                )
                .and_then(|value| export(value, &mut *packet))
        };
        if result.is_err() {
            state.close();
        }
        result
    })
}

const DESCRIPTOR_SIZE: usize = 8 + 16 + 128;
const MAGIC: &[u8; 8] = b"WMCHAN1\0";

pub(super) fn descriptor(endpoint: &[u16], id: Id) -> io::Result<OwnedHandle> {
    if endpoint.len() > 64 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = [0u8; DESCRIPTOR_SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&id);
    for (out, value) in bytes[24..].chunks_exact_mut(2).zip(endpoint) {
        out.copy_from_slice(&value.to_le_bytes());
    }
    // SAFETY: the new private section has no aliases until initialized. Only a
    // read-only handle is exported, after the writable view and handle are gone.
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
            &mut read_only,
            SECTION_MAP_READ | SECTION_QUERY,
            0,
            0,
        ))?;
        Ok(OwnedHandle::from_raw_handle(read_only))
    }
}

fn read_descriptor(descriptor: BorrowedHandle<'_>) -> io::Result<(Vec<u16>, Id)> {
    let mut bytes = [0u8; DESCRIPTOR_SIZE];
    // SAFETY: copy through the OS into owned storage before parsing untrusted
    // contents. ReadProcessMemory also reports inaccessible/in-page failures
    // rather than making a potentially faulting Rust load from a peer's section.
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
    let id = bytes[8..24].try_into().unwrap();
    let mut endpoint: Vec<_> = bytes[24..]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let end = endpoint
        .iter()
        .position(|value| *value == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    if end == 0
        || endpoint[..end]
            .iter()
            .any(|v| !matches!(*v, 45 | 48..=57 | 65..=90 | 97..=122))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    endpoint.truncate(end + 1);
    Ok((endpoint, id))
}
