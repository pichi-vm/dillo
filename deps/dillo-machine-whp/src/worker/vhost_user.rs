// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Provisional Windows binding: one native pipe message contains a standard
//! vhost-user message followed by backend-local u64 handle values.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::sync::Arc;

use dillo_machine::worker::{BorrowedResource, Channel, MAX_MESSAGE, Message};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;

use super::{check, wide};

const HEADER: usize = 12;
const MAX_HANDLES: usize = 8;

#[derive(Debug)]
struct Connection {
    pipe: Arc<OwnedHandle>,
    backend: Option<Arc<OwnedHandle>>,
}

pub(super) fn pair(backend: Arc<OwnedHandle>) -> io::Result<(Box<dyn Channel>, OwnedHandle)> {
    let name = wide(std::ffi::OsStr::new(&format!(
        r"\\.\pipe\LOCAL\dillo-vhost-{}",
        uuid::Uuid::new_v4()
    )));
    // Both ends are opened by the parent; the backend receives an existing
    // endpoint. A unique first instance and client PID check prevent accepting
    // a competing connection as the endpoint we are about to grant.
    #[allow(unsafe_code)]
    unsafe {
        let server = CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_MESSAGE as u32,
            MAX_MESSAGE as u32,
            0,
            std::ptr::null(),
        );
        if server == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let server = OwnedHandle::from_raw_handle(server);
        let client = CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        );
        if client == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let client = OwnedHandle::from_raw_handle(client);
        let mut overlap = OVERLAPPED::default();
        if ConnectNamedPipe(server.as_raw_handle(), &mut overlap) == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                // The client is already open, so this is not an outstanding
                // connection operation that may retain the stack OVERLAPPED.
                CancelIoEx(server.as_raw_handle(), &overlap);
                let mut count = 0;
                GetOverlappedResult(server.as_raw_handle(), &overlap, &mut count, 1);
                return Err(error);
            }
        }
        let mode = PIPE_READMODE_MESSAGE;
        check(SetNamedPipeHandleState(
            client.as_raw_handle(),
            &mode,
            std::ptr::null(),
            std::ptr::null(),
        ))?;
        let mut pid = 0;
        check(GetNamedPipeClientProcessId(
            server.as_raw_handle(),
            &mut pid,
        ))?;
        if pid != GetCurrentProcessId() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok((
            Box::new(Connection {
                pipe: Arc::new(server),
                backend: Some(backend),
            }),
            client,
        ))
    }
}

pub(super) fn adopt(pipe: OwnedHandle) -> io::Result<Box<dyn Channel>> {
    // A duplicate retains the message read mode selected by the parent.
    Ok(Box::new(Connection {
        pipe: Arc::new(pipe),
        backend: None,
    }))
}

impl Connection {
    fn transfer(&self, bytes: &mut [u8], write: bool) -> io::Result<usize> {
        // SAFETY: the buffer and OVERLAPPED remain live until completion. Each
        // concurrent operation owns its event. Cancellation is drained before
        // returning, including a timeout, so Windows retains no Rust pointers.
        #[allow(unsafe_code)]
        unsafe {
            let event = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
            if event.is_null() {
                return Err(io::Error::last_os_error());
            }
            let event = OwnedHandle::from_raw_handle(event);
            let mut overlap = OVERLAPPED {
                hEvent: event.as_raw_handle(),
                ..Default::default()
            };
            let result = if write {
                WriteFile(
                    self.pipe.as_raw_handle(),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    std::ptr::null_mut(),
                    &mut overlap,
                )
            } else {
                ReadFile(
                    self.pipe.as_raw_handle(),
                    bytes.as_mut_ptr(),
                    bytes.len() as u32,
                    std::ptr::null_mut(),
                    &mut overlap,
                )
            };
            if result == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                    return Err(error);
                }
            }
            let wait = if result != 0 {
                WAIT_OBJECT_0
            } else {
                WaitForSingleObject(event.as_raw_handle(), if write { 5000 } else { INFINITE })
            };
            let mut count = 0;
            if wait != WAIT_OBJECT_0 {
                let error = if wait == WAIT_TIMEOUT {
                    io::ErrorKind::TimedOut.into()
                } else {
                    io::Error::last_os_error()
                };
                CancelIoEx(self.pipe.as_raw_handle(), &overlap);
                GetOverlappedResult(self.pipe.as_raw_handle(), &overlap, &mut count, 1);
                return Err(error);
            }
            check(GetOverlappedResult(
                self.pipe.as_raw_handle(),
                &overlap,
                &mut count,
                0,
            ))?;
            Ok(count as usize)
        }
    }
}

impl Channel for Connection {
    fn share_socket(
        &self,
        socket: dillo_machine::worker::BorrowedSocket<'_>,
    ) -> io::Result<Message> {
        use std::os::windows::io::AsHandle;
        let peer = self.backend.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        super::socket::export(socket, peer.as_handle())
    }
    fn send(&mut self, bytes: &[u8], resources: &[BorrowedResource<'_>]) -> io::Result<()> {
        if !(HEADER..=MAX_MESSAGE).contains(&bytes.len())
            || resources.len() > MAX_HANDLES
            || u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len() - HEADER
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut wire = Vec::with_capacity(bytes.len() + 8 * resources.len());
        wire.extend(bytes);
        let mut transfers = Vec::with_capacity(resources.len());
        for resource in resources {
            let mut target = std::ptr::null_mut();
            // Every transmitted value belongs to the backend's table. A
            // backend sender relinquishes a dedicated duplicate; the frontend
            // consumes it with DUPLICATE_CLOSE_SOURCE when importing it.
            #[allow(unsafe_code)]
            unsafe {
                let process = self
                    .backend
                    .as_ref()
                    .map_or(GetCurrentProcess(), |p| p.as_raw_handle());
                check(DuplicateHandle(
                    GetCurrentProcess(),
                    resource.as_raw_handle(),
                    process,
                    &mut target,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                ))?;
                if self.backend.is_none() {
                    transfers.push(OwnedHandle::from_raw_handle(target));
                }
            }
            wire.extend((target as usize as u64).to_ne_bytes());
        }
        // Once submitted, never remotely close a numeric handle after an I/O
        // error: the peer may already have consumed and reused its table slot.
        for transfer in transfers {
            let _ = transfer.into_raw_handle();
        }
        if self.transfer(&mut wire, true)? != wire.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Message> {
        let mut bytes = vec![0; MAX_MESSAGE + 8 * MAX_HANDLES];
        // ERROR_MORE_DATA rejects an oversized native message; its remaining
        // fragments must never be mistaken for a new vhost-user header.
        let count = self.transfer(&mut bytes, false)?;
        bytes.truncate(count);
        if count < HEADER {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let end = HEADER + u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if end > MAX_MESSAGE || end > count || !(count - end).is_multiple_of(8) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let values = bytes[end..]
            .chunks_exact(8)
            .map(|value| u64::from_ne_bytes(value.try_into().unwrap()))
            .collect::<Vec<_>>();
        if values.len() > MAX_HANDLES
            || values.iter().enumerate().any(|(i, value)| {
                *value == 0
                    || *value > isize::MAX as u64
                    // Windows also accepts zero-extended 32-bit pseudo-handles.
                    // None names a transferable entry in the backend's table.
                    || (u64::from(u32::MAX - 5)..=u64::from(u32::MAX)).contains(value)
                    || values[..i].contains(value)
            })
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut resources = Vec::with_capacity(values.len());
        for value in values {
            let source = usize::try_from(value).map_err(io::Error::other)? as *mut std::ffi::c_void;
            // SAFETY: frontend import names the pinned backend process, never
            // the frontend's own table. Backend import trusts only the parent,
            // which just installed a fresh, uniquely transferred handle.
            #[allow(unsafe_code)]
            unsafe {
                let handle = if let Some(backend) = &self.backend {
                    let mut target = std::ptr::null_mut();
                    check(DuplicateHandle(
                        backend.as_raw_handle(),
                        source,
                        GetCurrentProcess(),
                        &mut target,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
                    ))?;
                    target
                } else {
                    source
                };
                resources.push(OwnedHandle::from_raw_handle(handle));
            }
        }
        bytes.truncate(end);
        Ok(Message { bytes, resources })
    }

    fn try_clone(&self) -> io::Result<Box<dyn Channel>> {
        Ok(Box::new(Self {
            pipe: Arc::clone(&self.pipe),
            backend: self.backend.clone(),
        }))
    }

    fn pair(&self) -> io::Result<(Box<dyn Channel>, OwnedHandle)> {
        pair(Arc::clone(
            self.backend.as_ref().ok_or(io::ErrorKind::Unsupported)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::windows::io::AsHandle;

    fn endpoints() -> (Box<dyn Channel>, Connection) {
        // SAFETY: make an owned reference to this process so the real transfer
        // path can be exercised without launching another executable.
        #[allow(unsafe_code)]
        let process = unsafe {
            let mut handle = std::ptr::null_mut();
            check(DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentProcess(),
                GetCurrentProcess(),
                &mut handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ))
            .unwrap();
            OwnedHandle::from_raw_handle(handle)
        };
        let (frontend, backend) = pair(Arc::new(process)).unwrap();
        (
            frontend,
            Connection {
                pipe: Arc::new(backend),
                backend: None,
            },
        )
    }

    fn header() -> Vec<u8> {
        [1u32, 5, 0]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect()
    }

    #[test]
    fn borrowed_resource_round_trip() {
        let (mut frontend, mut backend) = endpoints();
        let (reader, mut writer) = std::io::pipe().unwrap();
        frontend.send(&header(), &[reader.as_handle()]).unwrap();
        drop(reader);
        let first = backend.receive().unwrap().resources.remove(0);
        backend.send(&header(), &[first.as_handle()]).unwrap();
        drop(first);
        let returned = frontend.receive().unwrap().resources.remove(0);
        let mut returned = std::fs::File::from(returned);
        writer.write_all(b"x").unwrap();
        let mut byte = [0];
        returned.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
        drop(returned);
        assert_eq!(
            writer.write(b"x").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn untrusted_handle_numbers_are_rejected() {
        for value in [
            0,
            u64::MAX,
            u64::MAX - 1,
            u64::from(u32::MAX),
            u64::from(u32::MAX - 5),
        ] {
            let (mut frontend, backend) = endpoints();
            let mut bytes = header();
            bytes.extend(value.to_ne_bytes());
            backend.transfer(&mut bytes, true).unwrap();
            assert_eq!(
                frontend.receive().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
