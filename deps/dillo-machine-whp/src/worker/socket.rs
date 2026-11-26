// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Winsock grants for the already-owned worker process.

use std::io;
use std::os::windows::io::{AsRawHandle, AsRawSocket, BorrowedHandle, FromRawSocket, OwnedSocket};
use std::sync::OnceLock;

use dillo_machine::worker::{BorrowedSocket, Message};
use windows_sys::Win32::Networking::WinSock::{
    FROM_PROTOCOL_INFO, INVALID_SOCKET, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED, WSADATA,
    WSADuplicateSocketW, WSAGetLastError, WSAPROTOCOL_INFOW, WSASocketW, WSAStartup,
};
use windows_sys::Win32::System::Threading::GetProcessId;

const WORDS: usize = size_of::<WSAPROTOCOL_INFOW>().div_ceil(size_of::<u32>());
const _: () = assert!(align_of::<WSAPROTOCOL_INFOW>() <= align_of::<u32>());

fn bytes(words: &mut [u32; WORDS]) -> &mut [u8] {
    // SAFETY: initialized integer storage has no padding and is aligned for
    // the native protocol structure. Every byte representation is valid here.
    #[allow(unsafe_code)]
    unsafe {
        std::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), size_of::<WSAPROTOCOL_INFOW>())
    }
}

pub(super) fn export(socket: BorrowedSocket<'_>, peer: BorrowedHandle<'_>) -> io::Result<Message> {
    let mut info = [0u32; WORDS];
    // SAFETY: both objects are borrowed from owning handles. The PID comes
    // from the retained child owner, never from untrusted worker data. The
    // aligned output storage remains live through the call.
    #[allow(unsafe_code)]
    unsafe {
        let pid = GetProcessId(peer.as_raw_handle());
        if pid == 0 {
            return Err(io::Error::last_os_error());
        }
        if WSADuplicateSocketW(
            socket.as_raw_socket() as usize,
            pid,
            info.as_mut_ptr().cast(),
        ) != 0
        {
            return Err(io::Error::from_raw_os_error(WSAGetLastError()));
        }
    }
    Ok(Message {
        bytes: bytes(&mut info).to_vec(),
        resources: Vec::new(),
    })
}

pub(super) fn import(message: Message) -> io::Result<OwnedSocket> {
    if !message.resources.is_empty() || message.bytes.len() != size_of::<WSAPROTOCOL_INFOW>() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Process-lifetime Winsock initialization, also needed when the confined
    // worker cannot create a socket just to initialize std's networking layer.
    static STARTED: OnceLock<i32> = OnceLock::new();
    let status = *STARTED.get_or_init(|| {
        let mut data = WSADATA::default();
        // SAFETY: native output storage is valid for this synchronous call.
        #[allow(unsafe_code)]
        unsafe {
            WSAStartup(0x202, &mut data)
        }
    });
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let mut info = [0u32; WORDS];
    bytes(&mut info).copy_from_slice(&message.bytes);
    // SAFETY: the parent supplied a one-use protocol structure for this child.
    // WSASocket validates it and returns a new local socket, owned exactly once.
    #[allow(unsafe_code)]
    unsafe {
        let socket = WSASocketW(
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            info.as_ptr().cast(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        );
        if socket == INVALID_SOCKET {
            return Err(io::Error::from_raw_os_error(WSAGetLastError()));
        }
        Ok(OwnedSocket::from_raw_socket(socket as _))
    }
}
