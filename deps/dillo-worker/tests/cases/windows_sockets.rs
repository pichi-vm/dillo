// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native feasibility probe, not the production resource broker.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawSocket};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

const WORDS: usize = size_of::<WSAPROTOCOL_INFOW>().div_ceil(4);

fn bytes(info: &mut [u32; WORDS]) -> &mut [u8] {
    // SAFETY: initialized integer storage has no padding, remains suitably
    // aligned for WSAPROTOCOL_INFOW, and permits every byte representation.
    #[allow(unsafe_code)]
    unsafe {
        std::slice::from_raw_parts_mut(info.as_mut_ptr().cast(), size_of::<WSAPROTOCOL_INFOW>())
    }
}

pub(super) fn serve(files: &mut Vec<File>) -> io::Result<JoinHandle<io::Result<()>>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let connected = TcpStream::connect(listener.local_addr()?)?;
    let (mut peer, _) = listener.accept()?;
    peer.set_read_timeout(Some(Duration::from_secs(5)))?;
    peer.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (mut request, child_request) = io::pipe()?;
    let (child_reply, mut reply) = io::pipe()?;
    files.push(File::from(dillo_machine::worker::Resource::from(
        child_request,
    )));
    files.push(File::from(dillo_machine::worker::Resource::from(
        child_reply,
    )));
    std::thread::Builder::new()
        .name("socket-grant-probe".into())
        .spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut available = 0;
                // SAFETY: this is the retained read end and valid output storage.
                #[allow(unsafe_code)]
                if unsafe {
                    PeekNamedPipe(
                        request.as_raw_handle(),
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                if available >= 4 {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut pid = [0; 4];
            request.read_exact(&mut pid)?;
            let mut info = [0; WORDS];
            // SAFETY: the fixture child identifies itself over its granted pipe.
            // Production must instead bind the target to the retained process.
            #[allow(unsafe_code)]
            if unsafe {
                WSADuplicateSocketW(
                    connected.as_raw_socket() as usize,
                    u32::from_ne_bytes(pid),
                    info.as_mut_ptr().cast(),
                )
            } != 0
            {
                #[allow(unsafe_code)]
                return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
            }
            reply.write_all(bytes(&mut info))?;
            peer.write_all(b"grant")?;
            let mut received = [0; 5];
            peer.read_exact(&mut received)?;
            assert_eq!(&received, b"grant");
            // Keep the source socket until the child has imported and used it.
            drop(connected);
            Ok(())
        })
}

pub(super) fn use_grant(files: &mut Vec<File>) -> io::Result<()> {
    files
        .remove(1)
        .write_all(&std::process::id().to_ne_bytes())?;
    let mut info = [0; WORDS];
    files.remove(1).read_exact(bytes(&mut info))?;
    // SAFETY: trusted parent supplied the one-use Winsock protocol information
    // for this process. The preceding std networking probe initialized Winsock.
    #[allow(unsafe_code)]
    let mut socket = unsafe {
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
        TcpStream::from_raw_socket(socket as _)
    };
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut received = [0; 5];
    socket.read_exact(&mut received)?;
    assert_eq!(&received, b"grant");
    socket.write_all(&received)
}
