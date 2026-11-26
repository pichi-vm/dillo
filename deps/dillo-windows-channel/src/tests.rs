// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::io::{Read, Write};
use std::os::windows::io::{AsHandle, BorrowedHandle};
use std::time::Duration;

fn listener() -> Listener {
    // SAFETY: the pseudo handle is borrowed only for querying the current token.
    #[allow(unsafe_code)]
    let identity = unsafe {
        identity(BorrowedHandle::borrow_raw(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
        ))
    }
    .unwrap();
    Listener::bind(identity).unwrap()
}

fn pair(listener: &Listener) -> (Connection, Connection) {
    let descriptor = listener.descriptor().unwrap();
    let client = Connection::connect(descriptor.as_handle()).unwrap();
    (listener.accept().unwrap(), client)
}

fn expect_reader_released(mut writer: std::io::PipeWriter) {
    let (send, done) = std::sync::mpsc::channel();
    // A leaked reader could eventually fill the pipe and block a write. Keep
    // the deadline outside that I/O so the test still reports the failure.
    let thread = std::thread::spawn(move || {
        let result = loop {
            if let Err(error) = writer.write(b"x") {
                break error;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let _ = send.send(result);
    });
    let error = done
        .recv_timeout(Duration::from_secs(5))
        .expect("transferred reader leaked");
    assert!(matches!(error.raw_os_error(), Some(109 | 232)), "{error}");
    thread.join().unwrap();
}

#[test]
fn address_does_not_bypass_identity_authorization() {
    let forbidden = Listener::bind(vec![0]).unwrap();
    let error = Connection::connect_at(&forbidden.address()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn handles_and_bytes_in_both_directions() {
    let listener = listener();
    let (server, client) = pair(&listener);
    let (reader, mut writer) = std::io::pipe().unwrap();
    client.send(b"request", &[reader.as_handle()]).unwrap();
    drop(reader);
    let first = server.receive().unwrap();
    assert_eq!(first.bytes, b"request");
    server
        .send(b"reply", &[first.resources[0].as_handle()])
        .unwrap();
    drop(first);
    let mut reply = client.receive().unwrap();
    assert_eq!(reply.bytes, b"reply");
    let mut reader = std::fs::File::from(reply.resources.remove(0));
    writer.write_all(b"shared").unwrap();
    let mut bytes = [0; 6];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, *b"shared");
    drop(reader);
    // Server stub cleanup may follow client delivery. Closing the context also
    // drains queued resources; the pipe must then have no remaining reader.
    client.shutdown();
    expect_reader_released(writer);
}

#[test]
fn listener_survives_closed_connections_and_pending_accepts() {
    let listener = listener();
    let descriptor = listener.descriptor().unwrap();
    for _ in 0..32 {
        let client = Connection::connect(descriptor.as_handle()).unwrap();
        client.shutdown();
    }
    for _ in 0..3 {
        let (server, client) = pair(&listener);
        client.send(b"next", &[]).unwrap();
        assert_eq!(server.receive().unwrap().bytes, b"next");
        client.shutdown();
        assert!(server.receive().is_err());
    }
}

#[test]
fn shutdown_wakes_receive_without_terminating_the_server() {
    let listener = listener();
    let (server, client) = pair(&listener);
    let receiver = client.clone();
    let (started, ready) = std::sync::mpsc::channel();
    let (send, done) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        receiver.send(b"receiving", &[]).unwrap();
        started.send(()).unwrap();
        send.send(receiver.receive().is_err()).unwrap();
    });
    assert_eq!(server.receive().unwrap().bytes, b"receiving");
    // Dequeuing the message need not mean its sender's RPC has returned yet.
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    client.shutdown();
    assert!(done.recv_timeout(Duration::from_secs(10)).unwrap());
    thread.join().unwrap();
    let (server, client) = pair(&listener);
    client.send(b"alive", &[]).unwrap();
    assert_eq!(server.receive().unwrap().bytes, b"alive");
}

#[test]
fn closing_idle_connection_preserves_other_connections() {
    let listener = listener();
    let (server, client) = pair(&listener);
    let (survivor, other_client) = pair(&listener);
    let (reader, mut writer) = std::io::pipe().unwrap();
    server.send(b"unreceived", &[reader.as_handle()]).unwrap();
    drop(reader);
    writer.write_all(b"still open").unwrap();
    // This closes a kernel pipe writer, without a Close RPC or process exit.
    drop(client);
    expect_reader_released(writer);
    assert!(server.receive().is_err());
    other_client.send(b"alive", &[]).unwrap();
    assert_eq!(survivor.receive().unwrap().bytes, b"alive");
}

#[test]
#[ignore = "same-executable peer, launched by the disconnect fixture"]
fn peer_process() {
    let Ok(endpoint) = std::env::var("CHANNEL_ENDPOINT") else {
        return;
    };
    let address = Address {
        endpoint,
        listener: std::env::var("CHANNEL_LISTENER").unwrap().parse().unwrap(),
    };
    let client = Connection::connect_at(&address).unwrap();
    client.send(b"connected", &[]).unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn peer_death_releases_queued_resources_and_preserves_listener() {
    struct Peer(std::process::Child);
    impl Drop for Peer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let listener = listener();
    let address = listener.address();
    let mut peer = Peer(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::peer_process", "--ignored", "--nocapture"])
            .env("CHANNEL_ENDPOINT", address.endpoint)
            .env("CHANNEL_LISTENER", address.listener.to_string())
            .spawn()
            .unwrap(),
    );
    let server = listener.accept_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(server.receive().unwrap().bytes, b"connected");
    let (reader, mut writer) = std::io::pipe().unwrap();
    server.send(b"unreceived", &[reader.as_handle()]).unwrap();
    drop(reader);
    writer.write_all(b"still open").unwrap();
    peer.0.kill().unwrap();
    peer.0.wait().unwrap();
    expect_reader_released(writer);
    assert!(server.receive().is_err());
    let (next, client) = pair(&listener);
    client.send(b"next client", &[]).unwrap();
    assert_eq!(next.receive().unwrap().bytes, b"next client");
}
