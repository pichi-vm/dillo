// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native socket grants are usable after the source socket is closed.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use dillo_machine::worker::{Socket, WorkerHost};
use dillo_worker::grant::Client;

// The dedicated test child retains its resource service until process exit.
static GRANTS: std::sync::OnceLock<std::sync::Mutex<Client>> = std::sync::OnceLock::new();

fn retry<T>(mut action: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match action() {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

pub(super) fn receive(mut client: Client) -> io::Result<()> {
    let tcp: TcpStream = client.request(&[0], super::Worker::import_socket)?.into();
    let udp: UdpSocket = client.request(&[1], super::Worker::import_socket)?.into();
    let listener: TcpListener = client.request(&[2], super::Worker::import_socket)?.into();
    // Request 3 is processed after each import ack; every source socket is now
    // closed. Only the confined worker's owning imports retain these endpoints.
    client.request(&[3], |_| Ok(()))?;
    let metadata = vec![42; 128 * 1024];
    client.request(&metadata, |message| {
        assert_eq!(message.bytes, metadata);
        assert!(message.resources.is_empty());
        Ok(())
    })?;
    let (accepted, _) = retry(|| listener.accept())?;
    for mut stream in [tcp, accepted] {
        eprintln!("granted TCP peer {:?}", stream.peer_addr()?);
        let mut bytes = [0; 4];
        assert_eq!(retry(|| stream.read(&mut bytes))?, 4);
        assert_eq!(&bytes, b"ping");
        assert_eq!(retry(|| stream.write(&bytes))?, 4);
    }
    let mut bytes = [0; 4];
    assert_eq!(retry(|| udp.recv(&mut bytes))?, 4);
    assert_eq!(&bytes, b"ping");
    assert_eq!(retry(|| udp.send(&bytes))?, 4);
    // Keep the service connection for this dedicated test process's lifetime,
    // as the production network device does after its factory returns.
    GRANTS.set(std::sync::Mutex::new(client)).unwrap();
    Ok(())
}

pub(super) fn exercise() -> io::Result<()> {
    eprintln!("vhost process: connected TCP/UDP and listening socket grants");
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let connected = TcpStream::connect(listener.local_addr()?)?;
    let (peer, _) = listener.accept()?;
    let inbound = TcpStream::connect(listener.local_addr()?)?;
    let udp_peer = UdpSocket::bind("127.0.0.1:0")?;
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    udp.connect(udp_peer.local_addr()?)?;
    udp_peer.connect(udp.local_addr()?)?;
    connected.set_nonblocking(true)?;
    udp.set_nonblocking(true)?;
    listener.set_nonblocking(true)?;
    let mut sockets: Vec<Option<Socket>> = vec![
        Some(connected.into()),
        Some(udp.into()),
        Some(listener.into()),
    ];
    let echo = std::thread::spawn(move || -> io::Result<()> {
        for mut stream in [peer, inbound] {
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            stream.write_all(b"ping")?;
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes)?;
            assert_eq!(&bytes, b"ping");
        }
        udp_peer.set_read_timeout(Some(Duration::from_secs(5)))?;
        udp_peer.send(b"ping")?;
        let mut bytes = [0; 4];
        assert_eq!(udp_peer.recv(&mut bytes)?, 4);
        assert_eq!(&bytes, b"ping");
        Ok(())
    });
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 3,
            queues: vec![128; 2],
            config_len: 12,
        },
        &serde_json::json!({"mode": "sockets"}),
        Vec::new(),
    )?
    .with_grants(move |request, channel| {
        if request.len() == 128 * 1024 && request.iter().all(|byte| *byte == 42) {
            return Ok(dillo_machine::worker::Message {
                bytes: request.to_vec(),
                resources: Vec::new(),
            }
            .into());
        }
        if request == [3] {
            return Ok(dillo_machine::worker::Message {
                bytes: Vec::new(),
                resources: Vec::new(),
            }
            .into());
        }
        let [index] = request else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let socket = sockets
            .get_mut(*index as usize)
            .and_then(Option::take)
            .ok_or(io::ErrorKind::InvalidInput)?;
        #[cfg(unix)]
        let borrowed = std::os::fd::AsFd::as_fd(&socket);
        #[cfg(windows)]
        let borrowed = std::os::windows::io::AsSocket::as_socket(&socket);
        Ok(dillo_worker::grant::Grant::from(channel.share_socket(borrowed)?).retain(socket))
    });
    let (_, export) = super::memory()?;
    let started = prepared.start::<super::Worker>(export, || {});
    let observed = echo.join().unwrap();
    let (_, control) = started?;
    observed?;
    control.shutdown()
}
