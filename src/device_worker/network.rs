// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native network resource grants. Packet processing stays in the worker.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock, mpsc};

use dillo_machine::worker::{Channel, Message, Resource, Socket, WorkerHost};
use dillo_virtio_net::{Forward, HostNetwork, NetworkResources, Proto};
use dillo_worker::grant::{Client, Grant};

#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;

#[derive(serde::Serialize, serde::Deserialize)]
enum Request {
    ConnectTcp(SocketAddr),
    ConnectUdp(SocketAddr),
    ListenTcp(SocketAddr),
    BindUdp(SocketAddr),
    Resolve(String),
}

pub(crate) fn prepare(mac: [u8; 6], forwards: Vec<Forward>) -> io::Result<dillo_worker::Prepared> {
    let prepared = dillo_worker::Prepared::new(
        dillo_worker::DeviceInfo {
            kind: 1,
            queues: vec![256; 2],
            config_len: 8,
        },
        &super::Backing::UserNet {
            mac,
            forwards: forwards.clone(),
        },
        Vec::new(),
    )?;
    Ok(prepared.with_grants(move |bytes, channel| serve(bytes, channel, &forwards)))
}

fn serve(bytes: &[u8], channel: &dyn Channel, forwards: &[Forward]) -> io::Result<Grant> {
    let request: Request = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    let socket: Socket = match request {
        Request::ConnectTcp(address) => HostNetwork.connect_tcp(address)?.into(),
        Request::ConnectUdp(address) => HostNetwork.connect_udp(address)?.into(),
        Request::ListenTcp(address) => {
            require_forward(forwards, address, Proto::Tcp)?;
            HostNetwork.listen_tcp(address)?.into()
        }
        Request::BindUdp(address) => {
            require_forward(forwards, address, Proto::Udp)?;
            HostNetwork.bind_udp(address)?.into()
        }
        Request::Resolve(name) => return resolve(name),
    };
    #[cfg(unix)]
    let borrowed = socket.as_fd();
    #[cfg(windows)]
    let borrowed = socket.as_socket();
    let message = channel.share_socket(borrowed)?;
    Ok(Grant::from(message).retain(socket))
}

fn require_forward(forwards: &[Forward], address: SocketAddr, proto: Proto) -> io::Result<()> {
    if forwards
        .iter()
        .any(|f| f.proto == proto && f.host_ip == address.ip() && f.host_port == address.port())
    {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

type Lookup = (String, io::PipeWriter);

// Native DNS can block inside the OS. A fixed process-wide pool bounds those
// calls independently of VM reset or worker replacement. Jobs contain only a
// name and one result pipe, never guest memory, VM handles or device state.
// Closing a worker drops its result reader; a late lookup cannot reach a new
// activation. The stack also tags its own DNS work by activation.
fn resolver() -> io::Result<&'static mpsc::SyncSender<Lookup>> {
    static POOL: OnceLock<io::Result<mpsc::SyncSender<Lookup>>> = OnceLock::new();
    POOL.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<Lookup>(16);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..4 {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name("host-dns".into())
                .spawn(move || {
                    loop {
                        let Ok((name, mut output)) = receiver.lock().unwrap().recv() else {
                            break;
                        };
                        let addresses = HostNetwork
                            .resolve(&name)
                            .ok()
                            .map(|ips| ips.into_iter().take(16).collect::<Vec<_>>());
                        let bytes =
                            serde_json::to_vec(&addresses).expect("IP address serialization");
                        // One bounded result fits an initially empty native pipe.
                        // The child has only its read end, so it cannot fill it.
                        let _ = output
                            .write_all(&(bytes.len() as u32).to_ne_bytes())
                            .and_then(|()| output.write_all(&bytes));
                    }
                })?;
        }
        Ok(sender)
    })
    .as_ref()
    .map_err(|error| io::Error::other(error.to_string()))
}

fn resolve(name: String) -> io::Result<Grant> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (input, output) = io::pipe()?;
    resolver()?
        .try_send((name, output))
        .map_err(|_| io::ErrorKind::WouldBlock)?;
    Ok(Message {
        bytes: Vec::new(),
        resources: vec![Resource::from(input)],
    }
    .into())
}

pub(super) struct GrantedNetwork {
    grants: Mutex<Client>,
    import: fn(Message) -> io::Result<Socket>,
}

impl GrantedNetwork {
    pub(super) fn new<H: WorkerHost>(grants: Client) -> Self {
        Self {
            grants: Mutex::new(grants),
            import: H::import_socket,
        }
    }

    fn socket(&self, request: &Request) -> io::Result<Socket> {
        let bytes = serde_json::to_vec(request).map_err(io::Error::other)?;
        self.grants.lock().unwrap().request(&bytes, self.import)
    }
}

impl NetworkResources for GrantedNetwork {
    fn connect_tcp(&self, address: SocketAddr) -> io::Result<TcpStream> {
        self.socket(&Request::ConnectTcp(address)).map(Into::into)
    }
    fn connect_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        self.socket(&Request::ConnectUdp(address)).map(Into::into)
    }
    fn listen_tcp(&self, address: SocketAddr) -> io::Result<TcpListener> {
        self.socket(&Request::ListenTcp(address)).map(Into::into)
    }
    fn bind_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        self.socket(&Request::BindUdp(address)).map(Into::into)
    }
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        let bytes =
            serde_json::to_vec(&Request::Resolve(name.to_owned())).map_err(io::Error::other)?;
        let mut input = self.grants.lock().unwrap().request(&bytes, |mut message| {
            if !message.bytes.is_empty() || message.resources.len() != 1 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(File::from(message.resources.pop().unwrap()))
        })?;
        let mut length = [0; 4];
        input.read_exact(&mut length)?;
        let length = u32::from_ne_bytes(length) as usize;
        if length > 1024 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes)?;
        serde_json::from_slice::<Option<Vec<IpAddr>>>(&bytes)
            .map_err(io::Error::other)?
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
}
