// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Explicit guest IPv4 setup for benchmark kernels without IP autoconfiguration.

use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkFlags, LinkMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rustix::net::{self, RecvFlags, SendFlags, SocketFlags, SocketType};
use std::net::Ipv4Addr;
use std::time::Duration;

pub(crate) fn configure(cmdline: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Some(value) = super::cmdline_token(cmdline, "dillo.net_config=") else {
        return Ok(());
    };
    let (name, cidr) = value
        .split_once(',')
        .ok_or("expected interface,IPv4/prefix")?;
    let (address, prefix) = cidr.split_once('/').ok_or("expected IPv4/prefix")?;
    let address: Ipv4Addr = address.parse()?;
    let prefix: u8 = prefix.parse()?;
    if prefix > 32 {
        return Err("IPv4 prefix exceeds 32".into());
    }
    let socket = net::socket_with(
        net::AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None, // NETLINK_ROUTE
    )?;
    net::bind(&socket, &net::netlink::SocketAddrNetlink::new(0, 0))?;
    net::connect(&socket, &net::netlink::SocketAddrNetlink::new(0, 0))?;
    net::sockopt::set_socket_timeout(
        &socket,
        net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(2)),
    )?;
    let index = net::netdevice::name_to_index(&socket, name)?;
    let mut link = LinkMessage::default();
    link.header.index = index;
    link.header.flags = LinkFlags::Up;
    link.header.change_mask = LinkFlags::Up;
    let mut addr = AddressMessage::default();
    addr.header.family = AddressFamily::Inet;
    addr.header.index = index;
    addr.header.prefix_len = prefix;
    addr.attributes = vec![
        AddressAttribute::Local(address.into()),
        AddressAttribute::Address(address.into()),
    ];
    for (sequence, (payload, flags)) in [
        (RouteNetlinkMessage::NewLink(link), 0),
        (
            RouteNetlinkMessage::NewAddress(addr),
            NLM_F_CREATE | NLM_F_REPLACE,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = NetlinkMessage::from(payload);
        request.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        request.header.sequence_number = sequence as u32 + 1;
        request.finalize();
        let mut bytes = vec![0; request.buffer_len()];
        request.serialize(&mut bytes);
        net::send(&socket, &bytes, SendFlags::empty())?;
        let mut response = [0; 4096];
        let (length, received) = net::recv(&socket, &mut response[..], RecvFlags::TRUNC)?;
        if length != received {
            return Err("truncated netlink acknowledgement".into());
        }
        let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response[..length])?;
        if reply.header.sequence_number != request.header.sequence_number {
            return Err("unexpected netlink reply sequence".into());
        }
        match reply.payload {
            NetlinkPayload::Error(error) if error.code.is_none() => {}
            NetlinkPayload::Error(error) => return Err(error.to_io().into()),
            _ => return Err("expected netlink acknowledgement".into()),
        }
    }
    Ok(())
}
