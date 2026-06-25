// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! A minimal DHCPv4 server for the gateway, handing the guest its one static
//! lease so a stock guest image that expects DHCP "just works" without kernel
//! `ip=` configuration.
//!
//! smoltcp's DHCP socket is a *client*, so the server is hand-rolled. There is
//! exactly one client and one address ([`GUEST_IP`]): we answer `DISCOVER` with
//! `OFFER` and `REQUEST` with `ACK`, advertising the gateway as router, the DNS
//! alias as resolver, the `/24` mask, the link MTU, and a long lease. The wire
//! parse is bounds-checked and panic-free — it runs on guest-controlled bytes.
//!
//! [`GUEST_IP`]: super::GUEST_IP

use smoltcp::wire::Ipv4Address;

/// UDP port the DHCP server listens on (BOOTP server port).
pub(super) const SERVER_PORT: u16 = 67;
/// UDP port a DHCP client listens on (BOOTP client port).
pub(super) const CLIENT_PORT: u16 = 68;

/// Fixed BOOTP header length before options (op..file inclusive).
const BOOTP_HEADER_LEN: usize = 236;
/// DHCP magic cookie that precedes the options (RFC 2131).
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// Minimum length of a DHCP packet we'll parse: header + cookie.
const MIN_LEN: usize = BOOTP_HEADER_LEN + 4;

// DHCP option codes.
const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_MTU: u8 = 26;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_END: u8 = 255;

// DHCP message types (option 53 values).
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

/// Lease time advertised to the guest (seconds). Long — there is one static
/// lease and the backend lives only as long as the VM.
const LEASE_SECS: u32 = 86_400;

/// The kind of request the guest sent, as far as we care to distinguish.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum MsgKind {
    Discover,
    Request,
}

/// A parsed guest DHCP request: just the fields we echo into the reply.
#[derive(Debug, Clone)]
pub(super) struct DhcpRequest {
    pub(super) kind: MsgKind,
    /// Transaction id, echoed in the reply.
    xid: [u8; 4],
    /// Client hardware address (MAC), echoed so the client matches the reply.
    chaddr: [u8; 16],
    /// Broadcast flag from the request; if set, the client wants a broadcast
    /// reply (it has no IP configured to receive a unicast one).
    broadcast: bool,
}

/// Parse a guest DHCP packet. Returns `None` unless it is a well-formed
/// `DISCOVER` or `REQUEST` (the only messages this minimal server answers).
/// Panic-free and bounds-checked.
pub(super) fn parse(payload: &[u8]) -> Option<DhcpRequest> {
    if payload.len() < MIN_LEN {
        return None;
    }
    // op == 1 is a BOOTREQUEST (client → server).
    if payload[0] != 1 {
        return None;
    }
    let xid: [u8; 4] = payload[4..8].try_into().ok()?;
    let flags = u16::from_be_bytes([payload[10], payload[11]]);
    let broadcast = flags & 0x8000 != 0;
    let chaddr: [u8; 16] = payload[28..44].try_into().ok()?;

    // The magic cookie must precede the options.
    if payload[BOOTP_HEADER_LEN..BOOTP_HEADER_LEN + 4] != MAGIC_COOKIE {
        return None;
    }

    // Walk options for the message type (option 53).
    let mut pos = MIN_LEN;
    let mut msg_type = None;
    while pos < payload.len() {
        let code = payload[pos];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            pos += 1;
            continue;
        }
        // Every other option is TLV: code, len, value.
        let len = *payload.get(pos + 1)? as usize;
        let val_start = pos + 2;
        let val_end = val_start.checked_add(len)?;
        let value = payload.get(val_start..val_end)?;
        if code == OPT_MSG_TYPE && len == 1 {
            msg_type = Some(value[0]);
        }
        pos = val_end;
    }

    let kind = match msg_type? {
        DHCP_DISCOVER => MsgKind::Discover,
        DHCP_REQUEST => MsgKind::Request,
        _ => return None,
    };
    Some(DhcpRequest {
        kind,
        xid,
        chaddr,
        broadcast,
    })
}

/// Build the reply (`OFFER` for a `DISCOVER`, `ACK` for a `REQUEST`) for the
/// single static lease. `guest`/`gateway`/`dns` are the addresses to advertise;
/// `mtu` is the link MTU.
pub(super) fn build_reply(
    req: &DhcpRequest,
    guest: Ipv4Address,
    gateway: Ipv4Address,
    dns: Ipv4Address,
    mtu: u16,
) -> Vec<u8> {
    let msg_type = match req.kind {
        MsgKind::Discover => DHCP_OFFER,
        MsgKind::Request => DHCP_ACK,
    };

    let mut p = vec![0u8; MIN_LEN];
    p[0] = 2; // op = BOOTREPLY
    p[1] = 1; // htype = Ethernet
    p[2] = 6; // hlen = 6
    p[4..8].copy_from_slice(&req.xid);
    // flags: echo the client's broadcast bit.
    if req.broadcast {
        p[10] = 0x80;
    }
    // yiaddr = the address we're assigning.
    p[16..20].copy_from_slice(&guest.octets());
    // siaddr = next server (us).
    p[20..24].copy_from_slice(&gateway.octets());
    // chaddr = client MAC, echoed.
    p[28..44].copy_from_slice(&req.chaddr);
    // Magic cookie.
    p[BOOTP_HEADER_LEN..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);

    // Options.
    let mask = Ipv4Address::new(255, 255, 255, 0);
    push_opt(&mut p, OPT_MSG_TYPE, &[msg_type]);
    push_opt(&mut p, OPT_SERVER_ID, &gateway.octets());
    push_opt(&mut p, OPT_LEASE_TIME, &LEASE_SECS.to_be_bytes());
    push_opt(&mut p, OPT_SUBNET_MASK, &mask.octets());
    push_opt(&mut p, OPT_ROUTER, &gateway.octets());
    push_opt(&mut p, OPT_DNS, &dns.octets());
    push_opt(&mut p, OPT_MTU, &mtu.to_be_bytes());
    p.push(OPT_END);
    p
}

/// Append one TLV option.
fn push_opt(buf: &mut Vec<u8>, code: u8, value: &[u8]) {
    buf.push(code);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

/// Fuzz entry point for the untrusted DHCP parser. Must never panic.
#[doc(hidden)]
pub fn fuzz_parse_dhcp(payload: &[u8]) {
    let _ = parse(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DHCP DISCOVER/REQUEST for tests.
    fn request(msg_type: u8, broadcast: bool) -> Vec<u8> {
        let mut p = vec![0u8; MIN_LEN];
        p[0] = 1; // BOOTREQUEST
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // xid
        if broadcast {
            p[10] = 0x80;
        }
        p[28..34].copy_from_slice(&[0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC]); // chaddr MAC
        p[BOOTP_HEADER_LEN..MIN_LEN].copy_from_slice(&MAGIC_COOKIE);
        push_opt(&mut p, OPT_MSG_TYPE, &[msg_type]);
        p.push(OPT_END);
        p
    }

    #[test]
    fn parses_discover() {
        let r = parse(&request(DHCP_DISCOVER, true)).expect("valid discover");
        assert_eq!(r.kind, MsgKind::Discover);
        assert_eq!(r.xid, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(r.broadcast);
    }

    #[test]
    fn parses_request() {
        let r = parse(&request(DHCP_REQUEST, false)).expect("valid request");
        assert_eq!(r.kind, MsgKind::Request);
    }

    #[test]
    fn ignores_non_request_messages() {
        // An ACK (server→client) is not something we answer.
        assert!(parse(&request(DHCP_ACK, false)).is_none());
    }

    #[test]
    fn reply_carries_lease_options() {
        let req = parse(&request(DHCP_DISCOVER, true)).unwrap();
        let reply = build_reply(
            &req,
            Ipv4Address::new(10, 0, 2, 15),
            Ipv4Address::new(10, 0, 2, 2),
            Ipv4Address::new(10, 0, 2, 3),
            1500,
        );
        assert_eq!(reply[0], 2, "BOOTREPLY");
        assert_eq!(&reply[4..8], &[0xDE, 0xAD, 0xBE, 0xEF], "xid echoed");
        assert_eq!(&reply[16..20], &[10, 0, 2, 15], "yiaddr is the guest IP");
        assert_eq!(
            &reply[28..34],
            &[0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC],
            "chaddr echoed"
        );
        // Parse the reply back to confirm the message type is OFFER.
        let mt = find_opt(&reply, OPT_MSG_TYPE).expect("msg type present");
        assert_eq!(mt, &[DHCP_OFFER]);
        assert_eq!(find_opt(&reply, OPT_ROUTER).unwrap(), &[10, 0, 2, 2]);
        assert_eq!(find_opt(&reply, OPT_DNS).unwrap(), &[10, 0, 2, 3]);
        assert_eq!(
            find_opt(&reply, OPT_SUBNET_MASK).unwrap(),
            &[255, 255, 255, 0]
        );
    }

    #[test]
    fn request_reply_is_ack() {
        let req = parse(&request(DHCP_REQUEST, false)).unwrap();
        let reply = build_reply(
            &req,
            Ipv4Address::new(10, 0, 2, 15),
            Ipv4Address::new(10, 0, 2, 2),
            Ipv4Address::new(10, 0, 2, 3),
            1500,
        );
        assert_eq!(find_opt(&reply, OPT_MSG_TYPE).unwrap(), &[DHCP_ACK]);
    }

    #[test]
    fn never_panics_on_truncation() {
        let full = request(DHCP_DISCOVER, true);
        for len in 0..=full.len() {
            fuzz_parse_dhcp(&full[..len]);
        }
    }

    #[test]
    fn never_panics_on_garbage() {
        for len in 0..280usize {
            fuzz_parse_dhcp(&vec![0u8; len]);
            fuzz_parse_dhcp(&vec![0xffu8; len]);
            let ramp: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31) ^ len) as u8).collect();
            fuzz_parse_dhcp(&ramp);
        }
    }

    /// Find an option's value in a built packet (test helper).
    fn find_opt(packet: &[u8], code: u8) -> Option<&[u8]> {
        let mut pos = MIN_LEN;
        while pos < packet.len() {
            let c = packet[pos];
            if c == OPT_END {
                break;
            }
            if c == OPT_PAD {
                pos += 1;
                continue;
            }
            let len = *packet.get(pos + 1)? as usize;
            let start = pos + 2;
            let end = start + len;
            if c == code {
                return packet.get(start..end);
            }
            pos = end;
        }
        None
    }
}
