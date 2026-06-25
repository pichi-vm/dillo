// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! IPv6 Router Advertisement for zero-config guest networking.
//!
//! smoltcp answers Neighbor Solicitation for its own addresses automatically,
//! but it has **no Router Advertisement server** — so a guest doing SLAAC never
//! hears about a router or a prefix and can't autoconfigure an IPv6 address. We
//! hand-roll the missing half: detect the guest's Router Solicitation (ICMPv6
//! type 133) and reply with a Router Advertisement (type 134) that advertises
//! the gateway as a default router and the ULA prefix with the ADDRCONF
//! (autonomous) flag set, so the guest forms `PREFIX::<iid>` on its own.
//!
//! All parsing runs on guest-controlled bytes (the fuzzed surface) and is
//! bounds-checked and panic-free. Frame construction uses smoltcp's `wire`
//! builders. No privilege, no `unsafe`.
//!
//! DNS over IPv6: smoltcp's `NdiscRepr` has no RDNSS (RFC 8106) option, so the
//! RA doesn't carry a v6 resolver; the guest uses the IPv4 DNS alias (or a
//! literal resolver). Both DNS aliases answer regardless of how the query rides.

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::time::Duration;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv6Message, Icmpv6Packet, Icmpv6Repr,
    IpProtocol, Ipv6Address, Ipv6Packet, Ipv6Repr, NdiscPrefixInfoFlags as PrefixInfoFlags,
    NdiscPrefixInformation, NdiscRepr, NdiscRouterFlags, RawHardwareAddress,
};

/// Router lifetime advertised: how long the guest treats the gateway as a
/// default router. Refreshed by each solicited RA.
const ROUTER_LIFETIME: Duration = Duration::from_secs(1800);
/// Prefix validity. Long — the prefix is stable for the VM's lifetime.
const PREFIX_LIFETIME: Duration = Duration::from_secs(86_400);

/// Does this frame carry a guest IPv6 **Router Solicitation**? Bounds-checked
/// and panic-free; returns the guest's source link-layer address (its MAC) and
/// source IPv6 address so the RA can be unicast back if desired.
pub(super) fn parse_router_solicit(frame: &[u8]) -> Option<RouterSolicit> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv6 {
        return None;
    }
    let ip = Ipv6Packet::new_checked(eth.payload()).ok()?;
    if ip.next_header() != IpProtocol::Icmpv6 {
        return None;
    }
    let icmp = Icmpv6Packet::new_checked(ip.payload()).ok()?;
    if icmp.msg_type() != Icmpv6Message::RouterSolicit {
        return None;
    }
    // Validate the full ICMPv6 message (checksum, options) via the repr parser.
    let repr = Icmpv6Repr::parse(
        &ip.src_addr(),
        &ip.dst_addr(),
        &icmp,
        &ChecksumCapabilities::ignored(),
    )
    .ok()?;
    if !matches!(repr, Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit { .. })) {
        return None;
    }
    Some(RouterSolicit {
        guest_mac: eth.src_addr(),
        guest_ip: ip.src_addr(),
    })
}

/// A parsed guest Router Solicitation.
pub(super) struct RouterSolicit {
    pub(super) guest_mac: EthernetAddress,
    pub(super) guest_ip: Ipv6Address,
}

/// Build a full Ethernet+IPv6+ICMPv6 Router Advertisement frame replying to
/// `rs`, advertising `gateway` as the router (with `gateway_mac` as its link
/// address) and `prefix`/`prefix_len` as an autonomous SLAAC prefix.
pub(super) fn build_router_advert(
    rs: &RouterSolicit,
    gateway: Ipv6Address,
    gateway_mac: EthernetAddress,
    prefix: Ipv6Address,
    prefix_len: u8,
    mtu: u32,
) -> Vec<u8> {
    let advert = Icmpv6Repr::Ndisc(NdiscRepr::RouterAdvert {
        hop_limit: 64,
        flags: NdiscRouterFlags::empty(), // no DHCPv6 (stateless SLAAC only)
        router_lifetime: ROUTER_LIFETIME,
        reachable_time: Duration::ZERO,
        retrans_time: Duration::ZERO,
        lladdr: Some(RawHardwareAddress::from(gateway_mac)),
        mtu: Some(mtu),
        prefix_info: Some(NdiscPrefixInformation {
            prefix_len,
            // ON_LINK: the prefix is on this link. ADDRCONF: use it for SLAAC.
            flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
            valid_lifetime: PREFIX_LIFETIME,
            preferred_lifetime: PREFIX_LIFETIME,
            prefix,
        }),
    });

    // RAs are sent from the router's link-local-or-global source to the
    // soliciting guest. We use the gateway ULA as source and unicast back to the
    // guest's source address (valid: the guest already has a link-local).
    let ip = Ipv6Repr {
        src_addr: gateway,
        dst_addr: rs.guest_ip,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 255, // NDP requires 255 so receivers know it wasn't forwarded
        payload_len: advert.buffer_len(),
    };

    let mut buf =
        vec![0u8; EthernetFrame::<&[u8]>::header_len() + ip.buffer_len() + advert.buffer_len()];
    let mut eth = EthernetFrame::new_unchecked(&mut buf);
    eth.set_src_addr(gateway_mac);
    eth.set_dst_addr(rs.guest_mac);
    eth.set_ethertype(EthernetProtocol::Ipv6);
    {
        let mut ipp = Ipv6Packet::new_unchecked(eth.payload_mut());
        ip.emit(&mut ipp);
        let mut icmp = Icmpv6Packet::new_unchecked(ipp.payload_mut());
        advert.emit(
            &ip.src_addr,
            &ip.dst_addr,
            &mut icmp,
            &ChecksumCapabilities::default(),
        );
    }
    buf
}

/// Fuzz entry point for the untrusted Router Solicitation parser. Never panics.
#[doc(hidden)]
pub fn fuzz_parse_router_solicit(frame: &[u8]) {
    let _ = parse_router_solicit(frame);
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST_MAC: EthernetAddress = EthernetAddress([0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC]);
    const GW_MAC: EthernetAddress = EthernetAddress([0x52, 0x54, 0x00, 0x12, 0x35, 0x02]);

    /// Build a guest Router Solicitation frame (Ethernet+IPv6+ICMPv6) from a
    /// link-local source to the all-routers multicast.
    fn router_solicit_frame() -> Vec<u8> {
        let src = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x15);
        let dst = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2); // all-routers
        let rs = Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit {
            lladdr: Some(RawHardwareAddress::from(GUEST_MAC)),
        });
        let ip = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 255,
            payload_len: rs.buffer_len(),
        };
        let mut buf =
            vec![0u8; EthernetFrame::<&[u8]>::header_len() + ip.buffer_len() + rs.buffer_len()];
        let mut eth = EthernetFrame::new_unchecked(&mut buf);
        eth.set_src_addr(GUEST_MAC);
        eth.set_dst_addr(EthernetAddress([0x33, 0x33, 0, 0, 0, 2]));
        eth.set_ethertype(EthernetProtocol::Ipv6);
        let mut ipp = Ipv6Packet::new_unchecked(eth.payload_mut());
        ip.emit(&mut ipp);
        let mut icmp = Icmpv6Packet::new_unchecked(ipp.payload_mut());
        rs.emit(&src, &dst, &mut icmp, &ChecksumCapabilities::default());
        buf
    }

    #[test]
    fn parses_router_solicit() {
        let frame = router_solicit_frame();
        let rs = parse_router_solicit(&frame).expect("valid RS");
        assert_eq!(rs.guest_mac, GUEST_MAC);
    }

    #[test]
    fn ignores_non_rs_frames() {
        // An all-zeros frame and a truncated RS must not parse as an RS.
        assert!(parse_router_solicit(&[0u8; 60]).is_none());
        let frame = router_solicit_frame();
        assert!(parse_router_solicit(&frame[..frame.len() - 1]).is_none());
    }

    #[test]
    fn builds_a_parseable_advert() {
        let rs = parse_router_solicit(&router_solicit_frame()).unwrap();
        let gateway = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let prefix = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let frame = build_router_advert(&rs, gateway, GW_MAC, prefix, 64, 1500);

        // Parse it back: Ethernet → IPv6 → ICMPv6 RouterAdvert with our prefix.
        let eth = EthernetFrame::new_checked(&frame[..]).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);
        assert_eq!(eth.dst_addr(), GUEST_MAC);
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
        assert_eq!(ip.hop_limit(), 255, "NDP requires hop limit 255");
        let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
        let repr = Icmpv6Repr::parse(
            &ip.src_addr(),
            &ip.dst_addr(),
            &icmp,
            &ChecksumCapabilities::default(),
        )
        .expect("valid RA");
        match repr {
            Icmpv6Repr::Ndisc(NdiscRepr::RouterAdvert {
                prefix_info: Some(pi),
                router_lifetime,
                ..
            }) => {
                assert_eq!(pi.prefix, prefix);
                assert_eq!(pi.prefix_len, 64);
                assert!(pi.flags.contains(PrefixInfoFlags::ADDRCONF), "SLAAC flag");
                assert!(router_lifetime > Duration::ZERO, "advertises a router");
            }
            other => panic!("expected RouterAdvert with prefix, got {other:?}"),
        }
    }

    #[test]
    fn never_panics_on_garbage() {
        for len in 0..200usize {
            fuzz_parse_router_solicit(&vec![0u8; len]);
            fuzz_parse_router_solicit(&vec![0xffu8; len]);
            let ramp: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31) ^ len) as u8).collect();
            fuzz_parse_router_solicit(&ramp);
        }
    }
}
