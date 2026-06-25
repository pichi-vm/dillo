<!-- SPDX-License-Identifier: Apache-2.0 -->
# dillo-virtio-net

In-process virtio-net device for dillo: a cross-platform frontend plus three
host-side backends, selected with `--net backend=…`.

| backend | platforms | privilege | what it does |
|---------|-----------|-----------|--------------|
| `user` (default) | Linux, macOS, Windows | none | user-mode NAT (smoltcp) with outbound masquerade, guest→host, and inbound port forwarding |
| `bridge` | Linux (tap+bridge), macOS (vmnet) | `CAP_NET_ADMIN` / root+entitlement | put the guest on the host's real L2 segment |
| `macvtap` | Linux | `CAP_NET_ADMIN` | attach to an existing macvtap endpoint |

The device itself (the `VirtioDevice`/queue marshalling) is host-agnostic; each
backend just moves raw Ethernet frames in and out (see [`NetBackend`]).

## `user` — default, no privilege, everywhere

A smoltcp-based transport-terminating proxy. The guest sits on a private
`10.0.2.0/24` (gateway/host alias `10.0.2.2`, guest `10.0.2.15`, DNS `10.0.2.3`,
MTU 1500) plus an IPv6 ULA `fd00::/64` (gateway `fd00::2`, DNS `fd00::3`), and
the proxy re-originates its flows as ordinary host sockets driven by a `mio`
event loop. No `/dev/net/tun`, no permissions, identical on every OS.

```
--net                                              # user mode, no forwards
--net backend=user,forwards=[2222:22,udp:5353:53]  # inbound forwards (shorthand)
```

Forward shorthand is `[proto:]port[:guest]` (proto defaults to `tcp`, guest
defaults to the host port, bind defaults to loopback). To bind a non-loopback
address (e.g. expose on `0.0.0.0`), use the JSON `--layout` struct form:

```json
{ "net": { "backend": "user",
           "forwards": [ { "ip": "0.0.0.0", "port": 2222, "guest": 22 } ] } }
```

### Zero-config guest networking

A stock guest "just works" with no in-guest setup:

- **DHCP** — a built-in responder leases the guest `10.0.2.15` with the gateway,
  DNS, `/24` mask, and MTU, so a guest that DHCPs needs no kernel `ip=`. (Static
  config via `ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off`, `CONFIG_IP_PNP=y`,
  still works too.)
- **DNS** — queries to `10.0.2.3:53` (or `[fd00::3]:53`) are answered locally by
  resolving the name through the *host's* resolver (`std::net::ToSocketAddrs`),
  so the guest reaches hostnames with no external resolver. Scope: `A`/`AAAA`
  records (the dominant case); other record types return an empty `NOERROR`.
- **IPv6** — the guest autoconfigures a `fd00::/64` address via SLAAC: the proxy
  answers Router Solicitations with a Router Advertisement (smoltcp has no RA
  server, so this is hand-rolled). Outbound v6 is masqueraded onto host v6
  sockets exactly like v4. (DNS over v6 uses the v4-style alias; the RA carries
  no RDNSS option.)
- **Ping** — the guest can `ping` the gateway (`10.0.2.2` / `fd00::2`); smoltcp
  answers echo requests to its own addresses. Pinging *external* hosts is
  unsupported (no unprivileged, `unsafe`-free, cross-platform way to originate
  ICMP echo).

## `bridge` — join the host L2 segment

Linux creates a tap, enslaves it to the **existing** bridge named by `iface`,
and brings it up. The operator owns the bridge out of band.

macOS uses `vmnet` in bridged mode on the named physical interface (needs root
or the `com.apple.vm.networking` entitlement).

```
--net backend=bridge,iface=br0     # Linux: tap enslaved to bridge br0
--net backend=bridge,iface=en0     # macOS: vmnet bridged onto en0
```

Bridge mode is **unsupported on Windows** (a clean error).

### Setup recipe (Linux) + running the integration test

The bridge datapath needs root and a real bridge, so it is **never exercised in
CI**. Its construction is unit-tested (`braddif_ifreq_layout`,
`open_is_clean_without_privilege`), and a real enslave is covered by an opt-in,
`#[ignore]`d integration test you run manually:

```sh
# 1. Create a bridge (and optionally enslave a NIC to reach the LAN).
sudo ip link add br0 type bridge
sudo ip link set br0 up
# sudo ip link set eth0 master br0     # to bridge onto the physical network

# 2. Run the integration test as root with the bridge named.
sudo DILLO_NET_BRIDGE_TEST=br0 \
  cargo test -p dillo-virtio-net -- --ignored bridge_enslaves_tap

# 3. Tear down when done.
sudo ip link del br0
```

The test creates a tap via `BridgeBackend::open("br0")`, then asserts the tap's
`/sys/class/net/<tap>/master` link points at `br0` and that the tap is `IFF_UP`.

### Setup recipe (macOS) + running the integration test

`vmnet` bridged mode needs root or the `com.apple.vm.networking` entitlement.
The XPC param-dict construction is unit-tested (`bridged_desc_builds`); a real
start is covered by an opt-in, `#[ignore]`d test run manually:

```sh
# `en0` is typically the primary Ethernet/Wi-Fi interface (see `ifconfig`).
sudo DILLO_NET_VMNET_TEST=en0 \
  cargo test -p dillo-virtio-net -- --ignored vmnet_starts
```

The test starts vmnet bridged mode on the interface and writes one frame.

## `macvtap` — Linux only

Attach to an existing macvtap link (the operator creates it out of band):

```sh
sudo ip link add link eth0 name macvtap0 type macvtap mode bridge
sudo ip link set macvtap0 address 52:54:00:ab:cd:ef up
```

```
--net backend=macvtap,iface=macvtap0
```

## Testing

- **Layer 1 (all platforms, no VM):** the in-process two-smoltcp-stack datapath
  harness in `src/user/tests.rs` exercises outbound TCP, gateway→host redirect,
  inbound forward, UDP (including concurrent sources to one destination), the
  DNS responder, the DHCP OFFER/ACK exchange, gateway ping, the IPv6 datapath
  (gateway6 redirect, v6 UDP), and SLAAC Router Advertisement; plus edge cases
  (RST, half-close, multi-segment), the hand-rolled DNS/DHCP/NDP parsers (unit +
  fuzz), and config and bridge/macvtap construction unit tests.
- **Manual real-network repros (`--ignored`):** `masquerade_holds_to_real_internet`
  (TCP/443), `masquerade_holds_to_real_internet_v6` (v6/443),
  `dns_masquerade_to_real_resolver` and `dns_resolves_real_name` — needing real
  outbound connectivity, so they're run by hand, not in CI.
- **Layer 2 (real guest, CI):** dillo's `boots_with_net` (attach + MAC) and
  `boots_with_net_user` — guest↔host TCP/UDP, an inbound forward, **and real
  internet reach** (`dillo.net_reach=`: the guest masquerades to a well-known
  external endpoint on 443 and the connection holds), all asserted via
  `NetBench` on every CI lane.
- **Layer 3 (opt-in, never CI):** the bridge integration test above.
- **Layer 5 (fuzz):** `dillo/fuzz` target `net_demux` fuzzes the untrusted
  guest-frame demux.

[`NetBackend`]: src/backend.rs
