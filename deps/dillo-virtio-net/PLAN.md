# virtio-net: user + bridge modes — implementation plan

Grounding doc for adding real networking to dillo's virtio-net device. Follow
this during the build; update it if reality diverges.

## Scope & locked decisions

Three backends, selected by `--net backend=…`:

1. **`user`** (DEFAULT) — cross-platform, no OS permissions. A smoltcp-based
   user-mode NAT: the guest sits on a private `/24` behind the backend, which
   masquerades outbound flows to ordinary host sockets and supports inbound
   **port forwarding**. Single implementation, all platforms, fully CI-testable.
2. **`bridge`** — put the guest on the host's real L2 segment. One CLI, per-OS
   implementations behind a cfg-dispatched type:
   - Linux: create a tap and **enslave it to the named bridge** (`iface=br0`),
     needs `CAP_NET_ADMIN`.
   - macOS: `vmnet.framework` `VMNET_BRIDGED_MODE` on `iface=en0`, needs
     root/entitlement (FFI — the project's highest-risk piece).
   - Windows: **unsupported** (clean error), as agreed.
3. **`macvtap`** — Linux-only, already implemented; unchanged.

Removed: `none` (NullBackend) and the standalone `tap` backend. `tap` folds into
`bridge`'s Linux implementation; there is no bare `tap` backend anymore.

`mac` stays a device-level knob (advertised via config space, backend-agnostic).
`iface` is required for `bridge` and `macvtap`, unused by `user`.

### `forwards` schema (user mode only)

`ForwardSpec` deserializes from **either a string shorthand or a struct**, so CLI
key/value and JSON both accept both forms (preserves dillo-config's one-schema
rule).

Fields:

| field   | default       | meaning                                   |
|---------|---------------|-------------------------------------------|
| `proto` | `tcp`         | `tcp` \| `udp`                            |
| `ip`    | `127.0.0.1`   | host bind address (`0.0.0.0` to expose)   |
| `port`  | *required*    | host listen port                          |
| `guest` | = `port`      | guest port (defaults to `port` when omitted) |

Shorthand grammar `[proto:]port[:guest]`, split on `:`, 1–3 parts; the first part
is a proto only if it is exactly `tcp`/`udp`; `ip` is **not** expressible in
shorthand (use the struct form for a custom bind address):

```
2222:22        -> tcp 127.0.0.1:2222 -> guest 22
udp:5353:53    -> udp 127.0.0.1:5353 -> guest 53
2222           -> tcp 127.0.0.1:2222 -> guest 2222
```

Directionality: forwards are **inbound only** (host/outside → guest initiation;
data flows both ways once established). No `direction` field, no `guest-ip`
(the guest has exactly one address, owned by the backend). Outbound
(guest→internet) and guest→host (via the gateway IP) need no rules.

### CLI surface (final)

```
--net                                              # user mode, no forwards (default)
--net backend=user,forwards=[2222:22, udp:5353:53]
--net backend=user,forwards=[[ip=0.0.0.0,port=2222,guest=22]],mac=52:54:00:ab:cd:ef
--net backend=bridge,iface=br0                     # Linux
--net backend=bridge,iface=en0                     # macOS
--net backend=macvtap,iface=macvtap0               # Linux
```

## Network addressing (user mode, slirp-compatible defaults, hardcoded in v1)

- subnet `10.0.2.0/24`, MTU 1500
- gateway / host alias `10.0.2.2`  ← smoltcp interface owns this IP
- DNS `10.0.2.3`
- guest `10.0.2.15`  ← single assigned guest address

Guest is configured via the kernel `ip=` cmdline (`CONFIG_IP_PNP=y`, confirmed on
the firecracker test kernels), so no in-guest tooling or DHCP server is needed
for tests. (A minimal DHCP responder is a possible later nicety, not v1.)

## Dependencies to add (workspace + crate)

- `smoltcp = "0.13"` (default features off; enable `medium-ethernet`, `proto-ipv4`,
  `socket-tcp`, `socket-udp`, `std`/`alloc` as needed). Predominantly safe Rust;
  fits `unsafe_code = "deny"`.
- `mio = { version = "1", features = ["os-poll", "net"] }` — host-socket event loop.

Both go in `[workspace.dependencies]` and the net crate's
`[dependencies]` (mio/smoltcp are cross-platform, so unconditional). `libc`/`nix`
stay `cfg(target_os = "linux")` for bridge/macvtap; macOS adds a `cfg(macos)`
vmnet FFI dependency in a later phase.

## NetBackend trait

Unchanged — `send(&self, frame)` / `recv(&self, buf) -> Option<len>` /
`link_up()`. User mode runs its own internal stack thread; `send`/`recv` are the
queue endpoints into/out of it. This keeps the device's existing RX/TX workers
untouched.

## Crate layout

```
dillo/deps/dillo-virtio-net/src/
  lib.rs              # VirtioNet device (unchanged core); re-exports
  backend.rs          # NetBackend trait (drop NullBackend)
  user/
    mod.rs            # UserNetBackend: construction, stack thread, send/recv queues
    device.rs         # smoltcp phy::Device adapter over two frame queues
    stack.rs          # event loop: demux+provision, iface.poll, pump, mio wait
    tcp.rs            # per-flow TCP proxy (smoltcp socket <-> mio TcpStream)
    udp.rs            # per-flow UDP proxy
    forward.rs        # inbound listeners -> guest-originated connections
  bridge/
    mod.rs            # cfg-dispatched BridgeBackend constructor
    linux.rs          # cfg(linux): create tap + SIOCBRADDIF enslave (+ IFF_UP)
    macos.rs          # cfg(macos): vmnet bridged FFI  (later phase)
  linux_fd.rs         # shared FrameFd (existing; reused by bridge-linux + macvtap)
  macvtap.rs          # existing, unchanged
```

(Remove `tap.rs`; its open logic moves into `bridge/linux.rs`.)

## User mode — core mechanism (the crux + primary spike)

smoltcp is used as a **transport-terminating proxy** (not packet NAT — packet NAT
needs raw sockets = privilege). With `iface.set_any_ip(true)` plus a default
route whose gateway is the interface's own IP (`10.0.2.2`), smoltcp will locally
terminate connections to arbitrary destinations.

To accept arbitrary destination IP **and port**, a single listening socket isn't
enough. The pattern (de-risk in a spike first):

1. **Peek/demux** each guest→host frame with `smoltcp::wire`
   (`EthernetFrame` → `Ipv4Packet` → `TcpPacket`/`UdpPacket`). Extract the 5-tuple.
2. For a TCP **SYN** to an unseen `(dst_ip,dst_port)`, create a smoltcp TCP
   socket and `listen((dst_ip,dst_port))`; for a new UDP `(dst_ip,dst_port)`
   flow, create a bound UDP socket. ARP/ICMP-echo for `10.0.2.2` are handled by
   smoltcp itself.
3. Push the frame into the smoltcp `Device`'s RX queue and `iface.poll(...)`.
4. When a TCP socket reaches `ESTABLISHED`, its local endpoint is the guest's
   intended destination → open the corresponding host connection:
   - `dst == 10.0.2.2` (gateway) → connect host `127.0.0.1:port` (guest→host).
   - `dst == 10.0.2.3:53` → resolve via host (`ToSocketAddrs`) / forward.
   - else → connect the real `dst_ip:dst_port` (guest→internet masquerade).
5. Pump bidirectionally; handle FIN/RST/half-close and backpressure.

**Spike (Phase 0):** prove peek-SYN → provision listening socket → accept →
bridge to a host `TcpStream` for one flow, end to end. This is the one real
unknown; everything after is mechanical.

### Stack thread event loop (`user/stack.rs`)

Single dedicated thread owning `Interface` + `SocketSet` + the mio `Poll`:

```
loop {
  drain inbound guest frames (from send()): demux + provision sockets, push to device RX
  iface.poll(now, &mut device, &mut sockets)
  for each socket with activity: pump <-> its host socket (mio readiness)
  drain device TX queue -> outbound frame queue (consumed by recv())
  wait = min(iface.poll_delay, next timer); mio.poll(wait)   # woken by host-sock readiness or the send() Waker
  if stop flag: return
}
```

- `send(frame)` → push to inbound queue + `mio::Waker.wake()`.
- `recv(buf)` → pop from outbound queue, block up to `RECV_POLL`.
- Lifecycle: thread spawned on `UserNetBackend::new`, joined on `Drop` (Waker
  signals stop).

### Inbound port forwarding (`user/forward.rs`)

At construction, for each `ForwardSpec`: register a mio TCP listener (or UDP
socket) bound to `(ip,port)`. On accept, create a smoltcp TCP socket that
**originates** a connection to `(10.0.2.15, guest)` and bridge it; UDP relays
datagrams on the mapping.

## Bridge mode

`BridgeBackend` is a cfg-selected concrete type implementing `NetBackend`,
constructed in `build_net_device` for `backend=bridge`.

- **Linux (`bridge/linux.rs`)**: open `/dev/net/tun` `IFF_TAP|IFF_NO_PI` (reuse
  the old tap open), then: `if_nametoindex(tap)`, `SIOCBRADDIF` on the bridge
  (`ifreq{ ifr_name=br0, ifr_ifindex=tap_idx }` via `libc::ioctl`), and
  `SIOCSIFFLAGS` IFF_UP on the tap. `#[allow(unsafe_code)]` ioctls, needs
  `CAP_NET_ADMIN`. I/O via the existing `FrameFd`.
- **macOS (`bridge/macos.rs`, later phase + spike)**: vmnet FFI. A small
  `vmnet-sys`-style module linking the framework; `vmnet_start_interface` with an
  XPC param dict (`vmnet_operation_mode_key = VMNET_BRIDGED_MODE`,
  `vmnet_shared_interface_name_key = iface`), a `dispatch_queue`, a completion
  handler, an event callback for read-availability, and `vmnet_read`/`vmnet_write`
  over `vmpktdesc`/`iovec`. Apple blocks bridged via `block2` or a C trampoline.
  Needs root/entitlement. Isolate all unsafe here.
- **Windows**: `#[cfg]` constructor returns a clear "bridge unsupported on this
  host" error.

Not CI-testable (privilege/drivers) → unit-test param/enslave construction;
validate manually; document skip-in-CI.

## dillo-config changes

- `NetBackendKind { #[default] User, Bridge, Macvtap }` (remove `None`, `Tap`).
- `NetSpec`: keep `iface`, `mac`, `bus`, `slot`; add `forwards: Vec<ForwardSpec>`
  (`#[serde(default)]`).
- `ForwardSpec { proto: Proto (#[default] Tcp), ip: IpAddr (#[default]
  127.0.0.1), port: u16, guest: Option<u16> }` with a custom `Deserialize`
  accepting string-or-map and a `FromStr` for the shorthand. `guest` resolves to
  `port` when `None`.
- Validation in `resolve`: `bridge`/`macvtap` require `iface`; `forwards` only
  valid for `user` (error otherwise); MAC parse/derive unchanged.
- `ResolvedDevice::Net { backend, iface, mac, forwards }` (add `forwards`).
- Tests: shorthand↔struct↔JSON parity; shorthand grammar (1/2/3 parts, proto
  detection, guest-defaults-to-port); forwards-rejected-for-non-user.

## main.rs wiring

`build_net_device(backend, iface, mac, forwards)`:
- `User` → `UserNetBackend::new(forwards, …)` (all platforms).
- `Bridge` → cfg: Linux `bridge::linux`, macOS `bridge::macos`, else bail.
- `Macvtap` → cfg(linux) as today, else bail.

CLI doc/comment for `--net` updated to the final surface. `args.net` stays
unconditional (works on all platforms via user mode).

## snuffler — real I/O test (virtio-blk analog)

- `lib.rs`: add `NetBench { tx: NetOp, rx: NetOp }` and `NetOp { bytes, ops,
  duration_us, throughput_mibps, errors, verified }` (clone of `BlkBench`/
  `BlkOp`); add `Report.net_probe.bench: Option<NetBench>` (or a sibling field).
- `main.rs` probe: when `dillo.net_echo=IP:PORT` is present, the guest (already IP-
  configured by the kernel `ip=` cmdline) runs a `std::net` TCP/UDP echo +
  throughput loop against that host endpoint and records `NetBench`. Pure `std`,
  no libc/ioctls — within snuffler's rules (mirrors the vsock probe).

## Boot tests (`dillo/tests/boot.rs`)

- Update existing `boots_with_net`: drop the `none` backend; use `--net`
  (user, default). Keep the PCI-enumeration + assigned-MAC assertions.
- New `boots_with_net_user` (cross-platform, vm-tests): build a PMI with
  `ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off console=hvc0
  dillo.net_echo=10.0.2.2:9` (host echo via a forward or the gateway), boot with
  `--net backend=user,forwards=[…]`, host runs a `std::net` echo server, assert
  the round-trip + `NetBench` (bytes moved, errors==0, verified). Runs on all 4
  lanes (no permissions).
- Kernel DB: `INET`/`PACKET`/`IP_PNP` confirmed `=y` on firecracker v1.15; add
  `IP_PNP`/`INET` to the believed builtins so `require` selects/verifies them.

## Testing strategy

Six layers. Everything pure-Rust (Layers 1, 4, 5) runs on every platform,
including the Windows/macOS cross-builds; the real-guest tests (Layer 2) run on
all four CI lanes; the privilege/driver paths (Layer 3) are opt-in and never in
CI. Per [[always-fix-never-skip]], the only permitted CI skip is no-`/dev/kvm`
locally.

### Layer 1 — pure unit tests (host, no VM, all platforms)

- **Config** (`dillo-config`): shorthand↔struct↔JSON parity; shorthand grammar
  edges (1/2/3 parts, proto detection, `guest`-defaults-to-`port`, malformed);
  validation (`bridge`/`macvtap` require `iface`; `forwards` only valid for
  `user`; MAC parse/derive).
- **Device marshalling** (`lib.rs`): existing RX/TX `virtio_net_hdr`
  strip/prepend + no-RX-buffer tests.
- **User-mode datapath harness (centerpiece):** drive `UserNetBackend` with a
  **second smoltcp stack standing in for the guest** — guest-stack frames →
  `send()`, `recv()` → guest-stack — while the proxy's host side connects to an
  in-process `std::net` listener. Exercises the whole datapath deterministically,
  no VM, on all platforms. Required cases:
  - outbound TCP echo to an arbitrary destination (masquerade),
  - gateway→host-loopback redirect (`10.0.2.2` → `127.0.0.1`),
  - **inbound forward**: host connects to the forward port → guest-stack listener
    accepts (the host→guest direction),
  - a UDP flow (outbound + reply),
  - edge cases: connection-refused → guest sees RST; half-close; a multi-segment
    transfer (windowing); UDP idle-timeout reclaim.
- **Bridge construction** (cfg-gated, no privilege): assert the tap/`SIOCBRADDIF`
  ifreq and the vmnet XPC param dict are built correctly; a missing privilege
  yields a clean error, never a panic (the existing tap-test pattern).

### Layer 2 — integration boot tests (real guest, `vm-tests`, all 4 lanes)

- `boots_with_net`: virtio-net PCI function (`1af4:1041`) enumerates + the guest
  binds the driver and reports the assigned MAC (attach + driver-bind proof).
- `boots_with_net_user`: in a **single boot**, assert both directions and UDP:
  guest→host echo via the gateway; a host→guest connection through a `forward`
  into a listener snuffler opens in the guest; and a UDP leg. Record a
  `NetBench` — `bytes`/`errors`/`verified` are asserted, throughput is telemetry
  only (virtio-blk philosophy). Guest IP via kernel `ip=` (`IP_PNP=y`).

### Layer 3 — bridge integration (opt-in, NEVER in CI)

- Env-gated `#[ignore]`d tests (`DILLO_NET_BRIDGE_TEST=br0` on Linux as root;
  macOS vmnet likewise) that actually move packets, with a **documented setup
  recipe in the crate README** so it is a repeatable procedure. This is the
  confidence mechanism for the paths CI cannot run.

### Layer 4 — negative / error paths (unit)

- `bridge` on Windows → unsupported error; missing `iface` → resolve error;
  `forwards` on a non-`user` backend → resolve error; malformed shorthand →
  parse error; `bridge`/`macvtap` without privilege → clean error, no panic.

### Layer 5 — fuzzing

- A fuzz target for the user-mode guest-frame **demux/provisioning** path
  (untrusted `smoltcp::wire` parsing of guest-controlled Ethernet/IP/TCP/UDP):
  malformed frames must be dropped, never panic, never mis-provision. Lives under
  the existing fuzz setup (`dillo/fuzz`).

### Layer 6 — gates (existing CI)

- `cargo fmt`, rustc `-D warnings`, per-OS workspace tests, boot tests on all
  four lanes. The Layer-1 datapath harness is pure Rust, so it also builds/runs
  on the Windows/macOS lanes.

### Matrix

| test | Linux ×2 | Windows | macOS |
|------|----------|---------|-------|
| config + datapath unit (2-stack) | ✓ | ✓ | ✓ |
| `boots_with_net` (attach + MAC) | ✓ | ✓ | ✓ |
| `boots_with_net_user` (both dirs + UDP, NetBench) | ✓ | ✓ | ✓ |
| bridge unit (param build / unsupported) | ✓ | ✓ (unsupported) | ✓ |
| bridge integration | manual/root | n/a | manual/root |
| fuzz demux | nightly/manual | — | — |

## Build sequencing (keep the tree green each phase)

Each phase lands with its tests green (test layer in parentheses).

- **Phase 0 — spike** smoltcp single-flow TCP proxy (de-risk any-ip + per-flow
  demux). *Tests:* the spike graduates into the **two-stack datapath harness**
  (L1) — a single outbound TCP echo round-trip, asserted. Gate: if this proves
  out, the rest is mechanical.
- **Phase 1 — user backend**: add `smoltcp`/`mio` deps; implement
  `UserNetBackend` (hardcoded defaults, no config wiring yet). *Tests (L1):*
  full datapath harness — outbound TCP, gateway→host redirect, inbound forward,
  UDP, and the edge cases (RST, half-close, multi-segment, UDP timeout).
- **Phase 2 — config**: refactor `dillo-config` (User default + Bridge +
  Macvtap; drop None/Tap; `ForwardSpec` str-or-struct + shorthand; validation).
  *Tests (L1 config + L4):* parity, shorthand grammar, validation, and the
  negative paths (forwards-on-non-user, missing-iface, bad shorthand).
- **Phase 3 — wiring**: `main.rs` `build_net_device`; fold tap→bridge-linux;
  switch existing `boots_with_net` to user mode. *Tests (L2 + L6):*
  `boots_with_net` green on KVM x86_64 locally; workspace + Windows/macOS
  cross-checks green.
- **Phase 4 — snuffler I/O**: `NetBench`/`NetOp` schema + the `dillo.net_echo`
  probe; kernel DB (`IP_PNP`/`INET` beliefs). *Tests (L2):* `boots_with_net_user`
  — both directions + UDP + `NetBench` assertions, run locally on KVM x86_64.
- **Phase 5 — fuzz**: add the demux/provisioning fuzz target. *Tests (L5):* run
  the corpus briefly; confirm malformed frames are dropped without panic.
- **Phase 6 — bridge Linux**: create+enslave (`SIOCBRADDIF`). *Tests (L1 +
  L3):* construction unit tests (ifreq/ioctl args, clean error unprivileged);
  the env-gated `#[ignore]`d integration test + README recipe.
- **Phase 7 — bridge macOS** vmnet (spike + FFI impl). *Tests (L1 + L3):* XPC
  param-dict construction unit test; env-gated integration test + recipe.
- **Phase 8 — ship**: full local vm-tests suite (no regressions) + commit; CI
  green on all 4 platforms. *Tests (L6):* the whole matrix.

## Definition of done

- `user` mode is the default, real outbound + port-forwarding, all platforms, no
  permissions; snuffler `NetBench` round-trip green in CI on all 4 lanes.
- `bridge` works on Linux (root) and macOS (root/vmnet); Windows errors cleanly.
- `macvtap` unchanged and working on Linux.
- `none`/`tap` removed. `cargo fmt` clean; rustc `-D warnings` clean; cross-checks
  for Windows/macOS pass. Per [[always-fix-never-skip]], the only test skip is
  no-/dev/kvm locally.

## Risks

1. **smoltcp per-flow demux / any-ip provisioning** (Phase 0 spike) — the one
   genuine unknown; everything downstream depends on it.
2. **macOS vmnet FFI** (Phase 7) — dispatch/XPC/blocks; root/entitlement; most
   unsafe surface. Isolated and landed last.
3. **Linux bridge enslave** (`SIOCBRADDIF`, Phase 6) — minor ioctl detail.
4. Bridge paths aren't CI-testable → covered by Layer-1 construction unit tests
   plus the Layer-3 env-gated `#[ignore]`d integration tests + README recipe (not
   CI; the documented confidence mechanism for privilege/driver paths).
