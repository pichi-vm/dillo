# virtio-console: named MULTIPORT ports — design

Grounding design for extending dillo's singular virtio-console with named
MULTIPORT ports. This document locks CLI/schema/device rules only. A later
three-way consensus plan covers implementation sequencing; do not treat this
file as a crate patch list or build plan.

## Scope & locked decisions

### Device

- **One** plugged virtio-console (virtio device ID **3**). No second console
  instance for named ports. No new virtio device ID.
- Negotiate `VIRTIO_CONSOLE_F_MULTIPORT` when the layout's `ports=` list is
  present (non-empty after parse). Without `ports=`, keep today's single-port
  console behavior (no MULTIPORT feature).
- **DT-006** (see top-level `DESIGN-RULES.md`): discovery via virtio-mmio or
  PCI. The device tree may declare those transports; it must **not** describe
  virtio-console devices or their ports. Platform UART / early serial may stay
  DT-governed when present.

### Port 0 vs named ports

| Port | How it appears | Host wiring |
|------|----------------|-------------|
| **0** (unnamed) | Always present when `endpoint=stdio`; guest `hvc0` as today | Wired to the console endpoint (stdio) |
| **1..N** | Each entry in `ports=` is an **additional** named MULTIPORT port | Per-port `rx` / `tx` pipe backends (or closed) |

`ports=` does **not** replace port 0. With `endpoint=stdio`, port 0 remains the
implied unnamed hvc0 path; named ports are extras advertised over the control
plane.

### CLI / layout (house style)

Extend the singular top-level `ConsoleSpec` — nested `ports` list, same shape
as gpt `partitions=[[…]]` and net `forwards=[…]`. Same schema for CLI and JSON
(argh + serde_keyvalue + dillo-config). Console stays on `Layout.console`; it
does **not** move into `devices[]`.

**CLI:**

```
--console endpoint=stdio,ports=[[name=build,rx=pipe:3,tx=pipe:4],[name=log,tx=pipe:5]]
```

**JSON:**

```json
"console": {
  "endpoint": "stdio",
  "ports": [
    {"name": "build", "rx": "pipe:3", "tx": "pipe:4"},
    {"name": "log", "tx": "pipe:5"}
  ]
}
```

Bare `--console stdio` (no `ports=`) remains valid and means today's single-port
console.

## Schema

### `ConsoleSpec` (extended)

| field      | required | meaning |
|------------|----------|---------|
| `endpoint` | yes when `ports=` present; otherwise defaults to `stdio` as today | Port-0 host endpoint. v1: only `stdio` (existing resolve check). |
| `bus`      | optional | Placement (unchanged). |
| `slot`     | optional | Placement (unchanged). |
| `ports`    | optional; default empty / omitted | Nested list of `ConsolePortSpec`. When present and non-empty ⇒ MULTIPORT. |

**Rule:** `endpoint` is **required** whenever `ports=` is present. Reject configs
that set `ports=` without an explicit endpoint.

### `ConsolePortSpec`

| field  | required | meaning |
|--------|----------|---------|
| `name` | yes | Free-form unique string among ports on this console. Not a reserved keyword space. |
| `rx`   | no | Host→guest data path (`pipe:N`). Omit ⇒ that direction **closed**. |
| `tx`   | no | Guest→host data path (`pipe:N`). Omit ⇒ that direction **closed**. |

Names must be unique within the console's `ports` list. Uniqueness vs port 0's
unnamed identity is automatic (port 0 has no `name` field).

### Polarity (device-perspective)

Align with virtio-console device TX/RX, not "operator send/receive":

| field | Device sense | Data direction |
|-------|--------------|----------------|
| `tx=` | Device transmit | **guest → host** |
| `rx=` | Device receive  | **host → guest** |

Omitting `rx` or `tx` means that direction is **closed** (uni-directional port).
Omission is **not** a silent default to stdio. A port with both omitted is
name-only (control-plane advertised, no data workers).

## `pipe:N` host mapping

`N` is an **inherited host file-descriptor / handle number** for the device-side
end of an anonymous pipe the **parent process** creates and passes into dillo.

| value | dillo action |
|-------|--------------|
| `rx=pipe:N` | dillo **reads** host FD / handle `N` (host→guest) |
| `tx=pipe:N` | dillo **writes** host FD / handle `N` (guest→host) |

- Prefix is always `pipe:N` on Linux, macOS, and Windows.
- Dual anonymous pipes are the host backend for bi-directional ports (one FD for
  each open direction).
- OS-specific inheritance mechanics (Unix `CLOEXEC` / pass-fd, Windows handle
  inheritance, etc.) stay behind the host-backend boundary; the layout string
  does not change.
- **Not** named FIFOs, Unix domain sockets, or a second numbering scheme.
- No operator handoff protocol beyond "parent creates pipes and inherits the
  device-side ends into dillo as FD/handle `N`."

## Guest control plane (design intent)

When MULTIPORT is negotiated:

1. Advertise `max_nr_ports` in virtio-console config space large enough for port 0
   plus every named port.
2. Use the control RX/TX queues per virtio 1.x §5.3.
3. Announce each named port with `PORT_ADD` / `PORT_NAME` / open (and related
   control messages) as required for Linux `hvc_virtio` / `virtio_console`.
4. Closed directions have **no** data-path worker and no usable data queue
   traffic in that direction.

Exact message ordering and queue sizing belong in the later implementation plan;
this design only requires conformance with the virtio 1.x multiport control
model so stock Linux guests see named `hvc*` / virtio-console ports.

## Known consumer convention (informative)

Build one-shot flows may use the free-form name `dev.pichi.build` with
`rx=pipe:…` only (host→guest CBOR). That string is a **convention**, not a
schema reserved keyword; the layout accepts any unique free-form `name`.

## Anti-patterns (reject)

Do **not** accept or document:

- A separate `--console-port` flag
- Follow-on `--console port,…` after the primary `--console`
- Packed loose `port=` without nested `[[…]]` list syntax
- Moving console (or its ports) into `devices[]`

## Non-goals (this design)

- No DTB or kernel-cmdline description of console ports (DT-006)
- No second virtio-console instance dedicated to named ports
- No port-0 endpoints other than `stdio` in v1 (keep the existing endpoint check)
- No named FIFOs, path-based backends, or non-`pipe:` host URIs in v1
- Implementation sequencing, crate file diffs, and test matrices — deferred to
  a later consensus implementation plan (Dillo + Claude Opus + Codex)

## Definition of done (design phase)

- This document is merged (or PR-approved) as the locked surface for named
  MULTIPORT ports.
- Follow-on work produces a consensus implementation plan against this design,
  then implements it; merge of implementation still requires Nathaniel's
  explicit yes.
