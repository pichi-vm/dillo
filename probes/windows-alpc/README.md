# Windows kernel handle-transfer experiment

This report records the standalone experiment at
[`a16e4fd`](https://github.com/pichi-vm/dillo/tree/a16e4fd20586317f3806072b4da11666d0175108).
For the subsequent Dillo integration, see the [Windows binding](../../VHOST_USER_WINDOWS.md).

This standalone C experiment evaluates direct ALPC as a possible Windows
transport binding for vhost-user. Its objective is message-associated kernel
handle transfer without authority over another process's handle table. It does
not change Dillo's production RPC transport or define an accepted extension.

## Candidate and recommendation

ALPC is a smaller transport candidate than the current RPC plus lifetime-pipe
prototype: send the unchanged vhost-user header and payload as one native
message, with its ordered handles in native message attributes. The kernel
retains the transferred objects. Each endpoint owns a connection handle;
closing one connection does not require terminating either process. Both
directions use the same transfer mechanism. There is no MIDL interface, NDR
packet schema, connection UUID, lifetime pipe or remote receive procedure.

Recommend this candidate for the next design discussion, **conditional on
acceptance of its native Windows API dependency**. That is a material cost,
not a detail removed by the successful experiment. The declarations in
[`native.h`](native.h) are outside the supported Win32 SDK interface used by
the RPC alternative. Microsoft's [OpenVMM ALPC implementation][openvmm] is
precedent for their use, not a public compatibility guarantee or evidence that
QEMU will accept them. No upstream submission or production replacement is
part of this experiment.

## Ownership and failure

The sender lends its handles to a send operation and retains its originals.
After successful send it can close those originals. ALPC retains references
associated with the message; handle numbers are never used as authority in
the other process. The receiver obtains its own handles using the native
message-handle query, then releases the message's continuation, when present.
This release is kernel message bookkeeping, not a vhost-user acknowledgment.
The receiver owns and closes every handle it adopted, including on errors
after adopting only part of an attachment array.

The three relevant outcomes remain distinct:

1. Rejected or abandoned transfer: release native message resources and any
   locally acquired handles; do not dispatch an incomplete request.
2. Delivered request with uncertain completion: fail the connection without
   replaying the request or trying to revoke a peer's handles by number.
3. Connection loss: queued transfers are canceled. Already adopted resources
   and application effects still require the receiver's ordinary teardown.

ALPC can discard queued messages when the sender closes its connection. A
successful send is **not** proof that the peer received or executed it. This
differs from assuming that a graceful Unix stream close drains all queued
bytes. Neither binding promises exactly-once application effects. A complete
proposal must describe shutdown ordering explicitly and preserve the existing
vhost-user replies, `REPLY_ACK`, and reconnect/state-reconstruction rules.

## What the executable exercises

[`probe.c`](probe.c) contains the transport mechanics and a two-process
roundtrip. [`lifetime.h`](lifetime.h) and [`container.h`](container.h) contain
diagnostics, not a proposed reusable library or wire protocol.

- Sections and events travel in both directions. The original handles close
  before the returned section contents and event identity are checked.
- A complete `SET_MEM_TABLE` byte sequence is preserved. The extra event is
  deliberately a transport-test attachment; no vhost-user device dispatch or
  external interoperability is claimed.
- A reduced-rights event remains waitable but cannot be signaled by the
  receiver. A send containing an invalid handle fails without retaining the
  valid object supplied beside it.
- The receiver imports only the first of two handles, then abandons the
  message. Both resources are released.
- Either side closes a connection containing an unread transfer. The test
  observes the named lifetime witnesses disappear while both processes and a second connection
  remain alive, then exchanges a message over that second connection.
- A waitable listener handles connection requests and data through a Windows
  wait followed by a nonblocking receive.
- The listener's ACL admits one exact AppContainer SID and denies another.
  The admitted confined process completes the bidirectional roundtrip. The
  executable is the same for parent and children.

Lifetime witnesses are unique named events used only by the test. The queued
cases first confirm the event remains openable after the sender closes its
original handle, then confirm it disappears after connection closure. No
event names or refcounts form part of the proposed transport. The fixture's
named synchronization events, process handles and AppContainer launcher also
remain outside the binding.

## Build and run

Linux cross-build with MinGW GCC:

```sh
mkdir -p target/windows-alpc
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -O2 \
  probes/windows-alpc/probe.c -o target/windows-alpc/probe.exe \
  -lntdll -ladvapi32 -luserenv
```

Use `gcc` in an MSYS2 MINGW64 shell for a native Windows build. Run on Windows:

```powershell
./probes/windows-alpc/run.ps1 -Probe ./target/windows-alpc/probe.exe
```

The [workflow](../../.github/workflows/windows-alpc.yml) runs the cross-built
binary on Windows Server 2022 and 2025 and also builds/runs it with native
MinGW GCC on Server 2025. Logs, OS versions and executable hashes are uploaded
as artifacts. AppContainer cases create temporary profiles and grant those
profiles read/execute access to the fixture directory and binary; use a
disposable test directory. Successful runs delete their profiles.

## Costs and limits for a Windows binding

All adopters would need the native ALPC ABI, message/resource validation,
connection cancellation and message-release handling. A receiver must close
adopted handles even when parsing or dispatch subsequently fails. Native
rights do not establish that a resource matches a peer's declared size/type.
Peer identity, access control, bounds and backpressure need explicit treatment.
The AppContainer test checks listener admission; it does not qualify a full
mutual-authentication scheme or malicious-peer implementation.

The prototype's 4096-byte/eight-handle limits and 64-bit ABI are experimental
limits. The tested Windows versions report a native maximum message length
of 65535. This is not a claim that every optional vhost-user message fits, or
that Windows ARM64, 32-bit peers and all supported client Windows releases
have been qualified. Large messages may require a separately specified native
view or framing mechanism. No automatic fragmentation has been invented here.

ALPC ports themselves cannot simply be attached as another transferable
handle; [OpenVMM uses named rendezvous for this reason][mesh]. An auxiliary
protocol channel such as `SET_BACKEND_REQ_FD` still needs a defined rendezvous
or other native representation. This experiment does not settle that cost.
Likewise, event notification semantics, DAX, GPU resources, migration and other
optional resource meanings require explicit Windows mappings before their
features can be offered. A successful section transfer does not implement DAX.

The IOCP receive experiment did not establish a working integration; the
qualified event-loop primitive is the waitable port. IOCP is not required by
this candidate. The blocking helper functions, fixed buffers, test timeouts and AppContainer
launch policy are choices of this executable. The binding need not prescribe
them, a thread per connection, or a process-supervision scheme. The experiment
does not measure performance, exhaust kernel quotas, kill peers at every
instruction boundary or prove exhaustive failure-interleaving safety.

## QEMU and the RPC alternative

QEMU [supports native and cross MinGW builds][platforms]. This executable
uses that path without MSVC, generated RPC stubs or a Rust runtime. QEMU's
[`qemu_add_wait_object`][wait] already integrates Windows handles into its main
loop, making a waitable ALPC port a plausible adapter point. That is a source
and primitive-level assessment, not a QEMU patch or scalability measurement;
the existing wait-object facility has a finite handle limit.

More integration remains than a transport swap. QEMU's [QIOChannel attachment
API][qio] uses `int` file descriptors and `close()`, not native `HANDLE`s;
its [vhost-user build is disabled on Windows][meson]. Shared-memory resource
export and the chardev/vhost attachment boundary need Windows implementations.
Its [Windows event notifier][notifier] already uses events, but matching the
binding's notification semantics still needs review. No projected patch size
or upstream acceptance is asserted.

The current RPC prototype retains an advantage: [`system_handle`][rpc] has
documented input/output ownership and a supported local-RPC API. It adds an
RPC interface/schema and call completion machinery. Independent connection
retirement in that prototype uses a lifetime pipe because [RPC context
rundown can depend on shared associations][contexts]. Those costs affect
adopters, not just Dillo's implementation.

The inspected [MinGW RPC headers][mingw-rpc] still expand `RpcTryExcept` to
MSVC-style `__try`; a local GCC syntax check rejected that expansion. The
inspected [WIDL source][widl] does not implement the `system_handle` attribute.
This does not prove an RPC binding cannot use MinGW: generated stubs, another
compiler or additional exception-handling support could bridge those gaps.
It does mean the current MSVC/MIDL prototype is not evidence of a simple
stock MinGW GCC build. Direct ALPC avoids those particular toolchain costs
while accepting the native-API maintenance cost instead.

[openvmm]: https://github.com/microsoft/openvmm/blob/3bbdedc19c1a2990f5af19777d430e81c0688ab4/support/pal/src/windows/alpc.rs
[mesh]: https://github.com/microsoft/openvmm/blob/main/support/mesh/mesh_remote/src/alpc_node.rs
[platforms]: https://www.qemu.org/docs/master/about/build-platforms.html
[wait]: https://github.com/qemu/qemu/blob/master/util/main-loop.c
[qio]: https://github.com/qemu/qemu/blob/master/include/io/channel.h
[meson]: https://github.com/qemu/qemu/blob/master/meson.build
[notifier]: https://github.com/qemu/qemu/blob/master/util/event_notifier-win32.c
[rpc]: https://learn.microsoft.com/en-us/windows/win32/midl/system-handle
[contexts]: https://learn.microsoft.com/en-us/windows/win32/rpc/failure-semantics-for-context-handles
[mingw-rpc]: https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/rpc.h
[widl]: https://github.com/mingw-w64/mingw-w64/tree/master/mingw-w64-tools/widl/src
