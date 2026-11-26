# Proposed Windows binding for vhost-user

This is a working proposal, not an accepted extension of the
[vhost-user specification][vhost]. It replaces Unix socket transport and
`SCM_RIGHTS` with local Windows RPC and typed kernel resources. The vhost-user
header, request numbers, feature negotiation, payloads, replies and device/queue
lifecycle are unchanged. Unix implementations continue to use their existing
binding.

The binding must support independently managed peers, either connection role,
bidirectional resource transfer and persistent servers. Connection failure does
not require terminating either process. Process launch, supervision, confinement
and restart policy remain outside the protocol.

## Connection and messages

Use Windows local RPC (`ncalrpc`), available with `system_handle` on Windows 10
1607 / Windows Server 2016 or later. The prototype's complete interface is in
[`wire.idl`](deps/dillo-windows-channel/wire.idl). Its UUID/version and resource
tags are provisional until specification review.

The listening endpoint supplies an RPC endpoint name and a listener object UUID
through configuration. Either the vhost-user frontend or backend can listen.
The connector opens a connection. The interface has three operations:

- `Open`: return a fresh, unpredictable connection UUID and an owned lifetime
  pipe writer. The listener retains the pipe reader.
- `Send`: deliver one opaque message and its ordered resource attachments to
  the listening side.
- `Receive`: return one message and attachments sent by the listening side.

`Send` and `Receive` operate concurrently. Each direction has one logical sender
and receiver; implementations serialize messages within a direction. A persistent
server can own many connections and retain its listener after one closes.
Closing every connector-side lifetime writer releases that connection's queued
resources when the listener observes pipe closure. The pipe carries no message
payload; any byte or terminal read error also closes the connection. Implementations
must observe it even when no message calls are active. Listener identity checks
authorize every call, and connection UUIDs are resolved only within that listener.
The prototype uses asynchronous RPC with cancellation/disconnect notifications
so a pending receive or backpressured send can be interrupted.

The RPC packet contains a byte-array length, the unchanged complete vhost-user
message bytes, and an ordered typed resource array. The vhost-user header's
`size` still counts only its payload. This envelope is transport metadata, not a
new vhost-user request or feature. There is no resource receipt protocol or
extra acknowledgement per attachment. A successful transport call establishes
message acceptance, not successful execution of a vhost-user operation;
`REPLY_ACK` and ordinary replies retain their specified meanings.

Validate a complete packet before dispatch. Message bounds and native resource
types are checked before allocation/adoption; the vhost-user decoder still
checks header length, flags, negotiated operations and attachment counts. The
prototype bounds a packet to 65,536 bytes and 240 resources and buffers one
packet per direction. These are explicit reference-implementation limits, not
claims that every optional vhost-user feature fits them.

## Resource ownership and failure

RPC [`system_handle`][handles] performs transfer in either direction. Neither
peer opens the other process or receives `PROCESS_DUP_HANDLE` authority.
Original application resources remain owned by their callers.

For an RPC input, Windows creates a temporary receiver-side handle valid for
the call. The receiver locally duplicates it before retaining the resource.
Windows releases the temporary when the call ends. For an RPC output, the
server hands a dedicated owned handle to RPC; successful delivery gives the
caller an owned handle. If the server also needs the resource, it keeps its
original handle and transfers a duplicate.

Three distinct failure cases matter:

1. **No complete accepted message:** runtime transfer references and any
   partially acquired receiver references must be released. No vhost-user
   request is dispatched.
2. **Accepted message, uncertain return:** the receiver may already own the
   resources or have executed the request. The sender must not retry the
   request or close a receiver handle by number. Fail the connection and
   release its queued resources; preserve the existing vhost-user policy for
   already applied device state.
3. **Peer or connection loss:** cancel/drain outstanding transport operations,
   close the lifetime writer and release unconsumed packets. Pipe closure
   releases listener-side connection state independently of other clients or
   connections. Listener-side shutdown releases its queues and interrupts any
   pending message operations.

The lifetime writer is an RPC output: if `Open` cannot deliver it, RPC closes
its transfer reference, which also lets the listener retire the new connection.
This deliberately avoids RPC context handles. Their failed-close cleanup can
depend on a shared association pool; native probes retained the abandoned
context's resource with another binding alive, using both classic and fast RPC
bindings with unique-binding/no-linger options. A per-connection pipe supplies
an independently releasable kernel lifetime instead. No cleanup RPC or mandatory
peer termination is needed. See Microsoft's [context failure semantics][contexts].

This is the same distinction between resource transfer and application effects
that exists with Unix descriptor passing. A transport failure cannot prove a
request had no effect. Reconnection, when supported by the application, creates
a new context and follows vhost-user's existing state reconstruction rules;
this binding adds no automatic replay or exactly-once promise.

A received handle retains its native rights. The sender should reduce rights
before transfer; omitted MIDL access masks preserve those rights. The receiver
still validates that the object and its bounds/permissions suit the negotiated
operation. Ownership transfer does not establish the truth of a peer's
resource description. Kernel/runtime cleanup of an in-flight reference also
does not revoke a handle already retained by a peer or drain that peer's I/O.

## Native resource meanings

The prototype supports these resource tags:

- **Event:** queue kick/call/error notification. A userspace notification uses
  an initially nonsignaled auto-reset event with one logical consumer. Publish
  queue state before signaling; signals can coalesce. Follow existing virtio
  ordering and suppression rules, not a count inferred from event signals.
  Wait and signal rights can be granted independently.
- **Section:** shared memory, using the existing address, size and offset
  fields. Native alignment, mapped bounds and access rights still apply.
- **File or pipe:** only where the negotiated operation defines a corresponding
  file or stream resource. An arbitrary native file does not become a Unix
  device solely because it is transferable.

For a protocol channel such as `SET_BACKEND_REQ_FD`, the prototype transfers a
read-only section containing rendezvous information for another connection of
this binding: `WMCHAN1\0`, a 16-byte Windows UUID representation, then 64 UTF-16LE
code units containing a NUL-terminated RPC endpoint name. The receiver copies
and validates these 152 bytes before connecting. Endpoint names contain ASCII
letters, digits or hyphens and have at most 63 characters. This descriptor is
an address, not authentication or an already connected stream. The sender owns
the auxiliary listener and must release pending listeners on session failure
or an expired connection deadline. Auxiliary protocol bytes retain their own
specified encoding.

Windows events also support native notification/interrupt acceleration. The
binding does not require converting them into pipe messages. Section transfer
works in both directions, which leaves room for backend-provided memory.
DAX, GPU/dma-buf equivalents, migration and other optional resources still need
explicit native semantics before their features can be advertised. This
proposal does not claim they work merely because handles can be transferred.

## Costs shared by binding adopters

Authenticate peers using Windows security identity and authorize the particular
listener. An address or a peer-supplied PID is not authority. Client bindings
permit identification rather than granting server impersonation rights.

All implementations need the local RPC runtime/version, compatible marshalling
for this interface, connection lifecycle/cleanup, ordered messages and typed native
resource semantics. An implementation retaining an input handle beyond its RPC
call must duplicate that handle locally; mapping a section during the call can
instead retain the resulting view. Auxiliary protocol channels require a new
rendezvous connection and management of unaccepted listeners. These are binding
costs even if another implementation expresses them in fewer lines of code.

Each connection also requires a lifetime pipe, its two endpoint references and
ongoing closure observation. This is an additional binding cost; RPC pooling
cannot be assumed to provide independent per-connection retirement. The binding
does not require a dedicated monitoring thread.

Each `Send` or `Receive` also has an RPC request/reply envelope. The connector
issues a `Receive` call for each message from the listener, including unsolicited
vhost-user messages. Returning borrowed input buffers/handles to their caller
requires native call completion. Asynchronous implementations can overlap these
calls, but do not remove their traffic or lifetime obligations. RPC completion
does not replace a vhost-user reply or `REPLY_ACK`. These control-plane costs
do not put RPC calls into virtqueue payload transfer or native notification.

The binding does not prescribe a programming language, compiler, queue layout,
thread per connection, object-type discovery API or particular number of message
copies. It adds no process-launch convention or mandatory peer termination.

## Costs of the Dillo reference implementation

This implementation generates MIDL stubs with the Windows SDK/MSVC toolchain and
uses a C boundary for calls and Windows exception handling. Those build choices
are not requirements on every adopter. Safe Rust owns connection queues and
retained resources. Each direction buffers one copied packet; blocking waits
occupy RPC manager threads. A dedicated thread watches each lifetime pipe; an
implementation using asynchronous I/O could share that scheduling. The adapter
queries object types with `NtQueryObject`
before choosing the union arm. An implementation whose API already knows each
resource's type need not perform that query. None of these choices belongs in
the normative wire contract.

Dillo checks the kernel token on every call and authorizes each listener for its
worker's unique AppContainer SID. The library also supports user SIDs. That
particular authorization policy, 30-second worker connection deadline and
same-executable launch are Dillo choices. Guest payloads remain in shared memory;
the copied packets carry control messages. Successful Dillo execution tests one
implementation, not the minimality of its queueing, scheduling or copy strategy.

## Qualification and limits

Native probes have exercised bidirectional event/section/pipe transfer, reduced
rights, rejected calls, cancellation, peer death, undelivered outputs, context
rundown and AppContainer access. They also expose RPC context-pool retention;
the connection-lifetime design must pass its own independent-closure fixture.
They distinguish client reply delivery from the
slightly later server-stub cleanup. Object reference counts are a diagnostic
oracle only, never part of the binding.

The Windows probe workflow runs those diagnostics, the production-library
tests and Dillo's confined device-worker fixture. The library tests exercise
repeated connections, pending accepts, identity rejection and queued-resource
cleanup while the server survives. The worker fixture covers actual shared
memory, notifications, device I/O, reset, malformed replies and worker failure.
Repository CI additionally exercises native KVM, HVF and WHP guests. Results
must be tied to the tested revision; the former named-pipe/numeric-handle
binding's passing CI does not qualify its replacement.

No external vhost-user interoperability, Windows ARM64 execution, exhaustive
failure-interleaving proof or support for all optional features is claimed.
Dillo's bootstrap and host-service grants remain application-specific and
separate from vhost-user; Winsock grants still use their existing private path.

[vhost]: https://www.qemu.org/docs/master/interop/vhost-user.html
[handles]: https://learn.microsoft.com/en-us/windows/win32/midl/system-handle
[contexts]: https://learn.microsoft.com/en-us/windows/win32/rpc/failure-semantics-for-context-handles
