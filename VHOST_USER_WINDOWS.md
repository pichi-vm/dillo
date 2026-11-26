# Proposed Windows binding for vhost-user

This working proposal carries unchanged [vhost-user][vhost] message bytes and
ordered resource attachments over Windows ALPC. It is not an accepted protocol
extension. Frontend/backend roles are independent of listener/connector roles.
Peers can be independently managed processes, and a persistent listener can
serve multiple connections.

## Messages and resources

One native datagram contains one complete vhost-user header and payload. Handles
are attached in their existing order through ALPC's handle attributes. The
vhost-user size field still describes its payload. Native message headers and
attachment attributes are transport metadata; device commands, feature bits,
replies and REPLY_ACK retain their existing meanings.

The sender retains its original handles. The kernel holds references associated
with a queued message; the receiver acquires its own handles and releases the
native message continuation. Continuation release is kernel bookkeeping, not
acknowledgement that a vhost-user operation executed. Partial imports must close
all acquired handles and release the continuation before failing the connection.

Resource meanings are:

- Sections: shared memory with the existing GPA, size and offset descriptions.
  Recipients validate native extent, mapping alignment and required access.
- Events: initially nonsignaled auto-reset events with one logical consumer.
  Queue publication precedes signaling. Signals may coalesce; queue state, not
  an event count, determines available work. Wait/signal rights can be reduced.
- Files/pipes: only for operations specifying corresponding file/stream behavior.

A protocol channel such as SET_BACKEND_REQ_FD is represented by a read-only
section containing `WMALPC1\0` followed by 64 UTF-16LE code units: an endpoint
name terminated by NUL. Names contain at most 63 ASCII letters, digits or hyphens.
The peer copies the descriptor into owned storage and connects to that endpoint.
The address provides no authentication. Pending auxiliary listeners must be
retired on connection failure or their application's connection deadline.
ALPC port handles themselves cannot be transferred as attachments.

## Connection authority and failure

A listener applies a Windows ACL and checks the kernel-provided connecting
process identity. Dillo uses the particular worker's AppContainer SID; the
channel library also supports a user SID. Its identity check opens the sender
through the live native connection request with query-only process access,
then closes that handle. It does not impersonate the peer. Resource transfer
requires no permission to manipulate another process's handle table.

Native connection closure cancels queued transfers independently of other live
connections. The receiver must also discard its own unread messages and retire
already adopted resources through its normal device teardown. Either process
can remain alive. Send completion does not prove peer receipt or execution;
closing a sender can discard native queued messages. Use existing vhost-user
replies/REPLY_ACK where completion matters. An uncertain operation must not be
automatically replayed after failure. Reconnection reconstructs device state
according to the negotiated vhost-user features.

## Dillo implementation

The Windows channel uses a private native API boundary linked against ntdll.
Its declarations follow the native layouts also used by [OpenVMM][openvmm]; this
is a native ABI maintenance dependency, not a public Win32 SDK guarantee. The C
boundary requires no generated RPC stubs. Dillo builds and qualifies Windows
using `x86_64-pc-windows-msvc`; the standalone experiment's MinGW builds are
additional portability evidence for other adopters.

A listener dispatcher receives native messages and routes them by kernel port
context. Accepted connections retain that dispatcher after the public listener
is dropped. Connecting peers receive directly on their native ports. Native
disconnect interrupts local operations. The port closes after in-flight native
calls release it, notifying the peer without risking handle reuse under a call.
Receive waits include a local cancellation event, so shutdown also wins a race
with a receive that has not entered the kernel yet.
The implementation bounds accepted-but-unclaimed connections and queued bytes,
messages and handles per connection, and caps each native port's message pool
at 32 MiB. Exhaustion of a connection's receive queue disconnects that connection
rather than blocking unrelated clients. These limits and scheduling choices
are not requirements of the proposed binding.

Dillo limits complete messages to 60 KiB (leaving room for the native header
within ALPC's 16-bit extent) and attachments to 240 handles. Its existing private
metadata protocol chunks larger values; guest payloads remain in shared memory.
Dillo's launch/bootstrap policy and native socket grants remain separate from
vhost-user. Optional DAX/GPU/migration resources require defined native semantics
before their features can be advertised.

The standalone native experiment is recorded in [the probe report][probe].
Production qualification additionally requires the channel lifecycle tests,
confined device-worker fixtures and full native guest CI at the implementation's
exact revision. Neither a successful transfer nor green compilation establishes
external interoperability, every optional feature or performance improvement.

[vhost]: https://www.qemu.org/docs/master/interop/vhost-user.html
[openvmm]: https://github.com/microsoft/openvmm/blob/3bbdedc19c1a2990f5af19777d430e81c0688ab4/support/pal/src/windows/alpc.rs
[probe]: probes/windows-alpc/README.md
