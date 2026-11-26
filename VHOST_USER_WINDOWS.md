# Proposed Windows binding for vhost-user

Status: provisional binding implemented on `milestone/vhost-user`; design
finalization and upstream specification review remain separate steps. This is
a platform binding for the [vhost-user specification][vhost], with three changes:
message transport, attachment transfer, and native resource meanings. Requests,
replies, feature bits, header fields, payloads, and device lifecycle stay as
specified. Unix wire behavior is unchanged.

## 1. Message transport

Use a local duplex named pipe with `PIPE_TYPE_MESSAGE` and
`PIPE_READMODE_MESSAGE` on both ends. Restrict access to the intended peers and
prohibit remote clients. Each write contains exactly one complete message:

```text
request:u32 | flags:u32 | size:u32 | payload[size] | handles:u64[]
```

The existing header, payload, and native byte order are unchanged. `size` still
counts only payload bytes. Remaining bytes in the pipe message are ordered
64-bit handle values, replacing the ordered descriptors in Unix ancillary data.
The pipe supplies the boundary, so there is no outer header or handle-count
field. A message with no attachments has exactly the existing message bytes.

Receive a complete bounded message before dispatch. Reject short headers,
invalid payload sizes, a trailer not divisible by eight, and attachment counts
inconsistent with the negotiated operation. Derive limits from that operation;
never allocate solely from a peer's length. For example, `SET_MEM_TABLE` keeps
one attachment per declared region, while the existing invalid-FD flag in
`SET_VRING_KICK` still selects zero attachments. Optional attachments in replies
are observable from the message boundary without changing the reply payload.

Serialize writes and retain asynchronous I/O buffers until completion. A
single protocol message must not be split into several writes or combined with
another message. Partial reads with `ERROR_MORE_DATA` continue the same pipe
message; an early message boundary is truncation, not permission to read the
next message. Use overlapped I/O for cancellation and progress, not `PIPE_NOWAIT`.
These are documented [named-pipe semantics][pipe].

Endpoint configuration selects this binding; there is no autodetection,
additional handshake, or Windows feature bit. The ordinary vhost-user version
and feature negotiation remain in use. Backend-request channels use the same
binding; any negotiated auxiliary protocol retains its own header and payload.

## 2. Attachment transfer

The frontend holds a trusted handle to the backend process with
`PROCESS_DUP_HANDLE`. Connection establishment supplies and retains that process
object; an incoming PID is never authority. The backend receives no duplication
authority over the frontend. These roles do not depend on who listens or who
launches the other process. Every transmitted handle value is **backend-local**.

- **Frontend to backend:** the frontend duplicates each attachment into the
  backend, then sends the resulting values. The backend adopts those handles.
- **Backend to frontend:** the backend creates a dedicated local duplicate per
  attachment and relinquishes it to the transfer. The frontend imports it with
  `DuplicateHandle(backend, value, self, ..., DUPLICATE_CLOSE_SOURCE)`, consuming
  the temporary backend handle. Only the returned local handle is adopted.

Original application handles remain owned by their callers. Each transfer
duplicate has one recipient and is never reused for another attachment. Once
the send is submitted, the sender must not use or close that duplicate, even
if delivery fails: the receiver may already have consumed it and its number
may have been reused. No receipt, transfer ID, or pending-acknowledgement map
is needed. Ordinary replies and `REPLY_ACK` keep their existing semantics;
handles attached to replies need no extra acknowledgement either.

Reject null, pseudo-handles, and repeated attachment values within a message.
Use non-inheritable duplicates and access rights appropriate to the operation.
The frontend never adopts an incoming integer as its own handle. Validate
imported resources through their intended native APIs; a malicious backend can
substitute an object from its own handle table. Successful import establishes
ownership, not the truth of the backend's description.

[`DuplicateHandle`][duplicate] closes the source when `DUPLICATE_CLOSE_SOURCE`
is used even if the call fails. Do not retry that handle value or close it a
second time. On incomplete import, close acquired local handles and fail the
connection before dispatching the operation.

Delivery and duplication are not one transaction. Failed or abandoned sends
can leave transfer duplicates in the backend. Do not reclaim uncertain values
later by number or replay an uncertain operation. Bound queued transfers and
account for these grants during retirement; a supervised backend can be
terminated and reaped to release its handles. Native I/O references need their
own completion. Supporting a persistent backend that must survive arbitrary
transfer failures would require additional cleanup machinery.

## 3. Native resource meanings

- **Mapped memory:** use section handles with the existing region address,
  length, and mapping-offset fields. Validate native alignment, bounds, and
  access. Receiving a section does not authorize extra guest-visible mappings.
- **Notifications:** use Windows events in the existing kick/call/error
  operations. Give the backend wait access for kicks and signal access for
  calls/errors. A userspace receiver uses an initially nonsignaled auto-reset
  event with one logical consumer. Publish queue state before signaling and
  recheck it under virtio's existing ordering and suppression rules. Signals
  may coalesce; do not infer a completion count or manually reset after reading
  the queue. Native event consumers must preserve those semantics. See
  [Windows event semantics][event].
- **Protocol channels:** pass a message-mode pipe endpoint where the protocol
  specifies a control socket, including `SET_BACKEND_REQ_FD`. Migration data
  streams retain their separately specified stream semantics.

Events permit native [doorbell][doorbell] and [interrupt][trigger] acceleration;
a pipe-only rule would require conversion to those native event endpoints.
No in-band notification requirement or hypervisor-specific message is added.

Advertise optional features only when their resource semantics are supported.
Bidirectional handles permit backend-owned memory, including future DAX or
accelerator bindings; a Windows section or GPU handle is not automatically a
dma-buf or `userfaultfd`. Such features need their own native object semantics,
not new attachment directions.

## Boundary and remaining cost

Queue start/stop, reset, configuration, negotiation, and replies inherit the
existing specification. Process launch, confinement, resource policy, debugging,
and supervision remain outside this binding. Protocol suspension alone does
not prove a compromised backend released memory or native I/O references.

The frontend's handle-table authority and failed-transfer retirement obligation
are explicit costs. This proposal suits a trusted frontend supervising an
untrusted backend. A mutually isolated, persistent service may instead need
kernel-mediated transfer such as [RPC system handles][rpc]; that would add a
different transport/runtime integration.

## Implementation evidence and limits

Dillo's Windows implementation uses this binding for block, console, network
and filesystem workers. Native CI exercises AppContainer confinement, shared
memory, queue notifications, worker reset/retirement, guest I/O, and handle
round trips in both directions. The native transfer tests also reject invalid
handle values. Process bootstrap and scoped host-resource grants use separate
channels; they add no vhost-user requests or payload fields.

The implementation has not been interoperability-tested with an external
vhost-user implementation. It does not implement DAX, GPU resource semantics,
migration, or every optional protocol feature. Tests do not exhaust native I/O
failure interleavings or prove safe recovery for a persistent backend after an
uncertain transfer. Those remain limits on any upstream compatibility claim.

[vhost]: https://www.qemu.org/docs/master/interop/vhost-user.html
[pipe]: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes
[duplicate]: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
[event]: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw
[doorbell]: https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatenotificationport
[trigger]: https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatetrigger
[rpc]: https://learn.microsoft.com/en-us/windows/win32/midl/system-handle
