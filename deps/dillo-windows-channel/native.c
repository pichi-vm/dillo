// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Private ALPC boundary. Rust owns ports, received handles and message queues.
#include "native.h"
#include <sddl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define MAX_DATA (60 * 1024)
#define MAX_HANDLES 240

typedef struct { PortMessage head; unsigned char data[MAX_DATA]; } Message;
typedef union { uint64_t align; unsigned char bytes[128]; } AttributeBuffer;
typedef struct {
    Message message;
    HANDLE handles[MAX_HANDLES];
    ULONG count;
    uintptr_t context;
    ULONG attached;
} Received;

static DWORD result(NTSTATUS status)
{
    if (status == STATUS_TIMEOUT_VALUE) return ERROR_TIMEOUT;
    return status < 0 ? RtlNtStatusToDosError(status) : ERROR_SUCCESS;
}

void wm_free(void *value) { free(value); }

static DWORD token_sid(HANDLE token, BOOLEAN user, BYTE **sid, DWORD *length)
{
    DWORD container = 0, size = 0, error;
    TOKEN_INFORMATION_CLASS kind;
    void *information;
    PSID source;
    if (!user && !GetTokenInformation(token, TokenIsAppContainer, &container,
                                      sizeof(container), &size)) return GetLastError();
    kind = container ? TokenAppContainerSid : TokenUser;
    GetTokenInformation(token, kind, NULL, 0, &size);
    information = malloc(size);
    if (!information) return ERROR_NOT_ENOUGH_MEMORY;
    if (!GetTokenInformation(token, kind, information, size, &size)) {
        error = GetLastError(); free(information); return error;
    }
    source = container ? ((TOKEN_APPCONTAINER_INFORMATION *)information)->TokenAppContainer
                       : ((TOKEN_USER *)information)->User.Sid;
    *length = GetLengthSid(source);
    *sid = malloc(*length);
    if (!*sid) { free(information); return ERROR_NOT_ENOUGH_MEMORY; }
    memcpy(*sid, source, *length);
    free(information);
    return ERROR_SUCCESS;
}

DWORD wm_process_sid(HANDLE process, BYTE **sid, DWORD *length)
{
    HANDLE token;
    DWORD error;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return GetLastError();
    error = token_sid(token, FALSE, sid, length);
    CloseHandle(token);
    return error;
}

DWORD wm_peer_sid(HANDLE port, PortMessage *message, BYTE **sid, DWORD *length)
{
    HANDLE process;
    OBJECT_ATTRIBUTES oa = {0};
    oa.Length = sizeof(oa);
    // Resolve the sender through the live kernel message, not a supplied PID.
    // Query-only authority cannot access the peer's memory or handle table.
    DWORD error = result(NtAlpcOpenSenderProcess(&process, port, message, 0,
                        PROCESS_QUERY_LIMITED_INFORMATION, &oa));
    if (error) return error;
    error = wm_process_sid(process, sid, length);
    CloseHandle(process);
    return error;
}

static PortAttributes port_attributes(void)
{
    PortAttributes a = {0};
    a.flags = 0x20000 | 0x80000 | 0x2000000; // requests, handles, handle arrays
    a.qos.Length = sizeof(a.qos);
    a.qos.ImpersonationLevel = SecurityIdentification;
    a.max_message = sizeof(Message);
    a.max_pool = 32 * 1024 * 1024; // bound native queued-message storage too
    a.max_section = a.max_view = a.max_total = SIZE_MAX;
    a.object_types = 0x0091; // files (including pipes), events and sections
    return a;
}

static UNICODE_STRING port_name(const wchar_t *name, wchar_t *storage)
{
    int count = swprintf(storage, 128, L"\\RPC Control\\%ls", name);
    UNICODE_STRING value = {(USHORT)(count * 2), (USHORT)((count + 1) * 2), storage};
    return value;
}

DWORD wm_listen(const wchar_t *name, const BYTE *sid, DWORD length, HANDLE *port)
{
    HANDLE token;
    BYTE *owner_sid = NULL;
    DWORD owner_length, error;
    LPWSTR owner = NULL, allowed = NULL;
    wchar_t sddl[512], storage[128];
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PortAttributes a = port_attributes();
    UNICODE_STRING path = port_name(name, storage);
    OBJECT_ATTRIBUTES oa = {0};
    // Bounds precede any SID API: these APIs do not take a buffer length.
    if (length < 8 || length != 8u + 4u * sid[1] || !IsValidSid((PSID)sid))
        return ERROR_INVALID_SID;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return GetLastError();
    error = token_sid(token, TRUE, &owner_sid, &owner_length);
    CloseHandle(token);
    if (error) return error;
    if (!ConvertSidToStringSidW(owner_sid, &owner) ||
        !ConvertSidToStringSidW((PSID)sid, &allowed)) { error = GetLastError(); goto out; }
    swprintf(sddl, 512, L"D:P(A;;GA;;;%ls)(A;;GA;;;%ls)S:(ML;;NW;;;LW)", owner, allowed);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &descriptor, NULL)) { error = GetLastError(); goto out; }
    oa.Length = sizeof(oa);
    oa.ObjectName = &path;
    oa.SecurityDescriptor = descriptor;
    a.flags |= 0x40000; // waitable listener, including shutdown wake
    error = result(NtAlpcCreatePort(port, &oa, &a));
out:
    free(owner_sid);
    if (owner) LocalFree(owner);
    if (allowed) LocalFree(allowed);
    if (descriptor) LocalFree(descriptor);
    return error;
}

DWORD wm_connect(const wchar_t *name, HANDLE *port)
{
    wchar_t storage[128];
    UNICODE_STRING path = port_name(name, storage);
    PortAttributes a = port_attributes();
    a.flags |= 0x40000; // waitable client port for cancellable receive
    LARGE_INTEGER timeout = {.QuadPart = -300000000};
    return result(NtAlpcConnectPort(port, &path, NULL, &a, SYNC_REQUEST,
                                   NULL, NULL, NULL, NULL, NULL, &timeout));
}

DWORD wm_accept(HANDLE listener, PortMessage *message, uintptr_t context,
                 BOOLEAN allow, HANDLE *port)
{
    PortAttributes a = port_attributes();
    return result(NtAlpcAcceptConnectPort(port, listener, 0, NULL, &a,
        (void *)context, message, NULL, allow));
}

void wm_disconnect(HANDLE port) { NtAlpcDisconnectPort(port, 0); }

static DWORD attributes(AttributeBuffer *buffer)
{
    SIZE_T required;
    memset(buffer, 0, sizeof(*buffer));
    return result(AlpcInitializeMessageAttribute(ATTR_HANDLE | ATTR_CONTEXT,
        (Attributes *)buffer, sizeof(*buffer), &required));
}

DWORD wm_send(HANDLE port, const BYTE *bytes, DWORD size, const HANDLE *handles, DWORD count)
{
    Message *message;
    AttributeBuffer buffer;
    HandleEntry entries[MAX_HANDLES] = {0};
    Attributes *a = (Attributes *)&buffer;
    DWORD error;
    if (size > MAX_DATA || count > MAX_HANDLES) return ERROR_INVALID_PARAMETER;
    error = attributes(&buffer);
    if (error) return error;
    if (count) {
        HandleAttribute *h = AlpcGetMessageAttribute(a, ATTR_HANDLE);
        for (ULONG i = 0; i < count; ++i) {
            if ((uintptr_t)handles[i] > UINT32_MAX) return ERROR_INVALID_HANDLE;
            entries[i].flags = SAME_ACCESS;
            entries[i].handle = (ULONG)(uintptr_t)handles[i];
        }
        if (count == 1) { h->flags = SAME_ACCESS; h->u.handle = handles[0]; }
        else { h->flags = INDIRECT_HANDLES; h->u.array = entries; h->v.count = count; }
        a->valid = ATTR_HANDLE;
    }
    message = calloc(1, sizeof(PortMessage) + size);
    if (!message) return ERROR_NOT_ENOUGH_MEMORY;
    message->head.data_length = (USHORT)size;
    message->head.total_length = (USHORT)(sizeof(PortMessage) + size);
    memcpy(message->data, bytes, size);
    error = result(NtAlpcSendWaitReceivePort(port, RELEASE_MESSAGE, &message->head, a,
                                           NULL, NULL, NULL, NULL));
    free(message);
    return error;
}

static DWORD release_message(HANDLE port, PortMessage *message)
{
    PortMessage reply = {0};
    NTSTATUS status;
    if (!(message->type & CONTINUATION)) return ERROR_SUCCESS;
    reply.id = message->id;
    reply.u.callback = message->u.callback;
    reply.total_length = sizeof(reply);
    status = NtAlpcSendWaitReceivePort(port, RELEASE_MESSAGE, &reply, NULL,
                                     NULL, NULL, NULL, NULL);
    // A peer can close after delivery and cancel this native continuation.
    if (status == (NTSTATUS)0xc0000703 || status == (NTSTATUS)0xc0000037) return ERROR_SUCCESS;
    return result(status);
}

DWORD wm_receive(HANDLE port, HANDLE stopped, Received *r)
{
    AttributeBuffer buffer;
    Attributes *a = (Attributes *)&buffer;
    SIZE_T size = sizeof(r->message);
    LARGE_INTEGER immediate = {0};
    DWORD error = attributes(&buffer), released;
    NTSTATUS status;
    memset(r, 0, sizeof(*r));
    if (error) return error;
    for (;;) {
        HANDLE waits[2] = {stopped, port};
        DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0) return ERROR_OPERATION_ABORTED;
        if (wait != WAIT_OBJECT_0 + 1) return GetLastError();
        a->valid = 0;
        size = sizeof(r->message);
        status = NtAlpcSendWaitReceivePort(port, 0, NULL, NULL, &r->message.head,
                                          &size, a, &immediate);
        if (status != STATUS_TIMEOUT_VALUE) break;
    }
    if (status < 0) return result(status);
    if (a->valid & ATTR_CONTEXT) {
        ContextAttribute *c = AlpcGetMessageAttribute(a, ATTR_CONTEXT);
        r->context = (uintptr_t)c->port_context;
    }
    r->attached = !!(a->valid & ATTR_HANDLE);
    if (r->message.head.data_length > MAX_DATA ||
        r->message.head.total_length != sizeof(PortMessage) + r->message.head.data_length ||
        r->message.head.total_length > size) error = ERROR_INVALID_DATA;
    if (!error && r->attached && (r->message.head.type & 0xff) == TYPE_DATAGRAM) {
        HandleAttribute *h = AlpcGetMessageAttribute(a, ATTR_HANDLE);
        if (h->v.count > MAX_HANDLES) error = ERROR_INVALID_DATA;
        for (ULONG i = 0; !error && i < h->v.count; ++i) {
            HandleInfo info = {.index = i};
            error = result(NtAlpcQueryInformationMessage(port, &r->message.head, 3,
                           &info, sizeof(info), NULL));
            if (!error) r->handles[r->count++] = (HANDLE)(uintptr_t)info.handle;
        }
    }
    released = (r->message.head.type & 0xff) == TYPE_CONNECT
        ? ERROR_SUCCESS : release_message(port, &r->message.head);
    if (!error) error = released;
    if (error) {
        for (ULONG i = 0; i < r->count; ++i) CloseHandle(r->handles[i]);
        r->count = 0;
    }
    return error;
}
