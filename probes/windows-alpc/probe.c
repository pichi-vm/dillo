// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Native transport experiment. No peer process handles, RPC stubs or broker.
#include "native.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sddl.h>

#define MAX_DATA 4096
#define MAX_HANDLES 8
typedef struct { PortMessage head; unsigned char data[MAX_DATA]; } Message;
typedef union { uint64_t align; unsigned char bytes[128]; } AttributeBuffer;
typedef struct {
    Message message;
    AttributeBuffer attributes;
    HANDLE handles[MAX_HANDLES];
    ULONG count;
    uintptr_t context;
} Received;
static int use_waitable_listener;
static HANDLE waitable_listener;
static PSECURITY_DESCRIPTOR listener_security;

static void require(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "FAIL %s (Win32 %lu)\n", what, GetLastError());
        exit(1);
    }
}

static void check(NTSTATUS status, const char *what)
{
    if (status < 0) {
        fprintf(stderr, "FAIL %s (NTSTATUS %08lx)\n", what, (ULONG)status);
        exit(1);
    }
}

static PortAttributes port_attributes(void)
{
    PortAttributes a = {0};
    a.flags = 0x20000 | 0x80000 | 0x2000000; // requests, handles, handle arrays
    a.qos.Length = sizeof(a.qos);
    a.qos.ImpersonationLevel = SecurityIdentification;
    a.max_message = sizeof(Message);
    a.max_pool = a.max_section = a.max_view = a.max_total = SIZE_MAX;
    a.object_types = 0x0091; // files (includes pipes), events, sections only
    return a;
}

static Attributes *attributes(AttributeBuffer *buffer)
{
    SIZE_T required;
    memset(buffer, 0, sizeof(*buffer));
    check(AlpcInitializeMessageAttribute(ATTR_HANDLE | ATTR_CONTEXT,
          (Attributes *)buffer, sizeof(*buffer), &required), "attribute buffer");
    return (Attributes *)buffer;
}

static NTSTATUS try_send(HANDLE port, const void *bytes, size_t size,
                         const HANDLE *handles, ULONG count)
{
    Message m = {0};
    AttributeBuffer buffer;
    Attributes *a = attributes(&buffer);
    HandleEntry entries[MAX_HANDLES] = {0};
    require(size <= MAX_DATA && count <= MAX_HANDLES, "send bounds");
    m.head.data_length = (USHORT)size;
    m.head.total_length = (USHORT)(sizeof(m.head) + size);
    memcpy(m.data, bytes, size);
    if (count) {
        HandleAttribute *h = AlpcGetMessageAttribute(a, ATTR_HANDLE);
        for (ULONG i = 0; i < count; ++i) {
            require((uintptr_t)handles[i] <= UINT32_MAX, "native handle width");
            entries[i].flags = SAME_ACCESS;
            entries[i].handle = (ULONG)(uintptr_t)handles[i];
        }
        if (count == 1) {
            h->flags = SAME_ACCESS;
            h->u.handle = handles[0];
        } else {
            h->flags = INDIRECT_HANDLES;
            h->u.array = entries;
            h->v.count = count;
        }
        a->valid = ATTR_HANDLE;
    }
    return NtAlpcSendWaitReceivePort(port, RELEASE_MESSAGE, &m.head, a,
                                    NULL, NULL, NULL, NULL);
}

static void send_message(HANDLE port, const void *bytes, size_t size,
                         const HANDLE *handles, ULONG count)
{
    check(try_send(port, bytes, size, handles, count), "send opaque message and handles");
}

static NTSTATUS receive_raw(HANDLE port, Received *r)
{
    memset(r, 0, sizeof(*r));
    Attributes *a = attributes(&r->attributes);
    SIZE_T size = sizeof(r->message);
    LARGE_INTEGER timeout = {.QuadPart = -100000000}; // ten seconds
    if (port == waitable_listener) {
        require(WaitForSingleObject(port, 10000) == WAIT_OBJECT_0, "event-loop readiness");
        timeout.QuadPart = 0;
    }
    NTSTATUS s = NtAlpcSendWaitReceivePort(port, 0, NULL, NULL,
        &r->message.head, &size, a, &timeout);
    if (s < 0 || s == STATUS_TIMEOUT_VALUE) return s;
    if (a->valid & ATTR_CONTEXT) {
        ContextAttribute *c = AlpcGetMessageAttribute(a, ATTR_CONTEXT);
        r->context = (uintptr_t)c->port_context;
    }
    return s;
}

static void import_handles(HANDLE port, Received *r, ULONG limit)
{
    Attributes *a = (Attributes *)&r->attributes;
    if (a->valid & ATTR_HANDLE) {
        HandleAttribute *h = AlpcGetMessageAttribute(a, ATTR_HANDLE);
        require(h->v.count <= MAX_HANDLES, "receive handle bound");
        for (ULONG i = 0; i < h->v.count && i < limit; ++i) {
            HandleInfo info = {.index = i};
            check(NtAlpcQueryInformationMessage(port, &r->message.head, 3,
                  &info, sizeof(info), NULL), "take delivered handle");
            r->handles[r->count++] = (HANDLE)(uintptr_t)info.handle;
        }
    }
}

static NTSTATUS receive(HANDLE port, Received *r)
{
    NTSTATUS s = receive_raw(port, r);
    if (s >= 0 && s != STATUS_TIMEOUT_VALUE) import_handles(port, r, MAX_HANDLES);
    return s;
}

static void receive_data(HANDLE port, Received *r)
{
    NTSTATUS s = receive(port, r);
    check(s, "receive data");
    require(s != STATUS_TIMEOUT_VALUE, "receive deadline");
    if ((r->message.head.type & 0xff) != TYPE_DATAGRAM)
        fprintf(stderr, "received type=%04x length=%u\n", r->message.head.type,
                r->message.head.data_length);
    require((r->message.head.type & 0xff) == TYPE_DATAGRAM, "datagram type");
}

static void release_message(HANDLE port, Received *r)
{
    for (ULONG i = 0; i < r->count; ++i) CloseHandle(r->handles[i]);
    r->count = 0;
    if (r->message.head.type & CONTINUATION) {
        PortMessage reply = {0};
        reply.id = r->message.head.id;
        reply.u.callback = r->message.head.u.callback;
        reply.total_length = sizeof(reply);
        NTSTATUS s = NtAlpcSendWaitReceivePort(port, RELEASE_MESSAGE, &reply, NULL,
                                             NULL, NULL, NULL, NULL);
        // A peer can close after delivery; the kernel then cancels the message.
        if (s != (NTSTATUS)0xc0000703 && s != (NTSTATUS)0xc0000037)
            check(s, "release kernel message reference");
    }
}

static UNICODE_STRING port_name(const char *name, wchar_t *storage, size_t count)
{
    int n = swprintf(storage, count, L"\\RPC Control\\%hs", name);
    require(n > 0 && (size_t)n < count, "endpoint name");
    UNICODE_STRING value = {(USHORT)(n * 2), (USHORT)((n + 1) * 2), storage};
    return value;
}

static NTSTATUS try_connect_port(const char *name, HANDLE *port)
{
    wchar_t storage[128];
    UNICODE_STRING path = port_name(name, storage, 128);
    PortAttributes a = port_attributes();
    LARGE_INTEGER timeout = {.QuadPart = -100000000};
    return NtAlpcConnectPort(port, &path, NULL, &a, SYNC_REQUEST, NULL,
                            NULL, NULL, NULL, NULL, &timeout);
}

static HANDLE connect_port(const char *name)
{
    HANDLE port;
    check(try_connect_port(name, &port), "connect");
    return port;
}

static HANDLE accept_port(HANDLE listener, uintptr_t context)
{
    Received r;
    NTSTATUS s = receive_raw(listener, &r);
    check(s, "connection request");
    require(s != STATUS_TIMEOUT_VALUE &&
            (r.message.head.type & 0xff) == TYPE_CONNECT, "connection type");
    PortAttributes a = port_attributes();
    HANDLE peer;
    check(NtAlpcAcceptConnectPort(&peer, listener, 0, NULL, &a,
          (void *)context, &r.message.head, NULL, TRUE), "accept");
    return peer;
}

static HANDLE listen_port(const char *name)
{
    wchar_t storage[128];
    UNICODE_STRING path = port_name(name, storage, 128);
    OBJECT_ATTRIBUTES oa = {.Length = sizeof(oa), .ObjectName = &path,
                            .SecurityDescriptor = listener_security};
    PortAttributes a = port_attributes();
    HANDLE listener;
    if (use_waitable_listener) a.flags |= 0x40000; // waitable port
    check(NtAlpcCreatePort(&listener, &oa, &a), "listen");
    if (use_waitable_listener) waitable_listener = listener;
    return listener;
}

static int server(const char *name)
{
    HANDLE listener = listen_port(name);
    printf("READY max_native_message=%lu\n", AlpcMaxAllowedMessageLength());
    fflush(stdout);
    if (listener_security) {
        char ready_name[200];
        snprintf(ready_name, sizeof(ready_name), "Local\\%s-listening", name);
        HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ready_name);
        require(ready && SetEvent(ready), "signal confined fixture listener");
        CloseHandle(ready);
    }
    Received r;
    HANDLE peer = accept_port(listener, 1);
    receive_data(listener, &r);
    require(r.context == 1, "kernel connection context");
    require(r.count == 2, "section and event arrived");
    uint32_t *memory = MapViewOfFile(r.handles[0], FILE_MAP_WRITE, 0, 0, 4096);
    require(memory != NULL && *memory == 0xfeedcafe, "shared section contents");
    *memory = 0x12345678;
    UnmapViewOfFile(memory);
    require(SetEvent(r.handles[1]), "signal transferred event");
    send_message(peer, r.message.data, r.message.head.data_length, r.handles, 2);
    release_message(listener, &r);
    receive_data(listener, &r);
    require(r.count == 0, "completion carries no handles");
    release_message(listener, &r);
    CloseHandle(peer);
    CloseHandle(listener);
    puts("PASS server roundtrip and clean close");
    return 0;
}

static int client(const char *name)
{
    HANDLE port = connect_port(name);
    HANDLE h[2] = {CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                    0, 4096, NULL), CreateEventW(NULL, FALSE, FALSE, NULL)};
    require(h[0] && h[1], "create source resources");
    uint32_t *memory = MapViewOfFile(h[0], FILE_MAP_WRITE, 0, 0, 4096);
    require(memory != NULL, "map source section");
    *memory = 0xfeedcafe;
    UnmapViewOfFile(memory);
    // A complete standard vhost-user SET_MEM_TABLE envelope (one region).
    const uint32_t bytes[] = {5, 1, 40, 1, 0, 0, 0, 4096, 0, 0, 0, 0, 0};
    // Event is an additional transport-test attachment; no device dispatch here.
    send_message(port, bytes, sizeof(bytes), h, 2);
    CloseHandle(h[0]);
    CloseHandle(h[1]);
    Received r;
    receive_data(port, &r);
    require(r.message.head.data_length == sizeof(bytes) &&
            memcmp(r.message.data, bytes, sizeof(bytes)) == 0, "unchanged vhost bytes");
    require(r.count == 2, "reverse handles arrived");
    require(WaitForSingleObject(r.handles[1], 0) == WAIT_OBJECT_0, "same event object");
    memory = MapViewOfFile(r.handles[0], FILE_MAP_READ, 0, 0, 4096);
    require(memory && *memory == 0x12345678, "same section after source close");
    UnmapViewOfFile(memory);
    release_message(port, &r);
    send_message(port, bytes, sizeof(bytes), NULL, 0);
    NTSTATUS closed = receive_raw(port, &r);
    require(closed == (NTSTATUS)0xc0000037 ||
            (closed == 0 && (r.message.head.type & 0xff) == TYPE_CLOSED),
            "server completed before connection close");
    CloseHandle(port);
    puts("PASS bidirectional handles; original handles closed; unchanged message bytes");
    return 0;
}

// Diagnostic cases are kept apart from the transport mechanics above.
#include "lifetime.h"
#include "container.h"

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    require(argc >= 3 && argc <= 5, "usage: probe server|client endpoint [case]");
    if (!strcmp(argv[1], "container")) return container_probe(argv[2]);
    if (!strcmp(argv[1], "denied")) {
        check_container();
        HANDLE port;
        require(try_connect_port(argv[2], &port) == (NTSTATUS)0xc0000022,
                "wrong AppContainer denied by kernel");
        puts("PASS wrong AppContainer denied");
        return 0;
    }
    if (argc == 5) {
        set_listener_security(argv[4]);
        int result = server(argv[2]);
        LocalFree(listener_security);
        return result;
    }
    if (argc == 4 && !strcmp(argv[3], "confined")) {
        check_container();
        return client(argv[2]);
    }
    if (argc == 4) return lifetime(argv[1], argv[2], argv[3]);
    return strcmp(argv[1], "server") == 0 ? server(argv[2]) : client(argv[2]);
}
