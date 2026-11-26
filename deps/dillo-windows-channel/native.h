// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Private native ABI subset. These declarations are not a Win32 SDK contract.
// Layouts checked against Microsoft's MIT-licensed OpenVMM implementation:
// support/pal/src/windows/alpc.rs at 3bbdedc19c1a2990f5af19777d430e81c0688ab4.
#ifndef CHANNEL_NATIVE_H
#define CHANNEL_NATIVE_H
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0a00
#endif
#include <windows.h>
#include <winternl.h>
#include <stdint.h>

typedef struct {
    USHORT data_length, total_length, type, data_offset;
    CLIENT_ID client;
    ULONG id;
    union { SIZE_T view_size; ULONG callback; } u;
} PortMessage;

typedef struct {
    ULONG flags;
    SECURITY_QUALITY_OF_SERVICE qos;
    SIZE_T max_message, bandwidth, max_pool, max_section, max_view, max_total;
    ULONG object_types;
} PortAttributes;

typedef struct { ULONG allocated, valid; } Attributes;
typedef struct { ULONG flags, handle, object_type, access; } HandleEntry;
typedef struct {
    ULONG flags;
    union { HANDLE handle; HandleEntry *array; } u;
    union { ULONG object_type, count; } v;
    ULONG access;
} HandleAttribute;
typedef struct {
    void *port_context, *message_context;
    ULONG sequence, message_id, callback;
} ContextAttribute;
typedef struct { ULONG index, flags, handle, object_type, access; } HandleInfo;

#define ATTR_HANDLE 0x10000000u
#define ATTR_CONTEXT 0x20000000u
#define SAME_ACCESS 0x10000u
#define INDIRECT_HANDLES 0x40000u
#define RELEASE_MESSAGE 0x10000u
#define SYNC_REQUEST 0x20000u
#define CONTINUATION 0x2000u
#define TYPE_DATAGRAM 3
#define TYPE_CLOSED 5
#define TYPE_CONNECT 10
#define TYPE_CANCELLED 12
#define STATUS_TIMEOUT_VALUE ((NTSTATUS)0x102)

NTSTATUS NTAPI NtAlpcDisconnectPort(HANDLE, ULONG);
NTSTATUS NTAPI NtAlpcOpenSenderProcess(HANDLE *, HANDLE, PortMessage *, ULONG,
    ACCESS_MASK, OBJECT_ATTRIBUTES *);
NTSTATUS NTAPI NtAlpcCreatePort(HANDLE *, OBJECT_ATTRIBUTES *, PortAttributes *);
NTSTATUS NTAPI NtAlpcConnectPort(HANDLE *, UNICODE_STRING *, OBJECT_ATTRIBUTES *,
    PortAttributes *, ULONG, PSID, PortMessage *, SIZE_T *, Attributes *,
    Attributes *, LARGE_INTEGER *);
NTSTATUS NTAPI NtAlpcAcceptConnectPort(HANDLE *, HANDLE, ULONG, OBJECT_ATTRIBUTES *,
    PortAttributes *, void *, PortMessage *, Attributes *, BOOLEAN);
NTSTATUS NTAPI NtAlpcSendWaitReceivePort(HANDLE, ULONG, PortMessage *, Attributes *,
    PortMessage *, SIZE_T *, Attributes *, LARGE_INTEGER *);
NTSTATUS NTAPI NtAlpcQueryInformationMessage(HANDLE, PortMessage *, ULONG,
    void *, ULONG, ULONG *);
NTSTATUS NTAPI AlpcInitializeMessageAttribute(ULONG, Attributes *, SIZE_T, SIZE_T *);
void *NTAPI AlpcGetMessageAttribute(Attributes *, ULONG);
ULONG NTAPI AlpcMaxAllowedMessageLength(void);

_Static_assert(sizeof(void *) == 8, "ALPC channel requires the 64-bit ABI");
_Static_assert(sizeof(PortMessage) == 40, "PORT_MESSAGE ABI");
_Static_assert(sizeof(PortAttributes) == 72, "ALPC_PORT_ATTRIBUTES ABI");
_Static_assert(sizeof(HandleAttribute) == 24, "ALPC_HANDLE_ATTR ABI");
#endif
