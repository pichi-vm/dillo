// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// MIDL owns marshalling. Keep Windows SEH inside C, outside Rust stack frames.
#include <windows.h>
#include <rpc.h>
#include <rpcasync.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>
#include "wire.h"

extern unsigned long wm_authorize_sid(const UUID *, const BYTE *, unsigned long);
extern unsigned long wm_server_open(const UUID *, UUID *, HANDLE *);
extern unsigned long wm_context_matches(const UUID *, const UUID *);
extern unsigned long wm_server_send(const UUID *, const Packet *, HANDLE, HANDLE);
extern unsigned long wm_server_receive(const UUID *, Packet *, HANDLE, HANDLE);

void *__RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void __RPC_USER midl_user_free(void *value) { free(value); }
void *wm_allocate(size_t size) { return calloc(1, size); }
void wm_free(void *value) { free(value); }

static DWORD token_sid(HANDLE token, BYTE **sid, DWORD *length)
{
    DWORD container = 0, size = 0, error;
    TOKEN_INFORMATION_CLASS kind;
    void *information;
    PSID source;
    if (!GetTokenInformation(token, TokenIsAppContainer, &container, sizeof(container), &size))
        return GetLastError();
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
    DWORD result;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return GetLastError();
    result = token_sid(token, sid, length);
    CloseHandle(token);
    return result;
}

static RPC_STATUS RPC_ENTRY authorize(RPC_IF_HANDLE interface_id, void *binding)
{
    UUID object;
    HANDLE token;
    BYTE *sid = NULL;
    DWORD length = 0, result;
    (void)interface_id;
    result = RpcBindingInqObject(binding, &object);
    if (result) return result;
    result = RpcImpersonateClient(binding);
    if (result) return result;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) result = GetLastError();
    else { result = token_sid(token, &sid, &length); CloseHandle(token); }
    {
        DWORD reverted = RpcRevertToSelfEx(binding);
        if (reverted) result = reverted;
    }
    if (!result) result = wm_authorize_sid(&object, sid, length);
    free(sid);
    return result;
}

DWORD wm_start(const wchar_t *endpoint)
{
    PSECURITY_DESCRIPTOR descriptor;
    DWORD result;
    // The endpoint permits entry to the per-listener identity check above.
    // It grants no access to a listener or its messages by itself.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;WD)(A;;GA;;;AC)S:(ML;;NW;;;LW)", SDDL_REVISION_1, &descriptor, NULL))
        return GetLastError();
    result = RpcServerUseProtseqEpW((RPC_WSTR)L"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                                    (RPC_WSTR)endpoint, descriptor);
    if (!result) result = RpcServerRegisterIf3(server_LocalMessage_v1_0_s_ifspec, NULL, NULL,
        RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY | RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH
            | RPC_IF_SEC_NO_CACHE,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT, 65536, authorize, descriptor);
    LocalFree(descriptor);
    return result;
}

DWORD wm_bind(const wchar_t *endpoint, const UUID *object, handle_t *binding)
{
    RPC_WSTR address = NULL;
    DWORD result = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL,
        (RPC_WSTR)endpoint, (RPC_WSTR)L"Security=identification static true", &address);
    if (!result) result = RpcBindingFromStringBindingW(address, binding);
    if (address) RpcStringFreeW(&address);
    if (!result) result = RpcBindingSetObject(*binding, (UUID *)object);
    if (result && *binding) RpcBindingFree(binding);
    return result;
}

void wm_unbind(handle_t *binding) { RpcBindingFree(binding); }

DWORD wm_lifetime_pipe(HANDLE *reader, HANDLE *writer)
{
    UUID id;
    RPC_WSTR text = NULL;
    wchar_t name[96];
    OVERLAPPED operation = {0};
    DWORD result = UuidCreate(&id), count;
    *reader = *writer = INVALID_HANDLE_VALUE;
    if (result && result != RPC_S_UUID_LOCAL_ONLY) return result;
    result = UuidToStringW(&id, &text);
    if (result) return result;
    swprintf_s(name, 96, L"\\\\.\\pipe\\vhost-lifetime-%ls", text);
    RpcStringFreeW(&text);
    *reader = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED
        | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
        | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, NULL);
    if (*reader == INVALID_HANDLE_VALUE) return GetLastError();
    *writer = CreateFileW(name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (*writer == INVALID_HANDLE_VALUE) { result = GetLastError(); goto fail; }
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) { result = GetLastError(); goto fail; }
    if (!ConnectNamedPipe(*reader, &operation)) {
        result = GetLastError();
        if (result == ERROR_PIPE_CONNECTED) result = ERROR_SUCCESS;
        else if (result == ERROR_IO_PENDING)
            result = GetOverlappedResult(*reader, &operation, &count, TRUE) ? 0 : GetLastError();
    }
    CloseHandle(operation.hEvent);
    if (!result) return ERROR_SUCCESS;
fail:
    if (*writer != INVALID_HANDLE_VALUE) CloseHandle(*writer);
    CloseHandle(*reader);
    *reader = *writer = INVALID_HANDLE_VALUE;
    return result;
}

void wm_watch_lifetime(HANDLE reader, HANDLE stopped)
{
    OVERLAPPED operation = {0};
    HANDLE events[2];
    BYTE byte;
    DWORD count;
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) return;
    events[0] = operation.hEvent;
    events[1] = stopped;
    if (!ReadFile(reader, &byte, 1, &count, &operation) && GetLastError() == ERROR_IO_PENDING) {
        WaitForMultipleObjects(2, events, FALSE, INFINITE);
        // The buffer and OVERLAPPED remain live until cancellation/completion drains.
        CancelIoEx(reader, &operation);
        GetOverlappedResult(reader, &operation, &count, TRUE);
    }
    CloseHandle(operation.hEvent);
}

typedef struct {
    RPC_BINDING_HANDLE call;
    HANDLE events[2];
    unsigned int subscribed;
} Notifications;

static const RPC_NOTIFICATIONS kinds[2] = {RpcNotificationCallCancel, RpcNotificationClientDisconnect};

static void notifications_end(Notifications *state)
{
    unsigned int i;
    for (i = 0; i != state->subscribed; ++i) {
        unsigned long queued = 0;
        DWORD result = RpcServerUnsubscribeForNotification(state->call, kinds[i], &queued);
        if (!result) {
            if (queued) WaitForSingleObject(state->events[i], INFINITE);
            CloseHandle(state->events[i]);
        }
        // An unexpected native failure must not reuse an event still owned by RPC.
    }
}

static DWORD notifications_begin(PRPC_ASYNC_STATE async, Notifications *state)
{
    unsigned int i;
    DWORD result;
    RPC_ASYNC_NOTIFICATION_INFO info;
    memset(state, 0, sizeof(*state));
    state->call = RpcAsyncGetCallHandle(async);
    for (i = 0; i != 2; ++i) {
        state->events[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!state->events[i]) { result = GetLastError(); break; }
        info.hEvent = state->events[i];
        result = RpcServerSubscribeForNotification(state->call, kinds[i], RpcNotificationTypeEvent, &info);
        if (result) { CloseHandle(state->events[i]); break; }
        ++state->subscribed;
    }
    if (state->subscribed == 2) return ERROR_SUCCESS;
    notifications_end(state);
    return result;
}

void server_Open(PRPC_ASYNC_STATE async, handle_t binding, Connection *connection, HANDLE *lifetime)
{
    UUID object;
    DWORD result = RpcBindingInqObject(binding, &object);
    memset(connection, 0, sizeof(*connection));
    *lifetime = NULL;
    if (!result) result = wm_server_open(&object, connection, lifetime);
    RpcAsyncCompleteCall(async, &result);
}

static DWORD check_context(handle_t binding, const Connection *connection)
{
    UUID object;
    DWORD result = RpcBindingInqObject(binding, &object);
    return result ? result : wm_context_matches(&object, connection);
}

void server_Send(PRPC_ASYNC_STATE async, handle_t binding, Connection connection, Packet *packet)
{
    Notifications notifications;
    DWORD result = check_context(binding, &connection);
    if (!result) result = notifications_begin(async, &notifications);
    if (!result) {
        result = wm_server_send(&connection, packet, notifications.events[0], notifications.events[1]);
        notifications_end(&notifications);
    }
    RpcAsyncCompleteCall(async, &result);
}

void server_Receive(PRPC_ASYNC_STATE async, handle_t binding, Connection connection, Packet *packet)
{
    Notifications notifications;
    DWORD result = check_context(binding, &connection);
    memset(packet, 0, sizeof(*packet));
    if (!result) result = notifications_begin(async, &notifications);
    if (!result) {
        result = wm_server_receive(&connection, packet, notifications.events[0], notifications.events[1]);
        notifications_end(&notifications);
    }
    RpcAsyncCompleteCall(async, &result);
}

void wm_packet_free(Packet *packet, int resources);

DWORD wm_call(unsigned int operation, handle_t binding, Connection *connection,
              HANDLE *lifetime, Packet *packet, HANDLE cancel, DWORD timeout)
{
    RPC_ASYNC_STATE async;
    HANDLE events[2];
    DWORD result = RpcAsyncInitializeHandle(&async, sizeof(async)), reply = 0, wait;
    int completed = 0;
    if (result) return result;
    events[0] = CreateEventW(NULL, TRUE, FALSE, NULL);
    events[1] = cancel;
    if (!events[0]) return GetLastError();
    async.NotificationType = RpcNotificationTypeEvent;
    async.u.hEvent = events[0];
    RpcTryExcept {
        switch (operation) {
        case 0: client_Open(&async, binding, connection, lifetime); break;
        case 1: client_Send(&async, binding, *connection, packet); break;
        case 2: client_Receive(&async, binding, *connection, packet); break;
        default: result = ERROR_INVALID_PARAMETER; break;
        }
    } RpcExcept(RpcExceptionFilter(RpcExceptionCode())) {
        result = RpcExceptionCode();
    } RpcEndExcept
    if (!result) {
        wait = WaitForMultipleObjects(cancel ? 2 : 1, events, FALSE, timeout);
        if (wait != WAIT_OBJECT_0) RpcAsyncCancelCall(&async, TRUE);
        // Arguments remain live until the runtime finishes, including cancellation.
        WaitForSingleObject(events[0], INFINITE);
        result = RpcAsyncCompleteCall(&async, &reply);
        if (!result) {
            completed = 1;
            result = reply;
            // A valid RPC response may contain resources even when the peer
            // reports an application error. We own those outputs in that case.
            if (result && operation == 2) wm_packet_free(packet, 1);
            if (result && operation == 0 && *lifetime) {
                CloseHandle(*lifetime);
                *lifetime = NULL;
            }
        } else if (wait == WAIT_TIMEOUT && result == RPC_S_CALL_CANCELLED) {
            result = ERROR_TIMEOUT;
        }
    }
    // Failed RPC output is invalid and already cleaned by the runtime. A
    // successful completion racing cancellation still transfers its outputs.
    if (!completed && operation == 0) *lifetime = NULL;
    CloseHandle(events[0]);
    return result;
}

void wm_packet_free(Packet *packet, int resources)
{
    unsigned long i;
    if (resources && packet->resources) for (i = 0; i != packet->count; ++i)
        if (packet->resources[i].object.event_handle) CloseHandle(packet->resources[i].object.event_handle);
    free(packet->bytes);
    free(packet->resources);
    memset(packet, 0, sizeof(*packet));
}

DWORD wm_kind(HANDLE handle, unsigned long *kind)
{
    typedef NTSTATUS (WINAPI *query_fn)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    union { void *alignment; BYTE bytes[1024]; } storage;
    PUBLIC_OBJECT_TYPE_INFORMATION *info = (PUBLIC_OBJECT_TYPE_INFORMATION *)&storage;
    query_fn query = (query_fn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    NTSTATUS result;
    if (!query) return ERROR_NOT_SUPPORTED;
    result = query(handle, ObjectTypeInformation, info, sizeof(storage), NULL);
    if (result < 0) return ERROR_INVALID_HANDLE;
    if (info->TypeName.Length == 10 && !memcmp(info->TypeName.Buffer, L"Event", 10)) *kind = 1;
    else if (info->TypeName.Length == 14 && !memcmp(info->TypeName.Buffer, L"Section", 14)) *kind = 2;
    else if (info->TypeName.Length == 8 && !memcmp(info->TypeName.Buffer, L"File", 8))
        *kind = GetFileType(handle) == FILE_TYPE_PIPE ? 4 : 3;
    else return ERROR_NOT_SUPPORTED;
    return ERROR_SUCCESS;
}
