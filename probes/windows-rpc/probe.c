// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Diagnostic only: two independently started processes, no peer process handle.
#include <windows.h>
#include <rpc.h>
#include <rpcasync.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sddl.h>
#include "probe.h"

void *__RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void __RPC_USER midl_user_free(void *value) { free(value); }

static void require(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "FAIL %s (Win32 %lu)\n", what, GetLastError());
        exit(1);
    }
}

#ifdef PROBE_SERVER
static HANDLE retained;

void Echo(handle_t binding, Resource *input, Resource *output)
{
    (void)binding;
    output->kind = input->kind;
    require(DuplicateHandle(GetCurrentProcess(), input->object.event,
                            GetCurrentProcess(), &output->object.event,
                            0, FALSE, DUPLICATE_SAME_ACCESS), "echo typed resource");
}

unsigned long Signal(handle_t binding, HANDLE event)
{
    (void)binding;
    return SetEvent(event) ? ERROR_SUCCESS : GetLastError();
}

void Retain(handle_t binding, HANDLE input, HANDLE *output)
{
    (void)binding;
    require(retained == NULL, "one outstanding retained handle");
    require(DuplicateHandle(GetCurrentProcess(), input, GetCurrentProcess(),
                            &retained, 0, FALSE, DUPLICATE_SAME_ACCESS), "retain input");
    require(SetEvent(retained), "signal imported event");
    *output = CreateEventW(NULL, TRUE, TRUE, NULL);
    require(*output != NULL, "create output event");
    // RPC owns the temporary input and the returned output handle.
}

void Release(handle_t binding)
{
    (void)binding;
    require(CloseHandle(retained), "release retained handle");
    retained = NULL;
}

void Reject(handle_t binding, HANDLE input)
{
    (void)binding;
    (void)input;
    RpcRaiseException(RPC_S_INVALID_ARG);
}

unsigned long ServerPid(handle_t binding)
{
    (void)binding;
    return GetCurrentProcessId();
}

void Hold(handle_t binding, HANDLE input, HANDLE entered, HANDLE release, HANDLE *output)
{
    (void)binding;
    require(SetEvent(entered), "announce imported input");
    require(WaitForSingleObject(release, 10000) == WAIT_OBJECT_0, "release held call");
    require(DuplicateHandle(GetCurrentProcess(), input, GetCurrentProcess(),
                            output, 0, FALSE, DUPLICATE_SAME_ACCESS), "return after peer death");
}

void Adopt(handle_t binding, HANDLE input, Session *session)
{
    HANDLE *owner = malloc(sizeof(*owner));
    (void)binding;
    require(owner != NULL, "allocate session");
    require(DuplicateHandle(GetCurrentProcess(), input, GetCurrentProcess(),
                            owner, 0, FALSE, DUPLICATE_SAME_ACCESS), "session retains input");
    *session = owner;
}

void __RPC_USER Session_rundown(Session session)
{
    HANDLE *owner = session;
    require(CloseHandle(*owner), "rundown closes session resource");
    free(owner);
}

void WaitForCancel(PRPC_ASYNC_STATE async, handle_t binding, HANDLE input,
                   HANDLE entered, HANDLE *output)
{
    HANDLE signals[2];
    RPC_ASYNC_NOTIFICATION_INFO info;
    RPC_BINDING_HANDLE call = RpcAsyncGetCallHandle(async);
    RPC_NOTIFICATIONS kinds[2] = {RpcNotificationCallCancel, RpcNotificationClientDisconnect};
    unsigned long count, i, reply = 0;
    (void)binding;
    for (i = 0; i != 2; ++i) {
        signals[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        require(signals[i] != NULL, "create cancellation notification");
        info.hEvent = signals[i];
        require(RpcServerSubscribeForNotification(call, kinds[i], RpcNotificationTypeEvent, &info)
                    == RPC_S_OK, "subscribe cancellation notification");
    }
    require(SetEvent(entered), "announce cancellable call");
    require(WaitForMultipleObjects(2, signals, FALSE, 10000) < WAIT_OBJECT_0 + 2,
            "RPC notifies server of cancellation or disconnect");
    for (i = 0; i != 2; ++i) {
        require(RpcServerUnsubscribeForNotification(call, kinds[i], &count) == RPC_S_OK,
                "unsubscribe before completing call");
        if (count) require(WaitForSingleObject(signals[i], 5000) == WAIT_OBJECT_0,
                            "drain queued notification before closing event");
        CloseHandle(signals[i]);
    }
    require(DuplicateHandle(GetCurrentProcess(), input, GetCurrentProcess(), output,
                            0, FALSE, DUPLICATE_SAME_ACCESS), "output after cancellation");
    // Completion releases stub-owned arguments even though the client abandoned its result.
    (void)RpcAsyncCompleteCall(async, &reply);
}

void Stop(handle_t binding)
{
    (void)binding;
    require(RpcMgmtStopServerListening(NULL) == RPC_S_OK, "stop listening");
}

int main(int argc, char **argv)
{
    PSECURITY_DESCRIPTOR security = NULL;
    require(argc == 2 || argc == 3, "endpoint argument");
    if (argc == 3) {
        HANDLE token;
        char owner_buffer[256], descriptor[2048];
        DWORD size;
        LPSTR owner;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "query server identity");
        require(GetTokenInformation(token, TokenUser, owner_buffer, sizeof(owner_buffer), &size),
                "read server identity");
        require(ConvertSidToStringSidA(((TOKEN_USER *)owner_buffer)->User.Sid, &owner), "owner SID");
        sprintf_s(descriptor, sizeof(descriptor),
                  "O:%sD:(A;;GA;;;%s)(A;;GA;;;%s)S:(ML;;NW;;;LW)", owner, owner, argv[2]);
        require(ConvertStringSecurityDescriptorToSecurityDescriptorA(
                    descriptor, SDDL_REVISION_1, &security, NULL), "RPC interface ACL");
        LocalFree(owner);
        CloseHandle(token);
    }
    require(RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", 8,
                                  (RPC_CSTR)argv[1], security) == RPC_S_OK, "local endpoint");
    require(RpcServerRegisterIf3(HandleProbe_v1_0_s_ifspec, NULL, NULL,
                                 RPC_IF_ALLOW_LOCAL_ONLY, 8, 65536, NULL, security) == RPC_S_OK,
            "register interface");
    require(RpcServerListen(1, 8, TRUE) == RPC_S_OK, "listen");
    puts("READY");
    fflush(stdout);
    require(RpcMgmtWaitServerListen() == RPC_S_OK, "wait server");
    require(RpcServerUnregisterIf(NULL, NULL, TRUE) == RPC_S_OK, "unregister");
    LocalFree(security);
    return 0;
}
#else
// Object counts are only a diagnostic oracle, never a transfer protocol.
typedef LONG (WINAPI *query_object_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct { ULONG attributes, access, handles, pointers, reserved[10]; } object_basic;

static ULONG handles(HANDLE handle)
{
    object_basic value;
    query_object_fn query = (query_object_fn)(void *)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    require(query && query(handle, 0, &value, sizeof(value), NULL) >= 0, "query count");
    return value.handles;
}

static void expect_handles(HANDLE object, ULONG expected, const char *what)
{
    ULONGLONG deadline = GetTickCount64() + 5000;
    ULONG actual;
    // Reply delivery can precede the server stub's post-send cleanup.
    while ((actual = handles(object)) != expected && GetTickCount64() < deadline) Sleep(1);
    if (actual != expected) fprintf(stderr, "handle count: expected %lu, got %lu\n", expected, actual);
    require(actual == expected, what);
}

static void peer_loss(handle_t binding, const char *endpoint, int adopt)
{
    char names[3][128], command[1024];
    HANDLE events[3];
    STARTUPINFOA startup = { sizeof(startup) };
    PROCESS_INFORMATION child;
    DWORD peer = ServerPid(binding), i;
    ULONGLONG deadline;
    for (i = 0; i != 3; ++i) {
        sprintf_s(names[i], sizeof(names[i]), "Local\\%s-%d-%lu", endpoint, adopt, i);
        events[i] = CreateEventA(NULL, TRUE, FALSE, names[i]);
        require(events[i] != NULL, "create witness event");
    }
    sprintf_s(command, sizeof(command), "client.exe %s %s %s %s %s",
              endpoint, adopt ? "adopt" : "hold", names[0], names[1], names[2]);
    require(CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL,
                           &startup, &child), "start disposable client");
    require(WaitForSingleObject(events[1], 10000) == WAIT_OBJECT_0, "client reached failure point");
    require(TerminateProcess(child.hProcess, 23), "terminate client only");
    require(WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0, "reap client");
    require(SetEvent(events[2]), "let server complete abandoned call");
    deadline = GetTickCount64() + 10000;
    while (handles(events[0]) != 1 && GetTickCount64() < deadline) Sleep(10);
    require(handles(events[0]) == 1, "dead client leaves no transfer or session handles");
    require(ServerPid(binding) == peer, "server survives client death");
    for (i = 0; i != 3; ++i) CloseHandle(events[i]);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    printf("PASS %s cleanup with surviving server\n", adopt ? "session rundown" : "lost output");
}

static void cancellation(handle_t binding)
{
    RPC_ASYNC_STATE async;
    HANDLE input = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE entered = CreateEventW(NULL, TRUE, FALSE, NULL), output = NULL;
    DWORD exception = 0, reply = 0;
    require(input && entered, "cancellation fixtures");
    require(RpcAsyncInitializeHandle(&async, sizeof(async)) == RPC_S_OK, "initialize async call");
    async.NotificationType = RpcNotificationTypeEvent;
    async.u.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    require(async.u.hEvent != NULL, "completion event");
    RpcTryExcept { WaitForCancel(&async, binding, input, entered, &output); }
    RpcExcept(1) { exception = RpcExceptionCode(); } RpcEndExcept
    require(exception == 0, "start async call");
    require(WaitForSingleObject(entered, 5000) == WAIT_OBJECT_0, "server ready for cancellation");
    require(RpcAsyncCancelCall(&async, TRUE) == RPC_S_OK, "abort pending call");
    require(WaitForSingleObject(async.u.hEvent, 5000) == WAIT_OBJECT_0, "client cancellation completes");
    require(RpcAsyncCompleteCall(&async, &reply) == RPC_S_CALL_CANCELLED, "report cancelled result");
    expect_handles(input, 1, "cancelled transfer releases both temporary references");
    require(output == NULL, "cancelled output is not adopted");
    CloseHandle(async.u.hEvent);
    CloseHandle(input);
    CloseHandle(entered);
    puts("PASS bounded cancellation without process termination");
}

static void objects(handle_t binding)
{
    Resource input, output = {0};
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL), limited, reader, writer;
    void *first, *second;
    char byte;
    DWORD count;
    require(event != NULL, "create rights fixture");
    require(DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(),
                            &limited, SYNCHRONIZE, FALSE, 0), "reduce event rights");
    require(Signal(binding, limited) == ERROR_ACCESS_DENIED, "RPC does not amplify event rights");
    CloseHandle(limited);
    CloseHandle(event);
    input.kind = 2;
    input.object.section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                              0, 4096, NULL);
    require(input.object.section != NULL, "create section");
    Echo(binding, &input, &output);
    first = MapViewOfFile(input.object.section, FILE_MAP_WRITE, 0, 0, 4096);
    second = MapViewOfFile(output.object.section, FILE_MAP_READ, 0, 0, 4096);
    require(first && second, "map both transferred section references");
    *(volatile unsigned long *)first = 0x12345678;
    require(*(volatile unsigned long *)second == 0x12345678, "same section backing");
    CloseHandle(input.object.section);
    CloseHandle(output.object.section);
    UnmapViewOfFile(first);
    UnmapViewOfFile(second);
    require(CreatePipe(&reader, &writer, NULL, 0), "create pipe");
    input.kind = 3;
    input.object.pipe_handle = reader;
    Echo(binding, &input, &output);
    CloseHandle(reader);
    require(WriteFile(writer, "x", 1, &count, NULL) && count == 1, "write pipe");
    require(ReadFile(output.object.pipe_handle, &byte, 1, &count, NULL) && count == 1 && byte == 'x',
            "read returned pipe");
    expect_handles(output.object.pipe_handle, 1, "returned pipe reader has one owner");
    CloseHandle(output.object.pipe_handle);
    require(!WriteFile(writer, "x", 1, &count, NULL), "pipe has no remaining readers");
    require(GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_NO_DATA,
            "closed pipe reported");
    CloseHandle(writer);
    puts("PASS typed resources and rights preservation");
}

static void abandoned_context(const char *endpoint, int fast)
{
    handle_t binding = NULL;
    Session session = NULL;
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ULONGLONG start, deadline;
    if (fast) {
        RPC_BINDING_HANDLE_TEMPLATE_V1_A template = {0};
        RPC_BINDING_HANDLE_OPTIONS_V1 options = {1, RPC_BHO_DONTLINGER, 5, 0};
        template.Version = 1;
        template.ProtocolSequence = RPC_PROTSEQ_LRPC;
        template.StringEndpoint = (unsigned char *)endpoint;
        require(RpcBindingCreateA(&template, NULL, &options, &binding) == RPC_S_OK,
                "create fast binding");
        require(RpcBindingSetOption(binding, RPC_C_OPT_UNIQUE_BINDING, TRUE) == RPC_S_OK,
                "unique fast binding");
        require(RpcBindingBind(NULL, binding, HandleProbe_v1_0_c_ifspec) == RPC_S_OK,
                "connect fast binding");
    } else {
        RPC_CSTR address = NULL;
        require(RpcStringBindingComposeA(NULL, (RPC_CSTR)"ncalrpc", NULL,
                (RPC_CSTR)endpoint, NULL, &address) == RPC_S_OK, "compose isolated binding");
        require(RpcBindingFromStringBindingA(address, &binding) == RPC_S_OK,
                "create isolated binding");
        RpcStringFreeA(&address);
        require(RpcBindingSetOption(binding, RPC_C_OPT_UNIQUE_BINDING, TRUE) == RPC_S_OK,
                "unique classic binding");
    }
    require(event != NULL, "create abandoned-context witness");
    Adopt(binding, event, &session);
    require(RpcBindingSetOption(binding, RPC_C_OPT_DONT_LINGER, TRUE) == RPC_S_OK,
            "disable association linger");
    expect_handles(event, 2, "server context owns event");
    RpcSsDestroyClientContext(&session);
    if (fast) require(RpcBindingUnbind(binding) == RPC_S_OK, "unbind fast binding");
    require(RpcBindingFree(&binding) == RPC_S_OK, "free isolated binding");
    start = GetTickCount64();
    deadline = start + 30000;
    while (handles(event) != 1 && GetTickCount64() < deadline) Sleep(10);
    printf("DIAGNOSTIC %s abandoned context: handles=%lu after %llu ms; other binding alive\n",
           fast ? "fast" : "classic", handles(event), GetTickCount64() - start);
    fflush(stdout);
    CloseHandle(event);
}

int main(int argc, char **argv)
{
    RPC_CSTR address = NULL;
    handle_t binding = NULL;
    HANDLE input, output = NULL;
    ULONG peer = 0;
    DWORD exception = 0;
    require(argc == 2 || argc == 3 || argc == 6, "endpoint argument");
    require(RpcStringBindingComposeA(NULL, (RPC_CSTR)"ncalrpc", NULL,
                                     (RPC_CSTR)argv[1],
                                     (RPC_CSTR)"Security=identification static true", &address) == RPC_S_OK,
            "compose binding");
    require(RpcBindingFromStringBindingA(address, &binding) == RPC_S_OK, "bind");
    RpcStringFreeA(&address);
    if (argc == 3) {
        HANDLE token;
        DWORD container = 0, size;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "query client token");
        require(GetTokenInformation(token, TokenIsAppContainer, &container, sizeof(container), &size)
                    && container == 1, "client is actually confined");
        CloseHandle(token);
        if (!strcmp(argv[2], "denied")) {
            RpcTryExcept { (void)ServerPid(binding); }
            RpcExcept(1) { exception = RpcExceptionCode(); } RpcEndExcept
            require(exception == RPC_S_ACCESS_DENIED, "ungranted AppContainer denied");
            puts("PASS ungranted AppContainer denied");
            return 0;
        }
    }
    if (argc == 6) {
        HANDLE entered = OpenEventA(EVENT_ALL_ACCESS, FALSE, argv[4]);
        HANDLE release = OpenEventA(EVENT_ALL_ACCESS, FALSE, argv[5]);
        Session session = NULL;
        input = OpenEventA(EVENT_ALL_ACCESS, FALSE, argv[3]);
        require(input && entered && release, "open witness events");
        if (!strcmp(argv[2], "hold")) Hold(binding, input, entered, release, &output);
        else {
            Adopt(binding, input, &session);
            require(SetEvent(entered), "announce adopted session");
            Sleep(INFINITE);
        }
        return 2; // The controller must terminate this client at the gate.
    }
    input = CreateEventW(NULL, TRUE, FALSE, NULL);
    require(input != NULL && handles(input) == 1, "input initially owned once");
    RpcTryExcept {
        peer = ServerPid(binding);
        printf("connected to server %lu\n", peer);
        fflush(stdout);
        require(peer != GetCurrentProcessId(), "distinct process");
        Retain(binding, input, &output);
        require(WaitForSingleObject(input, 0) == WAIT_OBJECT_0, "input reached server");
        require(output && WaitForSingleObject(output, 0) == WAIT_OBJECT_0,
                "output reached client");
        expect_handles(input, 2, "temporary input released; retained duplicate lives");
        expect_handles(output, 1, "output ownership moved to caller");
        Release(binding);
        expect_handles(input, 1, "explicit receiver release");
    } RpcExcept(1) {
        exception = RpcExceptionCode();
    } RpcEndExcept
    printf("roundtrip exception=%lu\n", exception);
    require(exception == 0, "bidirectional transfer");
    RpcTryExcept {
        Reject(binding, input);
    } RpcExcept(1) {
        exception = RpcExceptionCode();
    } RpcEndExcept
    require(exception == RPC_S_INVALID_ARG, "receiver rejection propagated");
    expect_handles(input, 1, "rejected input released");
    require(ServerPid(binding) == peer, "server survives rejected call");
    objects(binding);
    cancellation(binding);
    if (argc == 2) {
        peer_loss(binding, argv[1], 0);
        peer_loss(binding, argv[1], 1);
        abandoned_context(argv[1], 0);
        abandoned_context(argv[1], 1);
        Stop(binding);
    }
    CloseHandle(input);
    CloseHandle(output);
    RpcBindingFree(&binding);
    puts("PASS local RPC bidirectional ownership and rejection cleanup");
    return 0;
}
#endif
