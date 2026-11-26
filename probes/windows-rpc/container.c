// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Diagnostic launcher: admit one AppContainer to the interface, refuse another.
#include <windows.h>
#include <rpc.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include "probe.h"

void *__RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void __RPC_USER midl_user_free(void *value) { free(value); }
static void require(int ok, const char *what)
{
    if (!ok) { fprintf(stderr, "FAIL %s: %lu\n", what, GetLastError()); exit(1); }
}

static void allow(char *path, PSID sid)
{
    PACL old_acl, acl;
    PSECURITY_DESCRIPTOR descriptor;
    EXPLICIT_ACCESSA access = {0};
    require(GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                  NULL, NULL, &old_acl, NULL, &descriptor) == ERROR_SUCCESS,
            "read fixture ACL");
    access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.ptstrName = sid;
    require(SetEntriesInAclA(1, &access, old_acl, &acl) == ERROR_SUCCESS, "add fixture grant");
    require(SetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                  NULL, NULL, acl, NULL) == ERROR_SUCCESS, "write fixture ACL");
    LocalFree(acl);
    LocalFree(descriptor);
}

static void client(const char *endpoint, PSID sid, const char *mode)
{
    char command[512];
    SECURITY_CAPABILITIES caps = {0};
    STARTUPINFOEXA startup = {0};
    PROCESS_INFORMATION process;
    SIZE_T size = 0;
    DWORD code;
    caps.AppContainerSid = sid;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    startup.lpAttributeList = malloc(size);
    require(startup.lpAttributeList != NULL, "allocate attributes");
    require(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size), "init attributes");
    require(UpdateProcThreadAttribute(startup.lpAttributeList, 0,
                                       PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                       &caps, sizeof(caps), NULL, NULL), "confine client");
    startup.StartupInfo.cb = sizeof(startup);
    sprintf_s(command, sizeof(command), "client.exe %s %s", endpoint, mode);
    require(CreateProcessA("client.exe", command, NULL, NULL, FALSE,
                           EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &startup.StartupInfo, &process),
            "launch confined client");
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    require(WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0, "confined client deadline");
    require(GetExitCodeProcess(process.hProcess, &code) && code == 0, "confined client success");
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

int main(void)
{
    wchar_t names[2][80];
    char endpoint[80], command[512], directory[MAX_PATH], executable[MAX_PATH];
    PSID sids[2];
    LPSTR sid_text;
    DWORD i, peer = 0;
    RPC_CSTR address;
    handle_t binding;
    STARTUPINFOA startup = { sizeof(startup) };
    PROCESS_INFORMATION server;
    ULONGLONG deadline;
    sprintf_s(endpoint, sizeof(endpoint), "rpc-container-%lu", GetCurrentProcessId());
    require(GetCurrentDirectoryA(sizeof(directory), directory) != 0, "fixture directory");
    sprintf_s(executable, sizeof(executable), "%s\\client.exe", directory);
    for (i = 0; i != 2; ++i) {
        swprintf_s(names[i], 80, L"dillo.rpc.probe.%lu.%lu", GetCurrentProcessId(), i);
        require(SUCCEEDED(CreateAppContainerProfile(names[i], names[i], names[i], NULL, 0, &sids[i])),
                "create AppContainer");
        allow(directory, sids[i]);
        allow(executable, sids[i]);
    }
    require(ConvertSidToStringSidA(sids[0], &sid_text), "container SID");
    sprintf_s(command, sizeof(command), "server.exe %s %s", endpoint, sid_text);
    LocalFree(sid_text);
    require(CreateProcessA("server.exe", command, NULL, NULL, FALSE, 0, NULL, NULL,
                           &startup, &server), "start persistent server");
    require(RpcStringBindingComposeA(NULL, (RPC_CSTR)"ncalrpc", NULL, (RPC_CSTR)endpoint,
                                     NULL, &address) == RPC_S_OK, "compose");
    require(RpcBindingFromStringBindingA(address, &binding) == RPC_S_OK, "bind");
    RpcStringFreeA(&address);
    deadline = GetTickCount64() + 10000;
    while (!peer && GetTickCount64() < deadline) {
        RpcTryExcept { peer = ServerPid(binding); } RpcExcept(1) {} RpcEndExcept
        if (!peer) Sleep(10);
    }
    require(peer != 0, "server became ready");
    client(endpoint, sids[0], "allowed");
    client(endpoint, sids[1], "denied");
    require(ServerPid(binding) == peer, "server survived both containers");
    Stop(binding);
    require(WaitForSingleObject(server.hProcess, 5000) == WAIT_OBJECT_0, "server stopped");
    RpcBindingFree(&binding);
    CloseHandle(server.hThread);
    CloseHandle(server.hProcess);
    for (i = 0; i != 2; ++i) { FreeSid(sids[i]); DeleteAppContainerProfile(names[i]); }
    puts("PASS exact AppContainer admission and resource transfer");
    return 0;
}
