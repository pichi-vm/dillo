// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test-only process setup; none of this belongs in a transport binding.
#include <userenv.h>
#include <aclapi.h>

static void check_container(void)
{
    HANDLE token;
    DWORD confined, size;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "client token");
    require(GetTokenInformation(token, TokenIsAppContainer, &confined, sizeof(confined),
                                &size) && confined, "client is confined");
    CloseHandle(token);
}

static void set_listener_security(const char *container_sid)
{
    HANDLE token;
    union { uint64_t align; unsigned char bytes[1024]; } user;
    DWORD size;
    LPSTR owner;
    char sddl[1024];
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "server token");
    require(GetTokenInformation(token, TokenUser, &user, sizeof(user), &size), "server user");
    require(ConvertSidToStringSidA(((TOKEN_USER *)&user)->User.Sid, &owner), "owner SID");
    snprintf(sddl, sizeof(sddl), "D:P(A;;GA;;;%s)(A;;GA;;;%s)S:(ML;;NW;;;LW)",
             owner, container_sid);
    require(ConvertStringSecurityDescriptorToSecurityDescriptorA(
                sddl, SDDL_REVISION_1, &listener_security, NULL), "exact identity ACL");
    LocalFree(owner);
    CloseHandle(token);
}

static void allow_binary(char *path, PSID sid)
{
    PACL old_acl, acl;
    PSECURITY_DESCRIPTOR descriptor;
    EXPLICIT_ACCESSA access = {0};
    require(GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &old_acl, NULL, &descriptor) == ERROR_SUCCESS, "read fixture ACL");
    access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.ptstrName = sid;
    require(SetEntriesInAclA(1, &access, old_acl, &acl) == ERROR_SUCCESS, "fixture ACE");
    require(SetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, acl, NULL) == ERROR_SUCCESS, "grant fixture execution");
    LocalFree(acl);
    LocalFree(descriptor);
}

static HANDLE start_probe(const char *exe, const char *args, PSID sid)
{
    char command[2048];
    STARTUPINFOEXA startup = {0};
    PROCESS_INFORMATION process;
    SECURITY_CAPABILITIES caps = {.AppContainerSid = sid};
    SIZE_T size = 0;
    DWORD flags = 0;
    startup.StartupInfo.cb = sizeof(STARTUPINFOA);
    if (sid) {
        InitializeProcThreadAttributeList(NULL, 1, 0, &size);
        startup.lpAttributeList = malloc(size);
        require(startup.lpAttributeList != NULL, "allocate startup attributes");
        require(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size),
                "initialize startup attributes");
        require(UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps, sizeof(caps), NULL, NULL),
            "set AppContainer");
        flags = EXTENDED_STARTUPINFO_PRESENT;
        startup.StartupInfo.cb = sizeof(startup);
    }
    snprintf(command, sizeof(command), "\"%s\" %s", exe, args);
    require(CreateProcessA(exe, command, NULL, NULL, FALSE, flags, NULL, NULL,
                          &startup.StartupInfo, &process), "launch probe peer");
    if (sid) {
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        free(startup.lpAttributeList);
    }
    CloseHandle(process.hThread);
    return process.hProcess;
}

static void reap_probe(HANDLE process)
{
    DWORD code;
    if (WaitForSingleObject(process, 15000) != WAIT_OBJECT_0) {
        TerminateProcess(process, 99);
        WaitForSingleObject(process, 5000);
        require(0, "probe process deadline");
    }
    require(GetExitCodeProcess(process, &code) && code == 0, "probe process result");
    CloseHandle(process);
}

static int container_probe(const char *name)
{
    char exe[MAX_PATH], directory[MAX_PATH], args[1024];
    wchar_t profiles[2][128];
    PSID sids[2];
    LPSTR allowed;
    require(GetModuleFileNameA(NULL, exe, sizeof(exe)) != 0, "probe path");
    strcpy(directory, exe);
    char *slash = strrchr(directory, '\\');
    require(slash != NULL, "probe directory");
    *slash = 0;
    for (int i = 0; i < 2; ++i) {
        swprintf(profiles[i], 128, L"dillo.alpc.probe.%lu.%d", GetCurrentProcessId(), i);
        require(SUCCEEDED(CreateAppContainerProfile(profiles[i], profiles[i], profiles[i],
            NULL, 0, &sids[i])), "create test AppContainer");
        allow_binary(directory, sids[i]);
        allow_binary(exe, sids[i]);
    }
    HANDLE ready = barrier(name, "listening");
    require(ConvertSidToStringSidA(sids[0], &allowed), "allowed SID");
    snprintf(args, sizeof(args), "server %s container %s", name, allowed);
    HANDLE server_process = start_probe(exe, args, NULL);
    LocalFree(allowed);
    await(ready);
    snprintf(args, sizeof(args), "denied %s", name);
    reap_probe(start_probe(exe, args, sids[1]));
    snprintf(args, sizeof(args), "client %s confined", name);
    reap_probe(start_probe(exe, args, sids[0]));
    reap_probe(server_process);
    CloseHandle(ready);
    for (int i = 0; i < 2; ++i) {
        FreeSid(sids[i]);
        require(SUCCEEDED(DeleteAppContainerProfile(profiles[i])), "delete test profile");
    }
    puts("PASS exact AppContainer admission and bidirectional resources");
    return 0;
}
