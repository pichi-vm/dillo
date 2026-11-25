# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Compare native HVF access under explicit Seatbelt filters, in fresh processes."""

import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile

SOURCE = r"""
#include <Hypervisor/Hypervisor.h>
#include <dlfcn.h>
#include <mach/mach_time.h>
#include <sandbox.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int sandbox_check(pid_t, const char *, int, ...);

static uint64_t raw_mach_call(int64_t number, uint64_t arg0) {
    register uint64_t x0 __asm__("x0") = arg0;
    register uint64_t x1 __asm__("x1") = 0;
    register int64_t x16 __asm__("x16") = number;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x16) : "memory", "cc");
    return x0;
}

static void inspect_code(const uint32_t *code, int depth) {
    Dl_info info = {0};
    if (!dladdr(code, &info)) return;
    static const uint32_t *seen[64];
    static size_t visited;
    for (size_t i = 0; i < visited; i++) if (seen[i] == code) return;
    if (visited == 64) return;
    seen[visited++] = code;
    if (info.dli_sname && strcmp(info.dli_sname, "_ZN2Hv2Vm6createERKP14hv_vm_config_s") == 0)
        depth = 2;
    printf("CODE %p %s %s\n", code, info.dli_fname,
           info.dli_sname ? info.dli_sname : "local");
    size_t available = (getpagesize() - (uintptr_t)code % getpagesize()) / 4;
    size_t count = available < 32 ? available : 32;
    for (size_t i = 0; i < count; i++) printf("%08x ", code[i]);
    putchar('\n');
    if (!depth) return;
    unsigned followed = 0;
    for (size_t i = 0; i < count && followed < 4; i++) {
        if ((code[i] & 0x7c000000) == 0x14000000) {
            int64_t offset = (int64_t)((int32_t)(code[i] << 6) >> 6) * 4;
            inspect_code((const uint32_t *)((uintptr_t)&code[i] + offset), depth - 1);
            followed++;
        }
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && strcmp(argv[1], "inspect") == 0) {
        inspect_code((const uint32_t *)hv_vm_create, 2);
        void *create = dlsym(RTLD_DEFAULT, "_ZN2Hv2Vm6createERKP14hv_vm_config_s");
        if (create) inspect_code(create, 3);
        return 0;
    }
    if (sandbox_check(getpid(), NULL, 0) != 0) {
        puts("unexpected inherited sandbox");
        return 2;
    }
    if (argc > 2 && strcmp(argv[2], "warmup") == 0) {
        hv_return_t status = hv_vm_create(NULL);
        printf("warmup hv_vm_create=0x%08x\n", status);
        if (status != HV_SUCCESS) return 6;
        status = hv_vm_destroy();
        printf("warmup hv_vm_destroy=0x%08x\n", status);
        if (status != HV_SUCCESS) return 7;
    }
    if (argc > 1) {
        char *error = NULL;
        if (sandbox_init(argv[1], 0, &error) != 0) {
            printf("sandbox_init: %s\n", error ? error : "no error text");
            if (error) sandbox_free_error(error);
            return 3;
        }
        puts("sandbox installed");
    }
    if (argc > 2 && strcmp(argv[2], "raw") == 0) {
        mach_timebase_info_data_t info = {0};
        printf("raw timebase trap=0x%llx\n", (unsigned long long)
               raw_mach_call(-89, (uintptr_t)&info));
        // An unsupported HVF operation has no VM or memory side effect. Its
        // rejection can be distinguished from the kernel's filter denial.
        printf("raw unsupported hv trap=0x%llx\n", (unsigned long long)
               raw_mach_call(-5, UINT32_MAX));
        return 0;
    }
    puts("calling hv_vm_create");
    hv_return_t status = hv_vm_create(NULL);
    printf("hv_vm_create=0x%08x\n", status);
    if (status == HV_SUCCESS) {
        hv_vcpu_t cpu;
        hv_vcpu_exit_t *exit;
        status = hv_vcpu_create(&cpu, &exit, NULL);
        printf("hv_vcpu_create=0x%08x\n", status);
        if (status == HV_SUCCESS) {
            status = hv_vcpu_destroy(cpu);
            printf("hv_vcpu_destroy=0x%08x\n", status);
            if (status != HV_SUCCESS) return 5;
        }
        status = hv_vm_destroy();
        printf("hv_vm_destroy=0x%08x\n", status);
        if (status != HV_SUCCESS) return 4;
    }
    return 0;
}
"""

BASE = "(version 1)(deny default)(allow signal (target self))(allow process-info* (target self))"
POLICIES = {
    "unconfined-control": None,
    "current-policy": BASE,
    "deny-iokit-open": BASE + "(deny iokit-open)",
    "deny-mig": BASE + "(deny syscall-mig)",
    "deny-system-privilege": BASE + "(deny system-privilege)",
    "deny-hv-trap": BASE + "(deny syscall-mach (machtrap-number 5))",
    "deny-negative-hv-trap": BASE + "(deny syscall-mach (machtrap-number -5))",
    "deny-hv-trap-symbol": BASE + "(deny syscall-mach (machtrap-number MSC_hv_trap))",
    "deny-mach": BASE + "(deny syscall-mach)",
    "deny-iokit-trap": BASE + "(deny syscall-mach (machtrap-number 100))",
    "deny-host-special-port": BASE + "(deny syscall-mig (kernel-mig-routine host_get_special_port))",
    "deny-host-io-master": BASE + "(deny syscall-mig (kernel-mig-routine host_get_io_master))",
    "version-three": BASE.replace("(version 1)", "(version 3)"),
}

with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
    root = Path(directory)
    source, binary, entitlements = root / "probe.c", root / "probe", root / "entitlements.plist"
    source.write_text(SOURCE)
    entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
    subprocess.run(["xcrun", "clang", "-Wno-deprecated-declarations", str(source),
                    "-framework", "Hypervisor", "-lsandbox", "-o", str(binary)], check=True)
    subprocess.run(["codesign", "--force", "--sign", "-", str(binary)], check=True)
    print("CASE no-entitlement-control", flush=True)
    control = subprocess.run([str(binary)], capture_output=True, text=True, timeout=8)
    print(json.dumps({"exit": control.returncode, "stdout": control.stdout,
                      "stderr": control.stderr}), flush=True)
    subprocess.run(["codesign", "--force", "--sign", "-", "--entitlements",
                    str(entitlements), str(binary)], check=True)
    subprocess.run([str(binary), "inspect"], check=True, timeout=8)
    for name, policy in POLICIES.items():
        print(f"CASE {name}", flush=True)
        try:
            result = subprocess.run([str(binary)] + ([policy] if policy else []),
                                    capture_output=True, text=True, timeout=8)
            print(json.dumps({"exit": result.returncode, "stdout": result.stdout,
                              "stderr": result.stderr}), flush=True)
            if name == "unconfined-control" and (result.returncode != 0 or
                    "hv_vcpu_create=0x00000000" not in result.stdout):
                raise SystemExit("Native positive control failed")
        except subprocess.TimeoutExpired as error:
            print(f"TIMEOUT stdout={error.stdout!r} stderr={error.stderr!r}", flush=True)
            if name == "unconfined-control":
                raise
    for name in ("current-policy", "deny-hv-trap", "deny-mach"):
        print(f"CASE {name}-after-warmup", flush=True)
        try:
            result = subprocess.run([str(binary), POLICIES[name], "warmup"],
                                    capture_output=True, text=True, timeout=8)
            print(json.dumps({"exit": result.returncode, "stdout": result.stdout,
                              "stderr": result.stderr}), flush=True)
        except subprocess.TimeoutExpired as error:
            print(f"TIMEOUT stdout={error.stdout!r} stderr={error.stderr!r}", flush=True)
    for name in ("current-policy", "deny-hv-trap", "deny-mach"):
        print(f"CASE {name}-raw", flush=True)
        try:
            result = subprocess.run([str(binary), POLICIES[name], "raw"],
                                    capture_output=True, text=True, timeout=8)
            print(json.dumps({"exit": result.returncode, "stdout": result.stdout,
                              "stderr": result.stderr}), flush=True)
        except subprocess.TimeoutExpired as error:
            print(f"TIMEOUT stdout={error.stdout!r} stderr={error.stderr!r}", flush=True)
