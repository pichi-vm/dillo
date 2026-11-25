# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Compare native instruction fetch through private and shared RAM mappings."""

import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile

SOURCE = r"""
#include <Hypervisor/Hypervisor.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CHECK(call) do { \
    hv_return_t status = (call); \
    printf(#call "=0x%08x\n", status); \
    if (status != HV_SUCCESS) return 1; \
} while (0)

static void *cancel_run(void *arg) {
    sleep(1);
    hv_vcpu_t cpu = *(hv_vcpu_t *)arg;
    printf("watchdog hv_vcpus_exit=0x%08x\n", hv_vcpus_exit(&cpu, 1));
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3) return 2;
    Dl_info origin = {0};
    if (!dladdr((const void *)hv_vcpu_run, &origin)) return 2;
    printf("hv_vcpu_run image=%s symbol=%s\n", origin.dli_fname,
           origin.dli_sname ? origin.dli_sname : "unknown");
    const size_t size = getpagesize();
    const int native = strcmp(argv[1], "native") == 0;
    const int example = native || strcmp(argv[1], "example") == 0;
    const uint64_t gpa = example ? 0x4000 : 0x40000000;
    CHECK(hv_vm_create(NULL));
    hv_vcpu_t cpu;
    hv_vcpu_exit_t *exit;
    CHECK(hv_vcpu_create(&cpu, &exit, NULL));
    if (example) {
        CHECK(hv_vcpu_set_trap_debug_exceptions(cpu, true));
        CHECK(hv_vcpu_set_trap_debug_reg_accesses(cpu, true));
    }
    int fd = -1;
    int flags = MAP_ANON | MAP_PRIVATE;
    if (strcmp(argv[1], "shm") == 0) {
        char name[64];
        snprintf(name, sizeof(name), "/dillo-probe-%d", getpid());
        fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd == -1) { perror("shm_open"); return 2; }
        if (shm_unlink(name) || ftruncate(fd, size)) {
            perror("initialize shm"); return 2;
        }
        flags = MAP_SHARED;
    }
    uint32_t *ram;
    if (native) {
        void *allocation = NULL;
        CHECK(hv_vm_allocate(&allocation, size, HV_ALLOCATE_DEFAULT));
        ram = allocation;
    } else {
        ram = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0);
        if (ram == MAP_FAILED) { perror("mmap"); return 2; }
    }
    if (fd != -1) close(fd);
    if (strcmp(argv[2], "before") == 0) {
        ram[0] = 0xf9000020; // str x0, [x1]
        ram[1] = 0xd4000002; // hvc #0
    }
    CHECK(hv_vm_map(ram, gpa, size, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC));
    if (strcmp(argv[2], "after") == 0) {
        ram[0] = 0xf9000020;
        ram[1] = 0xd4000002;
    }
    if (example) {
        ram[0] = 0xd2800840; // mov x0, #0x42
        ram[1] = 0xd4200000; // brk #0 (Applevisor's documented example)
    }
    printf("host instruction=0x%08x\n", ram[0]);
    CHECK(hv_vcpu_set_reg(cpu, HV_REG_PC,
          strcmp(argv[1], "unmapped") == 0 ? gpa + 2 * size : gpa));
    if (!example) {
        CHECK(hv_vcpu_set_reg(cpu, HV_REG_CPSR, 0x3c5));
        CHECK(hv_vcpu_set_reg(cpu, HV_REG_X0, 0xfeedcafe));
        CHECK(hv_vcpu_set_reg(cpu, HV_REG_X1, gpa + 0x1000));
        uint64_t sctlr;
        CHECK(hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_SCTLR_EL1, &sctlr));
        CHECK(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_SCTLR_EL1, sctlr & ~0x02001005ULL));
    }
    uint64_t execution_before, execution_after, cpsr, control;
    CHECK(hv_vcpu_get_exec_time(cpu, &execution_before));
    CHECK(hv_vcpu_get_reg(cpu, HV_REG_CPSR, &cpsr));
    CHECK(hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_SCTLR_EL1, &control));
    printf("entry CPSR=0x%llx SCTLR_EL1=0x%llx\n",
           (unsigned long long)cpsr, (unsigned long long)control);
    pthread_t watchdog;
    if (pthread_create(&watchdog, NULL, cancel_run, &cpu)) return 2;
    puts("entering guest");
    struct timespec entered, returned;
    if (clock_gettime(CLOCK_MONOTONIC, &entered)) return 2;
    CHECK(hv_vcpu_run(cpu));
    if (clock_gettime(CLOCK_MONOTONIC, &returned)) return 2;
    printf("hv_vcpu_run elapsed ns=%lld\n",
           (long long)(returned.tv_sec - entered.tv_sec) * 1000000000LL +
           returned.tv_nsec - entered.tv_nsec);
    pthread_join(watchdog, NULL);
    CHECK(hv_vcpu_get_exec_time(cpu, &execution_after));
    printf("execution ns before=%llu after=%llu\n",
           (unsigned long long)execution_before, (unsigned long long)execution_after);
    uint64_t pc;
    CHECK(hv_vcpu_get_reg(cpu, HV_REG_PC, &pc));
    printf("exit reason=%u syndrome=0x%llx pc=0x%llx\n", exit->reason,
           (unsigned long long)exit->exception.syndrome, (unsigned long long)pc);
    printf("guest store=0x%llx\n", (unsigned long long)*(uint64_t *)((char *)ram + 0x1000));
    uint64_t esr, elr, far;
    CHECK(hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_ESR_EL1, &esr));
    CHECK(hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_ELR_EL1, &elr));
    CHECK(hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_FAR_EL1, &far));
    printf("EL1 exception esr=0x%llx elr=0x%llx far=0x%llx\n",
           (unsigned long long)esr, (unsigned long long)elr, (unsigned long long)far);
    uint64_t x0;
    CHECK(hv_vcpu_get_reg(cpu, HV_REG_X0, &x0));
    printf("guest X0=0x%llx\n", (unsigned long long)x0);
    int passed = exit->reason == HV_EXIT_REASON_EXCEPTION &&
        (example ? x0 == 0x42 : strcmp(argv[1], "unmapped") == 0 ||
         *(uint64_t *)((char *)ram + 0x1000) == 0xfeedcafe);
    CHECK(hv_vcpu_destroy(cpu));
    CHECK(hv_vm_unmap(gpa, size));
    if (native) {
        CHECK(hv_vm_deallocate(ram, size));
    } else {
        munmap(ram, size);
    }
    CHECK(hv_vm_destroy());
    return passed ? 0 : 3;
}
"""

with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as directory:
    for key in ("kern.hv_support", "kern.hv_vmm_present", "machdep.cpu.brand_string"):
        result = subprocess.run(["sysctl", key], capture_output=True, text=True)
        print(json.dumps({"sysctl": key, "stdout": result.stdout,
                          "stderr": result.stderr}), flush=True)
    root = Path(directory)
    source, binary, entitlements = root / "probe.c", root / "probe", root / "entitlements.plist"
    source.write_text(SOURCE)
    entitlements.write_bytes(plistlib.dumps({"com.apple.security.hypervisor": True}))
    subprocess.run(["xcrun", "clang", "-Wall", "-Wextra", str(source),
                    "-framework", "Hypervisor", "-o", str(binary)], check=True)
    subprocess.run(["codesign", "--force", "--sign", "-", "--entitlements",
                    str(entitlements), str(binary)], check=True)
    failed = False
    for backing in ("native", "example", "private", "shm", "unmapped"):
        for placement in ("before", "after"):
            print(f"CASE {backing} write-{placement}-map", flush=True)
            try:
                result = subprocess.run([str(binary), backing, placement],
                                        capture_output=True, text=True, timeout=8)
                print(json.dumps({"exit": result.returncode, "stdout": result.stdout,
                                  "stderr": result.stderr}), flush=True)
                failed |= result.returncode != 0
            except subprocess.TimeoutExpired as error:
                print(f"TIMEOUT stdout={error.stdout!r} stderr={error.stderr!r}", flush=True)
                failed = True
    if failed:
        raise SystemExit("Native memory probe failed")
