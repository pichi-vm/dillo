// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Native IPC diagnostic, not a vhost-user endpoint or a Dillo performance test.
// Compare blocking pipe ping-pong with shared futexes at different addresses.
#include <err.h>
#include <errno.h>
#include <os/os_sync_wait_on_address.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int readiness(int fd) {
    int ready = kqueue();
    if (ready < 0) err(1, "kqueue");
    struct kevent event;
    EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(ready, &event, 1, NULL, 0, NULL) < 0) err(1, "register read");
    return ready;
}

static void transfer(int fd, bool send, int ready) {
    if (!send && ready >= 0) {
        struct kevent event;
        int n;
        do { n = kevent(ready, NULL, 0, &event, 1, NULL); } while (n < 0 && errno == EINTR);
        if (n < 0) err(1, "wait read");
        if (n != 1 || event.flags & EV_ERROR) errx(1, "read event failed");
    }
    uint64_t value = 1;
    ssize_t n;
    do {
        n = send ? write(fd, &value, sizeof(value)) : read(fd, &value, sizeof(value));
    } while (n < 0 && errno == EINTR);
    if (n < 0) err(1, "pipe");
    if (n != (ssize_t)sizeof(value)) errx(1, "short pipe transfer");
}

static void notify(_Atomic uint64_t *word, bool send) {
    if (send) {
        atomic_store_explicit(word, 1, memory_order_release);
        if (os_sync_wake_by_address_any(word, sizeof(*word), OS_SYNC_WAKE_BY_ADDRESS_SHARED) < 0
            && errno != ENOENT) err(1, "shared wake");
    } else {
        while (atomic_exchange_explicit(word, 0, memory_order_acquire) == 0) {
            if (os_sync_wait_on_address(word, 0, sizeof(*word), OS_SYNC_WAIT_ON_ADDRESS_SHARED) < 0
                && errno != EINTR && errno != EFAULT) err(1, "shared wait");
        }
    }
}

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t)) err(1, "clock");
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}

static double cpu(void) {
    struct rusage parent, children;
    if (getrusage(RUSAGE_SELF, &parent) || getrusage(RUSAGE_CHILDREN, &children)) err(1, "rusage");
    return parent.ru_utime.tv_sec + parent.ru_stime.tv_sec
        + children.ru_utime.tv_sec + children.ru_stime.tv_sec
        + (parent.ru_utime.tv_usec + parent.ru_stime.tv_usec
           + children.ru_utime.tv_usec + children.ru_stime.tv_usec) / 1000000.0;
}

static void run(unsigned trial, unsigned mode) {
    const unsigned warmup = 1000, count = 100000;
    bool shared = mode == 1;
    long page = sysconf(_SC_PAGESIZE);
    FILE *file = tmpfile();
    if (page <= 0 || !file || ftruncate(fileno(file), page)) err(1, "backing");
    _Atomic uint64_t *parent = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
    _Atomic uint64_t *child = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
    if (parent == MAP_FAILED || child == MAP_FAILED) err(1, "map");
    if (parent == child) errx(1, "aliases must have different addresses");
    fclose(file);
    atomic_init(&parent[0], 0);
    atomic_init(&parent[1], 0);
    if (!atomic_is_lock_free(parent)) errx(1, "shared atomics must be lock-free");
    int request[2], reply[2];
    if (pipe(request) || pipe(reply)) err(1, "pipe");
    double before_cpu = cpu();
    pid_t pid = fork();
    if (pid < 0) err(1, "fork");
    alarm(30);
    if (pid == 0) {
        munmap(parent, page);
        close(request[1]); close(reply[0]);
        int ready = mode == 2 ? readiness(request[0]) : -1;
        for (unsigned i = 0; i < warmup + count; ++i) {
            if (shared) { notify(&child[0], false); notify(&child[1], true); }
            else { transfer(request[0], false, ready); transfer(reply[1], true, -1); }
        }
        _exit(0);
    }
    munmap(child, page);
    close(request[0]); close(reply[1]);
    int ready = mode == 2 ? readiness(reply[0]) : -1;
    uint64_t start = 0;
    for (unsigned i = 0; i < warmup + count; ++i) {
        if (i == warmup) start = now();
        if (shared) { notify(&parent[0], true); notify(&parent[1], false); }
        else { transfer(request[1], true, -1); transfer(reply[0], false, ready); }
    }
    uint64_t elapsed = now() - start;
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) errx(1, "child failed");
    // CPU includes warm-up and process startup/retirement; RTT excludes them.
    printf("{\"trial\":%u,\"method\":\"%s\",\"round_trip_ns\":%.1f,\"tree_cpu_s\":%.6f,\"exchanges\":%u,\"warmup\":%u}\n",
           trial, mode == 2 ? "pipe-kqueue" : shared ? "shared-futex" : "pipe",
           (double)elapsed / count, cpu() - before_cpu, count, warmup);
    fflush(stdout);
    close(request[1]); close(reply[0]); munmap(parent, page);
    if (ready >= 0) close(ready);
    alarm(0);
}

int main(void) {
    for (unsigned i = 0; i < 6; ++i) {
        for (unsigned mode = 0; mode < 3; ++mode) run(i, (i + mode) % 3);
    }
}
