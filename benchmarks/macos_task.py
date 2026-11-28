# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Diagnostic process counters; these do not attribute CPU to individual calls."""

import ctypes
import os
import time


# Public PROC_PIDTASKINFO layout in XNU bsd/sys/proc_info.h. The kernel includes
# terminated threads and saturates event counts at INT32_MAX (fill_taskprocinfo).
class TaskInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "virtual_size", "resident_size", "total_user", "total_system",
        "threads_user", "threads_system")] + [(name, ctypes.c_int32) for name in (
        "policy", "faults", "pageins", "cow_faults", "messages_sent",
        "messages_received", "syscalls_mach", "syscalls_unix", "csw",
        "threadnum", "numrunning", "priority")]


assert ctypes.sizeof(TaskInfo) == 96
proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
proc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                             ctypes.c_void_p, ctypes.c_int]
proc.proc_pidinfo.restype = ctypes.c_int


def counters(pid):
    info = TaskInfo()
    size = ctypes.sizeof(info)
    result = proc.proc_pidinfo(pid, 4, 0, ctypes.byref(info), size)
    if result != size:
        raise OSError(ctypes.get_errno(), f"PROC_PIDTASKINFO returned {result}, expected {size}")
    values = {name: getattr(info, name) for name in ("syscalls_mach", "syscalls_unix", "csw")}
    if any(value < 0 or value == 2**31 - 1 for value in values.values()):
        raise OSError("unavailable or saturated task counter")
    return values


# Public PROC_PIDLISTTHREADS/PROC_PIDTHREADINFO use pthread addresses, not a
# position in an enumeration. XNU reports these runtimes in nanoseconds.
class ThreadInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ("user_ns", "system_ns")] + [
        (name, ctypes.c_int32) for name in (
            "cpu_usage", "policy", "run_state", "flags", "sleep_time",
            "current_priority", "priority", "max_priority")
    ] + [("name", ctypes.c_char * 64)]


assert ctypes.sizeof(ThreadInfo) == 112


def threads(pid):
    started = time.monotonic()
    addresses = (ctypes.c_uint64 * 256)()
    size = proc.proc_pidinfo(pid, 6, 0, addresses, ctypes.sizeof(addresses))
    if size <= 0 or size % 8 or size == ctypes.sizeof(addresses):
        raise OSError(ctypes.get_errno(), f"invalid or truncated thread list: {size}")
    result = []
    for address in addresses[:size // 8]:
        info = ThreadInfo()
        n = proc.proc_pidinfo(pid, 5, address, ctypes.byref(info), ctypes.sizeof(info))
        record = {"address": address}
        if n != ctypes.sizeof(info):
            record["error"] = f"thread info returned {n}, errno={ctypes.get_errno()}"
        else:
            record.update(name=info.name.decode(errors="replace"),
                          user_ns=info.user_ns, system_ns=info.system_ns,
                          priority=info.priority, current_priority=info.current_priority)
        result.append(record)
    return {"started": started, "finished": time.monotonic(), "threads": result}


if __name__ == "__main__":
    import json
    before = counters(os.getpid())
    for _ in range(128):
        os.stat("/")
    after = counters(os.getpid())
    assert after["syscalls_unix"] - before["syscalls_unix"] >= 128
    print(json.dumps({"before": before, "after": after, "size": ctypes.sizeof(TaskInfo)}))

    before_threads = threads(os.getpid())
    deadline = time.thread_time_ns() + 20_000_000
    while time.thread_time_ns() < deadline:
        pass
    after_threads = threads(os.getpid())
    a = {t["address"]: t for t in before_threads["threads"]}
    b = {t["address"]: t for t in after_threads["threads"]}
    assert a.keys() == b.keys() and not any("error" in t for t in [*a.values(), *b.values()])
    elapsed = sum(b[k][f] - a[k][f] for k in a for f in ["user_ns", "system_ns"])
    assert 10_000_000 <= elapsed < 200_000_000, elapsed
    print(json.dumps({"thread_info_size": ctypes.sizeof(ThreadInfo),
                      "thread_cpu_delta_ns": elapsed, "before": before_threads, "after": after_threads}))
