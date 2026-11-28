# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Diagnostic process counters; these do not attribute CPU to individual calls."""

import ctypes
import os


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


if __name__ == "__main__":
    import json
    before = counters(os.getpid())
    for _ in range(128):
        os.stat("/")
    after = counters(os.getpid())
    assert after["syscalls_unix"] - before["syscalls_unix"] >= 128
    print(json.dumps({"before": before, "after": after, "size": ctypes.sizeof(TaskInfo)}))
