# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Read-only scheduler diagnostics; cumulative counters, not latency samples.

See https://docs.kernel.org/scheduler/sched-stats.html#proc-pid-schedstat.
Runqueue wait excludes time asleep on I/O. Disabled scheduler statistics do not
establish an absence of scheduling delays; record the host setting separately.
"""

from pathlib import Path
import time


def stat(path):
    text = path.read_text()
    name, fields = text[text.index("(") + 1:].rsplit(") ", 1)
    fields = fields.split()
    return {"name": name, "state": fields[0], "start_ticks": int(fields[19]),
            "last_cpu": int(fields[36])}


def threads(pid):
    started = time.monotonic()
    result = []
    for task in sorted(Path(f"/proc/{pid}/task").iterdir(), key=lambda p: int(p.name)):
        record = {"tid": int(task.name)}
        try:
            before = stat(task / "stat")
            runtime, waiting, slices = map(int, (task / "schedstat").read_text().split())
            switches = {k: int(v) for k, v in (line.split(":", 1)
                        for line in (task / "status").read_text().splitlines()
                        if "ctxt_switches:" in line)}
            after = stat(task / "stat")
            if before["start_ticks"] != after["start_ticks"]:
                raise ValueError("thread identity changed during observation")
            record.update(after, runtime_ns=runtime, runqueue_wait_ns=waiting,
                          timeslices=slices, **switches)
        except (OSError, ValueError, IndexError) as error:
            record["error"] = str(error)
        result.append(record)
    return {"started": started, "finished": time.monotonic(), "threads": result}


if __name__ == "__main__":
    import json
    import os
    before = threads(os.getpid())
    deadline = time.thread_time_ns() + 20_000_000
    while time.thread_time_ns() < deadline:
        pass
    after = threads(os.getpid())
    a = {t["tid"]: t for t in before["threads"]}
    b = {t["tid"]: t for t in after["threads"]}
    assert a.keys() == b.keys() and not any("error" in t for t in [*a.values(), *b.values()])
    assert all(a[k]["start_ticks"] == b[k]["start_ticks"] for k in a)
    elapsed = sum(b[k]["runtime_ns"] - a[k]["runtime_ns"] for k in a)
    assert 10_000_000 <= elapsed < 200_000_000, elapsed
    print(json.dumps({"sched_schedstats": Path("/proc/sys/kernel/sched_schedstats").read_text().strip(),
                      "clock_ticks": os.sysconf("SC_CLK_TCK"), "before": before, "after": after}))
