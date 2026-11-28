# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Short ETW diagnostic; instrumented rates are not parity measurements."""

import collections
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
import uuid
import xml.etree.ElementTree as ET


assert sys.platform == "win32"
args = sys.argv[1:]
assert not {"--baseline-assets", "--calibrate-noise", "--no-sample"}.intersection(args)
output = Path(args[args.index("--output") + 1])
output.mkdir(parents=True, exist_ok=True)
tool = Path(os.environ["RUNNER_TEMP"]) / "PerfView-4.0.2.exe"
tool_hash = "b89cdc4e2f23db0d893824b4a75e095e5fa623b9a8bdd56d15380fdfa0d7709c"
if not tool.exists():
    with urllib.request.urlopen(
        "https://github.com/microsoft/perfview/releases/download/v4.0.2/PerfView.exe",
        timeout=60,
    ) as source:
        tool.write_bytes(source.read())
assert hashlib.sha256(tool.read_bytes()).hexdigest() == tool_hash

trace = output / "scheduler.etl"
common = [str(tool), "/AcceptEULA", "/NoGui", "/NoView"]
subprocess.run(common + [
    f"/LogFile:{output / 'scheduler-collect.txt'}",
    f"/DataFile:{trace}", f"/SessionName:DilloScheduler{uuid.uuid4().hex}",
    "/KernelEvents:Process,Thread,ImageLoad,Profile,ContextSwitch,Dispatcher",
    "/ClrEvents:None", "/NoClrRundown", "/NoNGenRundown", "/NoNGenPdbs",
    "/Merge:true", "/Zip:true", "/MaxCollectSec:900",
    "run", sys.executable, "benchmarks/run.py", *args,
], check=True)
archive = trace.with_suffix(".etl.zip")
xml = output / "scheduler.xml"
subprocess.run(common + [f"/LogFile:{output / 'scheduler-decode.txt'}",
                       "UserCommand", "DumpEventsAsXml", str(archive), str(xml)], check=True)

# Keep unmodified event attributes for the observed Dillo process tree, including
# switches out and wakeups issued by other processes. Do not export unrelated
# process command lines. PerfView's decode log retains event-loss diagnostics.
results = [json.loads(path.read_text()) for path in output.glob("*/result.json")]
assert len(results) == len(json.loads((output / "plan.json").read_text()))
assert results and all(r["returncode"] == 0 and not r["failure"] for r in results)
pids = {p["pid"] for r in results for p in r["last_process_samples"]}
counts = collections.Counter()
with gzip.open(output / "scheduler-events.jsonl.gz", "wt", encoding="utf-8") as out:
    events = ET.iterparse(xml, events=("start", "end"))
    _, root = next(events)
    for kind, event in events:
        if kind != "end" or event.tag != "Event":
            continue
        attributes = event.attrib
        if any(int(attributes.get(key, "-1").replace(",", "")) in pids
               for key in ("PID", "OldProcessID", "AwakenedProcessID")):
            out.write(json.dumps(attributes, sort_keys=True) + "\n")
            counts[attributes.get("EventName", "unknown")] += 1
        event.clear()
        root.clear()
assert any("CSwitch" in name for name in counts), counts
assert any("ReadyThread" in name for name in counts), counts
with archive.open("rb") as stream:
    trace_hash = hashlib.file_digest(stream, "sha256").hexdigest()
metadata = {"tool_sha256": tool_hash, "trace_sha256": trace_hash,
    "pids": sorted(pids), "events": counts,
    "scope": "Raw event attributes involving observed Dillo PIDs; unrelated processes omitted."}
(output / "scheduler.json").write_text(json.dumps(metadata, indent=2) + "\n")
print(json.dumps(metadata, indent=2))
