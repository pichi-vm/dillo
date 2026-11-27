#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Paired native device measurements; guest workloads remain in snuffler."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import socketserver
import statistics
import subprocess
import threading
import time

import psutil

MEMORY_MIB = 256
DISK_BYTES = 64 * 1024 * 1024
PHASE = re.compile(rb"<<<SNUFFLER-BENCH:([^>]+)>>>")
REPORT = re.compile(rb"<<<DILLO-E2E-REPORT>>>(.*?)<<<END>>>", re.S)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(60)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while data := self.request.recv(128 * 1024):
            self.request.sendall(data)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


def snapshot(process, memory):
    """Keep native metric names; summed RSS is deliberately not a result."""
    cpu = process.cpu_times()
    result = {"pid": process.pid, "created": process.create_time(),
              "cpu_user_s": cpu.user, "cpu_system_s": cpu.system,
              "threads": process.num_threads()}
    try:
        result["context_switches"] = process.num_ctx_switches()._asdict()
    except (psutil.Error, NotImplementedError) as error:
        result["context_switches_error"] = str(error)
    if memory:
        try:
            result["memory"] = process.memory_full_info()._asdict()
            if platform.system() == "Linux":
                text = Path(f"/proc/{process.pid}/smaps_rollup").read_text()
                result["hugetlb"] = {name: int(value) * 1024 for name, value in
                                     re.findall(r"(\w+_Hugetlb):\s+(\d+) kB", text)}
        except (psutil.Error, OSError) as error:
            result["memory_error"] = str(error)
    return result


def run_vm(args, assets, image, disks, case, mode, label):
    directory = args.output / label
    directory.mkdir()
    # Full initialization, outside measured time. Avoid sparse-file zero reads.
    pattern = bytes([0x5a]) * (1024 * 1024)
    for disk in disks:
        with disk.open("wb") as stream:
            for _ in range(DISK_BYTES // len(pattern)):
                stream.write(pattern)
            stream.flush()
            os.fsync(stream.fileno())
    pci_free = case.endswith("-mmio-only")
    bus = "mmio" if pci_free or case == "block-mmio" else "pci"
    console_bus = "mmio" if pci_free else "pci"
    command = [assets["dillo"], "--pmi", str(image), "--memory", str(MEMORY_MIB),
               "--cpus", "1", "--console", f"endpoint=stdio,bus={console_bus}"]
    for disk in disks:
        command += ["--blk", f"path={disk},bus={bus}"]
    if case.startswith("net-"):
        command += ["--net", f"bus={bus},backend=user"]
    env = os.environ.copy()
    env.pop("DILLO_BENCH_LOCAL", None)
    if mode == "local":
        env["DILLO_BENCH_LOCAL"] = "net" if case.startswith("net-") else "block"
    env["RUST_LOG"] = "warn,dillo::boot=trace"
    env["RUST_LOG_STYLE"] = "never"
    samples, phases, errors, known = [], [], [], {}
    profiles = []
    last_memory, ready = 0, None
    expected = 2 + (0 if mode == "local" else (len(disks) or 1))
    phase, failure = "startup", None
    output_path, error_path = directory / "stdout.txt", directory / "stderr.txt"
    sampler_start = time.process_time()
    start = time.monotonic()
    with output_path.open("wb") as out, error_path.open("wb") as err:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err, env=env)
        parent = psutil.Process(child.pid)
        tracked, next_discovery = {parent.pid: parent}, 0
        try:
            while child.poll() is None:
                elapsed = time.monotonic() - start
                if elapsed > args.timeout:
                    raise TimeoutError(f"VM exceeded {args.timeout} seconds")
                # Small console file; retain observation precision with every marker.
                found = PHASE.findall(output_path.read_bytes())
                if len(found) > len(phases):
                    for entry in found[len(phases):]:
                        phase = entry.decode()
                        phases.append({"phase": phase, "observed_s": elapsed})
                        if phase == "ready":
                            ready = elapsed
                memory = (phase in ("ready", "idle-after") and elapsed - last_memory >= 0.5
                          or phase.startswith("active:") and elapsed - last_memory >= 2)
                if memory:
                    last_memory = elapsed
                if elapsed >= next_discovery and len(tracked) < expected:
                    try:
                        tracked.update((p.pid, p) for p in parent.children(recursive=True))
                    except psutil.NoSuchProcess:
                        pass
                    next_discovery = elapsed + 0.5
                if args.stack_phase == phase and not profiles:
                    for process in tracked.values():
                        path = directory / f"stacks-{process.pid}.txt"
                        profile_command = ["sample", str(process.pid), "3", "1", "-file", str(path)]
                        with path.with_suffix(".log.txt").open("wb") as log:
                            profiler = subprocess.Popen(profile_command, stdout=log, stderr=log)
                        profiles.append({"process": profiler, "pid": process.pid,
                                         "observed_s": elapsed, "command": profile_command})
                if not args.no_sample:
                    records = []
                    for process in tracked.values():
                        try:
                            if not process.is_running():
                                continue
                            record = snapshot(process, memory)
                            known[(record["pid"], record["created"])] = record
                            records.append(record)
                        except psutil.NoSuchProcess:
                            pass  # Exit between discovery and sample; last sample is retained.
                        except psutil.Error as error:
                            errors.append({"pid": process.pid, "error": str(error)})
                    samples.append({"elapsed_s": elapsed, "phase": phase, "processes": records})
                time.sleep(args.sample_ms / 1000)
        except Exception as error:
            failure = repr(error)
        finally:
            if child.poll() is None:
                for process in reversed(list(tracked.values())):
                    try:
                        if process.is_running():
                            process.kill()
                    except psutil.NoSuchProcess:
                        pass
            child.wait()
            child.stdin.close()
            for profile in profiles:
                profiler = profile.pop("process")
                try:
                    profile["returncode"] = profiler.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    profiler.kill()
                    profile["returncode"] = profiler.wait()
            survivors = [p for p in tracked.values() if p.pid != child.pid and p.is_running()]
            if survivors:
                failure = f"surviving workers: {[p.pid for p in survivors]}"
                for process in survivors:
                    process.kill()
                psutil.wait_procs(survivors, timeout=3)
    elapsed = time.monotonic() - start
    output = output_path.read_bytes()
    match = REPORT.search(output)
    report = json.loads(match[1]) if match else None
    boot = error_path.read_text(errors="replace")
    stages = {name: int(us) for name, us in re.findall(r"\b(\w+) \+(\d+)us", boot)}
    result = {"case": case, "mode": mode, "label": label, "command": command,
              "returncode": child.returncode, "wall_s": elapsed, "ready_s": ready,
              "boot_stages_us": stages, "image_sha256": digest(image),
              "guest_allocation_bytes": MEMORY_MIB * 1024 * 1024,
              "samples": samples, "last_process_samples": list(known.values()),
              "sampling_errors": errors, "phases": phases, "guest": report,
              "failure": failure,
              "stack_profiles": profiles,
              "sampler_and_echo_cpu_s": time.process_time() - sampler_start}
    save(directory / "result.json", result)
    if args.stack_phase:
        assert len(profiles) == expected and all(p["returncode"] == 0 for p in profiles), (
            f"stack profiling failed: {directory}")
    assert not failure and child.returncode == 0 and ready is not None and report, f"boot failed: {directory}"
    if pci_free:
        assert not report["pci"], f"PCI device present in PCI-free case: {directory}"
    perf = report["performance"]
    assert not perf["errors"] and perf["operations"], f"guest benchmark failed: {directory}"
    expected_devices = {"net"} if case.startswith("net-") else {
        f"vd{chr(ord('a') + i)}" for i in range(len(disks))}
    observed_devices = {op["device"] for op in perf["operations"]} - {"block-group"}
    assert observed_devices == expected_devices, (expected_devices, observed_devices, directory)
    assert all(op["verified"] is not False and op["latency"]["count"] > 0
               for op in perf["operations"]), f"invalid result: {directory}"
    idle_counts = [len(s["processes"]) for s in samples if s["phase"] == "idle-after"]
    if not args.no_sample:
        assert idle_counts and min(idle_counts) == max(idle_counts) == expected, (
            f"expected {expected} processes, got {idle_counts}: {directory}")
    print(f"{label}: {len(perf['operations'])} operations, ready {ready:.3f}s", flush=True)
    return result


def summarize(results, output):
    pairs = {}
    for result in results:
        pairs.setdefault((result["case"], result["pair"]), {})[result["mode"]] = result
    ratios = {}
    for (case, _), modes in pairs.items():
        for mode, result in modes.items():
            result["metrics"] = {"ready_s": result["ready_s"]}
            for operation in result["guest"]["performance"]["operations"]:
                key = f"{operation['device']}/{operation['operation']}/{operation['request_bytes']}"
                result["metrics"][key + "/MiBps"] = operation["bytes"] * 1e9 / operation["elapsed_ns"] / 2**20
                result["metrics"][key + "/p99_upper_ns"] = operation["latency"]["p99_upper_ns"]
                active = [s for s in result["samples"] if s["phase"] ==
                          f"active:{operation['device']}:{operation['operation']}:{operation['request_bytes']}"]
                if len(active) >= 2:
                    first, last = active[0], active[-1]
                    cpu = lambda s: sum(p["cpu_user_s"] + p["cpu_system_s"] for p in s["processes"])
                    rate = (cpu(last) - cpu(first)) / (last["elapsed_s"] - first["elapsed_s"])
                    result["metrics"][key + "/cpu_cores"] = rate
                    result["metrics"][key + "/cpu_s_per_GiB"] = rate / (
                        operation["bytes"] * 1e9 / operation["elapsed_ns"] / 2**30)
            idle = [s for s in result["samples"] if s["phase"] == "idle-after"]
            for metric in ("uss", "pss", "private"):
                values = [sum(p["memory"][metric] for p in s["processes"])
                          for s in idle if s["processes"] and
                          all(metric in p.get("memory", {}) for p in s["processes"])]
                if values:
                    result["metrics"]["idle_sum_" + metric + "_bytes"] = statistics.median(values)
            host_private = [sum(p["memory"]["uss"] - p["hugetlb"]["Private_Hugetlb"]
                                for p in s["processes"]) for s in idle if s["processes"]
                            and all("hugetlb" in p and "uss" in p.get("memory", {}) for p in s["processes"])]
            if host_private:
                result["metrics"]["idle_private_excluding_hugetlb_bytes"] = statistics.median(host_private)
            result["metrics"]["sampled_tree_cpu_s"] = sum(
                p["cpu_user_s"] + p["cpu_system_s"] for p in result["last_process_samples"])
        for metric, local in modes["local"]["metrics"].items():
            if local and metric in modes["worker"]["metrics"]:
                ratios.setdefault(case + "/" + metric, []).append(modes["worker"]["metrics"][metric] / local)
    summary = {key: {"worker_over_local": values, "median": statistics.median(values),
                     "min": min(values), "max": max(values)} for key, values in ratios.items()}
    save(output / "summary.json", summary)
    save(output / "metrics.json", [{"case": r["case"], "pair": r["pair"], "mode": r["mode"],
                                   "metrics": r["metrics"]} for r in results])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", default="block-pci,block-mmio,block4-pci,net-pci")
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--duration-ms", type=int, default=1000)
    parser.add_argument("--queue-depth", type=int, choices=(1, 8, 32), default=1,
                        help="maximum concurrent block requests, one per guest thread")
    parser.add_argument("--warmup-ms", type=int, default=250)
    parser.add_argument("--sample-ms", type=int, default=50)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--no-sample", action="store_true")
    parser.add_argument("--backing-dir", type=Path, help="optional disposable disk directory, e.g. tmpfs")
    parser.add_argument("--extra-cmdline", default="", help="explicit guest settings for sensitivity runs")
    parser.add_argument("--serial", action="store_true", help="retain early boot diagnostics through SPCR")
    parser.add_argument("--stack-phase", help="macOS diagnostic only: sample stacks during this phase")
    args = parser.parse_args()
    assert args.pairs > 0 and args.sample_ms > 0
    if args.stack_phase:
        assert platform.system() == "Darwin" and shutil.which("sample")
        assert args.duration_ms >= 5000
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    backing = args.output
    if args.backing_dir:
        backing = args.backing_dir.resolve()
        backing.mkdir(parents=True, exist_ok=False)
    assets = json.loads(args.assets.read_text())
    environment = {"platform": platform.platform(), "uname": platform.uname()._asdict(),
                   "cpu_count": psutil.cpu_count(), "psutil": psutil.__version__,
                   "source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                   "dirty": subprocess.check_output(["git", "status", "--porcelain"], text=True),
                   "experimental_shared_isr": "DILLO_BENCH_SHARED_ISR" in os.environ,
                   "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
                   "assets": assets, "hashes": {k: digest(assets[k]) for k in
                                                ("dillo", "arma", "snuffler", "kernel")},
                   "options": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}}
    environment["host_cpu"] = (Path("/proc/cpuinfo").read_text() if platform.system() == "Linux" else
        subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True)
        if platform.system() == "Darwin" else os.environ.get("PROCESSOR_IDENTIFIER"))
    environment["host_load"] = psutil.getloadavg()
    if hasattr(psutil.Process(), "cpu_affinity"):
        environment["cpu_affinity"] = psutil.Process().cpu_affinity()
    save(args.output / "environment.json", environment)
    config = args.output / "kernel.config"
    config.write_text(assets["config"])
    results = []
    with Server(("127.0.0.1", 0), Echo) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        for case in args.cases.split(","):
            assert case in ("block-pci", "block-mmio", "block4-pci", "block4-concurrent-pci",
                            "net-pci", "block-mmio-only", "net-mmio-only")
            image = args.output / f"{case}.pmi"
            count = 0 if case.startswith("net-") else (4 if case.startswith("block4-") else 1)
            selected = ",".join(f"vd{chr(ord('a') + i)}" for i in range(count))
            cmdline = (f"console=hvc0 dillo.uptime_ns dillo.panic_report "
                       f"dillo.bench_ms={args.duration_ms} dillo.bench_warmup_ms={args.warmup_ms} "
                       f"dillo.bench_qd={args.queue_depth} dillo.bench_devices={selected}")
            cmdline += " " + args.extra_cmdline
            if case == "block4-concurrent-pci":
                cmdline += " dillo.bench_concurrent"
            if case.startswith("net-"):
                cmdline += (f" ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off"
                            f" dillo.net_echo=10.0.2.2:{port}")
            build = [assets["arma"], "build", "--kernel", assets["kernel"], "--config", str(config),
                     "--profile", assets["profile"], "--initrd", assets["snuffler"], "--cmdline", cmdline]
            if args.serial:
                build.append("--serial")
            if case.endswith("-mmio-only"):
                build += ["--pci-slots", "0", "--mmio-slots", "2"]
            build.append(str(image))
            subprocess.run(build, check=True)
            save(args.output / f"{case}-image.json", {"command": build, "sha256": digest(image)})
            disks = [backing / f"disk{i}.raw" for i in range(count)]
            for pair in range(-1, args.pairs):  # First pair warms the host and is retained but excluded.
                order = ("local", "worker") if pair % 2 == 0 else ("worker", "local")
                for mode in order:
                    label = f"{case}-{pair + 1:02d}-{mode}"
                    result = run_vm(args, assets, image, disks, case, mode, label)
                    result["pair"] = pair
                    if pair >= 0:
                        results.append(result)
            summarize(results, args.output)
        server.shutdown()


if __name__ == "__main__":
    main()
