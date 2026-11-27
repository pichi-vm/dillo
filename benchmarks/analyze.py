#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Export absolute results and paired ratios from one completed experiment."""

import argparse
import csv
import json
from pathlib import Path
import statistics


def analyze(root):
    records = json.loads((root / "metrics.json").read_text())
    pairs = {}
    for record in records:
        case, pair, mode = (record[k] for k in ("case", "pair", "mode"))
        raw = json.loads((root / f"{case}-{pair + 1:02d}-{mode}" / "result.json").read_text())
        assert raw["returncode"] == 0 and not raw["failure"]
        assert not raw["guest"]["performance"]["errors"]
        metrics = record["metrics"].copy()
        marks = raw["boot_stages_us"]
        metrics["setup_to_guest_loaded_ms"] = marks["guest_loaded"] / 1000
        metrics["device_attachment_ms"] = (marks["guest_loaded"] - marks["sections_loaded"]) / 1000
        metrics["sampler_and_echo_cpu_percent"] = raw["sampler_and_echo_cpu_s"] / raw["wall_s"] * 100
        idle = [s for s in raw["samples"] if s["phase"] == "idle-after"]
        if idle:
            metrics["idle_processes"] = statistics.median(len(s["processes"]) for s in idle)
            metrics["idle_threads"] = statistics.median(
                sum(p["threads"] for p in s["processes"]) for s in idle)
        for op in raw["guest"]["performance"]["operations"]:
            key = f"{op['device']}/{op['operation']}/{op['request_bytes']}/"
            metrics[key + "IOPS"] = op["latency"]["count"] * 1e9 / op["elapsed_ns"]
            for field in ("p50_upper_ns", "p95_upper_ns", "p99_upper_ns", "max_ns"):
                metrics[key + field] = op["latency"][field]
        pairs.setdefault(case, {}).setdefault(pair, {})[mode] = metrics
    rows = []
    for case, cases in pairs.items():
        assert all(set(modes) == {"worker", "local"} for modes in cases.values())
        common = set.intersection(*(set(m) for modes in cases.values() for m in modes.values()))
        for metric in sorted(common):
            values = {mode: [modes[mode][metric] for _, modes in sorted(cases.items())]
                      for mode in ("local", "worker")}
            ratios = [b / a for a, b in zip(values["local"], values["worker"]) if a]
            if len(ratios) != len(cases):
                continue
            rows.append({"case": case, "metric": metric, "pairs": len(cases),
                         "local_median": statistics.median(values["local"]),
                         "worker_median": statistics.median(values["worker"]),
                         "paired_delta_median": statistics.median(
                             b - a for a, b in zip(values["local"], values["worker"])),
                         "ratio_median": statistics.median(ratios),
                         "ratio_min": min(ratios), "ratio_max": max(ratios),
                         "local_values": values["local"], "worker_values": values["worker"],
                         "paired_ratios": ratios})
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = analyze(args.results)
    args.output.write_text(json.dumps(rows, indent=2) + "\n")
    with args.output.with_suffix(".csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
