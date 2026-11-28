#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Export absolute results and paired ratios from one completed experiment."""

import argparse
import csv
import json
from pathlib import Path
import random
import statistics


def median_interval(values):
    """Bootstrap 95% interval assuming exchangeable pairs, not absence of drift."""
    if len(values) < 10:
        return None
    rng = random.Random(20261127)
    medians = sorted(statistics.median(rng.choices(values, k=len(values)))
                     for _ in range(10000))
    return [medians[249], medians[9749]]


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
                         "ratio_median_ci95": median_interval(ratios),
                         "ratio_min": min(ratios), "ratio_max": max(ratios),
                         "local_values": values["local"], "worker_values": values["worker"],
                         "paired_ratios": ratios})
    return rows


def compare(baseline, candidate):
    """Compare like execution modes across interleaved labels or revisions."""
    indexes = [{(r["case"], r["metric"]): r for r in rows}
               for rows in (baseline, candidate)]
    assert indexes[0].keys() == indexes[1].keys(), "comparison metrics differ"
    rows = []
    for (case, metric), before in indexes[0].items():
        after = indexes[1][case, metric]
        assert before["pairs"] == after["pairs"], "comparison pair counts differ"
        for mode in ("local", "worker"):
            a, b = before[mode + "_values"], after[mode + "_values"]
            if any(value == 0 for value in a):
                continue
            ratios = [second / first for first, second in zip(a, b)]
            rows.append({"case": case, "metric": metric, "mode": mode,
                         "pairs": len(ratios),
                         "baseline_median": statistics.median(a),
                         "candidate_median": statistics.median(b),
                         "ratio_median": statistics.median(ratios),
                         "ratio_median_ci95": median_interval(ratios),
                         "baseline_values": a, "candidate_values": b,
                         "paired_ratios": ratios})
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--baseline", type=Path,
                        help="compare like modes with an interleaved baseline label")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = analyze(args.results)
    if args.baseline:
        rows = compare(analyze(args.baseline), rows)
    args.output.write_text(json.dumps(rows, indent=2) + "\n")
    with args.output.with_suffix(".csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
