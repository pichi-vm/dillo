#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Plot measured pair spread, not a confidence interval (matplotlib 3.10.8)."""

import gzip
import json
from pathlib import Path
import sys

import matplotlib.pyplot as plt


root = Path(sys.argv[1])
with gzip.open(root / "measurements.json.gz", "rt") as stream:
    experiments = json.load(stream)[:5]

plt.rcParams.update({"font.size": 10, "svg.fonttype": "none"})
fig, axes = plt.subplots(1, 2, figsize=(11, 4), sharey=True, layout="constrained")
for ax, field, title in zip(axes, ("MiBps", "cpu_s_per_GiB"),
                          ("Throughput retained (%)", "CPU time per GiB (%)")):
    ax.axvline(100, color="#777777", linestyle="--", linewidth=1)
    for offset, operation, color in ((-.13, "rand_read", "#1769aa"),
                                     (.13, "rand_write", "#c65b18")):
        for index, experiment in enumerate(experiments):
            row = next(r for r in experiment["comparisons"] if r["case"] == "block-pci"
                       and r["metric"] == f"vda/{operation}/4096/{field}")
            values = [x * 100 for x in row["paired_ratios"]]
            y = index + offset
            ax.plot([min(values), max(values)], [y, y], color=color, linewidth=1.3)
            ax.scatter(values, [y] * len(values), color=color, alpha=.45, s=16)
            ax.scatter([row["ratio_median"] * 100], [y], color=color, marker="|", s=160,
                       label=operation.replace("rand_", "Random ") if index == 0 else None)
    ax.set_title(title)
    ax.set_xlabel("Worker / in-process; 100% means equal")
    ax.grid(axis="x", alpha=.2)
    ax.spines[["top", "right", "left"]].set_visible(False)
axes[0].set_yticks(range(len(experiments)), [e["label"] for e in experiments])
axes[0].invert_yaxis()
axes[0].legend(loc="lower left", fontsize=9)
fig.suptitle("One block device, PCI, 4 KiB, queue depth 1\nFive paired measurements per host; dots are pairs, marks are medians")
fig.savefig(root / "block-cost.svg", metadata={"Date": None})
fig.savefig(root / "block-cost.png", dpi=160)
