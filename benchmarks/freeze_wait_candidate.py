#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Freeze one wait implementation for this branch's native comparison."""

import hashlib
import json
from pathlib import Path
import shutil
import sys

root = Path("target/benchmarks").resolve()
assets = json.loads((root / "assets.json").read_text())
binary = root / f"dillo-{sys.argv[1]}"
shutil.copy2(assets["dillo"], binary)
assets["dillo"] = str(binary)
source = Path("deps/dillo-machine-unix/src/notification.rs").read_bytes()
assets["notification_source_sha256"] = hashlib.sha256(source).hexdigest()
(root / f"{sys.argv[1]}.json").write_text(json.dumps(assets, indent=2))
