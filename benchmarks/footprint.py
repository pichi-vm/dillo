#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Count physical source lines and Rust unsafe sites, separating test items.

Analysis-only dependencies: tree-sitter==0.25.2, tree-sitter-rust==0.24.0.
Counts include comments/blank lines and every platform, not compiled size.
"""

import collections
import json
from pathlib import PurePosixPath
import re
import subprocess
import sys

from tree_sitter import Language, Parser
import tree_sitter_rust


def git(*args):
    return subprocess.check_output(["git", *args])


def group(path):
    if path.startswith(("deps/dillo-worker/", "deps/dillo-ipc/")):
        return "worker_and_wire"
    if path.startswith("deps/dillo-machine-unix/"):
        return "unix_services"
    if path.startswith("deps/dillo-windows-channel/"):
        return "windows_channel"
    if path.startswith("src/"):
        return "launcher"
    if path.startswith("deps/dillo-machine-"):
        return "native_backends"
    if path.startswith("deps/dillo-virtio-"):
        return "devices"
    return "other_runtime"


def measure(revision):
    parser = Parser(Language(tree_sitter_rust.language()))
    counts = collections.defaultdict(collections.Counter)
    inventory = []
    for path in git("ls-tree", "-r", "--name-only", revision).decode().splitlines():
        parts = PurePosixPath(path).parts
        if not (path.startswith(("src/", "tests/")) or
                path.startswith("deps/dillo-") and ("src" in parts or "tests" in parts)):
            continue
        if not path.endswith(".rs"):
            continue
        source = git("show", f"{revision}:{path}")
        # The grammar predates Rust 2024's unsafe extern blocks. Whitespace
        # preserves byte/line positions; block declarations aren't counted as
        # unsafe functions or unsafe execution blocks.
        parsed = re.sub(rb"unsafe(?=\s+extern\s+\"[^\"]*\"\s*\{)", b"      ", source)
        tree = parser.parse(parsed).root_node
        if tree.has_error:
            raise ValueError(f"cannot classify Rust syntax: {revision}:{path}")
        lines = len(source.splitlines())
        test_rows = set(range(lines)) if any(
            p == "tests" or p == "tests.rs" or p.startswith("tests_") for p in parts) else set()
        nodes = []

        def walk(node):
            nodes.append(node)
            start = None
            for child in node.named_children:
                if child.type == "attribute_item":
                    if re.search(rb"cfg\(\s*(?:test\s*\)|all\([^)]*\btest\b)", child.text):
                        start = child.start_point.row
                elif child.type not in ("line_comment", "block_comment"):
                    if start is not None:
                        test_rows.update(range(start, child.end_point.row + 1))
                        start = None
                walk(child)

        walk(tree)
        item = collections.Counter({"production_lines": lines - len(test_rows),
                                    "test_lines": len(test_rows), "files": 1})
        for node in nodes:
            kind = "unsafe_blocks" if node.type == "unsafe_block" else (
                "unsafe_functions" if node.type in ("function_item", "function_signature_item")
                and any(c.type == "function_modifiers" and b"unsafe" in c.text
                        for c in node.children) else None)
            if kind:
                item[("test_" if node.start_point.row in test_rows else "production_") + kind] += 1
        counts[group(path)].update(item)
        inventory.append({"path": path, **item})
    # Native C/header/build glue is separate; no Rust unsafe-site comparison applies.
    for path in ("native.c", "native.h", "build.rs"):
        path = "deps/dillo-windows-channel/" + path
        if git("ls-tree", "--name-only", revision, path):
            counts["windows_channel"]["native_and_build_lines"] += len(
                git("show", f"{revision}:{path}").splitlines())
    return {"components": counts, "files": inventory}


if __name__ == "__main__":
    print(json.dumps({revision: measure(revision) for revision in sys.argv[1:]}, indent=2))
