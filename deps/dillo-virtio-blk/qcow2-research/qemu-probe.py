"""QEMU reclamation reference. Creates and removes only a private temporary image."""
import json
import os
import subprocess
import tempfile

with tempfile.TemporaryDirectory(prefix="dillo-qcow-reference-") as directory:
    path = os.path.join(directory, "disk.qcow2")
    subprocess.run([
        "qemu-img", "create", "-f", "qcow2", "-o",
        "compat=1.1,cluster_size=65536,lazy_refcounts=off", path, "1G",
    ], check=True, stdout=subprocess.DEVNULL)

    def record(state):
        stat = os.stat(path)
        print(json.dumps({"state": state, "apparent_bytes": stat.st_size,
                          "allocated_bytes": stat.st_blocks * 512}), flush=True)

    record("empty")
    for state, command in [("written", "write -P 0x5a 0 64M"),
                           ("discarded", "discard 0 64M")]:
        subprocess.run(["qemu-io", "-f", "qcow2", "-c", command,
                        "-c", "flush", path], check=True, stdout=subprocess.DEVNULL)
        record(state)
    subprocess.run(["qemu-img", "check", "-f", "qcow2", path], check=True)
