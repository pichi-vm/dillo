#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Select Microsoft's unmodified prebuilt kernel for clock diagnostics.

This kernel includes Hyper-V clocks and virtio transports. The guest probe
configures benchmark IPv4 when the kernel lacks IP autoconfiguration.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zlib


URL = "https://github.com/microsoft/WSL/releases/download/3.0.5/wsl.3.0.5.0.x64.msi"
MSI_SHA256 = "2313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa"
KERNEL_SHA256 = "4845ac8718804c91f3b5cbb9c09c856732612af4e1729faf402f727b0f3285b6"


def embedded_config(kernel):
    offset = 0
    while (offset := kernel.find(b"\x1f\x8b\x08", offset)) >= 0:
        try:
            image = zlib.decompressobj(31).decompress(kernel[offset:])
            start = image.index(b"IKCFG_ST") + 8
            end = image.index(b"IKCFG_ED", start)
            return gzip.decompress(image[start:end]).decode()
        except (zlib.error, ValueError):
            offset += 1
    raise ValueError("kernel has no embedded configuration")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", type=Path)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    assets = json.loads(args.assets.read_text())
    assert assets["arch"] == "x86_64"
    args.cache.mkdir(parents=True, exist_ok=True)
    archive = args.cache / URL.rsplit("/", 1)[1]
    if not archive.exists():
        with urllib.request.urlopen(URL) as source, archive.open("wb") as target:
            shutil.copyfileobj(source, target)
    with archive.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == MSI_SHA256
    seven_zip = shutil.which("7z")
    if seven_zip is None:
        raise RuntimeError("7z is required to extract the prebuilt kernel")
    for source, member in [(archive, "cab3.cab"), (args.cache / "cab3.cab", "kernel")]:
        subprocess.run([seven_zip, "x", "-y", "-o" + str(args.cache), str(source), member],
                       check=True, stdout=subprocess.DEVNULL)
    kernel = args.cache / "kernel"
    content = kernel.read_bytes()
    assert hashlib.sha256(content).hexdigest() == KERNEL_SHA256
    config = embedded_config(content)
    for feature in ("HYPERV", "HYPERV_TIMER", "VIRTIO_PCI", "VIRTIO_MMIO",
                    "VIRTIO_BLK", "VIRTIO_CONSOLE", "VIRTIO_NET"):
        assert f"CONFIG_{feature}=y" in config.splitlines(), feature
    (args.cache / "kernel.config").write_text(config)
    assets.update(kernel=str(kernel.resolve()), config=config,
                  benchmark_kernel_source={"url": URL, "archive_sha256": MSI_SHA256})
    args.assets.write_text(json.dumps(assets, indent=2) + "\n")
    print("Selected unmodified WSL 6.18.58.1 kernel:", KERNEL_SHA256)


if __name__ == "__main__":
    main()
