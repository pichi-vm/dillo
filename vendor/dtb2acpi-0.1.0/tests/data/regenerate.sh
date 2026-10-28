#!/usr/bin/env bash
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Regenerate the .dtb binary fixtures from their .dts sources using
# dtc. Both sources and binaries are checked in; `cargo test` reads
# the binaries via include_bytes! and does not need dtc.
#
# Requires: dtc (Fedora: `sudo dnf install dtc`).

set -euo pipefail
cd "$(dirname "$0")"

for src in *.dts; do
    dst="${src%.dts}.dtb"
    dtc -q -I dts -O dtb -o "$dst" "$src"
done

echo "regenerated."
