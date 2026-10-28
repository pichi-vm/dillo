#!/usr/bin/env bash
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Regenerate the .dtb / .dtbo binary fixtures from their .dts / .dtso
# sources using dtc. Both sources and binaries are checked into the
# repo; `cargo test` reads the binaries via include_bytes! and does not
# need dtc. Run this script after editing any source.
#
# Requires: dtc (Fedora: `sudo dnf install dtc`).

set -euo pipefail
cd "$(dirname "$0")"

# Plain base trees.
dtc -q -I dts -O dtb -o simple.dtb simple.dts
dtc -q -I dts -O dtb -o phandles.dtb phandles.dts

# Overlay base needs -@ so the labeled nodes get a /__symbols__ entry
# the overlays can resolve against.
dtc -q -@ -I dts -O dtb -o overlay_base.dtb       overlay_base.dts
dtc -q -@ -I dts -O dtb -o overlay_expected.dtb   overlay_expected.dts

# Overlays themselves. -@ emits __fixups__ / __local_fixups__ /
# __symbols__ when needed.
dtc -q -@ -I dts -O dtb -o overlay_patch.dtbo     overlay_patch.dtso
dtc -q -@ -I dts -O dtb -o overlay_nested_a.dtbo  overlay_nested_a.dtso
dtc -q -@ -I dts -O dtb -o overlay_nested_b.dtbo  overlay_nested_b.dtso
# overlay_phandles exercises both __fixups__ (overlay -> base label)
# and __local_fixups__ (overlay-internal phandle reference). dtc emits
# warnings about clocks/reg formatting — harmless for our test, the
# overlay is intentionally minimal.
dtc -q -@ -I dts -O dtb -o overlay_phandles.dtbo     overlay_phandles.dtso 2>/dev/null

# Overlay error-path fixtures.
dtc -q -@ -I dts -O dtb -o overlay_target_path.dtbo  overlay_target_path.dtso
dtc -q -@ -I dts -O dtb -o overlay_unknown_label.dtbo overlay_unknown_label.dtso
dtc -q -@ -I dts -O dtb -o overlay_fragment_no_target.dtbo overlay_fragment_no_target.dtso
# Empty __overlay__ exercises the zero-strings boundary in apply
# (copy_within of strings tail becomes a no-op).
dtc -q -@ -I dts -O dtb -o overlay_empty_body.dtbo   overlay_empty_body.dtso

echo "regenerated."
