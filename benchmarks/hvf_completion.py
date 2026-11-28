#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Sign and run the bounded native HVF completion check."""

import json, subprocess, tempfile
build = subprocess.run([
    'cargo', '--config', '.copr/cargo-config.toml', 'test', '--locked',
    '-p', 'dillo-machine-hvf', '--lib', '--no-run', '--message-format=json',
], check=True, stdout=subprocess.PIPE, text=True)
binaries = [event['executable'] for line in build.stdout.splitlines()
            if (event := json.loads(line)).get('reason') == 'compiler-artifact'
            and event['target']['name'] == 'dillo_machine_hvf'
            and event['profile']['test']]
assert len(binaries) == 1
with tempfile.NamedTemporaryFile(mode='w', suffix='.plist') as entitlements:
    entitlements.write('<plist version="1.0"><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>')
    entitlements.flush()
    subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements',
                    entitlements.name, binaries[0]], check=True)
subprocess.run([binaries[0], '--ignored', '--exact', '--nocapture',
                'hypervisor::tests::hvf_shared_status_delivery_and_retirement'], check=True)
