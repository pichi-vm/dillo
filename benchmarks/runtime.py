#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Freeze a comparison executable, then give it the candidate's guest assets."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('action', choices=('freeze', 'match'))
parser.add_argument('directory', type=Path)
parser.add_argument('candidate', type=Path, nargs='?')
args = parser.parse_args()
assets_path = args.directory / 'assets.json'
runtime_path = args.directory / 'runtime.json'
if args.action == 'freeze':
    assets = json.loads(assets_path.read_text())
    source = Path(assets['dillo'])
    frozen = args.directory / source.name
    shutil.copy2(source, frozen)
    runtime_path.write_text(json.dumps({
        'dillo': str(frozen.resolve()),
        'runtime_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    }))
else:
    if args.candidate is None:
        parser.error('match requires candidate assets.json')
    assets = json.loads(args.candidate.read_text())
    runtime = json.loads(runtime_path.read_text())
    digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if digest(assets['dillo']) == digest(runtime['dillo']):
        parser.error('baseline and candidate executables are identical')
    assets.update(runtime)
    assets_path.write_text(json.dumps(assets))
