#!/usr/bin/env python3
"""Run one unmodified Rust boot test per revision and retain its actual inputs."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib

TEST = "boots_and_reports::mem_mib_1_256::cpus_1_1"
ARMA = "f8b8fb829d9489b5a3104562730a973c86f4c995"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


def artifacts(evidence, label):
    lockfile = evidence / f"{label}.Cargo.lock"
    lock = tomllib.loads(lockfile.read_text())
    for package in ("arma", "tatu"):
        [entry] = [entry for entry in lock["package"] if entry["name"] == package]
        assert entry["source"].endswith(f"#{ARMA}"), entry["source"]
    [exe] = [
        Path(record["executable"])
        for line in (evidence / f"{label}.build.jsonl").read_text().splitlines()
        if (record := json.loads(line))["reason"] == "compiler-artifact"
        and record["target"]["name"] == "boot"
        and record.get("executable")
    ]
    deps = dict(
        line.removeprefix("# env-dep:").split("=", 1)
        for line in exe.with_suffix(".d").read_text().splitlines()
        if line.startswith("# env-dep:CARGO_BIN_")
    )
    return {
        "boot": exe,
        "dillo": Path(deps["CARGO_BIN_EXE_dillo"]),
        "arma": Path(deps["CARGO_BIN_FILE_ARMA_arma"]),
        "snuffler": Path(deps["CARGO_BIN_FILE_SNUFFLER_snuffler"]),
        "lockfile": lockfile,
    }


def remember_inputs(parent, cwd, bins, observed):
    """Open read-only handles while the Rust fixture still owns the temp files."""
    for task in Path(f"/proc/{parent}/task").glob("[0-9]*"):
        try:
            children = (task / "children").read_text().split()
        except OSError:
            continue
        for pid in children:
            proc = Path("/proc") / pid
            try:
                command = Path(os.readlink(proc / "exe"))
                if command == bins["dillo"]:
                    flags = {"pmi": "--pmi"}
                elif command == bins["arma"]:
                    flags = {"kernel": "--kernel", "config": "--config",
                             "initrd": "--initrd"}
                else:
                    continue
                args = (proc / "cmdline").read_bytes().split(b"\0")
                for name, flag in flags.items():
                    if name in observed or os.fsencode(flag) not in args:
                        continue
                    path = cwd / os.fsdecode(args[args.index(os.fsencode(flag)) + 1])
                    observed[name] = (path, path.open("rb"))
            except (OSError, IndexError):
                # A short-lived child can exit between any of these observations.
                continue


def save_inputs(observed, output, bins):
    manifest = {}
    for name, (path, stream) in observed.items():
        with stream:
            entry = {"path": str(path), "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
            if name in {"pmi", "config"}:
                saved = output / f"fixture.{name}"
                stream.seek(0)
                with saved.open("wb") as sink:
                    shutil.copyfileobj(stream, sink)
                assert digest(saved) == entry["sha256"], f"{name} changed after observation"
                entry["saved"] = saved.name
            if name == "initrd":
                entry["matches_compiled_snuffler"] = entry["sha256"] == digest(bins["snuffler"])
            manifest[name] = entry
    write_json(output / "fixture.json", manifest)


def run_one(bins, cwd, output):
    output.mkdir()
    write_json(output / "artifact-sha256.json", {
        name: {"path": str(path), "sha256": digest(path)}
        for name, path in bins.items()
    })
    env = dict(os.environ)
    env.pop("RUST_LOG", None)
    command = [str(bins["boot"]), TEST, "--exact", "--test-threads=1", "--nocapture"]
    listing = subprocess.run([str(bins["boot"]), TEST, "--exact", "--list"],
                             cwd=cwd, env=env, check=True, text=True,
                             capture_output=True, timeout=10)
    (output / "selected-test.txt").write_text(listing.stdout)
    selected = re.findall(r"^(.+): test$", listing.stdout, re.MULTILINE)
    if selected != [TEST]:
        raise RuntimeError(f"unexpected test selection: {selected!r}")

    observed = {}
    start = time.monotonic()
    timed_out = False
    with (output / "stdout").open("wb") as stdout, (output / "stderr").open("wb") as stderr:
        with subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True,
                              stdout=stdout, stderr=stderr) as child:
            while child.poll() is None:
                if time.monotonic() - start >= 180:
                    timed_out = True
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=10)
                    break
                remember_inputs(child.pid, cwd, bins, observed)
                time.sleep(0.05)
            exit_code = child.returncode
    save_inputs(observed, output, bins)
    text = "\n".join((output / name).read_text(errors="replace") for name in ("stdout", "stderr"))
    count = re.findall(r"^running (\d+) tests?$", text, re.MULTILINE)
    report = {
        "command": command,
        "cwd": str(cwd),
        "rust_log_set": "RUST_LOG" in env,
        "selected_test_count": len(selected),
        "reported_running_counts": [int(value) for value in count],
        "fixture_captured": sorted(observed),
        "outer_timeout": timed_out,
        "exit_code": exit_code,
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "skipped": "skip: no usable /dev/kvm" in text,
    }
    write_json(output / "result.json", report)
    print(f"{output.name}: {json.dumps(report)}", flush=True)
    print(text, flush=True)
    return exit_code == 0 and not timed_out and count == ["1"] and not report["skipped"]


if __name__ == "__main__":
    scratch, evidence = map(Path, sys.argv[1:])
    outcomes = [
        run_one(artifacts(evidence, label), scratch / label, evidence / label)
        for label in ("base", "head")
    ]
    sys.exit(0 if all(outcomes) else 1)
