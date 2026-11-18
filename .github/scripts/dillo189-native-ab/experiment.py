#!/usr/bin/env python3
"""Build fixture PMIs once and compare native Dillo binaries on this host."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tomllib

ARMA = "f8b8fb829d9489b5a3104562730a973c86f4c995"
FIRECRACKER = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci"
FEDORA_CONFIG = (
    "https://src.fedoraproject.org/rpms/kernel/raw/"
    "e44c3f75126e5490b097372b199562776b3872f6/f/kernel-x86_64-fedora.config"
)
PCI_CONFIG = "CONFIG_PCI=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_MMIO=y\nCONFIG_VIRTIO_BLK=y\n"
MMIO_CONFIG = "CONFIG_VIRTIO_MMIO=y\nCONFIG_VIRTIO_BLK=y\n"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def artifacts(evidence, rev):
    lock = tomllib.loads((evidence / f"{rev}.Cargo.lock").read_text())
    for package in ("arma", "tatu"):
        [entry] = [entry for entry in lock["package"] if entry["name"] == package]
        assert entry["source"].endswith(f"#{ARMA}"), entry["source"]
    records = [
        json.loads(line)
        for line in (evidence / f"{rev}.build.jsonl").read_text().splitlines()
    ]
    [exe] = [
        Path(record["executable"])
        for record in records
        if record["reason"] == "compiler-artifact"
        and record["target"]["name"] == "boot"
        and record.get("executable")
    ]
    deps = dict(
        line.removeprefix("# env-dep:").split("=", 1)
        for line in exe.with_suffix(".d").read_text().splitlines()
        if line.startswith("# env-dep:CARGO_BIN_")
    )
    result = {
        "dillo": Path(deps["CARGO_BIN_EXE_dillo"]),
        "arma": Path(deps["CARGO_BIN_FILE_ARMA_arma"]),
        "snuffler": Path(deps["CARGO_BIN_FILE_SNUFFLER_snuffler"]),
    }
    assert all(path.is_file() and os.access(path, os.X_OK) for path in result.values())
    return result


def fetch(url, path):
    subprocess.run(
        ["curl", "--fail", "--silent", "--show-error", "--location",
         "--connect-timeout", "15", "--max-time", "120", "--output", str(path), url],
        check=True,
    )


def make_fixture(scratch, evidence, name, kernel_url, config_url, builtins,
                 config_override, cmdline, tools, forbidden=()):
    directory = scratch / name
    directory.mkdir()
    kernel = directory / "kernel"
    source_config = evidence / f"{name}.published.config"
    build_config = evidence / f"{name}.arma.config"
    pmi = directory / "boot.pmi"
    fetch(kernel_url, kernel)
    fetch(config_url, source_config)
    source_text = source_config.read_text()
    config_lines = set(source_text.splitlines())
    for symbol in builtins:
        assert f"CONFIG_{symbol}=y" in config_lines, (name, symbol)
    for symbol in forbidden:
        assert f"CONFIG_{symbol}=y" not in config_lines, (name, symbol)
    build_config.write_text(source_text if config_override is None else config_override)
    cmd = [str(tools["arma"]), "build", "--cmdline", cmdline]
    if config_override is not None:
        cmd += ["--profile", "x86-64-v2"]
    cmd += ["--config", str(build_config), "--kernel", str(kernel),
            "--initrd", str(tools["snuffler"]), str(pmi)]
    with (evidence / f"{name}.arma.log").open("wb") as output:
        subprocess.run(cmd, stdout=output, stderr=subprocess.STDOUT,
                       check=True, timeout=120)
    pmi.chmod(0o444)
    manifest = {
        "kernel_url": kernel_url,
        "config_url": config_url,
        "command": cmd,
        "sha256": {path.name: digest(path) for path in
                   (kernel, source_config, build_config, pmi)},
    }
    (evidence / f"{name}.fixture.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return pmi


def boot(exe, pmi, evidence, label, memory, bus, extra=()):
    command = [str(exe), "--console", f"endpoint=stdio,bus={bus}", "--pmi",
               str(pmi), "--memory", str(memory), "--cpus", "1", *extra]
    stdout = evidence / f"{label}.stdout"
    stderr = evidence / f"{label}.stderr"
    start = time.monotonic()
    timed_out = False
    with stdout.open("wb") as out, stderr.open("wb") as err:
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out,
                              stderr=err, start_new_session=True) as child:
            try:
                child.wait(timeout=120)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=10)
            exit_code = child.returncode
    text = stdout.read_text(errors="replace") + stderr.read_text(errors="replace")
    _, begin, tail = text.partition("<<<DILLO-E2E-REPORT>>>")
    payload, end, _ = tail.partition("<<<END>>>")
    report = None
    if begin and end:
        try:
            report = json.loads(payload)
        except json.JSONDecodeError:
            pass
    valid = (
        isinstance(report, dict)
        and report.get("arch") == "x86_64"
        and report.get("cpu", {}).get("online_count") == 1
    )
    if valid:
        cmdline = report.get("cmdline", "").split()
        valid = "console=hvc0" in cmdline
        if bus == "mmio":
            valid = valid and report.get("pci", None) == [] and bool(report.get("block"))
        if label.startswith("fedora"):
            valid = valid and "bootconfig" in cmdline and report.get("bootconfig") == ""
    if report is not None:
        (evidence / f"{label}.report.json").write_text(json.dumps(report, indent=2) + "\n")
    result = {
        "command": command,
        "timeout": timed_out,
        "exit_code": exit_code,
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "report_valid": valid,
    }
    (evidence / f"{label}.result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{label}: exit={exit_code} timeout={timed_out} report_valid={valid}", flush=True)
    return not timed_out and exit_code == 0 and valid


def main(scratch, evidence):
    versions = {rev: artifacts(evidence, rev) for rev in ("base", "head")}
    (evidence / "artifact-sha256.json").write_text(json.dumps(
        {rev: {key: {"path": str(path), "sha256": digest(path)} for key, path in files.items()}
         for rev, files in versions.items()}, indent=2) + "\n")
    # One builder and one initrd for every PMI. The Dillo test fixtures and
    # snuffler sources are identical at both revisions.
    tools = versions["base"]
    pci = f"{FIRECRACKER}/v1.15/x86_64/vmlinux-6.1.155"
    mmio = f"{FIRECRACKER}/v1.12/x86_64/vmlinux-6.1.128"
    fedora = "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/images/pxeboot/vmlinuz"
    fixtures = [
        ("firecracker-pci", pci, pci + ".config",
         ("PROC_PAGE_MONITOR", "PCI", "VIRTIO_PCI", "VIRTIO_MMIO", "VIRTIO_BLK",
          "VIRTIO_NET", "VIRTIO_CONSOLE", "VIRTIO_VSOCKETS", "RANDOMIZE_BASE", "INET", "IP_PNP"),
         PCI_CONFIG, "console=hvc0", 256, "pci", ()),
        ("fedora", fedora, FEDORA_CONFIG,
         ("BOOT_CONFIG", "BLK_DEV_INITRD", "PROC_FS", "VIRTIO_CONSOLE"),
         None, "bootconfig console=hvc0", 512, "pci", ()),
        ("firecracker-mmio", mmio, mmio + ".config",
         ("VIRTIO_MMIO", "VIRTIO_BLK", "VIRTIO_CONSOLE", "VIRTIO_VSOCKETS", "RANDOMIZE_BASE"),
         MMIO_CONFIG, "console=hvc0", 256, "mmio", ("PCI",)),
    ]
    outcomes = []
    for name, kernel, published, builtins, config, cmdline, memory, bus, forbids in fixtures:
        pmi = make_fixture(scratch, evidence, name, kernel, published, builtins,
                           config, cmdline, tools, forbids)
        before = digest(pmi)
        for rev in ("base", "head"):
            extra = []
            if bus == "mmio":
                disk = pmi.parent / f"{rev}.raw"
                with disk.open("wb") as stream:
                    stream.truncate(8 * 1024 * 1024)
                (evidence / f"{name}-{rev}.disk.sha256").write_text(digest(disk) + "\n")
                extra = ["--blk", f"path={disk},bus=mmio"]
            outcomes.append(boot(versions[rev]["dillo"], pmi, evidence,
                                 f"{name}-{rev}", memory, bus, extra))
            assert digest(pmi) == before, f"{name}: PMI changed on disk"
    return 0 if all(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
