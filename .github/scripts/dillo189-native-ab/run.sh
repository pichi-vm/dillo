#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C CARGO_INCREMENTAL=0 CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_BUILD_RUSTFLAGS='-D warnings'
export RUST_LOG=info,dillo::boot=trace,dillo_pci_virtio=debug,dillo_machine_kvm=debug,dillo_mmio_virtio=debug

base=36b784b15a276d94c842bb9ef83593edcbc50b52
head=19caa6fb8415fa0bef0a7380d06b2b1fa54b23f2
nightly=nightly-2026-07-06
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(realpath "$1")
mkdir -p "$2"
evidence=$(realpath "$2")
scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/dillo189-ab.XXXXXXXX")
{
    uname -a
    lscpu
    ls -l /dev/kvm
    grep -i huge /proc/meminfo
    for module in kvm kvm_intel kvm_amd; do
        if [[ -r /sys/module/$module/parameters/nested ]]; then
            printf '%s nested=' "$module"
            cat "/sys/module/$module/parameters/nested"
        fi
    done
    printf 'ImageOS=%s ImageVersion=%s RUST_LOG=%s CARGO_BUILD_RUSTFLAGS=%s\n' \
        "${ImageOS:-}" "${ImageVersion:-}" "$RUST_LOG" "$CARGO_BUILD_RUSTFLAGS"
    cargo "+$nightly" --version
    rustc "+$nightly" -Vv
} > "$evidence/host.txt"
python3 - <<'PY' >> "$evidence/host.txt"
import fcntl
with open("/dev/kvm", "rb+") as kvm:
    assert fcntl.ioctl(kvm, 0xAE00, 0) == 12, "expected KVM API version 12"
print("KVM API version 12")
PY

for label in base head; do
    ref=$base
    [[ $label == base ]] || ref=$head
    checkout=$scratch/$label
    mkdir -p "$checkout"
    git -C "$repo" archive "$ref" | tar -x -C "$checkout"
    git -C "$repo" show -s --format='%H %T %P %s' "$ref" > "$evidence/$label.ref"
    cp "$checkout/Cargo.lock" "$evidence/$label.Cargo.lock"
    (
        cd "$checkout"
        CARGO_TARGET_DIR="$scratch/target-$label" cargo "+$nightly" \
            --config .copr/cargo-config.toml test --locked -p dillo \
            --features vm-tests --test boot --no-run --message-format=json
    ) > "$evidence/$label.build.jsonl" 2> "$evidence/$label.build.stderr"
done

# Match native CI: reserve hugepages after compilation and before boot.
for _ in 1 2 3 4 5 6; do
    if [[ $(sysctl -n vm.nr_hugepages) -ge 4096 ]]; then break; fi
    sync || true
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null || true
    echo 1 | sudo tee /proc/sys/vm/compact_memory >/dev/null || true
    sudo sysctl -w vm.nr_hugepages=4096 || true
    sleep 3
done
grep -i huge /proc/meminfo | tee "$evidence/provisioning.txt"
[[ $(sysctl -n vm.nr_hugepages) -ge 4096 ]]
python3 "$script_dir/experiment.py" "$scratch" "$evidence"
