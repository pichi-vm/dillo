# Workspace application package for the dillo CLI (RPM name dillo-vm).
# Shaped like a rust2rpm binary spec and hand-tuned for this repo:
# one binary from the workspace root. Cargo.lock is vendored at SRPM
# time (Source1). %%build and %%install stay offline.
#
# cargo-rpm-macros >= 26 supplies %%cargo_prep -v, %%cargo_build, and
# %%cargo_install and sets net.offline. Do not BuildRequire rust-toolset:
# on RHEL that metapackage conflicts with cargo-rpm-macros.
#
# Linked dependency MSRV is rustc 1.91 (smoltcp 0.13.1 rust-version).
# centos-stream chroots do not ship cargo-rpm-macros; enable the matching
# EPEL repository there when the Copr package is wired.

%global crate dillo

# src/lib.rs is an internal launch library, not a published crate.
# cargo package cannot repack this workspace (path + git deps, publish = false).
%global cargo_install_lib 0

# Fedora and EPEL ship an unrelated dillo web browser. Name this
# package dillo-vm so it does not replace that package. The binary
# stays /usr/bin/dillo; that path is also owned by the browser, so
# the two packages cannot be co-installed.
Name:           dillo-vm
Version:        0.1.0
Release:        1%{?dist}
Summary:        VMM that boots PMI files
# Linux x86_64 and aarch64 link closure
# (cargo tree -p dillo --target <triple> -e no-build,no-dev,no-proc-macro).
# Upstream sources are Apache-2.0; a few files are Apache-2.0 OR BSD-3-Clause
# (see NOTICE). The AND expression also covers statically linked crates.
License:        0BSD AND Apache-2.0 AND BSD-3-Clause AND MIT AND (Apache-2.0 OR BSD-3-Clause) AND (Apache-2.0 OR MIT) AND (BSD-2-Clause OR Apache-2.0 OR MIT) AND (MIT OR Apache-2.0) AND (Unlicense OR MIT)
URL:            https://github.com/pichi-vm/dillo
# Source0 is the git tree without vendor/. Source1 is the vendor
# tarball produced by .copr/Makefile (cargo vendor --locked).
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

# Copr builds each arch on a native builder. Do not cross-emit aarch64.
ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo-rpm-macros >= 26
BuildRequires:  rust >= 1.91
BuildRequires:  cargo >= 1.91
# rustc invokes the system compiler to link.
BuildRequires:  gcc
BuildRequires:  python3

%description
Dillo is a virtual machine monitor that boots PMI files. This package
installs the Linux host binary, which drives the guest through KVM.

%prep
%autosetup -n %{name}-%{version} -p1 -a1
# Nightly is pinned for test-only artifact dependencies (-Z bindeps).
# The package build uses the chroot rustc.
rm -f rust-toolchain.toml
%cargo_prep -v vendor
# %%cargo_prep redirects crates.io only and drops [unstable]. Re-add git
# source replacements plus bindeps so Cargo.lock still parses (artifact
# dev-dependencies) and resolves entirely from vendor/.
cat packaging/cargo-vendor-git.toml >> .cargo/config.toml

%build
# Use -- to pass Cargo flags through the RPM macros.
# smoltcp reads SMOLTCP_IFACE_MAX_ADDR_COUNT in its build script (default 2).
# The virtio-net backend needs 4. %%cargo_prep replaces [env], so export it.
export SMOLTCP_IFACE_MAX_ADDR_COUNT=4
%cargo_build -- --locked
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies
# %%cargo_vendor_manifest uses cargo tree --target=all, which panics on
# the test-only artifact dependencies. Read the same locked source inventory
# as cargo vendor --locked instead, including optional, build and dev crates.
# Keep the cargo2rpm manifest format (and Git revisions) so Fedora's automatic
# bundled(crate(...)) Provides generator still handles cargo-vendor.txt.
python3 - <<'PY' > cargo-vendor.txt
import tomllib

with open("Cargo.lock", "rb") as lockfile:
    packages = tomllib.load(lockfile)["package"]
for package in sorted(packages, key=lambda p: (p["name"], p["version"])):
    source = package.get("source")
    if source is None:
        continue
    line = f'{package["name"]} v{package["version"]}'
    if source.startswith("git+"):
        line += f' ({source.removeprefix("git+")})'
    print(line)
PY

%install
export SMOLTCP_IFACE_MAX_ADDR_COUNT=4
# %%cargo_install also probes targets via cargo2rpm outside %%__cargo.
# Its cargo metadata call must accept the artifact dependency syntax too.
export RUSTC_BOOTSTRAP=1
%cargo_install -- --locked

%files
%license LICENSE
%license NOTICE
%license LICENSE.dependencies
%license cargo-vendor.txt
%{_bindir}/dillo

%changelog
* Tue Oct 27 2026 Nathaniel McCallum <nathaniel@mccallum.life> - 0.1.0-1
- Package the dillo VMM as dillo-vm. Vendor Cargo.lock when building the SRPM.
