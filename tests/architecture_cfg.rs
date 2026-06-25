// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

const DISALLOWED_PATTERNS: &[&str] = &[
    "cfg(target_os",
    "cfg(target_arch",
    "cfg(target_env",
    "cfg(target_family",
    "cfg_attr(target_os",
    "cfg_attr(target_arch",
    "cfg_attr(target_env",
    "cfg_attr(target_family",
];

const RETIRED_CRATES: &[&str] = &[
    "dillo-device",
    "dillo-hypervisor",
    "dillo-machine-backend",
    "dillo-platform",
    "dillo-pmi",
    "dillo-vm",
    "dillo-x86",
    "vhost-backend",
    "vm-pci",
];

#[test]
fn target_cfg_is_confined_to_machine_selection() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scanner = SourceScan::new(manifest);
    let mut failures = Vec::new();

    scanner.scan_dillo_sources(&mut failures);
    scanner.scan_portable_core_crates(&mut failures);

    assert!(
        failures.is_empty(),
        "target cfg must stay out of portable code; found {}",
        failures.join(", ")
    );
}

#[test]
fn retired_compatibility_crates_stay_retired() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().expect("dillo has workspace parent");

    let manifests = [
        workspace.join("Cargo.toml"),
        workspace.join("Cargo.lock"),
        manifest.join("Cargo.toml"),
    ];
    let mut failures = Vec::new();

    for krate in RETIRED_CRATES {
        if workspace.join("dillo/deps").join(krate).exists() {
            failures.push(format!("retired crate directory exists: {krate}"));
        }
        for manifest in manifests.iter().filter(|path| path.exists()) {
            let text = fs::read_to_string(manifest).expect("read manifest");
            if text.contains(krate) {
                failures.push(format!("{} references {krate}", manifest.display()));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "retired compatibility crates must stay out of the workspace: {}",
        failures.join(", ")
    );
}

struct SourceScan {
    manifest: PathBuf,
}

impl SourceScan {
    fn new(manifest: PathBuf) -> Self {
        Self { manifest }
    }

    fn scan_dillo_sources(&self, failures: &mut Vec<String>) {
        let src = self.manifest.join("src");
        self.visit_rust_files(&src, &mut |path| {
            self.scan_file(&src, path, failures);
        });
    }

    fn scan_portable_core_crates(&self, failures: &mut Vec<String>) {
        for crate_dir in [
            "deps/dillo-mmio",
            "deps/dillo-mmio-uart",
            "deps/dillo-mmio-virtio",
            "deps/dillo-pci",
            "deps/dillo-pci-virtio",
            "deps/dillo-virtio-console",
            "deps/dillo-virtio",
        ] {
            let root = self.manifest.join(crate_dir);
            self.visit_rust_files(&root.join("src"), &mut |path| {
                self.scan_file(&root, path, failures);
            });
        }
    }

    fn scan_file(&self, root: &Path, path: &Path, failures: &mut Vec<String>) {
        let _ = &self.manifest;
        let text = fs::read_to_string(path).expect("read source file");
        for (line_idx, line) in text.lines().enumerate() {
            if DISALLOWED_PATTERNS
                .iter()
                .any(|pattern| line.contains(pattern))
            {
                if is_allowed_machine_selection_cfg(root, path, line) {
                    continue;
                }
                let rel = path.strip_prefix(root).unwrap_or(path);
                failures.push(format!("{}:{}", rel.display(), line_idx + 1));
            }
        }
    }

    fn visit_rust_files(&self, dir: &Path, f: &mut impl FnMut(&Path)) {
        let _ = &self.manifest;
        for entry in fs::read_dir(dir).expect("read source directory") {
            let entry = entry.expect("read directory entry");
            let path = entry.path();
            if path.is_dir() {
                self.visit_rust_files(&path, f);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                f(&path);
            }
        }
    }
}

fn is_allowed_machine_selection_cfg(root: &Path, path: &Path, line: &str) -> bool {
    path.strip_prefix(root)
        .is_ok_and(|rel| rel == Path::new("main.rs"))
        && matches!(
            line.trim(),
            "#[cfg(target_os = \"linux\")]"
                | "#[cfg(target_os = \"macos\")]"
                | "#[cfg(target_os = \"windows\")]"
        )
}
