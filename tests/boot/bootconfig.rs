// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Native bootconfig through an unmodified stock kernel. Override the paired
//! kernel/config environment variables to run the same checks on another distro.

use super::*;

fn image(dir: &Path, cmdline: &str) -> PathBuf {
    let (kernel, config) = match (
        std::env::var_os("DILLO_BOOTCONFIG_KERNEL"),
        std::env::var_os("DILLO_BOOTCONFIG_CONFIG"),
    ) {
        (Some(kernel), Some(config)) => (
            PathBuf::from(kernel),
            std::fs::read_to_string(config).unwrap(),
        ),
        (None, None) => {
            let entry = KERNELS
                .iter()
                .find(|entry| entry.arch == host::ARCH && entry.builtins.contains(&"BOOT_CONFIG"))
                .expect("stock bootconfig kernel catalog entry");
            let (kernel, config) =
                resolve(entry).expect("download stock bootconfig kernel and config");
            (kernel, config.expect("stock config"))
        }
        _ => {
            panic!("DILLO_BOOTCONFIG_KERNEL and DILLO_BOOTCONFIG_CONFIG must be supplied together")
        }
    };
    for option in ["BOOT_CONFIG", "BLK_DEV_INITRD", "PROC_FS", "VIRTIO_CONSOLE"] {
        assert!(config_is_y(&config, option), "stock config lacks {option}");
    }
    let config_path = dir.join("kernel.config");
    std::fs::write(&config_path, config).unwrap();
    let pmi = dir.join("bootconfig.pmi");
    let status = Command::new(env!("CARGO_BIN_FILE_ARMA_arma"))
        .arg("build")
        .arg("--kernel")
        .arg(kernel)
        .arg("--config")
        .arg(config_path)
        .arg("--initrd")
        .arg(env!("CARGO_BIN_FILE_SNUFFLER_snuffler"))
        .args(["--cmdline", cmdline])
        .arg(&pmi)
        .status()
        .unwrap();
    assert!(status.success(), "arma bootconfig build");
    pmi
}

#[test]
fn bootconfig_optional_input_and_linux_parsing() {
    assert!(
        hypervisor_available(),
        "bootconfig gate requires a hypervisor"
    );
    let temp = TempDir::new().unwrap();
    let pmi = image(temp.path(), "bootconfig console=hvc0");
    let before = std::fs::read(&pmi).unwrap();
    let input = temp.path().join("input.bconf");
    for text in [
        None,
        Some(""),
        Some("carapace.tip = 'abc'; feature; list = a,b; list += c;"),
        Some(
            "carapace.tip = 'a-much-longer-tip-value-0123456789'; feature; list = a,b; list += c;",
        ),
    ] {
        let extra = if let Some(text) = text {
            std::fs::write(&input, text).unwrap();
            vec!["--bootconfig", input.to_str().unwrap()]
        } else {
            vec![]
        };
        let output = boot_with(&pmi, 512, 1, temp.path(), &extra);
        let report = parse_report(&output).unwrap_or_else(|| panic!("no guest report:\n{output}"));
        let config = report.bootconfig.expect("/proc/bootconfig must exist");
        match text {
            None | Some("") => assert!(config.is_empty(), "{config}"),
            Some(text) => {
                let tip = text.split('\'').nth(1).unwrap();
                assert!(
                    config.contains(&format!("carapace.tip = \"{tip}\"")),
                    "{config}"
                );
                assert!(config.contains("list = \"a\", \"b\", \"c\""), "{config}");
                assert!(config.contains("feature"), "{config}");
            }
        }
        assert!(
            report
                .cmdline
                .split_whitespace()
                .any(|arg| arg == "bootconfig")
        );
        assert_eq!(
            std::fs::read(&pmi).unwrap(),
            before,
            "PMI, DTB and initrd bounds stay unchanged"
        );
    }

    // Invalid syntax is transported intact. Linux reports a parse failure and
    // still boots userspace; neither dillo nor tatu imposes a different policy.
    std::fs::write(&input, "carapace { tip = 'unterminated\n").unwrap();
    let output = boot_with(
        &pmi,
        512,
        1,
        temp.path(),
        &["--bootconfig", input.to_str().unwrap()],
    );
    let report = parse_report(&output).unwrap_or_else(|| panic!("no guest report:\n{output}"));
    assert!(output.contains("Failed to parse bootconfig"), "{output}");
    assert_eq!(report.bootconfig.as_deref(), Some(""));
    assert_eq!(std::fs::read(pmi).unwrap(), before);
}

#[test]
fn bootconfig_input_requires_a_requested_reservation() {
    assert!(
        hypervisor_available(),
        "bootconfig gate requires a hypervisor"
    );
    let temp = TempDir::new().unwrap();
    let pmi = image(temp.path(), "console=hvc0");
    let output = boot(&pmi, 512, 1, temp.path());
    let report = parse_report(&output).unwrap_or_else(|| panic!("no guest report:\n{output}"));
    assert_eq!(report.cmdline, "console=hvc0");
    assert_eq!(report.bootconfig.as_deref(), Some(""));

    let input = temp.path().join("input.bconf");
    std::fs::write(&input, "example.value = supplied;").unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_dillo"))
        .arg("--pmi")
        .arg(pmi)
        .arg("--bootconfig")
        .arg(input)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let error = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        error.contains("--bootconfig supplied without a lbc:bootconfig fill"),
        "{error}"
    );
}
