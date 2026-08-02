//! Pinned public-API compatibility check for `venom-core`.

use std::{
    io,
    path::Path,
    process::{Command, Output},
};

use super::{run, TaskResult};

const PACKAGE: &str = "venom-core";
const BASELINE_REVISION: &str = "9f65c661028af2d7129caeee640f9b6185c357ca";
const SEMVER_CHECKS_VERSION: &str = "0.50.0";
const INSTALL_COMMAND: &str = "cargo install cargo-semver-checks --version 0.50.0 --locked";

pub(super) fn check(root: &Path) -> TaskResult {
    verify_tool_version()?;
    run(root, "cargo", &check_arguments())
}

fn check_arguments() -> [&'static str; 8] {
    [
        "semver-checks",
        "--package",
        PACKAGE,
        "--baseline-rev",
        BASELINE_REVISION,
        "--release-type",
        "patch",
        "--all-features",
    ]
}

fn verify_tool_version() -> TaskResult {
    let output = match Command::new("cargo-semver-checks")
        .arg("--version")
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(format!(
                "required tool cargo-semver-checks {SEMVER_CHECKS_VERSION} is not installed; run `{INSTALL_COMMAND}`"
            )
            .into());
        },
        Err(error) => return Err(error.into()),
    };

    validate_tool_version(&output)
}

fn validate_tool_version(output: &Output) -> TaskResult {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reported = if stdout.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };

    if !output.status.success() {
        return Err(format!(
            "failed to query cargo-semver-checks version (status {}): {}",
            output.status,
            if reported.is_empty() {
                "no diagnostic output"
            } else {
                reported
            }
        )
        .into());
    }

    let expected = format!("cargo-semver-checks {SEMVER_CHECKS_VERSION}");
    if reported == expected {
        Ok(())
    } else {
        Err(format!(
            "cargo-semver-checks {SEMVER_CHECKS_VERSION} is required, but `{reported}` was found; run `{INSTALL_COMMAND} --force`"
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitStatus;

    use super::*;

    #[cfg(unix)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }

    fn version_output(status: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: exit_status(status),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn command_is_scoped_to_the_pinned_core_patch_baseline() {
        assert_eq!(
            check_arguments(),
            [
                "semver-checks",
                "--package",
                "venom-core",
                "--baseline-rev",
                "9f65c661028af2d7129caeee640f9b6185c357ca",
                "--release-type",
                "patch",
                "--all-features",
            ]
        );
    }

    #[test]
    fn exact_tool_version_is_accepted() {
        let output = version_output(0, "cargo-semver-checks 0.50.0\n", "");
        assert!(validate_tool_version(&output).is_ok());
    }

    #[test]
    fn another_tool_version_reports_the_pinned_install_command() {
        let output = version_output(0, "cargo-semver-checks 0.51.0\n", "");
        let error = validate_tool_version(&output)
            .expect_err("a different version must be rejected")
            .to_string();

        assert!(error.contains("cargo-semver-checks 0.50.0 is required"));
        assert!(error.contains(INSTALL_COMMAND));
        assert!(error.contains("--force"));
    }
}
