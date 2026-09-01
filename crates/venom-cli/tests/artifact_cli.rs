//! Process-level contracts for the non-default, explicit-file artifact adapter.

#![cfg(feature = "artifact-adapter")]

use std::process::{Command, Output};

const LAB_SIGNATURES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../artifact-signatures/lab/venom-canary/signatures.toml"
));
const PATH_SENTINEL: &str = "VENOM-ARTIFACT-CLI-PATH-MUST-NOT-LEAK-123.bin";

fn venom() -> Command {
    Command::new(env!("CARGO_BIN_EXE_venom"))
}

fn write_inputs(
    directory: &std::path::Path,
    artifact: &[u8],
) -> (std::path::PathBuf, std::path::PathBuf) {
    let signatures = directory.join("signatures.toml");
    let input = directory.join(PATH_SENTINEL);
    std::fs::write(&signatures, LAB_SIGNATURES).unwrap();
    std::fs::write(&input, artifact).unwrap();
    (signatures, input)
}

fn scan(signatures: &std::path::Path, input: &std::path::Path, format: &str) -> Output {
    venom()
        .arg("artifact")
        .arg("scan-file")
        .arg("--signatures")
        .arg(signatures)
        .arg("--input")
        .arg(input)
        .arg("--format")
        .arg(format)
        .output()
        .expect("failed to run artifact adapter")
}

#[test]
fn enabled_help_exposes_only_the_explicit_scan_file_shape() {
    let output = venom()
        .args(["artifact", "--help"])
        .output()
        .expect("failed to run artifact help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout
        .lines()
        .any(|line| line.trim_start().starts_with("scan-file ")));
    assert!(!stdout.contains("recursive"));
    assert!(!stdout.contains("process"));
}

#[test]
fn json_scan_reports_observations_without_path_or_matched_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let (signatures, input) = write_inputs(directory.path(), b"prefix-VENOM-CANARY-suffix");
    let before = std::fs::read_dir(directory.path()).unwrap().count();
    let output = scan(&signatures, &input, "json");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "venom.artifact-scan/v1");
    assert_eq!(value["completion"], "complete");
    assert!(value["match_count"]
        .as_u64()
        .is_some_and(|count| count >= 1));

    let rendered = String::from_utf8(output.stdout).unwrap();
    assert!(!rendered.contains(PATH_SENTINEL));
    assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!rendered.contains("VENOM-CANARY"));
    assert!(!rendered.to_ascii_lowercase().contains("vulnerability"));
    assert!(!rendered.to_ascii_lowercase().contains("severity"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), before);
}

#[test]
fn observations_and_no_match_are_both_successful_completions() {
    let match_directory = tempfile::tempdir().unwrap();
    let (match_signatures, match_input) = write_inputs(match_directory.path(), b"AAA");
    let matched = scan(&match_signatures, &match_input, "json");
    assert!(matched.status.success());
    let matched: serde_json::Value = serde_json::from_slice(&matched.stdout).unwrap();
    assert_eq!(matched["match_count"], 2);

    let clear_directory = tempfile::tempdir().unwrap();
    let (clear_signatures, clear_input) = write_inputs(clear_directory.path(), b"no markers here");
    let clear = scan(&clear_signatures, &clear_input, "json");
    assert!(clear.status.success());
    let clear: serde_json::Value = serde_json::from_slice(&clear.stdout).unwrap();
    assert_eq!(clear["completion"], "complete");
    assert_eq!(clear["match_count"], 0);
}

#[test]
fn text_output_is_bounded_and_observation_only() {
    let directory = tempfile::tempdir().unwrap();
    let (signatures, input) = write_inputs(directory.path(), b"VENOM-CANARY");
    let output = scan(&signatures, &input, "text");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.len() < 16_384);
    assert!(stdout.contains("venom.artifact-scan/v1"));
    assert!(!stdout.contains(PATH_SENTINEL));
    assert!(!stdout.contains("VENOM-CANARY"));
    assert!(!stdout.to_ascii_lowercase().contains("malware confirmed"));
}

#[test]
fn directories_and_invalid_manifests_fail_with_sanitized_diagnostics() {
    let directory = tempfile::tempdir().unwrap();
    let (signatures, input) = write_inputs(directory.path(), b"VENOM-CANARY");

    let directory_input = scan(&signatures, directory.path(), "json");
    assert!(!directory_input.status.success());
    let diagnostic = String::from_utf8(directory_input.stderr).unwrap();
    assert!(diagnostic.contains("regular file"));
    assert!(!diagnostic.contains(directory.path().to_string_lossy().as_ref()));

    std::fs::write(&signatures, format!("not = '{PATH_SENTINEL}'")).unwrap();
    let malformed = scan(&signatures, &input, "json");
    assert!(!malformed.status.success());
    let diagnostic = String::from_utf8(malformed.stderr).unwrap();
    assert!(diagnostic.contains("signature manifest is invalid"));
    assert!(!diagnostic.contains(PATH_SENTINEL));
    assert!(malformed.stdout.is_empty());
}

#[test]
fn duplicate_signature_identity_is_rejected_before_scanning() {
    let directory = tempfile::tempdir().unwrap();
    let (signatures, input) = write_inputs(directory.path(), b"VENOM-CANARY");
    let duplicate = r#"

[[signatures]]
id = "venom-canary-exact"
revision = 1
label = "Duplicate identity"
observation_class = "test-canary"
pattern = "42 42"
tags = ["lab"]
description = "A duplicate identity that must fail closed."
"#;
    std::fs::write(&signatures, format!("{LAB_SIGNATURES}{duplicate}")).unwrap();
    let output = scan(&signatures, &input, "json");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("signature manifest is invalid"));
    assert!(!diagnostic.contains("venom-canary-exact"));
}

#[test]
fn input_above_the_default_bound_is_rejected_without_reading_or_reporting_it() {
    let directory = tempfile::tempdir().unwrap();
    let (signatures, input) = write_inputs(directory.path(), b"");
    let input_file = std::fs::OpenOptions::new()
        .write(true)
        .open(&input)
        .unwrap();
    input_file
        .set_len(venom_artifact::DEFAULT_INPUT_BYTES + 1)
        .unwrap();
    drop(input_file);

    let output = scan(&signatures, &input, "json");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("exceeds the configured byte limit"));
    assert!(!diagnostic.contains(PATH_SENTINEL));
}

#[test]
fn match_limit_returns_a_typed_partial_report_and_nonzero_exit() {
    let directory = tempfile::tempdir().unwrap();
    let input_bytes = vec![b'A'; venom_artifact::DEFAULT_MATCHES_PER_SCAN + 2];
    let (signatures, input) = write_inputs(directory.path(), &input_bytes);
    let output = scan(&signatures, &input, "json");
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["completion"], "match-limit-reached");
    assert_eq!(
        report["match_count"],
        venom_artifact::DEFAULT_MATCHES_PER_SCAN
    );
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("stopped before complete input coverage"));
    assert!(!diagnostic.contains(PATH_SENTINEL));
}

#[cfg(unix)]
#[test]
fn symbolic_link_input_is_rejected() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let (signatures, input) = write_inputs(directory.path(), b"VENOM-CANARY");
    let input_link = directory.path().join("linked.bin");
    symlink(&input, &input_link).unwrap();
    let output = scan(&signatures, &input_link, "json");
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("links are rejected"));

    let signature_link = directory.path().join("linked.toml");
    symlink(&signatures, &signature_link).unwrap();
    let output = scan(&signature_link, &input, "json");
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("links are rejected"));
}

#[cfg(windows)]
#[test]
fn symbolic_link_input_is_rejected_when_the_host_allows_creating_one() {
    use std::os::windows::fs::symlink_file;

    let directory = tempfile::tempdir().unwrap();
    let (signatures, input) = write_inputs(directory.path(), b"VENOM-CANARY");
    let input_link = directory.path().join("linked.bin");
    if symlink_file(&input, &input_link).is_err() {
        return;
    }
    let output = scan(&signatures, &input_link, "json");
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("links are rejected"));
}
