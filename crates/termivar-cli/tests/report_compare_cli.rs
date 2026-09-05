//! Actual-process checks for offline comparison. Synthetic document variants
//! are test data, not scan evidence; the genuine first-use capture is read-only.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use serde_json::{json, Value};

const GENUINE_REPORT: &[u8] = include_bytes!("../../../docs/examples/first-use/assessment.json");

fn termivar() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_termivar"));
    command.stdin(Stdio::null());
    // Child-local unusable proxy settings must be irrelevant to this offline
    // path; no listener, target URL, credentials, or network fixture is needed.
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(key, "not-a-valid-proxy-url");
    }
    command
}

fn compare(before: &Path, after: &Path, format: Option<&str>, output: Option<&Path>) -> Output {
    let mut command = termivar();
    command
        .args(["report", "compare", "--before"])
        .arg(before)
        .arg("--after")
        .arg(after)
        .arg("--same-scope");
    if let Some(format) = format {
        command.args(["--format", format]);
    }
    if let Some(output) = output {
        command.arg("--output").arg(output);
    }
    command.output().unwrap()
}

fn synthetic_item(identity: char, title: &str, evidence: &str) -> Value {
    json!({
        "schema": "venom-assessment-item/v1",
        "capability_id": format!("synthetic.display.{identity}@1"),
        "subject_reference": "subject-0000",
        "title": title,
        "disposition": "informational",
        "claim_basis": "observation",
        "severity": null,
        "confidence_ppm": 1_000_000,
        "fingerprint": format!("sha256:{}", identity.to_string().repeat(64)),
        "evidence_count": 1,
        "redacted_summary": "Synthetic comparison fixture; not a scan observation.",
        "category": "synthetic-display",
        "cwe": null,
        "remediation": {"id": "synthetic.display@1", "summary": "No security conclusion is supported by this fixture."},
        "evidence_references": [evidence],
        "control_evidence_references": [],
        "candidate_evidence_references": [],
        "case_reference": null,
        "outcome_reference": null,
        "verification_stage": null
    })
}

fn synthetic_report(items: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "venom-rendered-assessment/v1",
        "source_schema": "venom-assessment-run/v1",
        "run_schema": "venom-run/v1",
        "profile_schema": "venom.scan-profile/v1",
        "profile": "web-review",
        "status": "complete",
        "subject_count": 1,
        "item_count": items.len(),
        "items": items
    }))
    .unwrap()
}

fn synthetic_pair(directory: &Path) -> (PathBuf, PathBuf, Vec<u8>, Vec<u8>) {
    let before = synthetic_report(vec![
        synthetic_item('1', "Same display", "evidence-0000"),
        synthetic_item('2', "Earlier display", "evidence-0001"),
        synthetic_item('3', "Only in earlier input", "evidence-0002"),
    ]);
    let after = synthetic_report(vec![
        synthetic_item('4', "Only in later input", "evidence-0042"),
        synthetic_item('2', "Later display", "evidence-0041"),
        synthetic_item('1', "Same display", "evidence-0040"),
    ]);
    let before_path = directory.join("PRIVATE-before.json");
    let after_path = directory.join("PRIVATE-after.json");
    fs::write(&before_path, &before).unwrap();
    fs::write(&after_path, &after).unwrap();
    (before_path, after_path, before, after)
}

fn assert_refused(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!error.is_empty());
    assert!(!error.contains("PRIVATE"), "{error}");
    assert!(!error.contains("deterministic scan"), "{error}");
}

#[test]
fn actual_cli_markdown_and_json_have_independent_exact_group_counts() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, before_bytes, after_bytes) = synthetic_pair(directory.path());
    let markdown = compare(&before, &after, None, None);
    assert!(
        markdown.status.success(),
        "{}",
        String::from_utf8_lossy(&markdown.stderr)
    );
    assert!(markdown.stderr.is_empty());
    let markdown = String::from_utf8(markdown.stdout).unwrap();
    assert!(markdown.starts_with("# Offline report comparison\n"));
    for group in ["only_in_after", "only_in_before", "changed", "unchanged"] {
        assert!(markdown.contains(&format!("## {group} (1)")), "{markdown}");
    }
    let json_output = compare(&before, &after, Some("json"), None);
    assert!(
        json_output.status.success(),
        "{}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    assert!(json_output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(document["schema"], "termivar-report-comparison/v1");
    assert_eq!(document["scope_assurance"], "operator-declared");
    assert_eq!(document["coverage_equivalence"], "not-established");
    for (group, identity) in [
        ("only_in_after", '4'),
        ("only_in_before", '3'),
        ("changed", '2'),
        ("unchanged", '1'),
    ] {
        let items = document[group].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0]["fingerprint"],
            format!("sha256:{}", identity.to_string().repeat(64))
        );
    }
    assert_eq!(document["changed"][0]["changed_fields"], json!(["title"]));
    let repeated = compare(&before, &after, Some("json"), None);
    assert!(repeated.status.success());
    assert_eq!(repeated.stdout, json_output.stdout);
    // Exact byte equality is stronger than checking only the input hashes.
    assert_eq!(fs::read(before).unwrap(), before_bytes);
    assert_eq!(fs::read(after).unwrap(), after_bytes);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn actual_cli_html_file_is_complete_and_existing_output_is_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, before_bytes, after_bytes) = synthetic_pair(directory.path());
    let destination = directory.path().join("comparison.html");
    let result = compare(&before, &after, Some("html"), Some(&destination));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
    let html = fs::read(&destination).unwrap();
    let text = std::str::from_utf8(&html).unwrap().to_ascii_lowercase();
    assert!(text.starts_with("<!doctype html>"));
    assert!(text.trim_end().ends_with("</html>"));
    assert!(text.contains("operator-declared"));
    assert_refused(&compare(&before, &after, Some("html"), Some(&destination)));
    assert_eq!(fs::read(destination).unwrap(), html);
    assert_eq!(fs::read(before).unwrap(), before_bytes);
    assert_eq!(fs::read(after).unwrap(), after_bytes);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}

#[test]
fn actual_cli_same_file_accepts_genuine_capture_without_modifying_it() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("genuine-copy.json");
    fs::write(&input, GENUINE_REPORT).unwrap();
    let result = compare(&input, &input, Some("json"), None);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let document: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(document["unchanged"].as_array().unwrap().len(), 4);
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(document[group].as_array().unwrap().is_empty());
    }
    assert_eq!(document["before"]["sha256"], document["after"]["sha256"]);
    assert_eq!(fs::read(input).unwrap(), GENUINE_REPORT);
}

#[test]
fn actual_cli_refuses_input_output_collisions_and_creates_no_partial_failure_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, before_bytes, after_bytes) = synthetic_pair(directory.path());
    for collision in [&before, &after] {
        assert_refused(&compare(&before, &after, Some("json"), Some(collision)));
    }
    assert_eq!(fs::read(&before).unwrap(), before_bytes);
    assert_eq!(fs::read(&after).unwrap(), after_bytes);
    let alias = directory.path().join("input-hard-link.json");
    fs::hard_link(&before, &alias).unwrap();
    assert_refused(&compare(&before, &after, Some("json"), Some(&alias)));
    assert_eq!(fs::read(&alias).unwrap(), before_bytes);
    fs::write(&after, b"PRIVATE-MALFORMED-DOCUMENT").unwrap();
    let output = directory.path().join("must-not-exist.html");
    for format in ["markdown", "json", "html"] {
        assert_refused(&compare(&before, &after, Some(format), None));
        assert_refused(&compare(&before, &after, Some(format), Some(&output)));
        assert!(!output.exists());
    }
    assert_eq!(fs::read(&before).unwrap(), before_bytes);
    assert_eq!(fs::read(&after).unwrap(), b"PRIVATE-MALFORMED-DOCUMENT");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}

#[test]
fn actual_cli_rejects_nonfiles_urls_stdin_and_oversized_inputs_without_path_disclosure() {
    let directory = tempfile::tempdir().unwrap();
    let (before, _, before_bytes, _) = synthetic_pair(directory.path());
    let oversized = directory.path().join("PRIVATE-oversized.json");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    for invalid in [
        directory.path().to_owned(),
        directory.path().join("PRIVATE-missing.json"),
        oversized,
        PathBuf::from("https://example.test/PRIVATE"),
        PathBuf::from("file:/PRIVATE"),
        PathBuf::from("-"),
    ] {
        assert_refused(&compare(&before, &invalid, None, None));
        assert_refused(&compare(&invalid, &before, None, None));
    }
    assert_eq!(fs::read(before).unwrap(), before_bytes);
}

#[cfg(unix)]
#[test]
fn actual_cli_rejects_symlink_inputs_and_symlink_output_collisions() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, before_bytes, _) = synthetic_pair(directory.path());
    let link = directory.path().join("PRIVATE-link.json");
    std::os::unix::fs::symlink(&before, &link).unwrap();
    assert_refused(&compare(&link, &after, None, None));
    assert_refused(&compare(&before, &after, Some("json"), Some(&link)));
    assert_eq!(fs::read(before).unwrap(), before_bytes);
}

#[cfg(windows)]
#[test]
fn actual_cli_rejects_reparse_inputs_and_outputs_without_symlink_privilege() {
    let directory = tempfile::tempdir().unwrap();
    let (before, after, before_bytes, _) = synthetic_pair(directory.path());
    let destination = directory.path().join("destination");
    let link = directory.path().join("PRIVATE-link");
    fs::create_dir(&destination).unwrap();
    let result = Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&link)
        .arg(&destination)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(result.success(), "Windows junction fixture creation failed");
    assert_refused(&compare(&link, &after, None, None));
    assert_refused(&compare(&before, &after, Some("json"), Some(&link)));
    assert_eq!(fs::read(before).unwrap(), before_bytes);
}

#[test]
fn actual_cli_help_explains_offline_assertion_and_requires_two_paths() {
    let help = termivar().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout).unwrap().contains("report"));
    let help = termivar()
        .args(["report", "compare", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for marker in [
        "--before",
        "--after",
        "--same-scope",
        "--format",
        "--output",
        "not machine-verified",
    ] {
        assert!(help.contains(marker), "{help}");
    }
    for args in [
        vec!["report", "compare"],
        vec![
            "report", "compare", "--before", "a.json", "--after", "b.json",
        ],
        vec!["report", "compare", "--before", "a.json", "--same-scope"],
    ] {
        assert_refused(&termivar().args(args).output().unwrap());
    }
}
