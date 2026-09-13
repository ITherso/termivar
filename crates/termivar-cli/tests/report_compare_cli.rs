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

fn synthetic_supplied_session_audit_v1() -> Value {
    json!({
        "schema": "security.supplied-session-audit/v1",
        "capability_id": "session.supplied-context-assessment@1",
        "policy_reference": format!("supplied-session-policy-sha256:{}", "1".repeat(64)),
        "application_reference": format!(
            "supplied-session-application-sha256:{}",
            "2".repeat(64)
        ),
        "principal_reference": "supplied-session-principal-0001",
        "principal_alias": "synthetic-reader",
        "principal_assurance": "operator_declared",
        "credential_mechanism": "authorization_header",
        "health_oracle": {
            "kind": "json_boolean_true",
            "field_reference": format!(
                "supplied-session-health-field-sha256:{}",
                "3".repeat(64)
            )
        },
        "outcome": "complete",
        "coverage": "complete",
        "checkpoints": [
            {
                "sequence": 0,
                "phase": "startup",
                "after_subject_count": 0,
                "evidence_reference": format!(
                    "supplied-session-checkpoint-evidence-sha256:{}",
                    "4".repeat(64)
                ),
                "outcome": "healthy",
                "status": 200,
                "body_state": "complete",
                "predicate": "matched",
                "response_bytes": 17
            },
            {
                "sequence": 1,
                "phase": "terminal",
                "after_subject_count": 1,
                "evidence_reference": format!(
                    "supplied-session-checkpoint-evidence-sha256:{}",
                    "5".repeat(64)
                ),
                "outcome": "healthy",
                "status": 200,
                "body_state": "complete",
                "predicate": "matched",
                "response_bytes": 19
            }
        ],
        "resources": [{
            "sequence": 0,
            "resource_reference": format!(
                "supplied-session-resource-sha256:{}",
                "6".repeat(64)
            ),
            "evidence_reference": format!(
                "supplied-session-resource-evidence-sha256:{}",
                "7".repeat(64)
            ),
            "outcome": "committed",
            "status": 200,
            "response_bytes": 23,
            "epoch": 1
        }],
        "selected_resource_count": 1,
        "dispatched_resource_count": 1,
        "committed_resource_count": 1,
        "dispatched_request_count": 3,
        "response_bytes": 59,
        "response_byte_limit": 65_536,
        "response_byte_limit_exceeded": false,
        "refresh_performed": false,
        "anonymous_fallback_performed": false,
        "continuous_authentication_established": false,
        "exploit_execution": "not_performed",
        "impact_validation": "not_performed"
    })
}

fn synthetic_supplied_session_audit_v2() -> Value {
    let mut audit = synthetic_supplied_session_audit_v1();
    audit["schema"] = json!("security.supplied-session-audit/v2");
    audit["credential_mechanism"] = json!("cookie_jar");
    audit["cookie_policy"] = json!({
        "declared_count": 2,
        "host_only_count": 1,
        "domain_count": 1,
        "secure_count": 2,
        "http_only_count": 1,
        "session_count": 1,
        "persistent_count": 1,
        "same_site_missing_count": 0,
        "same_site_strict_count": 1,
        "same_site_lax_count": 0,
        "same_site_none_count": 1,
        "update_policy": "stop_on_selected_cookie",
        "browser_semantics": "attributes_preserved_not_browser_csrf_emulation"
    });
    audit["cookie_lifecycle"] = json!({
        "initial_epoch": 1,
        "final_epoch": 1,
        "selected_update_response_count": 0,
        "unselected_update_response_count": 1,
        "update_classification_failure_count": 0,
        "updates_applied": 0
    });
    audit
}

fn synthetic_supplied_session_report(audit: Value) -> Vec<u8> {
    let mut report: Value = serde_json::from_slice(&synthetic_report(vec![synthetic_item(
        '8',
        "Synthetic context-stable observation",
        "evidence-0008",
    )]))
    .unwrap();
    report["supplied_session"] = audit;
    serde_json::to_vec(&report).unwrap()
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
fn default_binary_compares_cookie_v2_and_keeps_v1_v2_contexts_unpaired_offline() {
    let directory = tempfile::tempdir().unwrap();
    let v1_bytes = synthetic_supplied_session_report(synthetic_supplied_session_audit_v1());
    let v2_bytes = synthetic_supplied_session_report(synthetic_supplied_session_audit_v2());
    let v1 = directory.path().join("synthetic-v1.json");
    let v2 = directory.path().join("synthetic-v2.json");
    fs::write(&v1, &v1_bytes).unwrap();
    fs::write(&v2, &v2_bytes).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());

    let mut self_compare = termivar();
    let self_compare = self_compare
        .args(["report", "compare", "--before"])
        .arg(&v2)
        .arg("--after")
        .arg(&v2)
        .args(["--same-scope", "--format", "json"])
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert!(
        self_compare.status.success(),
        "{}",
        String::from_utf8_lossy(&self_compare.stderr)
    );
    assert!(self_compare.stderr.is_empty());
    let self_document: Value = serde_json::from_slice(&self_compare.stdout).unwrap();
    assert_eq!(
        self_document["before"]["optional_audits"]["supplied_session"]["schema"],
        "security.supplied-session-audit/v2"
    );
    assert_eq!(
        self_document["before"]["optional_audits"]["supplied_session"]["cookie_policy"]
            ["declared_count"],
        2
    );
    assert_eq!(
        self_document["supplied_session_comparison"]["status"],
        "compared_within_same_declared_context"
    );
    assert_eq!(
        self_document["supplied_session_comparison"]["context"]["status"],
        "same_declared_context"
    );
    assert_eq!(
        self_document["supplied_session_comparison"]["health_and_coverage"]["status"],
        "unchanged"
    );
    assert_eq!(self_document["unchanged"].as_array().unwrap().len(), 1);
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(self_document[group].as_array().unwrap().is_empty());
    }

    let mut cross_version = termivar();
    let cross_version = cross_version
        .args(["report", "compare", "--before"])
        .arg(&v1)
        .arg("--after")
        .arg(&v2)
        .args(["--same-scope", "--format", "json"])
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert!(
        cross_version.status.success(),
        "{}",
        String::from_utf8_lossy(&cross_version.stderr)
    );
    assert!(cross_version.stderr.is_empty());
    let cross_document: Value = serde_json::from_slice(&cross_version.stdout).unwrap();
    assert_eq!(
        cross_document["supplied_session_comparison"]["status"],
        "not_compared"
    );
    assert_eq!(
        cross_document["supplied_session_comparison"]["reason"],
        "declared_session_context_changed"
    );
    assert_eq!(
        cross_document["supplied_session_comparison"]["context"]["changed_fields"],
        json!(["cookie_policy", "credential_mechanism", "schema"])
    );
    for facet in ["health_and_coverage", "accounting"] {
        assert_eq!(
            cross_document["supplied_session_comparison"][facet]["status"],
            "not_comparable"
        );
    }
    assert_eq!(
        cross_document["only_in_before"].as_array().unwrap().len(),
        1
    );
    assert_eq!(cross_document["only_in_after"].as_array().unwrap().len(), 1);
    assert_eq!(
        cross_document["only_in_before"][0]["fingerprint"],
        cross_document["only_in_after"][0]["fingerprint"]
    );
    for group in ["changed", "unchanged"] {
        assert!(cross_document[group].as_array().unwrap().is_empty());
    }

    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "feature-disabled offline comparison contacted the proxy tripwire"
    );
    assert_eq!(fs::read(&v1).unwrap(), v1_bytes);
    assert_eq!(fs::read(&v2).unwrap(), v2_bytes);
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
