//! Actual-process contracts for offline report-bundle verification.
//!
//! Tests copy the committed bundle before every mutation. Neither verification
//! nor comparison may change the supplied bytes or contact a network endpoint.

use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const HTML_NAME: &str = "assessment.html";
const JSON_NAME: &str = "assessment.json";
const MANIFEST_NAME: &str = "manifest.json";
const FILES: [&str; 3] = [HTML_NAME, JSON_NAME, MANIFEST_NAME];
const REFERENCE_BUNDLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/examples/report-bundle/assessment-001"
);

fn termivar() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_termivar"));
    command.stdin(Stdio::null());
    command
}

fn copy_reference_bundle(parent: &Path, name: &str) -> PathBuf {
    let destination = parent.join(name);
    fs::create_dir(&destination).expect("create private bundle copy");
    for file in FILES {
        fs::copy(
            Path::new(REFERENCE_BUNDLE).join(file),
            destination.join(file),
        )
        .expect("copy committed bundle payload");
    }
    destination
}

fn snapshot(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(directory).expect("enumerate bundle copy") {
        let entry = entry.expect("read bundle entry");
        let name = entry
            .file_name()
            .into_string()
            .expect("test bundle filenames are UTF-8");
        result.insert(
            name,
            fs::read(entry.path()).expect("read bundle entry bytes"),
        );
    }
    result
}

fn verify(directory: &Path, format: Option<&str>) -> Output {
    let mut command = termivar();
    command.args(["report", "verify", "--dir"]).arg(directory);
    if let Some(format) = format {
        command.args(["--format", format]);
    }
    command.output().expect("run report verifier")
}

fn parse_single_json(bytes: &[u8], context: &str) -> Value {
    let mut values = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
    let value = values
        .next()
        .unwrap_or_else(|| panic!("{context} emitted no JSON"))
        .unwrap_or_else(|error| panic!("{context} emitted invalid JSON: {error}"));
    assert!(
        values.next().is_none(),
        "{context} emitted more than one JSON value"
    );
    value
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn rewrite_html_manifest(directory: &Path, html: &[u8]) {
    fs::write(directory.join(HTML_NAME), html).expect("write modified HTML fixture");
    let manifest_path = directory.join(MANIFEST_NAME);
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse committed manifest");
    let entry = manifest["files"]
        .as_array_mut()
        .expect("manifest files")
        .iter_mut()
        .find(|entry| entry["name"] == HTML_NAME)
        .expect("HTML manifest entry");
    entry["byte_length"] = json!(html.len() as u64);
    entry["sha256"] = json!(sha256(html));
    let mut bytes = serde_json::to_vec_pretty(&manifest).expect("encode modified manifest");
    bytes.push(b'\n');
    fs::write(manifest_path, bytes).expect("write modified manifest fixture");
}

fn rewrite_json_manifest(directory: &Path, json_bytes: &[u8]) {
    fs::write(directory.join(JSON_NAME), json_bytes).expect("write modified JSON fixture");
    let manifest_path = directory.join(MANIFEST_NAME);
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse committed manifest");
    let entry = manifest["files"]
        .as_array_mut()
        .expect("manifest files")
        .iter_mut()
        .find(|entry| entry["name"] == JSON_NAME)
        .expect("JSON manifest entry");
    entry["byte_length"] = json!(json_bytes.len() as u64);
    entry["sha256"] = json!(sha256(json_bytes));
    manifest["producer"]["version"] = json!(env!("CARGO_PKG_VERSION"));
    let mut bytes = serde_json::to_vec_pretty(&manifest).expect("encode modified manifest");
    bytes.push(b'\n');
    fs::write(manifest_path, bytes).expect("write modified manifest fixture");
}

fn synthetic_cookie_supplied_session_audit_v2() -> Value {
    json!({
        "schema": "security.supplied-session-audit/v2",
        "capability_id": "session.supplied-context-assessment@1",
        "policy_reference": format!("supplied-session-policy-sha256:{}", "1".repeat(64)),
        "application_reference": format!(
            "supplied-session-application-sha256:{}",
            "2".repeat(64)
        ),
        "principal_reference": "supplied-session-principal-0001",
        "principal_alias": "synthetic-reader",
        "principal_assurance": "operator_declared",
        "credential_mechanism": "cookie_jar",
        "cookie_policy": {
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
        },
        "cookie_lifecycle": {
            "initial_epoch": 1,
            "final_epoch": 1,
            "selected_update_response_count": 0,
            "unselected_update_response_count": 1,
            "update_classification_failure_count": 0,
            "updates_applied": 0
        },
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

#[test]
fn reference_bundle_verifies_as_text_and_json_without_modification() {
    let temporary = tempfile::tempdir().expect("create private test directory");
    let bundle = copy_reference_bundle(temporary.path(), "reference");
    let before = snapshot(&bundle);

    let text = verify(&bundle, None);
    assert!(
        text.status.success(),
        "text verification failed: {}",
        String::from_utf8_lossy(&text.stderr)
    );
    assert!(text.stderr.is_empty());
    let text = String::from_utf8(text.stdout).expect("text output is UTF-8");
    assert!(text.contains("Termivar report bundle verification"));
    assert!(text.contains("status: integrity_match"));
    assert!(text.contains("layout: checked_matched"));
    assert!(text.contains("assessment_document: checked_matched"));
    assert!(text.contains("producer/source authenticity: not established"));

    let json = verify(&bundle, Some("json"));
    assert!(
        json.status.success(),
        "JSON verification failed: {}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(
        json.stderr.is_empty(),
        "JSON success must not append an unstructured diagnostic"
    );
    let document = parse_single_json(&json.stdout, "JSON verification");
    assert_eq!(document["schema"], "termivar-report-verification/v1");
    assert_eq!(document["status"], "integrity_match");
    assert_eq!(document["reason_codes"], json!([]));
    assert_eq!(document["checks"]["layout"], "checked_matched");
    assert_eq!(document["checks"]["manifest"], "checked_matched");
    assert_eq!(
        document["checks"]["assessment_html"]["state"],
        "checked_matched"
    );
    assert_eq!(
        document["checks"]["assessment_json"]["state"],
        "checked_matched"
    );
    assert_eq!(document["checks"]["assessment_document"], "checked_matched");
    assert_eq!(document["checks"]["assessment_summary"], "checked_matched");
    assert_eq!(
        document["trust"]["producer_source_authenticity"],
        "not_established"
    );
    assert_eq!(snapshot(&bundle), before, "verification must be read-only");
}

#[test]
fn same_length_payload_mutation_is_a_digest_mismatch_and_json_stays_clean() {
    let temporary = tempfile::tempdir().expect("create private test directory");
    let bundle = copy_reference_bundle(temporary.path(), "mismatch");
    let html_path = bundle.join(HTML_NAME);
    let mut html = fs::read(&html_path).expect("read HTML fixture");
    assert_eq!(html[1], b'!');
    html[1] = b'?';
    fs::write(&html_path, &html).expect("write same-length mutation");
    let modified = snapshot(&bundle);

    let output = verify(&bundle, Some("json"));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "ordinary JSON verification failure must stay in the JSON document"
    );
    let document = parse_single_json(&output.stdout, "mismatch verification");
    assert_eq!(document["status"], "not_verified");
    assert!(document["reason_codes"]
        .as_array()
        .unwrap()
        .contains(&json!("payload_digest_mismatch")));
    assert!(!document["reason_codes"]
        .as_array()
        .unwrap()
        .contains(&json!("payload_length_mismatch")));
    let check = &document["checks"]["assessment_html"];
    assert_eq!(check["state"], "checked_mismatched");
    assert_eq!(check["expected_byte_length"], check["observed_byte_length"]);
    assert_ne!(check["expected_sha256"], check["observed_sha256"]);
    assert_eq!(
        snapshot(&bundle),
        modified,
        "verifier must not repair files"
    );
}

#[test]
fn missing_manifest_leaves_dependent_checks_not_checked() {
    let temporary = tempfile::tempdir().expect("create private test directory");
    let bundle = copy_reference_bundle(temporary.path(), "incomplete");
    fs::remove_file(bundle.join(MANIFEST_NAME)).expect("remove manifest from test copy");
    let before = snapshot(&bundle);

    let output = verify(&bundle, Some("json"));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let document = parse_single_json(&output.stdout, "missing-manifest verification");
    assert_eq!(document["status"], "not_verified");
    assert!(document["reason_codes"]
        .as_array()
        .unwrap()
        .contains(&json!("missing_manifest")));
    assert_eq!(document["checks"]["layout"], "checked_mismatched");
    assert_eq!(document["checks"]["manifest"], "not_checked");
    assert_eq!(
        document["checks"]["assessment_html"]["state"],
        "not_checked"
    );
    assert_eq!(
        document["checks"]["assessment_json"]["state"],
        "not_checked"
    );
    assert_eq!(document["checks"]["assessment_document"], "not_checked");
    assert_eq!(document["checks"]["assessment_summary"], "not_checked");
    assert_eq!(snapshot(&bundle), before);
}

#[test]
fn verify_usage_errors_keep_the_clap_exit_two_contract() {
    for arguments in [
        vec!["report", "verify"],
        vec!["report", "verify", "--dir", "bundle", "--format", "html"],
        vec![
            "report", "verify", "--dir", "bundle", "--output", "out.json",
        ],
    ] {
        let output = termivar()
            .args(arguments)
            .output()
            .expect("run invalid verifier invocation");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn verify_help_exposes_only_the_closed_offline_interface() {
    let report = termivar()
        .args(["report", "--help"])
        .output()
        .expect("run report help");
    assert!(report.status.success());
    assert!(report.stderr.is_empty());
    let report = String::from_utf8(report.stdout).expect("report help is UTF-8");
    assert!(report.contains("Inspect saved assessment reports offline; no scan is performed"));
    assert!(report.contains("compare"));
    assert!(report.contains("verify"));

    let verify = termivar()
        .args(["report", "verify", "--help"])
        .output()
        .expect("run verifier help");
    assert!(verify.status.success());
    assert!(verify.stderr.is_empty());
    let verify = String::from_utf8(verify.stdout).expect("verifier help is UTF-8");
    assert!(verify.contains("--dir <DIRECTORY>"));
    assert!(verify.contains("[possible values: text, json]"));
    for forbidden in [
        "--output",
        "--repair",
        "--recursive",
        "--same-scope",
        "--watch",
    ] {
        assert!(
            !verify.contains(forbidden),
            "unexpected verifier option {forbidden}"
        );
    }
}

#[test]
fn consistently_rehashed_modified_bundle_matches_without_authenticating_source() {
    let temporary = tempfile::tempdir().expect("create private test directory");
    let bundle = copy_reference_bundle(temporary.path(), "rehashed");
    let mut html = fs::read(bundle.join(HTML_NAME)).expect("read HTML fixture");
    html.extend_from_slice(b"\n<!-- inert externally edited test marker -->\n");
    rewrite_html_manifest(&bundle, &html);
    let modified = snapshot(&bundle);

    let output = verify(&bundle, Some("json"));
    assert!(
        output.status.success(),
        "internally consistent modified bundle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document = parse_single_json(&output.stdout, "rehashed verification");
    assert_eq!(document["status"], "integrity_match");
    assert_eq!(
        document["trust"]["producer_source_authenticity"],
        "not_established"
    );
    assert_eq!(
        document["trust"]["html_content_equivalence_or_executable_safety"],
        "not_established"
    );
    assert_eq!(snapshot(&bundle), modified);
}

#[test]
fn verify_and_compare_remain_offline_and_comparison_compatible() {
    let temporary = tempfile::tempdir().expect("create private test directory");
    let bundle = copy_reference_bundle(temporary.path(), "offline");
    let before = snapshot(&bundle);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind network tripwire");
    listener
        .set_nonblocking(true)
        .expect("make network tripwire nonblocking");
    let proxy = format!("http://{}", listener.local_addr().unwrap());

    let mut verification = termivar();
    verification
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    let verification = verification.output().expect("run offline verification");
    assert!(verification.status.success());

    let json_path = bundle.join(JSON_NAME);
    let mut comparison = termivar();
    comparison
        .args(["report", "compare", "--before"])
        .arg(&json_path)
        .arg("--after")
        .arg(&json_path)
        .args(["--same-scope", "--format", "json"])
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    let comparison = comparison.output().expect("run offline comparison");
    assert!(
        comparison.status.success(),
        "comparison failed: {}",
        String::from_utf8_lossy(&comparison.stderr)
    );
    assert!(comparison.stderr.is_empty());
    let document = parse_single_json(&comparison.stdout, "offline comparison");
    assert_eq!(document["schema"], "termivar-report-comparison/v1");
    assert_eq!(document["unchanged"].as_array().unwrap().len(), 4);
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(document[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "offline report commands must not contact the configured proxy tripwire"
    );
    assert_eq!(snapshot(&bundle), before);
}

#[test]
fn default_binary_verifies_a_cookie_v2_bundle_without_feature_or_network_authority() {
    let temporary = tempfile::tempdir().expect("create private test directory");
    let bundle = copy_reference_bundle(temporary.path(), "cookie-v2");
    let json_path = bundle.join(JSON_NAME);
    let mut assessment: Value =
        serde_json::from_slice(&fs::read(&json_path).expect("read assessment fixture"))
            .expect("parse assessment fixture");
    assessment["supplied_session"] = synthetic_cookie_supplied_session_audit_v2();
    let assessment_bytes = serde_json::to_vec(&assessment).expect("encode synthetic assessment");
    rewrite_json_manifest(&bundle, &assessment_bytes);
    let before = snapshot(&bundle);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind network tripwire");
    listener
        .set_nonblocking(true)
        .expect("make network tripwire nonblocking");
    let proxy = format!("http://{}", listener.local_addr().unwrap());

    let mut command = termivar();
    let output = command
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("verify synthetic cookie-v2 bundle");
    assert!(
        output.status.success(),
        "cookie-v2 verification failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document = parse_single_json(&output.stdout, "cookie-v2 verification");
    assert_eq!(document["schema"], "termivar-report-verification/v1");
    assert_eq!(document["status"], "integrity_match");
    assert_eq!(document["checks"]["assessment_document"], "checked_matched");
    assert_eq!(document["checks"]["assessment_summary"], "checked_matched");
    assert_eq!(document["manifest"]["item_count"], 4);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "feature-disabled report verification contacted the proxy tripwire"
    );
    assert_eq!(
        snapshot(&bundle),
        before,
        "verification must remain read-only"
    );
}
