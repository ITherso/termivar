//! Actual-process acceptance for the versioned control-reference mapping.
//!
//! The mapping must consume the immutable composed assessment, add no target or
//! provider activity, preserve every source item byte-for-byte, and remain
//! readable by feature-independent offline report commands.

#![cfg(feature = "control-reference-mapping")]

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use serde_json::Value;

const BODY: &str = "<!doctype html><html><body><main>owned mapping fixture</main></body></html>";
const JSON_NAME: &str = "assessment.json";

fn termivar() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_termivar"));
    command.stdin(Stdio::null());
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(key);
    }
    command.env("NO_PROXY", "127.0.0.1,localhost");
    command.env("no_proxy", "127.0.0.1,localhost");
    command
}

struct TestServer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn serve() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind numeric-loopback fixture");
    let address: SocketAddr = listener.local_addr().expect("read fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            handle_connection(&mut stream, thread_requests.as_ref());
        }
    });

    TestServer {
        url: format!("http://{address}/"),
        requests,
    }
}

fn handle_connection(stream: &mut TcpStream, requests: &Mutex<Vec<String>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0_u8; 16 * 1024];
    let bytes_read = stream.read(&mut buffer).unwrap_or(0);
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    requests
        .lock()
        .expect("request trace lock")
        .push(request.lines().next().unwrap_or_default().to_owned());

    let response = format!(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n\r\n{}"
        ),
        BODY.len(),
        BODY
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn run_scan(server: &TestServer, destination: &Path, selected: bool) -> Output {
    let mut command = termivar();
    command
        .args(["scan", &server.url, "--profile", "web-review"])
        .arg("--report-dir")
        .arg(destination);
    if selected {
        command.arg("--control-reference-mapping");
    }
    command.output().expect("run real Termivar CLI process")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed with {:?}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_bundle(directory: &Path) -> Value {
    let mut names = fs::read_dir(directory)
        .expect("read report bundle")
        .map(|entry| {
            entry
                .expect("read bundle entry")
                .file_name()
                .into_string()
                .expect("fixed report filename is UTF-8")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["assessment.html", JSON_NAME, "manifest.json"]);

    serde_json::from_slice(
        &fs::read(directory.join(JSON_NAME)).expect("read bundled assessment JSON"),
    )
    .expect("parse bundled assessment JSON")
}

fn stable_item_projection(assessment: &Value) -> Vec<Value> {
    let mut items = assessment["items"]
        .as_array()
        .expect("assessment items")
        .clone();
    for item in &mut items {
        let fields = item.as_object_mut().expect("assessment item object");
        for field in [
            "evidence_references",
            "control_evidence_references",
            "candidate_evidence_references",
        ] {
            fields.remove(field);
        }
    }
    items.sort_by(|left, right| {
        left["fingerprint"]
            .as_str()
            .cmp(&right["fingerprint"].as_str())
    });
    items
}

fn assert_item_evidence_references_are_well_formed(assessment: &Value) {
    for item in assessment["items"].as_array().expect("assessment items") {
        let references = item["evidence_references"]
            .as_array()
            .expect("item evidence references");
        assert_eq!(
            item["evidence_count"].as_u64(),
            Some(references.len() as u64),
            "item evidence count does not reconcile"
        );
        let mut unique = BTreeSet::new();
        for reference in references {
            let reference = reference.as_str().expect("evidence reference string");
            assert!(
                reference
                    .strip_prefix("evidence-")
                    .is_some_and(|ordinal| ordinal.len() == 4
                        && ordinal.bytes().all(|byte| byte.is_ascii_digit())),
                "invalid evidence reference shape: {reference}"
            );
            assert!(
                unique.insert(reference),
                "duplicate item evidence reference"
            );
        }
        for field in [
            "control_evidence_references",
            "candidate_evidence_references",
        ] {
            let references = item[field]
                .as_array()
                .expect("typed item evidence reference array");
            assert!(references.iter().all(Value::is_string));
        }
    }
}

fn assert_offline_verify_and_self_compare(
    server: &TestServer,
    directory: &Path,
    assessment: &Value,
) {
    let requests_after_scan = server.requests.lock().expect("request trace lock").clone();

    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"])
        .output()
        .expect("run Report Verify");
    assert_success(&verify, "Report Verify");
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("parse Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let report = directory.join(JSON_NAME);
    let comparison = termivar()
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run self-Compare");
    assert_success(&comparison, "self-Compare");
    let comparison: Value =
        serde_json::from_slice(&comparison.stdout).expect("parse self-Compare JSON");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(comparison[group], serde_json::json!([]));
    }
    assert_eq!(
        comparison["unchanged"].as_array().map(Vec::len),
        assessment["items"].as_array().map(Vec::len)
    );

    assert_eq!(
        server
            .requests
            .lock()
            .expect("request trace lock")
            .as_slice(),
        requests_after_scan,
        "offline Verify/Compare contacted the fixture"
    );
}

fn assert_offline_controlled_compare(
    server: &TestServer,
    baseline_directory: &Path,
    selected_directory: &Path,
    assessment: &Value,
) {
    let requests_before = server.requests.lock().expect("request trace lock").clone();
    let comparison = termivar()
        .args(["report", "compare", "--before"])
        .arg(baseline_directory.join(JSON_NAME))
        .arg("--after")
        .arg(selected_directory.join(JSON_NAME))
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run controlled option-off to option-on Compare");
    assert_success(&comparison, "controlled option-off to option-on Compare");
    let comparison: Value =
        serde_json::from_slice(&comparison.stdout).expect("parse controlled Compare JSON");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(comparison[group], serde_json::json!([]));
    }
    assert_eq!(
        comparison["unchanged"].as_array().map(Vec::len),
        assessment["items"].as_array().map(Vec::len)
    );
    let mapping = &comparison["control_reference_mapping_comparison"];
    assert_eq!(
        mapping["schema"],
        "termivar-control-reference-mapping-comparison/v1"
    );
    assert_eq!(mapping["status"], "not_comparable");
    assert_eq!(mapping["reason"], "before_audit_missing");
    assert_eq!(mapping["methodology"]["status"], "not_comparable");
    assert_eq!(mapping["coverage"]["status"], "not_comparable");
    assert_eq!(mapping["reference_set"]["status"], "not_comparable");
    assert!(mapping["interpretation_limits"]
        .as_array()
        .expect("mapping interpretation limits")
        .iter()
        .any(|value| value.as_str().is_some_and(|value| {
            value.contains("never by themselves prove target change or remediation")
        })));
    assert_eq!(
        server
            .requests
            .lock()
            .expect("request trace lock")
            .as_slice(),
        requests_before,
        "controlled offline Compare contacted the fixture"
    );
}

#[test]
fn actual_cli_maps_composed_items_without_target_or_provider_activity() {
    let parent = tempfile::tempdir().expect("create private report parent");

    let server = serve();
    let baseline_directory = parent.path().join("option-off");
    let baseline = run_scan(&server, &baseline_directory, false);
    assert_success(&baseline, "option-off scan");
    let baseline_assessment = read_bundle(&baseline_directory);
    assert!(baseline_assessment
        .get("control_reference_mapping")
        .is_none());

    let baseline_requests = server.requests.lock().expect("baseline trace lock").clone();
    let selected_directory = parent.path().join("option-on");
    let selected = run_scan(&server, &selected_directory, true);
    assert_success(&selected, "selected scan");
    let assessment = read_bundle(&selected_directory);

    assert_item_evidence_references_are_well_formed(&baseline_assessment);
    assert_item_evidence_references_are_well_formed(&assessment);
    assert_eq!(
        stable_item_projection(&assessment),
        stable_item_projection(&baseline_assessment),
        "control-reference projection changed stable assessment-item semantics"
    );
    assert_eq!(assessment["item_count"], baseline_assessment["item_count"]);

    let audit = &assessment["control_reference_mapping"];
    assert_eq!(
        audit["schema"],
        "security.control-reference-mapping-audit/v1"
    );
    assert_eq!(audit["policy"], "termivar.control-reference-mapping/v1");
    assert_eq!(audit["selected"], true);
    assert_eq!(
        audit["catalogue"]["id"],
        "termivar.reviewed-control-references"
    );
    assert_eq!(audit["catalogue"]["revision"], "2026-09-20.1");
    assert_eq!(audit["sources"].as_array().map(Vec::len), Some(5));
    assert_eq!(audit["external_activity"]["target_request_count"], 0);
    assert_eq!(audit["external_activity"]["provider_request_count"], 0);
    assert_eq!(
        audit["external_activity"]["source_retrieval"],
        "not_performed"
    );
    assert_eq!(audit["claim_limits"]["control_assessment"], "not_performed");
    assert_eq!(audit["claim_limits"]["compliance"], "not_established");
    assert_eq!(audit["claim_limits"]["certification"], "not_established");
    assert_eq!(audit["claim_limits"]["legal_conclusion"], "not_established");
    assert_eq!(
        audit["claim_limits"]["source_authentication"],
        "not_established"
    );

    let source_rows = audit["sources"].as_array().expect("mapping sources");
    let owasp = source_rows
        .iter()
        .find(|row| row["source_id"] == "owasp-top-10-2025")
        .expect("OWASP Top 10:2025 source");
    assert_eq!(owasp["edition"], "2025");
    assert_eq!(
        owasp["mapping_availability"],
        "reviewed_identifiers_and_titles"
    );
    for source_id in ["pci-dss-4.0.1", "iso-iec-27001-2022-amd-1-2024"] {
        let source = source_rows
            .iter()
            .find(|row| row["source_id"] == source_id)
            .expect("rights-deferred bibliographic source");
        assert_eq!(
            source["mapping_availability"],
            "bibliographic_only_rights_deferred"
        );
        assert_eq!(source["rights_basis"], "bibliographic_metadata_only");
    }

    let items = assessment["items"].as_array().expect("assessment items");
    let relationships = audit["relationships"]
        .as_array()
        .expect("mapping relationships");
    assert!(
        !relationships.is_empty(),
        "fixture produced no exact mapping"
    );
    assert_eq!(
        audit["coverage"]["considered_item_count"].as_u64(),
        Some(items.len() as u64)
    );
    assert_eq!(
        audit["coverage"]["relationship_count"].as_u64(),
        Some(relationships.len() as u64)
    );
    assert_eq!(
        audit["coverage"]["mapped_item_count"],
        audit["coverage"]["relationship_count"]
    );
    let mapped_plus_unmapped = audit["coverage"]["mapped_item_count"]
        .as_u64()
        .expect("mapped count")
        + audit["coverage"]["unmapped_item_count"]
            .as_u64()
            .expect("unmapped count");
    assert_eq!(mapped_plus_unmapped, items.len() as u64);
    assert_eq!(audit["coverage"]["omitted_item_count"], 0);
    assert_eq!(audit["coverage"]["omitted_reference_link_count"], 0);

    let mut observed_a02 = false;
    for relationship in relationships {
        let source_item = items
            .iter()
            .find(|item| {
                item["fingerprint"] == relationship["item_fingerprint"]
                    && item["capability_id"] == relationship["capability_id"]
                    && item["cwe"] == relationship["cwe"]
                    && item["claim_basis"] == relationship["item_basis"]
            })
            .expect("mapping relationship links to an immutable source item");
        assert_eq!(source_item["disposition"], "informational");
        for reference in relationship["references"]
            .as_array()
            .expect("relationship references")
        {
            if reference["source_id"] == "owasp-top-10-2025" {
                assert_eq!(reference["edition"], "2025");
                assert_ne!(reference["control_reference"], "A03:2021");
                if reference["control_reference"] == "A02:2025" {
                    observed_a02 = true;
                    assert_eq!(reference["control_title"], "Security Misconfiguration");
                }
            }
        }
    }
    assert!(
        observed_a02,
        "fixture did not exercise OWASP A02:2025 mapping"
    );

    let combined_requests = server.requests.lock().expect("selected trace lock").clone();
    assert_eq!(
        baseline_requests,
        ["GET / HTTP/1.1", "GET / HTTP/1.1", "GET / HTTP/1.1"].map(str::to_owned),
        "option-off ordinary web-review trace changed"
    );
    assert_eq!(
        combined_requests.get(baseline_requests.len()..),
        Some(baseline_requests.as_slice()),
        "offline control mapping added or replaced a target request"
    );

    eprintln!(
        "control-reference-mapping-acceptance option_off_requests={} option_on_requests={} target_requests_added_by_mapping=0 provider_requests_added_by_mapping=0 items={} mapped_items={} relationships={} reference_links={} catalogue_revision={} control_assessment={} compliance={}",
        baseline_requests.len(),
        combined_requests.len() - baseline_requests.len(),
        items.len(),
        audit["coverage"]["mapped_item_count"],
        relationships.len(),
        audit["coverage"]["reference_link_count"],
        audit["catalogue"]["revision"],
        audit["claim_limits"]["control_assessment"],
        audit["claim_limits"]["compliance"],
    );

    assert_offline_verify_and_self_compare(&server, &selected_directory, &assessment);
    assert_offline_controlled_compare(
        &server,
        &baseline_directory,
        &selected_directory,
        &assessment,
    );
}
