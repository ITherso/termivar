//! Actual-process acceptance for the opt-in local reconnaissance snapshot import.
//!
//! Imported records are inert, source-qualified hypotheses. This test proves
//! that selecting the import does not alter the ordinary web-review request
//! plan or assessment items, cannot contact an imported listener, and remains
//! readable by offline Verify and Compare.

#![cfg(feature = "recon-snapshot-import")]

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BODY: &str = "<!doctype html><html><body><main>owned recon fixture</main></body></html>";
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
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("join numeric-loopback fixture");
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn serve() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind numeric-loopback fixture");
    listener
        .set_nonblocking(true)
        .expect("make numeric-loopback fixture nonblocking");
    let address: SocketAddr = listener.local_addr().expect("read fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => handle_connection(&mut stream, thread_requests.as_ref()),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                },
                Err(_) => break,
            }
        }
    });
    TestServer {
        url: format!("http://{address}/"),
        requests,
        stop,
        worker: Some(worker),
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

fn write_snapshot(directory: &Path, trap_port: u16, revision: &str) -> (PathBuf, Vec<u8>) {
    let document = json!({
        "schema": "security.recon-snapshot/v1",
        "snapshot_id": "owned-synthetic-snapshot",
        "snapshot_revision": revision,
        "sources": [
            {
                "source_id": "owned-ct",
                "namespace": "owned.fixture.ct",
                "revision": "ct-r1",
                "provider_time": null,
                "observed_time": "2026-09-20T10:30:00Z",
                "collection_method": "owned-offline-fixture",
                "completeness": "partial_as_declared",
                "origin": "</script><script>synthetic_recon_inert()</script>",
                "rights": {
                    "status": "permitted_as_declared",
                    "attribution": "Termivar synthetic test fixture",
                    "notice": null
                }
            },
            {
                "source_id": "owned-history",
                "namespace": "owned.fixture.history",
                "revision": "history-r1",
                "provider_time": "2026-09-19T09:00:00Z",
                "observed_time": "2026-09-20T10:31:00Z",
                "collection_method": "owned-offline-fixture",
                "completeness": "unknown",
                "origin": format!("http://127.0.0.1:{trap_port}/declared-provider-source"),
                "rights": {
                    "status": "permitted_as_declared",
                    "attribution": "Termivar synthetic test fixture",
                    "notice": "Synthetic values are not target authorization"
                }
            }
        ],
        "records": [
            {
                "kind": "ct_name",
                "record_id": "ct-name-1",
                "source_ids": ["owned-ct"],
                "name": "never-contact.invalid"
            },
            {
                "kind": "dns_history",
                "record_id": "dns-history-1",
                "source_ids": ["owned-ct", "owned-history"],
                "name": "historical.invalid",
                "address": "192.0.2.77"
            },
            {
                "kind": "service_banner_product",
                "record_id": "service-1",
                "source_ids": ["owned-history"],
                "host": "127.0.0.1",
                "port": trap_port,
                "transport": "tcp",
                "product": "synthetic-listener",
                "version": null
            },
            {
                "kind": "reputation_label",
                "record_id": "reputation-1",
                "source_ids": ["owned-history"],
                "subject": "never-contact.invalid",
                "label": "synthetic-review-only"
            }
        ]
    });
    let bytes = serde_json::to_vec_pretty(&document).expect("serialize independent fixture");
    let path = directory.join(format!("snapshot-{revision}.json"));
    fs::write(&path, &bytes).expect("write explicit local snapshot");
    (path, bytes)
}

fn write_empty_snapshot(directory: &Path, populated_bytes: &[u8]) -> (PathBuf, Vec<u8>) {
    let mut document: Value =
        serde_json::from_slice(populated_bytes).expect("parse owned populated fixture");
    document["snapshot_revision"] = json!("empty-revision");
    document["records"] = json!([]);
    let bytes = serde_json::to_vec_pretty(&document).expect("serialize empty fixture");
    let path = directory.join("snapshot-empty-revision.json");
    fs::write(&path, &bytes).expect("write explicit empty local snapshot");
    (path, bytes)
}

fn run_scan(server: &TestServer, destination: &Path, snapshot: Option<&Path>) -> Output {
    let mut command = termivar();
    command
        .args(["scan", &server.url, "--profile", "web-review"])
        .arg("--report-dir")
        .arg(destination);
    if let Some(snapshot) = snapshot {
        command.arg("--recon-snapshot").arg(snapshot);
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

fn run_offline_acceptance(
    baseline_directory: &Path,
    selected_directory: &Path,
    selected_assessment: &Value,
) {
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(selected_directory)
        .args(["--format", "json"])
        .output()
        .expect("run Report Verify");
    assert_success(&verify, "Report Verify");
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("parse Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let selected_report = selected_directory.join(JSON_NAME);
    let self_compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&selected_report)
        .arg("--after")
        .arg(&selected_report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run self-Compare");
    assert_success(&self_compare, "self-Compare");
    let self_compare: Value =
        serde_json::from_slice(&self_compare.stdout).expect("parse self-Compare JSON");
    assert_eq!(self_compare["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(self_compare[group], json!([]));
    }
    assert_eq!(
        self_compare["unchanged"].as_array().map(Vec::len),
        selected_assessment["items"].as_array().map(Vec::len)
    );
    let recon = &self_compare["recon_snapshot_import_comparison"];
    assert_eq!(
        recon["schema"],
        "termivar-recon-snapshot-import-comparison/v1"
    );
    assert_eq!(recon["status"], "compared");
    for facet in [
        "methodology",
        "provenance_and_sources",
        "coverage_and_accounting",
        "hypotheses",
    ] {
        assert_eq!(recon[facet]["status"], "unchanged", "facet {facet}");
    }

    let controlled = termivar()
        .args(["report", "compare", "--before"])
        .arg(baseline_directory.join(JSON_NAME))
        .arg("--after")
        .arg(&selected_report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run controlled option-off to option-on Compare");
    assert_success(&controlled, "controlled option-off to option-on Compare");
    let controlled: Value =
        serde_json::from_slice(&controlled.stdout).expect("parse controlled Compare JSON");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(controlled[group], json!([]));
    }
    assert_eq!(
        controlled["unchanged"].as_array().map(Vec::len),
        selected_assessment["items"].as_array().map(Vec::len)
    );
    let recon = &controlled["recon_snapshot_import_comparison"];
    assert_eq!(recon["status"], "not_comparable");
    assert_eq!(recon["reason"], "before_audit_missing");
}

#[test]
fn actual_cli_imports_hypotheses_without_expanding_scan_authority() {
    let parent = tempfile::tempdir().expect("create private acceptance parent");
    let trap = TcpListener::bind("127.0.0.1:0").expect("bind imported-address trap");
    trap.set_nonblocking(true).expect("make trap nonblocking");
    let trap_port = trap.local_addr().expect("read trap address").port();
    let (snapshot, snapshot_bytes) = write_snapshot(parent.path(), trap_port, "revision-1");

    let mut server = serve();
    let baseline_directory = parent.path().join("option-off");
    let baseline = run_scan(&server, &baseline_directory, None);
    assert_success(&baseline, "option-off scan");
    let baseline_assessment = read_bundle(&baseline_directory);
    assert!(baseline_assessment.get("recon_snapshot_import").is_none());
    let baseline_requests = server.requests.lock().expect("baseline trace lock").clone();

    let selected_directory = parent.path().join("option-on");
    let selected = run_scan(&server, &selected_directory, Some(&snapshot));
    assert_success(&selected, "selected scan");
    let assessment = read_bundle(&selected_directory);
    let html = fs::read_to_string(selected_directory.join("assessment.html"))
        .expect("read escaped HTML assessment");
    assert!(!html.contains("<script>synthetic_recon_inert()</script>"));
    assert!(html.contains("&lt;/script&gt;&lt;script&gt;synthetic_recon_inert()&lt;/script&gt;"));

    assert_eq!(
        assessment["subject_count"],
        baseline_assessment["subject_count"]
    );
    assert_eq!(assessment["item_count"], baseline_assessment["item_count"]);
    assert_eq!(
        stable_item_projection(&assessment),
        stable_item_projection(&baseline_assessment),
        "offline recon import changed assessment item semantics"
    );
    let combined_requests = server.requests.lock().expect("selected trace lock").clone();
    assert_eq!(
        combined_requests.get(baseline_requests.len()..),
        Some(baseline_requests.as_slice()),
        "recon import added or replaced a target request"
    );
    assert!(matches!(trap.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));

    let audit = &assessment["recon_snapshot_import"];
    assert_eq!(audit["schema"], "security.recon-snapshot-import-audit/v1");
    assert_eq!(audit["policy"], "termivar.recon-snapshot-import/v1");
    assert_eq!(audit["selected"], true);
    assert_eq!(
        audit["input"]["source_schema"],
        "security.recon-snapshot/v1"
    );
    assert_eq!(audit["input"]["byte_length"], snapshot_bytes.len() as u64);
    assert_eq!(
        audit["input"]["sha256"],
        format!("sha256:{:x}", Sha256::digest(&snapshot_bytes))
    );
    assert_eq!(audit["snapshot"]["id"], "owned-synthetic-snapshot");
    assert_eq!(audit["snapshot"]["revision"], "revision-1");
    assert_eq!(audit["sources"].as_array().map(Vec::len), Some(2));
    assert_eq!(audit["records"].as_array().map(Vec::len), Some(4));
    assert_eq!(audit["accounting"]["source_count"], 2);
    assert_eq!(audit["accounting"]["record_count"], 4);
    assert_eq!(audit["accounting"]["source_association_count"], 5);
    assert_eq!(audit["external_activity"]["target_request_count"], 0);
    assert_eq!(audit["external_activity"]["provider_request_count"], 0);
    assert_eq!(
        audit["external_activity"]["archive_processing"],
        "not_performed"
    );
    assert_eq!(audit["external_activity"]["decompression"], "not_performed");
    assert_eq!(
        audit["claim_limits"]["record_interpretation"],
        "source_qualified_hypotheses_only"
    );
    for field in [
        "source_authentication",
        "asset_ownership",
        "current_reachability",
        "vulnerability",
        "impact",
    ] {
        assert_eq!(audit["claim_limits"][field], "not_established", "{field}");
    }
    assert_eq!(audit["claim_limits"]["scan_authority"], "not_granted");
    let items = serde_json::to_string(&assessment["items"]).expect("serialize item projection");
    for imported in [
        "never-contact.invalid",
        "historical.invalid",
        "192.0.2.77",
        "synthetic-listener",
        "synthetic-review-only",
    ] {
        assert!(
            !items.contains(imported),
            "imported hypothesis leaked into an assessment item: {imported}"
        );
    }

    eprintln!(
        "recon-snapshot-acceptance option_off_requests={} option_on_requests={} import_target_requests=0 import_provider_requests=0 sources=2 records=4 associations=5 input_bytes={} input_sha256=sha256:{:x}",
        baseline_requests.len(),
        combined_requests.len() - baseline_requests.len(),
        snapshot_bytes.len(),
        Sha256::digest(&snapshot_bytes),
    );
    let (empty_snapshot, empty_snapshot_bytes) =
        write_empty_snapshot(parent.path(), &snapshot_bytes);
    let empty_directory = parent.path().join("option-on-empty");
    let requests_before_empty = server.requests.lock().expect("empty trace lock").len();
    let empty = run_scan(&server, &empty_directory, Some(&empty_snapshot));
    assert_success(&empty, "selected empty-snapshot scan");
    let requests_after_empty = server.requests.lock().expect("empty trace lock").clone();
    assert_eq!(
        requests_after_empty.get(requests_before_empty..),
        Some(baseline_requests.as_slice()),
        "selected empty import added or replaced a target request"
    );
    let empty_assessment = read_bundle(&empty_directory);
    assert_eq!(
        empty_assessment["subject_count"], baseline_assessment["subject_count"],
        "selected empty import changed assessment subjects"
    );
    assert_eq!(
        stable_item_projection(&empty_assessment),
        stable_item_projection(&baseline_assessment),
        "selected empty import changed assessment items"
    );
    let empty_audit = &empty_assessment["recon_snapshot_import"];
    assert_eq!(empty_audit["selected"], true);
    assert_eq!(
        empty_audit["input"]["byte_length"],
        empty_snapshot_bytes.len() as u64
    );
    assert_eq!(empty_audit["accounting"]["source_count"], 2);
    assert_eq!(empty_audit["accounting"]["record_count"], 0);
    assert_eq!(empty_audit["accounting"]["source_association_count"], 0);
    assert_eq!(empty_audit["records"], json!([]));
    server.shutdown();
    run_offline_acceptance(&baseline_directory, &selected_directory, &assessment);
    run_offline_acceptance(&baseline_directory, &empty_directory, &empty_assessment);
    assert!(
        matches!(trap.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "scan or offline commands contacted an imported host or declared source"
    );
}

#[test]
fn invalid_and_oversized_snapshots_fail_before_output_or_target_activity() {
    let parent = tempfile::tempdir().expect("create private preflight parent");
    let server = serve();
    let before = server.requests.lock().expect("request trace lock").clone();

    let malformed = parent.path().join("malformed.json");
    fs::write(&malformed, b"{\"schema\":\"security.recon-snapshot/v1\",")
        .expect("write malformed fixture");
    let malformed_output = parent.path().join("malformed-output");
    let output = run_scan(&server, &malformed_output, Some(&malformed));
    assert!(!output.status.success());
    assert!(!malformed_output.exists());
    let malformed_error = String::from_utf8_lossy(&output.stderr);
    assert!(!malformed_error.contains(&malformed.display().to_string()));
    assert!(!malformed_error.contains("security.recon-snapshot/v1"));

    let oversized = parent.path().join("oversized.json");
    fs::write(&oversized, vec![b' '; 1024 * 1024 + 1]).expect("write oversized fixture");
    let oversized_output = parent.path().join("oversized-output");
    let output = run_scan(&server, &oversized_output, Some(&oversized));
    assert!(!output.status.success());
    assert!(!oversized_output.exists());
    let oversized_error = String::from_utf8_lossy(&output.stderr);
    assert!(!oversized_error.contains(&oversized.display().to_string()));

    let directory_source = parent.path().join("directory-source");
    fs::create_dir(&directory_source).expect("create non-regular input");
    let directory_output = parent.path().join("directory-output");
    let output = run_scan(&server, &directory_output, Some(&directory_source));
    assert!(!output.status.success());
    assert!(!directory_output.exists());
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(&directory_source.display().to_string())
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let (target, _) = write_snapshot(parent.path(), 9, "symlink-target");
        let link = parent.path().join("snapshot-link.json");
        symlink(&target, &link).expect("create final-component symlink");
        let link_output = parent.path().join("symlink-output");
        let output = run_scan(&server, &link_output, Some(&link));
        assert!(!output.status.success());
        assert!(!link_output.exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&link.display().to_string()));
    }

    assert_eq!(
        server
            .requests
            .lock()
            .expect("request trace lock")
            .as_slice(),
        before,
        "invalid local input reached the target"
    );
}
