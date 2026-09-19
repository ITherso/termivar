//! Actual-process acceptance for passive response secret-exposure review.
//!
//! The synthetic value below is served only by a test-owned numeric-loopback
//! fixture. The feature must reuse the ordinary web-review responses, add no
//! request, retain no matched value, and remain readable by the offline report
//! commands after the fixture has stopped being relevant.

#![cfg(feature = "secret-exposure-review")]

use std::{
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

const SYNTHETIC_SECRET: &str = "sk_live_A1b2C3d4E5f6G7h8";
const BODY: &str = concat!(
    "<!doctype html><html><body><main>owned passive fixture</main>",
    "<pre>token=sk_live_A1b2C3d4E5f6G7h8</pre></body></html>"
);
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
    let request_line = request.lines().next().unwrap_or_default().to_owned();
    requests
        .lock()
        .expect("request trace lock")
        .push(request_line);

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
        command.arg("--secret-exposure-review");
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

fn assert_secret_absent(bytes: &[u8], label: &str) {
    assert!(
        !bytes
            .windows(SYNTHETIC_SECRET.len())
            .any(|window| window == SYNTHETIC_SECRET.as_bytes()),
        "{label} retained the synthetic secret"
    );
}

fn read_bundle_without_secret(directory: &Path) -> Value {
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

    for name in &names {
        let bytes = fs::read(directory.join(name)).expect("read report bundle member");
        assert_secret_absent(&bytes, name);
    }

    serde_json::from_slice(
        &fs::read(directory.join(JSON_NAME)).expect("read bundled assessment JSON"),
    )
    .expect("parse bundled assessment JSON")
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
    assert_secret_absent(&verify.stdout, "Verify stdout");
    assert_secret_absent(&verify.stderr, "Verify stderr");
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
    assert_secret_absent(&comparison.stdout, "Compare stdout");
    assert_secret_absent(&comparison.stderr, "Compare stderr");
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

#[test]
fn actual_cli_reuses_ordinary_responses_and_keeps_secret_value_out_of_reports() {
    let parent = tempfile::tempdir().expect("create private report parent");

    let baseline_server = serve();
    let baseline_directory = parent.path().join("option-off");
    let baseline = run_scan(&baseline_server, &baseline_directory, false);
    assert_success(&baseline, "option-off scan");
    assert_secret_absent(&baseline.stdout, "option-off stdout");
    assert_secret_absent(&baseline.stderr, "option-off stderr");
    let baseline_assessment = read_bundle_without_secret(&baseline_directory);
    assert!(baseline_assessment.get("secret_exposure_review").is_none());
    assert!(baseline_assessment["items"]
        .as_array()
        .expect("baseline items")
        .iter()
        .all(|item| item["capability_id"] != "exposure.response-stripe-live-secret@1"));

    let selected_server = serve();
    let selected_directory = parent.path().join("option-on");
    let selected = run_scan(&selected_server, &selected_directory, true);
    assert_success(&selected, "selected scan");
    assert_secret_absent(&selected.stdout, "selected stdout");
    assert_secret_absent(&selected.stderr, "selected stderr");
    let assessment = read_bundle_without_secret(&selected_directory);

    let audit = &assessment["secret_exposure_review"];
    assert_eq!(audit["schema"], "security.passive-secret-exposure-audit/v1");
    assert_eq!(audit["policy"], "termivar.passive-secret-exposure/v1");
    assert_eq!(audit["selected"], true);
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(audit["response_count"], 1);
    assert_eq!(audit["evaluated_response_count"], 1);
    assert_eq!(audit["not_evaluated_response_count"], 0);
    assert_eq!(
        audit["body_derived_projection_suppressed_response_count"],
        1
    );
    assert_eq!(audit["observation_count"], 1);
    assert_eq!(audit["match_occurrence_count"], 1);
    assert_eq!(audit["raw_values_retained"], false);
    assert_eq!(audit["public_secret_hashes_retained"], false);
    assert_eq!(audit["source_authentication"], "not_established");
    assert_eq!(audit["secret_validity"], "not_tested");
    assert_eq!(audit["provider_validation"], "not_performed");
    assert_eq!(audit["exploit_execution"], "not_performed");
    assert_eq!(audit["impact_validation"], "not_performed");
    assert_eq!(audit["observations"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        audit["observations"][0]["detector_class"],
        "stripe_live_secret"
    );
    assert_eq!(
        audit["observations"][0]["capability_id"],
        "exposure.response-stripe-live-secret@1"
    );
    assert_eq!(audit["observations"][0]["occurrence_count"], 1);
    assert_eq!(
        audit["observations"][0]["evidence_references"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    let matching_items = assessment["items"]
        .as_array()
        .expect("assessment items")
        .iter()
        .filter(|item| item["capability_id"] == "exposure.response-stripe-live-secret@1")
        .collect::<Vec<_>>();
    assert_eq!(matching_items.len(), 1);
    assert_eq!(matching_items[0]["disposition"], "informational");
    assert_eq!(matching_items[0]["claim_basis"], "observation");
    assert!(matching_items[0]["severity"].is_null());
    assert_eq!(matching_items[0]["evidence_count"], 1);

    let baseline_requests = baseline_server
        .requests
        .lock()
        .expect("baseline trace lock")
        .clone();
    let selected_requests = selected_server
        .requests
        .lock()
        .expect("selected trace lock")
        .clone();
    assert_eq!(
        baseline_requests,
        ["GET / HTTP/1.1", "GET / HTTP/1.1", "GET / HTTP/1.1"].map(str::to_owned),
        "option-off ordinary web-review trace changed"
    );
    assert_eq!(
        selected_requests, baseline_requests,
        "passive secret-exposure review must not add or replace requests"
    );

    assert_offline_verify_and_self_compare(&selected_server, &selected_directory, &assessment);
}

#[cfg(all(
    feature = "graphql-review",
    feature = "openapi-review",
    feature = "rest-review",
    feature = "authorization-review",
    feature = "wordpress-review"
))]
#[test]
fn actual_cli_rejects_each_unprotected_response_pipeline_before_target_or_output_work() {
    let parent = tempfile::tempdir().expect("create private report parent");
    let cases: &[(&str, &[&str])] = &[
        ("graphql", &["--graphql-review"]),
        ("openapi", &["--openapi-review"]),
        ("rest", &["--openapi-review", "--rest-review"]),
        (
            "resource-authorization",
            &[
                "--authorization-review-policy",
                "must-not-be-read.json",
                "--authz-primary-env",
                "S04_PRIMARY_MUST_NOT_BE_READ",
                "--authz-peer-env",
                "S04_PEER_MUST_NOT_BE_READ",
            ],
        ),
        (
            "wordpress-discovery",
            &["--wordpress-review", "--wordpress-discovery"],
        ),
    ];

    for (label, additional) in cases {
        let report_directory = parent.path().join(format!("must-not-exist-{label}"));
        let server = serve();
        let mut command = termivar();
        command.args([
            "scan",
            &server.url,
            "--profile",
            "web-review",
            "--secret-exposure-review",
        ]);
        command.args(*additional);
        let output = command
            .arg("--report-dir")
            .arg(&report_directory)
            .output()
            .expect("run real Termivar CLI preflight");

        assert!(
            !output.status.success(),
            "{label}: incompatible reviews were accepted"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(
                "cannot be combined with review options whose response-body digest privacy contract is not supported"
            ),
            "{label}: unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_secret_absent(&output.stdout, &format!("{label} preflight stdout"));
        assert_secret_absent(&output.stderr, &format!("{label} preflight stderr"));
        assert!(
            server
                .requests
                .lock()
                .expect("request trace lock")
                .is_empty(),
            "{label}: preflight refusal contacted the target"
        );
        assert!(
            !report_directory.exists(),
            "{label}: preflight refusal reserved report output"
        );
    }
}
