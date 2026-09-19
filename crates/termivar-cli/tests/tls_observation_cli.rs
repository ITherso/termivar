//! Actual-process acceptance for passive existing-response TLS observation.
//!
//! The process fixture deliberately uses plain HTTP. It proves that explicit
//! selection publishes the strict not-applicable audit without adding traffic,
//! while the scanner's owned trusted-loopback TLS test separately exercises
//! Reqwest's real TLS response extension with certificate verification enabled.

#![cfg(feature = "tls-observation")]

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

const BODY: &str =
    "<!doctype html><html><body>owned plain-http TLS-observation fixture</body></html>";
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
        command.arg("--tls-observation");
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
        comparison["tls_observation_comparison"]["status"],
        "compared"
    );
    assert_eq!(
        comparison["tls_observation_comparison"]["methodology"]["status"],
        "unchanged"
    );
    assert_eq!(
        comparison["tls_observation_comparison"]["coverage"]["status"],
        "unchanged"
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
fn actual_cli_publishes_plain_http_not_applicable_without_adding_work() {
    let parent = tempfile::tempdir().expect("create private report parent");

    let baseline_server = serve();
    let baseline_directory = parent.path().join("option-off");
    let baseline = run_scan(&baseline_server, &baseline_directory, false);
    assert_success(&baseline, "option-off scan");
    let baseline_assessment = read_bundle(&baseline_directory);
    assert!(baseline_assessment.get("tls_observation").is_none());

    let selected_server = serve();
    let selected_directory = parent.path().join("option-on");
    let selected = run_scan(&selected_server, &selected_directory, true);
    assert_success(&selected, "selected scan");
    let assessment = read_bundle(&selected_directory);

    let audit = &assessment["tls_observation"];
    assert_eq!(audit["schema"], "security.tls-observation-audit/v1");
    assert_eq!(
        audit["policy"],
        "termivar.existing-connection-tls-observation/v1"
    );
    assert_eq!(audit["selected"], true);
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(audit["target_scheme"], "http");
    assert_eq!(
        audit["observation_source_scope"],
        "assessment_exact_origin_existing_connections/v1"
    );
    assert_eq!(
        audit["observation_clock_assurance"],
        "local_system_clock_not_independently_verified"
    );
    assert_eq!(audit["successful_https_response_count"], 0);
    assert_eq!(audit["plaintext_response_count"], 3);
    assert_eq!(audit["assessment_request_count"], 3);
    for field in [
        "tls_info_unavailable_count",
        "malformed_certificate_count",
        "certificate_limit_rejection_count",
        "unretained_leaf_response_count",
        "leaf_observation_count",
    ] {
        assert_eq!(audit[field], 0, "unexpected `{field}` count");
    }
    for field in [
        "protocol",
        "cipher_suite",
        "alpn_protocol",
        "full_chain",
        "connection_reuse",
        "handshake_kind",
        "session_resumption",
    ] {
        assert_eq!(
            audit[field], "not_exposed_by_backend",
            "unexpected `{field}` assurance"
        );
    }
    assert_eq!(audit["revocation"], "not_checked");
    assert_eq!(
        audit["transport_validation_scope"],
        "successful_https_response_connection/v1"
    );
    assert_eq!(audit["active_tls_matrix"], "not_performed");
    assert_eq!(audit["source_authentication"], "not_established");
    assert_eq!(audit["observations"], serde_json::json!([]));

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
        "passive TLS observation must not add or replace requests"
    );
    assert_eq!(
        assessment["items"].as_array().map(Vec::len),
        baseline_assessment["items"].as_array().map(Vec::len),
        "passive TLS observation created a finding item"
    );

    assert_offline_verify_and_self_compare(&selected_server, &selected_directory, &assessment);
}
