//! Actual-process contracts for single-run assessment report bundles.
//!
//! Every assessment request stays on an in-process numeric-loopback fixture.
//! The generated JSON is handed to the existing offline comparison command;
//! that handoff must not add another connection to the fixture.

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
use sha2::{Digest, Sha256};

const HTML_NAME: &str = "assessment.html";
const JSON_NAME: &str = "assessment.json";
const MANIFEST_NAME: &str = "manifest.json";

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

fn serve_html(body: &'static str) -> TestServer {
    serve_response("200 OK", "text/html; charset=utf-8", body)
}

fn serve_response(
    status: &'static str,
    content_type: &'static str,
    body: &'static str,
) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind numeric-loopback fixture");
    let address: SocketAddr = listener.local_addr().expect("read fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            handle_connection(
                &mut stream,
                status,
                content_type,
                body,
                thread_requests.as_ref(),
            );
        }
    });

    TestServer {
        url: format!("http://{address}/"),
        requests,
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    requests: &Mutex<Vec<String>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0_u8; 16 * 1024];
    let bytes_read = stream.read(&mut buffer).unwrap_or(0);
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    requests.lock().expect("request trace lock").push(target);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn run_bundle(command_name: &str, target: &str, destination: &Path) -> Output {
    termivar()
        .arg(command_name)
        .arg(target)
        .args(["--profile", "web-review", "--report-dir"])
        .arg(destination)
        .output()
        .expect("run report-bundle command")
}

fn parse_json(bytes: &[u8], context: &str) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "{context} must be one JSON document ({error}):\n{}",
            String::from_utf8_lossy(bytes)
        )
    })
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn assert_three_bundle_files(destination: &Path) {
    let mut names = fs::read_dir(destination)
        .expect("read completed bundle")
        .map(|entry| {
            entry
                .expect("read bundle entry")
                .file_name()
                .into_string()
                .expect("fixed bundle filenames are UTF-8")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, [HTML_NAME, JSON_NAME, MANIFEST_NAME]);
}

#[test]
fn actual_cli_one_scan_writes_two_reports_and_a_matching_manifest() {
    let server = serve_html("<main>bounded fixture</main>");
    let parent = tempfile::tempdir().expect("create private test parent");
    let destination = parent.path().join("assessment-001");
    let output = run_bundle("scan", &server.url, &destination);

    assert!(
        output.status.success(),
        "bundle scan failed with {:?}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "bundle success must not emit a report to stdout"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Report bundle completed"),
        "bundle success must emit a concise diagnostic"
    );
    assert_three_bundle_files(&destination);

    let html = fs::read(destination.join(HTML_NAME)).expect("read bundled HTML");
    let json = fs::read(destination.join(JSON_NAME)).expect("read bundled JSON");
    let manifest_bytes = fs::read(destination.join(MANIFEST_NAME)).expect("read manifest");
    let assessment = parse_json(&json, "bundled assessment");
    let manifest = parse_json(&manifest_bytes, "bundle manifest");
    let html_text = std::str::from_utf8(&html).expect("bundled HTML must be UTF-8");

    assert_eq!(assessment["schema"], "venom-rendered-assessment/v1");
    assert_eq!(assessment["profile"], "web-review");
    assert_eq!(assessment["status"], "complete");
    assert!(html_text.starts_with("<!doctype html>"));
    assert!(html_text.contains("Content-Security-Policy"));
    assert!(!html_text.contains("<script"));
    assert_eq!(manifest["schema"], "termivar-report-bundle/v1");
    assert_eq!(manifest["producer"]["product"], "Termivar");
    assert_eq!(manifest["producer"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["assessment"]["profile"], assessment["profile"]);
    assert_eq!(manifest["assessment"]["status"], assessment["status"]);
    assert_eq!(
        manifest["assessment"]["subject_count"],
        assessment["subject_count"]
    );
    assert_eq!(
        manifest["assessment"]["item_count"],
        assessment["item_count"]
    );

    let files = manifest["files"].as_array().expect("manifest file entries");
    assert_eq!(files.len(), 2);
    for (entry, expected_name, expected_format, expected_media, bytes) in [
        (
            &files[0],
            HTML_NAME,
            "html",
            "text/html; charset=utf-8",
            html.as_slice(),
        ),
        (
            &files[1],
            JSON_NAME,
            "json",
            "application/json",
            json.as_slice(),
        ),
    ] {
        assert_eq!(entry["name"], expected_name);
        assert_eq!(entry["format"], expected_format);
        assert_eq!(entry["media_type"], expected_media);
        assert_eq!(entry["byte_length"], bytes.len() as u64);
        assert_eq!(entry["sha256"], sha256(bytes));
        assert_eq!(entry["sha256"].as_str().unwrap().len(), 64);
    }
    assert!(files.iter().all(|entry| entry["name"] != MANIFEST_NAME));
    assert!(!String::from_utf8_lossy(&manifest_bytes).contains(&server.url));
    assert!(!String::from_utf8_lossy(&manifest_bytes)
        .contains(&parent.path().to_string_lossy().to_string()));

    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(
        requests_after_scan,
        vec!["/", "/", "/"],
        "bundle selection must retain the ordinary web-review request trace"
    );

    let comparison = termivar()
        .args(["report", "compare", "--before"])
        .arg(destination.join(JSON_NAME))
        .arg("--after")
        .arg(destination.join(JSON_NAME))
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("self-compare bundled JSON");
    assert!(
        comparison.status.success(),
        "bundle self-compare failed:\n{}",
        String::from_utf8_lossy(&comparison.stderr)
    );
    assert!(comparison.stderr.is_empty());
    let comparison = parse_json(&comparison.stdout, "bundle self-comparison");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len() as u64,
        assessment["item_count"].as_u64().unwrap()
    );
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(comparison["before"]["sha256"], sha256(&json));
    assert_eq!(comparison["after"]["sha256"], sha256(&json));
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline comparison must not contact the assessment fixture"
    );
}

#[test]
fn report_dir_preflight_rejects_destinations_before_secret_loading_or_network() {
    const MISSING_AUTH_ENV: &str = "TERMIVAR_REPORT_BUNDLE_TEST_MISSING_AUTH";

    let server = serve_html("must not be requested");
    let parent = tempfile::tempdir().expect("create private test parent");
    let existing = parent.path().join("existing-bundle");
    fs::create_dir(&existing).expect("create foreign destination");
    fs::write(existing.join("foreign.txt"), b"preserve me").expect("write foreign marker");

    let existing_result = termivar()
        .args([
            "scan",
            &server.url,
            "--profile",
            "web-review",
            "--report-dir",
        ])
        .arg(&existing)
        .args(["--auth-env", MISSING_AUTH_ENV])
        .env_remove(MISSING_AUTH_ENV)
        .output()
        .expect("run existing-destination preflight");
    assert!(!existing_result.status.success());
    assert!(existing_result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&existing_result.stderr).contains("already exists"),
        "unexpected error: {}",
        String::from_utf8_lossy(&existing_result.stderr)
    );
    assert_eq!(
        fs::read(existing.join("foreign.txt")).unwrap(),
        b"preserve me"
    );

    let missing_parent = parent.path().join("missing-parent").join("bundle");
    let missing_result = termivar()
        .args([
            "scan",
            &server.url,
            "--profile",
            "web-review",
            "--report-dir",
        ])
        .arg(&missing_parent)
        .args(["--auth-env", MISSING_AUTH_ENV])
        .env_remove(MISSING_AUTH_ENV)
        .output()
        .expect("run missing-parent preflight");
    assert!(!missing_result.status.success());
    assert!(missing_result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&missing_result.stderr).contains("parent is unavailable"),
        "unexpected error: {}",
        String::from_utf8_lossy(&missing_result.stderr)
    );
    assert!(!missing_parent.exists());

    let missing_secret_destination = parent.path().join("missing-secret-bundle");
    let missing_secret_result = termivar()
        .args([
            "scan",
            &server.url,
            "--profile",
            "web-review",
            "--report-dir",
        ])
        .arg(&missing_secret_destination)
        .args(["--auth-env", MISSING_AUTH_ENV])
        .env_remove(MISSING_AUTH_ENV)
        .output()
        .expect("run missing-secret cleanup path");
    assert!(!missing_secret_result.status.success());
    assert!(missing_secret_result.stdout.is_empty());
    assert!(
        !missing_secret_destination.exists(),
        "a secret-load failure must release its exclusive uncommitted reservation"
    );
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn report_dir_conflicts_and_profiles_fail_before_network() {
    let server = serve_html("must not be requested");
    let parent = tempfile::tempdir().expect("create private test parent");
    let destination = parent.path().join("bundle");
    let single_output = parent.path().join("single.json");

    let cases = [
        vec![
            "scan".to_owned(),
            server.url.clone(),
            "--report-dir".to_owned(),
            destination.to_string_lossy().into_owned(),
        ],
        vec![
            "scan".to_owned(),
            server.url.clone(),
            "--profile".to_owned(),
            "baseline".to_owned(),
            "--report-dir".to_owned(),
            destination.to_string_lossy().into_owned(),
        ],
        vec![
            "scan".to_owned(),
            server.url.clone(),
            "--profile".to_owned(),
            "web-review".to_owned(),
            "--report-dir".to_owned(),
            destination.to_string_lossy().into_owned(),
            "--report-format".to_owned(),
            "json".to_owned(),
        ],
        vec![
            "decision-scan".to_owned(),
            server.url.clone(),
            "--profile".to_owned(),
            "web-review".to_owned(),
            "--report-dir".to_owned(),
            destination.to_string_lossy().into_owned(),
            "--report-output".to_owned(),
            single_output.to_string_lossy().into_owned(),
        ],
    ];
    for arguments in cases {
        let output = termivar()
            .args(arguments)
            .output()
            .expect("run CLI refusal");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    assert!(!destination.exists());
    assert!(!single_output.exists());
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn incomplete_scan_emits_diagnostics_and_removes_the_uncommitted_directory() {
    let server = serve_html("bounded fixture");
    let parent = tempfile::tempdir().expect("create private test parent");
    let destination = parent.path().join("incomplete-bundle");
    let query = (0..65)
        .map(|index| format!("parameter_{index:02}=redacted"))
        .collect::<Vec<_>>()
        .join("&");
    let target = format!("{}?{query}", server.url);
    let output = termivar()
        .args([
            "scan",
            &target,
            "--profile",
            "web-review",
            "--format",
            "json",
            "--report-dir",
        ])
        .arg(&destination)
        .output()
        .expect("run incomplete bundle scan");

    assert!(
        !output.status.success(),
        "incomplete assessment must exit nonzero"
    );
    let diagnostic = parse_json(&output.stdout, "incomplete diagnostic");
    assert_eq!(diagnostic["schema_version"], "web-assessment/v2");
    assert_eq!(diagnostic["disposition"], "incomplete");
    assert!(diagnostic["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "query_parameter_name_limit"));
    assert!(
        !destination.exists(),
        "an incomplete assessment must not leave a completed or reusable bundle directory"
    );
}

#[test]
fn decision_scan_alias_can_publish_the_same_fixed_bundle_contract() {
    let server = serve_html("<main>alias fixture</main>");
    let parent = tempfile::tempdir().expect("create private test parent");
    let destination = parent.path().join("alias-bundle");
    let output = run_bundle("decision-scan", &server.url, &destination);

    assert!(
        output.status.success(),
        "decision-scan alias bundle failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert_three_bundle_files(&destination);
    assert_eq!(server.requests.lock().unwrap().as_slice(), ["/", "/", "/"]);
}

#[test]
fn empty_complete_bundle_self_compares_without_a_security_claim() {
    let server = serve_response("404 Not Found", "text/plain; charset=utf-8", "");
    let parent = tempfile::tempdir().expect("create private test parent");
    let destination = parent.path().join("empty-bundle");
    let output = run_bundle("scan", &server.url, &destination);

    assert!(
        output.status.success(),
        "zero-item bundle scan failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let assessment_bytes = fs::read(destination.join(JSON_NAME)).expect("read empty assessment");
    let assessment = parse_json(&assessment_bytes, "empty bundled assessment");
    assert_eq!(assessment["status"], "complete");
    assert_eq!(assessment["item_count"], 0);
    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(requests_after_scan, ["/", "/", "/"]);

    let comparison = termivar()
        .args(["report", "compare", "--before"])
        .arg(destination.join(JSON_NAME))
        .arg("--after")
        .arg(destination.join(JSON_NAME))
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("self-compare empty bundled JSON");
    assert!(
        comparison.status.success(),
        "empty bundle self-comparison failed:\n{}",
        String::from_utf8_lossy(&comparison.stderr)
    );
    let comparison = parse_json(&comparison.stdout, "empty bundle self-comparison");
    for group in ["only_in_after", "only_in_before", "changed", "unchanged"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(comparison["before"]["sha256"], sha256(&assessment_bytes));
    assert_eq!(comparison["after"]["sha256"], sha256(&assessment_bytes));
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline comparison must not add fixture requests"
    );
}
