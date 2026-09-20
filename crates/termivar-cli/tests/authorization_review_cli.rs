//! Actual-process acceptance for Resource Authorization Review.
//!
//! The owned numeric-loopback fixture classifies credentials and cookies while
//! reading each request, but deliberately retains neither header value. The
//! positive case exercises the normal CLI/runtime path, report publication,
//! feature-independent Verify, and self-Compare.

#![cfg(feature = "authorization-review")]

use std::{
    fs,
    io::{Read, Write},
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

const PRIMARY_AUTHORIZATION: &str = "Bearer AUTHORIZATION-REVIEW-PRIMARY-PROCESS-CANARY-83D5A7";
const PEER_AUTHORIZATION: &str = "Bearer AUTHORIZATION-REVIEW-PEER-PROCESS-CANARY-4E29C1";
const COOKIE_CANARY: &str = "authorization-review-cookie-canary=must-not-return";
const RESOURCE_PATH: &str = "/api/account";
const SELECTED_PATH: &str = "/data/account";
const IGNORED_PATH: &str = "/data/account/updated_at";
const RESOURCE_HANDLE: &str = "private-account-process-fixture";
const SELECTED_ID_CANARY: &str = "AUTHORIZATION-REVIEW-SELECTED-ID-CANARY-4F72";
const SELECTED_NAME_CANARY: &str = "AUTHORIZATION-REVIEW-SELECTED-NAME-CANARY-8C31";
const IGNORED_PRIMARY_CANARY_PREFIX: &str = "AUTHORIZATION-REVIEW-IGNORED-PRIMARY-CANARY-";
const IGNORED_PEER_CANARY_PREFIX: &str = "AUTHORIZATION-REVIEW-IGNORED-PEER-CANARY-";
const CAPABILITY: &str = "authorization.resource-cross-principal-equivalence@1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorizationClass {
    Primary,
    Peer,
    Absent,
    Unexpected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CookieClass {
    Absent,
    Present,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestRecord {
    method: String,
    target: String,
    authorization: AuthorizationClass,
    cookie: CookieClass,
}

struct TestServer {
    url: String,
    records: Arc<Mutex<Vec<RequestRecord>>>,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    address: SocketAddr,
}

impl TestServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(usize, &RequestRecord) -> Vec<u8> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind owned loopback fixture");
        let address = listener.local_addr().expect("read fixture address");
        let records = Arc::new(Mutex::new(Vec::new()));
        let worker_records = Arc::clone(&records);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let handler = Arc::new(handler);
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                if worker_shutdown.load(Ordering::Acquire) {
                    break;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let record = read_request(&mut stream);
                let sequence = {
                    let mut records = worker_records.lock().expect("fixture trace lock");
                    records.push(record.clone());
                    records.len()
                };
                let response = handler(sequence, &record);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        Self {
            url: format!("http://{address}/"),
            records,
            shutdown,
            worker: Some(worker),
            address,
        }
    }

    fn stop(&mut self) -> Vec<RequestRecord> {
        if let Some(worker) = self.worker.take() {
            self.shutdown.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            worker.join().expect("join loopback fixture");
        }
        self.records.lock().expect("fixture trace lock").clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn read_request(stream: &mut TcpStream) -> RequestRecord {
    const MAX_REQUEST_BYTES: usize = 32 * 1024;
    let mut buffer = [0_u8; MAX_REQUEST_BYTES];
    let mut length = 0_usize;
    while length < buffer.len() {
        match stream.read(&mut buffer[length..]) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                length += read;
                if buffer[..length]
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
                {
                    break;
                }
            },
        }
    }
    let request = String::from_utf8_lossy(&buffer[..length]);
    let mut request_line = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or_default().to_owned();
    let target = request_line.next().unwrap_or("/").to_owned();
    let authorization = request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then_some(value.trim())
        })
        .map_or(AuthorizationClass::Absent, |value| match value {
            PRIMARY_AUTHORIZATION => AuthorizationClass::Primary,
            PEER_AUTHORIZATION => AuthorizationClass::Peer,
            _ => AuthorizationClass::Unexpected,
        });
    let cookie = if request.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("cookie"))
    }) {
        CookieClass::Present
    } else {
        CookieClass::Absent
    };
    RequestRecord {
        method,
        target,
        authorization,
        cookie,
    }
}

fn response(status: &str, media_type: &str, body: &str, extra_headers: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {media_type}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn html(body: &str) -> Vec<u8> {
    response("200 OK", "text/html; charset=utf-8", body, "")
}

fn json_response(body: &str) -> Vec<u8> {
    response(
        "200 OK",
        "application/json",
        body,
        &format!("Set-Cookie: {COOKIE_CANARY}; HttpOnly; SameSite=Strict\r\n"),
    )
}

fn termivar(proxy_url: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_termivar"));
    command.stdin(Stdio::null());
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(key);
    }
    if let Some(proxy_url) = proxy_url {
        for key in ["HTTP_PROXY", "ALL_PROXY", "http_proxy", "all_proxy"] {
            command.env(key, proxy_url);
        }
    }
    command
}

fn assert_success(output: &Output, label: &str) {
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    assert!(
        output.status.success(),
        "{label} failed with {:?}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_no_private_values(bytes: &[u8]) {
    assert_no_private_values_with(bytes, &[]);
}

fn assert_no_private_values_with(bytes: &[u8], extra_forbidden: &[&str]) {
    let text = String::from_utf8_lossy(bytes);
    for forbidden in [
        PRIMARY_AUTHORIZATION,
        PEER_AUTHORIZATION,
        PRIMARY_AUTHORIZATION
            .strip_prefix("Bearer ")
            .expect("primary fixture uses the reviewed Bearer mechanism"),
        PEER_AUTHORIZATION
            .strip_prefix("Bearer ")
            .expect("peer fixture uses the reviewed Bearer mechanism"),
        COOKIE_CANARY,
        COOKIE_CANARY
            .strip_prefix("authorization-review-cookie-canary=")
            .expect("cookie fixture uses the reviewed name"),
        RESOURCE_HANDLE,
        SELECTED_PATH,
        IGNORED_PATH,
        SELECTED_ID_CANARY,
        SELECTED_NAME_CANARY,
        IGNORED_PRIMARY_CANARY_PREFIX,
        IGNORED_PEER_CANARY_PREFIX,
    ] {
        assert!(
            !text.contains(forbidden),
            "authorization-review private fixture value leaked"
        );
    }
    for forbidden in extra_forbidden {
        assert!(
            !text.contains(forbidden),
            "authorization-review private fixture location leaked"
        );
    }
}

fn read_bundle(directory: &Path) -> (Value, Vec<u8>) {
    let mut names = fs::read_dir(directory)
        .expect("read authorization-review bundle")
        .map(|entry| {
            entry
                .expect("read bundle entry")
                .file_name()
                .into_string()
                .expect("fixed report filename is UTF-8")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["assessment.html", "assessment.json", "manifest.json"]
    );
    let assessment_bytes = fs::read(directory.join("assessment.json"))
        .expect("read authorization-review assessment JSON");
    let assessment = serde_json::from_slice(&assessment_bytes)
        .expect("parse authorization-review assessment JSON");
    let mut bundle = Vec::new();
    for name in names {
        bundle.extend(fs::read(directory.join(name)).expect("read report bundle member"));
    }
    (assessment, bundle)
}

#[test]
fn private_value_guard_rejects_selected_and_ignored_response_scalars() {
    for forbidden in [
        SELECTED_ID_CANARY,
        SELECTED_NAME_CANARY,
        IGNORED_PRIMARY_CANARY_PREFIX,
        IGNORED_PEER_CANARY_PREFIX,
    ] {
        assert!(
            std::panic::catch_unwind(|| assert_no_private_values(forbidden.as_bytes())).is_err(),
            "private response scalar was not covered by the denylist"
        );
    }
    assert_no_private_values(b"bounded value-free authorization audit");
}

fn write_inputs(directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let policy = directory.join("authorization-policy.toml");
    let primary = directory.join("primary-authorization.txt");
    let peer = directory.join("peer-authorization.txt");
    fs::write(
        &policy,
        format!(
            r#"schema = "security.authorization-review-policy/v1"
resource = "{RESOURCE_PATH}"
resource_handle = "{RESOURCE_HANDLE}"
expectation = "primary-only"
method = "GET"

[comparison]
selected_paths = ["{SELECTED_PATH}"]
ignored_paths = ["{IGNORED_PATH}"]
unordered_array_paths = []
max_diff_paths = 8
"#
        ),
    )
    .expect("write authorization-review policy");
    fs::write(&primary, format!("{PRIMARY_AUTHORIZATION}\n"))
        .expect("write primary credential input");
    fs::write(&peer, format!("{PEER_AUTHORIZATION}\r\n")).expect("write peer credential input");
    (policy, primary, peer)
}

fn assert_offline_verify_and_self_compare(directory: &Path, assessment: &Value) {
    let verify = termivar(None)
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"])
        .output()
        .expect("run offline Report Verify");
    assert_success(&verify, "Report Verify");
    let verification: Value =
        serde_json::from_slice(&verify.stdout).expect("parse Report Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let report = directory.join("assessment.json");
    let comparison = termivar(None)
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run offline self-Compare");
    assert_success(&comparison, "self-Compare");
    let comparison: Value =
        serde_json::from_slice(&comparison.stdout).expect("parse self-Compare JSON");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(comparison[group], json!([]));
    }
    assert_eq!(
        comparison["unchanged"].as_array().map(Vec::len),
        assessment["items"].as_array().map(Vec::len)
    );
}

#[test]
fn actual_cli_projects_stable_cross_principal_review_and_offline_bundle() {
    let parent = tempfile::tempdir().expect("create private authorization-review directory");
    let (policy, primary, peer) = write_inputs(parent.path());
    let report_directory = parent.path().join("report");

    // The ambient proxy receives ordinary traffic where the HTTP stack chooses
    // to use it, but it must never receive either classified principal. This
    // also turns loss of the dedicated no-proxy authorization pool into a
    // positive-case failure on platforms that proxy numeric loopback.
    let mut proxy = TestServer::start(|_, _| html("ordinary proxy fixture response"));
    let mut application = TestServer::start(|sequence, record| {
        let is_resource = record.target == RESOURCE_PATH;
        if !is_resource {
            return html("<html><body>owned authorization fixture</body></html>");
        }
        let principal = match record.authorization {
            AuthorizationClass::Primary => "primary",
            AuthorizationClass::Peer => "peer",
            AuthorizationClass::Absent | AuthorizationClass::Unexpected => {
                return response(
                    "401 Unauthorized",
                    "application/json",
                    r#"{"error":"unauthorized"}"#,
                    "",
                );
            },
        };
        json_response(&format!(
            r#"{{"data":{{"account":{{"id":"{SELECTED_ID_CANARY}","name":"{SELECTED_NAME_CANARY}","updated_at":"AUTHORIZATION-REVIEW-IGNORED-{}-CANARY-{sequence}"}}}}}}"#,
            principal.to_ascii_uppercase(),
        ))
    });

    let output = termivar(Some(&proxy.url))
        .args(["scan", "--profile", "web-review"])
        .arg(&application.url)
        .arg("--authorization-review-policy")
        .arg(&policy)
        .arg("--authz-primary-file")
        .arg(&primary)
        .arg("--authz-peer-file")
        .arg(&peer)
        .arg("--report-dir")
        .arg(&report_directory)
        .output()
        .expect("run authorization-review CLI acceptance");
    assert_success(&output, "authorization-review scan");
    let application_url = application.url.clone();
    let canonical_origin = application_url.trim_end_matches('/').to_owned();
    let resource_url = format!("{canonical_origin}{RESOURCE_PATH}");
    let private_locations = [
        application_url.as_str(),
        canonical_origin.as_str(),
        &resource_url,
    ];
    assert_no_private_values_with(&output.stdout, &private_locations);
    assert_no_private_values_with(&output.stderr, &private_locations);

    let application_trace = application.stop();
    let proxy_trace = proxy.stop();
    let resource_trace = application_trace
        .iter()
        .filter(|record| record.target == RESOURCE_PATH)
        .collect::<Vec<_>>();
    assert_eq!(resource_trace.len(), 4);
    assert_eq!(
        resource_trace
            .iter()
            .map(|record| record.authorization)
            .collect::<Vec<_>>(),
        [
            AuthorizationClass::Primary,
            AuthorizationClass::Peer,
            AuthorizationClass::Primary,
            AuthorizationClass::Peer,
        ]
    );
    assert!(resource_trace.iter().all(|record| {
        record.method == "GET"
            && record.cookie == CookieClass::Absent
            && !record.target.contains('?')
    }));
    let ordinary_application_trace = application_trace
        .iter()
        .filter(|record| record.target != RESOURCE_PATH)
        .collect::<Vec<_>>();
    assert!(ordinary_application_trace.iter().all(|record| {
        record.authorization == AuthorizationClass::Absent && record.cookie == CookieClass::Absent
    }));
    assert!(
        !proxy_trace.is_empty(),
        "ambient proxy control must observe ordinary assessment traffic"
    );
    assert!(proxy_trace.iter().all(|record| {
        record.authorization == AuthorizationClass::Absent && record.cookie == CookieClass::Absent
    }));
    let ordinary_request_count = ordinary_application_trace.len() + proxy_trace.len();
    assert_eq!(ordinary_request_count, 3);
    assert_eq!(ordinary_request_count + resource_trace.len(), 7);

    let (assessment, bundle) = read_bundle(&report_directory);
    assert_no_private_values_with(&bundle, &private_locations);
    assert_eq!(assessment["schema"], "venom-rendered-assessment/v1");
    assert_eq!(assessment["status"], "complete");
    let audit = &assessment["authorization_review"];
    assert_eq!(audit["schema"], "security.authorization-review-audit/v1");
    assert_eq!(audit["capability_id"], CAPABILITY);
    let policy_id = audit["policy_id"]
        .as_str()
        .expect("authorization policy identity must be a string");
    let policy_digest = policy_id
        .strip_prefix("authorization-policy-sha256:")
        .expect("authorization policy identity must use the reviewed digest domain");
    assert_eq!(policy_digest.len(), 64);
    assert!(policy_digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
    assert_eq!(audit["selected_path_count"], 1);
    assert_eq!(audit["ignored_path_count"], 1);
    assert_eq!(audit["request_count"], 4);
    assert_eq!(audit["outcome"], "stable_cross_principal_equivalence");
    assert_eq!(audit["primary_stable"], true);
    assert_eq!(audit["peer_stable"], true);
    assert_eq!(audit["cross_resources_equivalent"], true);
    assert_eq!(audit["item_projected"], true);
    let items = assessment["items"]
        .as_array()
        .expect("assessment items must be an array");
    assert_eq!(assessment["item_count"].as_u64(), Some(items.len() as u64));
    let authorization_items = items
        .iter()
        .filter(|item| item["capability_id"] == CAPABILITY)
        .collect::<Vec<_>>();
    assert_eq!(authorization_items.len(), 1);
    let item = authorization_items[0];
    assert_eq!(item["disposition"], "needs_review");
    assert_eq!(item["claim_basis"], "differential");
    assert_eq!(item["severity"], Value::Null);
    assert_eq!(item["evidence_count"], 4);
    assert_eq!(
        item["control_evidence_references"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        item["candidate_evidence_references"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_ne!(item["disposition"], "confirmed");

    // Both servers have been stopped: these commands can only succeed offline.
    assert_offline_verify_and_self_compare(&report_directory, &assessment);
}
