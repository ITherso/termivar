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
    proxy_authorization_present: bool,
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
        proxy_authorization_present: request.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
        }),
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

#[cfg(feature = "secret-exposure-review")]
mod privacy_composition {
    use super::*;
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::Instant,
    };

    // Original synthetic bytes, not captured native output. The two objects
    // have identical fields/counts and differ only in one selected scalar.
    const BODY_A: &str = r#"{"data":{"account":{"id":"AUTHORIZATION-REVIEW-SELECTED-ID-CANARY-4F72","name":"AUTHORIZATION-REVIEW-SELECTED-NAME-CANARY-8C31","updated_at":"PRIVATE-AUTH-TIMESTAMP"}}}"#;
    const BODY_B: &str = r#"{"data":{"account":{"id":"AUTHORIZATION-REVIEW-SELECTED-ID-CANARY-4F73","name":"AUTHORIZATION-REVIEW-SELECTED-NAME-CANARY-8C31","updated_at":"PRIVATE-AUTH-TIMESTAMP"}}}"#;
    const MALFORMED: &str = r#"{"data":{"account":{"id":"AUTH-PRIVACY-MALFORMED","name":["#;
    const RATE_BODY: &str = r#"{"error":"private-auth-rate-limit"}"#;
    const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;
    const PROJECTION_FIELDS: [&str; 10] = [
        "title",
        "category",
        "disposition",
        "claim_basis",
        "severity",
        "cwe",
        "confidence_ppm",
        "redacted_summary",
        "remediation",
        "evidence",
    ];

    #[derive(Clone, Copy)]
    enum Scene {
        StableA,
        StableB,
        CrossDifferent,
        PrimaryUnstable,
        Malformed,
        Partial,
        RateLimited,
    }

    struct SceneState {
        scene: Scene,
        resource_requests: usize,
    }

    fn fixture() -> (TestServer, Arc<Mutex<SceneState>>) {
        let state = Arc::new(Mutex::new(SceneState {
            scene: Scene::StableA,
            resource_requests: 0,
        }));
        let worker_state = Arc::clone(&state);
        let server = TestServer::start(move |sequence, record| {
            assert!(sequence <= 128, "owned application request ceiling");
            assert!(
                !record.proxy_authorization_present,
                "proxy credential reached the application"
            );
            if record.target != RESOURCE_PATH {
                return html("<html><body>owned authorization privacy fixture</body></html>");
            }
            let mut state = worker_state.lock().expect("synthetic scene state");
            let ordinal = state.resource_requests;
            state.resource_requests += 1;
            assert!(ordinal < 4, "authorization request allowance changed");
            match state.scene {
                Scene::Malformed => json_response(MALFORMED),
                Scene::Partial => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY_A}",
                    BODY_A.len() + 17
                )
                .into_bytes(),
                Scene::RateLimited => response(
                    "429 Too Many Requests",
                    "application/json",
                    RATE_BODY,
                    "Retry-After: 60\r\n",
                ),
                _ => {
                    let body = match state.scene {
                        Scene::StableB => BODY_B,
                        Scene::CrossDifferent
                            if record.authorization == AuthorizationClass::Peer => BODY_B,
                        Scene::PrimaryUnstable if ordinal == 2 => BODY_B,
                        _ => BODY_A,
                    };
                    json_response(body)
                },
            }
        });
        (server, state)
    }

    fn set_scene(state: &Mutex<SceneState>, scene: Scene) {
        let mut state = state.lock().expect("synthetic scene state");
        state.scene = scene;
        state.resource_requests = 0;
    }

    fn bounded_run(mut command: Command) -> Output {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn actual CLI process");
        let capture = |pipe: Box<dyn Read + Send>| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                pipe.take(OUTPUT_LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .expect("bounded process capture");
                bytes
            })
        };
        let stdout = capture(Box::new(child.stdout.take().expect("child stdout")));
        let stderr = capture(Box::new(child.stderr.take().expect("child stderr")));
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll actual process") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout.join();
                let _ = stderr.join();
                panic!("actual CLI exceeded the owned process deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        let stdout = stdout.join().expect("stdout worker");
        let stderr = stderr.join().expect("stderr worker");
        assert!(stdout.len() <= OUTPUT_LIMIT as usize && stderr.len() <= OUTPUT_LIMIT as usize);
        Output {
            status,
            stdout,
            stderr,
        }
    }

    fn value_free(bytes: &[u8], locations: &[&str]) {
        assert_no_private_values_with(bytes, locations);
        let text = String::from_utf8_lossy(bytes);
        for forbidden in [
            "AUTHORIZATION-REVIEW-SELECTED-ID-CANARY-4F73",
            "PRIVATE-AUTH-TIMESTAMP",
            "AUTH-PRIVACY-MALFORMED",
            "private-auth-rate-limit",
            BODY_A,
            BODY_B,
            MALFORMED,
            RATE_BODY,
            // Independently executed Python hashlib.sha256 over the exact
            // literal UTF-8 bodies above, respectively 168/168/58/35 bytes.
            "e05351cfc1c64a3f2f8397b4006fa426e0a5ddbfa61dc782378e8531c03b55d3",
            "63e5557d37ccb8b4b4bffde7767179f42b59fc11e513ec097f532f7485b9da69",
            "8441232c797f9e8e96315cd9b8bd403907604ab489406bf86f1b7a4be8e50869",
            "ab9086437205a5bdde34e38a5978eb611a6d307376e68f746b3349858b6f5183",
        ] {
            assert!(
                !text.contains(forbidden),
                "private authorization body or hash retained"
            );
        }
    }

    fn output_ok(output: &Output, locations: &[&str]) {
        if !output.status.success() {
            // Bounded status only: do not dump an unexpected diagnostic body.
            eprintln!(
                "actual authorization CLI native exit={:?}",
                output.status.code()
            );
        }
        value_free(&output.stdout, locations);
        value_free(&output.stderr, locations);
        assert!(
            output.status.success(),
            "actual CLI failed: exit={:?}",
            output.status.code()
        );
    }

    fn scan_command(
        url: &str,
        proxy: Option<&str>,
        inputs: &(PathBuf, PathBuf, PathBuf),
        privacy: bool,
    ) -> Command {
        let mut process = termivar(proxy);
        process
            .args(["scan", url, "--profile", "web-review", "--format", "json"])
            .arg("--authorization-review-policy")
            .arg(&inputs.0)
            .arg("--authz-primary-file")
            .arg(&inputs.1)
            .arg("--authz-peer-file")
            .arg(&inputs.2);
        if privacy {
            process.arg("--secret-exposure-review");
        }
        process
    }

    fn input_bytes(inputs: &(PathBuf, PathBuf, PathBuf)) -> Vec<Vec<u8>> {
        [&inputs.0, &inputs.1, &inputs.2]
            .iter()
            .map(|path| {
                assert!(fs::metadata(path).expect("owned input metadata").len() < 4096);
                fs::read(path).expect("read owned input")
            })
            .collect()
    }

    struct Bundle {
        directory: PathBuf,
        document: Value,
        bytes: BTreeMap<String, Vec<u8>>,
    }

    fn bundle(directory: &Path, locations: &[&str]) -> Bundle {
        let mut bytes = BTreeMap::new();
        for entry in fs::read_dir(directory).expect("owned bundle directory") {
            assert!(bytes.len() < 3, "bundle member ceiling");
            let entry = entry.expect("bundle member");
            assert!(entry.file_type().expect("bundle member type").is_file());
            assert!(entry.metadata().expect("bundle bound").len() <= OUTPUT_LIMIT);
            let body = fs::read(entry.path()).expect("bounded own bundle bytes");
            value_free(&body, locations);
            assert!(bytes
                .insert(entry.file_name().into_string().expect("ASCII member"), body)
                .is_none());
        }
        assert!(bytes.keys().map(String::as_str).eq([
            "assessment.html",
            "assessment.json",
            "manifest.json"
        ]));
        let document = serde_json::from_slice(&bytes["assessment.json"]).expect("rendered JSON");
        Bundle {
            directory: directory.to_owned(),
            document,
            bytes,
        }
    }

    fn item_identity(item: &Value) -> (String, String) {
        (
            item["fingerprint"]
                .as_str()
                .expect("fingerprint")
                .to_owned(),
            item["capability_id"]
                .as_str()
                .expect("capability identity")
                .to_owned(),
        )
    }

    fn source_items(source: &Value) -> BTreeMap<(String, String), Value> {
        assert_eq!(source["schema"], "venom-rendered-assessment/v1");
        let items = source["items"].as_array().expect("source item array");
        assert!(!items.is_empty(), "ordinary observations retained");
        assert_eq!(source["item_count"].as_u64(), Some(items.len() as u64));
        let projected = items.iter().map(|item| {
            let mut projection = serde_json::Map::new();
            for field in &PROJECTION_FIELDS[..9] {
                projection.insert((*field).to_owned(), item.get(*field).expect("source projection field").clone());
            }
            projection.insert("evidence".to_owned(), json!({
                "evidence_count": item["evidence_count"].as_u64().expect("typed evidence count"),
                "evidence_reference_count": item["evidence_references"].as_array().expect("direct references").len(),
                "control_reference_count": item["control_evidence_references"].as_array().expect("control references").len(),
                "candidate_reference_count": item["candidate_evidence_references"].as_array().expect("candidate references").len(),
                "case_present": !item.get("case_reference").expect("case field").is_null(),
                "outcome_present": !item.get("outcome_reference").expect("outcome field").is_null(),
                "verification_stage": item.get("verification_stage").expect("stage field"),
            }));
            (item_identity(item), Value::Object(projection))
        }).collect::<BTreeMap<_, _>>();
        assert_eq!(
            projected.len(),
            items.len(),
            "duplicate source item identity"
        );
        projected
    }

    fn assert_comparison(document: &Value, before: &Value, after: &Value, self_compare: bool) {
        assert_eq!(document["schema"], "termivar-report-comparison/v1");
        assert!(
            document.get("counts").is_none(),
            "no product counts object exists"
        );
        let expected_before = source_items(before);
        let expected_after = source_items(after);
        let mut actual_before = BTreeSet::new();
        let mut actual_after = BTreeSet::new();
        let mut lengths = [0; 4];
        for (index, group) in ["only_in_before", "only_in_after", "changed", "unchanged"]
            .iter()
            .enumerate()
        {
            let rows = document
                .get(*group)
                .expect("required comparison group")
                .as_array()
                .expect("comparison group array");
            lengths[index] = rows.len();
            for row in rows {
                let object = row.as_object().expect("comparison row object");
                assert_eq!(object.len(), 5);
                for field in [
                    "fingerprint",
                    "capability_id",
                    "before",
                    "after",
                    "changed_fields",
                ] {
                    assert!(object.contains_key(field), "required comparison row field");
                }
                let identity = item_identity(row);
                let old = object.get("before").unwrap();
                let new = object.get("after").unwrap();
                assert_eq!(old.is_object(), index != 1, "before partition shape");
                assert_eq!(new.is_object(), index != 0, "after partition shape");
                if index == 0 {
                    assert!(new.is_null());
                }
                if index == 1 {
                    assert!(old.is_null());
                }
                if old.is_object() {
                    assert!(
                        actual_before.insert(identity.clone()),
                        "duplicate before identity"
                    );
                    assert!(
                        expected_before.get(&identity) == Some(old),
                        "before projection/identity substituted"
                    );
                }
                if new.is_object() {
                    assert!(
                        actual_after.insert(identity.clone()),
                        "duplicate after identity"
                    );
                    assert!(
                        expected_after.get(&identity) == Some(new),
                        "after projection/identity substituted"
                    );
                }
                let changes = object["changed_fields"]
                    .as_array()
                    .expect("changed field array");
                let expected_changes = if index >= 2 {
                    PROJECTION_FIELDS
                        .into_iter()
                        .filter(|field| old[*field] != new[*field])
                        .map(Value::from)
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                assert!(
                    changes == &expected_changes,
                    "changed field classification mismatch"
                );
                assert_eq!(
                    !changes.is_empty(),
                    index == 2,
                    "changed/unchanged partition mismatch"
                );
            }
        }
        assert_eq!(lengths[0] + lengths[2] + lengths[3], expected_before.len());
        assert_eq!(lengths[1] + lengths[2] + lengths[3], expected_after.len());
        assert!(actual_before.iter().eq(expected_before.keys()));
        assert!(actual_after.iter().eq(expected_after.keys()));
        if self_compare {
            assert_eq!(lengths, [0, 0, 0, expected_before.len()]);
        }
    }

    fn compare(before: &Bundle, after: &Bundle, locations: &[&str], identical: bool) -> Value {
        let mut process = termivar(None);
        process
            .args(["report", "compare", "--before"])
            .arg(before.directory.join("assessment.json"))
            .arg("--after")
            .arg(after.directory.join("assessment.json"))
            .args(["--same-scope", "--format", "json"]);
        let output = bounded_run(process);
        output_ok(&output, locations);
        let document = serde_json::from_slice(&output.stdout).expect("comparison JSON");
        assert_comparison(&document, &before.document, &after.document, identical);
        document
    }

    fn offline(saved: &Bundle, locations: &[&str]) {
        let mut process = termivar(None);
        process
            .args(["report", "verify", "--dir"])
            .arg(&saved.directory)
            .args(["--format", "json"]);
        let output = bounded_run(process);
        output_ok(&output, locations);
        let verification: Value =
            serde_json::from_slice(&output.stdout).expect("verification JSON");
        assert_eq!(verification["status"], "integrity_match");
        compare(saved, saved, locations, true);
        assert!(
            bundle(&saved.directory, locations).bytes == saved.bytes,
            "offline command modified bundle"
        );
    }

    fn assert_review(document: &Value, outcome: &str, projected: bool, privacy: bool) {
        assert_eq!(document["status"], "complete");
        let _ = source_items(document);
        let audit = &document["authorization_review"];
        assert_eq!(audit["schema"], "security.authorization-review-audit/v1");
        assert_eq!(audit["capability_id"], CAPABILITY);
        assert_eq!(audit["selected_path_count"], 1);
        assert_eq!(audit["ignored_path_count"], 1);
        assert_eq!(audit["request_count"], 4);
        assert_eq!(audit["outcome"], outcome);
        assert_eq!(audit["item_projected"], projected);
        let items = document["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["capability_id"] == CAPABILITY)
            .collect::<Vec<_>>();
        assert_eq!(items.len(), usize::from(projected));
        if projected {
            assert_eq!(audit["primary_stable"], true);
            assert_eq!(audit["peer_stable"], true);
            assert_eq!(audit["cross_resources_equivalent"], true);
            assert_eq!(items[0]["disposition"], "needs_review");
            assert_eq!(items[0]["claim_basis"], "differential");
            assert!(items[0]["severity"].is_null());
            assert_eq!(items[0]["evidence_count"], 4);
        }
        if privacy {
            let secret = &document["secret_exposure_review"];
            assert_eq!(
                secret["schema"],
                "security.passive-secret-exposure-audit/v1"
            );
            assert_eq!(secret["selected"], true);
            assert_eq!(
                secret["response_count"], 1,
                "only ordinary committed bootstrap is detector input"
            );
            assert_eq!(secret["evaluated_response_count"], 1);
            assert_eq!(secret["observation_count"], 0);
            assert_eq!(secret["additional_request_count"], 0);
            assert_eq!(secret["raw_values_retained"], false);
            assert_eq!(secret["public_secret_hashes_retained"], false);
        } else {
            assert!(document.get("secret_exposure_review").is_none());
        }
    }

    fn assert_trace(application: &[RequestRecord], proxy: &[RequestRecord], protected: usize) {
        let resource = application
            .iter()
            .filter(|record| record.target == RESOURCE_PATH)
            .collect::<Vec<_>>();
        assert_eq!(resource.len(), protected);
        let expected = [
            AuthorizationClass::Primary,
            AuthorizationClass::Peer,
            AuthorizationClass::Primary,
            AuthorizationClass::Peer,
        ];
        assert!(
            resource
                .iter()
                .map(|record| record.authorization)
                .eq(expected.into_iter().take(protected)),
            "principal request order changed"
        );
        assert!(resource.iter().all(|record| record.method == "GET"
            && record.cookie == CookieClass::Absent
            && !record.proxy_authorization_present));
        let ordinary = application
            .iter()
            .filter(|record| record.target != RESOURCE_PATH)
            .chain(proxy.iter())
            .collect::<Vec<_>>();
        assert_eq!(
            ordinary.len(),
            3,
            "ordinary assessment request count changed"
        );
        assert!(ordinary.iter().all(|record| record.method == "GET"
            && record.authorization == AuthorizationClass::Absent
            && record.cookie == CookieClass::Absent));
        assert!(application
            .iter()
            .all(|record| !record.proxy_authorization_present));
    }

    #[test]
    fn actual_cli_authorization_privacy_preserves_four_role_semantics_trace_and_offline_bundles() {
        let parent = tempfile::tempdir().expect("owned privacy parent");
        let inputs = write_inputs(parent.path());
        let original_inputs = input_bytes(&inputs);
        let (mut application, state) = fixture();
        let mut proxy = TestServer::start(|sequence, _| {
            assert!(sequence <= 128, "owned proxy request ceiling");
            html("<html><body>owned authorization privacy fixture</body></html>")
        });
        let locations = [
            application.url.as_str(),
            application.url.trim_end_matches('/'),
            proxy.url.as_str(),
        ];
        let mut saved = Vec::new();
        for (index, (scene, privacy, outcome, projected)) in [
            (
                Scene::StableA,
                false,
                "stable_cross_principal_equivalence",
                true,
            ),
            (
                Scene::StableA,
                true,
                "stable_cross_principal_equivalence",
                true,
            ),
            (
                Scene::StableB,
                true,
                "stable_cross_principal_equivalence",
                true,
            ),
            (
                Scene::CrossDifferent,
                true,
                "cross_fields_equivalent_only",
                false,
            ),
            (Scene::PrimaryUnstable, true, "primary_unstable", false),
        ]
        .into_iter()
        .enumerate()
        {
            set_scene(&state, scene);
            let app_start = application.records.lock().unwrap().len();
            let proxy_start = proxy.records.lock().unwrap().len();
            let directory = parent.path().join(format!("bundle-{index}"));
            let mut process = scan_command(&application.url, Some(&proxy.url), &inputs, privacy);
            process.arg("--report-dir").arg(&directory);
            let output = bounded_run(process);
            output_ok(&output, &locations);
            let value = bundle(&directory, &locations);
            assert_review(&value.document, outcome, projected, privacy);
            assert_trace(
                &application.records.lock().unwrap()[app_start..],
                &proxy.records.lock().unwrap()[proxy_start..],
                4,
            );
            saved.push(value);
        }
        let locations = locations.map(str::to_owned);
        let application_trace = application.stop();
        let proxy_trace = proxy.stop();
        let locations = locations.iter().map(String::as_str).collect::<Vec<_>>();
        for value in &saved {
            offline(value, &locations);
        }
        compare(&saved[1], &saved[2], &locations, true);
        for (before, after) in [(0, 1), (1, 0), (1, 3), (3, 1), (1, 4)] {
            let comparison = compare(&saved[before], &saved[after], &locations, false);
            if before == 0 || after == 0 {
                assert_eq!(
                    comparison["secret_exposure_comparison"]["status"],
                    "not_comparable"
                );
            }
        }
        assert!(
            application.stop() == application_trace && proxy.stop() == proxy_trace,
            "offline operation generated a request"
        );
        assert!(
            input_bytes(&inputs) == original_inputs,
            "input bytes changed"
        );
        for value in &saved {
            assert!(
                bundle(&value.directory, &locations).bytes == value.bytes,
                "controlled Compare modified bundle"
            );
        }
    }

    #[test]
    fn actual_cli_authorization_privacy_renders_all_central_formats_without_response_values() {
        for format in ["json", "html", "markdown", "csv"] {
            let parent = tempfile::tempdir().expect("owned format parent");
            let inputs = write_inputs(parent.path());
            let original_inputs = input_bytes(&inputs);
            let (mut application, _) = fixture();
            let mut process = scan_command(&application.url, None, &inputs, true);
            process.args(["--report-format", format]);
            let output = bounded_run(process);
            let trace = application.stop();
            output_ok(
                &output,
                &[&application.url, application.url.trim_end_matches('/')],
            );
            assert_trace(&trace, &[], 4);
            assert!(
                input_bytes(&inputs) == original_inputs,
                "format command changed inputs"
            );
            let rendered = String::from_utf8(output.stdout).expect("UTF-8 central format");
            assert!(rendered.contains("stable_cross_principal_equivalence"));
            if format == "json" {
                assert_review(
                    &serde_json::from_str(&rendered).expect("central JSON"),
                    "stable_cross_principal_equivalence",
                    true,
                    true,
                );
            }
        }
    }

    #[test]
    fn actual_cli_authorization_privacy_terminal_responses_stop_without_complete_publication() {
        for (scene, outcome) in [
            (Scene::Malformed, "malformed_json"),
            (Scene::Partial, "incomplete"),
            (Scene::RateLimited, "rate_limited"),
        ] {
            let parent = tempfile::tempdir().expect("owned terminal parent");
            let inputs = write_inputs(parent.path());
            let original_inputs = input_bytes(&inputs);
            let (mut application, state) = fixture();
            set_scene(&state, scene);
            let directory = parent.path().join("must-not-publish");
            let mut process = scan_command(&application.url, None, &inputs, true);
            process.arg("--report-dir").arg(&directory);
            let output = bounded_run(process);
            let trace = application.stop();
            value_free(&output.stdout, &[&application.url]);
            value_free(&output.stderr, &[&application.url]);
            assert_eq!(output.status.code(), Some(1));
            assert!(
                !directory.exists(),
                "terminal response published a complete bundle"
            );
            let diagnostic: Value =
                serde_json::from_slice(&output.stdout).expect("typed incomplete JSON");
            assert_eq!(diagnostic["disposition"], "incomplete");
            let audit = &diagnostic["assessment"]["report"]["authorization_review_audit"];
            assert_eq!(audit["outcome"], outcome);
            assert_eq!(audit["request_count"], 1);
            assert_eq!(audit["item_projected"], false);
            assert_trace(&trace, &[], 1);
            assert!(
                input_bytes(&inputs) == original_inputs,
                "terminal command changed inputs"
            );
        }
    }

    #[test]
    fn actual_cli_authorization_privacy_invalid_composition_refuses_before_inputs_and_network() {
        for baseline in [false, true] {
            let parent = tempfile::tempdir().expect("owned preflight parent");
            let (mut application, _) = fixture();
            let policy = parent.path().join("must-not-read-policy.toml");
            let primary = parent.path().join("must-not-read-primary.txt");
            let peer = parent.path().join("must-not-read-peer.txt");
            let directory = parent.path().join("must-not-reserve");
            let mut process = termivar(None);
            process
                .args([
                    "scan",
                    &application.url,
                    "--profile",
                    if baseline { "baseline" } else { "web-review" },
                    "--secret-exposure-review",
                ])
                .arg("--authorization-review-policy")
                .arg(&policy)
                .arg("--authz-primary-file")
                .arg(&primary)
                .arg("--authz-peer-file")
                .arg(&peer)
                .arg("--report-dir")
                .arg(&directory);
            if !baseline {
                process.args(["--auth-env", "S04_MUST_NOT_READ_ROOT_CREDENTIAL"]);
            }
            let output = bounded_run(process);
            assert_eq!(output.status.code(), Some(2));
            value_free(&output.stdout, &[&application.url]);
            value_free(&output.stderr, &[&application.url]);
            assert!(application.stop().is_empty());
            assert!(!directory.exists() && !policy.exists() && !primary.exists() && !peer.exists());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("cannot be used")
                    || stderr.contains("requires")
                    || stderr.contains("cannot be combined")
            );
            assert!(
                !stderr.contains("must-not-read")
                    && !stderr.contains("S04_MUST_NOT_READ_ROOT_CREDENTIAL"),
                "preflight exposed a private input source"
            );
        }
    }
}
