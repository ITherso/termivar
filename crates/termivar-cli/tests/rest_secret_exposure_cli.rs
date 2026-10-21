//! Real CLI regressions over original synthetic REST/OpenAPI bytes.
//! These fixtures are not captured target output or a real-CMS qualification.

#![cfg(all(feature = "rest-review", feature = "secret-exposure-review"))]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

const ROOT: &str = "<!doctype html><html><body>Owned ordinary response.</body></html>";
const REST_A: &str = r#"{"note":"LowEntropyRestCanaryA","ok":true}"#;
const REST_B: &str = r#"{"note":"LowEntropyRestCanaryB","ok":true}"#;
const REST_REORDERED: &str = "{ \"ok\": true, \"note\": \"LowEntropyRestCanaryA\" }\n";
const DOCUMENT_A: &str = r#"{"openapi":"3.1.0","info":{"title":"PrivateRestCatalogA","version":"private-build"},"paths":{"/data":{"get":{"operationId":"PrivateRestOperationA","responses":{"200":{"description":"original synthetic response","content":{"application/json":{}}}}}}}}"#;
const DOCUMENT_B: &str = r#"{"openapi":"3.1.0","info":{"title":"PrivateRestCatalogB","version":"private-build"},"paths":{"/data":{"get":{"operationId":"PrivateRestOperationB","responses":{"200":{"description":"original synthetic response","content":{"application/json":{}}}}}}}}"#;
const MALFORMED_REST: &str = r#"{"note":"LowEntropyRestErrorCanary","ok":["#;
const INELIGIBLE_DOCUMENTS: [&str; 4] = [
    r#"{"openapi":"3.1.0","paths":{"/data":{"post":{"responses":{"200":{"content":{"application/json":{}}}}}}}}"#,
    r#"{"openapi":"3.1.0","paths":{"/data":{"get":{"requestBody":{},"responses":{"200":{"content":{"application/json":{}}}}}}}}"#,
    r#"{"openapi":"3.1.0","components":{"securitySchemes":{"Auth":{"type":"http","scheme":"bearer"}}},"security":[{"Auth":[]}],"paths":{"/data":{"get":{"responses":{"200":{"content":{"application/json":{}}}}}}}}"#,
    r#"{"openapi":"3.1.0","paths":{"/data":{"get":{"parameters":[{"name":"filter","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"content":{"application/json":{}}}}}}}}"#,
];
const OPENAPI_ACCEPT: &str = "application/vnd.oai.openapi+json, application/json, application/yaml, application/x-yaml, text/yaml, text/plain";
const REST_CAPABILITY: &str = "api.rest-readonly-surface-observed@1";
const OPENAPI_CAPABILITY: &str = "api.openapi-contract-observed@1";
const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Scene {
    MatchingA,
    MatchingB,
    CatalogB,
    Reordered,
    SameShapeDifferentScalar,
    MalformedRest,
    PartialRest,
    NoEligible(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Request {
    path: &'static str,
    accept: &'static str,
}

struct State {
    scene: Scene,
    rest_requests: usize,
    document_override: Option<String>,
    trace: Vec<Request>,
}

struct Fixture {
    url: String,
    state: Arc<Mutex<State>>,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Fixture {
    fn new(scene: Scene) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("owned loopback listener");
        listener.set_nonblocking(true).expect("bounded accept");
        let url = format!(
            "http://{}/",
            listener.local_addr().expect("fixture address")
        );
        let state = Arc::new(Mutex::new(State {
            scene,
            rest_requests: 0,
            document_override: None,
            trace: Vec::new(),
        }));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stopped = Arc::clone(&stopped);
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(90);
            while !thread_stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_request(&mut stream);
                        let mut state = thread_state.lock().expect("fixture state");
                        assert!(state.trace.len() < 64, "fixture request ceiling");
                        let (body, media) = match request.path {
                            "/openapi.json" => {
                                let document = match state.scene {
                                    Scene::CatalogB => DOCUMENT_B,
                                    Scene::NoEligible(document) => document,
                                    _ => DOCUMENT_A,
                                };
                                (
                                    state
                                        .document_override
                                        .clone()
                                        .unwrap_or_else(|| document.to_owned()),
                                    "application/json",
                                )
                            },
                            "/data" => {
                                let ordinal = state.rest_requests;
                                state.rest_requests += 1;
                                let body = match state.scene {
                                    Scene::MatchingB => REST_B,
                                    Scene::Reordered if ordinal % 2 == 1 => REST_REORDERED,
                                    Scene::SameShapeDifferentScalar if ordinal % 2 == 1 => REST_B,
                                    Scene::MalformedRest => MALFORMED_REST,
                                    _ => REST_A,
                                };
                                (body.to_owned(), "application/json")
                            },
                            _ => (ROOT.to_owned(), "text/html; charset=utf-8"),
                        };
                        let partial =
                            request.path == "/data" && matches!(state.scene, Scene::PartialRest);
                        state.trace.push(request);
                        drop(state);
                        let headers = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len() + usize::from(partial) * 17
                        );
                        let _ = stream.write_all(headers.as_bytes());
                        let _ = stream.write_all(body.as_bytes());
                        let _ = stream.flush();
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    },
                    Err(_) => panic!("owned fixture accept failed"),
                }
            }
        });
        Self {
            url,
            state,
            stopped,
            thread: Some(thread),
        }
    }

    fn scene(&self, scene: Scene) {
        let mut state = self.state.lock().expect("fixture state");
        state.scene = scene;
        state.rest_requests = 0;
    }

    fn document(&self, document: String) {
        assert!(document.len() < 4096, "synthetic document bound");
        self.state.lock().expect("fixture state").document_override = Some(document);
    }

    fn trace(&self) -> Vec<Request> {
        self.state.lock().expect("fixture trace").trace.clone()
    }

    fn shutdown(&mut self) -> Vec<Request> {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("owned fixture task");
        }
        self.trace()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    stream.set_nonblocking(false).expect("bounded stream");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read deadline");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("write deadline");
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let end = loop {
        let count = stream.read(&mut buffer).expect("bounded request read");
        assert!(count > 0, "incomplete request headers");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 16 * 1024, "request header ceiling");
        if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            break end + 4;
        }
    };
    assert_eq!(bytes.len(), end, "bodyless request only");
    let headers = std::str::from_utf8(&bytes[..end]).expect("ASCII headers");
    let mut line = headers
        .lines()
        .next()
        .expect("request line")
        .split_whitespace();
    assert_eq!(line.next(), Some("GET"), "no method promotion");
    // Keep only closed labels; never dump unknown URI/header values in panic.
    let path = match line.next() {
        Some("/") => "/",
        Some("/openapi.json") => "/openapi.json",
        Some("/data") => "/data",
        _ => "unexpected-route",
    };
    let mut accept = "ordinary";
    for line in headers.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            assert!(
                !["authorization", "cookie", "proxy-authorization"]
                    .iter()
                    .any(|forbidden| name.eq_ignore_ascii_case(forbidden)),
                "credential forwarding is forbidden"
            );
            if name.eq_ignore_ascii_case("content-length") {
                assert_eq!(value.trim(), "0", "bodyless request only");
            }
            if name.eq_ignore_ascii_case("accept") {
                accept = match value.trim() {
                    OPENAPI_ACCEPT => "openapi",
                    "application/json" => "rest",
                    _ => "ordinary",
                };
            }
        }
    }
    Request { path, accept }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_termivar"));
    command.stdin(Stdio::null());
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(name);
    }
    command
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1");
    command
}

fn run(mut command: Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("actual CLI");
    let capture = |pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .expect("bounded CLI capture");
            bytes
        })
    };
    let stdout = capture(Box::new(child.stdout.take().expect("stdout")));
    let stderr = capture(Box::new(child.stderr.take().expect("stderr")));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll CLI") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            panic!("actual CLI exceeded owned fixture deadline");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().expect("stdout task");
    let stderr = stderr.join().expect("stderr task");
    assert!(stdout.len() <= OUTPUT_LIMIT as usize && stderr.len() <= OUTPUT_LIMIT as usize);
    Output {
        status,
        stdout,
        stderr,
    }
}

fn success(output: &Output, label: &str) {
    let old_guard =
        String::from_utf8_lossy(&output.stderr).contains("privacy contract is not supported");
    assert!(
        output.status.success(),
        "{label}: exit={:?}, old-source-guard={old_guard}",
        output.status.code()
    );
}

fn scan(fixture: &Fixture, directory: &Path, privacy: bool) -> Output {
    let mut process = command();
    process
        .args([
            "scan",
            &fixture.url,
            "--profile",
            "web-review",
            "--openapi-review",
            "--rest-review",
            "--format",
            "json",
        ])
        .arg("--report-dir")
        .arg(directory);
    if privacy {
        process.arg("--secret-exposure-review");
    }
    run(process)
}

fn value_free(bytes: &[u8], sink: &str) {
    let mut forbidden = vec![
        "LowEntropyRestCanaryA".as_bytes().to_vec(),
        "LowEntropyRestCanaryB".as_bytes().to_vec(),
        "LowEntropyRestErrorCanary".as_bytes().to_vec(),
        "PrivateRestCatalogA".as_bytes().to_vec(),
        "PrivateRestCatalogB".as_bytes().to_vec(),
        "PrivateRestOperationA".as_bytes().to_vec(),
        "PrivateRestOperationB".as_bytes().to_vec(),
        "openapi-catalog-sha256:".as_bytes().to_vec(),
        "openapi-operation-sha256:".as_bytes().to_vec(),
        "openapi-observed@1:".as_bytes().to_vec(),
        "rest-readonly-target-sha256:".as_bytes().to_vec(),
        // Literal independent Python hashlib results over the documented
        // framed resource/field streams for the two JSON objects above.
        "d86a1e1c5b2600cc47c65eafbeac4cee24d3d4e734c3e8ae5a1d92f82e313d06"
            .as_bytes()
            .to_vec(),
        "d55a8b2a0a0fa71856bc64d6d8f9dea441b0c76c2d36a84456b6ca087a62a697"
            .as_bytes()
            .to_vec(),
        "8985b2adfe82fa50b90337271ee6858a2a961b799598ca772814579665f7c24c"
            .as_bytes()
            .to_vec(),
    ];
    for body in [
        ROOT,
        REST_A,
        REST_B,
        REST_REORDERED,
        DOCUMENT_A,
        DOCUMENT_B,
        MALFORMED_REST,
    ] {
        forbidden.push(body.as_bytes().to_vec());
        forbidden.push(format!("{:x}", Sha256::digest(body.as_bytes())).into_bytes());
        let mut salted = Sha256::new();
        salted.update(b"security.rest-review.body-receipt.v1\0");
        salted.update(body.as_bytes());
        forbidden.push(format!("{:x}", salted.finalize()).into_bytes());
    }
    for forbidden in forbidden {
        assert!(
            !bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden),
            "{sink}: private response-derived identity retained"
        );
    }
}

fn bundle(directory: &Path, privacy: bool) -> (Value, BTreeMap<String, Vec<u8>>) {
    let mut files = BTreeMap::new();
    for member in fs::read_dir(directory).expect("owned bundle") {
        assert!(files.len() < 3, "bundle member ceiling");
        let member = member.expect("bundle member");
        assert!(member.file_type().expect("member kind").is_file());
        assert!(member.metadata().expect("member bound").len() <= OUTPUT_LIMIT);
        let bytes = fs::read(member.path()).expect("bounded own bundle bytes");
        if privacy {
            value_free(&bytes, "bundle");
        }
        assert!(files
            .insert(
                member.file_name().into_string().expect("ASCII member"),
                bytes
            )
            .is_none());
    }
    assert_eq!(
        files.keys().map(String::as_str).collect::<Vec<_>>(),
        ["assessment.html", "assessment.json", "manifest.json"]
    );
    (
        serde_json::from_slice(&files["assessment.json"]).expect("rendered JSON"),
        files,
    )
}

fn identities(document: &Value) -> BTreeSet<(String, String)> {
    let items = document["items"].as_array().expect("source items");
    assert!(!items.is_empty(), "ordinary observations remain");
    assert_eq!(document["item_count"].as_u64(), Some(items.len() as u64));
    let identities = items
        .iter()
        .map(|item| {
            (
                item["fingerprint"]
                    .as_str()
                    .expect("fingerprint")
                    .to_owned(),
                item["capability_id"]
                    .as_str()
                    .expect("capability")
                    .to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(identities.len(), items.len(), "unique item identities");
    identities
}

fn assert_review(document: &Value, outcome: &str, projected: bool, privacy: bool) {
    assert_eq!(document["schema"], "venom-rendered-assessment/v1");
    let _ = identities(document);
    let openapi = &document["openapi_review"];
    assert_eq!(openapi["schema"], "security.openapi-review-audit/v1");
    assert_eq!(openapi["outcome"], "document_observed");
    assert_eq!(openapi["request_count"], 2);
    assert_eq!(openapi["active_verification_count"], 1);
    assert_eq!(openapi["replay_matched"], true);
    assert_eq!(openapi["path_count"], 1);
    assert_eq!(openapi["operation_count"], 1);
    let rest = document["rest_review"]
        .as_object()
        .expect("selected REST audit");
    assert_eq!(
        rest.get("schema").and_then(Value::as_str),
        Some("security.rest-readonly-review-audit/v1")
    );
    assert_eq!(
        rest.get("capability_id").and_then(Value::as_str),
        Some(REST_CAPABILITY)
    );
    assert_eq!(rest.get("outcome").and_then(Value::as_str), Some(outcome));
    assert_eq!(rest.get("method").and_then(Value::as_str), Some("get"));
    assert_eq!(rest.get("request_count").and_then(Value::as_u64), Some(2));
    assert_eq!(
        rest.get("active_verification_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        rest.get("eligible_operation_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        rest.get("documented_response").and_then(Value::as_str),
        Some("json_compatible")
    );
    assert_eq!(
        rest.get("observed_media").and_then(Value::as_str),
        Some("json_compatible")
    );
    assert_eq!(rest.get("status_class").and_then(Value::as_u64), Some(2));
    assert_eq!(
        rest.get("replay_stable").and_then(Value::as_bool),
        Some(projected)
    );
    assert_eq!(
        rest.get("item_projected").and_then(Value::as_bool),
        Some(projected)
    );
    if privacy {
        assert!(
            rest.get("selected_operation_identity").is_none(),
            "selected privacy must omit the content-derived operation identity"
        );
        assert!(openapi
            .as_object()
            .expect("OpenAPI audit")
            .get("semantic_digest")
            .expect("digest key")
            .is_null());
        let secret = &document["secret_exposure_review"];
        assert_eq!(
            secret["schema"],
            "security.passive-secret-exposure-audit/v1"
        );
        assert_eq!(
            secret["response_count"], 1,
            "planned Accept-bearing document and REST GETs are not detector input"
        );
        assert_eq!(secret["evaluated_response_count"], 1);
        assert_eq!(
            secret["body_derived_projection_suppressed_response_count"],
            1
        );
        assert_eq!(secret["additional_request_count"], 0);
        assert_eq!(secret["match_occurrence_count"], 0);
        assert_eq!(secret["observation_count"], 0);
        assert_eq!(secret["observations"].as_array().map(Vec::len), Some(0));
        assert_eq!(secret["public_secret_hashes_retained"], false);
    } else {
        assert!(rest
            .get("selected_operation_identity")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("openapi-operation-sha256:")));
        assert!(openapi["semantic_digest"]
            .as_str()
            .is_some_and(|value| value.starts_with("openapi-catalog-sha256:")));
        assert!(document.get("secret_exposure_review").is_none());
    }
    let items = document["items"].as_array().expect("items");
    assert_eq!(
        items
            .iter()
            .filter(|item| item["capability_id"] == REST_CAPABILITY)
            .count(),
        usize::from(projected)
    );
    assert_eq!(
        items
            .iter()
            .filter(|item| item["capability_id"] == OPENAPI_CAPABILITY)
            .count(),
        1
    );
    for item in items
        .iter()
        .filter(|item| item["capability_id"] == REST_CAPABILITY)
    {
        assert_eq!(item["disposition"], "informational");
        assert_eq!(item["claim_basis"], "observation");
        assert!(item["severity"].is_null());
        assert_eq!(item["subject_reference"], "subject-0000");
    }
}

fn expected_trace() -> Vec<Request> {
    // Independently specified normal root orchestration: ordinary bootstrap,
    // two document GETs, two selected REST GETs, two later ordinary root GETs.
    vec![
        Request {
            path: "/",
            accept: "ordinary",
        },
        Request {
            path: "/openapi.json",
            accept: "openapi",
        },
        Request {
            path: "/openapi.json",
            accept: "openapi",
        },
        Request {
            path: "/data",
            accept: "rest",
        },
        Request {
            path: "/data",
            accept: "rest",
        },
        Request {
            path: "/",
            accept: "ordinary",
        },
        Request {
            path: "/",
            accept: "ordinary",
        },
    ]
}

fn compare(before: &Path, after: &Path) -> Output {
    let mut process = command();
    process
        .args(["report", "compare", "--before"])
        .arg(before.join("assessment.json"))
        .arg("--after")
        .arg(after.join("assessment.json"))
        .args(["--same-scope", "--format", "json"]);
    run(process)
}

fn comparison_partitions(output: &Output, before: &Value, after: &Value, unchanged: bool) {
    success(output, "offline actual comparison");
    let document: Value = serde_json::from_slice(&output.stdout).expect("comparison JSON");
    assert_eq!(document["schema"], "termivar-report-comparison/v1");
    let mut before_ids = BTreeSet::new();
    let mut after_ids = BTreeSet::new();
    for group in ["only_in_before", "only_in_after", "changed", "unchanged"] {
        let rows = document[group]
            .as_array()
            .expect("required four comparison arrays");
        if unchanged && group != "unchanged" {
            assert!(rows.is_empty());
        }
        for row in rows {
            let identity = (
                row["fingerprint"]
                    .as_str()
                    .expect("row fingerprint")
                    .to_owned(),
                row["capability_id"]
                    .as_str()
                    .expect("row capability")
                    .to_owned(),
            );
            if row["before"].is_object() {
                assert!(before_ids.insert(identity.clone()));
            }
            if row["after"].is_object() {
                assert!(after_ids.insert(identity));
            }
            if group == "unchanged" {
                assert_eq!(row["changed_fields"].as_array().map(Vec::len), Some(0));
            }
        }
    }
    assert_eq!(before_ids, identities(before));
    assert_eq!(after_ids, identities(after));
}

fn offline(
    directory: &Path,
    source: &Value,
    bytes: &BTreeMap<String, Vec<u8>>,
    privacy: bool,
    fixture: &Fixture,
    trace: &[Request],
) {
    assert!(
        fixture.thread.is_none(),
        "fixture must stop before offline commands"
    );
    let mut process = command();
    process
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"]);
    let verified = run(process);
    success(&verified, "offline Verify");
    let verification: Value = serde_json::from_slice(&verified.stdout).expect("Verify JSON");
    assert_eq!(verification["status"], "integrity_match");
    let compared = compare(directory, directory);
    comparison_partitions(&compared, source, source, true);
    if privacy {
        for output in [&verified, &compared] {
            value_free(&output.stdout, "offline stdout");
            value_free(&output.stderr, "offline stderr");
        }
    }
    assert_eq!(fixture.trace(), trace, "offline command caused a request");
    assert_eq!(
        &bundle(directory, privacy).1,
        bytes,
        "offline command changed bundle bytes"
    );
}

#[test]
fn actual_cli_rest_privacy_keeps_private_replay_trace_and_coarse_subject_with_offline_reports() {
    let parent = tempfile::tempdir().expect("owned report parent");
    let mut fixture = Fixture::new(Scene::MatchingA);
    let historical_dir = parent.path().join("historical");
    let historical = scan(&fixture, &historical_dir, false);
    success(&historical, "historical REST scan");
    let (historical_doc, historical_bytes) = bundle(&historical_dir, false);
    assert_review(&historical_doc, "surface_observed", true, false);
    assert!(
        String::from_utf8_lossy(&historical_bytes["assessment.html"]).contains("rest_operation")
    );
    assert_eq!(fixture.trace(), expected_trace());

    let mut selected = Vec::new();
    for (name, scene) in [
        ("a", Scene::MatchingA),
        ("b", Scene::MatchingB),
        ("catalogue-b", Scene::CatalogB),
        ("reordered", Scene::Reordered),
    ] {
        fixture.scene(scene);
        let directory = parent.path().join(name);
        let output = scan(&fixture, &directory, true);
        success(&output, "selected REST scan");
        value_free(&output.stdout, "scan stdout");
        value_free(&output.stderr, "scan stderr");
        let (document, bytes) = bundle(&directory, true);
        assert_review(&document, "surface_observed", true, true);
        let html = String::from_utf8_lossy(&bytes["assessment.html"]);
        assert!(html.contains("assessment_subject"));
        assert!(!html.contains("rest_operation") && !html.contains("openapi_document"));
        selected.push((directory, document, bytes));
    }
    let trace = fixture.shutdown();
    assert_eq!(trace, expected_trace().repeat(5));
    offline(
        &historical_dir,
        &historical_doc,
        &historical_bytes,
        false,
        &fixture,
        &trace,
    );
    for (directory, document, bytes) in &selected {
        offline(directory, document, bytes, true, &fixture, &trace);
        // Same coarse public projection is not a claim of equal private JSON,
        // document catalogue, installed state or security posture across runs.
        assert_eq!(identities(&selected[0].1), identities(document));
        let compared = compare(&selected[0].0, directory);
        comparison_partitions(&compared, &selected[0].1, document, true);
        value_free(&compared.stdout, "controlled comparison");
    }
    for (before, after, before_doc, after_doc, reason) in [
        (
            &historical_dir,
            &selected[0].0,
            &historical_doc,
            &selected[0].1,
            "before_audit_missing",
        ),
        (
            &selected[0].0,
            &historical_dir,
            &selected[0].1,
            &historical_doc,
            "after_audit_missing",
        ),
    ] {
        let compared = compare(before, after);
        comparison_partitions(&compared, before_doc, after_doc, false);
        let value: Value = serde_json::from_slice(&compared.stdout).expect("scope comparison");
        assert_eq!(
            value["secret_exposure_comparison"]["status"],
            "not_comparable"
        );
        assert_eq!(value["secret_exposure_comparison"]["reason"], reason);
        assert_eq!(value["coverage_equivalence"], "not-established");
        assert_eq!(value["source_authenticity"], "not-established-by-parsing");
    }
    assert_eq!(fixture.trace(), trace);
    assert_eq!(bundle(&historical_dir, false).1, historical_bytes);
    for (directory, _, bytes) in selected {
        assert_eq!(bundle(&directory, true).1, bytes);
    }
}

#[test]
fn actual_cli_rest_privacy_rejects_same_shape_different_scalar_replay() {
    let parent = tempfile::tempdir().expect("owned mismatch parent");
    let mut fixture = Fixture::new(Scene::SameShapeDifferentScalar);
    let directory = parent.path().join("mismatch");
    let output = scan(&fixture, &directory, true);
    success(&output, "complete REST scalar mismatch");
    value_free(&output.stdout, "mismatch stdout");
    value_free(&output.stderr, "mismatch stderr");
    let (document, bytes) = bundle(&directory, true);
    assert_review(&document, "replay_mismatch", false, true);
    let trace = fixture.shutdown();
    assert_eq!(trace, expected_trace());
    offline(&directory, &document, &bytes, true, &fixture, &trace);
}

#[test]
fn actual_cli_rest_privacy_uses_all_central_formats_without_content_identity() {
    for format in ["json", "html", "markdown", "csv"] {
        let mut fixture = Fixture::new(Scene::MatchingA);
        let mut process = command();
        process.args([
            "scan",
            &fixture.url,
            "--profile",
            "web-review",
            "--openapi-review",
            "--rest-review",
            "--secret-exposure-review",
            "--report-format",
            format,
        ]);
        let output = run(process);
        let trace = fixture.shutdown();
        success(&output, "actual central format");
        value_free(&output.stdout, "central stdout");
        value_free(&output.stderr, "central stderr");
        assert!(String::from_utf8_lossy(&output.stdout).contains(REST_CAPABILITY));
        if format == "json" {
            let document: Value = serde_json::from_slice(&output.stdout).expect("central JSON");
            assert_review(&document, "surface_observed", true, true);
        }
        if matches!(format, "html" | "markdown") {
            let rendered = String::from_utf8_lossy(&output.stdout);
            assert!(
                rendered.contains("assessment_subject") && !rendered.contains("rest_operation")
            );
        }
        assert_eq!(trace, expected_trace());
    }
}

#[test]
fn actual_cli_rest_privacy_partial_or_malformed_response_never_publishes_complete_bundle() {
    // The existing phase-terminal rule has OutcomeStatus::Blocked, not a
    // successful scan verdict. Parent ordinary root work remains scheduled.
    for scene in [Scene::MalformedRest, Scene::PartialRest] {
        let parent = tempfile::tempdir().expect("owned terminal parent");
        let mut fixture = Fixture::new(scene);
        let directory = parent.path().join("must-not-publish");
        let output = scan(&fixture, &directory, true);
        let trace = fixture.shutdown();
        value_free(&output.stdout, "terminal stdout");
        value_free(&output.stderr, "terminal stderr");
        assert_eq!(output.status.code(), Some(1));
        assert!(
            !directory.exists(),
            "terminal scan published a complete bundle"
        );
        let document: Value =
            serde_json::from_slice(&output.stdout).expect("typed incomplete JSON");
        assert_eq!(document["disposition"], "incomplete");
        let rest = &document["assessment"]["report"]["rest_review_audit"];
        assert_eq!(rest["outcome"], "incomplete");
        assert_eq!(rest["request_count"], 1);
        assert_eq!(rest["active_verification_count"], 0);
        assert_eq!(rest["item_projected"], false);
        assert_eq!(rest["replay_stable"], false);
        let mut expected = expected_trace();
        expected.remove(4); // Failed REST candidate is never retried or replayed.
        assert_eq!(trace, expected);
    }
}

fn assert_no_eligible_rest(fixture: &mut Fixture) {
    let parent = tempfile::tempdir().expect("owned ineligible parent");
    let directory = parent.path().join("must-not-publish");
    let output = scan(fixture, &directory, true);
    let trace = fixture.shutdown();
    value_free(&output.stdout, "ineligible stdout");
    value_free(&output.stderr, "ineligible stderr");
    assert_eq!(
        output.status.code(),
        Some(1),
        "existing blocked phase is not a completed scan"
    );
    assert!(!directory.exists());
    let document: Value =
        serde_json::from_slice(&output.stdout).expect("typed ineligible diagnostic");
    assert_eq!(document["disposition"], "incomplete");
    let report = &document["assessment"]["report"];
    assert_eq!(
        report["openapi_review_audit"]["outcome"],
        "document_observed"
    );
    assert_eq!(report["openapi_review_audit"]["request_count"], 2);
    assert_eq!(
        report["openapi_review_audit"]["semantic_digest"],
        Value::Null
    );
    let rest = &report["rest_review_audit"];
    assert_eq!(rest["outcome"], "not_eligible");
    assert_eq!(rest["eligible_operation_count"], 0);
    assert_eq!(rest["request_count"], 0);
    assert_eq!(rest["active_verification_count"], 0);
    assert_eq!(rest["item_projected"], false);
    assert_eq!(rest["replay_stable"], false);
    let expected = expected_trace()
        .into_iter()
        .filter(|request| request.path != "/data")
        .collect::<Vec<_>>();
    assert_eq!(
        trace, expected,
        "ineligible document nominated a resource request"
    );
}

#[test]
fn actual_cli_rest_privacy_preserves_method_body_auth_parameter_and_foreign_origin_refusals() {
    for document in INELIGIBLE_DOCUMENTS {
        let mut fixture = Fixture::new(Scene::NoEligible(document));
        assert_no_eligible_rest(&mut fixture);
    }
    // A second actual owned loopback server is the foreign origin oracle.
    // Its URL is inert catalogue data, never a transport grant.
    let mut foreign = Fixture::new(Scene::MatchingA);
    let mut fixture = Fixture::new(Scene::MatchingA);
    fixture.document(serde_json::json!({
        "openapi": "3.1.0",
        "servers": [{"url": foreign.url.trim_end_matches('/')}],
        "paths": {"/data": {"get": {"responses": {"200": {"content": {"application/json": {}}}}}}}
    }).to_string());
    assert_no_eligible_rest(&mut fixture);
    assert!(
        foreign.shutdown().is_empty(),
        "untrusted server declaration expanded target origin"
    );
}

#[cfg(feature = "ssrf-oast-review")]
#[test]
fn actual_cli_rest_secret_and_oast_selection_refuses_before_input_output_or_network() {
    let parent = tempfile::tempdir().expect("owned preflight parent");
    let mut fixture = Fixture::new(Scene::MatchingA);
    let policy = parent.path().join("must-not-open-policy.json");
    let secret = parent.path().join("must-not-open-secret.txt");
    let directory = parent.path().join("must-not-reserve");
    let mut process = command();
    process
        .args([
            "scan",
            &fixture.url,
            "--profile",
            "web-review",
            "--openapi-review",
            "--rest-review",
            "--secret-exposure-review",
            "--ssrf-oast-review",
            "--ssrf-oast-policy",
        ])
        .arg(&policy)
        .arg("--oast-admin-token-file")
        .arg(&secret)
        .arg("--report-dir")
        .arg(&directory);
    let output = run(process);
    assert_eq!(output.status.code(), Some(2));
    assert!(fixture.shutdown().is_empty());
    assert!(!directory.exists() && !policy.exists() && !secret.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be combined") && stderr.contains("privacy contract"));
    assert!(!stderr.contains("must-not-open"));
    value_free(&output.stdout, "preflight stdout");
    value_free(&output.stderr, "preflight stderr");
}
