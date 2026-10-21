//! Actual-process acceptance for OpenAPI's selected value-free projection.
//! The document bytes, request traces and expected relationships below are
//! original synthetic fixtures, not captured executable or target output.

#![cfg(all(feature = "openapi-review", feature = "secret-exposure-review"))]

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

const ROOT_BODY: &str = "<!doctype html><html><body>Owned ordinary response.</body></html>";
const CANARY_A: &str = "LowEntropyOpenApiCanaryA";
const CANARY_B: &str = "LowEntropyOpenApiCanaryB";
const ERROR_CANARY: &str = "SYNTHETIC_OPENAPI_ERROR_CANARY";
const DOCUMENT_A: &str = r#"{"openapi":"3.1.0","info":{"title":"LowEntropyOpenApiCanaryA","version":"private-build"},"paths":{"/LowEntropyOpenApiCanaryA":{"get":{"responses":{"200":{"description":"original synthetic response"}}}}}}"#;
const DOCUMENT_B: &str = r#"{"openapi":"3.1.0","info":{"title":"LowEntropyOpenApiCanaryB","version":"private-build"},"paths":{"/LowEntropyOpenApiCanaryB":{"get":{"responses":{"200":{"description":"original synthetic response"}}}}}}"#;
const DOCUMENT_A_REORDERED: &str = r#"{"paths":{"/LowEntropyOpenApiCanaryA":{"get":{"responses":{"200":{"description":"original synthetic response"}}}}},"info":{"version":"private-build","title":"LowEntropyOpenApiCanaryA"},"openapi":"3.1.0"}"#;
const MALFORMED_DOCUMENT: &str =
    r#"{"openapi":"3.1.0","private":"SYNTHETIC_OPENAPI_ERROR_CANARY","paths":["#;
const OPENAPI_ACCEPT: &str = "application/vnd.oai.openapi+json, application/json, application/yaml, application/x-yaml, text/yaml, text/plain";
const CAPABILITY: &str = "api.openapi-contract-observed@1";
const MAX_PROCESS_OUTPUT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Scene {
    MatchingA,
    MatchingB,
    Reordered,
    SameCountsDifferentCatalog,
    Malformed,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestRecord {
    method: &'static str,
    path: &'static str,
    openapi_accept: bool,
    credential_header: bool,
    body_bytes: usize,
}

struct FixtureState {
    scene: Scene,
    document_requests: usize,
    requests: Vec<RequestRecord>,
}

struct Fixture {
    url: String,
    state: Arc<Mutex<FixtureState>>,
    stopped: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

impl Fixture {
    fn new(scene: Scene) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind owned loopback fixture");
        listener
            .set_nonblocking(true)
            .expect("bounded listener mode");
        let url = format!(
            "http://{}/",
            listener.local_addr().expect("fixture address")
        );
        let state = Arc::new(Mutex::new(FixtureState {
            scene,
            document_requests: 0,
            requests: Vec::new(),
        }));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stopped = Arc::clone(&stopped);
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(90);
            while !thread_stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let record = read_request(&mut stream);
                        let mut state = thread_state.lock().expect("fixture state lock");
                        assert!(state.requests.len() < 64, "fixture request ceiling");
                        let is_document = record.path == "/openapi.json";
                        let ordinal = state.document_requests;
                        let (body, media) = if is_document {
                            state.document_requests += 1;
                            let body = match state.scene {
                                Scene::MatchingB => DOCUMENT_B,
                                Scene::Reordered if ordinal % 2 == 1 => DOCUMENT_A_REORDERED,
                                Scene::SameCountsDifferentCatalog if ordinal % 2 == 1 => DOCUMENT_B,
                                Scene::Malformed => MALFORMED_DOCUMENT,
                                _ => DOCUMENT_A,
                            };
                            (body, "application/json")
                        } else {
                            (ROOT_BODY, "text/html; charset=utf-8")
                        };
                        let partial = is_document && matches!(state.scene, Scene::Truncated);
                        state.requests.push(record);
                        drop(state);
                        let declared_length = body.len() + usize::from(partial) * 17;
                        let headers = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
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
            server: Some(server),
        }
    }

    fn select_scene(&self, scene: Scene) {
        // Called only after the previous CLI process has exited; no existing
        // response is rewritten, replayed or used as a hidden expected value.
        let mut state = self.state.lock().expect("fixture state lock");
        state.scene = scene;
        state.document_requests = 0;
    }

    fn trace(&self) -> Vec<RequestRecord> {
        self.state.lock().expect("fixture trace").requests.clone()
    }

    fn shutdown(&mut self) -> Vec<RequestRecord> {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().expect("owned fixture task failed");
        }
        self.trace()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            // Cleanup must not conceal a pre-existing acceptance failure.
            let _ = server.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> RequestRecord {
    stream.set_nonblocking(false).expect("bounded stream mode");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("write timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut buffer).expect("bounded fixture headers");
        assert!(count > 0, "incomplete fixture request headers");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 16 * 1024, "request header bound");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("ASCII fixture headers");
    let mut line = headers
        .lines()
        .next()
        .expect("request line")
        .split_whitespace();
    let method = match line.next().expect("request method") {
        "GET" => "GET",
        "HEAD" => "HEAD",
        _ => "unexpected-method",
    };
    let path = match line.next().expect("request route") {
        "/" => "/",
        "/openapi.json" => "/openapi.json",
        _ => "unexpected-route",
    };
    // Retain only closed labels and bounded counts; never echo an unexpected
    // request URI/header value in a fixture panic or diagnostic.
    let mut openapi_accept = false;
    let mut credential_header = false;
    let mut body_bytes = 0;
    for line in headers.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("accept") {
                openapi_accept = value.trim() == OPENAPI_ACCEPT;
            }
            if name.eq_ignore_ascii_case("content-length") {
                body_bytes = value.trim().parse().expect("numeric request body length");
            }
            credential_header |= ["authorization", "proxy-authorization", "cookie"]
                .iter()
                .any(|forbidden| name.eq_ignore_ascii_case(forbidden));
        }
    }
    assert_eq!(body_bytes, 0, "only bodyless fixture GETs are authorized");
    assert_eq!(bytes.len(), header_end, "unexpected request body bytes");
    RequestRecord {
        method,
        path,
        openapi_accept,
        credential_header,
        body_bytes,
    }
}

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
        .expect("spawn bounded actual CLI");
    let capture = |pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(MAX_PROCESS_OUTPUT + 1)
                .read_to_end(&mut bytes)
                .expect("bounded CLI sink");
            bytes
        })
    };
    let stdout = capture(Box::new(child.stdout.take().expect("CLI stdout")));
    let stderr = capture(Box::new(child.stderr.take().expect("CLI stderr")));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll actual CLI") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            panic!("actual CLI exceeded fixture deadline");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().expect("join stdout");
    let stderr = stderr.join().expect("join stderr");
    assert!(stdout.len() <= MAX_PROCESS_OUTPUT as usize, "stdout bound");
    assert!(stderr.len() <= MAX_PROCESS_OUTPUT as usize, "stderr bound");
    Output {
        status,
        stdout,
        stderr,
    }
}

fn assert_success(output: &Output, label: &str) {
    let old_guard =
        String::from_utf8_lossy(&output.stderr).contains("privacy contract is not supported");
    assert!(
        output.status.success(),
        "{label}: exit={:?}, old-source-guard={old_guard}",
        output.status.code()
    );
}

fn scan(fixture: &Fixture, directory: &Path, privacy: bool) -> Output {
    let mut command = termivar();
    command
        .args([
            "scan",
            &fixture.url,
            "--profile",
            "web-review",
            "--openapi-review",
            "--format",
            "json",
        ])
        .arg("--report-dir")
        .arg(directory);
    if privacy {
        command.arg("--secret-exposure-review");
    }
    run(command)
}

fn assert_value_free(bytes: &[u8], sink: &str) {
    let mut forbidden = vec![
        CANARY_A.as_bytes().to_vec(),
        CANARY_B.as_bytes().to_vec(),
        ERROR_CANARY.as_bytes().to_vec(),
        b"openapi-catalog-sha256:".to_vec(),
        b"openapi-observed@1:".to_vec(),
    ];
    for body in [
        ROOT_BODY,
        DOCUMENT_A,
        DOCUMENT_B,
        DOCUMENT_A_REORDERED,
        MALFORMED_DOCUMENT,
    ] {
        forbidden.push(body.as_bytes().to_vec());
        forbidden.push(format!("{:x}", Sha256::digest(body.as_bytes())).into_bytes());
    }
    for value in forbidden {
        assert!(
            !bytes.windows(value.len()).any(|part| part == value),
            "{sink}: forbidden response-derived material retained"
        );
    }
}

fn bundle(directory: &Path, privacy: bool) -> (Value, BTreeMap<String, Vec<u8>>) {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory).expect("owned bundle members") {
        assert!(files.len() < 3, "bundle member count bound");
        let entry = entry.expect("bundle member");
        assert!(entry.file_type().expect("bundle member kind").is_file());
        assert!(
            entry.metadata().expect("owned member metadata").len() <= MAX_PROCESS_OUTPUT,
            "bundle member bound before read"
        );
        let name = entry
            .file_name()
            .into_string()
            .expect("ASCII bundle member");
        let bytes = fs::read(entry.path()).expect("bounded owned bundle read");
        assert!(
            bytes.len() <= MAX_PROCESS_OUTPUT as usize,
            "bundle member bound"
        );
        if privacy {
            assert_value_free(&bytes, "bundle member");
        }
        assert!(
            files.insert(name, bytes).is_none(),
            "duplicate bundle member"
        );
    }
    assert_eq!(
        files.keys().map(String::as_str).collect::<Vec<_>>(),
        ["assessment.html", "assessment.json", "manifest.json"]
    );
    let document = serde_json::from_slice(&files["assessment.json"]).expect("rendered source JSON");
    (document, files)
}

fn item_identities(document: &Value) -> BTreeSet<(String, String)> {
    let items = document["items"].as_array().expect("source item array");
    assert!(
        !items.is_empty(),
        "ordinary source observations must remain"
    );
    assert_eq!(document["item_count"].as_u64(), Some(items.len() as u64));
    let identities = items
        .iter()
        .map(|item| {
            (
                item["fingerprint"]
                    .as_str()
                    .expect("source fingerprint")
                    .to_owned(),
                item["capability_id"]
                    .as_str()
                    .expect("source capability")
                    .to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        identities.len(),
        items.len(),
        "unique source item identities"
    );
    identities
}

fn openapi_fingerprint(document: &Value) -> &str {
    document["items"]
        .as_array()
        .expect("source items")
        .iter()
        .find(|item| item["capability_id"] == CAPABILITY)
        .expect("one independently expected OpenAPI observation")["fingerprint"]
        .as_str()
        .expect("OpenAPI fingerprint")
}

fn assert_openapi(
    document: &Value,
    outcome: &str,
    request_count: u64,
    projected: bool,
    privacy: bool,
) {
    assert_eq!(document["schema"], "venom-rendered-assessment/v1");
    let _ = item_identities(document);
    let audit = document["openapi_review"]
        .as_object()
        .expect("selected typed OpenAPI audit");
    assert_eq!(
        audit.get("schema").and_then(Value::as_str),
        Some("security.openapi-review-audit/v1")
    );
    assert_eq!(audit.get("outcome").and_then(Value::as_str), Some(outcome));
    assert_eq!(
        audit.get("candidate_source").and_then(Value::as_str),
        Some("conventional_open_api_json")
    );
    let catalogued = matches!(outcome, "document_observed" | "replay_mismatch");
    assert_eq!(
        audit.get("version").expect("version key").as_str(),
        catalogued.then_some("3.1")
    );
    for field in [
        "path_count",
        "operation_count",
        "get_operation_count",
        "anonymous_operation_count",
    ] {
        assert_eq!(
            audit.get(field).and_then(Value::as_u64),
            Some(u64::from(catalogued)),
            "literal fixture count: {field}"
        );
    }
    for field in [
        "write_operation_count",
        "path_parameter_count",
        "query_parameter_count",
        "explicit_auth_operation_count",
        "url_like_operation_count",
        "multipart_operation_count",
        "deprecated_operation_count",
    ] {
        assert_eq!(
            audit.get(field).and_then(Value::as_u64),
            Some(0),
            "literal zero field: {field}"
        );
    }
    assert_eq!(
        audit.get("request_count").and_then(Value::as_u64),
        Some(request_count)
    );
    assert_eq!(
        audit
            .get("active_verification_count")
            .and_then(Value::as_u64),
        Some(u64::from(request_count == 2))
    );
    assert_eq!(
        audit.get("item_projected").and_then(Value::as_bool),
        Some(projected)
    );
    assert_eq!(
        audit.get("replay_matched").and_then(Value::as_bool),
        Some(projected)
    );
    let digest = audit
        .get("semantic_digest")
        .expect("digest key must remain explicitly present");
    if privacy {
        assert!(
            digest.is_null(),
            "selected privacy audit retained a semantic digest"
        );
    } else {
        assert!(digest
            .as_str()
            .is_some_and(|value| value.starts_with("openapi-catalog-sha256:")));
    }
    let openapi_items = document["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|item| item["capability_id"] == CAPABILITY)
        .collect::<Vec<_>>();
    assert_eq!(openapi_items.len(), usize::from(projected));
    for item in openapi_items {
        assert_eq!(item["disposition"], "informational");
        assert_eq!(item["claim_basis"], "observation");
        assert!(item["severity"].is_null());
        assert_eq!(item["subject_reference"], "subject-0000");
    }
    if privacy {
        let audit = &document["secret_exposure_review"];
        assert_eq!(audit["schema"], "security.passive-secret-exposure-audit/v1");
        assert_eq!(
            audit["response_count"], 1,
            "separate Accept-bearing OpenAPI GETs are not passive detector inputs"
        );
        assert_eq!(audit["evaluated_response_count"], 1);
        assert_eq!(
            audit["body_derived_projection_suppressed_response_count"],
            1
        );
        assert_eq!(audit["additional_request_count"], 0);
        assert_eq!(audit["match_occurrence_count"], 0);
        assert_eq!(audit["observation_count"], 0);
        assert_eq!(audit["observations"].as_array().map(Vec::len), Some(0));
        assert_eq!(audit["public_secret_hashes_retained"], false);
    }
}

fn expected_trace(document_requests: usize) -> Vec<RequestRecord> {
    // The ordinary bootstrap commits first. OpenAPI's planned candidate and
    // active replay execute inside that root assessment before its two later
    // ordinary GETs; unlike GraphQL this is not an after-subject collector.
    let mut trace = vec![
        RequestRecord {
            method: "GET",
            path: "/",
            openapi_accept: false,
            credential_header: false,
            body_bytes: 0
        };
        1
    ];
    trace.extend((0..document_requests).map(|_| RequestRecord {
        method: "GET",
        path: "/openapi.json",
        openapi_accept: true,
        credential_header: false,
        body_bytes: 0,
    }));
    trace.extend([trace[0]; 2]);
    trace
}

fn compare(before: &Path, after: &Path) -> Output {
    let mut command = termivar();
    command
        .args(["report", "compare", "--before"])
        .arg(before.join("assessment.json"))
        .arg("--after")
        .arg(after.join("assessment.json"))
        .args(["--same-scope", "--format", "json"]);
    run(command)
}

fn assert_unchanged_comparison(output: &Output, source: &Value, privacy: bool) {
    assert_success(output, "offline comparison");
    if privacy {
        assert_value_free(&output.stdout, "Compare stdout");
        assert_value_free(&output.stderr, "Compare stderr");
    }
    let comparison: Value = serde_json::from_slice(&output.stdout).expect("actual comparison JSON");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(comparison[group].as_array().map(Vec::len), Some(0));
    }
    let unchanged = comparison["unchanged"]
        .as_array()
        .expect("required unchanged array");
    let identities = unchanged
        .iter()
        .map(|row| {
            assert!(row["before"].is_object() && row["after"].is_object());
            assert_eq!(row["changed_fields"].as_array().map(Vec::len), Some(0));
            (
                row["fingerprint"]
                    .as_str()
                    .expect("paired fingerprint")
                    .to_owned(),
                row["capability_id"]
                    .as_str()
                    .expect("paired capability")
                    .to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(identities.len(), unchanged.len());
    assert_eq!(identities, item_identities(source));
}

fn offline(
    directory: &Path,
    source: &Value,
    original: &BTreeMap<String, Vec<u8>>,
    fixture: &Fixture,
    trace: &[RequestRecord],
) {
    assert!(
        fixture.server.is_none(),
        "fixture must be joined before offline commands"
    );
    let mut command = termivar();
    command
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"]);
    let verification = run(command);
    assert_success(&verification, "offline Verify");
    assert_value_free(&verification.stdout, "Verify stdout");
    assert_value_free(&verification.stderr, "Verify stderr");
    let verified: Value = serde_json::from_slice(&verification.stdout).expect("Verify JSON");
    assert_eq!(verified["status"], "integrity_match");
    assert_unchanged_comparison(&compare(directory, directory), source, true);
    assert_eq!(
        fixture.trace(),
        trace,
        "offline commands changed request trace"
    );
    assert!(
        &bundle(directory, true).1 == original,
        "offline commands changed bundle bytes"
    );
}

#[test]
fn actual_cli_openapi_privacy_retains_semantics_trace_and_coarse_subject_without_catalogue_identity(
) {
    let parent = tempfile::tempdir().expect("owned output parent");
    let mut fixture = Fixture::new(Scene::MatchingA);
    let baseline_dir = parent.path().join("option-off");
    let baseline = scan(&fixture, &baseline_dir, false);
    assert_success(&baseline, "historical OpenAPI option-off scan");
    let (baseline_document, baseline_original) = bundle(&baseline_dir, false);
    assert_openapi(&baseline_document, "document_observed", 2, true, false);
    assert!(baseline_document.get("secret_exposure_review").is_none());
    assert_eq!(fixture.trace(), expected_trace(2));
    assert!(
        String::from_utf8_lossy(&baseline_original["assessment.html"]).contains("openapi_document")
    );

    let selected_a_dir = parent.path().join("selected-a");
    let selected_a = scan(&fixture, &selected_a_dir, true);
    assert_value_free(&selected_a.stdout, "selected stdout");
    assert_value_free(&selected_a.stderr, "selected progress/stderr");
    assert_success(&selected_a, "privacy-selected OpenAPI scan");
    let (selected_a_document, selected_a_original) = bundle(&selected_a_dir, true);
    assert_openapi(&selected_a_document, "document_observed", 2, true, true);
    let html = String::from_utf8_lossy(&selected_a_original["assessment.html"]);
    assert!(html.contains("assessment_subject"));
    assert!(!html.contains("openapi_document"));

    fixture.select_scene(Scene::MatchingB);
    let selected_b_dir = parent.path().join("selected-b");
    let selected_b = scan(&fixture, &selected_b_dir, true);
    assert_success(&selected_b, "different private catalogue scan");
    assert_value_free(&selected_b.stdout, "different catalogue stdout");
    assert_value_free(&selected_b.stderr, "different catalogue stderr");
    let (selected_b_document, selected_b_original) = bundle(&selected_b_dir, true);
    assert_openapi(&selected_b_document, "document_observed", 2, true, true);
    // This is an independent relationship oracle: the literal paths differ,
    // but their public coarse per-root observations must not encode them.
    assert!(
        item_identities(&selected_a_document) == item_identities(&selected_b_document),
        "private catalogue values changed coarse public identity"
    );
    assert!(
        openapi_fingerprint(&baseline_document) != openapi_fingerprint(&selected_a_document),
        "selected OpenAPI projection retained historical document identity"
    );
    assert!(
        openapi_fingerprint(&selected_a_document) == openapi_fingerprint(&selected_b_document),
        "private catalogue changed the OpenAPI-specific coarse identity"
    );

    fixture.select_scene(Scene::Reordered);
    let reordered_dir = parent.path().join("reordered");
    let reordered = scan(&fixture, &reordered_dir, true);
    assert_success(&reordered, "independent reordered semantic replay");
    assert_value_free(&reordered.stdout, "reordered stdout");
    assert_value_free(&reordered.stderr, "reordered stderr");
    let (reordered_document, reordered_original) = bundle(&reordered_dir, true);
    assert_openapi(&reordered_document, "document_observed", 2, true, true);
    let trace = fixture.shutdown();
    assert_eq!(trace, expected_trace(2).repeat(4));
    offline(
        &selected_a_dir,
        &selected_a_document,
        &selected_a_original,
        &fixture,
        &trace,
    );
    offline(
        &selected_b_dir,
        &selected_b_document,
        &selected_b_original,
        &fixture,
        &trace,
    );
    offline(
        &reordered_dir,
        &reordered_document,
        &reordered_original,
        &fixture,
        &trace,
    );
    // Unchanged coarse item projections are NOT proof of private catalogue or
    // response-byte equality. Both distinct source audits remain available.
    assert_unchanged_comparison(
        &compare(&selected_a_dir, &selected_b_dir),
        &selected_a_document,
        true,
    );
    for (before_dir, after_dir, before_source, after_source, reason) in [
        (
            &baseline_dir,
            &selected_a_dir,
            &baseline_document,
            &selected_a_document,
            "before_audit_missing",
        ),
        (
            &selected_a_dir,
            &baseline_dir,
            &selected_a_document,
            &baseline_document,
            "after_audit_missing",
        ),
    ] {
        let output = compare(before_dir, after_dir);
        assert_success(&output, "offline option-off/selected privacy comparison");
        let document: Value =
            serde_json::from_slice(&output.stdout).expect("actual scope comparison");
        let facet = &document["secret_exposure_comparison"];
        assert_eq!(facet["status"], "not_comparable");
        assert_eq!(facet["reason"], reason);
        assert_eq!(document["coverage_equivalence"], "not-established");
        assert_eq!(
            document["source_authenticity"],
            "not-established-by-parsing"
        );
        assert!(document["interpretation_limits"].as_array().unwrap().iter().any(|value| value == "Unchanged means equal compared item projections, not equivalent coverage or security."));
        let mut before_ids = BTreeSet::new();
        let mut after_ids = BTreeSet::new();
        for group in ["only_in_before", "only_in_after", "changed", "unchanged"] {
            for row in document[group]
                .as_array()
                .expect("required comparison group")
            {
                let identity = (
                    row["fingerprint"].as_str().unwrap().to_owned(),
                    row["capability_id"].as_str().unwrap().to_owned(),
                );
                if row["before"].is_object() {
                    assert!(before_ids.insert(identity.clone()));
                }
                if row["after"].is_object() {
                    assert!(after_ids.insert(identity));
                }
            }
        }
        assert_eq!(before_ids, item_identities(before_source));
        assert_eq!(after_ids, item_identities(after_source));
        // The historical source intentionally retains its old digest. Do not
        // reinterpret it as selected privacy or redact saved product bytes.
    }
    assert_eq!(fixture.trace(), trace);
    assert!(
        bundle(&baseline_dir, false).1 == baseline_original,
        "historical bundle bytes changed"
    );
    assert!(
        bundle(&selected_a_dir, true).1 == selected_a_original,
        "selected A bundle bytes changed"
    );
    assert!(
        bundle(&selected_b_dir, true).1 == selected_b_original,
        "selected B bundle bytes changed"
    );
}

#[test]
fn actual_cli_openapi_privacy_uses_every_central_format_without_body_material() {
    for format in ["json", "html", "markdown", "csv"] {
        let mut fixture = Fixture::new(Scene::MatchingA);
        let mut command = termivar();
        command.args([
            "scan",
            &fixture.url,
            "--profile",
            "web-review",
            "--openapi-review",
            "--secret-exposure-review",
            "--report-format",
            format,
        ]);
        let output = run(command);
        let trace = fixture.shutdown();
        assert_success(&output, "central format scan");
        assert_value_free(&output.stdout, "central format stdout");
        assert_value_free(&output.stderr, "central format stderr");
        assert!(String::from_utf8_lossy(&output.stdout).contains(CAPABILITY));
        if matches!(format, "html" | "markdown") {
            let rendered = String::from_utf8_lossy(&output.stdout);
            assert!(rendered.contains("assessment_subject"));
            assert!(!rendered.contains("openapi_document"));
        }
        if format == "json" {
            let document = serde_json::from_slice(&output.stdout).expect("actual central JSON");
            assert_openapi(&document, "document_observed", 2, true, true);
        }
        assert_eq!(trace, expected_trace(2));
    }
}

#[test]
fn actual_cli_openapi_privacy_preserves_private_same_count_replay_mismatch() {
    let parent = tempfile::tempdir().expect("owned negative parent");
    let mut fixture = Fixture::new(Scene::SameCountsDifferentCatalog);
    let directory = parent.path().join("negative");
    let output = scan(&fixture, &directory, true);
    assert_value_free(&output.stdout, "negative scan stdout");
    assert_value_free(&output.stderr, "negative scan stderr");
    assert_success(&output, "complete nonprojected OpenAPI replay mismatch");
    let (document, original) = bundle(&directory, true);
    assert_openapi(&document, "replay_mismatch", 2, false, true);
    let trace = fixture.shutdown();
    assert_eq!(trace, expected_trace(2));
    offline(&directory, &document, &original, &fixture, &trace);
}

#[test]
fn actual_cli_terminal_openapi_privacy_never_publishes_a_completed_bundle() {
    // The phase-terminal rule is Blocked; the enclosing decision sequence
    // becomes AwaitHumanReview even when the child's audit is finalizable.
    // Child Complete is therefore not evidence of CLI completion here.
    for scene in [Scene::Truncated, Scene::Malformed] {
        let parent = tempfile::tempdir().expect("owned incomplete parent");
        let mut fixture = Fixture::new(scene);
        let directory = parent.path().join("incomplete");
        let output = scan(&fixture, &directory, true);
        let trace = fixture.shutdown();
        assert_value_free(&output.stdout, "incomplete stdout");
        assert_value_free(&output.stderr, "incomplete stderr");
        assert_eq!(output.status.code(), Some(1));
        let document: Value =
            serde_json::from_slice(&output.stdout).expect("typed incomplete diagnostic");
        assert_eq!(document["disposition"], "incomplete");
        assert!(
            !directory.exists(),
            "terminal input published a complete bundle"
        );
        // No active replay/replacement of the failed OpenAPI candidate. The
        // ordinary assessment's remaining root observations are not suppressed
        // by a child phase-terminal classification; its final result stays
        // incomplete. Preserve those two independently scheduled ordinary GETs.
        assert_eq!(trace, expected_trace(1));
    }
}

#[test]
fn actual_cli_historical_openapi_option_off_bundle_is_readable_after_fixture_shutdown() {
    let parent = tempfile::tempdir().expect("owned historical bundle parent");
    let mut fixture = Fixture::new(Scene::MatchingA);
    let directory = parent.path().join("historical-option-off");
    let output = scan(&fixture, &directory, false);
    assert_success(&output, "historical option-off OpenAPI scan");
    let (document, original) = bundle(&directory, false);
    assert_openapi(&document, "document_observed", 2, true, false);
    assert!(document.get("secret_exposure_review").is_none());
    let trace = fixture.shutdown();
    assert_eq!(trace, expected_trace(2));
    assert!(fixture.server.is_none());
    let mut command = termivar();
    command
        .args(["report", "verify", "--dir"])
        .arg(&directory)
        .args(["--format", "json"]);
    let verified = run(command);
    assert_success(&verified, "historical option-off offline Verify");
    let verification: Value =
        serde_json::from_slice(&verified.stdout).expect("historical Verify JSON");
    assert_eq!(verification["status"], "integrity_match");
    // Historical digests remain allowed: do not run selected-mode absence
    // assertions against an option-off source to conceal reader incompatibility.
    assert_unchanged_comparison(&compare(&directory, &directory), &document, false);
    assert_eq!(
        fixture.trace(),
        trace,
        "historical offline commands issued requests"
    );
    assert!(
        bundle(&directory, false).1 == original,
        "historical offline commands changed bundle bytes"
    );
}

#[cfg(feature = "ssrf-oast-review")]
#[test]
fn actual_cli_openapi_secret_and_oast_triple_is_refused_before_policy_secret_output_or_network() {
    let parent = tempfile::tempdir().expect("owned preflight parent");
    let mut fixture = Fixture::new(Scene::MatchingA);
    let policy = parent.path().join("policy-must-not-be-opened.json");
    let secret = parent.path().join("secret-must-not-be-opened.txt");
    let directory = parent.path().join("must-not-be-reserved");
    let mut command = termivar();
    command
        .args([
            "scan",
            &fixture.url,
            "--profile",
            "web-review",
            "--openapi-review",
            "--secret-exposure-review",
            "--ssrf-oast-review",
            "--ssrf-oast-policy",
        ])
        .arg(&policy)
        .arg("--oast-admin-token-file")
        .arg(&secret)
        .arg("--report-dir")
        .arg(&directory);
    let output = run(command);
    let trace = fixture.shutdown();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        trace.is_empty(),
        "preflight conflict issued a target request"
    );
    assert!(!directory.exists(), "preflight conflict reserved output");
    assert!(!policy.exists() && !secret.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be combined") && stderr.contains("privacy contract"));
    assert!(!stderr.contains("policy-must-not-be-opened"));
    assert!(!stderr.contains("secret-must-not-be-opened"));
    assert_value_free(&output.stdout, "preflight stdout");
    assert_value_free(&output.stderr, "preflight stderr");
}
