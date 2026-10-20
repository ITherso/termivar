//! Actual-process, owned-loopback acceptance for GraphQL's value-free response
//! lineage. Handwritten GraphQL envelopes and traces are independent oracles;
//! these fixtures are synthetic, not captured target or provider output.

#![cfg(all(feature = "graphql-review", feature = "secret-exposure-review"))]

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
const CANARY: &str = "LowEntropyCanary";
const ERROR_CANARY: &str = "SYNTHETIC_GRAPHQL_ERROR_CANARY";
const CONTROL_BODY: &str = r#"{"data":{"venomControlV1":"Query"}}"#;
const CANDIDATE_BODY: &str = r#"{"data":{"venomCandidateV1":"LowEntropyCanary","__schema":{"queryType":{"name":"LowEntropyCanary"},"mutationType":null,"subscriptionType":null}}}"#;
const REPLAY_BODY: &str = r#"{"data":{"venomReplayV1":"LowEntropyCanary","__schema":{"queryType":{"name":"LowEntropyCanary"},"mutationType":null,"subscriptionType":null}}}"#;
const ERROR_BODY: &str =
    r#"{"errors":[{"message":"introspection is disabled: SYNTHETIC_GRAPHQL_ERROR_CANARY"}]}"#;
const MAX_PROCESS_OUTPUT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Scene {
    Available,
    Restricted,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestRecord {
    method: String,
    path: String,
    operation: Option<&'static str>,
    credential_header: bool,
}

struct Fixture {
    url: String,
    requests: Arc<Mutex<Vec<RequestRecord>>>,
    stopped: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

impl Fixture {
    fn new(scene: Scene) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind owned loopback fixture");
        listener.set_nonblocking(true).expect("bound fixture mode");
        let url = format!(
            "http://{}/",
            listener.local_addr().expect("fixture address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stopped = Arc::clone(&stopped);
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !thread_stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (record, body) = read_request(&mut stream);
                        let response_body = if record.method == "GET" && record.path == "/" {
                            ROOT_BODY
                        } else {
                            assert_eq!(record.method, "POST", "unexpected fixture method");
                            assert_eq!(record.path, "/graphql", "unexpected fixture route");
                            match record.operation {
                                Some("control") => CONTROL_BODY,
                                Some("candidate") if matches!(scene, Scene::Restricted) => {
                                    ERROR_BODY
                                },
                                Some("replay") if matches!(scene, Scene::Restricted) => ERROR_BODY,
                                Some("candidate") => CANDIDATE_BODY,
                                Some("replay") => REPLAY_BODY,
                                _ => panic!("unknown fixed GraphQL operation"),
                            }
                        };
                        // Request bodies are scanner-owned fixed literals, not
                        // a second response oracle or retained target content.
                        assert!(body.len() <= 8 * 1024, "fixture request bound");
                        let incomplete = matches!(scene, Scene::Incomplete)
                            && record.operation == Some("candidate");
                        let html = record.method == "GET";
                        let mut trace = thread_requests.lock().expect("fixture trace lock");
                        assert!(trace.len() < 32, "fixture request ceiling");
                        trace.push(record);
                        drop(trace);
                        let media = if html {
                            "text/html; charset=utf-8"
                        } else {
                            "application/graphql-response+json"
                        };
                        let declared_length = response_body.len() + usize::from(incomplete) * 17;
                        let headers = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(headers.as_bytes());
                        let _ = stream.write_all(response_body.as_bytes());
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
            requests,
            stopped,
            server: Some(server),
        }
    }

    fn shutdown(&mut self) -> Vec<RequestRecord> {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().expect("owned fixture task failed");
        }
        self.requests.lock().expect("frozen fixture trace").clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            // A cleanup failure must not replace an existing test failure.
            let _ = server.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> (RequestRecord, Vec<u8>) {
    // On Windows an accepted stream can inherit the listener's nonblocking
    // mode. Only listener accept is polled; request I/O uses explicit timeouts.
    stream
        .set_nonblocking(false)
        .expect("bounded fixture stream mode");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("fixture read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("fixture write timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let (header_end, content_length) = loop {
        let read = stream
            .read(&mut buffer)
            .expect("bounded fixture request read");
        assert!(read > 0, "incomplete fixture request headers");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 16 * 1024, "fixture request size ceiling");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).expect("ASCII request headers");
            let content_length = headers
                .lines()
                .skip(1)
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| {
                        value
                            .trim()
                            .parse::<usize>()
                            .expect("numeric request length")
                    })
                })
                .unwrap_or(0);
            assert!(content_length <= 8 * 1024, "fixture request body ceiling");
            break (end + 4, content_length);
        }
    };
    while bytes.len() - header_end < content_length {
        let read = stream.read(&mut buffer).expect("bounded fixture body read");
        assert!(read > 0, "incomplete fixture request body");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 16 * 1024, "fixture request size ceiling");
    }
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("ASCII request headers");
    let mut start = headers
        .lines()
        .next()
        .expect("request line")
        .split_whitespace();
    // Store only closed route/method labels. An unexpected request must not
    // put a reflected query, credential or arbitrary URI into a panic trace.
    let method = match start.next().expect("request method") {
        "GET" => "GET",
        "POST" => "POST",
        _ => "unexpected-method",
    }
    .to_owned();
    let path = match start.next().expect("request path") {
        "/" => "/",
        "/graphql" => "/graphql",
        _ => "unexpected-route",
    }
    .to_owned();
    let body = bytes[header_end..header_end + content_length].to_vec();
    let operation = if method == "POST" {
        let document: Value = serde_json::from_slice(&body).expect("fixed GraphQL request JSON");
        assert_eq!(document.as_object().map(serde_json::Map::len), Some(1));
        let query = document["query"].as_str().expect("fixed GraphQL query");
        if query.contains("VenomGraphqlControlV1") {
            Some("control")
        } else if query.contains("VenomGraphqlCandidateV1") {
            Some("candidate")
        } else if query.contains("VenomGraphqlReplayV1") {
            Some("replay")
        } else {
            panic!("unknown fixed operation name")
        }
    } else {
        None
    };
    let credential_header = headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, _)| {
            ["authorization", "proxy-authorization", "cookie"]
                .iter()
                .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        })
    });
    (
        RequestRecord {
            method,
            path,
            operation,
            credential_header,
        },
        body,
    )
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
        .expect("spawn bounded CLI process");
    let capture = |pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(MAX_PROCESS_OUTPUT + 1)
                .read_to_end(&mut bytes)
                .expect("capture CLI sink");
            bytes
        })
    };
    let stdout = capture(Box::new(child.stdout.take().expect("CLI stdout")));
    let stderr = capture(Box::new(child.stderr.take().expect("CLI stderr")));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll CLI process") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            panic!("CLI exceeded the bounded fixture deadline");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().expect("join stdout capture");
    let stderr = stderr.join().expect("join stderr capture");
    assert!(stdout.len() <= MAX_PROCESS_OUTPUT as usize, "stdout bound");
    assert!(stderr.len() <= MAX_PROCESS_OUTPUT as usize, "stderr bound");
    Output {
        status,
        stdout,
        stderr,
    }
}

fn assert_success(output: &Output, label: &str) {
    let old_guard = String::from_utf8_lossy(&output.stderr)
        .contains("cannot be combined with review options whose response-body digest privacy contract is not supported");
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
            "--graphql-review",
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

fn forbidden_values() -> Vec<Vec<u8>> {
    let mut forbidden = vec![CANARY.as_bytes().to_vec(), ERROR_CANARY.as_bytes().to_vec()];
    for body in [
        ROOT_BODY,
        CONTROL_BODY,
        CANDIDATE_BODY,
        REPLAY_BODY,
        ERROR_BODY,
    ] {
        forbidden.push(body.as_bytes().to_vec());
        forbidden.push(format!("{:x}", Sha256::digest(body.as_bytes())).into_bytes());
        // Independent framing oracle from the documented existing GraphQL
        // digest contract; no runtime projector/matcher generates this input.
        let mut framed = Sha256::new();
        let domain = b"graphql-review-response/v1";
        framed.update((domain.len() as u64).to_be_bytes());
        framed.update(domain);
        framed.update((body.len() as u64).to_be_bytes());
        framed.update(body.as_bytes());
        forbidden.push(format!("{:x}", framed.finalize()).into_bytes());
    }
    forbidden
}

fn assert_value_free(bytes: &[u8], sink: &str) {
    for forbidden in forbidden_values() {
        assert!(
            !bytes.windows(forbidden.len()).any(|part| part == forbidden),
            "{sink}: forbidden response material retained"
        );
    }
}

fn read_bundle(directory: &Path, privacy: bool) -> (Value, BTreeMap<String, Vec<u8>>) {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory).expect("read owned bundle") {
        let entry = entry.expect("bundle member");
        let name = entry
            .file_name()
            .into_string()
            .expect("fixed ASCII bundle name");
        assert!(
            entry.file_type().expect("bundle member type").is_file(),
            "regular bundle member required"
        );
        let bytes = fs::read(entry.path()).expect("read owned bundle member");
        if privacy {
            assert_value_free(&bytes, "saved bundle member");
        }
        files.insert(name, bytes);
    }
    assert_eq!(
        files.keys().map(String::as_str).collect::<Vec<_>>(),
        ["assessment.html", "assessment.json", "manifest.json"]
    );
    let document = serde_json::from_slice(&files["assessment.json"]).expect("bundle JSON");
    (document, files)
}

fn item_identities(document: &Value) -> BTreeSet<(String, String)> {
    let items = document["items"].as_array().expect("source item array");
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
        "unique source identities required"
    );
    identities
}

fn assert_graphql_semantics(document: &Value, introspection: bool) {
    let identities = item_identities(document);
    let capabilities = identities
        .iter()
        .map(|(_, capability)| capability.as_str())
        .filter(|capability| capability.starts_with("graphql."))
        .collect::<BTreeSet<_>>();
    let expected = if introspection {
        BTreeSet::from([
            "graphql.surface-observed@1",
            "graphql.anonymous-root-introspection@1",
        ])
    } else {
        BTreeSet::from(["graphql.surface-observed@1"])
    };
    assert_eq!(capabilities, expected);
    for item in document["items"].as_array().expect("items") {
        if item["capability_id"]
            .as_str()
            .expect("capability")
            .starts_with("graphql.")
        {
            assert_eq!(item["disposition"], "informational");
            assert_eq!(item["claim_basis"], "observation");
            assert!(item["severity"].is_null());
        }
    }
}

fn assert_passive_scope(document: &Value) {
    let audit = &document["secret_exposure_review"];
    assert_eq!(audit["schema"], "security.passive-secret-exposure-audit/v1");
    assert_eq!(
        audit["response_count"], 1,
        "POSTs are not passive detector responses"
    );
    assert_eq!(audit["evaluated_response_count"], 1);
    assert_eq!(
        audit["body_derived_projection_suppressed_response_count"],
        1
    );
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(audit["match_occurrence_count"], 0);
    assert_eq!(audit["observation_count"], 0);
    assert_eq!(audit["observations"], serde_json::json!([]));
    assert_eq!(audit["public_secret_hashes_retained"], false);
}

fn expected_trace() -> Vec<RequestRecord> {
    // The existing CLI web-review plan has three ordinary root GETs, followed
    // by the fixed control/candidate/replay GraphQL POST sequence.
    [
        ("GET", "/", None),
        ("GET", "/", None),
        ("GET", "/", None),
        ("POST", "/graphql", Some("control")),
        ("POST", "/graphql", Some("candidate")),
        ("POST", "/graphql", Some("replay")),
    ]
    .into_iter()
    .map(|(method, path, operation)| RequestRecord {
        method: method.to_owned(),
        path: path.to_owned(),
        operation,
        credential_header: false,
    })
    .collect()
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
    let mut verify = termivar();
    verify
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"]);
    let verify = run(verify);
    assert_success(&verify, "offline Verify");
    assert_value_free(&verify.stdout, "Verify stdout");
    assert_value_free(&verify.stderr, "Verify stderr");
    let verified: Value = serde_json::from_slice(&verify.stdout).expect("Verify JSON");
    assert_eq!(verified["status"], "integrity_match");

    let report = directory.join("assessment.json");
    let mut compare = termivar();
    compare
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"]);
    let comparison = run(compare);
    assert_success(&comparison, "offline self-Compare");
    assert_value_free(&comparison.stdout, "Compare stdout");
    assert_value_free(&comparison.stderr, "Compare stderr");
    let compared: Value = serde_json::from_slice(&comparison.stdout).expect("Compare JSON");
    assert_eq!(compared["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(compared[group].as_array().map(Vec::len), Some(0));
    }
    let unchanged = compared["unchanged"].as_array().expect("unchanged array");
    let identities = unchanged
        .iter()
        .map(|item| {
            assert!(item["before"].is_object() && item["after"].is_object());
            assert_eq!(item["changed_fields"].as_array().map(Vec::len), Some(0));
            (
                item["fingerprint"]
                    .as_str()
                    .expect("compared fingerprint")
                    .to_owned(),
                item["capability_id"]
                    .as_str()
                    .expect("compared capability")
                    .to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(identities.len(), unchanged.len());
    assert_eq!(identities, item_identities(source));
    assert!(
        fixture.requests.lock().expect("offline trace").as_slice() == trace,
        "offline request trace changed"
    );
    let (_, after) = read_bundle(directory, true);
    assert!(original == &after, "offline commands changed bundle bytes");
}

#[test]
fn actual_cli_graphql_privacy_keeps_positive_semantics_and_exact_anonymous_trace() {
    let parent = tempfile::tempdir().expect("owned bundle parent");
    let mut fixture = Fixture::new(Scene::Available);
    let baseline_dir = parent.path().join("baseline");
    let baseline = scan(&fixture, &baseline_dir, false);
    assert_success(&baseline, "GraphQL option-off baseline");
    let (baseline_document, _) = read_bundle(&baseline_dir, false);
    assert_graphql_semantics(&baseline_document, true);
    assert!(baseline_document.get("secret_exposure_review").is_none());
    let baseline_trace = fixture.requests.lock().expect("baseline trace").clone();
    assert_eq!(baseline_trace, expected_trace());

    let directory = parent.path().join("value-free");
    let selected = scan(&fixture, &directory, true);
    assert_value_free(&selected.stdout, "selected scan stdout");
    assert_value_free(&selected.stderr, "selected scan stderr/progress");
    assert_success(&selected, "GraphQL privacy-selected scan");
    let (document, original) = read_bundle(&directory, true);
    assert_graphql_semantics(&document, true);
    assert_passive_scope(&document);
    assert_eq!(
        item_identities(&document),
        item_identities(&baseline_document)
    );
    let trace = fixture.shutdown();
    assert_eq!(trace.len(), baseline_trace.len() * 2);
    assert_eq!(&trace[baseline_trace.len()..], baseline_trace.as_slice());
    offline(&directory, &document, &original, &fixture, &trace);
}

#[test]
fn actual_cli_graphql_structured_errors_remain_value_free_without_introspection() {
    let parent = tempfile::tempdir().expect("owned bundle parent");
    let mut fixture = Fixture::new(Scene::Restricted);
    let directory = parent.path().join("restricted");
    let selected = scan(&fixture, &directory, true);
    assert_value_free(&selected.stdout, "restricted stdout");
    assert_value_free(&selected.stderr, "restricted stderr/progress");
    assert_success(&selected, "restricted GraphQL scan");
    let (document, original) = read_bundle(&directory, true);
    assert_graphql_semantics(&document, false);
    assert_passive_scope(&document);
    let trace = fixture.shutdown();
    assert_eq!(trace, expected_trace());
    offline(&directory, &document, &original, &fixture, &trace);
}

#[test]
fn actual_cli_incomplete_graphql_response_never_publishes_a_completed_bundle() {
    let parent = tempfile::tempdir().expect("owned bundle parent");
    let mut fixture = Fixture::new(Scene::Incomplete);
    let directory = parent.path().join("incomplete");
    let selected = scan(&fixture, &directory, true);
    let trace = fixture.shutdown();
    assert_value_free(&selected.stdout, "incomplete stdout");
    assert_value_free(&selected.stderr, "incomplete stderr/progress");
    assert!(
        !selected.status.success(),
        "incomplete scan must fail safely"
    );
    let diagnostic: Value =
        serde_json::from_slice(&selected.stdout).expect("typed incomplete diagnostic");
    assert_eq!(diagnostic["disposition"], "incomplete");
    assert!(
        !directory.exists(),
        "incomplete scan published a completed bundle"
    );
    assert_eq!(trace, expected_trace()[..5]);
}
