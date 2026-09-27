//! Actual-process acceptance for the explicit supplied-session WebSocket composition.
//!
//! The fixture is owned numeric loopback. It classifies credential presence
//! without retaining its value and independently controls both health checks.

#![cfg(all(feature = "websocket-review", feature = "supplied-session-review"))]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{
    handshake::derive_accept_key,
    protocol::{Role, WebSocket},
    Message,
};

const AUTHORIZATION: &str = "Bearer WS-SESSION-PROCESS-CANARY-0123456789ABCDEF";
const RESPONSE_CANARY: &str = "PRIVATE-WS-SESSION-RESPONSE-CANARY";
const FIRST_OUTBOUND: &str = r#"{"type":"ping"}"#;
const SECOND_OUTBOUND: &str = r#"{"type":"status"}"#;
const FIRST_INBOUND: &str = r#"{"type":"pong"}"#;
const SECOND_INBOUND: &str = r#"{"status":"ok"}"#;
const FIRST_INBOUND_SHA256: &str =
    "b94f1fbb072a53089df2bd74bd78c1a4d4ef81f6c0e9c316492583edc79830d3";
const SECOND_INBOUND_SHA256: &str =
    "a29ee2b15c494311c52521766e44af56a3ad2248e7a8ab465e5206463c13d288";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HealthMode {
    Healthy,
    StartupUnhealthy,
    TerminalUnhealthy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizationClass {
    Expected,
    Absent,
    Unexpected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestRecord {
    target: String,
    authorization: AuthorizationClass,
    websocket_upgrade: bool,
}

struct OwnedFixture {
    address: SocketAddr,
    target: String,
    endpoint: String,
    records: Arc<Mutex<Vec<RequestRecord>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl OwnedFixture {
    fn start(mode: HealthMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
        let address = listener.local_addr().expect("fixture address");
        let records = Arc::new(Mutex::new(Vec::new()));
        let worker_records = Arc::clone(&records);
        let health_count = Arc::new(AtomicUsize::new(0));
        let worker_health_count = Arc::clone(&health_count);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                handle_connection(
                    &mut stream,
                    mode,
                    worker_health_count.as_ref(),
                    worker_records.as_ref(),
                );
            }
        });
        Self {
            address,
            target: format!("http://{address}/app/"),
            endpoint: format!("ws://{address}/app/socket"),
            records,
            stop,
            worker: Some(worker),
        }
    }

    fn records(&self) -> Vec<RequestRecord> {
        self.records.lock().expect("request record lock").clone()
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = TcpStream::connect(self.address);
            worker.join().expect("join loopback fixture");
        }
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    mode: HealthMode,
    health_count: &AtomicUsize,
    records: &Mutex<Vec<RequestRecord>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 4096];
    while captured.len() < 16 * 1024 {
        let Ok(read) = stream.read(&mut buffer) else {
            return;
        };
        if read == 0 {
            return;
        }
        captured.extend_from_slice(&buffer[..read]);
        if captured.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&captured);
    let request_line = request.lines().next().unwrap_or_default();
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let authorization = match header(&request, "authorization") {
        Some(value) if value == AUTHORIZATION => AuthorizationClass::Expected,
        None => AuthorizationClass::Absent,
        Some(_) => AuthorizationClass::Unexpected,
    };
    let websocket_upgrade = header(&request, "upgrade") == Some("websocket");
    records
        .lock()
        .expect("request record lock")
        .push(RequestRecord {
            target: target.clone(),
            authorization,
            websocket_upgrade,
        });

    if target == "/app/socket" && websocket_upgrade {
        let key = header(&request, "sec-websocket-key").expect("upgrade key");
        let response = format!(
            concat!(
                "HTTP/1.1 101 Switching Protocols\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Accept: {}\r\n\r\n"
            ),
            derive_accept_key(key.as_bytes())
        );
        stream
            .write_all(response.as_bytes())
            .expect("write upgrade response");
        stream.flush().expect("flush upgrade response");
        let owned = stream.try_clone().expect("clone upgraded stream");
        let mut socket = WebSocket::from_raw_socket(owned, Role::Server, None);
        for (expected, response) in [
            (FIRST_OUTBOUND, FIRST_INBOUND),
            (SECOND_OUTBOUND, SECOND_INBOUND),
        ] {
            let message = socket.read().expect("read bounded client message");
            assert_eq!(message.into_text().expect("client text").as_str(), expected);
            socket
                .send(Message::Text(response.into()))
                .expect("send bounded fixture response");
        }
        let _ = socket.close(None);
        return;
    }

    let body = match (target.as_str(), authorization) {
        ("/app/health", AuthorizationClass::Expected) => {
            let attempt = health_count.fetch_add(1, Ordering::AcqRel);
            let healthy = match mode {
                HealthMode::Healthy => true,
                HealthMode::StartupUnhealthy => false,
                HealthMode::TerminalUnhealthy => attempt == 0,
            };
            format!(r#"{{"authenticated":{healthy}}}"#)
        },
        ("/app/private", AuthorizationClass::Expected) => {
            format!(r#"{{"record":"{RESPONSE_CANARY}"}}"#)
        },
        (target, AuthorizationClass::Absent) if target.starts_with("/app/") => {
            "<!doctype html><html><body><main>ordinary anonymous fixture</main></body></html>"
                .to_owned()
        },
        _ => r#"{"error":true}"#.to_owned(),
    };
    let media_type = if body.starts_with("<!doctype") {
        "text/html; charset=utf-8"
    } else {
        "application/json"
    };
    let status = if body == r#"{"error":true}"# {
        "401 Unauthorized"
    } else {
        "200 OK"
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write HTTP response");
    stream.flush().expect("flush HTTP response");
}

fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
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
    command.env("NO_PROXY", "127.0.0.1,localhost");
    command.env("no_proxy", "127.0.0.1,localhost");
    command
}

fn write_websocket_policy(parent: &Path, endpoint: &str) -> PathBuf {
    let path = parent.join("websocket-policy.json");
    let document = json!({
        "schema": "security.websocket-review-policy/v1",
        "target_authorized": true,
        "messages_read_only_acknowledged": true,
        "message_content_is_non_secret": true,
        "endpoint": endpoint,
        "origin_mode": "application_origin",
        "subprotocol": null,
        "compression": false,
        "reconnect": false,
        "messages": [
            {"id": "ping", "text": FIRST_OUTBOUND,
             "expected_response": {"sha256": FIRST_INBOUND_SHA256, "length": 15}},
            {"id": "status", "text": SECOND_OUTBOUND,
             "expected_response": {"sha256": SECOND_INBOUND_SHA256, "length": 15}}
        ],
        "limits": {
            "max_inbound_message_bytes": 4096,
            "max_outbound_message_bytes": 4096,
            "max_messages": 2,
            "max_control_frames": 4,
            "max_wall_time_ms": 3000
        }
    });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("serialize WebSocket policy"),
    )
    .expect("write WebSocket policy");
    path
}

fn v1_policy(resources: &[&str]) -> String {
    let max_session_requests = resources.len() * 2 + 1;
    let resources = resources
        .iter()
        .map(|resource| format!("\"{resource}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        concat!(
            "schema = \"security.supplied-session-policy/v1\"\n",
            "principal_alias = \"fixture-ws-reader\"\n",
            "credential_mechanism = \"authorization_header\"\n",
            "health_path = \"/app/health\"\n",
            "health_json_field = \"authenticated\"\n",
            "resources = [{}]\n",
            "max_session_requests = {}\n",
            "max_total_response_bytes = 65536\n",
            "max_response_body_bytes = 16384\n",
            "max_wall_time_ms = 5000\n"
        ),
        resources, max_session_requests
    )
}

fn write_inputs(parent: &Path, endpoint: &str) -> (PathBuf, PathBuf, PathBuf) {
    let session = parent.join("session-policy.toml");
    let authorization = parent.join("authorization.secret");
    fs::write(&session, v1_policy(&["/app/private"])).expect("write session policy");
    fs::write(&authorization, format!("{AUTHORIZATION}\r\n")).expect("write Authorization input");
    (
        session,
        authorization,
        write_websocket_policy(parent, endpoint),
    )
}

fn run_scan(
    fixture: &OwnedFixture,
    session: &Path,
    authorization: &Path,
    websocket: &Path,
    destination: &Path,
    combined: bool,
) -> Output {
    let mut command = termivar();
    command
        .args(["scan", &fixture.target, "--profile", "web-review"])
        .arg("--session-policy")
        .arg(session)
        .arg("--session-auth-file")
        .arg(authorization)
        .arg("--websocket-review-policy")
        .arg(websocket);
    if combined {
        command.arg("--websocket-supplied-session");
    }
    command
        .arg("--report-dir")
        .arg(destination)
        .output()
        .expect("run actual Termivar process")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label}: process exited unsuccessfully with status {:?}",
        output.status
    );
}

fn assert_no_private_values(bytes: &[u8]) {
    let rendered = String::from_utf8_lossy(bytes);
    for private in [
        AUTHORIZATION,
        "WS-SESSION-PROCESS-CANARY",
        RESPONSE_CANARY,
        FIRST_OUTBOUND,
        SECOND_OUTBOUND,
        FIRST_INBOUND,
        SECOND_INBOUND,
        "/app/health",
        "/app/private",
        "/app/socket",
    ] {
        assert!(!rendered.contains(private), "output retained private value");
    }
}

fn read_assessment(destination: &Path) -> Value {
    let bytes = fs::read(destination.join("assessment.json")).expect("read assessment JSON");
    assert_no_private_values(&bytes);
    for entry in fs::read_dir(destination).expect("read bundle") {
        let entry = entry.expect("read bundle entry");
        if entry.file_type().expect("bundle entry type").is_file() {
            assert_no_private_values(&fs::read(entry.path()).expect("read bundle member"));
        }
    }
    serde_json::from_slice(&bytes).expect("parse assessment JSON")
}

fn authenticated_targets(records: &[RequestRecord]) -> Vec<&str> {
    records
        .iter()
        .filter(|record| record.authorization == AuthorizationClass::Expected)
        .map(|record| record.target.as_str())
        .collect()
}

fn assert_offline(destination: &Path, assessment: &Value, websocket_comparison_schema: &str) {
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(destination)
        .args(["--format", "json"])
        .output()
        .expect("run offline Verify");
    assert_success(&verify, "offline Verify");
    assert_no_private_values(&verify.stdout);
    assert_no_private_values(&verify.stderr);
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let report = destination.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run offline self-Compare");
    assert_success(&compare, "offline self-Compare");
    assert_no_private_values(&compare.stdout);
    assert_no_private_values(&compare.stderr);
    let comparison: Value = serde_json::from_slice(&compare.stdout).expect("Compare JSON");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(comparison[group], json!([]));
    }
    assert_eq!(
        comparison["unchanged"].as_array().map(Vec::len),
        assessment["items"].as_array().map(Vec::len)
    );
    let websocket = &comparison["websocket_review_comparison"];
    assert_eq!(websocket["schema"], websocket_comparison_schema);
    assert_eq!(websocket["status"], "compared");
    let facets = if websocket_comparison_schema == "termivar-websocket-review-comparison/v2" {
        &[
            "supplied_session_context",
            "methodology",
            "coverage",
            "outcome",
        ][..]
    } else {
        &["methodology", "coverage", "outcome"][..]
    };
    for facet in facets {
        assert_eq!(websocket[facet]["status"], "unchanged", "facet {facet}");
    }
}

#[test]
fn explicit_v1_composition_qualifies_one_resource_and_one_websocket_exchange() {
    let mut fixture = OwnedFixture::start(HealthMode::Healthy);
    let parent = tempfile::tempdir().expect("create private fixture directory");
    let (session, authorization, websocket) = write_inputs(parent.path(), &fixture.endpoint);

    let destination = parent.path().join("combined-bundle");
    let output = run_scan(
        &fixture,
        &session,
        &authorization,
        &websocket,
        &destination,
        true,
    );
    assert_success(&output, "combined WebSocket supplied-session scan");
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let records = fixture.records();
    assert_eq!(
        records
            .iter()
            .map(|record| {
                (
                    record.target.as_str(),
                    record.authorization,
                    record.websocket_upgrade,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("/app/health", AuthorizationClass::Expected, false),
            ("/app/private", AuthorizationClass::Expected, false),
            ("/app/socket", AuthorizationClass::Expected, true),
            ("/app/health", AuthorizationClass::Expected, false),
            ("/app/", AuthorizationClass::Absent, false),
            ("/app/", AuthorizationClass::Absent, false),
            ("/app/", AuthorizationClass::Absent, false),
        ],
        "combined review must preserve the fixed three-request ordinary anonymous root plan after the session/WebSocket window"
    );
    assert_eq!(
        authenticated_targets(&records),
        ["/app/health", "/app/private", "/app/socket", "/app/health"]
    );
    assert!(records
        .iter()
        .all(|record| record.authorization != AuthorizationClass::Unexpected));
    assert_eq!(
        records
            .iter()
            .filter(|record| record.websocket_upgrade)
            .count(),
        1
    );

    fixture.shutdown();
    let assessment = read_assessment(&destination);
    let session_audit = &assessment["supplied_session"];
    assert_eq!(
        session_audit["schema"],
        "security.supplied-session-audit/v1"
    );
    assert_eq!(session_audit["outcome"], "complete");
    assert_eq!(session_audit["coverage"], "complete");
    assert_eq!(session_audit["selected_resource_count"], 1);
    assert_eq!(session_audit["dispatched_resource_count"], 1);
    assert_eq!(session_audit["committed_resource_count"], 1);
    assert_eq!(session_audit["dispatched_request_count"], 3);

    let websocket_audit = &assessment["websocket_review"];
    assert_eq!(
        websocket_audit["schema"],
        "security.websocket-review-audit/v2"
    );
    assert_eq!(websocket_audit["context"], "supplied_session");
    assert_eq!(websocket_audit["coverage"]["connection_attempt_count"], 1);
    assert_eq!(websocket_audit["coverage"]["handshake_completed_count"], 1);
    assert_eq!(websocket_audit["coverage"]["matched_response_count"], 2);
    let context = &websocket_audit["supplied_session_context"];
    assert_eq!(context["principal_alias"], "fixture-ws-reader");
    assert_eq!(context["principal_assurance"], "operator_declared");
    assert_eq!(context["credential_mechanism"], "authorization_header");
    assert_eq!(context["session_epoch"], 1);
    assert_eq!(context["startup_health"]["outcome"], "healthy");
    assert_eq!(context["terminal_health"]["outcome"], "healthy");
    assert_eq!(context["qualification"], "context_qualified");
    assert_eq!(context["continuous_authentication_established"], false);
    assert!(websocket_audit["claim_limits"]
        .as_array()
        .expect("claim limits")
        .iter()
        .any(|claim| claim == "continuous_authentication_not_established"));
    assert_offline(
        &destination,
        &assessment,
        "termivar-websocket-review-comparison/v2",
    );
}

#[test]
fn absent_flag_remains_anonymous_and_health_loss_never_yields_a_qualified_context() {
    let mut option_off = OwnedFixture::start(HealthMode::Healthy);
    let parent = tempfile::tempdir().expect("create private option fixture");
    let (session, authorization, websocket) = write_inputs(parent.path(), &option_off.endpoint);
    let off_destination = parent.path().join("option-off");
    let output = run_scan(
        &option_off,
        &session,
        &authorization,
        &websocket,
        &off_destination,
        false,
    );
    assert_success(&output, "standalone session plus anonymous WebSocket scan");
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let off_records = option_off.records();
    assert_eq!(
        off_records
            .iter()
            .filter(|record| {
                record.target == "/app/"
                    && record.authorization == AuthorizationClass::Absent
                    && !record.websocket_upgrade
            })
            .count(),
        3,
        "the option-off run independently retains the ordinary three-request anonymous root plan"
    );
    let off_upgrade = off_records
        .iter()
        .find(|record| record.websocket_upgrade)
        .expect("anonymous WebSocket upgrade");
    assert_eq!(off_upgrade.authorization, AuthorizationClass::Absent);
    option_off.shutdown();
    let off_assessment = read_assessment(&off_destination);
    assert_eq!(
        off_assessment["websocket_review"]["schema"],
        "security.websocket-review-audit/v1"
    );
    assert_eq!(off_assessment["websocket_review"]["context"], "anonymous");
    assert!(off_assessment["websocket_review"]
        .get("supplied_session_context")
        .is_none());
    assert_offline(
        &off_destination,
        &off_assessment,
        "termivar-websocket-review-comparison/v1",
    );

    let mut startup_lost = OwnedFixture::start(HealthMode::StartupUnhealthy);
    let startup_parent = tempfile::tempdir().expect("create startup-loss fixture");
    let (session, authorization, websocket) =
        write_inputs(startup_parent.path(), &startup_lost.endpoint);
    let startup_destination = startup_parent.path().join("startup-loss");
    let output = run_scan(
        &startup_lost,
        &session,
        &authorization,
        &websocket,
        &startup_destination,
        true,
    );
    assert_success(&output, "startup-unhealthy combined scan");
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let startup_records = startup_lost.records();
    assert_eq!(authenticated_targets(&startup_records), ["/app/health"]);
    assert!(!startup_records
        .iter()
        .any(|record| record.websocket_upgrade));
    startup_lost.shutdown();
    let startup_assessment = read_assessment(&startup_destination);
    assert_eq!(
        startup_assessment["supplied_session"]["outcome"],
        "startup_unhealthy"
    );
    let startup_websocket = &startup_assessment["websocket_review"];
    assert_eq!(startup_websocket["coverage"]["connection_attempt_count"], 0);
    assert_eq!(
        startup_websocket["supplied_session_context"]["qualification"],
        "not_established"
    );
    assert_offline(
        &startup_destination,
        &startup_assessment,
        "termivar-websocket-review-comparison/v2",
    );

    let mut terminal_lost = OwnedFixture::start(HealthMode::TerminalUnhealthy);
    let terminal_parent = tempfile::tempdir().expect("create terminal-loss fixture");
    let (session, authorization, websocket) =
        write_inputs(terminal_parent.path(), &terminal_lost.endpoint);
    let terminal_destination = terminal_parent.path().join("terminal-loss");
    let output = run_scan(
        &terminal_lost,
        &session,
        &authorization,
        &websocket,
        &terminal_destination,
        true,
    );
    assert_success(&output, "terminal-unhealthy combined scan");
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let terminal_records = terminal_lost.records();
    assert_eq!(
        authenticated_targets(&terminal_records),
        ["/app/health", "/app/private", "/app/socket", "/app/health"]
    );
    terminal_lost.shutdown();
    let terminal_assessment = read_assessment(&terminal_destination);
    assert_eq!(
        terminal_assessment["supplied_session"]["outcome"],
        "session_lost"
    );
    assert_eq!(
        terminal_assessment["supplied_session"]["committed_resource_count"],
        0
    );
    let terminal_websocket = &terminal_assessment["websocket_review"];
    assert_eq!(
        terminal_websocket["coverage"]["handshake_completed_count"],
        1
    );
    assert_eq!(
        terminal_websocket["supplied_session_context"]["qualification"],
        "context_unqualified"
    );
    assert_eq!(
        terminal_websocket["supplied_session_context"]["terminal_health"]["outcome"],
        "unhealthy"
    );
    assert_offline(
        &terminal_destination,
        &terminal_assessment,
        "termivar-websocket-review-comparison/v2",
    );
}

#[test]
fn unsupported_or_multi_resource_session_fails_before_secret_or_output_acquisition() {
    let parent = tempfile::tempdir().expect("create private preflight fixture");
    let websocket = write_websocket_policy(parent.path(), "ws://127.0.0.1:9/app/socket");
    let missing_secret = parent.path().join("PRIVATE-MISSING-SESSION-SECRET");

    let v2_policy = parent.path().join("v2-session-policy.toml");
    fs::write(
        &v2_policy,
        concat!(
            "schema = \"security.supplied-session-policy/v2\"\n",
            "principal_alias = \"fixture-cookie-reader\"\n",
            "credential_mechanism = \"cookie_jar\"\n",
            "cookie_update_policy = \"stop_on_selected_cookie\"\n",
            "health_path = \"/app/health\"\n",
            "health_json_field = \"authenticated\"\n",
            "resources = [\"/app/private\"]\n",
            "max_session_requests = 3\n",
            "max_total_response_bytes = 65536\n",
            "max_response_body_bytes = 16384\n",
            "max_wall_time_ms = 5000\n",
            "[[cookies]]\n",
            "id = \"session\"\n",
            "name = \"session\"\n",
            "domain = \"127.0.0.1\"\n",
            "host_only = true\n",
            "path = \"/app/\"\n",
            "secure = false\n",
            "http_only = true\n",
            "same_site = \"strict\"\n"
        ),
    )
    .expect("write V2 policy");
    let blocked = parent.path().join("blocked-v2-output");
    fs::write(&blocked, b"unchanged sentinel").expect("write output sentinel");
    let output = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--websocket-supplied-session",
        ])
        .arg("--websocket-review-policy")
        .arg(&websocket)
        .arg("--session-policy")
        .arg(&v2_policy)
        .arg("--session-cookie-file")
        .arg(&missing_secret)
        .arg("--report-dir")
        .arg(&blocked)
        .output()
        .expect("run V2 preflight refusal");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("supports only authorization-header V1"));
    assert!(!stderr.contains("PRIVATE-MISSING-SESSION-SECRET"));
    assert_eq!(fs::read(&blocked).unwrap(), b"unchanged sentinel");

    let multi_policy = parent.path().join("multi-resource-session-policy.toml");
    fs::write(
        &multi_policy,
        v1_policy(&["/app/private", "/app/private-two"]),
    )
    .expect("write multi-resource policy");
    let blocked = parent.path().join("blocked-multi-output");
    fs::write(&blocked, b"unchanged sentinel").expect("write output sentinel");
    let output = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--websocket-supplied-session",
        ])
        .arg("--websocket-review-policy")
        .arg(&websocket)
        .arg("--session-policy")
        .arg(&multi_policy)
        .arg("--session-auth-file")
        .arg(&missing_secret)
        .arg("--report-dir")
        .arg(&blocked)
        .output()
        .expect("run multi-resource preflight refusal");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires exactly one selected session resource"),
        "unexpected multi-resource refusal: {stderr}"
    );
    assert!(!stderr.contains("PRIVATE-MISSING-SESSION-SECRET"));
    assert_eq!(fs::read(&blocked).unwrap(), b"unchanged sentinel");
}
