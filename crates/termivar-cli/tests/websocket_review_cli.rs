//! Actual-process acceptance for the opt-in bounded WebSocket review.
//!
//! The owned numeric-loopback fixture shares one port between ordinary HTTP
//! assessment traffic and one WebSocket upgrade. Tests exercise the public CLI
//! and saved report path; no public target or ambient credential is used.

#![cfg(feature = "websocket-review")]

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
use tokio_tungstenite::tungstenite::{
    handshake::derive_accept_key,
    protocol::{Role, WebSocket},
    Message,
};

const FIRST_OUTBOUND: &str = r#"{"type":"ping"}"#;
const SECOND_OUTBOUND: &str = r#"{"type":"status"}"#;
const FIRST_INBOUND: &str = r#"{"type":"pong"}"#;
const SECOND_INBOUND: &str = r#"{"status":"ok"}"#;
const FIRST_INBOUND_SHA256: &str =
    "b94f1fbb072a53089df2bd74bd78c1a4d4ef81f6c0e9c316492583edc79830d3";
const SECOND_INBOUND_SHA256: &str =
    "a29ee2b15c494311c52521766e44af56a3ad2248e7a8ab465e5206463c13d288";
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum FixtureEvent {
    Http(String),
    Upgrade {
        request_line: String,
        origin: Option<String>,
        cookie_present: bool,
        authorization_present: bool,
        proxy_authorization_present: bool,
        extension_present: bool,
    },
    ClientText(String),
}

struct OwnedFixture {
    address: SocketAddr,
    target: String,
    endpoint: String,
    events: Arc<Mutex<Vec<FixtureEvent>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl OwnedFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind owned loopback fixture");
        let address = listener.local_addr().expect("fixture address");
        let events = Arc::new(Mutex::new(Vec::new()));
        let worker_events = Arc::clone(&events);
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
                handle_connection(&mut stream, worker_events.as_ref());
            }
        });
        Self {
            address,
            target: format!("http://{address}/app/"),
            endpoint: format!("ws://{address}/app/socket"),
            events,
            stop,
            worker: Some(worker),
        }
    }

    fn events(&self) -> Vec<FixtureEvent> {
        self.events.lock().expect("event lock").clone()
    }

    fn clear_events(&self) {
        self.events.lock().expect("event lock").clear();
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

fn handle_connection(stream: &mut TcpStream, events: &Mutex<Vec<FixtureEvent>>) {
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
    let request = String::from_utf8_lossy(&captured).into_owned();
    let request_line = request.lines().next().unwrap_or_default().to_owned();
    if request_line == "GET /app/socket HTTP/1.1"
        && header(&request, "upgrade") == Some("websocket")
    {
        let key = header(&request, "sec-websocket-key").expect("upgrade key");
        events
            .lock()
            .expect("event lock")
            .push(FixtureEvent::Upgrade {
                request_line,
                origin: header(&request, "origin").map(str::to_owned),
                cookie_present: header(&request, "cookie").is_some(),
                authorization_present: header(&request, "authorization").is_some(),
                proxy_authorization_present: header(&request, "proxy-authorization").is_some(),
                extension_present: header(&request, "sec-websocket-extensions").is_some(),
            });
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
            .expect("write upgrade");
        stream.flush().expect("flush upgrade");
        let owned = stream.try_clone().expect("clone upgraded stream");
        let mut socket = WebSocket::from_raw_socket(owned, Role::Server, None);
        for (expected, response) in [
            (FIRST_OUTBOUND, FIRST_INBOUND),
            (SECOND_OUTBOUND, SECOND_INBOUND),
        ] {
            let message = socket.read().expect("read client message");
            let text = message.into_text().expect("client text message");
            events
                .lock()
                .expect("event lock")
                .push(FixtureEvent::ClientText(text.to_string()));
            assert_eq!(text.as_str(), expected);
            socket
                .send(Message::Text(response.into()))
                .expect("send fixture response");
        }
        let _ = socket.close(None);
        return;
    }

    events
        .lock()
        .expect("event lock")
        .push(FixtureEvent::Http(request_line));
    let body = b"<!doctype html><html><body><main>owned websocket fixture</main></body></html>";
    let head = format!(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n\r\n"
        ),
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write HTTP head");
    stream.write_all(body).expect("write HTTP body");
    stream.flush().expect("flush HTTP response");
}

fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn write_policy(directory: &Path, endpoint: &str, target_authorized: bool) -> PathBuf {
    let document = json!({
        "schema": "security.websocket-review-policy/v1",
        "target_authorized": target_authorized,
        "messages_read_only_acknowledged": true,
        "message_content_is_non_secret": true,
        "endpoint": endpoint,
        "origin_mode": "application_origin",
        "subprotocol": null,
        "compression": false,
        "reconnect": false,
        "messages": [
            {
                "id": "ping",
                "text": FIRST_OUTBOUND,
                "expected_response": {
                    "sha256": FIRST_INBOUND_SHA256,
                    "length": 15,
                }
            },
            {
                "id": "status",
                "text": SECOND_OUTBOUND,
                "expected_response": {
                    "sha256": SECOND_INBOUND_SHA256,
                    "length": 15,
                }
            }
        ],
        "limits": {
            "max_inbound_message_bytes": 4096,
            "max_outbound_message_bytes": 4096,
            "max_messages": 2,
            "max_control_frames": 4,
            "max_wall_time_ms": 3000,
        }
    });
    let path = directory.join(if target_authorized {
        "websocket-review.json"
    } else {
        "PRIVATE-unauthorized-websocket-review.json"
    });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("serialize policy"),
    )
    .expect("write policy");
    path
}

fn run_scan(target: &str, destination: &Path, policy: Option<&Path>) -> Output {
    let mut command = termivar();
    command
        .args(["scan", target, "--profile", "web-review"])
        .arg("--report-dir")
        .arg(destination);
    if let Some(policy) = policy {
        command.arg("--websocket-review-policy").arg(policy);
    }
    command.output().expect("run actual Termivar process")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label}: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_bundle(directory: &Path) -> Value {
    let mut names = fs::read_dir(directory)
        .expect("read bundle")
        .map(|entry| {
            entry
                .expect("bundle entry")
                .file_name()
                .into_string()
                .expect("fixed filename")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["assessment.html", JSON_NAME, "manifest.json"]);
    serde_json::from_slice(&fs::read(directory.join(JSON_NAME)).expect("read assessment"))
        .expect("parse assessment")
}

fn run_offline_acceptance(directory: &Path, assessment: &Value) {
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"])
        .output()
        .expect("run offline Verify");
    assert_success(&verify, "offline Verify");
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let report = directory.join(JSON_NAME);
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run offline Compare");
    assert_success(&compare, "offline self-Compare");
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
    assert_eq!(websocket["status"], "compared");
    for facet in ["methodology", "coverage", "outcome"] {
        assert_eq!(websocket[facet]["status"], "unchanged", "facet {facet}");
    }
}

#[test]
fn malformed_policy_fails_before_output_or_transport() {
    let fixture = OwnedFixture::start();
    let directory = tempfile::tempdir().unwrap();
    let policy = write_policy(directory.path(), &fixture.endpoint, false);
    let output = run_scan(
        &fixture.target,
        &directory.path().join("must-not-exist"),
        Some(&policy),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!directory.path().join("must-not-exist").exists());
    assert!(fixture.events().is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("InvalidDocument"));
    assert!(!stderr.contains("PRIVATE-unauthorized"));
    assert!(!stderr.contains(&fixture.endpoint));
}

#[test]
fn actual_cli_uses_one_anonymous_connection_and_remains_offline_readable() {
    let mut fixture = OwnedFixture::start();
    let directory = tempfile::tempdir().unwrap();

    let option_off = directory.path().join("option-off");
    let output = run_scan(&fixture.target, &option_off, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("assessment_subject_identity_unavailable")
    );
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("profiled assessment did not complete within its authority"));
    assert!(!option_off.exists());
    let option_off_http = fixture
        .events()
        .into_iter()
        .filter_map(|event| match event {
            FixtureEvent::Http(request_line) => Some(request_line),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!option_off_http.is_empty());
    assert!(fixture.events().iter().all(|event| !matches!(
        event,
        FixtureEvent::Upgrade { .. } | FixtureEvent::ClientText(_)
    )));
    fixture.clear_events();

    let policy = write_policy(directory.path(), &fixture.endpoint, true);
    let option_on = directory.path().join("option-on");
    let output = run_scan(&fixture.target, &option_on, Some(&policy));
    assert_success(&output, "WebSocket review scan");
    let events = fixture.events();
    let option_on_http = events
        .iter()
        .filter_map(|event| match event {
            FixtureEvent::Http(request_line) => Some(request_line.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        option_on_http, option_off_http,
        "ordinary HTTP plan changed"
    );
    let upgrades = events
        .iter()
        .filter_map(|event| match event {
            FixtureEvent::Upgrade {
                request_line,
                origin,
                cookie_present,
                authorization_present,
                proxy_authorization_present,
                extension_present,
            } => Some((
                request_line,
                origin,
                cookie_present,
                authorization_present,
                proxy_authorization_present,
                extension_present,
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(upgrades.len(), 1);
    assert_eq!(upgrades[0].0, "GET /app/socket HTTP/1.1");
    let expected_origin = format!("http://{}", fixture.address);
    assert_eq!(upgrades[0].1.as_deref(), Some(expected_origin.as_str()));
    assert!(!*upgrades[0].2);
    assert!(!*upgrades[0].3);
    assert!(!*upgrades[0].4);
    assert!(!*upgrades[0].5);
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event {
                FixtureEvent::ClientText(text) => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [FIRST_OUTBOUND, SECOND_OUTBOUND]
    );

    fixture.shutdown();
    let assessment = read_bundle(&option_on);
    let serialized = serde_json::to_string(&assessment).expect("serialize public report");
    for private in [
        FIRST_OUTBOUND,
        SECOND_OUTBOUND,
        FIRST_INBOUND,
        SECOND_INBOUND,
        "/app/socket",
    ] {
        assert!(!serialized.contains(private), "report leaked {private:?}");
    }
    let audit = &assessment["websocket_review"];
    assert_eq!(audit["schema"], "security.websocket-review-audit/v1");
    assert_eq!(audit["selected"], true);
    assert_eq!(audit["context"], "anonymous");
    assert_eq!(audit["coverage"]["connection_attempt_count"], 1);
    assert_eq!(audit["coverage"]["handshake_completed_count"], 1);
    assert_eq!(audit["coverage"]["outbound_message_count"], 2);
    assert_eq!(audit["coverage"]["inbound_message_count"], 2);
    assert_eq!(audit["coverage"]["outbound_application_bytes"], 32);
    assert_eq!(audit["coverage"]["inbound_application_bytes"], 30);
    assert_eq!(audit["coverage"]["expected_response_count"], 2);
    assert_eq!(audit["coverage"]["matched_response_count"], 2);
    assert_eq!(audit["coverage"]["mismatched_response_count"], 0);
    assert_eq!(audit["coverage"]["terminal"], "completed");
    assert_eq!(audit["messages"].as_array().map(Vec::len), Some(2));
    run_offline_acceptance(&option_on, &assessment);
}
