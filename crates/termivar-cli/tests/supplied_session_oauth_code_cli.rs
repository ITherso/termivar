//! Actual-process tests over original synthetic IdP/application responses.
//! These are not a real IdP or interactive OAuth/OIDC qualification.
#![cfg(feature = "supplied-session-review")]

use serde_json::Value;
use sha2::{Digest, Sha256};
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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static SERIAL: Mutex<()> = Mutex::new(());
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CODE: &str = "SYNTHETIC_OAUTH_CODE_A_0123456789";
// Original non-provider Bearer fixtures, not operational service keys. The
// separate anonymous positive control proves the body's detector meaning.
const ACCESS: &str = "SYNTHETIC_OAUTH_ACCESS_CANARY_A_0123456789";
const REFRESH: &str = "SYNTHETIC_REFRESH_OAUTH_CANARY_0123456789";
const PRIVATE_TOKEN: &str = "SYNTHETIC_PRIVATE_OAUTH_CANARY_0123456789";
const PRIVATE_BODY: &str = "authorization = \"Bearer SYNTHETIC_PRIVATE_OAUTH_CANARY_0123456789\"";
const EXPECTED_FORM: &str = concat!(
    "grant_type=authorization_code&client_id=owned-public&redirect_uri=",
    "http%3A%2F%2F127.0.0.1%3A1%2Fcallback&code=SYNTHETIC_OAUTH_CODE_A_0123456789",
    "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Ordinary,
    Token,
    Health,
    One,
    Two,
    Unexpected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    Absent,
    Expected,
    Unexpected,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    role: Role,
    method: String,
    auth: Auth,
    cookie: bool,
    exact_form: bool,
    identity_requested: bool,
}
#[derive(Clone, Copy)]
enum Mode {
    Success,
    PublicExposureControl,
    BadRequest,
    Throttled,
    Redirect,
    Coded,
    Html,
    InvalidJson,
    WrongScope,
    IdToken,
    Dpop,
    Truncated,
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(idp: bool, mode: Mode, healthy: bool, trace: Arc<Mutex<Vec<Request>>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind owned numeric loopback");
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            for accepted in listener.incoming() {
                let Ok(mut stream) = accepted else {
                    break;
                };
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let request = read_request(&mut stream, idp);
                let reply = if idp {
                    let valid = request.role == Role::Token
                        && request.method == "POST"
                        && request.auth == Auth::Absent
                        && !request.cookie
                        && request.exact_form
                        && request.identity_requested;
                    if valid {
                        idp_reply(mode, address)
                    } else {
                        response("400 Bad Request", "application/json", b"{}", "", None)
                    }
                } else {
                    match request.role {
                        Role::Health => response("200 OK", "application/json", if healthy && request.auth == Auth::Expected {
                            br#"{"authenticated":true}"#
                        } else { br#"{"authenticated":false}"# }, "", None),
                        Role::One | Role::Two if request.auth == Auth::Expected => {
                            response("200 OK", "text/plain", PRIVATE_BODY.as_bytes(), "", None)
                        },
                        Role::One | Role::Two => response("403 Forbidden", "text/plain", b"not authorized", "", None),
                        _ if matches!(mode, Mode::PublicExposureControl) => response("200 OK", "text/plain", PRIVATE_BODY.as_bytes(), "", None),
                        _ => response("200 OK", "text/html", b"<!doctype html><title>Owned OAuth fixture</title><p>Original harmless fixture.</p>", "", None),
                    }
                };
                trace.lock().unwrap().push(request);
                let _ = stream.write_all(&reply);
                let _ = stream.flush();
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }
    fn stop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stop.store(true, Ordering::Release);
            // Fixture-owned accept wakeup, not a scanner HTTP request.
            let _ = TcpStream::connect(self.address);
            worker.join().expect("stop owned fixture");
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_request(stream: &mut TcpStream, idp: bool) -> Request {
    const MAX: usize = 24 * 1024;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 2048];
    let (headers_end, body_len) = loop {
        let length = stream.read(&mut chunk).expect("read bounded owned request");
        assert!(length > 0 && bytes.len() + length <= MAX, "request bounds");
        bytes.extend_from_slice(&chunk[..length]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..index]).expect("owned request headers");
            let mut body_len = 0;
            for line in headers.split("\r\n").skip(1) {
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        body_len = value.trim().parse::<usize>().expect("request byte count");
                    }
                }
            }
            assert!(index + 4 + body_len <= MAX, "request body bounds");
            break (index + 4, body_len);
        }
    };
    while bytes.len() < headers_end + body_len {
        let length = stream.read(&mut chunk).expect("read bounded owned form");
        assert!(length > 0 && bytes.len() + length <= MAX, "form bounds");
        bytes.extend_from_slice(&chunk[..length]);
    }
    let headers = std::str::from_utf8(&bytes[..headers_end - 4]).unwrap();
    let mut lines = headers.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let path = first.next().unwrap();
    let role = match (idp, path) {
        (true, "/realm/token") => Role::Token,
        (true, _) => Role::Unexpected,
        (false, "/app/health") => Role::Health,
        (false, "/app/private/one") => Role::One,
        (false, "/app/private/two") => Role::Two,
        (false, _) => Role::Ordinary,
    };
    let mut auth = Auth::Absent;
    let mut cookie = false;
    let mut form_type = false;
    let mut identity_requested = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                auth = if value.trim() == format!("Bearer {ACCESS}") {
                    Auth::Expected
                } else {
                    Auth::Unexpected
                };
            }
            if name.eq_ignore_ascii_case("cookie") {
                cookie = true;
            }
            if name.eq_ignore_ascii_case("content-type") {
                form_type = value.trim() == "application/x-www-form-urlencoded";
            }
            if name.eq_ignore_ascii_case("accept-encoding") {
                identity_requested = value.trim() == "identity";
            }
        }
    }
    Request {
        role,
        method,
        auth,
        cookie,
        identity_requested,
        exact_form: form_type
            && &bytes[headers_end..headers_end + body_len] == EXPECTED_FORM.as_bytes(),
    }
}

fn response(
    status: &str,
    media: &str,
    body: &[u8],
    extra: &str,
    declared: Option<usize>,
) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", declared.unwrap_or(body.len())).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn token_json() -> String {
    format!(
        r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":60,"scope":"canary-read","refresh_token":"{REFRESH}","provider_extension":{{"inert":"not-an-instruction"}}}}"#
    )
}
fn idp_reply(mode: Mode, address: SocketAddr) -> Vec<u8> {
    let json = token_json();
    match mode {
        Mode::Success | Mode::PublicExposureControl => response(
            "200 OK",
            "application/json;charset=utf-8",
            json.as_bytes(),
            "",
            None,
        ),
        Mode::BadRequest => response(
            "400 Bad Request",
            "application/json",
            format!(
                r#"{{"error":"invalid_grant","error_description":"{CODE} {VERIFIER} {REFRESH}"}}"#
            )
            .as_bytes(),
            "",
            None,
        ),
        Mode::Throttled => response("429 Too Many Requests", "application/json", b"{}", "", None),
        Mode::Redirect => response(
            "302 Found",
            "application/json",
            b"{}",
            &format!("Location: http://{address}/never\r\n"),
            None,
        ),
        // Deliberate coding/header contradiction: deleting the absent-coding
        // guard would wrongly promote these otherwise valid JSON bytes.
        Mode::Coded => response(
            "200 OK",
            "application/json",
            json.as_bytes(),
            "Content-Encoding: gzip\r\n",
            None,
        ),
        Mode::Html => response("200 OK", "text/html", json.as_bytes(), "", None),
        Mode::InvalidJson => response(
            "200 OK",
            "application/json",
            format!("{{{ACCESS}").as_bytes(),
            "",
            None,
        ),
        Mode::WrongScope => response(
            "200 OK",
            "application/json",
            json.replace("canary-read", "different-scope").as_bytes(),
            "",
            None,
        ),
        Mode::IdToken => response(
            "200 OK",
            "application/json",
            json.replacen('{', "{\"id_token\":\"SYNTHETIC_UNVALIDATED_ID_TOKEN\",", 1)
                .as_bytes(),
            "",
            None,
        ),
        Mode::Dpop => response(
            "200 OK",
            "application/json",
            json.replace("Bearer", "DPoP").as_bytes(),
            "",
            None,
        ),
        Mode::Truncated => response(
            "200 OK",
            "application/json",
            json.as_bytes(),
            "",
            Some(json.len() + 10),
        ),
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
// Same bounded actual-process pattern as the reviewed privacy CLI helpers.
fn run(mut command: Command) -> Output {
    const LIMIT: u64 = 1024 * 1024;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn owned actual CLI");
    let capture = |pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .expect("bounded process output");
            bytes
        })
    };
    let stdout = capture(Box::new(child.stdout.take().unwrap()));
    let stderr = capture(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll owned CLI") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            panic!("owned OAuth CLI exceeded its deadline");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    assert!(
        stdout.len() <= LIMIT as usize && stderr.len() <= LIMIT as usize,
        "process output bounds"
    );
    Output {
        status,
        stdout,
        stderr,
    }
}
fn private_values_absent(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for value in [
        CODE,
        VERIFIER,
        CHALLENGE,
        ACCESS,
        REFRESH,
        PRIVATE_TOKEN,
        PRIVATE_BODY,
        EXPECTED_FORM,
        "SYNTHETIC_UNVALIDATED_ID_TOKEN",
    ] {
        assert!(
            !text.contains(value),
            "private synthetic material reached a saved/output sink"
        );
        let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
        assert!(
            !text.contains(&digest),
            "unkeyed secret/body identity reached a saved/output sink"
        );
    }
    let body_digest = format!("{:x}", Sha256::digest(token_json().as_bytes()));
    assert!(
        !text.contains(&body_digest),
        "raw token response digest reached a sink"
    );
    let header_digest = format!(
        "{:x}",
        Sha256::digest(format!("Bearer {ACCESS}").as_bytes())
    );
    assert!(
        !text.contains(&header_digest),
        "whole credential header digest reached a sink"
    );
}
fn inputs(root: &Path, issuer_origin: &str) -> (PathBuf, PathBuf) {
    let policy = root.join("oauth-policy.toml");
    let grant = root.join("oauth-secret.tsv");
    fs::write(
        &policy,
        format!(
            r#"schema = "security.supplied-session-policy/v5"
principal_alias = "canary-a"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 6
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000
[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "owned-numeric-loopback-http/v1"
issuer = "{issuer_origin}/realm"
token_endpoint = "{issuer_origin}/realm/token"
client_id = "owned-public"
redirect_uri = "http://127.0.0.1:1/callback"
scopes = ["canary-read"]
max_token_response_bytes = 8192
"#
        ),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fs::write(&grant, format!("authorization_code\t{CODE}\ncode_verifier\t{VERIFIER}\ncode_challenge\t{CHALLENGE}\nissuer\t{issuer_origin}/realm\nclient_id\towned-public\nredirect_uri\thttp://127.0.0.1:1/callback\nscope\tcanary-read\nreceived_unix_seconds\t{now}\n")).unwrap();
    (policy, grant)
}
fn scan(application: &str, files: Option<(&Path, &Path)>, destination: &Path) -> Output {
    scan_with_privacy(application, files, destination, false)
}
fn scan_with_privacy(
    application: &str,
    files: Option<(&Path, &Path)>,
    destination: &Path,
    privacy: bool,
) -> Output {
    let mut command = termivar();
    command.args([
        "scan",
        application,
        "--profile",
        "web-review",
        "--format",
        "json",
    ]);
    if privacy {
        command.arg("--secret-exposure-review");
    }
    if let Some((policy, grant)) = files {
        command
            .arg("--session-policy")
            .arg(policy)
            .arg("--session-oauth-code-file")
            .arg(grant);
    }
    command.arg("--report-dir").arg(destination);
    let output = run(command);
    private_values_absent(&output.stdout);
    private_values_absent(&output.stderr);
    if !output.status.success() {
        // Closed, value-safe diagnostics: never render raw process output, paths,
        // response content, headers or the secret transaction.
        let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let known_error = [
            "SecretExposureAuditMismatch",
            "secret-exposure review audit does not match committed item truth",
            "ProjectionInvariant",
            "InvalidDocument",
            "comparison input has invalid or inconsistent fields",
            "RunEnvelopeInvalid",
            "AssessmentIncomplete",
            "SubjectReferenceMismatch",
            "rendered report serialization failed",
        ]
        .into_iter()
        .find(|code| stderr.contains(code));
        // Permit only a single bounded enum-shaped classification, never error
        // arguments, paths, URLs, quoted values or arbitrary response prose.
        let bare_error = stderr.lines().find_map(|line| {
            line.strip_prefix("Error: ").filter(|value| {
                !value.is_empty()
                    && value.len() <= 64
                    && value.as_bytes()[0].is_ascii_uppercase()
                    && value.bytes().all(|byte| byte.is_ascii_alphabetic())
            })
        });
        eprintln!(
            "synthetic CLI failure: exit={:?}; disposition={:?}; reasons={:?}; usage={:?}; runtime_error={}; publication_error={}; input_error={}; known_error={:?}; bare_error={:?}; stdout_bytes={}; stderr_bytes={}",
            output.status.code(),
            parsed.get("disposition"),
            parsed.get("incomplete_reasons"),
            parsed.pointer("/assessment/report/usage"),
            stderr.contains("assessment failed after execution started"),
            stderr.contains("publication") || stderr.contains("report bundle"),
            stderr.contains("invalid") || stderr.contains("policy"),
            known_error,
            bare_error,
            output.stdout.len(),
            output.stderr.len()
        );
    }
    output
}
fn assessment(destination: &Path) -> Value {
    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        private_values_absent(
            &fs::read(destination.join(name)).expect("actual complete bundle member"),
        );
    }
    serde_json::from_slice(&fs::read(destination.join("assessment.json")).unwrap()).unwrap()
}
fn offline(destination: &Path, source: &Value) {
    let before: Vec<_> = ["assessment.html", "assessment.json", "manifest.json"]
        .iter()
        .map(|name| fs::read(destination.join(name)).unwrap())
        .collect();
    let mut verify = termivar();
    verify
        .args(["report", "verify", "--dir"])
        .arg(destination)
        .args(["--format", "json"]);
    let output = run(verify);
    private_values_absent(&output.stdout);
    private_values_absent(&output.stderr);
    assert!(output.status.success(), "offline Verify process failed");
    let verified: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(verified["status"] == "integrity_match");
    let mut compare = termivar();
    compare
        .args(["report", "compare", "--before"])
        .arg(destination.join("assessment.json"))
        .arg("--after")
        .arg(destination.join("assessment.json"))
        .args(["--same-scope", "--format", "json"]);
    let output = run(compare);
    private_values_absent(&output.stdout);
    private_values_absent(&output.stderr);
    assert!(
        output.status.success(),
        "offline self-Compare process failed"
    );
    let compared: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(compared["schema"] == "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(compared[group]
            .as_array()
            .expect("real array contract")
            .is_empty());
    }
    let count = source["item_count"]
        .as_u64()
        .expect("integer source item count");
    assert!(count > 0);
    assert_eq!(
        compared["unchanged"].as_array().unwrap().len() as u64,
        count
    );
    if source.get("supplied_session").is_some() {
        assert!(
            compared["supplied_session_comparison"]["status"]
                == "compared_within_same_declared_context"
        );
    }
    for (index, name) in ["assessment.html", "assessment.json", "manifest.json"]
        .iter()
        .enumerate()
    {
        assert!(
            fs::read(destination.join(name)).unwrap() == before[index],
            "offline operation changed bundle bytes"
        );
    }
}

#[test]
fn oauth_code_real_cli_acquires_once_then_qualifies_existing_bearer_resources_offline() {
    let _serial = SERIAL.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut target = Server::start(false, Mode::Success, true, Arc::clone(&trace));
    let mut idp = Server::start(true, Mode::Success, true, Arc::clone(&trace));
    // The anonymous baseline deliberately uses its supported root projection.
    // An unselected anonymous subpath has a pre-existing incomplete identity
    // outcome; this feature does not change that unrelated contract.
    let application = format!("{}/", target.origin());
    let off_dir = root.path().join("off");
    let off = scan(&application, None, &off_dir);
    assert!(off.status.success(), "ordinary baseline failed");
    let off_trace = trace.lock().unwrap().clone();
    assert!(
        !off_trace.is_empty()
            && off_trace
                .iter()
                .all(|row| row.auth == Auth::Absent && row.role == Role::Ordinary)
    );
    let (policy, grant) = inputs(root.path(), &idp.origin());
    let original_grant = fs::read(&grant).unwrap();
    let original_policy = fs::read(&policy).unwrap();
    let on_dir = root.path().join("on");
    let on = scan(&application, Some((&policy, &grant)), &on_dir);
    assert!(
        on.status.success(),
        "OAuth actual CLI did not complete the expected session"
    );
    let all = trace.lock().unwrap().clone();
    let on_trace = &all[off_trace.len()..];
    let ordinary: Vec<_> = on_trace
        .iter()
        .filter(|row| row.role == Role::Ordinary)
        .cloned()
        .collect();
    assert!(
        ordinary == off_trace,
        "new option changed ordinary page request method/order"
    );
    let session: Vec<_> = on_trace
        .iter()
        .filter(|row| row.role != Role::Ordinary)
        .collect();
    assert_eq!(
        session.iter().map(|row| row.role).collect::<Vec<_>>(),
        [
            Role::Token,
            Role::Health,
            Role::One,
            Role::Health,
            Role::Two,
            Role::Health
        ]
    );
    assert!(
        session[0].auth == Auth::Absent && session[0].exact_form && session[0].identity_requested
    );
    assert!(session[1..]
        .iter()
        .all(|row| row.auth == Auth::Expected && row.method == "GET"));
    assert!(all
        .iter()
        .all(|row| !row.cookie && row.auth != Auth::Unexpected));
    let document = assessment(&on_dir);
    let audit = &document["supplied_session"];
    assert!(
        audit["schema"] == "security.supplied-session-audit/v5" && audit["outcome"] == "complete"
    );
    assert_eq!(audit["dispatched_request_count"].as_u64(), Some(6));
    assert_eq!(audit["committed_resource_count"].as_u64(), Some(2));
    let code = &audit["oauth_code"];
    for key in [
        "request_attempt_count",
        "request_admitted_count",
        "response_completed_count",
        "credential_commit_count",
    ] {
        assert_eq!(code[key].as_u64(), Some(1));
    }
    assert!(
        code["outcome"] == "credential_committed"
            && code["transaction_context_assurance"] == "operator_declared_external_transaction"
    );
    assert!(code["response_scope_matched"] == true && code["refresh_token_returned"] == true);
    for field in [
        "authorization_initiated",
        "browser_callback_received",
        "state_nonce_verified",
        "oidc_identity_validation_performed",
        "token_signature_validation_performed",
    ] {
        assert!(code[field] == false);
    }
    assert_eq!(
        code["response_bytes"].as_u64(),
        Some(token_json().len() as u64)
    );
    assert!(
        fs::read(&grant).unwrap() == original_grant
            && fs::read(&policy).unwrap() == original_policy
    );
    target.stop();
    idp.stop();
    let stopped_trace = trace.lock().unwrap().clone();
    offline(&on_dir, &document);
    offline(&off_dir, &assessment(&off_dir));
    assert!(
        trace.lock().unwrap().as_slice() == stopped_trace,
        "offline operation contacted fixture"
    );
}

#[cfg(feature = "secret-exposure-review")]
#[test]
fn oauth_code_real_cli_does_not_select_idp_or_bearer_bodies_as_anonymous_secret_exposure() {
    let _serial = SERIAL.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut target = Server::start(false, Mode::Success, true, Arc::clone(&trace));
    let mut idp = Server::start(true, Mode::Success, true, Arc::clone(&trace));
    let (policy, grant) = inputs(root.path(), &idp.origin());
    let destination = root.path().join("privacy");
    let output = scan_with_privacy(
        &format!("{}/", target.origin()),
        Some((&policy, &grant)),
        &destination,
        true,
    );
    assert!(
        output.status.success(),
        "selected privacy/session process failed"
    );
    let document = assessment(&destination);
    assert_eq!(document["supplied_session"]["outcome"], "complete");
    assert_eq!(document["supplied_session"]["dispatched_request_count"], 6);
    let privacy = &document["secret_exposure_review"];
    assert_eq!(privacy["selected"], true);
    assert_eq!(privacy["context"], "anonymous-ordinary-get");
    assert_eq!(privacy["additional_request_count"], 0);
    assert_eq!(privacy["response_count"], 1);
    assert_eq!(privacy["evaluated_response_count"], 1);
    assert_eq!(privacy["observation_count"], 0);
    assert_eq!(privacy["match_occurrence_count"], 0);
    assert!(privacy["observations"].as_array().unwrap().is_empty());
    let rows = trace.lock().unwrap().clone();
    assert_eq!(rows.iter().filter(|row| row.role == Role::Token).count(), 1);
    assert_eq!(
        rows.iter().filter(|row| row.role == Role::Health).count(),
        3
    );
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row.role, Role::One | Role::Two))
            .count(),
        2
    );
    assert!(rows
        .iter()
        .all(|row| !row.cookie && row.auth != Auth::Unexpected));
    target.stop();
    idp.stop();
    offline(&destination, &document);
    assert!(trace.lock().unwrap().as_slice() == rows);
}

#[cfg(feature = "secret-exposure-review")]
#[test]
fn oauth_code_anonymous_positive_control_detects_the_same_original_bearer_body_without_a_provider_key(
) {
    let _serial = SERIAL.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut target = Server::start(
        false,
        Mode::PublicExposureControl,
        false,
        Arc::clone(&trace),
    );
    let destination = root.path().join("anonymous-positive");
    let output = scan_with_privacy(&format!("{}/", target.origin()), None, &destination, true);
    assert!(output.status.success(), "anonymous body control failed");
    let document = assessment(&destination);
    assert!(document.get("supplied_session").is_none());
    let privacy = &document["secret_exposure_review"];
    assert_eq!(privacy["context"], "anonymous-ordinary-get");
    assert_eq!(privacy["additional_request_count"], 0);
    assert_eq!(privacy["observation_count"], 1);
    assert_eq!(privacy["match_occurrence_count"], 1);
    assert_eq!(privacy["observations"].as_array().unwrap().len(), 1);
    assert!(document["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["capability_id"] == "exposure.response-bearer-authorization@1"));
    let rows = trace.lock().unwrap().clone();
    assert!(rows
        .iter()
        .all(|row| row.role == Role::Ordinary && row.auth == Auth::Absent && !row.cookie));
    target.stop();
    offline(&destination, &document);
    assert!(trace.lock().unwrap().as_slice() == rows);
}

#[test]
fn oauth_code_real_cli_preflight_refuses_unsafe_or_inconsistent_inputs_without_target_activity() {
    let _serial = SERIAL.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut target = Server::start(false, Mode::Success, true, Arc::clone(&trace));
    let mut idp = Server::start(true, Mode::Success, true, Arc::clone(&trace));
    let application = format!("{}/", target.origin());
    let (policy, grant) = inputs(root.path(), &idp.origin());
    let original_policy = fs::read_to_string(&policy).unwrap();
    let original_grant = fs::read_to_string(&grant).unwrap();
    for case in 0..5 {
        let destination = root.path().join(format!("preflight-{case}"));
        let secret = if case == 1 {
            root.path().join("not-present.secret.tsv")
        } else {
            grant.clone()
        };
        fs::write(
            &policy,
            if case == 0 {
                original_policy.replace(
                    "transport_profile = \"owned-numeric-loopback-http/v1\"",
                    "transport_profile = \"verified-https/v1\"",
                )
            } else if case == 1 {
                original_policy.replace(
                    "max_token_response_bytes = 8192",
                    "max_token_response_bytes = 32768",
                )
            } else {
                original_policy.clone()
            },
        )
        .unwrap();
        fs::write(
            &grant,
            if case == 2 {
                original_grant.replace(CHALLENGE, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            } else if case == 3 {
                original_grant
                    .lines()
                    .map(|line| {
                        if line.starts_with("received_unix_seconds\t") {
                            "received_unix_seconds\t0".to_owned()
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                original_grant.clone()
            },
        )
        .unwrap();
        if case == 4 {
            fs::create_dir(&destination).unwrap();
            fs::write(
                destination.join("owner-marker"),
                b"untouched original marker",
            )
            .unwrap();
        }
        let output = scan(&application, Some((&policy, &secret)), &destination);
        assert!(
            !output.status.success(),
            "invalid selected input was accepted, case {case}"
        );
        assert!(
            trace.lock().unwrap().is_empty(),
            "preflight contacted a fixture, case {case}"
        );
        for path in [&policy, &secret] {
            let text = path.to_string_lossy();
            assert!(!String::from_utf8_lossy(&output.stderr).contains(text.as_ref()));
            assert!(!String::from_utf8_lossy(&output.stdout).contains(text.as_ref()));
        }
        if case == 4 {
            assert!(
                fs::read(destination.join("owner-marker")).unwrap() == b"untouched original marker"
            );
            assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
        } else {
            assert!(
                !destination.exists(),
                "preflight left a reserved output, case {case}"
            );
        }
    }
    target.stop();
    idp.stop();
}

#[test]
fn oauth_code_real_cli_refuses_bad_responses_without_retry_or_target_credential_dispatch() {
    let _serial = SERIAL.lock().unwrap();
    for mode in [
        Mode::BadRequest,
        Mode::Throttled,
        Mode::Redirect,
        Mode::Coded,
        Mode::Html,
        Mode::InvalidJson,
        Mode::WrongScope,
        Mode::IdToken,
        Mode::Dpop,
        Mode::Truncated,
    ] {
        let root = tempfile::tempdir().unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let mut target = Server::start(false, mode, true, Arc::clone(&trace));
        let mut idp = Server::start(true, mode, true, Arc::clone(&trace));
        let (policy, grant) = inputs(root.path(), &idp.origin());
        let destination = root.path().join("rejected");
        let output = scan(
            &format!("{}/app/", target.origin()),
            Some((&policy, &grant)),
            &destination,
        );
        assert!(
            output.status.success(),
            "rejected acquisition must preserve the established assessment publication contract"
        );
        let rows = trace.lock().unwrap().clone();
        assert_eq!(rows.iter().filter(|row| row.role == Role::Token).count(), 1);
        assert!(rows
            .iter()
            .all(|row| row.auth == Auth::Absent && !row.cookie));
        assert!(
            rows.iter()
                .all(|row| matches!(row.role, Role::Ordinary | Role::Token)),
            "rejected or redirected source authorized extra work"
        );
        let document = assessment(&destination);
        let audit = &document["supplied_session"];
        assert!(
            audit["outcome"] == "oauth_code_exchange_unavailable" && audit["coverage"] == "none"
        );
        assert_eq!(audit["dispatched_request_count"].as_u64(), Some(1));
        assert_eq!(audit["committed_resource_count"].as_u64(), Some(0));
        let code = &audit["oauth_code"];
        assert_eq!(code["credential_commit_count"].as_u64(), Some(0));
        assert!(
            code["declared_token_lifetime_seconds"].is_null()
                && code["refresh_token_returned"].is_null()
                && code["response_scope_matched"].is_null()
        );
        target.stop();
        idp.stop();
        let stopped = trace.lock().unwrap().clone();
        offline(&destination, &document);
        assert!(trace.lock().unwrap().as_slice() == stopped);
    }
}

#[test]
fn oauth_code_real_cli_does_not_equate_token_acquisition_with_target_session_health() {
    let _serial = SERIAL.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut target = Server::start(false, Mode::Success, false, Arc::clone(&trace));
    let mut idp = Server::start(true, Mode::Success, true, Arc::clone(&trace));
    let (policy, grant) = inputs(root.path(), &idp.origin());
    let destination = root.path().join("unhealthy");
    let output = scan(
        &format!("{}/app/", target.origin()),
        Some((&policy, &grant)),
        &destination,
    );
    assert!(output.status.success());
    let document = assessment(&destination);
    let audit = &document["supplied_session"];
    assert!(audit["outcome"] == "startup_unhealthy" && audit["coverage"] == "none");
    assert_eq!(audit["dispatched_request_count"].as_u64(), Some(2));
    assert_eq!(audit["committed_resource_count"].as_u64(), Some(0));
    assert_eq!(
        audit["oauth_code"]["credential_commit_count"].as_u64(),
        Some(1)
    );
    let rows = trace.lock().unwrap().clone();
    assert_eq!(
        rows.iter()
            .filter(|row| row.role != Role::Ordinary)
            .map(|row| row.role)
            .collect::<Vec<_>>(),
        [Role::Token, Role::Health]
    );
    target.stop();
    idp.stop();
    offline(&destination, &document);
    assert!(trace.lock().unwrap().as_slice() == rows);
}
