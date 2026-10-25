//! Actual-process tests over original synthetic application/IdP responses.
//! This is not a real IdP, interactive OAuth/OIDC or provider-revocation test.
#![cfg(feature = "supplied-session-review")]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static SERIAL: Mutex<()> = Mutex::new(());
const CODE: &str = "SYNTHETIC_REFRESH_CODE_0123456789";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ACCESS_A: &str = "SYNTHETIC_RENEWABLE_ACCESS_A_0123456789";
const ACCESS_B: &str = "SYNTHETIC_RENEWABLE_ACCESS_B_0123456789";
// A refresh value is form data, not a header. SP and '+' deliberately have
// different, independently specified form encodings in EXPECTED_REFRESH_FORM.
const REFRESH_A: &str = "SYNTHETIC_REFRESH_CANARY_A WITH SPACE+0123456789";
const ENCODED_REFRESH_A: &str = "SYNTHETIC_REFRESH_CANARY_A+WITH+SPACE%2B0123456789";
const REFRESH_B: &str = "SYNTHETIC_REFRESH_CANARY_B_0123456789";
const PRIVATE_TOKEN: &str = "SYNTHETIC_RENEWAL_PRIVATE_BODY_0123456789";
const PRIVATE_BODY: &str = "authorization = \"Bearer SYNTHETIC_RENEWAL_PRIVATE_BODY_0123456789\"";
const EXPECTED_CODE_FORM: &str = concat!(
    "grant_type=authorization_code&client_id=owned-public&redirect_uri=",
    "http%3A%2F%2F127.0.0.1%3A1%2Fcallback&code=SYNTHETIC_REFRESH_CODE_0123456789",
    "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
);
const EXPECTED_REFRESH_FORM: &str = concat!(
    "grant_type=refresh_token&client_id=owned-public&refresh_token=",
    "SYNTHETIC_REFRESH_CANARY_A+WITH+SPACE%2B0123456789&scope=canary-read"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Ordinary,
    Code,
    Refresh,
    Health,
    One,
    Two,
    Child,
    Unexpected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    Absent,
    A,
    B,
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
    private_request_target: bool,
}
#[derive(Debug, Clone, Copy)]
enum Mode {
    Success,
    MissingInitialRefresh,
    MissingReplacementRefresh,
    UnchangedReplacementRefresh,
    WrongScope,
    IdToken,
    Confirmation,
    WrongType,
    Coded,
    Html,
    InvalidJson,
    Truncated,
    BadRequest,
    Throttled,
    Redirect,
    WrongPrincipalAfterRefresh,
    StalledRefresh,
    IncompletePlan,
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    health_after_refresh: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(idp: bool, mode: Mode, epoch: Arc<AtomicU8>, trace: Arc<Mutex<Vec<Request>>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind owned numeric loopback");
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let health_after_refresh = Arc::new(AtomicBool::new(true));
        let healthy_after_refresh = Arc::clone(&health_after_refresh);
        let worker = thread::spawn(move || {
            for accepted in listener.incoming() {
                let Ok(mut stream) = accepted else { break };
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
                    if request.method == "POST"
                        && request.auth == Auth::Absent
                        && !request.cookie
                        && request.exact_form
                        && request.identity_requested
                    {
                        match request.role {
                            Role::Code => token_response(mode, false, address),
                            Role::Refresh => {
                                epoch.store(2, Ordering::Release);
                                token_response(mode, true, address)
                            },
                            _ => response("400 Bad Request", "application/json", b"{}", "", None),
                        }
                    } else {
                        response("400 Bad Request", "application/json", b"{}", "", None)
                    }
                } else {
                    let active = if epoch.load(Ordering::Acquire) == 1 {
                        Auth::A
                    } else {
                        Auth::B
                    };
                    match request.role {
                        Role::Health => {
                            let healthy = request.auth == active
                                && (active != Auth::B || healthy_after_refresh.load(Ordering::Acquire))
                                && !(matches!(mode, Mode::WrongPrincipalAfterRefresh)
                                    && active == Auth::B);
                            response("200 OK", "application/json", if healthy {
                                br#"{"authenticated":true}"#
                            } else { br#"{"authenticated":false}"# }, "", None)
                        },
                        Role::One | Role::Two if request.auth == active =>
                            response("200 OK", "text/plain", PRIVATE_BODY.as_bytes(), "", None),
                        Role::One | Role::Two =>
                            response("403 Forbidden", "text/plain", b"not authorized", "", None),
                        Role::Ordinary if matches!(mode, Mode::IncompletePlan) => {
                            let query = (0..65).map(|i| format!("parameter_{i:02}=value"))
                                .collect::<Vec<_>>().join("&");
                            let html = format!("<a href=\"/app/child?{query}\">bounded child</a>");
                            response("200 OK", "text/html", html.as_bytes(), "", None)
                        },
                        Role::Ordinary | Role::Child => response("200 OK", "text/html",
                            b"<!doctype html><title>Owned renewal fixture</title><p>Original harmless fixture.</p>", "", None),
                        _ => response("404 Not Found", "text/plain", b"not found", "", None),
                    }
                };
                // Record only bounded classes, never raw request/header/form bytes.
                let stall =
                    idp && matches!(mode, Mode::StalledRefresh) && request.role == Role::Refresh;
                let consume_prior_wall =
                    !idp && matches!(mode, Mode::StalledRefresh) && request.role == Role::One;
                trace.lock().unwrap().push(request);
                if consume_prior_wall {
                    // Separate the fixed session deadline from the later IdP
                    // per-request timeout; two ready timers have a legitimate
                    // result-first tie and would not prove a wall-only cause.
                    thread::sleep(Duration::from_millis(300));
                }
                if stall {
                    thread::sleep(Duration::from_millis(1500));
                }
                let _ = stream.write_all(&reply);
                let _ = stream.flush();
            }
        });
        Self {
            address,
            stop,
            health_after_refresh,
            worker: Some(worker),
        }
    }
    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }
    fn stop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stop.store(true, Ordering::Release);
            // Test-owned accept wakeup, not a scanner HTTP operation.
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
        let n = stream.read(&mut chunk).expect("read bounded owned request");
        assert!(n > 0 && bytes.len() + n <= MAX, "owned request bounds");
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(i) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..i]).unwrap();
            let body_len = headers
                .split("\r\n")
                .skip(1)
                .filter_map(|line| line.split_once(':'))
                .find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("owned body length"))
                })
                .unwrap_or(0);
            assert!(i + 4 + body_len <= MAX, "owned form bounds");
            break (i + 4, body_len);
        }
    };
    while bytes.len() < headers_end + body_len {
        let n = stream.read(&mut chunk).expect("read bounded owned form");
        assert!(n > 0 && bytes.len() + n <= MAX, "owned form bounds");
        bytes.extend_from_slice(&chunk[..n]);
    }
    let headers = std::str::from_utf8(&bytes[..headers_end - 4]).unwrap();
    let mut lines = headers.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let path = first.next().unwrap();
    let body = &bytes[headers_end..headers_end + body_len];
    let role = if idp {
        match (path, body) {
            ("/realm/token", b) if b == EXPECTED_CODE_FORM.as_bytes() => Role::Code,
            ("/realm/token", b) if b == EXPECTED_REFRESH_FORM.as_bytes() => Role::Refresh,
            _ => Role::Unexpected,
        }
    } else {
        match path {
            "/" => Role::Ordinary,
            "/app/health" => Role::Health,
            "/app/private/one" => Role::One,
            "/app/private/two" => Role::Two,
            p if p.starts_with("/app/child?") => Role::Child,
            _ => Role::Unexpected,
        }
    };
    let mut auth = Auth::Absent;
    let mut cookie = false;
    let mut form = false;
    let mut identity_requested = false;
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        let value = value.trim();
        if name.eq_ignore_ascii_case("authorization") {
            auth = if value == format!("Bearer {ACCESS_A}") {
                Auth::A
            } else if value == format!("Bearer {ACCESS_B}") {
                Auth::B
            } else {
                Auth::Unexpected
            };
        }
        cookie |= name.eq_ignore_ascii_case("cookie");
        form |= name.eq_ignore_ascii_case("content-type")
            && value == "application/x-www-form-urlencoded";
        identity_requested |= name.eq_ignore_ascii_case("accept-encoding") && value == "identity";
    }
    Request {
        role,
        method,
        auth,
        cookie,
        identity_requested,
        exact_form: form && matches!(role, Role::Code | Role::Refresh),
        private_request_target: [CODE, VERIFIER, ACCESS_A, ACCESS_B, REFRESH_A, REFRESH_B]
            .iter()
            .any(|value| path.contains(value)),
    }
}

fn response(status: &str, mime: &str, body: &[u8], extra: &str, length: Option<usize>) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", length.unwrap_or(body.len())).into_bytes();
    out.extend_from_slice(body);
    out
}
fn token_json(renewed: bool) -> String {
    let (access, refresh) = if renewed {
        (ACCESS_B, REFRESH_B)
    } else {
        (ACCESS_A, REFRESH_A)
    };
    format!(
        r#"{{"access_token":"{access}","token_type":"Bearer","expires_in":60,"scope":"canary-read","refresh_token":"{refresh}"}}"#
    )
}
fn token_response(mode: Mode, renewed: bool, address: SocketAddr) -> Vec<u8> {
    let mut json = token_json(renewed);
    if !renewed {
        if matches!(mode, Mode::MissingInitialRefresh) {
            json = format!(
                r#"{{"access_token":"{ACCESS_A}","token_type":"Bearer","expires_in":60,"scope":"canary-read"}}"#
            );
        }
        return response("200 OK", "application/json", json.as_bytes(), "", None);
    }
    match mode {
        Mode::MissingReplacementRefresh => {
            json = format!(
                r#"{{"access_token":"{ACCESS_B}","token_type":"Bearer","expires_in":60,"scope":"canary-read"}}"#
            )
        },
        Mode::UnchangedReplacementRefresh => json = json.replace(REFRESH_B, REFRESH_A),
        Mode::WrongScope => json = json.replace("canary-read", "different-scope"),
        Mode::IdToken => {
            json = json.replacen(
                '{',
                "{\"id_token\":\"SYNTHETIC_UNVALIDATED_REFRESH_ID_TOKEN\",",
                1,
            )
        },
        Mode::Confirmation => {
            json = json.replacen(
                '{',
                "{\"cnf\":{\"jkt\":\"SYNTHETIC_UNVALIDATED_BINDING\"},",
                1,
            )
        },
        Mode::WrongType => json = json.replace("Bearer", "DPoP"),
        Mode::InvalidJson => json = format!("{{{ACCESS_B}"),
        Mode::BadRequest => {
            return response(
                "400 Bad Request",
                "application/json",
                format!(
                    r#"{{"error":"invalid_grant","error_description":"{REFRESH_A} {ACCESS_B}"}}"#
                )
                .as_bytes(),
                "",
                None,
            )
        },
        Mode::Throttled => {
            return response("429 Too Many Requests", "application/json", b"{}", "", None)
        },
        Mode::Redirect => {
            return response(
                "302 Found",
                "application/json",
                b"{}",
                &format!("Location: http://{address}/never\r\n"),
                None,
            )
        },
        _ => {},
    }
    response(
        "200 OK",
        if matches!(mode, Mode::Html) {
            "text/html"
        } else {
            "application/json"
        },
        json.as_bytes(),
        if matches!(mode, Mode::Coded) {
            "Content-Encoding: gzip\r\n"
        } else {
            ""
        },
        matches!(mode, Mode::Truncated).then_some(json.len() + 10),
    )
}

fn termivar() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_termivar"));
    cmd.stdin(Stdio::null());
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env_remove(key);
    }
    cmd.env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1");
    cmd
}
fn run(mut cmd: Command) -> Output {
    const LIMIT: u64 = 1024 * 1024;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn actual CLI");
    let capture = |pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .expect("bounded CLI capture");
            bytes
        })
    };
    let stdout = capture(Box::new(child.stdout.take().unwrap()));
    let stderr = capture(Box::new(child.stderr.take().unwrap()));
    let end = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll actual CLI") {
            break status;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            panic!("owned refresh CLI exceeded its process deadline");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    assert!(
        stdout.len() <= LIMIT as usize && stderr.len() <= LIMIT as usize,
        "CLI output bounds"
    );
    private_values_absent(&stdout);
    private_values_absent(&stderr);
    if !status.success() {
        let text = String::from_utf8_lossy(&stderr);
        let known_error = [
            "ProjectionInvariant",
            "Serialization",
            "rendered report serialization failed",
            "assessment report",
            "InvalidDocument",
            "InvalidPolicy",
            "SuppliedSessionAuditMismatch",
            "supplied-session policy is invalid",
            "already exists",
        ]
        .into_iter()
        .find(|marker| text.contains(marker));
        let _ = writeln!(std::io::stderr().lock(), "owned refresh CLI: exit={:?}; stdout_bytes={}; stderr_bytes={}; known_error={known_error:?}",
            status.code(), stdout.len(), stderr.len());
    }
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
        ACCESS_A,
        ACCESS_B,
        REFRESH_A,
        ENCODED_REFRESH_A,
        REFRESH_B,
        PRIVATE_TOKEN,
        PRIVATE_BODY,
        EXPECTED_CODE_FORM,
        EXPECTED_REFRESH_FORM,
        "SYNTHETIC_UNVALIDATED_REFRESH_ID_TOKEN",
        "SYNTHETIC_UNVALIDATED_BINDING",
    ] {
        assert!(
            !text.contains(value),
            "private synthetic material reached a sink"
        );
        let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
        assert!(
            !text.contains(&digest),
            "public unkeyed private-material identity reached a sink"
        );
    }
    for value in [
        token_json(false),
        token_json(true),
        format!("Bearer {ACCESS_A}"),
        format!("Bearer {ACCESS_B}"),
    ] {
        let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
        assert!(
            !text.contains(&digest),
            "whole private response/header identity reached a sink"
        );
    }
}
fn policy(issuer: &str, renewable: bool) -> String {
    let (schema, requests) = if renewable {
        ("security.supplied-session-policy/v6", 8)
    } else {
        ("security.supplied-session-policy/v5", 6)
    };
    let mut text = format!(
        r#"schema = "{schema}"
principal_alias = "canary-a"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = {requests}
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000
[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "owned-numeric-loopback-http/v1"
issuer = "{issuer}/realm"
token_endpoint = "{issuer}/realm/token"
client_id = "owned-public"
redirect_uri = "http://127.0.0.1:1/callback"
scopes = ["canary-read"]
max_token_response_bytes = 8192
"#
    );
    if renewable {
        text.push_str(
            r#"[oauth_refresh]
profile = "scheduled-public-bearer-refresh/v1"
after_resource_count = 1
max_attempts = 1
"#,
        );
    }
    text
}
fn inputs(root: &Path, issuer: &str, renewable: bool) -> (PathBuf, PathBuf) {
    let p = root.join("policy.toml");
    let g = root.join("grant.secret.tsv");
    fs::write(&p, policy(issuer, renewable)).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fs::write(&g, format!("authorization_code\t{CODE}\ncode_verifier\t{VERIFIER}\ncode_challenge\t{CHALLENGE}\nissuer\t{issuer}/realm\nclient_id\towned-public\nredirect_uri\thttp://127.0.0.1:1/callback\nscope\tcanary-read\nreceived_unix_seconds\t{now}\n")).unwrap();
    (p, g)
}
fn scan(origin: &str, files: Option<(&Path, &Path)>, destination: Option<&Path>) -> Output {
    scan_with_privacy(origin, files, destination, false)
}
fn scan_with_privacy(
    origin: &str,
    files: Option<(&Path, &Path)>,
    destination: Option<&Path>,
    privacy: bool,
) -> Output {
    let input_bytes = files.map(|(policy, grant)| (fs::read(policy).ok(), fs::read(grant).ok()));
    let mut cmd = termivar();
    cmd.args([
        "scan",
        &format!("{origin}/"),
        "--profile",
        "web-review",
        "--format",
        "json",
        "--progress",
    ]);
    if privacy {
        cmd.arg("--secret-exposure-review");
    }
    if let Some((p, g)) = files {
        cmd.arg("--session-policy")
            .arg(p)
            .arg("--session-oauth-code-file")
            .arg(g);
    }
    if let Some(path) = destination {
        cmd.arg("--report-dir").arg(path);
    }
    let out = run(cmd);
    if let (Some((policy, grant)), Some(before)) = (files, input_bytes) {
        assert!(
            (fs::read(policy).ok(), fs::read(grant).ok()) == before,
            "scan changed explicit synthetic input bytes or created a missing input"
        );
    }
    if let Some((policy, grant)) = files {
        for path in [policy, grant] {
            let path = path.to_string_lossy();
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains(path.as_ref()),
                "input path reached stdout"
            );
            assert!(
                !String::from_utf8_lossy(&out.stderr).contains(path.as_ref()),
                "input path reached stderr"
            );
        }
    }
    out
}
fn assessment(path: &Path) -> Value {
    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        private_values_absent(&fs::read(path.join(name)).expect("actual complete bundle member"));
    }
    serde_json::from_slice(&fs::read(path.join("assessment.json")).unwrap()).unwrap()
}
fn snapshot(path: &Path) -> Vec<Vec<u8>> {
    ["assessment.html", "assessment.json", "manifest.json"]
        .iter()
        .map(|n| fs::read(path.join(n)).unwrap())
        .collect()
}
fn assert_trace(rows: &[Request], expected: &[(Role, Auth)]) {
    let ordinary: Vec<_> = rows.iter().filter(|r| r.role == Role::Ordinary).collect();
    assert_eq!(ordinary.len(), 3, "ordinary baseline request count");
    assert!(ordinary
        .iter()
        .all(|r| r.method == "GET" && r.auth == Auth::Absent));
    assert!(
        rows.iter()
            .all(|r| !r.cookie && !r.private_request_target && r.auth != Auth::Unexpected),
        "credential scope"
    );
    let selected: Vec<_> = rows.iter().filter(|r| r.role != Role::Ordinary).collect();
    assert_eq!(
        selected
            .iter()
            .map(|r| (r.role, r.auth))
            .collect::<Vec<_>>(),
        expected,
        "closed selected request sequence"
    );
    for r in selected {
        if matches!(r.role, Role::Code | Role::Refresh) {
            assert!(
                r.method == "POST"
                    && r.auth == Auth::Absent
                    && r.exact_form
                    && r.identity_requested
            );
        } else {
            assert!(r.method == "GET" && !r.exact_form && matches!(r.auth, Auth::A | Auth::B));
        }
    }
}
fn assert_keys(value: &Value, expected: &[&str]) {
    let actual = value.as_object().expect("required typed audit object");
    assert_eq!(
        actual.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        expected.iter().copied().collect::<BTreeSet<_>>(),
        "closed audit field inventory"
    );
}
fn assert_reference(value: &Value, prefix: &str) {
    let reference = value.as_str().expect("explicit opaque reference");
    assert!(
        reference
            .strip_prefix(prefix)
            .is_some_and(|digest| digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))),
        "documented opaque reference shape"
    );
}
fn selected_v6(document: &Value) -> &Value {
    let audit = &document["supplied_session"];
    assert_keys(
        audit,
        &[
            "schema",
            "capability_id",
            "policy_reference",
            "application_reference",
            "principal_reference",
            "principal_alias",
            "principal_assurance",
            "credential_mechanism",
            "credential_acquisition",
            "oauth_code",
            "oauth_refresh",
            "health_oracle",
            "outcome",
            "coverage",
            "checkpoints",
            "resources",
            "selected_resource_count",
            "dispatched_resource_count",
            "committed_resource_count",
            "dispatched_request_count",
            "response_bytes",
            "response_byte_limit",
            "response_byte_limit_exceeded",
            "refresh_performed",
            "anonymous_fallback_performed",
            "continuous_authentication_established",
            "exploit_execution",
            "impact_validation",
        ],
    );
    assert_eq!(audit["schema"], "security.supplied-session-audit/v6");
    assert_eq!(audit["credential_mechanism"], "authorization_header");
    assert_eq!(audit["credential_acquisition"], "imported_oauth_code_pkce");
    assert_eq!(audit["principal_assurance"], "operator_declared");
    assert_eq!(audit["selected_resource_count"].as_u64(), Some(2));
    assert_eq!(
        audit["resources"]
            .as_array()
            .expect("selected resource rows")
            .len(),
        2
    );
    for field in [
        "anonymous_fallback_performed",
        "continuous_authentication_established",
    ] {
        assert_eq!(audit[field], false);
    }
    assert_eq!(audit["exploit_execution"], "not_performed");
    assert_eq!(audit["impact_validation"], "not_performed");
    let code = &audit["oauth_code"];
    for field in [
        "authorization_initiated",
        "browser_callback_received",
        "state_nonce_verified",
        "oidc_identity_validation_performed",
        "token_signature_validation_performed",
    ] {
        assert_eq!(code[field], false);
    }
    assert_eq!(
        code["transaction_context_assurance"],
        "operator_declared_external_transaction"
    );
    let refresh = &audit["oauth_refresh"];
    assert_keys(
        refresh,
        &[
            "profile",
            "idp_reference",
            "refresh_policy_reference",
            "after_resource_count",
            "max_attempts",
            "token_interpretation",
            "rotation_assurance",
            "server_replay_detection_established",
            "initial_epoch",
            "final_epoch",
            "request_attempt_count",
            "request_admitted_count",
            "response_completed_count",
            "credential_commit_count",
            "status",
            "body_state",
            "response_bytes",
            "configured_token_response_byte_limit",
            "token_response_validated",
            "response_scope_matched",
            "declared_token_lifetime_seconds",
            "replacement_refresh_token_received",
            "replacement_value_differs",
            "prior_credential_evidence_reference",
            "boundary_resource_evidence_reference",
            "boundary_health_evidence_reference",
            "evidence_reference",
            "health",
            "outcome",
        ],
    );
    assert_eq!(refresh["profile"], "scheduled-public-bearer-refresh/v1");
    assert_eq!(
        refresh["token_interpretation"],
        "opaque_bearer_not_oidc_identity"
    );
    assert_eq!(
        refresh["rotation_assurance"],
        "replacement_value_observed_not_server_revocation"
    );
    assert_eq!(refresh["server_replay_detection_established"], false);
    assert_eq!(refresh["after_resource_count"].as_u64(), Some(1));
    assert_eq!(refresh["max_attempts"].as_u64(), Some(1));
    assert_eq!(refresh["initial_epoch"].as_u64(), Some(1));
    for field in [
        "request_attempt_count",
        "request_admitted_count",
        "response_completed_count",
        "credential_commit_count",
    ] {
        assert!(
            refresh[field].as_u64().is_some_and(|count| count <= 1),
            "typed bounded counter"
        );
    }
    assert_reference(&refresh["idp_reference"], "oauth-code-policy-sha256:");
    assert_reference(
        &refresh["refresh_policy_reference"],
        "oauth-refresh-policy-sha256:",
    );
    assert_eq!(refresh["idp_reference"], code["idp_reference"]);
    audit
}
fn assert_boundary_binding(audit: &Value) {
    let refresh = &audit["oauth_refresh"];
    assert_eq!(
        refresh["prior_credential_evidence_reference"],
        audit["oauth_code"]["evidence_reference"]
    );
    assert_eq!(
        refresh["boundary_resource_evidence_reference"],
        audit["resources"][0]["evidence_reference"]
    );
    assert_eq!(
        refresh["boundary_health_evidence_reference"],
        audit["checkpoints"][1]["evidence_reference"]
    );
    for (field, prefix) in [
        (
            "prior_credential_evidence_reference",
            "supplied-session-oauth-code-evidence-sha256:",
        ),
        (
            "boundary_resource_evidence_reference",
            "supplied-session-resource-evidence-sha256:",
        ),
        (
            "boundary_health_evidence_reference",
            "supplied-session-checkpoint-evidence-sha256:",
        ),
    ] {
        assert_reference(&refresh[field], prefix);
    }
}
fn assert_complete_v6(document: &Value) {
    let audit = selected_v6(document);
    assert_eq!(audit["outcome"], "complete");
    assert_eq!(audit["coverage"], "complete");
    assert_eq!(audit["dispatched_request_count"].as_u64(), Some(8));
    assert_eq!(audit["dispatched_resource_count"].as_u64(), Some(2));
    assert_eq!(audit["committed_resource_count"].as_u64(), Some(2));
    assert_eq!(audit["response_bytes"].as_u64(), Some(579));
    assert_eq!(audit["response_byte_limit"].as_u64(), Some(65536));
    assert_eq!(audit["response_byte_limit_exceeded"], false);
    assert_eq!(audit["refresh_performed"], true);
    let code = &audit["oauth_code"];
    let refresh = &audit["oauth_refresh"];
    for phase in [code, refresh] {
        for field in [
            "request_attempt_count",
            "request_admitted_count",
            "response_completed_count",
            "credential_commit_count",
        ] {
            assert_eq!(phase[field].as_u64(), Some(1));
        }
        assert_eq!(phase["outcome"], "credential_committed");
        assert_eq!(phase["status"].as_u64(), Some(200));
        assert_eq!(phase["body_state"], "complete");
        assert_eq!(phase["token_response_validated"], true);
        assert_eq!(phase["response_scope_matched"], true);
        assert_eq!(phase["declared_token_lifetime_seconds"].as_u64(), Some(60));
    }
    assert_eq!(code["response_bytes"].as_u64(), Some(185));
    assert_eq!(code["refresh_token_returned"], true);
    assert_eq!(refresh["response_bytes"].as_u64(), Some(174));
    assert_eq!(
        refresh["configured_token_response_byte_limit"].as_u64(),
        Some(8192)
    );
    assert_eq!(refresh["replacement_refresh_token_received"], true);
    assert_eq!(refresh["replacement_value_differs"], true);
    assert_eq!(refresh["final_epoch"].as_u64(), Some(2));
    assert_boundary_binding(audit);
    let checkpoints = audit["checkpoints"].as_array().unwrap();
    assert_eq!(
        checkpoints.len(),
        3,
        "renewed health is a distinct nested record, not a fourth common checkpoint"
    );
    for (index, (phase, epoch)) in [("startup", 1), ("subject_boundary", 1), ("terminal", 2)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(checkpoints[index]["sequence"].as_u64(), Some(index as u64));
        assert_eq!(checkpoints[index]["phase"], phase);
        assert_eq!(checkpoints[index]["epoch"].as_u64(), Some(epoch));
        assert_eq!(checkpoints[index]["outcome"], "healthy");
        assert_eq!(checkpoints[index]["response_bytes"].as_u64(), Some(22));
    }
    let health = &refresh["health"];
    assert_eq!(health["sequence"].as_u64(), Some(2));
    assert_eq!(health["phase"], "renewal");
    assert_eq!(health["after_subject_count"].as_u64(), Some(1));
    assert_eq!(health["epoch"].as_u64(), Some(2));
    assert_eq!(health["outcome"], "healthy");
    assert_eq!(health["predicate"], "matched");
    assert_eq!(health["response_bytes"].as_u64(), Some(22));
    let resources = audit["resources"].as_array().unwrap();
    for (i, row) in resources.iter().enumerate() {
        assert_eq!(row["epoch"].as_u64(), Some(1 + i as u64));
        assert_eq!(row["outcome"], "committed");
        assert_eq!(row["response_bytes"].as_u64(), Some(66));
    }
    let mut references = BTreeSet::new();
    for value in [
        code,
        refresh,
        &checkpoints[0],
        &checkpoints[1],
        &checkpoints[2],
        &resources[0],
        &resources[1],
        health,
    ] {
        assert!(
            references.insert(
                value["evidence_reference"]
                    .as_str()
                    .expect("committed evidence reference")
            ),
            "duplicate committed evidence identity"
        );
    }
}
fn assert_uncommitted_refresh(audit: &Value) {
    assert_eq!(audit["committed_resource_count"].as_u64(), Some(1));
    assert_eq!(audit["dispatched_resource_count"].as_u64(), Some(1));
    assert_eq!(audit["coverage"], "partial");
    assert_eq!(audit["refresh_performed"], false);
    assert_eq!(audit["checkpoints"].as_array().unwrap().len(), 2);
    assert_eq!(audit["resources"][0]["outcome"], "committed");
    assert_eq!(audit["resources"][1]["outcome"], "not_dispatched");
    assert_eq!(audit["resources"][1]["epoch"].as_u64(), Some(1));
    let refresh = &audit["oauth_refresh"];
    assert_eq!(refresh["request_attempt_count"].as_u64(), Some(1));
    assert_eq!(refresh["request_admitted_count"].as_u64(), Some(1));
    assert_eq!(refresh["credential_commit_count"].as_u64(), Some(0));
    assert_eq!(refresh["final_epoch"].as_u64(), Some(1));
    assert_eq!(refresh["token_response_validated"], false);
    for key in [
        "health",
        "evidence_reference",
        "response_scope_matched",
        "declared_token_lifetime_seconds",
        "replacement_refresh_token_received",
        "replacement_value_differs",
    ] {
        assert!(refresh.get(key).expect("required nullable field").is_null());
    }
    assert_boundary_binding(audit);
}
fn offline(path: &Path, source: &Value) {
    let before = snapshot(path);
    let mut verify = termivar();
    verify
        .args(["report", "verify", "--dir"])
        .arg(path)
        .args(["--format", "json"]);
    let out = run(verify);
    assert!(out.status.success(), "actual offline Verify failed");
    let verified: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(verified["status"], "integrity_match");
    let mut compare = termivar();
    compare
        .args(["report", "compare", "--before"])
        .arg(path.join("assessment.json"))
        .arg("--after")
        .arg(path.join("assessment.json"))
        .args(["--same-scope", "--format", "json"]);
    let out = run(compare);
    assert!(out.status.success(), "actual offline self-Compare failed");
    let document: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(document["schema"], "termivar-report-comparison/v1");
    for name in ["only_in_after", "only_in_before", "changed"] {
        assert!(document[name]
            .as_array()
            .expect("explicit comparison array")
            .is_empty());
    }
    let count = source["item_count"]
        .as_u64()
        .expect("typed source cardinality");
    assert!(count > 0);
    assert_eq!(source["items"].as_array().unwrap().len() as u64, count);
    assert_eq!(
        document["unchanged"].as_array().unwrap().len() as u64,
        count
    );
    if source.get("supplied_session").is_some() {
        let session = &document["supplied_session_comparison"];
        assert_eq!(session["status"], "compared_within_same_declared_context");
        assert_eq!(session["health_and_coverage"]["status"], "unchanged");
        assert_eq!(session["accounting"]["status"], "unchanged");
    }
    assert!(
        snapshot(path) == before,
        "offline operations changed original bundle bytes"
    );
}
fn controlled_compare(before: &Path, after: &Path) -> Value {
    let before_bytes = snapshot(before);
    let after_bytes = snapshot(after);
    let before_source = assessment(before);
    let after_source = assessment(after);
    let mut cmd = termivar();
    cmd.args(["report", "compare", "--before"])
        .arg(before.join("assessment.json"))
        .arg("--after")
        .arg(after.join("assessment.json"))
        .args(["--same-scope", "--format", "json"]);
    let out = run(cmd);
    assert!(out.status.success(), "actual controlled Compare failed");
    let compared: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(compared["schema"], "termivar-report-comparison/v1");
    let length = |group: &str| {
        compared[group]
            .as_array()
            .expect("required comparison array")
            .len() as u64
    };
    assert_eq!(
        length("only_in_before") + length("changed") + length("unchanged"),
        before_source["item_count"].as_u64().unwrap()
    );
    assert_eq!(
        length("only_in_after") + length("changed") + length("unchanged"),
        after_source["item_count"].as_u64().unwrap()
    );
    assert!(
        snapshot(before) == before_bytes && snapshot(after) == after_bytes,
        "controlled Compare changed source bundle bytes"
    );
    compared
}

#[test]
fn oauth_refresh_real_cli_has_one_scheduled_exchange_and_preserves_option_off_and_v5() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let epoch = Arc::new(AtomicU8::new(1));
    let mut target = Server::start(false, Mode::Success, Arc::clone(&epoch), Arc::clone(&trace));
    let mut idp = Server::start(true, Mode::Success, Arc::clone(&epoch), Arc::clone(&trace));
    let off_dir = root.path().join("off");
    assert!(scan(&target.origin(), None, Some(&off_dir))
        .status
        .success());
    let off_trace = trace.lock().unwrap().clone();
    assert_trace(&off_trace, &[]);
    let off = assessment(&off_dir);
    assert!(off.get("supplied_session").is_none());
    let (p, g) = inputs(root.path(), &idp.origin(), false);
    let v5_dir = root.path().join("v5");
    assert!(scan(&target.origin(), Some((&p, &g)), Some(&v5_dir))
        .status
        .success());
    let v5_rows = trace.lock().unwrap()[off_trace.len()..].to_vec();
    assert_trace(
        &v5_rows,
        &[
            (Role::Code, Auth::Absent),
            (Role::Health, Auth::A),
            (Role::One, Auth::A),
            (Role::Health, Auth::A),
            (Role::Two, Auth::A),
            (Role::Health, Auth::A),
        ],
    );
    let v5 = assessment(&v5_dir);
    assert_eq!(
        v5["supplied_session"]["schema"],
        "security.supplied-session-audit/v5"
    );
    assert_eq!(v5["supplied_session"]["refresh_performed"], false);
    assert_eq!(
        v5["supplied_session"]["oauth_code"]["refresh_token_returned"],
        true
    );
    assert!(v5["supplied_session"].get("oauth_refresh").is_none());
    fs::write(&p, policy(&idp.origin(), true)).unwrap();
    let original_inputs = (fs::read(&p).unwrap(), fs::read(&g).unwrap());
    let start = trace.lock().unwrap().len();
    let on_dir = root.path().join("v6");
    // Explicitly exercise S04 composition when that feature is built. This
    // test flag does not change production selection or the option-off scan.
    assert!(
        scan_with_privacy(
            &target.origin(),
            Some((&p, &g)),
            Some(&on_dir),
            cfg!(feature = "secret-exposure-review")
        )
        .status
        .success(),
        "selected refresh process failed"
    );
    let on_rows = trace.lock().unwrap()[start..].to_vec();
    assert_trace(
        &on_rows,
        &[
            (Role::Code, Auth::Absent),
            (Role::Health, Auth::A),
            (Role::One, Auth::A),
            (Role::Health, Auth::A),
            (Role::Refresh, Auth::Absent),
            (Role::Health, Auth::B),
            (Role::Two, Auth::B),
            (Role::Health, Auth::B),
        ],
    );
    let on = assessment(&on_dir);
    assert_complete_v6(&on);
    let html = fs::read_to_string(on_dir.join("assessment.html")).unwrap();
    for required in [
        "OAuth renewal profile",
        "OAuth renewal final epoch",
        "OAuth renewal health checkpoint",
        "epoch=1",
        "epoch=2",
        "not server revocation or replay-detection proof",
    ] {
        assert!(
            html.contains(required),
            "actual HTML omits V6 explanation: {required}"
        );
    }
    #[cfg(feature = "secret-exposure-review")]
    {
        let privacy = &on["secret_exposure_review"];
        assert_eq!(privacy["selected"], true);
        assert_eq!(privacy["context"], "anonymous-ordinary-get");
        assert_eq!(privacy["additional_request_count"], 0);
        assert_eq!(privacy["response_count"], 1);
        assert_eq!(privacy["evaluated_response_count"], 1);
        assert_eq!(privacy["observation_count"], 0);
        assert!(privacy["observations"].as_array().unwrap().is_empty());
    }
    let before = snapshot(&on_dir);
    let stopped_trace = trace.lock().unwrap().clone();
    let unread_secret = root.path().join("not-present-for-no-overwrite.secret.tsv");
    let overwrite = scan(&target.origin(), Some((&p, &unread_secret)), Some(&on_dir));
    assert!(!overwrite.status.success());
    assert!(
        String::from_utf8_lossy(&overwrite.stderr).contains("already exists"),
        "existing output must fail before the missing secret is read"
    );
    assert_eq!(
        trace.lock().unwrap().as_slice(),
        stopped_trace,
        "no-overwrite dispatched work"
    );
    assert!(
        snapshot(&on_dir) == before,
        "no-overwrite changed existing bundle bytes"
    );
    assert!(
        fs::read(&p).unwrap() == original_inputs.0 && fs::read(&g).unwrap() == original_inputs.1,
        "selected input bytes changed"
    );
    // Same application/policy, independently changed protected-health truth.
    // The synthetic IdP is deliberately not a provider replay-protection oracle.
    epoch.store(1, Ordering::Release);
    target.health_after_refresh.store(false, Ordering::Release);
    let start = trace.lock().unwrap().len();
    let lost_dir = root.path().join("renewed-health-lost");
    assert!(scan_with_privacy(
        &target.origin(),
        Some((&p, &g)),
        Some(&lost_dir),
        cfg!(feature = "secret-exposure-review")
    )
    .status
    .success());
    let lost_rows = trace.lock().unwrap()[start..].to_vec();
    assert_trace(
        &lost_rows,
        &[
            (Role::Code, Auth::Absent),
            (Role::Health, Auth::A),
            (Role::One, Auth::A),
            (Role::Health, Auth::A),
            (Role::Refresh, Auth::Absent),
            (Role::Health, Auth::B),
        ],
    );
    let lost = assessment(&lost_dir);
    let lost_audit = selected_v6(&lost);
    assert_eq!(lost_audit["outcome"], "session_lost");
    assert_eq!(lost_audit["coverage"], "partial");
    assert_eq!(lost_audit["committed_resource_count"].as_u64(), Some(1));
    assert_eq!(
        lost_audit["oauth_refresh"]["health"]["outcome"],
        "unhealthy"
    );
    assert_eq!(lost_audit["oauth_refresh"]["final_epoch"].as_u64(), Some(2));
    assert_eq!(lost_audit["resources"][1]["outcome"], "not_dispatched");
    let stopped_trace = trace.lock().unwrap().clone();
    target.stop();
    idp.stop();
    offline(&off_dir, &off);
    offline(&v5_dir, &v5);
    offline(&on_dir, &on);
    offline(&lost_dir, &lost);
    let methodology = controlled_compare(&v5_dir, &on_dir);
    let session = &methodology["supplied_session_comparison"];
    assert_eq!(session["status"], "not_compared");
    assert_eq!(session["reason"], "session_policy_changed");
    assert_eq!(
        session["context"]["before"]["schema"],
        "security.supplied-session-audit/v5"
    );
    assert_eq!(
        session["context"]["after"]["schema"],
        "security.supplied-session-audit/v6"
    );
    assert!(
        v5["supplied_session"]["policy_reference"] != on["supplied_session"]["policy_reference"]
    );
    let coverage = controlled_compare(&on_dir, &lost_dir);
    let session = &coverage["supplied_session_comparison"];
    assert_eq!(session["status"], "compared_within_same_declared_context");
    assert_eq!(session["health_and_coverage"]["status"], "changed");
    assert_eq!(
        trace.lock().unwrap().as_slice(),
        stopped_trace,
        "offline network activity"
    );
}

#[test]
fn oauth_refresh_real_cli_refuses_bad_replacements_without_retry_or_old_epoch_fallback() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for mode in [
        Mode::MissingReplacementRefresh,
        Mode::UnchangedReplacementRefresh,
        Mode::WrongScope,
        Mode::IdToken,
        Mode::Confirmation,
        Mode::WrongType,
        Mode::Coded,
        Mode::Html,
        Mode::InvalidJson,
        Mode::Truncated,
        Mode::BadRequest,
        Mode::Throttled,
        Mode::Redirect,
    ] {
        let root = tempfile::tempdir().unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let epoch = Arc::new(AtomicU8::new(1));
        let mut target = Server::start(false, mode, Arc::clone(&epoch), Arc::clone(&trace));
        let mut idp = Server::start(true, mode, Arc::clone(&epoch), Arc::clone(&trace));
        let (p, g) = inputs(root.path(), &idp.origin(), true);
        let destination = root.path().join("stopped");
        let out = scan(&target.origin(), Some((&p, &g)), Some(&destination));
        assert!(
            out.status.success(),
            "stopped refresh assessment publication, mode {mode:?}"
        );
        let rows = trace.lock().unwrap().clone();
        assert_trace(
            &rows,
            &[
                (Role::Code, Auth::Absent),
                (Role::Health, Auth::A),
                (Role::One, Auth::A),
                (Role::Health, Auth::A),
                (Role::Refresh, Auth::Absent),
            ],
        );
        let document = assessment(&destination);
        let audit = selected_v6(&document);
        assert_uncommitted_refresh(audit);
        assert_eq!(audit["outcome"], "oauth_refresh_unavailable");
        assert_eq!(audit["dispatched_request_count"].as_u64(), Some(5));
        assert_eq!(
            audit["oauth_refresh"]["outcome"],
            if matches!(mode, Mode::Throttled) {
                "throttled"
            } else if matches!(mode, Mode::Truncated) {
                // A framing EOF fails in response.chunk() before a collected
                // response exists. It is not a retained partial representation.
                "transport_failed"
            } else {
                "response_rejected"
            },
            "independently classified response failure, mode {mode:?}"
        );
        assert_eq!(
            audit["oauth_refresh"]["response_completed_count"].as_u64(),
            Some(u64::from(!matches!(mode, Mode::Truncated)))
        );
        if matches!(mode, Mode::Truncated) {
            assert!(audit["oauth_refresh"]["status"].is_null());
            assert!(
                audit["oauth_refresh"]["response_bytes"].as_u64().unwrap() > 0,
                "framing failure must retain delivered-byte accounting"
            );
        }
        target.stop();
        idp.stop();
        offline(&destination, &document);
        assert_eq!(trace.lock().unwrap().as_slice(), rows);
    }
}

#[test]
fn oauth_refresh_real_cli_requires_initial_refresh_material_and_renewed_principal_health() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (mode, expected) in [
        (
            Mode::MissingInitialRefresh,
            vec![(Role::Code, Auth::Absent)],
        ),
        (
            Mode::WrongPrincipalAfterRefresh,
            vec![
                (Role::Code, Auth::Absent),
                (Role::Health, Auth::A),
                (Role::One, Auth::A),
                (Role::Health, Auth::A),
                (Role::Refresh, Auth::Absent),
                (Role::Health, Auth::B),
            ],
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let epoch = Arc::new(AtomicU8::new(1));
        let mut target = Server::start(false, mode, Arc::clone(&epoch), Arc::clone(&trace));
        let mut idp = Server::start(true, mode, Arc::clone(&epoch), Arc::clone(&trace));
        let (p, g) = inputs(root.path(), &idp.origin(), true);
        let no_refresh_v5 = if matches!(mode, Mode::MissingInitialRefresh) {
            fs::write(&p, policy(&idp.origin(), false)).unwrap();
            let v5_dir = root.path().join("v5-no-refresh-returned");
            assert!(scan(&target.origin(), Some((&p, &g)), Some(&v5_dir))
                .status
                .success());
            assert_trace(
                &trace.lock().unwrap(),
                &[
                    (Role::Code, Auth::Absent),
                    (Role::Health, Auth::A),
                    (Role::One, Auth::A),
                    (Role::Health, Auth::A),
                    (Role::Two, Auth::A),
                    (Role::Health, Auth::A),
                ],
            );
            let v5 = assessment(&v5_dir);
            assert_eq!(
                v5["supplied_session"]["schema"],
                "security.supplied-session-audit/v5"
            );
            assert_eq!(v5["supplied_session"]["outcome"], "complete");
            assert_eq!(
                v5["supplied_session"]["oauth_code"]["refresh_token_returned"],
                false
            );
            assert_eq!(v5["supplied_session"]["refresh_performed"], false);
            trace.lock().unwrap().clear();
            fs::write(&p, policy(&idp.origin(), true)).unwrap();
            Some((v5_dir, v5))
        } else {
            None
        };
        let destination = root.path().join("unqualified");
        assert!(scan(&target.origin(), Some((&p, &g)), Some(&destination))
            .status
            .success());
        let rows = trace.lock().unwrap().clone();
        assert_trace(&rows, &expected);
        let document = assessment(&destination);
        let audit = selected_v6(&document);
        if matches!(mode, Mode::MissingInitialRefresh) {
            assert_eq!(audit["outcome"], "oauth_code_exchange_unavailable");
            assert_eq!(audit["coverage"], "none");
            assert_eq!(audit["dispatched_request_count"].as_u64(), Some(1));
            assert_eq!(audit["committed_resource_count"].as_u64(), Some(0));
            assert_eq!(
                audit["oauth_code"]["credential_commit_count"].as_u64(),
                Some(0)
            );
            assert_eq!(audit["oauth_refresh"]["outcome"], "not_reached");
            assert_eq!(
                audit["oauth_refresh"]["request_attempt_count"].as_u64(),
                Some(0)
            );
            assert!(audit["oauth_refresh"]["health"].is_null());
            assert!(audit["resources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["outcome"] == "not_dispatched"));
        } else {
            assert_eq!(audit["outcome"], "session_lost");
            assert_eq!(audit["coverage"], "partial");
            assert_eq!(audit["dispatched_request_count"].as_u64(), Some(6));
            assert_eq!(audit["committed_resource_count"].as_u64(), Some(1));
            assert_eq!(audit["refresh_performed"], true);
            assert_eq!(
                audit["oauth_refresh"]["credential_commit_count"].as_u64(),
                Some(1)
            );
            assert_eq!(audit["oauth_refresh"]["final_epoch"].as_u64(), Some(2));
            assert_eq!(audit["oauth_refresh"]["health"]["outcome"], "unhealthy");
            assert_eq!(audit["resources"][1]["outcome"], "not_dispatched");
        }
        target.stop();
        idp.stop();
        offline(&destination, &document);
        if let Some((path, source)) = no_refresh_v5 {
            offline(&path, &source);
        }
        assert_eq!(trace.lock().unwrap().as_slice(), rows);
    }
}

#[test]
fn oauth_refresh_real_cli_preflight_rejects_policy_expansion_before_secret_or_output() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let epoch = Arc::new(AtomicU8::new(1));
    let mut target = Server::start(false, Mode::Success, Arc::clone(&epoch), Arc::clone(&trace));
    let mut idp = Server::start(true, Mode::Success, Arc::clone(&epoch), Arc::clone(&trace));
    let (p, _) = inputs(root.path(), &idp.origin(), true);
    let original = policy(&idp.origin(), true);
    for (i, policy) in [
        original.replace("max_attempts = 1", "max_attempts = 2"),
        original.replace("after_resource_count = 1", "after_resource_count = 2"),
        original.replace("max_session_requests = 8", "max_session_requests = 9"),
        original.replace("max_wall_time_ms = 10000", "max_wall_time_ms = 10001"),
        original.replace(
            "\"/app/private/two\"]",
            "\"/app/private/two\", \"/app/private/three\"]",
        ),
        original.replace(
            "security.supplied-session-policy/v6",
            "security.supplied-session-policy/v5",
        ),
        original.replace(
            "scheduled-public-bearer-refresh/v1",
            "automatic-unbounded-refresh/v1",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        fs::write(&p, policy).unwrap();
        let destination = root.path().join(format!("preflight-{i}"));
        let missing_secret = root.path().join("not-present.secret.tsv");
        let out = scan(
            &target.origin(),
            Some((&p, &missing_secret)),
            Some(&destination),
        );
        assert!(!out.status.success(), "expanded policy accepted, case {i}");
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .any(|line| line == "Error: InvalidPolicy"),
            "invalid policy did not fail before unread secret acquisition, case {i}"
        );
        assert!(
            trace.lock().unwrap().is_empty(),
            "preflight dispatched work"
        );
        assert!(!destination.exists(), "invalid policy reserved output");
        for path in [&p, &missing_secret] {
            let path = path.to_string_lossy();
            assert!(!String::from_utf8_lossy(&out.stdout).contains(path.as_ref()));
            assert!(!String::from_utf8_lossy(&out.stderr).contains(path.as_ref()));
        }
    }
    fs::write(&p, &original).unwrap();
    #[cfg(feature = "wordpress-review")]
    {
        let destination = root.path().join("unsupported-wordpress");
        let mut command = termivar();
        command
            .args([
                "scan",
                &format!("{}/", target.origin()),
                "--profile",
                "web-review",
                "--wordpress-review",
                "--wordpress-discovery",
                "--wordpress-supplied-session",
            ])
            .arg("--session-policy")
            .arg(&p)
            .arg("--session-oauth-code-file")
            .arg(root.path().join("not-present.secret.tsv"))
            .arg("--report-dir")
            .arg(&destination);
        let out = run(command);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr)
            .contains("does not support imported OAuth code policies"));
        assert!(!destination.exists());
        assert!(trace.lock().unwrap().is_empty());
    }
    #[cfg(feature = "websocket-review")]
    {
        // Valid inert policy data; the V6 composition conflict must precede
        // credential acquisition or any handshake. No expected WS reply ran.
        let websocket = root.path().join("websocket-policy.json");
        let document = serde_json::json!({
            "schema":"security.websocket-review-policy/v1",
            "target_authorized":true,"messages_read_only_acknowledged":true,
            "message_content_is_non_secret":true,
            "endpoint":format!("ws://{}/app/socket", target.address),
            "origin_mode":"application_origin","subprotocol":null,
            "compression":false,"reconnect":false,
            "messages":[{"id":"peek","text":"original harmless status request",
                "expected_response":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111","length":2}}],
            "limits":{"max_inbound_message_bytes":4096,"max_outbound_message_bytes":4096,
                "max_messages":1,"max_control_frames":4,"max_wall_time_ms":1000}
        });
        fs::write(&websocket, serde_json::to_vec(&document).unwrap()).unwrap();
        let destination = root.path().join("unsupported-websocket");
        let mut command = termivar();
        command
            .args([
                "scan",
                &format!("{}/", target.origin()),
                "--profile",
                "web-review",
                "--websocket-supplied-session",
            ])
            .arg("--websocket-review-policy")
            .arg(&websocket)
            .arg("--session-policy")
            .arg(&p)
            .arg("--session-oauth-code-file")
            .arg(root.path().join("not-present.secret.tsv"))
            .arg("--report-dir")
            .arg(&destination);
        let out = run(command);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr)
            .contains("supports only authorization-header V1 supplied-session policies"));
        assert!(!destination.exists());
        assert!(trace.lock().unwrap().is_empty());
    }
    target.stop();
    idp.stop();
}

#[test]
fn oauth_refresh_real_cli_keeps_shared_byte_and_deadline_limits_without_retry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Independent byte oracles: 185 + 22 + 66 + 22 = 295 before refresh;
    // another complete 174-byte token response would require 469, beyond 384.
    assert_eq!(token_json(false).len(), 185);
    assert_eq!(token_json(true).len(), 174);
    assert_eq!(PRIVATE_BODY.len(), 66);
    for (mode, budget) in [(Mode::Success, true), (Mode::StalledRefresh, false)] {
        let root = tempfile::tempdir().unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let epoch = Arc::new(AtomicU8::new(1));
        let mut target = Server::start(false, mode, Arc::clone(&epoch), Arc::clone(&trace));
        let mut idp = Server::start(true, mode, Arc::clone(&epoch), Arc::clone(&trace));
        let (p, g) = inputs(root.path(), &idp.origin(), true);
        let text = if budget {
            policy(&idp.origin(), true)
                .replace(
                    "max_total_response_bytes = 65536",
                    "max_total_response_bytes = 384",
                )
                .replace(
                    "max_response_body_bytes = 8192",
                    "max_response_body_bytes = 384",
                )
                .replace(
                    "max_token_response_bytes = 8192",
                    "max_token_response_bytes = 384",
                )
        } else {
            policy(&idp.origin(), true)
                .replace("max_wall_time_ms = 10000", "max_wall_time_ms = 1000")
        };
        fs::write(&p, text).unwrap();
        let destination = root.path().join("limited");
        let out = scan(&target.origin(), Some((&p, &g)), Some(&destination));
        assert!(
            out.status.success(),
            "bounded session stop did not preserve publication"
        );
        let rows = trace.lock().unwrap().clone();
        assert_trace(
            &rows,
            &[
                (Role::Code, Auth::Absent),
                (Role::Health, Auth::A),
                (Role::One, Auth::A),
                (Role::Health, Auth::A),
                (Role::Refresh, Auth::Absent),
            ],
        );
        let document = assessment(&destination);
        let audit = selected_v6(&document);
        assert_uncommitted_refresh(audit);
        assert_eq!(audit["dispatched_request_count"].as_u64(), Some(5));
        if budget {
            let bytes = audit["response_bytes"]
                .as_u64()
                .expect("actual charged bytes");
            assert!(
                (384..=469).contains(&bytes),
                "honest bounded chunk-overrun accounting"
            );
            assert_eq!(audit["response_byte_limit"].as_u64(), Some(384));
            assert_eq!(
                audit["oauth_refresh"]["configured_token_response_byte_limit"].as_u64(),
                Some(384)
            );
            assert_eq!(audit["response_byte_limit_exceeded"], bytes > 384);
            let outcome = audit["outcome"].as_str().unwrap();
            assert!(matches!(
                outcome,
                "runtime_limit" | "oauth_refresh_unavailable"
            ));
            // An exact-cap incomplete representation can be rejected without
            // an overrun; an observed overrun is a runtime limit, not clamping.
            if bytes > 384 {
                assert_eq!(outcome, "runtime_limit");
            }
        } else {
            assert_eq!(audit["outcome"], "runtime_limit");
            assert_eq!(audit["oauth_refresh"]["outcome"], "runtime_limit");
            assert_eq!(audit["oauth_refresh"]["response_bytes"].as_u64(), Some(0));
            assert_eq!(
                audit["oauth_refresh"]["response_completed_count"].as_u64(),
                Some(0)
            );
        }
        target.stop();
        idp.stop();
        offline(&destination, &document);
        assert_eq!(trace.lock().unwrap().as_slice(), rows);
    }
}

#[test]
fn oauth_refresh_real_cli_incomplete_generic_coverage_is_not_relabelled_complete() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = tempfile::tempdir().unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let epoch = Arc::new(AtomicU8::new(1));
    let mut target = Server::start(
        false,
        Mode::IncompletePlan,
        Arc::clone(&epoch),
        Arc::clone(&trace),
    );
    let mut idp = Server::start(true, Mode::Success, Arc::clone(&epoch), Arc::clone(&trace));
    let (p, g) = inputs(root.path(), &idp.origin(), true);
    let out = scan(&target.origin(), Some((&p, &g)), None);
    assert!(
        !out.status.success(),
        "incomplete generic assessment returned success"
    );
    let document: Value =
        serde_json::from_slice(&out.stdout).expect("bounded incomplete diagnostic");
    assert_eq!(document["schema_version"], "web-assessment/v2");
    assert_eq!(document["disposition"], "incomplete");
    assert!(document["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "query_parameter_name_limit"));
    let audit = &document["assessment"]["report"]["supplied_session_audit"];
    assert_eq!(audit["schema"], "security.supplied-session-audit/v6");
    assert_eq!(audit["outcome"], "complete");
    assert_eq!(audit["dispatched_request_count"].as_u64(), Some(8));
    assert_eq!(audit["committed_resource_count"].as_u64(), Some(2));
    assert_eq!(audit["oauth_refresh"]["final_epoch"].as_u64(), Some(2));
    assert_eq!(
        audit["oauth_refresh"]["credential_commit_count"].as_u64(),
        Some(1)
    );
    let rows = trace.lock().unwrap().clone();
    assert!(rows
        .iter()
        .all(|r| !r.cookie && !r.private_request_target && r.auth != Auth::Unexpected));
    assert_eq!(
        document["assessment"]["report"]["usage"]["total_requests"].as_u64(),
        Some(rows.len() as u64),
        "incomplete diagnostic retains actual parent accounting"
    );
    target.stop();
    idp.stop();
}
