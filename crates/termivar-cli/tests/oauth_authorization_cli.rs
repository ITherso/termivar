//! Normal CLI-process construction over original synthetic OAuth/application
//! responses. The fixture user agent submits the product-generated transaction;
//! it is not an actual identity-provider, browser-login or OIDC qualification.
#![cfg(feature = "supplied-session-review")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

static SERIAL: Mutex<()> = Mutex::new(());
const CODE: &str = "SYNTHETIC_INITIATED_CODE_CANARY_0123456789";
const ACCESS: &str = "SYNTHETIC_INITIATED_ACCESS_CANARY_0123456789";
const RESOURCE: &[u8] = b"Original harmless protected response.";
const HEALTH: &[u8] = br#"{"authenticated":true}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Ordinary,
    Token,
    Health,
    One,
    Two,
    Unexpected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    role: Role,
    method: String,
    expected_authorization: bool,
    any_authorization: bool,
    cookie: bool,
    valid_form: bool,
}

#[derive(Default)]
struct PrivateTransaction {
    challenge: Option<String>,
    callback: String,
    consumed: bool,
    sentinels: Vec<String>,
}

struct Server {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(
        idp: bool,
        transaction: Arc<Mutex<PrivateTransaction>>,
        trace: Arc<Mutex<Vec<Request>>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind owned fixture");
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                if stop.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let (row, body) = fixture_request(&mut stream, idp, &transaction);
                let token = format!(
                    r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":60,"scope":"canary-read"}}"#
                );
                let (status, media, response): (&str, &str, &[u8]) = match row.role {
                    Role::Token if row.valid_form && !row.any_authorization && !row.cookie => ("200 OK", "application/json", token.as_bytes()),
                    Role::Token | Role::Unexpected => ("400 Bad Request", "application/json", b"{}"),
                    Role::Health if row.expected_authorization => ("200 OK", "application/json", HEALTH),
                    Role::One | Role::Two if row.expected_authorization => ("200 OK", "text/plain", RESOURCE),
                    Role::Health | Role::One | Role::Two => ("403 Forbidden", "application/json", b"{}"),
                    Role::Ordinary => ("200 OK", "text/html", b"<!doctype html><title>Original OAuth fixture</title><p>Harmless entry.</p>"),
                };
                assert!(body.len() <= 16 * 1024, "fixture request body bound");
                let reply = format!("HTTP/1.1 {status}\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len());
                trace.lock().unwrap().push(row);
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.write_all(response);
                let _ = stream.flush();
            }
        });
        Self {
            address,
            stopped,
            worker: Some(worker),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn stop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stopped.store(true, Ordering::Release);
            // Fixture-owned accept wakeup; not a scanner HTTP request.
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

fn fixture_request(
    stream: &mut TcpStream,
    idp: bool,
    transaction: &Mutex<PrivateTransaction>,
) -> (Request, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 2048];
    let (header_end, content_length) = loop {
        let n = stream.read(&mut chunk).expect("bounded fixture request");
        assert!(
            n > 0 && bytes.len() + n <= 24 * 1024,
            "fixture request bound"
        );
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..index]).unwrap();
            let lengths = headers
                .split("\r\n")
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                .collect::<Vec<_>>();
            assert!(lengths.len() <= 1, "fixture framing");
            let length = lengths.first().copied().unwrap_or(0);
            assert!(index + 4 + length <= 24 * 1024, "fixture body bound");
            break (index + 4, length);
        }
    };
    while bytes.len() < header_end + content_length {
        let n = stream.read(&mut chunk).expect("bounded fixture form");
        assert!(n > 0 && bytes.len() + n <= 24 * 1024, "fixture form bound");
        bytes.extend_from_slice(&chunk[..n]);
    }
    let headers = std::str::from_utf8(&bytes[..header_end - 4]).unwrap();
    let mut lines = headers.split("\r\n");
    let first = lines.next().unwrap().split_whitespace().collect::<Vec<_>>();
    assert!(first.len() == 3, "fixture request line");
    let role = match (idp, first[1]) {
        (true, "/realm/token") => Role::Token,
        (true, _) => Role::Unexpected,
        (false, "/app/health") => Role::Health,
        (false, "/app/private/one") => Role::One,
        (false, "/app/private/two") => Role::Two,
        (false, _) => Role::Ordinary,
    };
    let fields = lines
        .filter_map(|line| line.split_once(':'))
        .collect::<Vec<_>>();
    let header = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    };
    let authorization = header("authorization");
    let body = bytes[header_end..header_end + content_length].to_vec();
    let mut valid_form = false;
    if role == Role::Token {
        let form = url::form_urlencoded::parse(&body)
            .into_owned()
            .collect::<Vec<_>>();
        let get = |key: &str| {
            form.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        let mut state = transaction.lock().unwrap();
        if let Some(verifier) = get("code_verifier") {
            state.sentinels.push(verifier.to_owned());
            let derived = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            valid_form = !state.consumed
                && form.len() == 5
                && form
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == 5
                && get("grant_type") == Some("authorization_code")
                && get("code") == Some(CODE)
                && get("client_id") == Some("owned-public")
                && get("redirect_uri") == Some(state.callback.as_str())
                && state.challenge.as_deref() == Some(derived.as_str())
                && verifier.len() == 43
                && header("content-type") == Some("application/x-www-form-urlencoded")
                && header("accept-encoding") == Some("identity")
                && first[0] == "POST";
            state.consumed = true;
        }
    }
    (
        Request {
            role,
            method: first[0].to_owned(),
            expected_authorization: authorization == Some(format!("Bearer {ACCESS}").as_str()),
            any_authorization: authorization.is_some(),
            cookie: header("cookie").is_some(),
            valid_form,
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

// The same bounded real-process helper pattern used by existing session tests.
fn run(mut command: Command) -> Output {
    const LIMIT: u64 = 1024 * 1024;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn actual CLI");
    let capture = |pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(LIMIT + 1).read_to_end(&mut bytes).unwrap();
            bytes
        })
    };
    let stdout = capture(Box::new(child.stdout.take().unwrap()));
    let stderr = capture(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            panic!("owned OAuth authorization CLI deadline exceeded");
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

fn safe_checkpoint(mode: &str, result: &Output, trace: &Mutex<Vec<Request>>) {
    let rows = trace
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let stderr = String::from_utf8_lossy(&result.stderr);
    eprintln!("synthetic OAuth V7 case={mode} exit={:?} stdout_bytes={} stderr_bytes={} ordinary={} token={} protected={} projection_rejected={} serialization_rejected={}",
        result.status.code(),result.stdout.len(),result.stderr.len(),
        rows.iter().filter(|r|r.role==Role::Ordinary).count(),
        rows.iter().filter(|r|r.role==Role::Token).count(),
        rows.iter().filter(|r|matches!(r.role,Role::Health|Role::One|Role::Two)).count(),
        stderr.contains("supplied-session review audit does not match runtime truth"),
        stderr.contains("rendered report serialization failed"));
}

fn policy(root: &Path, idp: &str, callback: SocketAddr, wait_ms: u64) -> PathBuf {
    let path = root.join("policy.toml");
    fs::write(
        &path,
        format!(
            r#"schema = "security.supplied-session-policy/v7"
principal_alias = "canary-a"
credential_mechanism = "authorization_header"
credential_acquisition = "client_initiated_oauth_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 6
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000
[oauth_code]
profile = "client-initiated-public-code-s256-bearer/v1"
transport_profile = "owned-numeric-loopback-http/v1"
issuer = "{idp}/realm"
token_endpoint = "{idp}/realm/token"
client_id = "owned-public"
redirect_uri = "http://{callback}/termivar/oauth/callback"
scopes = ["canary-read"]
max_token_response_bytes = 8192
[oauth_authorization]
profile = "loopback-form-post-state/v1"
authorization_endpoint = "{idp}/realm/authorize"
max_wait_ms = {wait_ms}
"#
        ),
    )
    .unwrap();
    path
}

fn selected_callback() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    assert!(address.port() >= 1024, "owned unprivileged callback port");
    address
}

fn scan(application: &str, selected: Option<(&Path, &Path)>, bundle: &Path) -> Command {
    let mut command = termivar();
    command.args([
        "scan",
        application,
        "--profile",
        "web-review",
        "--format",
        "json",
    ]);
    if let Some((policy, output)) = selected {
        command
            .arg("--session-policy")
            .arg(policy)
            .arg("--session-oauth-authorization-output")
            .arg(output);
    }
    command.arg("--report-dir").arg(bundle);
    command
}

#[derive(Clone, Copy)]
enum Reply {
    Success,
    WrongState,
    WrongIssuer,
    WrongHost,
    WrongPath,
    Partial,
    ProviderError,
}

fn user_agent(
    path: PathBuf,
    idp: String,
    callback: SocketAddr,
    transaction: Arc<Mutex<PrivateTransaction>>,
    mode: Reply,
) -> thread::JoinHandle<usize> {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let handoff = loop {
            if let Ok(bytes) = fs::read(&path) {
                assert!(bytes.len() <= 4097, "private handoff bound");
                if bytes.last() == Some(&b'\n') {
                    break bytes;
                }
            }
            assert!(
                Instant::now() < deadline,
                "product did not publish bounded private handoff"
            );
            thread::sleep(Duration::from_millis(2));
        };
        let uri = std::str::from_utf8(&handoff[..handoff.len() - 1]).unwrap();
        let parsed = url::Url::parse(uri).unwrap();
        assert!(
            parsed
                .as_str()
                .starts_with(&format!("{idp}/realm/authorize?")),
            "authorization endpoint changed"
        );
        let fields = parsed.query_pairs().into_owned().collect::<Vec<_>>();
        assert!(fields.len() == 8, "closed authorization request fields");
        let get = |key: &str| {
            fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
                .unwrap()
        };
        assert!(
            get("response_type") == "code"
                && get("response_mode") == "form_post"
                && get("code_challenge_method") == "S256",
            "explicit public code/S256/form-post contract"
        );
        assert!(
            get("client_id") == "owned-public" && get("scope") == "canary-read",
            "configured client and scope"
        );
        assert!(
            get("redirect_uri") == format!("http://{callback}/termivar/oauth/callback"),
            "exact registered callback"
        );
        assert!(
            get("state").len() == 43 && get("code_challenge").len() == 43,
            "random state and S256 width"
        );
        assert!(
            !fields.iter().any(|(name, _)| name == "code_verifier"),
            "verifier must not be handed to authorization endpoint"
        );
        {
            let mut state = transaction.lock().unwrap();
            state.challenge = Some(get("code_challenge").to_owned());
            state.callback = get("redirect_uri").to_owned();
            state.sentinels.extend([
                uri.to_owned(),
                get("state").to_owned(),
                get("code_challenge").to_owned(),
            ]);
        }
        let state = if matches!(mode, Reply::WrongState) {
            "SYNTHETIC-WRONG-STATE"
        } else {
            get("state")
        };
        let issuer = if matches!(mode, Reply::WrongIssuer) {
            "https://unrelated.invalid/realm".to_owned()
        } else {
            format!("{idp}/realm")
        };
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("state", state).append_pair("iss", &issuer);
        if matches!(mode, Reply::ProviderError) {
            form.append_pair("error", "access_denied");
        } else {
            form.append_pair("code", CODE);
        }
        let body = form.finish();
        let host = if matches!(mode, Reply::WrongHost) {
            "127.0.0.2:1".to_owned()
        } else {
            callback.to_string()
        };
        let target = if matches!(mode, Reply::WrongPath) {
            "/other"
        } else {
            "/termivar/oauth/callback"
        };
        let extra = if matches!(mode, Reply::Partial) {
            10
        } else {
            0
        };
        let request = format!("POST {target} HTTP/1.1\r\nHost: {host}\r\nOrigin: {idp}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len() + extra);
        let mut stream = TcpStream::connect_timeout(&callback, Duration::from_secs(2))
            .expect("connect product-owned callback");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        let _ = stream.take(513).read_to_end(&mut reply);
        assert!(reply.len() <= 512, "inert callback reply bound");
        for value in [CODE, state] {
            assert!(
                !String::from_utf8_lossy(&reply).contains(value),
                "callback reflected sensitive form"
            );
        }
        request.len()
    })
}

fn private_values_absent(bytes: &[u8], transaction: &Mutex<PrivateTransaction>) {
    let source = String::from_utf8_lossy(bytes);
    let state = transaction.lock().unwrap();
    for value in state
        .sentinels
        .iter()
        .map(String::as_str)
        .chain([CODE, ACCESS])
    {
        assert!(
            !source.contains(value),
            "private transaction material reached an output sink"
        );
        let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
        assert!(
            !source.contains(&digest),
            "unkeyed private transaction identity reached an output sink"
        );
    }
}

fn assessment(bundle: &Path, transaction: &Mutex<PrivateTransaction>) -> Value {
    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        private_values_absent(
            &fs::read(bundle.join(name)).expect("actual bundle member"),
            transaction,
        );
    }
    serde_json::from_slice(&fs::read(bundle.join("assessment.json")).unwrap()).unwrap()
}

fn offline(bundle: &Path, document: &Value, transaction: &Mutex<PrivateTransaction>) {
    let before = ["assessment.html", "assessment.json", "manifest.json"]
        .map(|name| fs::read(bundle.join(name)).unwrap());
    let mut verify = termivar();
    verify
        .args(["report", "verify", "--dir"])
        .arg(bundle)
        .args(["--format", "json"]);
    let result = run(verify);
    assert!(result.status.success(), "actual offline Verify failed");
    private_values_absent(&result.stdout, transaction);
    private_values_absent(&result.stderr, transaction);
    let verified: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(verified["status"] == "integrity_match");
    let mut compare = termivar();
    compare
        .args(["report", "compare", "--before"])
        .arg(bundle.join("assessment.json"))
        .arg("--after")
        .arg(bundle.join("assessment.json"))
        .args(["--same-scope", "--format", "json"]);
    let result = run(compare);
    assert!(
        result.status.success(),
        "actual offline self-Compare failed"
    );
    private_values_absent(&result.stdout, transaction);
    private_values_absent(&result.stderr, transaction);
    let compared: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(compared["schema"] == "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(compared[group]
            .as_array()
            .expect("required comparison array")
            .is_empty());
    }
    let count = document["item_count"].as_u64().unwrap();
    assert!(count > 0);
    assert_eq!(
        compared["unchanged"].as_array().unwrap().len() as u64,
        count
    );
    if document.get("supplied_session").is_some() {
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
            fs::read(bundle.join(name)).unwrap() == before[index],
            "offline command changed product bundle bytes"
        );
    }
}

#[test]
fn oauth_authorization_real_cli_generated_transaction_qualifies_bearer_and_offline_bundle() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = tempfile::tempdir().unwrap();
    let transaction = Arc::new(Mutex::new(PrivateTransaction::default()));
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut target = Server::start(false, Arc::clone(&transaction), Arc::clone(&trace));
    let mut idp = Server::start(true, Arc::clone(&transaction), Arc::clone(&trace));
    let application = format!("{}/", target.origin());
    let off_bundle = root.path().join("off");
    let off = run(scan(&application, None, &off_bundle));
    assert!(off.status.success(), "ordinary option-off baseline failed");
    let off_trace = trace.lock().unwrap().clone();
    assert!(
        !off_trace.is_empty()
            && off_trace
                .iter()
                .all(|row| row.role == Role::Ordinary && !row.any_authorization)
    );
    let callback = selected_callback();
    let policy = policy(root.path(), &idp.origin(), callback, 5_000);
    let original_policy = fs::read(&policy).unwrap();
    let handoff = root.path().join("PRIVATE-HANDOFF.txt");
    let bundle = root.path().join("on");
    let agent = user_agent(
        handoff.clone(),
        idp.origin(),
        callback,
        Arc::clone(&transaction),
        Reply::Success,
    );
    let result = run(scan(&application, Some((&policy, &handoff)), &bundle));
    let ingress = agent.join().expect("fixture user agent");
    private_values_absent(&result.stdout, &transaction);
    private_values_absent(&result.stderr, &transaction);
    safe_checkpoint("positive", &result, &trace);
    assert!(
        result.status.success(),
        "client-initiated OAuth CLI did not complete"
    );
    assert!(
        !handoff.exists(),
        "task-owned private handoff was not removed"
    );
    assert!(
        fs::read(&policy).unwrap() == original_policy,
        "policy bytes changed"
    );
    let rows = trace.lock().unwrap().clone();
    let selected = &rows[off_trace.len()..];
    let ordinary = selected
        .iter()
        .filter(|row| row.role == Role::Ordinary)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        ordinary == off_trace,
        "authorization changed ordinary target method/order"
    );
    let session = selected
        .iter()
        .filter(|row| row.role != Role::Ordinary)
        .collect::<Vec<_>>();
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
    assert!(session[0].valid_form && !session[0].any_authorization && session[0].method == "POST");
    assert!(session[1..]
        .iter()
        .all(|row| row.expected_authorization && row.method == "GET"));
    assert!(rows
        .iter()
        .all(|row| !row.cookie && (!row.any_authorization || row.expected_authorization)));
    let document = assessment(&bundle, &transaction);
    let audit = &document["supplied_session"];
    assert!(
        audit["schema"] == "security.supplied-session-audit/v7" && audit["outcome"] == "complete"
    );
    assert_eq!(audit["dispatched_request_count"].as_u64(), Some(6));
    assert_eq!(audit["committed_resource_count"].as_u64(), Some(2));
    assert!(audit.get("oauth_code").is_none() && audit.get("oauth_refresh").is_none());
    let authorization = &audit["oauth_authorization"];
    for key in [
        "reservation_count",
        "accepted_connection_count",
        "completed_form_count",
        "callback_commit_count",
    ] {
        assert_eq!(authorization[key].as_u64(), Some(1));
    }
    for key in [
        "listener_bound",
        "handoff_written",
        "state_validated",
        "issuer_validated",
        "listener_closed",
    ] {
        assert!(authorization[key] == true);
    }
    for key in [
        "oidc_nonce_validation_performed",
        "oidc_identity_validation_performed",
        "token_signature_validation_performed",
    ] {
        assert!(authorization[key] == false);
    }
    assert!(authorization["outcome"] == "callback_committed");
    assert_eq!(
        authorization["ingress_bytes"].as_u64(),
        Some(ingress as u64)
    );
    let exchange = &audit["oauth_token_exchange"];
    for key in [
        "request_attempt_count",
        "request_admitted_count",
        "response_completed_count",
        "credential_commit_count",
    ] {
        assert_eq!(exchange[key].as_u64(), Some(1));
    }
    assert!(
        exchange["outcome"] == "credential_committed"
            && exchange["pkce_assurance"] == "client_generated_s256_not_remote_enforcement"
    );
    assert!(audit["principal_assurance"] == "operator_declared");
    assert!(
        TcpStream::connect_timeout(&callback, Duration::from_millis(50)).is_err(),
        "one-shot listener stayed open"
    );
    target.stop();
    idp.stop();
    let closed_trace = trace.lock().unwrap().clone();
    offline(&bundle, &document, &transaction);
    offline(
        &off_bundle,
        &assessment(&off_bundle, &transaction),
        &transaction,
    );
    assert!(
        trace.lock().unwrap().as_slice() == closed_trace,
        "offline command contacted stopped fixture"
    );
}

#[test]
fn oauth_authorization_real_cli_bad_callback_never_redeems_or_dispatches_credentials() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for mode in [
        Reply::WrongState,
        Reply::WrongIssuer,
        Reply::WrongHost,
        Reply::WrongPath,
        Reply::Partial,
        Reply::ProviderError,
    ] {
        let root = tempfile::tempdir().unwrap();
        let transaction = Arc::new(Mutex::new(PrivateTransaction::default()));
        let trace = Arc::new(Mutex::new(Vec::new()));
        let mut target = Server::start(false, Arc::clone(&transaction), Arc::clone(&trace));
        let mut idp = Server::start(true, Arc::clone(&transaction), Arc::clone(&trace));
        let callback = selected_callback();
        let policy = policy(root.path(), &idp.origin(), callback, 3_000);
        let handoff = root.path().join("private-handoff.txt");
        let bundle = root.path().join("rejected");
        let agent = user_agent(
            handoff.clone(),
            idp.origin(),
            callback,
            Arc::clone(&transaction),
            mode,
        );
        let result = run(scan(
            &format!("{}/app/", target.origin()),
            Some((&policy, &handoff)),
            &bundle,
        ));
        agent.join().expect("negative fixture user agent");
        private_values_absent(&result.stdout, &transaction);
        private_values_absent(&result.stderr, &transaction);
        safe_checkpoint(
            match mode {
                Reply::WrongState => "wrong-state",
                Reply::WrongIssuer => "wrong-issuer",
                Reply::WrongHost => "wrong-host",
                Reply::WrongPath => "wrong-path",
                Reply::Partial => "partial",
                Reply::ProviderError => "provider-error",
                Reply::Success => "positive",
            },
            &result,
            &trace,
        );
        assert!(
            result.status.success(),
            "rejected callback must retain the existing publication contract"
        );
        assert!(!handoff.exists());
        assert!(
            trace
                .lock()
                .unwrap()
                .iter()
                .all(|row| row.role == Role::Ordinary && !row.any_authorization && !row.cookie),
            "rejected callback authorized token or protected work"
        );
        let document = assessment(&bundle, &transaction);
        let audit = &document["supplied_session"];
        assert_eq!(audit["dispatched_request_count"].as_u64(), Some(0));
        assert_eq!(audit["committed_resource_count"].as_u64(), Some(0));
        assert_eq!(
            audit["oauth_authorization"]["reservation_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            audit["oauth_authorization"]["accepted_connection_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            audit["oauth_authorization"]["callback_commit_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            audit["oauth_token_exchange"]["request_attempt_count"].as_u64(),
            Some(0)
        );
        assert!(
            TcpStream::connect_timeout(&callback, Duration::from_millis(50)).is_err(),
            "rejected callback reopened a listener"
        );
        target.stop();
        idp.stop();
        offline(&bundle, &document, &transaction);
    }
}

#[test]
fn oauth_authorization_real_cli_preflight_does_not_create_handoff_or_contact_target() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = tempfile::tempdir().unwrap();
    let transaction = Arc::new(Mutex::new(PrivateTransaction::default()));
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut target = Server::start(false, Arc::clone(&transaction), Arc::clone(&trace));
    let mut idp = Server::start(true, Arc::clone(&transaction), Arc::clone(&trace));
    let application = format!("{}/app/", target.origin());
    let callback = selected_callback();
    let policy_path = policy(root.path(), &idp.origin(), callback, 100);
    let original = fs::read(&policy_path).unwrap();
    for case in 0..6 {
        let handoff = root.path().join(format!("private-handoff-{case}.txt"));
        let bundle = root.path().join(format!("preflight-{case}"));
        let mut command = scan(&application, Some((&policy_path, &handoff)), &bundle);
        match case {
            0 => {
                command
                    .arg("--session-auth-file")
                    .arg(root.path().join("PRIVATE-SECRET-MUST-NOT-OPEN"));
            },
            1 => {
                fs::write(
                    &policy_path,
                    String::from_utf8(original.clone())
                        .unwrap()
                        .replace("max_wait_ms = 100", "max_wait_ms = 0"),
                )
                .unwrap();
            },
            2 => {
                fs::write(&handoff, b"EXISTING-PRIVATE-FILE").unwrap();
            },
            3 => {
                fs::create_dir(&bundle).unwrap();
                fs::write(bundle.join("unrelated-marker"), b"retain").unwrap();
            },
            4 => {
                command = termivar();
                command
                    .args(["scan", &application, "--profile", "baseline"])
                    .arg("--session-policy")
                    .arg(&policy_path)
                    .arg("--session-oauth-authorization-output")
                    .arg(&handoff)
                    .arg("--report-dir")
                    .arg(&bundle);
            },
            5 => {
                command
                    .arg("--session-oauth-code-file")
                    .arg(root.path().join("PRIVATE-CODE-MUST-NOT-OPEN"));
            },
            _ => unreachable!(),
        }
        let result = run(command);
        assert!(!result.status.success(), "invalid preflight was accepted");
        assert!(
            trace.lock().unwrap().is_empty(),
            "preflight contacted a target or IdP fixture"
        );
        private_values_absent(&result.stdout, &Mutex::new(PrivateTransaction::default()));
        private_values_absent(&result.stderr, &Mutex::new(PrivateTransaction::default()));
        if case == 2 {
            assert_eq!(fs::read(&handoff).unwrap(), b"EXISTING-PRIVATE-FILE");
        } else {
            assert!(!handoff.exists(), "preflight created sensitive handoff");
        }
        if case == 3 {
            assert_eq!(
                fs::read(bundle.join("unrelated-marker")).unwrap(),
                b"retain"
            );
            assert_eq!(fs::read_dir(&bundle).unwrap().count(), 1);
        } else {
            assert!(!bundle.exists(), "preflight reserved report output");
        }
        fs::write(&policy_path, &original).unwrap();
    }
    target.stop();
    idp.stop();
}
