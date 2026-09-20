//! Actual-process acceptance for transport-free local JWT policy review.

#![cfg(feature = "jwt-policy-review")]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde_json::{json, Value};

const BODY: &str =
    "<!doctype html><html><body>owned transport-free JWT policy fixture</body></html>";
const JSON_NAME: &str = "assessment.json";
const PRIVATE_ISSUER: &str = "issuer-private-canary-8f3129";
const PRIVATE_AUDIENCE: &str = "audience-private-canary-62c4d1";
const PRIVATE_TYPE: &str = "type-private-canary-12ac91+jwt";
const PRIVATE_CLAIM_NAME: &str = "claim_private_canary_779ac1";
const PRIVATE_CLAIM_VALUE: &str = "claim-value-private-canary-01fe82";

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

struct TestServer {
    address: SocketAddr,
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

#[cfg(feature = "jwt-target-acceptance-review")]
#[derive(Clone, Copy)]
enum TargetFixtureMode {
    Marker,
    Redirect,
}

impl TestServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind numeric-loopback fixture");
        let address = listener.local_addr().expect("read fixture address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                handle_connection(&mut stream, &thread_requests);
            }
        });
        Self {
            address,
            url: format!("http://{address}/"),
            requests,
            stop,
            thread: Some(thread),
        }
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    fn start_target_acceptance() -> Self {
        Self::start_target_acceptance_with_mode(TargetFixtureMode::Marker)
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    fn start_target_redirect() -> Self {
        Self::start_target_acceptance_with_mode(TargetFixtureMode::Redirect)
    }

    #[cfg(feature = "jwt-target-acceptance-review")]
    fn start_target_acceptance_with_mode(mode: TargetFixtureMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind numeric-loopback fixture");
        let address = listener.local_addr().expect("read fixture address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                handle_target_acceptance_connection(&mut stream, &thread_requests, mode);
            }
        });
        Self {
            address,
            url: format!("http://{address}/"),
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn shutdown(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join fixture server");
        }
        let trace = self.requests.lock().expect("request trace lock").clone();
        trace
    }
}

#[cfg(feature = "jwt-target-acceptance-review")]
fn handle_target_acceptance_connection(
    stream: &mut TcpStream,
    requests: &Mutex<Vec<String>>,
    mode: TargetFixtureMode,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
    let mut request_bytes = Vec::with_capacity(2048);
    while !request_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 2048];
        let bytes_read = stream
            .read(&mut chunk)
            .expect("read target-acceptance fixture request headers");
        assert!(
            bytes_read > 0,
            "target-acceptance fixture request ended before its header terminator"
        );
        assert!(
            request_bytes.len() + bytes_read <= MAX_REQUEST_HEADER_BYTES,
            "target-acceptance fixture request headers exceeded the independent test ceiling"
        );
        request_bytes.extend_from_slice(&chunk[..bytes_read]);
    }
    let request = String::from_utf8_lossy(&request_bytes).into_owned();
    requests
        .lock()
        .expect("target-acceptance request trace lock")
        .push(request.clone());
    let request_lower = request.to_ascii_lowercase();
    let protected = request
        .lines()
        .next()
        .is_some_and(|line| line.starts_with("GET /protected/marker HTTP/1.1"));
    let body = if protected && matches!(mode, TargetFixtureMode::Redirect) {
        b"redirect is an unsupported target representation".as_slice()
    } else if protected {
        if request_lower.contains("\r\nauthorization: bearer ") {
            br#"{"accepted":true}"#.as_slice()
        } else {
            br#"{"accepted":false}"#.as_slice()
        }
    } else {
        BODY.as_bytes()
    };
    let media_type = if protected && matches!(mode, TargetFixtureMode::Redirect) {
        "text/plain; charset=utf-8"
    } else if protected {
        "application/json"
    } else {
        "text/html; charset=utf-8"
    };
    let set_cookie = if protected {
        "Set-Cookie: jwt_target_fixture=must-not-return; HttpOnly\r\n"
    } else {
        ""
    };
    let (status, redirect) = if protected && matches!(mode, TargetFixtureMode::Redirect) {
        ("302 Found", "Location: /redirect-canary\r\n")
    } else {
        ("200 OK", "")
    };
    let response = format!(
        concat!(
            "HTTP/1.1 {}\r\n",
            "Content-Type: {}\r\n",
            "{}",
            "{}",
            "Content-Length: {}\r\n",
            "Connection: close\r\n\r\n"
        ),
        status,
        media_type,
        redirect,
        set_cookie,
        body.len(),
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_connection(stream: &mut TcpStream, requests: &Mutex<Vec<String>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
    let mut request_bytes = Vec::with_capacity(2048);
    while !request_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 2048];
        let bytes_read = stream
            .read(&mut chunk)
            .expect("read fixture request headers");
        assert!(
            bytes_read > 0,
            "fixture request ended before its header terminator"
        );
        assert!(
            request_bytes.len() + bytes_read <= MAX_REQUEST_HEADER_BYTES,
            "fixture request headers exceeded the independent test ceiling"
        );
        request_bytes.extend_from_slice(&chunk[..bytes_read]);
    }
    let request = String::from_utf8_lossy(&request_bytes).into_owned();
    requests.lock().expect("request trace lock").push(request);
    let response = format!(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n\r\n{}"
        ),
        BODY.len(),
        BODY
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

struct LocalJwtFixture {
    token: String,
    public_jwk: String,
    public_x: String,
    private_pkcs8: String,
}

fn local_jwt_fixture() -> LocalJwtFixture {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("generate task-owned ES256 key");
    let private_pkcs8 = URL_SAFE_NO_PAD.encode(pkcs8.as_ref());
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("parse task-owned ES256 key");
    let point = key_pair.public_key().as_ref();
    assert_eq!(point.len(), 65);
    assert_eq!(point[0], 0x04);
    let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&point[33..65]);
    let public_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": x,
        "y": y,
    })
    .to_string();
    let header =
        URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","typ":"{PRIVATE_TYPE}"}}"#).as_bytes());
    let claims = URL_SAFE_NO_PAD.encode(
        format!(
            r#"{{"iss":"{PRIVATE_ISSUER}","aud":"{PRIVATE_AUDIENCE}","{PRIVATE_CLAIM_NAME}":"{PRIVATE_CLAIM_VALUE}","exp":4000000000}}"#
        )
        .as_bytes(),
    );
    let signing_input = format!("{header}.{claims}");
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("sign task-owned JWT");
    LocalJwtFixture {
        token: format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ),
        public_jwk,
        public_x: x,
        private_pkcs8,
    }
}

fn write_inputs(directory: &Path, fixture: &LocalJwtFixture) -> (String, String, String) {
    let policy = directory.join("private-policy.toml");
    let public_jwk = directory.join("private-public.jwk");
    let token = directory.join("private-token.secret");
    fs::write(
        &policy,
        format!(
            concat!(
                "schema = \"security.jwt-local-policy/v1\"\n",
                "policy_reference = \"owned-es256-fixture\"\n",
                "policy_revision = \"owned-es256-fixture-v1\"\n",
                "expected_type = \"{}\"\n",
                "expected_issuer = \"{}\"\n",
                "expected_audience = \"{}\"\n",
                "required_claims = [\"{}\"]\n",
                "require_expiration = true\n",
                "allowed_clock_skew_seconds = 30\n"
            ),
            PRIVATE_TYPE, PRIVATE_ISSUER, PRIVATE_AUDIENCE, PRIVATE_CLAIM_NAME
        ),
    )
    .expect("write local policy");
    fs::write(&public_jwk, &fixture.public_jwk).expect("write public JWK");
    fs::write(&token, format!("{}\n", fixture.token)).expect("write secret token");
    (
        policy.to_string_lossy().into_owned(),
        public_jwk.to_string_lossy().into_owned(),
        token.to_string_lossy().into_owned(),
    )
}

#[cfg(feature = "jwt-target-acceptance-review")]
fn write_target_acceptance_policy(directory: &Path, server: &TestServer) -> String {
    let policy = directory.join("private-target-acceptance-policy.toml");
    fs::write(
        &policy,
        format!(
            concat!(
                "schema = \"security.jwt-target-acceptance-policy/v1\"\n",
                "policy_reference = \"owned-target-acceptance\"\n",
                "policy_revision = \"owned-target-acceptance-v1\"\n",
                "application = \"{}\"\n",
                "resource = \"{}protected/marker\"\n",
                "resource_reference = \"protected-marker\"\n",
                "success_json_field = \"accepted\"\n"
            ),
            server.url, server.url,
        ),
    )
    .expect("write target-acceptance policy");
    policy.to_string_lossy().into_owned()
}

#[cfg(feature = "jwt-target-acceptance-review")]
fn flip_one_signature_bit(token: &str) -> String {
    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let mut signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("decode fixture signature");
    assert_eq!(signature.len(), 64);
    signature[0] ^= 1;
    format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(signature)
    )
}

fn run_scan(
    server: &TestServer,
    destination: &Path,
    inputs: Option<&(String, String, String)>,
) -> Output {
    let mut command = termivar();
    command
        .args(["scan", &server.url, "--profile", "web-review"])
        .arg("--report-dir")
        .arg(destination);
    if let Some((policy, public_jwk, token)) = inputs {
        command
            .args(["--jwt-policy", policy])
            .args(["--jwt-public-jwk", public_jwk])
            .args(["--jwt-token-file", token]);
    }
    command.output().expect("run real Termivar CLI process")
}

#[cfg(feature = "jwt-target-acceptance-review")]
fn run_target_acceptance_scan(
    server: &TestServer,
    destination: &Path,
    inputs: &(String, String, String),
    target_policy: &str,
) -> Output {
    termivar()
        .args(["scan", &server.url, "--profile", "web-review"])
        .args(["--jwt-policy", &inputs.0])
        .args(["--jwt-public-jwk", &inputs.1])
        .args(["--jwt-token-file", &inputs.2])
        .args(["--jwt-target-acceptance-policy", target_policy])
        .arg("--report-dir")
        .arg(destination)
        .output()
        .expect("run real target-acceptance CLI process")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed with {:?}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_bundle(directory: &Path) -> (Value, Vec<u8>) {
    let mut names = fs::read_dir(directory)
        .expect("read report bundle")
        .map(|entry| {
            entry
                .expect("read bundle entry")
                .file_name()
                .into_string()
                .expect("fixed report filename is UTF-8")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["assessment.html", JSON_NAME, "manifest.json"]);
    let json_bytes = fs::read(directory.join(JSON_NAME)).expect("read assessment JSON");
    let assessment = serde_json::from_slice(&json_bytes).expect("parse assessment JSON");
    let mut all_bytes = Vec::new();
    for name in names {
        all_bytes.extend(fs::read(directory.join(name)).expect("read bundle member"));
    }
    (assessment, all_bytes)
}

fn offline_verify_and_self_compare(directory: &Path, assessment: &Value) -> Value {
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"])
        .output()
        .expect("run Report Verify");
    assert_success(&verify, "Report Verify");
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("parse Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let report = directory.join(JSON_NAME);
    let comparison = termivar()
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run self-Compare");
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
    comparison
}

fn stable_item_projection(assessment: &Value) -> Vec<Value> {
    let items = assessment["items"]
        .as_array()
        .expect("assessment items must be an array");
    let mut projected = items
        .iter()
        .map(|item| {
            let item = item.as_object().expect("assessment item must be an object");
            json!({
                "schema": item.get("schema").expect("item schema"),
                "capability_id": item.get("capability_id").expect("item capability"),
                "category": item.get("category").expect("item category"),
                "claim_basis": item.get("claim_basis").expect("item claim basis"),
                "disposition": item.get("disposition").expect("item disposition"),
                "confidence_ppm": item.get("confidence_ppm").expect("item confidence"),
                "cwe": item.get("cwe").expect("item CWE"),
                "severity": item.get("severity").expect("item severity"),
                "subject_reference": item.get("subject_reference").expect("item subject"),
                "title": item.get("title").expect("item title"),
                "redacted_summary": item.get("redacted_summary").expect("item summary"),
                "remediation": item.get("remediation").expect("item remediation"),
                "case_reference": item.get("case_reference").expect("item case reference"),
                "outcome_reference": item.get("outcome_reference").expect("item outcome reference"),
                "verification_stage": item.get("verification_stage").expect("item verification stage"),
                "evidence_count": item.get("evidence_count").expect("item evidence count"),
                "candidate_evidence_references": item
                    .get("candidate_evidence_references")
                    .expect("item candidate evidence references"),
                "control_evidence_references": item
                    .get("control_evidence_references")
                    .expect("item control evidence references"),
            })
        })
        .collect::<Vec<_>>();
    projected.sort_by(|left, right| {
        left["capability_id"]
            .as_str()
            .expect("projected capability is a string")
            .cmp(
                right["capability_id"]
                    .as_str()
                    .expect("projected capability is a string"),
            )
    });
    projected
}

#[test]
fn non_web_review_rejects_complete_jwt_selection_before_input_or_output() {
    let parent = tempfile::tempdir().expect("create private preflight directory");
    let missing_policy = parent
        .path()
        .join("missing-policy-private-canary-781b2d.toml");
    let missing_public_jwk = parent
        .path()
        .join("missing-public-jwk-private-canary-c45811.json");
    let missing_token = parent
        .path()
        .join("missing-token-private-canary-6445eb.secret");
    let destination = parent.path().join("must-not-be-reserved-private-canary");
    let server = TestServer::start();

    let output = termivar()
        .args(["scan", &server.url, "--profile", "baseline"])
        .arg("--jwt-policy")
        .arg(&missing_policy)
        .arg("--jwt-public-jwk")
        .arg(&missing_public_jwk)
        .arg("--jwt-token-file")
        .arg(&missing_token)
        .arg("--report-dir")
        .arg(&destination)
        .output()
        .expect("run non-web-review JWT preflight refusal");
    let trace = server.shutdown();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("preflight error must be UTF-8");
    assert!(stderr.contains("JWT policy review requires `--profile web-review`"));
    assert!(trace.is_empty(), "profile refusal must precede target I/O");
    assert!(
        !destination.exists(),
        "profile refusal must precede report-directory reservation"
    );
    for path in [
        &missing_policy,
        &missing_public_jwk,
        &missing_token,
        &destination,
    ] {
        assert!(!path.exists());
        assert!(
            !stderr.contains(path.to_string_lossy().as_ref()),
            "preflight error leaked a complete local input path"
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_special_jwt_file_paths_fail_before_open_target_or_output() {
    let parent = tempfile::tempdir().expect("create private Windows-path directory");
    let fixture = local_jwt_fixture();
    let valid_inputs = write_inputs(parent.path(), &fixture);

    for (label, input_index, expected_error) in [
        ("policy", 0_usize, "PolicySource(SourceUnavailable)"),
        ("public-jwk", 1_usize, "PublicKeySource(SourceUnavailable)"),
        ("token", 2_usize, "TokenSource(SourceUnavailable)"),
    ] {
        let special_path = format!(r"\\.\pipe\termivar-jwt-{label}-must-not-open");
        let mut inputs = valid_inputs.clone();
        match input_index {
            0 => inputs.0.clone_from(&special_path),
            1 => inputs.1.clone_from(&special_path),
            2 => inputs.2.clone_from(&special_path),
            _ => unreachable!("fixed input index"),
        }
        let destination = parent.path().join(format!("must-not-be-reserved-{label}"));
        let server = TestServer::start();
        let output = run_scan(&server, &destination, Some(&inputs));
        let trace = server.shutdown();

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("path refusal must be UTF-8");
        assert!(
            stderr.contains(expected_error),
            "{label} path produced an unexpected safe error: {stderr}"
        );
        assert!(
            trace.is_empty(),
            "{label} path refusal must precede target I/O"
        );
        assert!(
            !destination.exists(),
            "{label} path refusal must precede report reservation"
        );
        for forbidden in [
            special_path.as_str(),
            valid_inputs.0.as_str(),
            valid_inputs.1.as_str(),
            valid_inputs.2.as_str(),
            fixture.token.as_str(),
            fixture.public_jwk.as_str(),
            fixture.private_pkcs8.as_str(),
            PRIVATE_ISSUER,
            PRIVATE_AUDIENCE,
            PRIVATE_TYPE,
            PRIVATE_CLAIM_NAME,
            PRIVATE_CLAIM_VALUE,
        ] {
            assert!(
                !stderr.contains(forbidden),
                "{label} path refusal leaked a path or JWT input"
            );
        }
    }
}

#[test]
fn invalid_stdin_token_is_loaded_after_reservation_and_aborts_private_bundle() {
    const INVALID_TOKEN_SENTINEL: &str = "invalid-jwt-private-canary-e218f4";

    let parent = tempfile::tempdir().expect("create private cleanup directory");
    let fixture = local_jwt_fixture();
    let inputs = write_inputs(parent.path(), &fixture);
    let destination = parent.path().join("reserved-bundle-private-canary");
    let server = TestServer::start();
    let mut command = termivar();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["scan", &server.url, "--profile", "web-review"])
        .arg("--jwt-policy")
        .arg(&inputs.0)
        .arg("--jwt-public-jwk")
        .arg(&inputs.1)
        .arg("--jwt-token-stdin")
        .arg("--report-dir")
        .arg(&destination);
    let mut child = command
        .spawn()
        .expect("start real CLI with a blocked JWT stdin source");

    let deadline = Instant::now() + Duration::from_secs(10);
    while !destination.is_dir() {
        assert!(
            child.try_wait().expect("poll blocked JWT CLI").is_none(),
            "CLI exited before reserving its report directory"
        );
        assert!(
            Instant::now() < deadline,
            "CLI did not reserve its report directory before reading JWT stdin"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let mut stdin = child.stdin.take().expect("retain child JWT stdin");
    let invalid_token = format!(
        "{INVALID_TOKEN_SENTINEL}{}",
        "x".repeat((4 * 1024 + 3) - INVALID_TOKEN_SENTINEL.len())
    );
    assert_eq!(invalid_token.len(), 4 * 1024 + 3);
    stdin
        .write_all(invalid_token.as_bytes())
        .expect("send oversized JWT sentinel");
    drop(stdin);
    let output = child
        .wait_with_output()
        .expect("wait for JWT input refusal");
    let trace = server.shutdown();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("JWT input error must be UTF-8");
    assert!(stderr.contains("TokenSource(ValueTooLarge)"));
    assert!(
        trace.is_empty(),
        "invalid local JWT must precede target I/O"
    );
    assert!(
        !destination.exists(),
        "an invalid token must remove the uncommitted reserved bundle"
    );
    let destination_path = destination.to_string_lossy().into_owned();
    for forbidden in [
        INVALID_TOKEN_SENTINEL,
        fixture.token.as_str(),
        fixture.public_jwk.as_str(),
        fixture.public_x.as_str(),
        fixture.private_pkcs8.as_str(),
        PRIVATE_ISSUER,
        PRIVATE_AUDIENCE,
        PRIVATE_TYPE,
        PRIVATE_CLAIM_NAME,
        PRIVATE_CLAIM_VALUE,
        inputs.0.as_str(),
        inputs.1.as_str(),
        inputs.2.as_str(),
        destination_path.as_str(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "JWT input failure leaked secret material or a complete local path"
        );
    }
}

#[test]
fn actual_cli_reviews_local_es256_without_forwarding_or_extra_requests() {
    let parent = tempfile::tempdir().expect("create private acceptance directory");
    let fixture = local_jwt_fixture();
    let inputs = write_inputs(parent.path(), &fixture);

    let baseline_server = TestServer::start();
    let baseline_dir = parent.path().join("option-off");
    let baseline = run_scan(&baseline_server, &baseline_dir, None);
    assert_success(&baseline, "option-off scan");
    let baseline_trace = baseline_server.shutdown();
    let (baseline_assessment, _) = read_bundle(&baseline_dir);
    assert!(baseline_assessment.get("jwt_policy_review").is_none());

    let selected_server = TestServer::start();
    let selected_dir = parent.path().join("option-on");
    let selected = run_scan(&selected_server, &selected_dir, Some(&inputs));
    assert_success(&selected, "selected scan");
    let selected_trace = selected_server.shutdown();
    let (assessment, bundle_bytes) = read_bundle(&selected_dir);
    let token_segments = fixture.token.split('.').collect::<Vec<_>>();
    assert_eq!(
        token_segments.len(),
        3,
        "fixture must remain one compact JWS"
    );

    let audit = &assessment["jwt_policy_review"];
    assert_eq!(audit["schema"], "security.jwt-policy-review-audit/v1");
    assert_eq!(audit["policy"], "termivar.jwt-local-policy/es256-v1");
    assert_eq!(audit["selected"], true);
    assert_eq!(audit["parsing_status"], "parsed");
    assert_eq!(audit["policy_status"], "consistent");
    assert_eq!(audit["local_signature_status"], "verified");
    assert_eq!(audit["target_acceptance_status"], "not_performed");
    assert_eq!(
        audit["methodology"]["operator_policy_reference"],
        "owned-es256-fixture"
    );
    assert_eq!(
        audit["methodology"]["operator_policy_revision"],
        "owned-es256-fixture-v1"
    );
    let public_key_sha256 = audit["methodology"]["local_public_key_sha256"]
        .as_str()
        .expect("public key SHA-256 reference");
    assert!(public_key_sha256.starts_with("sha256:"));
    assert_eq!(public_key_sha256.len(), "sha256:".len() + 64);
    assert_eq!(audit["methodology"]["required_claim_count"], 1);
    assert_eq!(audit["methodology"]["require_expiration"], true);
    assert_eq!(audit["external_activity"]["target_request_count"], 0);
    assert_eq!(
        audit["external_activity"]["remote_key_retrieval"],
        "not_performed"
    );
    assert_eq!(
        audit["external_activity"]["token_forwarding"],
        "not_performed"
    );
    assert_eq!(audit["policy_violations"], json!([]));

    assert_eq!(baseline_trace.len(), 3);
    assert_eq!(selected_trace.len(), 3);
    let request_lines = |trace: &[String]| {
        trace
            .iter()
            .map(|request| request.lines().next().unwrap_or_default().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        request_lines(&selected_trace),
        request_lines(&baseline_trace)
    );
    for request in &selected_trace {
        let lower = request.to_ascii_lowercase();
        assert!(!lower.contains("authorization:"));
        for forbidden in [
            fixture.token.as_str(),
            token_segments[0],
            token_segments[1],
            token_segments[2],
            PRIVATE_ISSUER,
            PRIVATE_AUDIENCE,
            PRIVATE_TYPE,
            PRIVATE_CLAIM_NAME,
            PRIVATE_CLAIM_VALUE,
        ] {
            assert!(
                !request.contains(forbidden),
                "private JWT input entered the request trace"
            );
        }
    }
    for output in [
        &selected.stdout[..],
        &selected.stderr[..],
        &bundle_bytes[..],
    ] {
        let output = String::from_utf8_lossy(output);
        for forbidden in [
            fixture.token.as_str(),
            token_segments[0],
            token_segments[1],
            token_segments[2],
            PRIVATE_ISSUER,
            PRIVATE_AUDIENCE,
            PRIVATE_TYPE,
            PRIVATE_CLAIM_NAME,
            PRIVATE_CLAIM_VALUE,
            fixture.public_x.as_str(),
            fixture.private_pkcs8.as_str(),
            inputs.0.as_str(),
            inputs.1.as_str(),
            inputs.2.as_str(),
        ] {
            assert!(!output.contains(forbidden), "private JWT input leaked");
        }
    }
    let expected_capabilities = [
        "web.passive.csp.missing@1",
        "web.passive.permissions-policy.missing@1",
        "web.passive.referrer-policy.missing@1",
        "web.passive.x-content-type-options.missing@1",
    ];
    for observed in [&baseline_assessment, &assessment] {
        let mut capabilities = observed["items"]
            .as_array()
            .expect("assessment items must be an array")
            .iter()
            .map(|item| {
                item["capability_id"]
                    .as_str()
                    .expect("capability ID must be a string")
            })
            .collect::<Vec<_>>();
        capabilities.sort_unstable();
        assert_eq!(capabilities, expected_capabilities);
    }
    assert_eq!(
        stable_item_projection(&assessment),
        stable_item_projection(&baseline_assessment),
        "transport-free local JWT review changed or substituted stable item semantics"
    );

    let comparison = offline_verify_and_self_compare(&selected_dir, &assessment);
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["status"],
        "compared"
    );
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["methodology"]["status"],
        "unchanged"
    );
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["outcome"]["status"],
        "unchanged"
    );
    eprintln!(
        "jwt-policy-cli-acceptance option_off_requests={} option_on_requests={} parsing=parsed policy=consistent local_signature=verified target_acceptance=not_performed jwt_target_requests=0 verify=integrity_match self_compare=unchanged",
        baseline_trace.len(),
        selected_trace.len()
    );
}

#[cfg(feature = "jwt-target-acceptance-review")]
#[test]
fn actual_cli_runs_six_leg_target_acceptance_and_offline_bundle_checks() {
    let parent = tempfile::tempdir().expect("create private target-acceptance directory");
    let fixture = local_jwt_fixture();
    let inputs = write_inputs(parent.path(), &fixture);
    let server = TestServer::start_target_acceptance();
    let target_policy = write_target_acceptance_policy(parent.path(), &server);
    let destination = parent.path().join("target-acceptance");

    let output = run_target_acceptance_scan(&server, &destination, &inputs, &target_policy);
    assert_success(&output, "target-acceptance scan");
    let trace = server.shutdown();
    let (assessment, bundle_bytes) = read_bundle(&destination);

    let audit = &assessment["jwt_policy_review"];
    assert_eq!(audit["schema"], "security.jwt-policy-review-audit/v2");
    assert_eq!(audit["parsing_status"], "parsed");
    assert_eq!(audit["policy_status"], "consistent");
    assert_eq!(audit["local_signature_status"], "verified");
    assert_eq!(audit["target_acceptance_status"], "completed");
    assert_eq!(audit["external_activity"]["target_request_count"], 6);
    assert_eq!(audit["external_activity"]["token_forwarding"], "performed");
    let target = &audit["target_acceptance"];
    assert_eq!(target["schema"], "security.jwt-target-acceptance-audit/v1");
    assert_eq!(
        target["policy"],
        "termivar.jwt-target-acceptance/exact-origin-json-marker-v1"
    );
    assert_eq!(target["status"], "completed");
    assert_eq!(
        target["conclusion"]["kind"],
        "invalid_signature_control_marker_observed_with_anonymous_control"
    );
    assert_eq!(target["dimensions"]["valid_marker"], "observed_stable");
    assert_eq!(
        target["dimensions"]["anonymous_marker"],
        "not_observed_stable"
    );
    assert_eq!(target["dimensions"]["invalid_marker"], "observed_stable");
    assert_eq!(target["accounting"]["request_limit"], 6);
    assert_eq!(target["accounting"]["active_request_limit"], 2);
    assert_eq!(target["accounting"]["dispatched_request_count"], 6);
    assert_eq!(target["accounting"]["dispatched_passive_request_count"], 4);
    assert_eq!(target["accounting"]["dispatched_active_request_count"], 2);
    assert_eq!(target["accounting"]["committed_response_count"], 6);
    let retained = target["accounting"]["retained_response_bytes"]
        .as_u64()
        .expect("retained target bytes");
    let accounted = target["accounting"]["accounted_transport_response_bytes"]
        .as_u64()
        .expect("accounted target transport bytes");
    assert!(retained > 0);
    assert!(accounted >= retained);
    let legs = target["legs"]
        .as_array()
        .expect("target legs must be an array");
    assert_eq!(legs.len(), 6);
    assert_eq!(
        legs.iter()
            .map(|leg| leg["role"].as_str().expect("target role"))
            .collect::<Vec<_>>(),
        [
            "valid_candidate",
            "anonymous_candidate",
            "invalid_candidate",
            "valid_replay",
            "anonymous_replay",
            "invalid_replay",
        ]
    );

    let target_requests = trace
        .iter()
        .filter(|request| {
            request
                .lines()
                .next()
                .is_some_and(|line| line.starts_with("GET /protected/marker HTTP/1.1"))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        trace.len(),
        9,
        "six target-control legs must not replace the three-request ordinary plan"
    );
    assert_eq!(target_requests.len(), 6);
    assert_eq!(
        trace
            .iter()
            .take(6)
            .filter(|request| {
                request
                    .lines()
                    .next()
                    .is_some_and(|line| line.starts_with("GET /protected/marker HTTP/1.1"))
            })
            .count(),
        6,
        "target-control legs must finish before the ordinary anonymous plan"
    );
    let expected_valid = format!("Bearer {}", fixture.token);
    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut anonymous_count = 0;
    let mut invalid_control_headers = Vec::new();
    let mut invalid_control_tokens = Vec::new();
    for request in &target_requests {
        let authorization = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then_some(value.trim())
        });
        match authorization {
            Some(value) if value == expected_valid => valid_count += 1,
            Some(value) => {
                assert!(
                    value.starts_with("Bearer ") && value != expected_valid,
                    "invalid control must remain a distinct Bearer credential"
                );
                invalid_count += 1;
                invalid_control_headers.push(value.to_owned());
                invalid_control_tokens.push(
                    value
                        .strip_prefix("Bearer ")
                        .expect("invalid control uses the reviewed Bearer mechanism")
                        .to_owned(),
                );
            },
            None => anonymous_count += 1,
        }
        let lower = request.to_ascii_lowercase();
        assert!(!lower.contains("\r\ncookie:"));
        assert!(!lower.contains("\r\nproxy-authorization:"));
    }
    assert_eq!((valid_count, anonymous_count, invalid_count), (2, 2, 2));
    invalid_control_headers.sort();
    invalid_control_headers.dedup();
    invalid_control_tokens.sort();
    invalid_control_tokens.dedup();
    assert_eq!(invalid_control_headers.len(), 1);
    assert_eq!(invalid_control_tokens.len(), 1);
    let ordinary_requests = trace
        .iter()
        .filter(|request| {
            !request
                .lines()
                .next()
                .is_some_and(|line| line.starts_with("GET /protected/marker HTTP/1.1"))
        })
        .collect::<Vec<_>>();
    assert_eq!(ordinary_requests.len(), 3);
    for request in ordinary_requests {
        let lower = request.to_ascii_lowercase();
        assert!(!lower.contains("\r\nauthorization:"));
        assert!(!lower.contains("\r\nproxy-authorization:"));
        assert!(!request.contains(&fixture.token));
        for invalid in invalid_control_headers
            .iter()
            .chain(&invalid_control_tokens)
        {
            assert!(!request.contains(invalid));
        }
    }
    assert!(
        trace
            .iter()
            .all(|request| !request.to_ascii_lowercase().contains("\r\ncookie:")),
        "fixture Set-Cookie values must not enter a later target leg or the ordinary plan"
    );

    let all_output = [&output.stdout[..], &output.stderr[..], &bundle_bytes[..]];
    for bytes in all_output {
        assert!(!bytes
            .windows(fixture.token.len())
            .any(|window| { window == fixture.token.as_bytes() }));
        assert!(!bytes
            .windows(b"\"accepted\"".len())
            .any(|window| { window == b"\"accepted\"" }));
        assert!(!bytes
            .windows(b"/protected/marker".len())
            .any(|window| { window == b"/protected/marker" }));
        assert!(!bytes
            .windows(b"must-not-return".len())
            .any(|window| window == b"must-not-return"));
        for invalid in invalid_control_headers
            .iter()
            .chain(&invalid_control_tokens)
        {
            assert!(
                !bytes
                    .windows(invalid.len())
                    .any(|window| window == invalid.as_bytes()),
                "derived invalid credential leaked outside the private target transport"
            );
        }
    }
    assert!(assessment["items"]
        .as_array()
        .expect("assessment items")
        .iter()
        .all(|item| !item["capability_id"]
            .as_str()
            .unwrap_or_default()
            .contains("jwt-target-acceptance")));

    let comparison = offline_verify_and_self_compare(&destination, &assessment);
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["status"],
        "compared"
    );
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["methodology"]["status"],
        "unchanged"
    );
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["coverage"]["status"],
        "unchanged"
    );
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["outcome"]["status"],
        "unchanged"
    );
    let comparison_bytes = serde_json::to_vec(&comparison).expect("serialize comparison");
    assert!(!comparison_bytes
        .windows(fixture.token.len())
        .any(|window| window == fixture.token.as_bytes()));
    for invalid in invalid_control_headers
        .iter()
        .chain(&invalid_control_tokens)
    {
        assert!(
            !comparison_bytes
                .windows(invalid.len())
                .any(|window| window == invalid.as_bytes()),
            "derived invalid credential leaked into semantic Compare"
        );
    }
    eprintln!(
        "jwt-target-cli-acceptance total_requests=9 target_requests=6 ordinary_requests=3 passive=4 active=2 committed=6 retained_bytes={retained} accounted_transport_bytes={accounted} valid=observed_stable anonymous=not_observed_stable invalid=observed_stable conclusion=review_level verify=integrity_match self_compare=unchanged"
    );
}

#[cfg(feature = "jwt-target-acceptance-review")]
#[test]
fn target_redirect_is_not_followed_and_suppresses_active_controls() {
    let parent = tempfile::tempdir().expect("create private redirect target directory");
    let fixture = local_jwt_fixture();
    let inputs = write_inputs(parent.path(), &fixture);
    let server = TestServer::start_target_redirect();
    let target_policy = write_target_acceptance_policy(parent.path(), &server);
    let destination = parent.path().join("target-redirect");

    let output = run_target_acceptance_scan(&server, &destination, &inputs, &target_policy);
    assert_success(&output, "redirect target-acceptance scan");
    let trace = server.shutdown();
    let (assessment, bundle_bytes) = read_bundle(&destination);

    let target_requests = trace
        .iter()
        .filter(|request| request.starts_with("GET /protected/marker "))
        .collect::<Vec<_>>();
    assert_eq!(target_requests.len(), 4);
    assert!(trace
        .iter()
        .all(|request| !request.starts_with("GET /redirect-canary ")));
    assert_eq!(
        target_requests
            .iter()
            .filter(|request| request.to_ascii_lowercase().contains("\r\nauthorization:"))
            .count(),
        2
    );
    assert!(trace.iter().all(|request| {
        !request.to_ascii_lowercase().contains("\r\ncookie:")
            && !request
                .to_ascii_lowercase()
                .contains("\r\nproxy-authorization:")
    }));

    let audit = &assessment["jwt_policy_review"];
    assert_eq!(audit["schema"], "security.jwt-policy-review-audit/v2");
    assert_eq!(audit["target_acceptance_status"], "partially_performed");
    assert_eq!(audit["external_activity"]["target_request_count"], 4);
    let target = &audit["target_acceptance"];
    assert_eq!(target["status"], "partially_performed");
    assert_eq!(target["accounting"]["dispatched_request_count"], 4);
    assert_eq!(target["accounting"]["dispatched_passive_request_count"], 4);
    assert_eq!(target["accounting"]["dispatched_active_request_count"], 0);
    assert_eq!(target["accounting"]["committed_response_count"], 4);
    assert_eq!(target["conclusion"]["kind"], "incomplete");
    assert_eq!(
        target["conclusion"]["incomplete_reason"]["kind"],
        "response_not_classified"
    );
    assert_eq!(
        target["conclusion"]["incomplete_reason"]["role"],
        "valid_candidate"
    );
    assert_eq!(
        target["legs"]
            .as_array()
            .expect("redirect target legs")
            .iter()
            .filter(|leg| leg["activity"] == "active" && leg["dispatch_status"] == "dispatched")
            .count(),
        0
    );
    assert!(assessment["items"]
        .as_array()
        .expect("assessment items")
        .iter()
        .all(|item| !item["capability_id"]
            .as_str()
            .unwrap_or_default()
            .contains("jwt-target-acceptance")));
    for bytes in [&output.stdout[..], &output.stderr[..], &bundle_bytes[..]] {
        for forbidden in [
            fixture.token.as_bytes(),
            b"/protected/marker".as_slice(),
            b"/redirect-canary".as_slice(),
            b"must-not-return".as_slice(),
        ] {
            assert!(!bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
    }

    let comparison = offline_verify_and_self_compare(&destination, &assessment);
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["status"],
        "compared"
    );
}

#[cfg(feature = "jwt-target-acceptance-review")]
#[test]
fn locally_invalid_signature_never_reaches_selected_target_acceptance() {
    let parent = tempfile::tempdir().expect("create private ineligible target directory");
    let mut fixture = local_jwt_fixture();
    fixture.token = flip_one_signature_bit(&fixture.token);
    let inputs = write_inputs(parent.path(), &fixture);
    let server = TestServer::start_target_acceptance();
    let target_policy = write_target_acceptance_policy(parent.path(), &server);
    let destination = parent.path().join("target-local-signature-invalid");

    let output = run_target_acceptance_scan(&server, &destination, &inputs, &target_policy);
    assert_success(&output, "locally ineligible target-acceptance scan");
    let trace = server.shutdown();
    let (assessment, bundle_bytes) = read_bundle(&destination);

    assert_eq!(trace.len(), 3);
    assert!(trace.iter().all(|request| {
        !request.starts_with("GET /protected/marker ")
            && !request.to_ascii_lowercase().contains("\r\nauthorization:")
    }));
    let audit = &assessment["jwt_policy_review"];
    assert_eq!(audit["schema"], "security.jwt-policy-review-audit/v2");
    assert_eq!(audit["parsing_status"], "parsed");
    assert_eq!(audit["policy_status"], "consistent");
    assert_eq!(audit["local_signature_status"], "invalid");
    assert_eq!(audit["target_acceptance_status"], "not_performed");
    assert_eq!(audit["external_activity"]["target_request_count"], 0);
    assert_eq!(
        audit["external_activity"]["token_forwarding"],
        "not_performed"
    );
    let target = &audit["target_acceptance"];
    assert_eq!(target["selected"], true);
    assert_eq!(target["status"], "not_performed");
    assert_eq!(target["accounting"]["dispatched_request_count"], 0);
    assert_eq!(target["accounting"]["committed_response_count"], 0);
    assert_eq!(target["legs"], json!([]));
    assert_eq!(target["conclusion"]["kind"], "incomplete");
    assert_eq!(
        target["conclusion"]["incomplete_reason"]["kind"],
        "not_eligible"
    );
    assert_eq!(
        target["conclusion"]["incomplete_reason"]["not_eligible_reason"],
        "local_signature_not_established"
    );
    for bytes in [&output.stdout[..], &output.stderr[..], &bundle_bytes[..]] {
        assert!(!bytes
            .windows(fixture.token.len())
            .any(|window| window == fixture.token.as_bytes()));
    }

    let comparison = offline_verify_and_self_compare(&destination, &assessment);
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["status"],
        "compared"
    );
    assert_eq!(
        comparison["jwt_policy_review_comparison"]["coverage"]["status"],
        "unchanged"
    );
}

#[cfg(feature = "jwt-target-acceptance-review")]
#[test]
fn malformed_target_policy_fails_before_secret_target_or_output_access() {
    let parent = tempfile::tempdir().expect("create private target preflight directory");
    let fixture = local_jwt_fixture();
    let inputs = write_inputs(parent.path(), &fixture);
    let missing_token = parent.path().join("missing-private-token.secret");
    let target_policy = parent.path().join("invalid-target-policy.toml");
    let server = TestServer::start_target_acceptance();
    let server_url = server.url.clone();
    let normalized_resource = format!("{server_url}safe/%2e%2e/protected/marker");
    fs::write(
        &target_policy,
        format!(
            concat!(
                "schema = \"security.jwt-target-acceptance-policy/v1\"\n",
                "policy_reference = \"owned-target-acceptance\"\n",
                "policy_revision = \"owned-target-acceptance-v1\"\n",
                "application = \"{}\"\n",
                "resource = \"{}\"\n",
                "resource_reference = \"protected-marker\"\n",
                "success_json_field = \"accepted\"\n"
            ),
            server_url, normalized_resource,
        ),
    )
    .expect("write malformed target policy");
    let destination = parent.path().join("must-not-be-reserved");
    let output = termivar()
        .args(["scan", &server.url, "--profile", "web-review"])
        .args(["--jwt-policy", &inputs.0])
        .args(["--jwt-public-jwk", &inputs.1])
        .arg("--jwt-token-file")
        .arg(&missing_token)
        .arg("--jwt-target-acceptance-policy")
        .arg(&target_policy)
        .arg("--report-dir")
        .arg(&destination)
        .output()
        .expect("run target-policy preflight refusal");
    let trace = server.shutdown();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("preflight error is UTF-8");
    assert!(stderr.contains("InvalidTargetPolicy"));
    assert!(
        trace.is_empty(),
        "invalid target policy preceded target I/O"
    );
    assert!(
        !destination.exists(),
        "invalid target policy preceded output reservation"
    );
    let missing_token_path = missing_token.to_string_lossy().into_owned();
    let target_policy_path = target_policy.to_string_lossy().into_owned();
    for forbidden in [
        missing_token_path.as_str(),
        target_policy_path.as_str(),
        inputs.0.as_str(),
        inputs.1.as_str(),
        fixture.token.as_str(),
        PRIVATE_ISSUER,
        PRIVATE_AUDIENCE,
        PRIVATE_TYPE,
        PRIVATE_CLAIM_NAME,
        PRIVATE_CLAIM_VALUE,
        normalized_resource.as_str(),
        server_url.as_str(),
        "accepted",
    ] {
        assert!(
            !stderr.contains(forbidden),
            "preflight leaked private input"
        );
    }
}
