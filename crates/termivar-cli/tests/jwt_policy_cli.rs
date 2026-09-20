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
