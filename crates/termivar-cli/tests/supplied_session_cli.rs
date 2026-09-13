//! Actual-process acceptance for the first supplied-session vertical slice.
//!
//! The fixture is numeric loopback, owned by the test, and has an independent
//! structured health oracle. Request records deliberately classify rather than
//! retain Authorization or Cookie values.

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use serde_json::Value;

const AUTHORIZATION: &str = "Bearer SESSION-PROCESS-CANARY-0123456789ABCDEF";
const RESPONSE_CANARY: &str = "PRIVATE-RESPONSE-CANARY-MUST-NOT-LEAK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationClass {
    Expected,
    Absent,
    Unexpected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestRecord {
    target: String,
    authorization: AuthorizationClass,
    cookie_present: bool,
}

struct TestServer {
    application_url: String,
    requests: Arc<Mutex<Vec<RequestRecord>>>,
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
    command.env("NO_PROXY", "127.0.0.1");
    command.env("no_proxy", "127.0.0.1");
    command
}

fn serve<F>(handler: F) -> TestServer
where
    F: Fn(usize, &str, AuthorizationClass) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address: SocketAddr = listener.local_addr().expect("read fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    let handler = Arc::new(handler);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buffer = [0_u8; 32 * 1024];
            let mut bytes_read = 0_usize;
            while bytes_read < buffer.len()
                && !buffer[..bytes_read]
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
            {
                match stream.read(&mut buffer[bytes_read..]) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => bytes_read += read,
                }
            }
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_owned();
            let authorization = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim())
                })
                .map_or(AuthorizationClass::Absent, |value| {
                    if value == AUTHORIZATION {
                        AuthorizationClass::Expected
                    } else {
                        AuthorizationClass::Unexpected
                    }
                });
            let cookie_present = request.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            });
            let sequence = {
                let mut records = thread_requests.lock().expect("request trace lock");
                records.push(RequestRecord {
                    target: target.clone(),
                    authorization,
                    cookie_present,
                });
                records.len()
            };
            let response = handler(sequence, &target, authorization);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
    });

    TestServer {
        application_url: format!("http://{address}/app/"),
        requests,
    }
}

fn response(status: &str, media_type: &str, body: &str, extra_headers: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {media_type}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn json_ok(body: &str) -> Vec<u8> {
    response("200 OK", "application/json", body, "")
}

fn html_ok(body: &str) -> Vec<u8> {
    response("200 OK", "text/html; charset=utf-8", body, "")
}

fn policy() -> &'static str {
    r#"schema = "security.supplied-session-policy/v1"
principal_alias = "fixture-reader"
credential_mechanism = "authorization_header"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000
"#
}

fn write_inputs(parent: &Path) -> (PathBuf, PathBuf) {
    let policy_path = parent.join("session-policy.toml");
    let authorization_path = parent.join("authorization.secret");
    fs::write(&policy_path, policy()).expect("write synthetic policy");
    fs::write(&authorization_path, format!("{AUTHORIZATION}\r\n"))
        .expect("write synthetic Authorization value");
    (policy_path, authorization_path)
}

fn scan_bundle(
    server: &TestServer,
    policy_path: &Path,
    authorization_path: &Path,
    destination: &Path,
) -> Output {
    termivar()
        .args([
            "scan",
            &server.application_url,
            "--profile",
            "web-review",
            "--format",
            "json",
        ])
        .arg("--session-policy")
        .arg(policy_path)
        .arg("--session-auth-file")
        .arg(authorization_path)
        .arg("--report-dir")
        .arg(destination)
        .output()
        .expect("run supplied-session assessment")
}

fn read_assessment(destination: &Path) -> (Vec<u8>, Value) {
    let bytes = fs::read(destination.join("assessment.json")).expect("read assessment JSON");
    let document = serde_json::from_slice(&bytes).expect("parse assessment JSON");
    (bytes, document)
}

fn assert_no_private_values(bytes: &[u8]) {
    let rendered = String::from_utf8_lossy(bytes);
    for private in [
        AUTHORIZATION,
        "SESSION-PROCESS-CANARY",
        RESPONSE_CANARY,
        "/app/private",
        "/app/health",
        "rotated-cookie-canary",
    ] {
        assert!(!rendered.contains(private), "output retained private input");
    }
}

fn assert_bundle_has_no_private_values(destination: &Path) {
    for entry in fs::read_dir(destination).expect("read report bundle") {
        let entry = entry.expect("read report bundle entry");
        if entry
            .file_type()
            .expect("read report bundle type")
            .is_file()
        {
            assert_no_private_values(&fs::read(entry.path()).expect("read report bundle member"));
        }
    }
}

#[test]
fn ambiguous_raw_application_targets_fail_before_input_or_network_acquisition() {
    for (index, target) in [
        "https://example.test/app/../sibling/",
        "https://example.test/app/%2e%2e/sibling/",
        "https://example.test/app/%2fprivate/",
        "https://example.test/app/%5cprivate/",
        "https://example.test/app/%25encoded/",
        "https://example.test/app//private/",
        r"https://example.test/app\private/",
        "https://EXAMPLE.test/app/",
        "https://example.test:443/app/",
    ]
    .into_iter()
    .enumerate()
    {
        let policy = format!("PRIVATE-MISSING-POLICY-{index}");
        let credential = format!("PRIVATE-MISSING-CREDENTIAL-{index}");
        let output = termivar()
            .args([
                "scan",
                target,
                "--profile",
                "web-review",
                "--session-policy",
            ])
            .arg(&policy)
            .arg("--session-auth-file")
            .arg(&credential)
            .output()
            .expect("run supplied-session preflight refusal");
        assert!(
            !output.status.success(),
            "ambiguous target was accepted: {target}"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("unambiguous raw trailing-slash path"),
            "unexpected refusal for {target}: {stderr}"
        );
        assert!(!stderr.contains(&policy));
        assert!(!stderr.contains(&credential));
    }
}

#[test]
fn invalid_policy_precedes_output_reservation_and_secret_acquisition() {
    let directory = tempfile::tempdir().expect("create private fixture directory");
    let policy_path = directory.path().join("invalid-session-policy.toml");
    let missing_authorization = directory.path().join("PRIVATE-MISSING-AUTHORIZATION");
    let blocked_destination = directory.path().join("blocked-report-destination");
    fs::write(&policy_path, "schema = [invalid").expect("write invalid policy");
    fs::write(&blocked_destination, b"existing sentinel").expect("reserve sentinel path");

    let output = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--session-policy",
        ])
        .arg(&policy_path)
        .arg("--session-auth-file")
        .arg(&missing_authorization)
        .arg("--report-dir")
        .arg(&blocked_destination)
        .output()
        .expect("run invalid supplied-session preflight");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("bounded UTF-8 diagnostic");
    assert!(
        stderr.contains("InvalidPolicy"),
        "policy validation did not precede output reservation: {stderr}"
    );
    assert!(!stderr.contains("PRIVATE-MISSING-AUTHORIZATION"));
    assert_eq!(
        fs::read(&blocked_destination).expect("read unchanged sentinel"),
        b"existing sentinel"
    );
}

#[cfg(feature = "ssrf-oast-review")]
fn assert_oast_policy_precedes_selected_secret(output: Output, private_markers: &[&str]) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("bounded UTF-8 diagnostic");
    assert!(
        stderr.contains("InvalidPolicyEncoding"),
        "OAST policy validation did not precede secret acquisition: {stderr}"
    );
    assert!(!stderr.contains("AuthorizationSource"));
    for private in private_markers {
        assert!(
            !stderr.contains(private),
            "diagnostic retained private source"
        );
    }
}

#[cfg(feature = "ssrf-oast-review")]
#[test]
fn oast_policy_precedes_every_compatible_secret_and_output_acquisition() {
    let directory = tempfile::tempdir().expect("create private fixture directory");
    let session_policy = directory.path().join("valid-session-policy.toml");
    let invalid_oast_policy = directory.path().join("invalid-oast-policy.toml");
    let missing_session_secret = directory.path().join("PRIVATE-MISSING-SESSION-SECRET");
    let missing_oast_secret = directory.path().join("PRIVATE-MISSING-OAST-SECRET");
    let missing_root_secret = directory.path().join("PRIVATE-MISSING-ROOT-SECRET");
    #[cfg(feature = "authorization-review")]
    let missing_authz_policy = directory.path().join("PRIVATE-MISSING-AUTHZ-POLICY");
    #[cfg(feature = "authorization-review")]
    let missing_authz_primary = directory.path().join("PRIVATE-MISSING-AUTHZ-PRIMARY");
    #[cfg(feature = "authorization-review")]
    let missing_authz_peer = directory.path().join("PRIVATE-MISSING-AUTHZ-PEER");
    let blocked_destination = directory.path().join("blocked-report-destination");
    fs::write(&session_policy, policy()).expect("write valid session policy");
    fs::write(&invalid_oast_policy, [0xff, 0xfe]).expect("write invalid OAST policy");
    fs::write(&blocked_destination, b"existing sentinel").expect("reserve sentinel path");

    let mut command = termivar();
    command
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--session-policy",
        ])
        .arg(&session_policy)
        .arg("--session-auth-file")
        .arg(&missing_session_secret)
        .arg("--ssrf-oast-review")
        .arg("--ssrf-oast-policy")
        .arg(&invalid_oast_policy)
        .arg("--oast-admin-token-file")
        .arg(&missing_oast_secret);
    let output = command
        .output()
        .expect("run combined secret-precedence refusal");
    assert_oast_policy_precedes_selected_secret(
        output,
        &[
            "PRIVATE-MISSING-SESSION-SECRET",
            "PRIVATE-MISSING-OAST-SECRET",
            "invalid-oast-policy.toml",
        ],
    );

    let output = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/",
            "--profile",
            "web-review",
            "--auth-file",
        ])
        .arg(&missing_root_secret)
        .arg("--ssrf-oast-review")
        .arg("--ssrf-oast-policy")
        .arg(&invalid_oast_policy)
        .arg("--oast-admin-token-file")
        .arg(&missing_oast_secret)
        .output()
        .expect("run root-authorization secret-precedence refusal");
    assert_oast_policy_precedes_selected_secret(
        output,
        &["PRIVATE-MISSING-ROOT-SECRET", "PRIVATE-MISSING-OAST-SECRET"],
    );

    #[cfg(feature = "authorization-review")]
    {
        let output = termivar()
            .args([
                "scan",
                "http://127.0.0.1:9/app/",
                "--profile",
                "web-review",
                "--authorization-review-policy",
            ])
            .arg(&missing_authz_policy)
            .arg("--authz-primary-file")
            .arg(&missing_authz_primary)
            .arg("--authz-peer-file")
            .arg(&missing_authz_peer)
            .arg("--ssrf-oast-review")
            .arg("--ssrf-oast-policy")
            .arg(&invalid_oast_policy)
            .arg("--oast-admin-token-file")
            .arg(&missing_oast_secret)
            .output()
            .expect("run authorization-review secret-precedence refusal");
        assert_oast_policy_precedes_selected_secret(
            output,
            &[
                "PRIVATE-MISSING-AUTHZ-POLICY",
                "PRIVATE-MISSING-AUTHZ-PRIMARY",
                "PRIVATE-MISSING-AUTHZ-PEER",
                "PRIVATE-MISSING-OAST-SECRET",
            ],
        );
    }

    let output = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--session-policy",
        ])
        .arg(&session_policy)
        .arg("--session-auth-file")
        .arg(&missing_session_secret)
        .arg("--ssrf-oast-review")
        .arg("--ssrf-oast-policy")
        .arg(&invalid_oast_policy)
        .arg("--oast-admin-token-file")
        .arg(&missing_oast_secret)
        .arg("--report-dir")
        .arg(&blocked_destination)
        .output()
        .expect("run combined output-precedence refusal");
    assert_oast_policy_precedes_selected_secret(
        output,
        &[
            "PRIVATE-MISSING-SESSION-SECRET",
            "PRIVATE-MISSING-OAST-SECRET",
            "invalid-oast-policy.toml",
        ],
    );
    assert_eq!(
        fs::read(&blocked_destination).expect("read unchanged sentinel"),
        b"existing sentinel"
    );
}

fn assert_typed_evidence_reference(value: &Value, prefix: &str) {
    let reference = value
        .as_str()
        .expect("committed activity must have a string evidence reference");
    let digest = reference
        .strip_prefix(prefix)
        .expect("evidence reference must have the expected typed prefix");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "evidence reference must end in lowercase SHA-256 hex"
    );
}

fn authenticated_targets(records: &[RequestRecord]) -> Vec<&str> {
    records
        .iter()
        .filter(|record| record.authorization == AuthorizationClass::Expected)
        .map(|record| record.target.as_str())
        .collect()
}

#[test]
fn supplied_session_real_cli_commits_two_resources_and_is_offline_verifiable() {
    let server = serve(|_, target, authorization| match (target, authorization) {
        ("/app/health", AuthorizationClass::Expected) => response(
            "200 OK",
            "application/json",
            r#"{"authenticated":true}"#,
            "Set-Cookie: session=rotated-cookie-canary; Path=/app/; HttpOnly\r\n",
        ),
        ("/app/private", AuthorizationClass::Expected) => {
            json_ok(&format!(r#"{{"record":"{RESPONSE_CANARY}-ONE"}}"#))
        },
        ("/app/private-2", AuthorizationClass::Expected) => {
            json_ok(&format!(r#"{{"record":"{RESPONSE_CANARY}-TWO"}}"#))
        },
        (target, AuthorizationClass::Absent) if target.starts_with("/app/") => {
            html_ok("<main>ordinary anonymous fixture</main>")
        },
        _ => response(
            "401 Unauthorized",
            "application/json",
            r#"{"error":true}"#,
            "",
        ),
    });
    let parent = tempfile::tempdir().expect("create private test directory");
    let (policy_path, authorization_path) = write_inputs(parent.path());
    let destination = parent.path().join("bundle");
    let output = scan_bundle(&server, &policy_path, &authorization_path, &destination);
    assert!(
        output.status.success(),
        "scan failed with {:?}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);

    let (assessment_bytes, assessment) = read_assessment(&destination);
    assert_no_private_values(&assessment_bytes);
    assert_bundle_has_no_private_values(&destination);
    let audit = &assessment["supplied_session"];
    assert_eq!(audit["schema"], "security.supplied-session-audit/v1");
    assert_eq!(
        audit["capability_id"],
        "session.supplied-context-assessment@1"
    );
    assert_eq!(
        audit["principal_reference"],
        "supplied-session-principal-0001"
    );
    assert_eq!(audit["principal_alias"], "fixture-reader");
    assert_eq!(audit["principal_assurance"], "operator_declared");
    assert_eq!(audit["credential_mechanism"], "authorization_header");
    assert_eq!(audit["outcome"], "complete");
    assert_eq!(audit["coverage"], "complete");
    assert_eq!(audit["selected_resource_count"], 2);
    assert_eq!(audit["dispatched_resource_count"], 2);
    assert_eq!(audit["committed_resource_count"], 2);
    assert_eq!(audit["dispatched_request_count"], 5);
    assert_eq!(audit["checkpoints"].as_array().unwrap().len(), 3);
    assert_eq!(audit["resources"].as_array().unwrap().len(), 2);
    let checkpoints = audit["checkpoints"].as_array().unwrap();
    assert_eq!(checkpoints[0]["phase"], "startup");
    assert_eq!(checkpoints[1]["phase"], "subject_boundary");
    assert_eq!(checkpoints[2]["phase"], "terminal");
    for (sequence, checkpoint) in checkpoints.iter().enumerate() {
        assert_eq!(checkpoint["sequence"], sequence as u64);
        assert_eq!(checkpoint["after_subject_count"], sequence as u64);
        assert_eq!(checkpoint["outcome"], "healthy");
        assert_eq!(checkpoint["predicate"], "matched");
        assert_typed_evidence_reference(
            &checkpoint["evidence_reference"],
            "supplied-session-checkpoint-evidence-sha256:",
        );
    }
    for (sequence, resource) in audit["resources"].as_array().unwrap().iter().enumerate() {
        assert_eq!(resource["sequence"], sequence as u64);
        assert_eq!(resource["outcome"], "committed");
        assert_eq!(resource["status"], 200);
        assert_eq!(resource["epoch"], 1);
        assert_typed_evidence_reference(
            &resource["evidence_reference"],
            "supplied-session-resource-evidence-sha256:",
        );
    }
    for false_claim in [
        "refresh_performed",
        "anonymous_fallback_performed",
        "continuous_authentication_established",
    ] {
        assert_eq!(
            audit[false_claim], false,
            "unexpected claim in {false_claim}"
        );
    }
    assert_eq!(audit["exploit_execution"], "not_performed");
    assert_eq!(audit["impact_validation"], "not_performed");

    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(
        authenticated_targets(&requests_after_scan),
        [
            "/app/health",
            "/app/private",
            "/app/health",
            "/app/private-2",
            "/app/health",
        ]
    );
    assert!(requests_after_scan
        .iter()
        .all(|record| record.authorization != AuthorizationClass::Unexpected));
    assert!(requests_after_scan
        .iter()
        .all(|record| !record.cookie_present));
    assert!(requests_after_scan.iter().any(|record| {
        record.target == "/app/" && record.authorization == AuthorizationClass::Absent
    }));

    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&destination)
        .args(["--format", "json"])
        .output()
        .expect("verify supplied-session bundle");
    assert!(verify.status.success());
    assert_no_private_values(&verify.stdout);
    assert_no_private_values(&verify.stderr);
    let verification: Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verification["status"], "integrity_match");

    let comparison = termivar()
        .args(["report", "compare", "--before"])
        .arg(destination.join("assessment.json"))
        .arg("--after")
        .arg(destination.join("assessment.json"))
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("self-compare supplied-session bundle");
    assert!(
        comparison.status.success(),
        "self-compare failed: {}",
        String::from_utf8_lossy(&comparison.stderr)
    );
    assert_no_private_values(&comparison.stdout);
    assert_no_private_values(&comparison.stderr);
    let comparison: Value = serde_json::from_slice(&comparison.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len() as u64,
        assessment["item_count"].as_u64().unwrap()
    );
    assert_eq!(
        comparison["supplied_session_comparison"]["schema"],
        "termivar-supplied-session-comparison/v1"
    );
    assert_eq!(
        comparison["supplied_session_comparison"]["status"],
        "compared_within_same_declared_context"
    );
    assert_eq!(
        comparison["supplied_session_comparison"]["context"]["status"],
        "same_declared_context"
    );
    assert_eq!(
        comparison["supplied_session_comparison"]["health_and_coverage"]["status"],
        "unchanged"
    );
    assert_eq!(
        comparison["supplied_session_comparison"]["accounting"]["status"],
        "unchanged"
    );
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline Verify/Compare contacted the fixture"
    );
}

#[test]
fn supplied_session_does_not_commit_login_like_200_before_post_health_qualifies_it() {
    let health_count = Arc::new(Mutex::new(0_usize));
    let handler_count = Arc::clone(&health_count);
    let server = serve(
        move |_, target, authorization| match (target, authorization) {
            ("/app/health", AuthorizationClass::Expected) => {
                let mut count = handler_count.lock().unwrap();
                *count += 1;
                if *count == 1 {
                    json_ok(r#"{"authenticated":true}"#)
                } else {
                    json_ok(r#"{"authenticated":false}"#)
                }
            },
            ("/app/private", AuthorizationClass::Expected) => {
                html_ok(&format!("<form>{RESPONSE_CANARY}</form>"))
            },
            ("/app/private-2", AuthorizationClass::Expected) => {
                panic!("second protected resource must not be dispatched after session loss")
            },
            (target, AuthorizationClass::Absent) if target.starts_with("/app/") => {
                html_ok("<main>ordinary anonymous fixture</main>")
            },
            _ => response(
                "401 Unauthorized",
                "application/json",
                r#"{"error":true}"#,
                "",
            ),
        },
    );
    let parent = tempfile::tempdir().unwrap();
    let (policy_path, authorization_path) = write_inputs(parent.path());
    let destination = parent.path().join("loss-bundle");
    let output = scan_bundle(&server, &policy_path, &authorization_path, &destination);
    assert!(
        output.status.success(),
        "scan failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let (assessment_bytes, assessment) = read_assessment(&destination);
    assert_no_private_values(&assessment_bytes);
    let audit = &assessment["supplied_session"];
    assert_eq!(audit["outcome"], "session_lost");
    assert_eq!(audit["coverage"], "none");
    assert_eq!(audit["selected_resource_count"], 2);
    assert_eq!(audit["dispatched_resource_count"], 1);
    assert_eq!(audit["committed_resource_count"], 0);
    assert_eq!(audit["dispatched_request_count"], 3);
    assert_eq!(audit["checkpoints"].as_array().unwrap().len(), 2);
    assert_eq!(audit["resources"].as_array().unwrap().len(), 2);
    assert_eq!(audit["resources"][0]["outcome"], "health_unqualified");
    assert_eq!(audit["resources"][0]["status"], 200);
    assert_eq!(audit["resources"][1]["outcome"], "not_dispatched");
    assert_typed_evidence_reference(
        &audit["resources"][0]["evidence_reference"],
        "supplied-session-resource-evidence-sha256:",
    );
    assert!(audit["resources"][1]["evidence_reference"].is_null());
    for checkpoint in audit["checkpoints"].as_array().unwrap() {
        assert_typed_evidence_reference(
            &checkpoint["evidence_reference"],
            "supplied-session-checkpoint-evidence-sha256:",
        );
    }
    let records = server.requests.lock().unwrap().clone();
    assert_eq!(
        authenticated_targets(&records),
        ["/app/health", "/app/private", "/app/health"]
    );
    assert!(!records
        .iter()
        .any(|record| record.target == "/app/private-2"));
    assert!(records.iter().all(|record| !record.cookie_present));
}

#[test]
fn a_200_login_page_does_not_establish_session_health() {
    let server = serve(|_, target, authorization| match (target, authorization) {
        ("/app/health", AuthorizationClass::Expected) => html_ok("<form><input name=login></form>"),
        (target, AuthorizationClass::Expected) if target.starts_with("/app/private") => {
            panic!("protected resource must not run after an unhealthy startup")
        },
        (target, AuthorizationClass::Absent) if target.starts_with("/app/") => {
            html_ok("<main>ordinary anonymous fixture</main>")
        },
        _ => response(
            "401 Unauthorized",
            "application/json",
            r#"{"error":true}"#,
            "",
        ),
    });
    let parent = tempfile::tempdir().unwrap();
    let (policy_path, authorization_path) = write_inputs(parent.path());
    let destination = parent.path().join("login-bundle");
    let output = scan_bundle(&server, &policy_path, &authorization_path, &destination);
    assert!(output.status.success());
    let (assessment_bytes, assessment) = read_assessment(&destination);
    assert_no_private_values(&assessment_bytes);
    let audit = &assessment["supplied_session"];
    assert_eq!(audit["outcome"], "startup_unhealthy");
    assert_eq!(audit["coverage"], "none");
    assert_eq!(audit["dispatched_resource_count"], 0);
    assert_eq!(audit["committed_resource_count"], 0);
    assert_eq!(audit["dispatched_request_count"], 1);
    assert_eq!(audit["checkpoints"].as_array().unwrap().len(), 1);
    assert_eq!(audit["checkpoints"][0]["status"], 200);
    assert_eq!(audit["checkpoints"][0]["predicate"], "not_evaluated");
    assert_typed_evidence_reference(
        &audit["checkpoints"][0]["evidence_reference"],
        "supplied-session-checkpoint-evidence-sha256:",
    );
    assert!(audit["resources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|resource| resource["outcome"] == "not_dispatched"));
    assert_eq!(
        authenticated_targets(&server.requests.lock().unwrap()),
        ["/app/health"]
    );
}
