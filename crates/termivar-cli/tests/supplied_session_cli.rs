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
const BROAD_COOKIE: &str = "BROAD-COOKIE-PROCESS-CANARY-0123456789";
const NARROW_COOKIE: &str = "NARROW-COOKIE-PROCESS-CANARY-9876543210";
const ALTERNATE_BROAD_COOKIE: &str = "ALTERNATE-BROAD-COOKIE-PROCESS-CANARY";
const ALTERNATE_NARROW_COOKIE: &str = "ALTERNATE-NARROW-COOKIE-PROCESS-CANARY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationClass {
    Expected,
    Absent,
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookieClass {
    Expected,
    Alternate,
    Absent,
    Unexpected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestRecord {
    target: String,
    authorization: AuthorizationClass,
    cookie: CookieClass,
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
    F: Fn(usize, &str, AuthorizationClass, CookieClass) -> Vec<u8> + Send + Sync + 'static,
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
            let cookie = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("cookie").then(|| value.trim())
                })
                .map_or(CookieClass::Absent, |value| {
                    let expected = if target == "/app/private" {
                        format!("session={NARROW_COOKIE}; session={BROAD_COOKIE}")
                    } else {
                        format!("session={BROAD_COOKIE}")
                    };
                    let alternate = if target == "/app/private" {
                        format!(
                            "session={ALTERNATE_NARROW_COOKIE}; session={ALTERNATE_BROAD_COOKIE}"
                        )
                    } else {
                        format!("session={ALTERNATE_BROAD_COOKIE}")
                    };
                    if value == expected {
                        CookieClass::Expected
                    } else if value == alternate {
                        CookieClass::Alternate
                    } else {
                        CookieClass::Unexpected
                    }
                });
            let sequence = {
                let mut records = thread_requests.lock().expect("request trace lock");
                records.push(RequestRecord {
                    target: target.clone(),
                    authorization,
                    cookie,
                });
                records.len()
            };
            let response = handler(sequence, &target, authorization, cookie);
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

fn cookie_policy(host: &str) -> String {
    format!(
        r#"schema = "security.supplied-session-policy/v2"
principal_alias = "fixture-cookie-reader"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private", "/app/private-2"]
max_session_requests = 5
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000

[[cookies]]
id = "broad-session"
name = "session"
domain = "{host}"
host_only = true
path = "/app/"
secure = false
http_only = true
same_site = "lax"

[[cookies]]
id = "narrow-session"
name = "session"
domain = "{host}"
host_only = true
path = "/app/private"
secure = false
http_only = true
same_site = "strict"
expires_unix_seconds = 4102444800
"#
    )
}

fn principal_cookie_policy(host: &str, principal_alias: &str, resource: &str) -> String {
    format!(
        r#"schema = "security.supplied-session-policy/v2"
principal_alias = "{principal_alias}"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["{resource}"]
max_session_requests = 3
max_total_response_bytes = 65536
max_response_body_bytes = 16384
max_wall_time_ms = 5000

[[cookies]]
id = "principal-session"
name = "session"
domain = "{host}"
host_only = true
path = "/app/"
secure = false
http_only = true
same_site = "strict"
"#
    )
}

fn write_inputs(parent: &Path) -> (PathBuf, PathBuf) {
    let policy_path = parent.join("session-policy.toml");
    let authorization_path = parent.join("authorization.secret");
    fs::write(&policy_path, policy()).expect("write synthetic policy");
    fs::write(&authorization_path, format!("{AUTHORIZATION}\r\n"))
        .expect("write synthetic Authorization value");
    (policy_path, authorization_path)
}

fn write_cookie_inputs(parent: &Path, application_url: &str) -> (PathBuf, PathBuf) {
    let host = url::Url::parse(application_url)
        .expect("parse fixture application URL")
        .host_str()
        .expect("fixture URL has host")
        .to_owned();
    let policy_path = parent.join("cookie-session-policy.toml");
    let cookie_path = parent.join("cookies.secret.tsv");
    fs::write(&policy_path, cookie_policy(&host)).expect("write synthetic cookie policy");
    fs::write(
        &cookie_path,
        format!("narrow-session\t{NARROW_COOKIE}\r\nbroad-session\t{BROAD_COOKIE}\n"),
    )
    .expect("write synthetic cookie secret");
    (policy_path, cookie_path)
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

fn scan_cookie_bundle(
    server: &TestServer,
    policy_path: &Path,
    cookie_path: &Path,
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
        .arg("--session-cookie-file")
        .arg(cookie_path)
        .arg("--report-dir")
        .arg(destination)
        .output()
        .expect("run supplied-cookie assessment")
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
        "COOKIE-PROCESS-CANARY",
        BROAD_COOKIE,
        NARROW_COOKIE,
        ALTERNATE_BROAD_COOKIE,
        ALTERNATE_NARROW_COOKIE,
        RESPONSE_CANARY,
        "/app/private",
        "/app/alice-private",
        "/app/bob-private",
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

fn cookie_targets(records: &[RequestRecord]) -> Vec<&str> {
    records
        .iter()
        .filter(|record| record.cookie == CookieClass::Expected)
        .map(|record| record.target.as_str())
        .collect()
}

fn assert_bundle_verify_and_self_compare_are_offline(
    server: &TestServer,
    destination: &Path,
    assessment: &Value,
) {
    let requests_after_scan = server.requests.lock().unwrap().clone();
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(destination)
        .args(["--format", "json"])
        .output()
        .expect("verify supplied-session bundle");
    assert!(
        verify.status.success(),
        "Verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
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
        comparison["supplied_session_comparison"]["status"],
        "compared_within_same_declared_context"
    );
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline Verify/Compare contacted the fixture"
    );
}

#[test]
fn supplied_cookie_real_cli_preserves_scope_order_and_offline_contracts() {
    let server = serve(
        |_, target, authorization, cookie| match (target, authorization, cookie) {
            ("/app/health", AuthorizationClass::Absent, CookieClass::Expected) => response(
                "200 OK",
                "application/json",
                r#"{"authenticated":true}"#,
                "Set-Cookie: analytics=VALUE-MUST-NOT-BE-RETAINED; Path=/app/; HttpOnly\r\n",
            ),
            ("/app/private", AuthorizationClass::Absent, CookieClass::Expected) => {
                json_ok(&format!(r#"{{"record":"{RESPONSE_CANARY}-COOKIE-ONE"}}"#))
            },
            ("/app/private-2", AuthorizationClass::Absent, CookieClass::Expected) => {
                json_ok(&format!(r#"{{"record":"{RESPONSE_CANARY}-COOKIE-TWO"}}"#))
            },
            (target, AuthorizationClass::Absent, CookieClass::Absent)
                if target.starts_with("/app/") =>
            {
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
    let parent = tempfile::tempdir().expect("create private cookie fixture directory");
    let (policy_path, cookie_path) = write_cookie_inputs(parent.path(), &server.application_url);
    let destination = parent.path().join("cookie-bundle");
    let output = scan_cookie_bundle(&server, &policy_path, &cookie_path, &destination);
    assert!(
        output.status.success(),
        "cookie scan failed with {:?}:\nstdout:\n{}\nstderr:\n{}",
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
    assert_eq!(audit["schema"], "security.supplied-session-audit/v2");
    assert_eq!(audit["credential_mechanism"], "cookie_jar");
    assert_eq!(audit["outcome"], "complete");
    assert_eq!(audit["coverage"], "complete");
    assert_eq!(audit["selected_resource_count"], 2);
    assert_eq!(audit["dispatched_resource_count"], 2);
    assert_eq!(audit["committed_resource_count"], 2);
    assert_eq!(audit["dispatched_request_count"], 5);
    assert_eq!(audit["checkpoints"].as_array().unwrap().len(), 3);
    assert_eq!(audit["resources"].as_array().unwrap().len(), 2);
    assert_eq!(audit["cookie_policy"]["declared_count"], 2);
    assert_eq!(audit["cookie_policy"]["host_only_count"], 2);
    assert_eq!(audit["cookie_policy"]["domain_count"], 0);
    assert_eq!(audit["cookie_policy"]["secure_count"], 0);
    assert_eq!(audit["cookie_policy"]["http_only_count"], 2);
    assert_eq!(audit["cookie_policy"]["session_count"], 1);
    assert_eq!(audit["cookie_policy"]["persistent_count"], 1);
    assert_eq!(
        audit["cookie_policy"]["update_policy"],
        "stop_on_selected_cookie"
    );
    assert_eq!(
        audit["cookie_policy"]["browser_semantics"],
        "attributes_preserved_not_browser_csrf_emulation"
    );
    assert_eq!(audit["cookie_lifecycle"]["initial_epoch"], 1);
    assert_eq!(audit["cookie_lifecycle"]["final_epoch"], 1);
    assert_eq!(
        audit["cookie_lifecycle"]["selected_update_response_count"],
        0
    );
    assert_eq!(
        audit["cookie_lifecycle"]["unselected_update_response_count"],
        3
    );
    assert_eq!(
        audit["cookie_lifecycle"]["update_classification_failure_count"],
        0
    );
    assert_eq!(audit["cookie_lifecycle"]["updates_applied"], 0);
    assert_eq!(audit["refresh_performed"], false);

    let records = server.requests.lock().unwrap().clone();
    assert_eq!(
        cookie_targets(&records),
        [
            "/app/health",
            "/app/private",
            "/app/health",
            "/app/private-2",
            "/app/health",
        ]
    );
    assert!(records
        .iter()
        .all(|record| record.authorization == AuthorizationClass::Absent));
    assert!(records
        .iter()
        .all(|record| record.cookie != CookieClass::Unexpected));
    assert!(records.iter().any(|record| {
        record.target == "/app/"
            && record.authorization == AuthorizationClass::Absent
            && record.cookie == CookieClass::Absent
    }));

    assert_bundle_verify_and_self_compare_are_offline(&server, &destination, &assessment);
}

#[test]
fn supplied_cookie_started_runtime_failure_retains_v2_value_free_audit_contract() {
    let server = serve(
        |_, target, authorization, cookie| match (target, authorization, cookie) {
            ("/app/health", AuthorizationClass::Absent, CookieClass::Expected) => {
                json_ok(r#"{"authenticated":true}"#)
            },
            ("/app/private", AuthorizationClass::Absent, CookieClass::Expected) => response(
                "200 OK",
                "application/json",
                &format!(r#"{{"record":"{RESPONSE_CANARY}"}}"#),
                "Set-Cookie: session=rotated-cookie-canary; Path=/app/; HttpOnly\r\n",
            ),
            ("/app/private-2", _, _) => {
                panic!("second resource must not run after a selected cookie update")
            },
            ("/app/", AuthorizationClass::Absent, CookieClass::Absent) => {
                // End the ordinary anonymous response before any HTTP bytes are
                // committed. The supplied-session child has already completed,
                // so the CLI must project its V2 audit into the started-failure
                // diagnostic without exposing credential material.
                Vec::new()
            },
            _ => response(
                "401 Unauthorized",
                "application/json",
                r#"{"error":true}"#,
                "",
            ),
        },
    );
    let parent = tempfile::tempdir().expect("create private started-failure fixture");
    let (policy_path, cookie_path) = write_cookie_inputs(parent.path(), &server.application_url);
    let output = termivar()
        .args([
            "scan",
            &server.application_url,
            "--profile",
            "web-review",
            "--format",
            "json",
        ])
        .arg("--session-policy")
        .arg(&policy_path)
        .arg("--session-cookie-file")
        .arg(&cookie_path)
        .output()
        .expect("run supplied-cookie started-failure assessment");

    assert!(
        !output.status.success(),
        "started failure must return nonzero"
    );
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let document: Value = serde_json::from_slice(&output.stdout)
        .expect("started failure emits bounded diagnostic JSON before returning nonzero");
    assert_eq!(document["schema_version"], "web-assessment/v2");
    assert_eq!(document["disposition"], "failed");
    assert!(document["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "started_runtime_failure"));
    let audit = &document["assessment"]["report"]["supplied_session_audit"];
    assert_eq!(audit["schema"], "security.supplied-session-audit/v2");
    assert_eq!(audit["credential_mechanism"], "cookie_jar");
    assert_eq!(audit["outcome"], "credential_update_required");
    assert_eq!(audit["cookie_policy"]["declared_count"], 2);
    assert_eq!(audit["cookie_policy"]["host_only_count"], 2);
    assert_eq!(audit["cookie_policy"]["domain_count"], 0);
    assert_eq!(audit["cookie_policy"]["secure_count"], 0);
    assert_eq!(audit["cookie_policy"]["http_only_count"], 2);
    assert_eq!(audit["cookie_policy"]["session_count"], 1);
    assert_eq!(audit["cookie_policy"]["persistent_count"], 1);
    assert_eq!(audit["cookie_policy"]["same_site_missing_count"], 0);
    assert_eq!(audit["cookie_policy"]["same_site_strict_count"], 1);
    assert_eq!(audit["cookie_policy"]["same_site_lax_count"], 1);
    assert_eq!(audit["cookie_policy"]["same_site_none_count"], 0);
    assert_eq!(
        audit["cookie_policy"]["update_policy"],
        "stop_on_selected_cookie"
    );
    assert_eq!(
        audit["cookie_policy"]["browser_semantics"],
        "attributes_preserved_not_browser_csrf_emulation"
    );
    assert_eq!(audit["cookie_lifecycle"]["initial_epoch"], 1);
    assert_eq!(audit["cookie_lifecycle"]["final_epoch"], 1);
    assert_eq!(
        audit["cookie_lifecycle"]["selected_update_response_count"],
        1
    );
    assert_eq!(
        audit["cookie_lifecycle"]["unselected_update_response_count"],
        0
    );
    assert_eq!(
        audit["cookie_lifecycle"]["update_classification_failure_count"],
        0
    );
    assert_eq!(audit["cookie_lifecycle"]["updates_applied"], 0);

    let text_output = termivar()
        .args([
            "scan",
            &server.application_url,
            "--profile",
            "web-review",
            "--format",
            "text",
        ])
        .arg("--session-policy")
        .arg(&policy_path)
        .arg("--session-cookie-file")
        .arg(&cookie_path)
        .output()
        .expect("run supplied-cookie started-failure text assessment");
    assert!(!text_output.status.success());
    assert_no_private_values(&text_output.stdout);
    assert_no_private_values(&text_output.stderr);
    let text = String::from_utf8(text_output.stdout).expect("text diagnostic is UTF-8");
    assert!(text.contains("outcome=credential_update_required coverage=none"));
    assert!(!text.contains("outcome=unknown"));
}

#[test]
fn supplied_cookie_real_cli_partitions_two_principals_and_anonymous_collection() {
    let server = serve(
        |_, target, authorization, cookie| match (target, authorization, cookie) {
            ("/app/health", AuthorizationClass::Absent, CookieClass::Expected)
            | ("/app/health", AuthorizationClass::Absent, CookieClass::Alternate) => {
                json_ok(r#"{"authenticated":true}"#)
            },
            ("/app/alice-private", AuthorizationClass::Absent, CookieClass::Expected) => {
                json_ok(&format!(r#"{{"record":"{RESPONSE_CANARY}-ALICE"}}"#))
            },
            ("/app/bob-private", AuthorizationClass::Absent, CookieClass::Alternate) => {
                json_ok(&format!(r#"{{"record":"{RESPONSE_CANARY}-BOB"}}"#))
            },
            (target, AuthorizationClass::Absent, CookieClass::Absent)
                if target.starts_with("/app/") =>
            {
                html_ok("<main>ordinary anonymous fixture without protected links</main>")
            },
            ("/app/bob-private", AuthorizationClass::Absent, CookieClass::Expected) => response(
                "403 Forbidden",
                "application/json",
                r#"{"denied":true}"#,
                "",
            ),
            ("/app/alice-private", AuthorizationClass::Absent, CookieClass::Alternate) => response(
                "403 Forbidden",
                "application/json",
                r#"{"denied":true}"#,
                "",
            ),
            _ => response(
                "401 Unauthorized",
                "application/json",
                r#"{"error":true}"#,
                "",
            ),
        },
    );
    let parent = tempfile::tempdir().expect("create private two-principal fixture");
    let host = url::Url::parse(&server.application_url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_owned();
    let alice_policy = parent.path().join("alice-policy.toml");
    let alice_secret = parent.path().join("alice-cookies.secret.tsv");
    let bob_policy = parent.path().join("bob-policy.toml");
    let bob_secret = parent.path().join("bob-cookies.secret.tsv");
    fs::write(
        &alice_policy,
        principal_cookie_policy(&host, "fixture-alice", "/app/alice-private"),
    )
    .unwrap();
    fs::write(
        &bob_policy,
        principal_cookie_policy(&host, "fixture-bob", "/app/bob-private"),
    )
    .unwrap();
    fs::write(
        &alice_secret,
        format!("principal-session\t{BROAD_COOKIE}\n"),
    )
    .unwrap();
    fs::write(
        &bob_secret,
        format!("principal-session\t{ALTERNATE_BROAD_COOKIE}\n"),
    )
    .unwrap();

    let alice_destination = parent.path().join("alice-bundle");
    let alice = scan_cookie_bundle(&server, &alice_policy, &alice_secret, &alice_destination);
    assert!(
        alice.status.success(),
        "Alice scan failed: stdout={} stderr={}",
        String::from_utf8_lossy(&alice.stdout),
        String::from_utf8_lossy(&alice.stderr)
    );
    let alice_boundary = server.requests.lock().unwrap().len();
    let (alice_bytes, alice_assessment) = read_assessment(&alice_destination);
    assert_no_private_values(&alice_bytes);
    assert_bundle_has_no_private_values(&alice_destination);
    assert_eq!(alice_assessment["supplied_session"]["outcome"], "complete");
    assert_eq!(
        alice_assessment["supplied_session"]["committed_resource_count"],
        1
    );
    assert_eq!(
        alice_assessment["supplied_session"]["dispatched_request_count"],
        3
    );

    let bob_destination = parent.path().join("bob-bundle");
    let bob = scan_cookie_bundle(&server, &bob_policy, &bob_secret, &bob_destination);
    assert!(
        bob.status.success(),
        "Bob scan failed: stdout={} stderr={}",
        String::from_utf8_lossy(&bob.stdout),
        String::from_utf8_lossy(&bob.stderr)
    );
    let (bob_bytes, bob_assessment) = read_assessment(&bob_destination);
    assert_no_private_values(&bob_bytes);
    assert_bundle_has_no_private_values(&bob_destination);
    assert_eq!(bob_assessment["supplied_session"]["outcome"], "complete");
    assert_eq!(
        bob_assessment["supplied_session"]["committed_resource_count"],
        1
    );
    assert_eq!(
        bob_assessment["supplied_session"]["dispatched_request_count"],
        3
    );

    let requests = server.requests.lock().unwrap().clone();
    let alice_requests = &requests[..alice_boundary];
    let bob_requests = &requests[alice_boundary..];
    assert_eq!(
        alice_requests
            .iter()
            .filter(|record| record.cookie == CookieClass::Expected)
            .map(|record| record.target.as_str())
            .collect::<Vec<_>>(),
        ["/app/health", "/app/alice-private", "/app/health"]
    );
    assert!(!alice_requests
        .iter()
        .any(|record| record.target == "/app/bob-private"));
    assert_eq!(
        bob_requests
            .iter()
            .filter(|record| record.cookie == CookieClass::Alternate)
            .map(|record| record.target.as_str())
            .collect::<Vec<_>>(),
        ["/app/health", "/app/bob-private", "/app/health"]
    );
    assert!(!bob_requests
        .iter()
        .any(|record| record.target == "/app/alice-private"));
    assert!(requests.iter().all(|record| {
        record.authorization == AuthorizationClass::Absent
            && record.cookie != CookieClass::Unexpected
    }));
    assert!(alice_requests
        .iter()
        .any(|record| record.cookie == CookieClass::Absent));
    assert!(bob_requests
        .iter()
        .any(|record| record.cookie == CookieClass::Absent));
    assert_bundle_verify_and_self_compare_are_offline(
        &server,
        &alice_destination,
        &alice_assessment,
    );
    assert_bundle_verify_and_self_compare_are_offline(&server, &bob_destination, &bob_assessment);
}

#[test]
fn supplied_cookie_selected_update_stops_without_applying_or_advancing_epoch() {
    let server = serve(
        |_, target, authorization, cookie| match (target, authorization, cookie) {
            ("/app/health", AuthorizationClass::Absent, CookieClass::Expected) => {
                json_ok(r#"{"authenticated":true}"#)
            },
            ("/app/private", AuthorizationClass::Absent, CookieClass::Expected) => response(
                "200 OK",
                "application/json",
                &format!(r#"{{"record":"{RESPONSE_CANARY}-COOKIE-UPDATE"}}"#),
                "Set-Cookie: session=rotated-cookie-canary; Path=/app/; HttpOnly\r\n",
            ),
            ("/app/private-2", _, _) => {
                panic!("second resource must not run after a selected cookie update")
            },
            (target, AuthorizationClass::Absent, CookieClass::Absent)
                if target.starts_with("/app/") =>
            {
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
    let parent = tempfile::tempdir().expect("create private cookie-update fixture");
    let (policy_path, cookie_path) = write_cookie_inputs(parent.path(), &server.application_url);
    let destination = parent.path().join("cookie-update-bundle");
    let output = scan_cookie_bundle(&server, &policy_path, &cookie_path, &destination);
    assert!(
        output.status.success(),
        "cookie update scan failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let (assessment_bytes, assessment) = read_assessment(&destination);
    assert_no_private_values(&assessment_bytes);
    assert_bundle_has_no_private_values(&destination);
    let audit = &assessment["supplied_session"];
    assert_eq!(audit["schema"], "security.supplied-session-audit/v2");
    assert_eq!(audit["outcome"], "credential_update_required");
    assert_eq!(audit["coverage"], "none");
    assert_eq!(audit["dispatched_request_count"], 2);
    assert_eq!(audit["dispatched_resource_count"], 1);
    assert_eq!(audit["committed_resource_count"], 0);
    assert_eq!(audit["checkpoints"].as_array().unwrap().len(), 1);
    assert_eq!(audit["resources"].as_array().unwrap().len(), 2);
    assert_eq!(audit["resources"][0]["outcome"], "health_unqualified");
    assert_eq!(audit["resources"][1]["outcome"], "not_dispatched");
    assert_eq!(
        audit["cookie_lifecycle"]["selected_update_response_count"],
        1
    );
    assert_eq!(
        audit["cookie_lifecycle"]["unselected_update_response_count"],
        0
    );
    assert_eq!(audit["cookie_lifecycle"]["initial_epoch"], 1);
    assert_eq!(audit["cookie_lifecycle"]["final_epoch"], 1);
    assert_eq!(audit["cookie_lifecycle"]["updates_applied"], 0);
    assert_eq!(audit["refresh_performed"], false);
    let records = server.requests.lock().unwrap().clone();
    assert_eq!(cookie_targets(&records), ["/app/health", "/app/private"]);
    assert!(!records
        .iter()
        .any(|record| record.target == "/app/private-2"));
    assert_bundle_verify_and_self_compare_are_offline(&server, &destination, &assessment);
}

#[test]
fn supplied_cookie_unusable_update_stops_without_applying_or_advancing_epoch() {
    let server = serve(
        |_, target, authorization, cookie| match (target, authorization, cookie) {
            ("/app/health", AuthorizationClass::Absent, CookieClass::Expected) => {
                json_ok(r#"{"authenticated":true}"#)
            },
            ("/app/private", AuthorizationClass::Absent, CookieClass::Expected) => response(
                "200 OK",
                "application/json",
                &format!(r#"{{"record":"{RESPONSE_CANARY}-COOKIE-UNUSABLE"}}"#),
                "Set-Cookie: analytics=invalid value; Path=/app/; HttpOnly\r\n",
            ),
            ("/app/private-2", _, _) => {
                panic!("second resource must not run after an unusable cookie update")
            },
            (target, AuthorizationClass::Absent, CookieClass::Absent)
                if target.starts_with("/app/") =>
            {
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
    let parent = tempfile::tempdir().expect("create private unusable-update fixture");
    let (policy_path, cookie_path) = write_cookie_inputs(parent.path(), &server.application_url);
    let destination = parent.path().join("cookie-unusable-update-bundle");
    let output = scan_cookie_bundle(&server, &policy_path, &cookie_path, &destination);
    assert!(
        output.status.success(),
        "unusable cookie update scan failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_private_values(&output.stdout);
    assert_no_private_values(&output.stderr);
    let (assessment_bytes, assessment) = read_assessment(&destination);
    assert_no_private_values(&assessment_bytes);
    assert_bundle_has_no_private_values(&destination);
    let audit = &assessment["supplied_session"];
    assert_eq!(audit["schema"], "security.supplied-session-audit/v2");
    assert_eq!(audit["outcome"], "credential_update_unusable");
    assert_eq!(audit["coverage"], "none");
    assert_eq!(audit["dispatched_request_count"], 2);
    assert_eq!(audit["dispatched_resource_count"], 1);
    assert_eq!(audit["committed_resource_count"], 0);
    assert_eq!(audit["checkpoints"].as_array().unwrap().len(), 1);
    assert_eq!(audit["resources"].as_array().unwrap().len(), 2);
    assert_eq!(audit["resources"][0]["outcome"], "health_unqualified");
    assert_eq!(audit["resources"][1]["outcome"], "not_dispatched");
    assert_eq!(
        audit["cookie_lifecycle"]["selected_update_response_count"],
        0
    );
    assert_eq!(
        audit["cookie_lifecycle"]["unselected_update_response_count"],
        0
    );
    assert_eq!(
        audit["cookie_lifecycle"]["update_classification_failure_count"],
        1
    );
    assert_eq!(audit["cookie_lifecycle"]["initial_epoch"], 1);
    assert_eq!(audit["cookie_lifecycle"]["final_epoch"], 1);
    assert_eq!(audit["cookie_lifecycle"]["updates_applied"], 0);
    assert_eq!(audit["refresh_performed"], false);
    let records = server.requests.lock().unwrap().clone();
    assert_eq!(cookie_targets(&records), ["/app/health", "/app/private"]);
    assert!(!records
        .iter()
        .any(|record| record.target == "/app/private-2"));
    assert_bundle_verify_and_self_compare_are_offline(&server, &destination, &assessment);
}

#[test]
fn supplied_cookie_preflight_rejects_mismatch_secure_http_and_expired_coverage() {
    let parent = tempfile::tempdir().expect("create private cookie preflight fixture");
    let host = "127.0.0.1";
    let cookie_path = parent.path().join("cookies.secret.tsv");
    fs::write(
        &cookie_path,
        format!("narrow-session\t{NARROW_COOKIE}\nbroad-session\t{BROAD_COOKIE}\n"),
    )
    .unwrap();

    let authorization_policy = parent.path().join("authorization-policy.toml");
    fs::write(&authorization_policy, policy()).unwrap();
    let missing_cookie = parent.path().join("PRIVATE-MISSING-COOKIE-SECRET");
    let mismatch = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--session-policy",
        ])
        .arg(&authorization_policy)
        .arg("--session-cookie-file")
        .arg(&missing_cookie)
        .output()
        .expect("run credential-mechanism mismatch");
    assert!(!mismatch.status.success());
    assert!(mismatch.stdout.is_empty());
    let mismatch_stderr = String::from_utf8(mismatch.stderr).unwrap();
    assert!(mismatch_stderr.contains("CredentialMechanismMismatch"));
    assert!(!mismatch_stderr.contains("PRIVATE-MISSING-COOKIE-SECRET"));

    let secure_policy = parent.path().join("secure-over-http-policy.toml");
    fs::write(
        &secure_policy,
        cookie_policy(host).replace("secure = false", "secure = true"),
    )
    .unwrap();
    let secure = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--session-policy",
        ])
        .arg(&secure_policy)
        .arg("--session-cookie-file")
        .arg(&cookie_path)
        .output()
        .expect("run Secure-cookie HTTP refusal");
    assert!(!secure.status.success());
    assert!(secure.stdout.is_empty());
    assert!(String::from_utf8(secure.stderr)
        .unwrap()
        .contains("InvalidPolicy"));

    let expired_policy = parent.path().join("expired-cookie-policy.toml");
    fs::write(
        &expired_policy,
        cookie_policy(host).replacen(
            "same_site = \"lax\"",
            "same_site = \"lax\"\nexpires_unix_seconds = 1",
            1,
        ),
    )
    .unwrap();
    let expired = termivar()
        .args([
            "scan",
            "http://127.0.0.1:9/app/",
            "--profile",
            "web-review",
            "--session-policy",
        ])
        .arg(&expired_policy)
        .arg("--session-cookie-file")
        .arg(&cookie_path)
        .output()
        .expect("run expired-cookie refusal");
    assert!(!expired.status.success());
    assert!(expired.stdout.is_empty());
    let expired_stderr = String::from_utf8(expired.stderr).unwrap();
    assert!(expired_stderr.contains("InvalidCredentialValue"));
    assert!(!expired_stderr.contains(BROAD_COOKIE));
    assert!(!expired_stderr.contains(NARROW_COOKIE));
}

#[test]
fn supplied_session_real_cli_commits_two_resources_and_is_offline_verifiable() {
    let server = serve(
        |_, target, authorization, _| match (target, authorization) {
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
        },
    );
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
        .all(|record| record.cookie == CookieClass::Absent));
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
        move |_, target, authorization, _| match (target, authorization) {
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
    assert!(records
        .iter()
        .all(|record| record.cookie == CookieClass::Absent));
}

#[test]
fn a_200_login_page_does_not_establish_session_health() {
    let server = serve(
        |_, target, authorization, _| match (target, authorization) {
            ("/app/health", AuthorizationClass::Expected) => {
                html_ok("<form><input name=login></form>")
            },
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
        },
    );
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
