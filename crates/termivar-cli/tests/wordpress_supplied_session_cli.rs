//! Actual-process acceptance for WordPress observations supplied by one bounded
//! cookie session.
//!
//! The numeric-loopback fixture is owned by this test. Its request ledger stores
//! only typed credential presence, never the cookie value. The anonymous entry
//! selects the conventional WordPress layout; one health-qualified protected
//! HTML resource can then nominate a plugin readme without granting credentials
//! to that metadata request.

#![cfg(all(feature = "wordpress-review", feature = "supplied-session-review"))]

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
use sha2::{Digest, Sha256};

const SESSION_COOKIE: &str = "WORDPRESS-SESSION-COOKIE-CANARY-7c23b1a91f";
const PROTECTED_BODY_CANARY: &str = "PRIVATE-WORDPRESS-PAGE-CANARY-MUST-NOT-LEAK";
const MISSING_POLICY_PATH_CANARY: &str = "PRIVATE-MISSING-POLICY-CANARY.toml";
const MISSING_SECRET_PATH_CANARY: &str = "PRIVATE-MISSING-COOKIE-CANARY.tsv";

const ENTRY_HTML: &str = r#"<!doctype html><html><head>
<meta name="generator" content="WordPress 6.9.4">
<link rel="https://api.w.org/" href="/wp-json/">
<link rel="stylesheet" href="/wp-content/themes/session-fixture-theme/style.css">
</head><body>public synthetic WordPress entry</body></html>"#;

const PROTECTED_HTML: &str = r#"<!doctype html><html><head>
<script src="/wp-content/plugins/session-page-component/assets/site.js"></script>
<link rel="stylesheet" href="/wp-content/plugins/session-page-component/assets/site.css">
</head><body>PRIVATE-WORDPRESS-PAGE-CANARY-MUST-NOT-LEAK</body></html>"#;

const REST_INDEX: &str = r#"{"namespaces":["wp/v2","oembed/1.0"]}"#;
const THEME_STYLESHEET: &str = r#"/*
Theme Name: Session Fixture Theme
Version: 1.5
*/
body { color: #111; }
"#;
const PLUGIN_README: &str = r#"=== Session Page Component ===
Stable tag: 9.9.9
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionBehavior {
    Healthy,
    LostAfterResource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CookieClass {
    Expected,
    Absent,
    Unexpected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestRecord {
    method: String,
    target: String,
    cookie: CookieClass,
    authorization_present: bool,
    proxy_authorization_present: bool,
}

struct FixtureServer {
    origin: String,
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

fn serve(behavior: SessionBehavior) -> FixtureServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let address: SocketAddr = listener.local_addr().expect("read fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    let health_request_count = Arc::new(Mutex::new(0_usize));
    let thread_health_request_count = Arc::clone(&health_request_count);

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
            let mut request_line = request
                .lines()
                .next()
                .unwrap_or_default()
                .split_ascii_whitespace();
            let method = request_line.next().unwrap_or_default().to_owned();
            let target = request_line.next().unwrap_or_default().to_owned();
            let header = |expected: &str| {
                request.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case(expected).then(|| value.trim())
                })
            };
            let cookie = match header("cookie") {
                Some(value) if value == format!("session={SESSION_COOKIE}") => {
                    CookieClass::Expected
                },
                Some(_) => CookieClass::Unexpected,
                None => CookieClass::Absent,
            };
            let record = RequestRecord {
                method: method.clone(),
                target: target.clone(),
                cookie,
                authorization_present: header("authorization").is_some(),
                proxy_authorization_present: header("proxy-authorization").is_some(),
            };
            thread_requests
                .lock()
                .expect("request ledger lock")
                .push(record);

            let (status, media_type, body) = match (method.as_str(), target.as_str(), cookie) {
                ("GET", "/session-health", CookieClass::Expected) => {
                    let mut count = thread_health_request_count
                        .lock()
                        .expect("health counter lock");
                    *count += 1;
                    let healthy = behavior == SessionBehavior::Healthy || *count == 1;
                    (
                        "200 OK",
                        "application/json; charset=utf-8",
                        if healthy {
                            r#"{"authenticated":true}"#
                        } else {
                            r#"{"authenticated":false}"#
                        },
                    )
                },
                ("GET", "/member-page", CookieClass::Expected) => {
                    ("200 OK", "text/html; charset=utf-8", PROTECTED_HTML)
                },
                ("GET" | "HEAD", "/", CookieClass::Absent) => {
                    ("200 OK", "text/html; charset=utf-8", ENTRY_HTML)
                },
                ("GET", "/wp-json/", CookieClass::Absent) => {
                    ("200 OK", "application/json; charset=utf-8", REST_INDEX)
                },
                (
                    "GET" | "HEAD",
                    "/wp-content/themes/session-fixture-theme/style.css",
                    CookieClass::Absent,
                ) => ("200 OK", "text/css; charset=utf-8", THEME_STYLESHEET),
                (
                    "GET",
                    "/wp-content/plugins/session-page-component/readme.txt",
                    CookieClass::Absent,
                ) => ("200 OK", "text/plain; charset=utf-8", PLUGIN_README),
                _ => ("404 Not Found", "text/plain; charset=utf-8", "not found"),
            };
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes());
            if method != "HEAD" {
                let _ = stream.write_all(body.as_bytes());
            }
            let _ = stream.flush();
        }
    });

    FixtureServer {
        origin: format!("http://{address}/"),
        requests,
    }
}

fn policy(application_url: &str) -> String {
    let host = url::Url::parse(application_url)
        .expect("parse fixture application URL")
        .host_str()
        .expect("fixture URL has host")
        .to_owned();
    format!(
        r#"schema = "security.supplied-session-policy/v2"
principal_alias = "synthetic-wordpress-member"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/session-health"
health_json_field = "authenticated"
resources = ["/member-page"]
max_session_requests = 3
max_total_response_bytes = 131072
max_response_body_bytes = 32768
max_wall_time_ms = 5000

[[cookies]]
id = "fixture-session"
name = "session"
domain = "{host}"
host_only = true
path = "/"
secure = false
http_only = true
same_site = "strict"
"#
    )
}

fn write_inputs(parent: &Path, origin: &str) -> (PathBuf, PathBuf) {
    let policy_path = parent.join("session-policy.toml");
    let cookie_path = parent.join("session-cookie.secret.tsv");
    fs::write(&policy_path, policy(origin)).expect("write supplied-session policy");
    fs::write(
        &cookie_path,
        format!("fixture-session\t{SESSION_COOKIE}\r\n"),
    )
    .expect("write supplied-session secret");
    (policy_path, cookie_path)
}

fn scan(
    server: &FixtureServer,
    policy_path: &Path,
    cookie_path: &Path,
    report_directory: &Path,
) -> Output {
    termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--wordpress-supplied-session",
            "--session-policy",
        ])
        .arg(policy_path)
        .arg("--session-cookie-file")
        .arg(cookie_path)
        .arg("--report-dir")
        .arg(report_directory)
        .arg(&server.origin)
        .output()
        .expect("execute WordPress supplied-session CLI")
}

fn scan_without_wordpress_session_integration(
    server: &FixtureServer,
    policy_path: &Path,
    cookie_path: &Path,
    report_directory: &Path,
) -> Output {
    termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-discovery",
            "--session-policy",
        ])
        .arg(policy_path)
        .arg("--session-cookie-file")
        .arg(cookie_path)
        .arg("--report-dir")
        .arg(report_directory)
        .arg(&server.origin)
        .output()
        .expect("execute option-off WordPress supplied-session CLI")
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with {:?}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_scan_success(server: &FixtureServer, output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with {:?}:\nrequest ledger: {:#?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        server.requests.lock().expect("request ledger lock"),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_assessment(report_directory: &Path) -> (Vec<u8>, Value) {
    let bytes = fs::read(report_directory.join("assessment.json"))
        .expect("read assessment JSON from bundle");
    let document = serde_json::from_slice(&bytes).expect("parse assessment JSON");
    (bytes, document)
}

fn assert_no_secret(bytes: &[u8]) {
    let rendered = String::from_utf8_lossy(bytes);
    for private in [
        SESSION_COOKIE,
        PROTECTED_BODY_CANARY,
        MISSING_POLICY_PATH_CANARY,
        MISSING_SECRET_PATH_CANARY,
    ] {
        assert!(
            !rendered.contains(private),
            "output retained supplied-session private data"
        );
    }
}

fn assert_bundle_has_no_secret(report_directory: &Path) {
    for entry in fs::read_dir(report_directory).expect("read report bundle") {
        let entry = entry.expect("read report bundle entry");
        if entry
            .file_type()
            .expect("read report bundle entry type")
            .is_file()
        {
            assert_no_secret(&fs::read(entry.path()).expect("read report bundle member"));
        }
    }
}

fn assert_transport_partition(records: &[RequestRecord]) {
    assert!(records
        .iter()
        .all(|record| !record.authorization_present && !record.proxy_authorization_present));
    assert!(records
        .iter()
        .all(|record| record.cookie != CookieClass::Unexpected));

    let credentialed = records
        .iter()
        .filter(|record| record.cookie == CookieClass::Expected)
        .map(|record| (record.method.as_str(), record.target.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        credentialed,
        [
            ("GET", "/session-health"),
            ("GET", "/member-page"),
            ("GET", "/session-health"),
        ],
        "only the bounded supplied-session child may carry the cookie"
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record.method == "GET" && record.target == "/member-page")
            .count(),
        1,
        "WordPress integration must reuse the supplied-session response instead of fetching the page anonymously"
    );

    for public_metadata_path in [
        "/wp-json/",
        "/wp-content/themes/session-fixture-theme/style.css",
        "/wp-content/plugins/session-page-component/readme.txt",
    ] {
        assert!(records.iter().all(|record| {
            record.target != public_metadata_path || record.cookie == CookieClass::Absent
        }));
        let get_count = records
            .iter()
            .filter(|record| record.method == "GET" && record.target == public_metadata_path)
            .count();
        assert!(
            get_count <= 1,
            "public WordPress metadata must not be fetched more than once"
        );
    }
}

fn assert_offline_verify_and_self_compare(
    server: &FixtureServer,
    report_directory: &Path,
    assessment: &Value,
) {
    let requests_after_scan = server.requests.lock().expect("request ledger lock").clone();
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(report_directory)
        .args(["--format", "json"])
        .output()
        .expect("execute Report Verify");
    assert_success(&verify, "Report Verify");
    assert_no_secret(&verify.stdout);
    assert_no_secret(&verify.stderr);
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("parse Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let assessment_path = report_directory.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("execute Report Compare");
    assert_success(&compare, "Report Compare");
    assert_no_secret(&compare.stdout);
    assert_no_secret(&compare.stderr);
    let comparison: Value = serde_json::from_slice(&compare.stdout).expect("parse Compare JSON");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group]
            .as_array()
            .expect("comparison group must be an array")
            .is_empty());
    }
    assert_eq!(
        comparison["unchanged"]
            .as_array()
            .expect("unchanged must be an array")
            .len() as u64,
        assessment["item_count"]
            .as_u64()
            .expect("assessment item_count must be an integer")
    );
    assert_eq!(
        server
            .requests
            .lock()
            .expect("request ledger lock")
            .as_slice(),
        requests_after_scan,
        "offline Verify/Compare contacted the fixture"
    );
}

fn source<'a>(discovery: &'a Value, kind: &str, slug: Option<&str>) -> &'a Value {
    discovery["sources"]
        .as_array()
        .expect("WordPress discovery sources must be an array")
        .iter()
        .find(|source| {
            source["kind"] == kind
                && source
                    .get("component")
                    .and_then(|component| component.get("slug"))
                    .and_then(Value::as_str)
                    == slug
        })
        .expect("expected WordPress discovery source")
}

fn assert_sha256_reference(value: &Value, prefix: &str) {
    let reference = value.as_str().expect("reference must be a string");
    let digest = reference
        .strip_prefix(prefix)
        .expect("reference must use the reviewed domain prefix");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "reference must end in lowercase SHA-256 hex"
    );
}

fn expected_context_page_reference(session: &Value, target: &str, sequence: u8) -> String {
    let resource_reference = session["resources"][usize::from(sequence)]["resource_reference"]
        .as_str()
        .expect("session resource reference must be a string");
    let mut digest = Sha256::new();
    for value in [
        b"security.wordpress-supplied-session-page.v1".as_slice(),
        session["policy_reference"].as_str().unwrap().as_bytes(),
        session["application_reference"]
            .as_str()
            .unwrap()
            .as_bytes(),
        session["principal_reference"].as_str().unwrap().as_bytes(),
        target.as_bytes(),
        resource_reference.as_bytes(),
        &[sequence],
    ] {
        digest.update(u64::try_from(value.len()).unwrap().to_be_bytes());
        digest.update(value);
    }
    format!("sha256:{:x}", digest.finalize())
}

fn assert_supplied_session_page_scope(
    discovery: &Value,
    session: &Value,
    target: &str,
    committed: bool,
) -> String {
    let scope = discovery["supplied_session_pages"]
        .as_object()
        .expect("v4 discovery must contain a supplied-session page ledger");
    assert_eq!(scope["mode"], "committed_supplied_session_resources");
    assert_eq!(scope["policy_reference"], session["policy_reference"]);
    assert_eq!(
        scope["application_reference"],
        session["application_reference"]
    );
    assert_eq!(scope["principal_reference"], session["principal_reference"]);
    assert_eq!(scope["credential_mechanism"], "cookie_jar");
    assert_eq!(scope["session_epoch"], 1);
    assert_eq!(scope["selected_count"], 1);
    assert_eq!(scope["committed_count"], u64::from(committed));
    assert_eq!(scope["accepted_association_count"], u64::from(committed));
    assert_eq!(scope["rejected_association_count"], 0);
    assert_eq!(
        scope["not_established_association_count"],
        u64::from(!committed)
    );
    assert_eq!(scope["not_evaluated_count"], u64::from(!committed));

    let pages = scope["pages"]
        .as_array()
        .expect("supplied-session pages must be an array");
    assert_eq!(pages.len(), 1);
    let page = &pages[0];
    let expected_page_reference = expected_context_page_reference(session, target, 0);
    assert_eq!(page["page_reference"], expected_page_reference);
    assert_sha256_reference(&page["page_reference"], "sha256:");
    assert_eq!(
        page["resource_reference"],
        session["resources"][0]["resource_reference"]
    );
    assert_sha256_reference(
        &page["resource_reference"],
        "supplied-session-resource-sha256:",
    );
    assert_eq!(page["acquisition"], "reused_supplied_session_response");
    assert_eq!(page["fingerprint_evaluation"], "not_selected_in_v1");
    if committed {
        assert_eq!(
            page["resource_evidence_reference"],
            session["resources"][0]["evidence_reference"]
        );
        assert_sha256_reference(
            &page["resource_evidence_reference"],
            "supplied-session-resource-evidence-sha256:",
        );
        assert_eq!(page["association"], "accepted");
        assert_eq!(page["outcome"], "accepted");
        assert_eq!(page["interpreted_response_bytes"], PROTECTED_HTML.len());
        assert_eq!(scope["interpreted_response_bytes"], PROTECTED_HTML.len());
        assert_eq!(page["evidence_reference_count"], 1);
        assert_eq!(page["evidence_references"].as_array().unwrap().len(), 1);
    } else {
        assert!(page["resource_evidence_reference"].is_null());
        assert_eq!(page["association"], "not_established");
        assert_eq!(page["outcome"], "not_evaluated");
        assert_eq!(page["interpreted_response_bytes"], 0);
        assert_eq!(scope["interpreted_response_bytes"], 0);
        assert_eq!(page["evidence_reference_count"], 0);
        assert!(page["evidence_references"].as_array().unwrap().is_empty());
    }
    expected_page_reference
}

#[test]
fn supplied_session_without_wordpress_integration_preserves_entry_only_discovery() {
    let server = serve(SessionBehavior::Healthy);
    let temporary = tempfile::tempdir().expect("create private test directory");
    let (policy_path, cookie_path) = write_inputs(temporary.path(), &server.origin);
    let report_directory = temporary.path().join("option-off-bundle");
    let output = scan_without_wordpress_session_integration(
        &server,
        &policy_path,
        &cookie_path,
        &report_directory,
    );
    assert_scan_success(
        &server,
        &output,
        "option-off WordPress supplied-session scan",
    );
    assert_no_secret(&output.stdout);
    assert_no_secret(&output.stderr);

    let (assessment_bytes, assessment) = read_assessment(&report_directory);
    assert_no_secret(&assessment_bytes);
    assert_bundle_has_no_secret(&report_directory);

    let session = &assessment["supplied_session"];
    assert_eq!(session["schema"], "security.supplied-session-audit/v2");
    assert_eq!(session["outcome"], "complete");
    assert_eq!(session["selected_resource_count"], 1);
    assert_eq!(session["committed_resource_count"], 1);
    assert_eq!(session["dispatched_request_count"], 3);

    let discovery = &assessment["wordpress_discovery"];
    assert_eq!(discovery["schema"], "security.wordpress-discovery-audit/v2");
    assert_eq!(
        discovery["policy_id"],
        "termivar.wordpress-deployment-aware-metadata-discovery/v1"
    );
    assert_eq!(discovery["credential_mode"], "anonymous");
    assert_eq!(discovery["attempted_request_count"], 2);
    assert_eq!(discovery["completed_response_count"], 2);
    assert_eq!(discovery["committed_response_count"], 2);
    assert_eq!(discovery["source_count"], 2);
    assert!(discovery.get("supplied_session_pages").is_none());
    let sources = discovery["sources"]
        .as_array()
        .expect("entry-only discovery sources must be an array");
    assert_eq!(sources.len(), 2);
    assert!(sources.iter().all(|source| {
        source
            .get("source_supplied_session_page_references")
            .is_none()
    }));
    assert!(sources.iter().all(|source| {
        source
            .get("component")
            .and_then(|component| component.get("slug"))
            .and_then(Value::as_str)
            != Some("session-page-component")
    }));
    assert!(assessment["wordpress_review"]["components"]
        .as_array()
        .expect("WordPress components must be an array")
        .iter()
        .all(|component| component["identity"]["slug"] != "session-page-component"));
    assert!(assessment.get("wordpress_asset_fingerprints").is_none());

    let records = server.requests.lock().expect("request ledger lock").clone();
    assert_transport_partition(&records);
    let wordpress_metadata_gets = records
        .iter()
        .filter(|record| {
            record.method == "GET"
                && matches!(
                    record.target.as_str(),
                    "/wp-json/"
                        | "/wp-content/themes/session-fixture-theme/style.css"
                        | "/wp-content/plugins/session-page-component/readme.txt"
                )
        })
        .map(|record| record.target.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        wordpress_metadata_gets,
        [
            "/wp-json/",
            "/wp-content/themes/session-fixture-theme/style.css"
        ],
        "without the integration flag, protected session HTML must not change the entry-only WordPress schedule"
    );

    assert_offline_verify_and_self_compare(&server, &report_directory, &assessment);
}

#[test]
fn incomplete_wordpress_session_composition_fails_before_input_or_output_acquisition() {
    let server = serve(SessionBehavior::Healthy);
    let temporary = tempfile::tempdir().expect("create private test directory");
    let missing_policy = temporary.path().join(MISSING_POLICY_PATH_CANARY);
    let missing_secret = temporary.path().join(MISSING_SECRET_PATH_CANARY);

    let cases = [
        (
            "missing discovery",
            vec![
                "scan",
                "--profile",
                "web-review",
                "--wordpress-review",
                "--wordpress-supplied-session",
                "--session-policy",
            ],
            Some(missing_secret.as_path()),
            "--wordpress-discovery",
        ),
        (
            "missing credential",
            vec![
                "scan",
                "--profile",
                "web-review",
                "--wordpress-review",
                "--wordpress-discovery",
                "--wordpress-supplied-session",
                "--session-policy",
            ],
            None,
            "Error: MissingCredentialSource",
        ),
    ];

    for (case, leading_arguments, optional_secret, expected_error) in cases {
        let report_directory = temporary.path().join(format!("{case}-must-not-exist"));
        let mut command = termivar();
        command.args(leading_arguments).arg(&missing_policy);
        if let Some(secret) = optional_secret {
            command.arg("--session-cookie-file").arg(secret);
        }
        let output = command
            .arg("--report-dir")
            .arg(&report_directory)
            .arg(&server.origin)
            .output()
            .expect("execute invalid WordPress supplied-session composition");
        assert!(
            !output.status.success(),
            "{case} unexpectedly passed preflight"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected_error),
            "{case} reported the wrong preflight error: {stderr}"
        );
        assert_no_secret(&output.stdout);
        assert_no_secret(&output.stderr);
        assert!(
            !report_directory.exists(),
            "{case} reserved or published output before preflight rejection"
        );
        assert!(!missing_policy.exists());
        assert!(!missing_secret.exists());
        assert!(
            server
                .requests
                .lock()
                .expect("request ledger lock")
                .is_empty(),
            "{case} reached the network before preflight rejection"
        );
    }
}

#[test]
fn health_qualified_protected_page_nominates_anonymous_wordpress_metadata() {
    let server = serve(SessionBehavior::Healthy);
    let temporary = tempfile::tempdir().expect("create private test directory");
    let (policy_path, cookie_path) = write_inputs(temporary.path(), &server.origin);
    let report_directory = temporary.path().join("healthy-bundle");
    let output = scan(&server, &policy_path, &cookie_path, &report_directory);
    assert_scan_success(&server, &output, "healthy WordPress supplied-session scan");
    assert_no_secret(&output.stdout);
    assert_no_secret(&output.stderr);

    let (assessment_bytes, assessment) = read_assessment(&report_directory);
    assert_no_secret(&assessment_bytes);
    assert_bundle_has_no_secret(&report_directory);

    let session = &assessment["supplied_session"];
    assert_eq!(session["schema"], "security.supplied-session-audit/v2");
    assert_eq!(session["outcome"], "complete");
    assert_eq!(session["coverage"], "complete");
    assert_eq!(session["selected_resource_count"], 1);
    assert_eq!(session["dispatched_resource_count"], 1);
    assert_eq!(session["committed_resource_count"], 1);
    assert_eq!(session["dispatched_request_count"], 3);
    assert_eq!(session["checkpoints"].as_array().unwrap().len(), 2);
    assert_eq!(session["resources"].as_array().unwrap().len(), 1);
    assert_eq!(session["resources"][0]["outcome"], "committed");

    let discovery = &assessment["wordpress_discovery"];
    assert_eq!(discovery["schema"], "security.wordpress-discovery-audit/v4");
    assert_eq!(
        discovery["policy_id"],
        "termivar.wordpress-supplied-session-metadata-discovery/v1"
    );
    assert_eq!(discovery["credential_mode"], "anonymous");
    assert_eq!(discovery["attempted_request_count"], 3);
    assert_eq!(discovery["completed_response_count"], 3);
    assert_eq!(discovery["committed_response_count"], 3);
    assert_eq!(discovery["source_count"], 3);
    let protected_target = format!("{}member-page", server.origin);
    let context_page_reference =
        assert_supplied_session_page_scope(discovery, session, &protected_target, true);

    let plugin = source(discovery, "plugin_readme", Some("session-page-component"));
    assert_eq!(plugin["outcome"], "observed");
    assert_eq!(plugin["association"], "observed_conventional");
    assert_eq!(plugin["plugin"]["stable_tag"], "9.9.9");
    assert!(plugin["source_supplied_session_page_references"].is_array());
    assert_eq!(
        plugin["source_supplied_session_page_references"],
        serde_json::json!([context_page_reference])
    );
    assert!(
        source(discovery, "rest_index", None)["source_supplied_session_page_references"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        source(discovery, "theme_stylesheet", Some("session-fixture-theme"))
            ["source_supplied_session_page_references"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let component = assessment["wordpress_review"]["components"]
        .as_array()
        .expect("WordPress components must be an array")
        .iter()
        .find(|component| component["identity"]["slug"] == "session-page-component")
        .expect("health-qualified page must nominate its plugin");
    assert_eq!(component["versions"], serde_json::json!([]));
    assert!(assessment.get("wordpress_asset_fingerprints").is_none());

    let records = server.requests.lock().expect("request ledger lock").clone();
    assert_transport_partition(&records);
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record.method == "GET"
                    && record.target == "/wp-content/plugins/session-page-component/readme.txt"
            })
            .count(),
        1,
        "the protected page's two assets must deduplicate to one readme request"
    );
    assert!(!records.iter().any(|record| {
        record.method == "GET"
            && record
                .target
                .starts_with("/wp-content/plugins/session-page-component/assets/")
    }));

    assert_offline_verify_and_self_compare(&server, &report_directory, &assessment);
}

#[test]
fn session_loss_after_protected_response_prevents_wordpress_nomination() {
    let server = serve(SessionBehavior::LostAfterResource);
    let temporary = tempfile::tempdir().expect("create private test directory");
    let (policy_path, cookie_path) = write_inputs(temporary.path(), &server.origin);
    let report_directory = temporary.path().join("lost-bundle");
    let output = scan(&server, &policy_path, &cookie_path, &report_directory);
    assert_scan_success(&server, &output, "lost-session WordPress scan");
    assert_no_secret(&output.stdout);
    assert_no_secret(&output.stderr);

    let (assessment_bytes, assessment) = read_assessment(&report_directory);
    assert_no_secret(&assessment_bytes);
    assert_bundle_has_no_secret(&report_directory);

    let session = &assessment["supplied_session"];
    assert_eq!(session["outcome"], "session_lost");
    assert_eq!(session["coverage"], "none");
    assert_eq!(session["selected_resource_count"], 1);
    assert_eq!(session["dispatched_resource_count"], 1);
    assert_eq!(session["committed_resource_count"], 0);
    assert_eq!(session["dispatched_request_count"], 3);
    assert_eq!(session["resources"][0]["outcome"], "health_unqualified");
    assert_eq!(session["resources"][0]["status"], 200);

    let discovery = &assessment["wordpress_discovery"];
    assert_eq!(discovery["schema"], "security.wordpress-discovery-audit/v4");
    assert_eq!(
        discovery["policy_id"],
        "termivar.wordpress-supplied-session-metadata-discovery/v1"
    );
    assert_eq!(discovery["credential_mode"], "anonymous");
    assert_eq!(discovery["attempted_request_count"], 2);
    assert_eq!(discovery["completed_response_count"], 2);
    assert_eq!(discovery["committed_response_count"], 2);
    assert_eq!(discovery["source_count"], 2);
    let protected_target = format!("{}member-page", server.origin);
    assert_supplied_session_page_scope(discovery, session, &protected_target, false);
    assert!(discovery["sources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|source| {
            source["source_supplied_session_page_references"]
                .as_array()
                .is_some_and(Vec::is_empty)
        }));
    assert!(discovery["sources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|source| source
            .get("component")
            .and_then(|component| component.get("slug"))
            .and_then(Value::as_str)
            != Some("session-page-component")));
    assert!(assessment["wordpress_review"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .all(|component| component["identity"]["slug"] != "session-page-component"));
    assert!(assessment.get("wordpress_asset_fingerprints").is_none());

    let records = server.requests.lock().expect("request ledger lock").clone();
    assert_transport_partition(&records);
    assert!(!records.iter().any(|record| {
        record.target == "/wp-content/plugins/session-page-component/readme.txt"
    }));
    assert!(!records.iter().any(|record| {
        record
            .target
            .starts_with("/wp-content/plugins/session-page-component/assets/")
    }));

    assert_offline_verify_and_self_compare(&server, &report_directory, &assessment);
}
