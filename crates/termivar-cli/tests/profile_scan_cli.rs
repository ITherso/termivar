//! Process-level contracts for explicitly selected deterministic scan profiles.
//!
//! Every network interaction stays on an in-process loopback fixture. These
//! tests keep the no-profile compatibility schema separate from the additive
//! profile schema and verify fail-closed, redacted exact-origin behavior.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn termivar() -> Command {
    Command::new(env!("CARGO_BIN_EXE_termivar"))
}

struct TestServer {
    url: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

fn serve<F>(handler: F) -> TestServer
where
    F: Fn(&str) -> Vec<u8> + Send + Sync + 'static,
{
    serve_request(move |target, _| handler(target))
}

fn serve_request<F>(handler: F) -> TestServer
where
    F: Fn(&str, &str) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_connections = Arc::clone(&connections);
    let thread_requests = Arc::clone(&requests);
    let handler = Arc::new(handler);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            thread_connections.fetch_add(1, Ordering::SeqCst);
            handle_connection(&mut stream, handler.as_ref(), thread_requests.as_ref());
        }
    });

    TestServer {
        url: format!("http://{address}/"),
        connections,
        requests,
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    handler: &(dyn Fn(&str, &str) -> Vec<u8> + Send + Sync),
    requests: &Mutex<Vec<String>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0_u8; 16 * 1024];
    let bytes_read = stream.read(&mut buffer).unwrap_or(0);
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    requests.lock().unwrap().push(target.clone());
    let response = handler(&target, &request);
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

fn ok_html(body: &str, extra_headers: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn ok_json(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn parse_stdout(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must be one complete JSON document ({error}):\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn unique_report_path(extension: &str) -> PathBuf {
    static NEXT_REPORT: AtomicUsize = AtomicUsize::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "termivar-assessment-report-{}-{nonce}-{}.{}",
        std::process::id(),
        NEXT_REPORT.fetch_add(1, Ordering::Relaxed),
        extension
    ))
}

#[test]
fn no_profile_preserves_decision_scan_v1() {
    let server = serve(|_| ok_html("hello", ""));
    let output = termivar()
        .args(["scan", "--format", "json", &server.url])
        .output()
        .expect("failed to run termivar");

    assert!(
        output.status.success(),
        "unexpected exit status: {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_stdout(&output);
    assert_eq!(value["schema_version"], "decision-scan/v1");
    assert!(value.get("profile_contract").is_none());
    assert!(value.get("assessment").is_none());
}

#[test]
fn explicit_profiles_emit_the_additive_schema_and_exact_scope() {
    let server = serve(|_| ok_html("hello", ""));
    let baseline = termivar()
        .args([
            "scan",
            "--profile",
            "baseline",
            "--format",
            "json",
            &server.url,
        ])
        .output()
        .expect("failed to run termivar");
    assert!(baseline.status.success());
    let value = parse_stdout(&baseline);
    assert_eq!(value["schema_version"], "web-assessment/v1");
    assert_eq!(value["disposition"], "complete");
    assert_eq!(value["profile_contract"]["schema"], "venom.scan-profile/v1");
    assert_eq!(value["profile_contract"]["profile"], "baseline");
    assert_eq!(value["profile_contract"]["scope"], "single-resource");
    assert_eq!(value["assessment"]["scope"], "single-resource");
    assert!(value["assessment"]["report"]
        .get("assessment_items")
        .is_none());

    let web_review = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            &server.url,
        ])
        .output()
        .expect("failed to run termivar");
    assert!(
        web_review.status.success(),
        "web-review failed with {:?}:\n{}",
        web_review.status,
        String::from_utf8_lossy(&web_review.stderr)
    );
    let value = parse_stdout(&web_review);
    assert_eq!(value["schema"], "venom-rendered-assessment/v1");
    assert_eq!(value["source_schema"], "venom-assessment-run/v1");
    assert_eq!(value["profile_schema"], "venom.scan-profile/v1");
    assert_eq!(value["profile"], "web-review");
    assert_eq!(value["status"], "complete");
    assert!(value["item_count"].as_u64().unwrap() > 0);
    assert!(value["items"].as_array().unwrap().iter().all(|item| {
        item["disposition"] == "informational"
            && item["claim_basis"] == "observation"
            && item["subject_reference"] == "subject-0000"
    }));
}

#[cfg(feature = "openapi-review")]
#[test]
fn openapi_review_executes_through_boxed_scan_and_renders_the_composed_audit() {
    const DOCUMENT: &str = r#"{"openapi":"3.1.0","info":{"title":"fixture","version":"1"},"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#;
    let server = serve(|target| {
        if target == "/openapi.json" {
            ok_json(DOCUMENT)
        } else {
            ok_html("fixture root", "")
        }
    });
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--openapi-review",
            &server.url,
        ])
        .output()
        .expect("failed to run OpenAPI review");

    assert!(
        output.status.success(),
        "OpenAPI review failed with {:?}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_stdout(&output);
    assert_eq!(value["openapi_review"]["outcome"], "document_observed");
    assert_eq!(value["openapi_review"]["request_count"], 2);
    assert_eq!(value["openapi_review"]["active_verification_count"], 1);
    assert_eq!(value["openapi_review"]["replay_matched"], true);
    assert_eq!(value["openapi_review"]["item_projected"], true);
    let openapi_items = value["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["capability_id"] == "api.openapi-contract-observed@1")
        .collect::<Vec<_>>();
    assert_eq!(openapi_items.len(), 1);
    assert_eq!(openapi_items[0]["disposition"], "informational");
    assert_eq!(openapi_items[0]["claim_basis"], "observation");

    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|target| target.as_str() == "/openapi.json")
            .count(),
        2
    );
}

#[cfg(feature = "openapi-review")]
#[test]
fn incomplete_openapi_review_exposes_actionable_redacted_diagnostics() {
    const PRIVATE_BODY: &str = "OPENAPI-ERROR-BODY-MUST-NOT-LEAK-2D79F4";
    let server = serve(|target| {
        if target == "/openapi.json" {
            let body = format!(r#"{{"error":"{PRIVATE_BODY}"}}"#);
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        } else {
            ok_html("fixture root", "")
        }
    });

    let mut arguments = vec![
        "scan",
        "--profile",
        "web-review",
        "--format",
        "json",
        "--openapi-review",
    ];
    #[cfg(feature = "rest-review")]
    arguments.push("--rest-review");
    arguments.push(&server.url);
    let json = termivar()
        .args(arguments)
        .output()
        .expect("failed to run incomplete OpenAPI/REST review");
    assert!(!json.status.success(), "terminal review must fail closed");
    let value = parse_stdout(&json);
    assert_eq!(value["schema_version"], "web-assessment/v2");
    assert_eq!(value["disposition"], "incomplete");
    assert!(value["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "human_review_required"));

    let report = &value["assessment"]["report"];
    assert_eq!(
        report["subjects"][0]["decision"]["terminal"]["command"],
        "await_human_review"
    );
    let openapi = &report["openapi_review_audit"];
    assert_eq!(openapi["schema"], "security.openapi-review-audit/v1");
    assert_eq!(openapi["capability_id"], "api.openapi-contract-observed@1");
    assert_eq!(openapi["candidate_source"], "conventional_openapi_json");
    assert_eq!(openapi["outcome"], "http_error");
    assert_eq!(openapi["request_count"], 1);
    assert_eq!(openapi["active_verification_count"], 0);
    assert_eq!(openapi["replay_matched"], false);
    assert_eq!(openapi["item_projected"], false);

    #[cfg(feature = "rest-review")]
    {
        let rest = &report["rest_review_audit"];
        assert_eq!(rest["schema"], "security.rest-readonly-review-audit/v1");
        assert_eq!(
            rest["capability_id"],
            "api.rest-readonly-surface-observed@1"
        );
        assert_eq!(rest["outcome"], "not_eligible");
        assert_eq!(rest["eligible_operation_count"], 0);
        assert_eq!(rest["request_count"], 0);
        assert_eq!(rest["active_verification_count"], 0);
        assert_eq!(rest["replay_stable"], false);
        assert_eq!(rest["item_projected"], false);
        assert!(rest.get("selected_operation_identity").is_none());
    }

    let json_stdout = String::from_utf8(json.stdout).unwrap();
    let json_stderr = String::from_utf8(json.stderr).unwrap();
    assert!(!json_stdout.contains(PRIVATE_BODY));
    assert!(!json_stderr.contains(PRIVATE_BODY));
    assert!(!json_stdout.contains("/openapi.json"));

    let mut text_arguments = vec![
        "scan",
        "--profile",
        "web-review",
        "--format",
        "text",
        "--openapi-review",
    ];
    #[cfg(feature = "rest-review")]
    text_arguments.push("--rest-review");
    text_arguments.push(&server.url);
    let text = termivar()
        .args(text_arguments)
        .output()
        .expect("failed to render incomplete OpenAPI/REST text review");
    assert!(!text.status.success(), "terminal review must fail closed");
    let text_stdout = String::from_utf8(text.stdout).unwrap();
    let text_stderr = String::from_utf8(text.stderr).unwrap();
    assert!(text_stdout.contains("incomplete reasons: human_review_required"));
    assert!(text_stdout.contains(
        "OpenAPI review audit: source=conventional_openapi_json requests=1 active_verifications=0 outcome=http_error replay_matched=false item_projected=false"
    ));
    #[cfg(feature = "rest-review")]
    assert!(text_stdout.contains(
        "REST review audit: eligible_operations=0 requests=0 active_verifications=0 outcome=not_eligible replay_stable=false item_projected=false"
    ));
    assert!(!text_stdout.contains(PRIVATE_BODY));
    assert!(!text_stderr.contains(PRIVATE_BODY));
    assert!(!text_stdout.contains("/openapi.json"));

    let requests = server.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|target| target.as_str() == "/openapi.json")
            .count(),
        2
    );
    assert!(!requests.iter().any(|target| target == "/status"));
}

#[test]
fn completed_web_review_uses_the_central_renderer_for_every_format() {
    let server = serve_request(|target, request| {
        let origin = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("origin")
                .then(|| value.trim().to_owned())
        });
        if let Some(origin) = origin {
            return ok_html(
                "cors candidate",
                &format!(
                    "Access-Control-Allow-Origin: {origin}\r\nAccess-Control-Allow-Credentials: true\r\nVary: Origin\r\n"
                ),
            );
        }
        if target.contains('?') {
            let parsed = url::Url::parse(&format!("http://fixture{target}")).unwrap();
            let candidate = parsed
                .query_pairs()
                .find_map(|(name, value)| (name == "next").then(|| value.into_owned()))
                .unwrap();
            let body = format!("<script>const destination = '{candidate}'</script>");
            return format!(
                "HTTP/1.1 302 Found\r\nContent-Type: text/html; charset=utf-8\r\nLocation: {candidate}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes();
        }
        ok_html("hello", "")
    });
    let target = format!("{}?next=host-value", server.url);
    for (format, required) in [
        ("json", "\"schema\":\"venom-rendered-assessment/v1\""),
        ("csv", "\"record_type\",\"document_schema\""),
        ("html", "<title>Termivar assessment report</title>"),
        ("markdown", "# Termivar assessment report"),
    ] {
        let output = termivar()
            .args([
                "scan",
                "--profile",
                "web-review",
                "--report-format",
                format,
                &target,
            ])
            .output()
            .expect("failed to run termivar");
        assert!(
            output.status.success(),
            "{format} report failed with {:?}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("reports are UTF-8");
        assert!(
            stdout.contains(required),
            "unexpected {format} report: {stdout}"
        );
        assert!(stdout.contains("informational"));
        assert!(stdout.contains("observation"));
        assert!(stdout.contains("needs_review"));
        assert!(stdout.contains("differential"));
        assert!(!stdout.contains(&server.url));
        assert!(!stdout.contains("decision-scan/v1"));
    }
}

#[test]
fn report_output_is_complete_atomic_and_never_overwritten() {
    let server = serve(|_| ok_html("hello", ""));
    let path = unique_report_path("json");
    let path_text = path.to_string_lossy().into_owned();
    let arguments = [
        "scan",
        "--profile",
        "web-review",
        "--report-format",
        "json",
        "--report-output",
        path_text.as_str(),
        server.url.as_str(),
    ];
    let first = termivar()
        .args(arguments)
        .output()
        .expect("failed to run termivar");
    assert!(
        first.status.success(),
        "atomic output failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        first.stdout.is_empty(),
        "file mode must not duplicate stdout"
    );
    let original = std::fs::read(&path).expect("completed report file must exist");
    let value: serde_json::Value =
        serde_json::from_slice(&original).expect("report file must be complete JSON");
    assert_eq!(value["schema"], "venom-rendered-assessment/v1");

    let second = termivar()
        .args(arguments)
        .output()
        .expect("failed to rerun termivar");
    assert!(!second.status.success(), "existing output must be rejected");
    assert!(second.stdout.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    std::fs::remove_file(path).expect("test report cleanup");
}

#[test]
fn incomplete_web_review_emits_diagnostic_and_never_creates_report_output() {
    let server = serve(|_| ok_html("hello", ""));
    let path = unique_report_path("json");
    let path_text = path.to_string_lossy().into_owned();
    let query = (0..65)
        .map(|index| format!("parameter_{index:02}=redacted"))
        .collect::<Vec<_>>()
        .join("&");
    let target = format!("{}?{query}", server.url);
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--report-format",
            "json",
            "--report-output",
            path_text.as_str(),
            target.as_str(),
        ])
        .output()
        .expect("failed to run termivar");

    assert!(!output.status.success(), "incomplete run must exit nonzero");
    assert!(!path.exists(), "incomplete run published a report artifact");
    let value = parse_stdout(&output);
    assert_eq!(value["schema_version"], "web-assessment/v2");
    assert_eq!(value["disposition"], "incomplete");
    assert_eq!(
        value["assessment"]["report"]["assessment_items"]["projection_status"],
        "unavailable"
    );
    #[cfg(feature = "openapi-review")]
    assert!(value["assessment"]["report"]
        .get("openapi_review_audit")
        .is_none());
    #[cfg(feature = "rest-review")]
    assert!(value["assessment"]["report"]
        .get("rest_review_audit")
        .is_none());
}

#[test]
fn profile_conflicts_fail_before_connection_or_output() {
    let server = serve(|_| ok_html("must not be requested", ""));
    for arguments in [
        vec![
            "scan",
            "--profile",
            "baseline",
            "--enforce-defense",
            &server.url,
        ],
        vec!["scan", "--profile", "web-review", "--explain", &server.url],
        vec![
            "scan",
            "--profile",
            "baseline",
            "--report-format",
            "json",
            &server.url,
        ],
        vec!["scan", "--report-format", "json", &server.url],
    ] {
        let output = termivar()
            .args(arguments)
            .output()
            .expect("failed to run termivar");
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "a rejected profile invocation emitted output:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--profile"),
            "conflict must identify the profile boundary:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        0,
        "profile conflicts must be rejected before network dispatch"
    );
}

#[test]
fn authorization_context_sources_are_root_only_atomic_and_fully_redacted() {
    const SECRET: &str = "Bearer CLI_PRIVATE_AUTHORIZATION_SENTINEL";
    const ENV_NAME: &str = "TERMIVAR_TEST_AUTHORIZATION_CONTEXT";
    const PRIVATE_JSON_SENTINEL: &str = "CLI_PRIVATE_RESPONSE_FIELD_SENTINEL";

    let authorized_hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&authorized_hits);
    let server = serve_request(move |_, request| {
        let json_request = request.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("accept")
                    && value.trim().eq_ignore_ascii_case("application/json")
            })
        });
        if json_request {
            let authorized = request.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("authorization") && value.trim() == SECRET
                })
            });
            if authorized {
                counted.fetch_add(1, Ordering::SeqCst);
                ok_json(&format!(
                    r#"{{"id":1,"{PRIVATE_JSON_SENTINEL}":"visible"}}"#
                ))
            } else {
                ok_json(r#"{"id":1}"#)
            }
        } else {
            ok_html("root", "")
        }
    });

    let assert_output = |output: Output, source_identifiers: &[&str]| {
        assert!(
            output.status.success(),
            "authorization-context scan failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stdout.contains(SECRET));
        assert!(!stderr.contains(SECRET));
        assert!(!stdout.contains(PRIVATE_JSON_SENTINEL));
        assert!(!stderr.contains(PRIVATE_JSON_SENTINEL));
        for identifier in source_identifiers {
            assert!(!stdout.contains(identifier));
            assert!(!stderr.contains(identifier));
        }
        assert!(stdout.contains("api.review.authorization-context.visibility-difference@1"));
        let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let item = value["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["capability_id"] == "api.review.authorization-context.visibility-difference@1"
            })
            .unwrap();
        assert_eq!(item["disposition"], "needs_review");
        assert_eq!(item["claim_basis"], "differential");
        assert_eq!(item["evidence_references"].as_array().unwrap().len(), 1);
        assert!(item["control_evidence_references"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(item["candidate_evidence_references"]
            .as_array()
            .unwrap()
            .is_empty());
    };

    let environment = termivar()
        .env(ENV_NAME, SECRET)
        .args([
            "scan",
            "--profile",
            "web-review",
            "--report-format",
            "json",
            "--auth-env",
            ENV_NAME,
            &server.url,
        ])
        .output()
        .expect("failed to run environment authorization source");
    assert_output(environment, &[ENV_NAME]);

    let auth_path = unique_report_path("auth-input");
    std::fs::write(&auth_path, format!("{SECRET}\r\n")).unwrap();
    let auth_path_text = auth_path.to_string_lossy().into_owned();
    let file = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--report-format",
            "json",
            "--auth-file",
            auth_path_text.as_str(),
            &server.url,
        ])
        .output()
        .expect("failed to run file authorization source");
    assert_output(file, &[auth_path_text.as_str()]);
    std::fs::remove_file(&auth_path).unwrap();

    let mut child = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--report-format",
            "json",
            "--auth-stdin",
            &server.url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run stdin authorization source");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{SECRET}\n").as_bytes())
        .unwrap();
    assert_output(child.wait_with_output().unwrap(), &[]);
    assert_eq!(authorized_hits.load(Ordering::SeqCst), 3);

    let before = server.connections.load(Ordering::SeqCst);
    let missing_path = unique_report_path("missing-auth-input");
    let missing_path_text = missing_path.to_string_lossy().into_owned();
    let non_root = format!("{}private", server.url);
    let rejected = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--auth-file",
            missing_path_text.as_str(),
            &non_root,
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("exact origin root"));
    assert!(!stderr.contains(missing_path_text.as_str()));
    assert_eq!(server.connections.load(Ordering::SeqCst), before);

    let raw_secret = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--authorization",
            &server.url,
        ])
        .output()
        .unwrap();
    assert!(!raw_secret.status.success());
    assert!(raw_secret.stdout.is_empty());
    assert_eq!(server.connections.load(Ordering::SeqCst), before);
}

#[test]
fn insecure_domain_http_is_rejected_before_the_authorization_source_is_read() {
    let missing_path = unique_report_path("insecure-http-missing-auth");
    let missing_path_text = missing_path.to_string_lossy().into_owned();
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--auth-file",
            missing_path_text.as_str(),
            "http://localhost/",
        ])
        .output()
        .expect("failed to run insecure-transport preflight");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires HTTPS"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains(missing_path_text.as_str()));
    assert!(!stderr.contains("input source is unavailable"));
}

#[cfg(feature = "authorization-review")]
fn authorization_review_policy(resource: &str) -> String {
    format!(
        r#"schema = "security.authorization-review-policy/v1"
resource = "{resource}"
resource_handle = "private-account"
expectation = "primary-only"
method = "GET"

[comparison]
selected_paths = ["/data/account"]
ignored_paths = []
unordered_array_paths = []
max_diff_paths = 8
"#
    )
}

#[cfg(feature = "authorization-review")]
#[test]
fn resource_authorization_cli_rejects_incomplete_or_ambiguous_inputs_before_network() {
    let server = serve(|_| ok_json(r#"{"data":{"account":{"id":1}}}"#));
    let policy = unique_report_path("authz-policy.toml");
    let primary = unique_report_path("authz-primary.txt");
    let peer = unique_report_path("authz-peer.txt");
    std::fs::write(&policy, authorization_review_policy("/resource")).unwrap();
    std::fs::write(
        &primary,
        "Bearer PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19\n",
    )
    .unwrap();
    std::fs::write(&peer, "Bearer PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44\r\n").unwrap();
    let policy_text = policy.to_string_lossy().into_owned();
    let primary_text = primary.to_string_lossy().into_owned();
    let peer_text = peer.to_string_lossy().into_owned();

    let cases = [
        vec![
            "scan",
            "--profile",
            "baseline",
            "--authorization-review-policy",
            policy_text.as_str(),
            "--authz-primary-file",
            primary_text.as_str(),
            "--authz-peer-file",
            peer_text.as_str(),
            server.url.as_str(),
        ],
        vec![
            "scan",
            "--profile",
            "web-review",
            "--authorization-review-policy",
            policy_text.as_str(),
            "--authz-primary-file",
            primary_text.as_str(),
            server.url.as_str(),
        ],
        vec![
            "scan",
            "--profile",
            "web-review",
            "--auth-file",
            primary_text.as_str(),
            "--authorization-review-policy",
            policy_text.as_str(),
            "--authz-primary-file",
            primary_text.as_str(),
            "--authz-peer-file",
            peer_text.as_str(),
            server.url.as_str(),
        ],
        vec![
            "scan",
            "--profile",
            "web-review",
            "--authorization-review-policy",
            policy_text.as_str(),
            "--authz-primary-stdin",
            "--authz-peer-stdin",
            server.url.as_str(),
        ],
        vec![
            "scan",
            "--profile",
            "web-review",
            "--auth-stdin",
            "--authorization-review-policy",
            policy_text.as_str(),
            "--authz-primary-env",
            "PRIVATE_PRIMARY_ENV",
            "--authz-peer-file",
            peer_text.as_str(),
            server.url.as_str(),
        ],
    ];
    for arguments in cases {
        let output = termivar().args(arguments).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        for secret in [
            "PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19",
            "PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44",
        ] {
            assert!(!stderr.contains(secret));
        }
        for source_identifier in [
            policy_text.as_str(),
            primary_text.as_str(),
            peer_text.as_str(),
            "PRIVATE_PRIMARY_ENV",
        ] {
            assert!(!stderr.contains(source_identifier));
        }
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);

    std::fs::remove_file(policy).unwrap();
    std::fs::remove_file(primary).unwrap();
    std::fs::remove_file(peer).unwrap();
}

#[cfg(feature = "authorization-review")]
#[test]
fn resource_authorization_cli_rejects_equal_credentials_and_unsafe_transport() {
    const SECRET: &str = "Bearer PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19";
    let policy = unique_report_path("authz-policy.toml");
    let primary = unique_report_path("authz-primary.txt");
    let peer = unique_report_path("authz-peer.txt");
    std::fs::write(&policy, authorization_review_policy("/resource")).unwrap();
    std::fs::write(&primary, format!("{SECRET}\n")).unwrap();
    std::fs::write(&peer, format!("{SECRET}\r\n")).unwrap();
    let policy_text = policy.to_string_lossy().into_owned();
    let primary_text = primary.to_string_lossy().into_owned();
    let peer_text = peer.to_string_lossy().into_owned();

    let equal = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--authorization-review-policy",
            policy_text.as_str(),
            "--authz-primary-file",
            primary_text.as_str(),
            "--authz-peer-file",
            peer_text.as_str(),
            "https://example.test/",
        ])
        .output()
        .unwrap();
    assert!(!equal.status.success());
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&equal.stdout),
        String::from_utf8_lossy(&equal.stderr)
    );
    assert!(
        rendered.contains("PrincipalsNotDistinct")
            || rendered.contains("requires distinct principal credentials")
    );
    assert!(!rendered.contains(SECRET));
    assert!(!rendered.contains(policy_text.as_str()));
    assert!(!rendered.contains(primary_text.as_str()));
    assert!(!rendered.contains(peer_text.as_str()));

    let unsafe_transport = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--authorization-review-policy",
            "missing-private-policy",
            "--authz-primary-file",
            "missing-private-primary",
            "--authz-peer-file",
            "missing-private-peer",
            "http://localhost/",
        ])
        .output()
        .unwrap();
    assert!(!unsafe_transport.status.success());
    let stderr = String::from_utf8_lossy(&unsafe_transport.stderr);
    assert!(stderr.contains("requires HTTPS"));
    assert!(!stderr.contains("missing-private"));

    std::fs::remove_file(policy).unwrap();
    std::fs::remove_file(primary).unwrap();
    std::fs::remove_file(peer).unwrap();
}

#[cfg(feature = "authorization-review")]
#[test]
fn incomplete_resource_authorization_audit_is_rendered_and_fully_redacted() {
    const PRIMARY_SECRET: &str = "PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19";
    const PEER_SECRET: &str = "PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44";
    const QUERY_SECRET: &str = "RESOURCE-QUERY-MUST-NOT-LEAK-51A9BC";
    const HANDLE_SECRET: &str = "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A";
    const SELECTED_PATH: &str = "/data/account";

    let server = serve_request(|target, request| {
        if !target.starts_with("/resource") {
            return ok_html("fixture root", "");
        }
        let is_peer = request.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("authorization") && value.trim().ends_with(PEER_SECRET)
            })
        });
        if is_peer {
            let body = r#"{"error":"rate limited"}"#;
            return format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes();
        }
        ok_json(r#"{"data":{"account":{"id":"42"}}}"#)
    });
    let policy = unique_report_path("authz-incomplete-policy.toml");
    let primary = unique_report_path("authz-incomplete-primary.txt");
    let peer = unique_report_path("authz-incomplete-peer.txt");
    std::fs::write(
        &policy,
        format!(
            r#"schema = "security.authorization-review-policy/v1"
resource = "/resource?opaque={QUERY_SECRET}"
resource_handle = "{HANDLE_SECRET}"
expectation = "primary-only"
method = "GET"

[comparison]
selected_paths = ["{SELECTED_PATH}"]
ignored_paths = []
unordered_array_paths = []
max_diff_paths = 8
"#
        ),
    )
    .unwrap();
    std::fs::write(&primary, format!("Bearer {PRIMARY_SECRET}\n")).unwrap();
    std::fs::write(&peer, format!("Bearer {PEER_SECRET}\n")).unwrap();
    let policy_text = policy.to_string_lossy().into_owned();
    let primary_text = primary.to_string_lossy().into_owned();
    let peer_text = peer.to_string_lossy().into_owned();

    for format in ["json", "text"] {
        let output = termivar()
            .args([
                "scan",
                "--profile",
                "web-review",
                "--format",
                format,
                "--authorization-review-policy",
                policy_text.as_str(),
                "--authz-primary-file",
                primary_text.as_str(),
                "--authz-peer-file",
                peer_text.as_str(),
                server.url.as_str(),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("authorization_review_incomplete"));
        assert!(stdout.contains("rate_limited"));
        if format == "json" {
            let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            let audit = &value["assessment"]["report"]["authorization_review_audit"];
            assert_eq!(audit["request_count"], 2);
            assert_eq!(audit["outcome"], "rate_limited");
            assert_eq!(audit["item_projected"], false);
        } else {
            assert!(stdout.contains("requests=2 outcome=rate_limited"));
        }
        let combined = format!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
        for secret in [
            PRIMARY_SECRET,
            PEER_SECRET,
            QUERY_SECRET,
            HANDLE_SECRET,
            SELECTED_PATH,
            policy_text.as_str(),
            primary_text.as_str(),
            peer_text.as_str(),
        ] {
            assert!(!combined.contains(secret));
        }
    }
    assert_eq!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|target| target.starts_with("/resource"))
            .count(),
        4
    );

    std::fs::remove_file(policy).unwrap();
    std::fs::remove_file(primary).unwrap();
    std::fs::remove_file(peer).unwrap();
}

#[test]
fn non_regular_authorization_file_is_rejected_before_network_dispatch() {
    let server = serve(|_| ok_html("must not be requested", ""));
    let directory = unique_report_path("auth-directory");
    std::fs::create_dir(&directory).expect("create non-regular authorization source");
    let directory_text = directory.to_string_lossy().into_owned();
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--auth-file",
            directory_text.as_str(),
            &server.url,
        ])
        .output()
        .expect("failed to run non-regular authorization-source preflight");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SourceNotRegularFile"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains(directory_text.as_str()));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    std::fs::remove_dir(directory).expect("remove non-regular authorization source");
}

#[test]
fn report_destination_is_preflighted_before_secret_loading_or_network() {
    let server = serve(|_| ok_html("must not be requested", ""));
    let output_path = unique_report_path("existing-report");
    let original = b"EXISTING_REPORT_MUST_NOT_CHANGE";
    std::fs::write(&output_path, original).expect("create existing report destination");
    let output_path_text = output_path.to_string_lossy().into_owned();
    let missing_auth_path = unique_report_path("missing-report-preflight-auth");
    let missing_auth_path_text = missing_auth_path.to_string_lossy().into_owned();
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--report-format",
            "json",
            "--report-output",
            output_path_text.as_str(),
            "--auth-file",
            missing_auth_path_text.as_str(),
            &server.url,
        ])
        .output()
        .expect("failed to run report-output preflight");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("report output already exists"));
    assert!(!stderr.contains(missing_auth_path_text.as_str()));
    assert!(!stderr.contains("authorization-context input source"));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(&output_path).unwrap(), original);
    std::fs::remove_file(output_path).expect("remove existing report destination");
}

#[test]
fn post_load_runtime_failure_never_discloses_authorization_material() {
    const SECRET: &str = "Bearer POST_LOAD_RUNTIME_FAILURE_SECRET";
    const ENV_NAME: &str = "TERMIVAR_POST_LOAD_FAILURE_AUTH_SOURCE";
    const PRIVATE_TRANSPORT_DIAGNOSTIC: &str = "PRIVATE_TRANSPORT_DIAGNOSTIC";

    let authorized_hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&authorized_hits);
    let server = serve_request(move |_, request| {
        let authorized = request.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("authorization") && value.trim() == SECRET
            })
        });
        if authorized {
            counted.fetch_add(1, Ordering::SeqCst);
            // Closing without a response forces a transport failure only after
            // the out-of-band credential has been loaded and dispatched.
            Vec::new()
        } else if request.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("accept")
                    && value.trim().eq_ignore_ascii_case("application/json")
            })
        }) {
            ok_json(r#"{"id":1}"#)
        } else {
            ok_html(PRIVATE_TRANSPORT_DIAGNOSTIC, "")
        }
    });
    let auth_path = unique_report_path("post-load-runtime-auth");
    std::fs::write(&auth_path, SECRET).expect("write bounded authorization source");
    let auth_path_text = auth_path.to_string_lossy().into_owned();
    let file_output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--auth-file",
            auth_path_text.as_str(),
            &server.url,
        ])
        .output()
        .expect("failed to run post-load transport failure");

    let assert_redacted_failure = |output: &Output, source_identifier: &str| {
        assert!(!output.status.success());
        for rendered in [&output.stdout, &output.stderr] {
            let rendered = String::from_utf8_lossy(rendered);
            assert!(!rendered.contains(SECRET));
            assert!(!rendered.contains(source_identifier));
            assert!(!rendered.contains(PRIVATE_TRANSPORT_DIAGNOSTIC));
        }
    };
    assert_redacted_failure(&file_output, auth_path_text.as_str());

    let environment_output = termivar()
        .env(ENV_NAME, SECRET)
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--auth-env",
            ENV_NAME,
            &server.url,
        ])
        .output()
        .expect("failed to run post-load environment transport failure");
    assert_redacted_failure(&environment_output, ENV_NAME);
    assert_eq!(authorized_hits.load(Ordering::SeqCst), 2);
    std::fs::remove_file(auth_path).expect("remove authorization source");
}

#[test]
fn web_review_is_exact_origin_bounded_parseable_and_value_redacted() {
    const QUERY_VALUE: &str = "CLI_QUERY_VALUE_SECRET";
    const LINK_VALUE: &str = "CLI_LINK_VALUE_SECRET";
    const FORM_VALUE: &str = "CLI_FORM_VALUE_SECRET";
    const PATH_VALUE: &str = "CLI_PATH_VALUE_SECRET";
    const FORM_PATH_VALUE: &str = "CLI_FORM_PATH_VALUE_SECRET";
    const CREDENTIAL_VALUE: &str = "CLI_CREDENTIAL_VALUE_SECRET";
    const COOKIE_VALUE: &str = "CLI_COOKIE_VALUE_SECRET";
    const OUTSIDE_VALUE: &str = "CLI_OUTSIDE_VALUE_SECRET";

    let outside = serve(|_| ok_html("outside", ""));
    let outside_reference = format!("{}outside?leak={OUTSIDE_VALUE}", outside.url);
    let root_html = format!(
        concat!(
            "<html><body>",
            "<a href=\"/reset/{PATH_VALUE}?token={LINK_VALUE}\">child</a>",
            "<a href=\"{outside_reference}\">outside</a>",
            "<form method=\"get\" action=\"/submit/{FORM_PATH_VALUE}?next={FORM_VALUE}\">",
            "<input name=\"authorization\" value=\"{CREDENTIAL_VALUE}\">",
            "<input name=\"password\" value=\"{CREDENTIAL_VALUE}\">",
            "</form></body></html>"
        ),
        PATH_VALUE = PATH_VALUE,
        LINK_VALUE = LINK_VALUE,
        outside_reference = outside_reference,
        FORM_PATH_VALUE = FORM_PATH_VALUE,
        FORM_VALUE = FORM_VALUE,
        CREDENTIAL_VALUE = CREDENTIAL_VALUE,
    );
    let inside = serve(move |target| {
        if target.split('?').next() == Some("/") {
            ok_html(
                &root_html,
                "Set-Cookie: session=CLI_COOKIE_VALUE_SECRET; HttpOnly\r\n",
            )
        } else {
            ok_html("child", "")
        }
    });
    let query = (0..65)
        .map(|index| format!("parameter_{index:02}={QUERY_VALUE}"))
        .collect::<Vec<_>>()
        .join("&");
    let target = format!("{}?{query}", inside.url);

    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            &target,
        ])
        .output()
        .expect("failed to run termivar");

    assert!(
        !output.status.success(),
        "a bounded incomplete assessment must exit nonzero"
    );
    let value = parse_stdout(&output);
    assert_eq!(value["schema_version"], "web-assessment/v2");
    assert_eq!(value["disposition"], "incomplete");
    assert_eq!(value["assessment"]["scope"], "exact-origin");
    assert!(value["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str() == Some("query_parameter_name_limit")));

    let subjects = value["assessment"]["report"]["subjects"]
        .as_array()
        .unwrap();
    assert!(subjects.len() >= 3, "same-origin routes were not retained");
    assert_eq!(subjects[0]["subject_reference"], "subject-0000");
    assert!(subjects.iter().enumerate().all(|(index, subject)| {
        subject["subject_reference"] == format!("subject-{index:04}")
            && subject.get("canonical_url").is_none()
    }));
    assert!(subjects.iter().any(|subject| {
        subject["query_parameter_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name.as_str() == Some("token")))
    }));
    assert!(subjects.iter().any(|subject| {
        subject["query_parameter_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name.as_str() == Some("next")))
    }));
    let forms = value["assessment"]["report"]["forms"].as_array().unwrap();
    assert!(forms.iter().any(|form| {
        form["form_reference"] == "form-0000"
            && form.get("document_url").is_none()
            && form.get("action_url").is_none()
            && form["control_names"].as_array().is_some_and(|names| {
                names
                    .iter()
                    .any(|name| name.as_str() == Some("authorization"))
            })
    }));
    assert_eq!(
        outside.connections.load(Ordering::SeqCst),
        0,
        "cross-origin discovery must never dispatch"
    );

    let item_projection = &value["assessment"]["report"]["assessment_items"];
    assert_eq!(item_projection["projection_status"], "unavailable");
    assert_eq!(
        item_projection["code"],
        "incomplete_assessment_items_withheld"
    );
    assert!(item_projection.get("items").is_none());
    assert!(item_projection.get("projected_item_count").is_none());
    assert!(!value["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str() == Some("assessment_subject_identity_unavailable")));

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("profiled assessment did not complete within its authority"),
        "nonzero status must follow the complete JSON document:\n{stderr}"
    );
    for secret in [
        QUERY_VALUE,
        LINK_VALUE,
        FORM_VALUE,
        PATH_VALUE,
        FORM_PATH_VALUE,
        CREDENTIAL_VALUE,
        COOKIE_VALUE,
        OUTSIDE_VALUE,
    ] {
        assert!(!stdout.contains(secret), "stdout leaked {secret}");
        assert!(!stderr.contains(secret), "stderr leaked {secret}");
    }
    assert!(!stdout.contains(&outside.url));

    let dispatched_targets = inside.requests.lock().unwrap();
    assert!(dispatched_targets
        .iter()
        .any(|request| request.contains(PATH_VALUE)));
    assert!(dispatched_targets
        .iter()
        .any(|request| request.contains(FORM_PATH_VALUE)));
    assert!(dispatched_targets.iter().all(|request| {
        !request.contains(QUERY_VALUE)
            && !request.contains(LINK_VALUE)
            && !request.contains(FORM_VALUE)
            && !request.contains(CREDENTIAL_VALUE)
            && !request.contains(COOKIE_VALUE)
    }));
}
