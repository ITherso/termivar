//! Actual-process acceptance for the opt-in Cert Spotter reconnaissance provider.
//!
//! The fixture keeps the selected target and provider on distinct owned numeric
//! loopback origins. It proves policy preflight precedes networking, the option
//! adds only the two bounded provider requests, returned names remain inert,
//! and the saved bundle remains useful after both listeners are gone.

#![cfg(feature = "recon-ct-provider")]

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
use sha2::{Digest, Sha256};

const TARGET_BODY: &str =
    "<!doctype html><html><body><main>owned Cert Spotter target fixture</main></body></html>";
const JSON_NAME: &str = "assessment.json";
const QUERY_DOMAIN: &str = "example.test";
const POLICY_REVISION: &str = "owned-policy-r1";
const QUERY_REFERENCE: &str = "owned-query-1";
const PRIVATE_MISMATCH_DOMAIN: &str = "private-mismatched-scope.invalid";
const PRIVATE_MISMATCH_REVISION: &str = "private-production-policy-r1";
const PRIVATE_MISMATCH_REFERENCE: &str = "private-production-query-1";
const FIRST_ISSUANCE_ID: &str = "opaque/\u{202e}name@example.com";
const ISSUANCE_REFERENCE_PREFIX: &str = "certspotter-issuance-sha256:";
const CLAIM_LIMITS: [&str; 5] = [
    "hypotheses_only",
    "scan_authority_not_granted",
    "ownership_not_established",
    "currentness_not_established",
    "source_authentication_not_established",
];
const RETAINED_NAMES: [&str; 3] = ["example.test", "www.example.test", "*.example.test"];

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

#[derive(Clone)]
struct FixtureResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl FixtureResponse {
    fn html(body: &str) -> Self {
        Self {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }

    fn json(body: Vec<u8>) -> Self {
        Self {
            status: "200 OK",
            content_type: "application/json",
            body,
        }
    }

    fn json_status(status: &'static str, body: &[u8]) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.to_vec(),
        }
    }
}

struct TestServer {
    url: String,
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    address: SocketAddr,
}

impl TestServer {
    fn request_trace(&self) -> Vec<String> {
        self.requests.lock().expect("request trace lock").clone()
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = TcpStream::connect(self.address);
            worker.join().expect("join numeric-loopback fixture");
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn serve(responses: Vec<FixtureResponse>) -> TestServer {
    assert!(!responses.is_empty(), "fixture requires one response");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind numeric-loopback fixture");
    let address = listener.local_addr().expect("read fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            if thread_stop.load(Ordering::Acquire) {
                break;
            }
            handle_connection(&mut stream, thread_requests.as_ref(), &responses);
        }
    });
    TestServer {
        url: format!("http://{address}/"),
        origin: format!("http://{address}"),
        requests,
        stop,
        worker: Some(worker),
        address,
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    requests: &Mutex<Vec<String>>,
    responses: &[FixtureResponse],
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 4096];
    while captured.len() < 16 * 1024 {
        let Ok(read) = stream.read(&mut buffer) else {
            break;
        };
        if read == 0 {
            break;
        }
        captured.extend_from_slice(&buffer[..read]);
        if captured.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&captured).into_owned();
    let response_index = {
        let mut trace = requests.lock().expect("request trace lock");
        let index = trace.len();
        trace.push(request);
        index
    };
    let response = responses
        .get(response_index)
        .unwrap_or_else(|| responses.last().expect("nonempty fixture responses"));
    let head = format!(
        concat!(
            "HTTP/1.1 {}\r\n",
            "Content-Type: {}\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n\r\n"
        ),
        response.status,
        response.content_type,
        response.body.len(),
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

fn write_policy(directory: &Path, provider_origin: &str, provider_use_authorized: bool) -> PathBuf {
    let document = json!({
        "schema": "security.recon-certspotter-policy/v1",
        "revision": POLICY_REVISION,
        "query_domain": QUERY_DOMAIN,
        "query_reference": QUERY_REFERENCE,
        "execution_mode": "owned_loopback_fixture",
        "provider_origin": provider_origin,
        "provider_use_authorized": provider_use_authorized,
        "privacy_disclosure_acknowledged": true,
    });
    let suffix = if provider_use_authorized {
        "valid"
    } else {
        "PRIVATE-invalid"
    };
    let path = directory.join(format!("cert-spotter-{suffix}.json"));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("serialize policy fixture"),
    )
    .expect("write explicit local policy");
    path
}

fn write_mismatched_production_policy(directory: &Path) -> PathBuf {
    let document = json!({
        "schema": "security.recon-certspotter-policy/v1",
        "revision": PRIVATE_MISMATCH_REVISION,
        "query_domain": PRIVATE_MISMATCH_DOMAIN,
        "query_reference": PRIVATE_MISMATCH_REFERENCE,
        "execution_mode": "production",
        "provider_use_authorized": true,
        "privacy_disclosure_acknowledged": true,
    });
    let path = directory.join("PRIVATE-mismatched-production-policy.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("serialize production policy fixture"),
    )
    .expect("write mismatched production policy");
    path
}

fn run_scan(target: &TestServer, destination: &Path, policy: Option<&Path>) -> Output {
    run_scan_url(&target.url, destination, policy)
}

fn run_scan_url(target: &str, destination: &Path, policy: Option<&Path>) -> Output {
    let mut command = termivar();
    command
        .args(["scan", target, "--profile", "web-review"])
        .arg("--report-dir")
        .arg(destination);
    if let Some(policy) = policy {
        command.arg("--recon-certspotter-policy").arg(policy);
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

fn read_bundle(directory: &Path) -> Value {
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
    serde_json::from_slice(
        &fs::read(directory.join(JSON_NAME)).expect("read bundled assessment JSON"),
    )
    .expect("parse bundled assessment JSON")
}

fn request_lines(trace: &[String]) -> Vec<&str> {
    trace
        .iter()
        .map(|request| request.lines().next().unwrap_or_default())
        .collect()
}

fn stable_item_projection(assessment: &Value) -> Vec<Value> {
    let mut items = assessment["items"]
        .as_array()
        .expect("assessment items")
        .clone();
    for item in &mut items {
        let fields = item.as_object_mut().expect("assessment item object");
        for field in [
            "evidence_references",
            "control_evidence_references",
            "candidate_evidence_references",
        ] {
            fields.remove(field);
        }
    }
    items.sort_by(|left, right| {
        left["fingerprint"]
            .as_str()
            .cmp(&right["fingerprint"].as_str())
    });
    items
}

fn assert_claim_limits(value: &Value) {
    assert_eq!(value, &json!(CLAIM_LIMITS));
}

fn issuance_reference(value: &str) -> String {
    format!(
        "{ISSUANCE_REFERENCE_PREFIX}{:x}",
        Sha256::digest(value.as_bytes())
    )
}

fn assert_audit(assessment: &Value, provider_origin: &str, first_page_bytes: usize) {
    let audit = &assessment["recon_certspotter"];
    assert_eq!(audit["schema"], "security.recon-certspotter-audit/v1");
    assert_eq!(audit["policy"], "termivar.recon-certspotter-provider/v1");
    assert_eq!(audit["selected"], true);

    let provider = &audit["provider"];
    assert_eq!(provider["name"], "cert_spotter");
    assert_eq!(
        provider["policy_schema"],
        "security.recon-certspotter-policy/v1"
    );
    assert_eq!(provider["policy_revision"], POLICY_REVISION);
    assert_eq!(provider["query_domain"], QUERY_DOMAIN);
    assert_eq!(provider["query_reference"], QUERY_REFERENCE);
    assert_eq!(provider["execution_mode"], "owned_loopback_fixture");
    assert_eq!(provider["origin"], provider_origin);

    let methodology = &audit["methodology"];
    assert_eq!(methodology["request_path"], "/v1/issuances");
    assert_eq!(methodology["pagination"], "after_cursor");
    assert_eq!(methodology["retries"], "none");
    assert_eq!(methodology["polling"], "none");
    assert_eq!(methodology["credentials"], "none");
    assert_eq!(methodology["maximum_pages"], 2);
    assert_eq!(methodology["maximum_response_page_bytes"], 256 * 1024);
    assert_eq!(methodology["maximum_response_bytes"], 512 * 1024);
    assert_eq!(methodology["maximum_elapsed_milliseconds"], 10_000);
    assert_eq!(methodology["maximum_in_flight_requests"], 1);
    assert_eq!(methodology["maximum_retained_names"], 256);

    let accepted_response_bytes = first_page_bytes + 2;
    let coverage = &audit["coverage"];
    assert_eq!(coverage["terminal"], "provider_exhausted");
    assert_eq!(coverage["completeness"], "provider_exhausted_as_observed");
    assert_eq!(coverage["first_failure"], Value::Null);
    assert_eq!(coverage["initial_after_reference"], Value::Null);
    assert_eq!(coverage["initial_after_byte_length"], Value::Null);
    assert_eq!(
        coverage["last_cursor_reference"],
        issuance_reference(FIRST_ISSUANCE_ID)
    );
    assert_eq!(coverage["last_cursor_byte_length"], FIRST_ISSUANCE_ID.len());
    assert!(coverage.get("initial_after").is_none());
    assert!(coverage.get("last_cursor").is_none());
    assert_eq!(coverage["request_attempt_count"], 2);
    assert_eq!(coverage["request_admitted_count"], 2);
    assert_eq!(coverage["response_completed_count"], 2);
    assert_eq!(coverage["observed_response_bytes"], accepted_response_bytes);
    assert_eq!(coverage["accepted_page_count"], 2);
    assert_eq!(coverage["accepted_response_bytes"], accepted_response_bytes);
    assert_eq!(coverage["issuance_count"], 1);
    assert_eq!(coverage["retained_name_count"], 3);
    assert_eq!(coverage["foreign_name_count"], 1);
    assert_eq!(coverage["duplicate_name_count"], 1);
    assert_eq!(coverage["omitted_name_count"], 2);

    let hypotheses = audit["hypotheses"].as_array().expect("provider hypotheses");
    assert_eq!(hypotheses.len(), RETAINED_NAMES.len());
    for (hypothesis, expected_name) in hypotheses.iter().zip(RETAINED_NAMES) {
        assert_eq!(hypothesis["name"], expected_name);
        assert_eq!(hypothesis["source"]["provider"], "cert_spotter");
        assert_eq!(hypothesis["source"]["origin"], provider_origin);
        assert_eq!(
            hypothesis["source"]["first_issuance_reference"],
            issuance_reference(FIRST_ISSUANCE_ID)
        );
        assert_eq!(
            hypothesis["source"]["first_issuance_byte_length"],
            FIRST_ISSUANCE_ID.len()
        );
        assert!(hypothesis["source"].get("first_issuance_id").is_none());
        assert_claim_limits(&hypothesis["claim_limits"]);
    }
    assert_claim_limits(&audit["claim_limits"]);

    let public_audit = serde_json::to_string(audit).expect("serialize public provider audit");
    assert!(!public_audit.contains(FIRST_ISSUANCE_ID));
    assert!(!public_audit.contains('\u{202e}'));
    assert!(!public_audit.contains("name@example.com"));
    assert!(!public_audit.contains("opaque/"));
}

fn run_offline_acceptance(directory: &Path, assessment: &Value) {
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"])
        .output()
        .expect("run Report Verify");
    assert_success(&verify, "Report Verify after listener shutdown");
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("parse Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let report = directory.join(JSON_NAME);
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run self-Compare");
    assert_success(&compare, "self-Compare after listener shutdown");
    let comparison: Value =
        serde_json::from_slice(&compare.stdout).expect("parse self-Compare JSON");
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(comparison[group], json!([]));
    }
    assert_eq!(
        comparison["unchanged"].as_array().map(Vec::len),
        assessment["items"].as_array().map(Vec::len)
    );
    let recon = &comparison["recon_certspotter_comparison"];
    assert_eq!(recon["schema"], "termivar-recon-certspotter-comparison/v1");
    assert_eq!(recon["status"], "compared");
    for facet in ["provider", "methodology", "coverage", "hypotheses"] {
        assert_eq!(recon[facet]["status"], "unchanged", "facet {facet}");
    }
}

#[test]
fn production_scope_mismatch_precedes_output_and_unavailable_secret_acquisition() {
    let parent = tempfile::tempdir().expect("create private preflight parent");
    let mut target = serve(vec![FixtureResponse::html("must not be requested")]);
    let policy = write_mismatched_production_policy(parent.path());
    let missing_secret = parent.path().join("PRIVATE-missing-authorization.secret");
    let missing_output_parent = parent.path().join("PRIVATE-missing-output-parent");
    let destination = missing_output_parent.join("assessment-bundle");

    let output = termivar()
        .args(["scan", &target.url, "--profile", "web-review"])
        .arg("--recon-certspotter-policy")
        .arg(&policy)
        .arg("--auth-file")
        .arg(&missing_secret)
        .arg("--report-dir")
        .arg(&destination)
        .output()
        .expect("run mismatched production-scope preflight");
    let target_trace = target.request_trace();
    target.shutdown();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("static preflight error is UTF-8");
    assert!(
        stderr.contains("ReconCtProviderComposition"),
        "CT composition error did not win preflight ordering: {stderr}"
    );
    assert!(!stderr.contains("authorization-context input source is unavailable"));
    assert!(!stderr.contains("report output parent is unavailable"));
    assert!(
        !destination.exists() && !missing_output_parent.exists(),
        "CT scope refusal must precede report output reservation"
    );
    assert!(
        target_trace.is_empty(),
        "CT scope refusal must precede target traffic and the later provider phase"
    );

    let policy_path = policy.to_string_lossy().into_owned();
    let secret_path = missing_secret.to_string_lossy().into_owned();
    let destination_path = destination.to_string_lossy().into_owned();
    for private in [
        policy_path.as_str(),
        secret_path.as_str(),
        destination_path.as_str(),
        PRIVATE_MISMATCH_DOMAIN,
        PRIVATE_MISMATCH_REVISION,
        PRIVATE_MISMATCH_REFERENCE,
        target.url.as_str(),
        "api.certspotter.com",
    ] {
        assert!(!stderr.contains(private), "preflight leaked private input");
    }
}

#[test]
fn actual_cli_queries_two_bounded_pages_without_expanding_target_authority() {
    let parent = tempfile::tempdir().expect("create private acceptance parent");
    let first_page = serde_json::to_vec(&json!([{
        "id": FIRST_ISSUANCE_ID,
        "dns_names": [
            "example.test",
            "WWW.Example.TEST",
            "*.example.test",
            "foreign.invalid",
            "münich.example.test",
            "192.0.2.1",
            "www.example.test"
        ],
        "future": {"nested": [true, null, 7]}
    }]))
    .expect("serialize provider page");
    let first_page_bytes = first_page.len();
    let mut target = serve(vec![FixtureResponse::html(TARGET_BODY)]);
    let mut provider = serve(vec![
        FixtureResponse::json(first_page),
        FixtureResponse::json(b"[]".to_vec()),
    ]);
    assert_ne!(target.origin, provider.origin);

    let invalid_policy = write_policy(parent.path(), &provider.origin, false);
    let invalid_directory = parent.path().join("invalid-policy-output");
    let invalid = run_scan(&target, &invalid_directory, Some(&invalid_policy));
    assert!(!invalid.status.success());
    assert!(!invalid_directory.exists());
    let invalid_error = String::from_utf8_lossy(&invalid.stderr);
    assert!(!invalid_error.contains(&invalid_policy.display().to_string()));
    assert!(!invalid_error.contains(QUERY_DOMAIN));
    assert!(target.request_trace().is_empty());
    assert!(provider.request_trace().is_empty());

    let baseline_directory = parent.path().join("option-off");
    let baseline = run_scan(&target, &baseline_directory, None);
    assert_success(&baseline, "option-off scan");
    let baseline_assessment = read_bundle(&baseline_directory);
    assert!(baseline_assessment.get("recon_certspotter").is_none());
    let baseline_target_trace = target.request_trace();
    assert!(!baseline_target_trace.is_empty());
    assert!(provider.request_trace().is_empty());

    let policy = write_policy(parent.path(), &provider.origin, true);
    let selected_directory = parent.path().join("option-on");
    let selected = run_scan(&target, &selected_directory, Some(&policy));
    assert_success(&selected, "option-on scan");
    let assessment = read_bundle(&selected_directory);

    let combined_target_trace = target.request_trace();
    assert_eq!(
        combined_target_trace.get(baseline_target_trace.len()..),
        Some(baseline_target_trace.as_slice()),
        "Cert Spotter hypotheses added or replaced a target request"
    );
    assert_eq!(
        assessment["subject_count"], baseline_assessment["subject_count"],
        "Cert Spotter hypotheses became assessment subjects"
    );
    assert_eq!(assessment["item_count"], baseline_assessment["item_count"]);
    assert_eq!(
        stable_item_projection(&assessment),
        stable_item_projection(&baseline_assessment),
        "Cert Spotter hypotheses changed assessment findings"
    );
    let items = serde_json::to_string(&assessment["items"]).expect("serialize item projection");
    for name in RETAINED_NAMES {
        assert!(
            !items.contains(name),
            "provider hypothesis leaked into an assessment item: {name}"
        );
    }
    for request in &combined_target_trace[baseline_target_trace.len()..] {
        for name in RETAINED_NAMES {
            assert!(
                !request.contains(name),
                "provider hypothesis expanded target request authority: {name}"
            );
        }
    }

    let provider_trace = provider.request_trace();
    let provider_request_lines = request_lines(&provider_trace);
    assert_eq!(provider_request_lines.len(), 2);
    assert_eq!(
        provider_request_lines[0],
        "GET /v1/issuances?domain=example.test&expand=dns_names HTTP/1.1"
    );
    let second_request_target = provider_request_lines[1]
        .split_ascii_whitespace()
        .nth(1)
        .expect("second provider request target");
    let second_request_url =
        url::Url::parse(&format!("http://fixture.invalid{second_request_target}"))
            .expect("parse encoded second provider request target");
    let second_query = second_request_url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    assert_eq!(
        second_query,
        [
            ("domain".to_owned(), QUERY_DOMAIN.to_owned()),
            ("expand".to_owned(), "dns_names".to_owned()),
            ("after".to_owned(), FIRST_ISSUANCE_ID.to_owned()),
        ]
    );
    for request in &provider_trace {
        let lowercase = request.to_ascii_lowercase();
        assert!(lowercase.contains("accept: application/json"));
        assert!(lowercase.contains("accept-encoding: identity"));
        assert!(!lowercase.contains("authorization:"));
        assert!(!lowercase.contains("cookie:"));
    }

    assert_audit(&assessment, &provider.origin, first_page_bytes);
    let expected_issuance_reference = issuance_reference(FIRST_ISSUANCE_ID);
    for filename in [JSON_NAME, "assessment.html"] {
        let rendered = fs::read_to_string(selected_directory.join(filename))
            .expect("read public report representation");
        assert!(rendered.contains(&expected_issuance_reference));
        assert!(!rendered.contains(FIRST_ISSUANCE_ID));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains("name@example.com"));
        assert!(!rendered.contains("opaque/"));
    }

    eprintln!(
        "recon-certspotter-acceptance option_off_target_requests={} option_on_target_requests={} provider_requests=2 pages=2 issuances=1 retained_names=3 foreign_names=1 duplicate_names=1 omitted_names=2",
        baseline_target_trace.len(),
        combined_target_trace.len() - baseline_target_trace.len(),
    );

    target.shutdown();
    provider.shutdown();
    let target_trace_before_offline = target.request_trace();
    let provider_trace_before_offline = provider.request_trace();
    run_offline_acceptance(&selected_directory, &assessment);
    assert_eq!(target.request_trace(), target_trace_before_offline);
    assert_eq!(provider.request_trace(), provider_trace_before_offline);

    let first_partial_page = serde_json::to_vec(&json!([{
        "id": "opaque-a",
        "dns_names": ["one.example.test"]
    }]))
    .expect("serialize first bounded-partial page");
    let second_partial_page = serde_json::to_vec(&json!([{
        "id": "opaque-b",
        "dns_names": ["two.example.test"]
    }]))
    .expect("serialize second bounded-partial page");
    let mut partial_target = serve(vec![FixtureResponse::html(TARGET_BODY)]);
    let mut partial_provider = serve(vec![
        FixtureResponse::json(first_partial_page),
        FixtureResponse::json(second_partial_page),
    ]);
    let partial_policy = write_policy(parent.path(), &partial_provider.origin, true);
    let partial_directory = parent.path().join("bounded-partial");
    let partial = run_scan(&partial_target, &partial_directory, Some(&partial_policy));
    assert_success(&partial, "bounded-partial provider scan");
    let partial_assessment = read_bundle(&partial_directory);
    let partial_audit = &partial_assessment["recon_certspotter"];
    assert_eq!(partial_audit["selected"], true);
    assert_eq!(partial_audit["coverage"]["terminal"], "page_limit_reached");
    assert_eq!(partial_audit["coverage"]["completeness"], "bounded_partial");
    assert_eq!(partial_audit["coverage"]["first_failure"], Value::Null);
    assert_eq!(partial_audit["coverage"]["accepted_page_count"], 2);
    assert_eq!(partial_audit["coverage"]["retained_name_count"], 2);
    assert_eq!(
        partial_audit["hypotheses"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        request_lines(&partial_provider.request_trace()),
        [
            "GET /v1/issuances?domain=example.test&expand=dns_names HTTP/1.1",
            "GET /v1/issuances?domain=example.test&expand=dns_names&after=opaque-a HTTP/1.1",
        ]
    );
    partial_target.shutdown();
    partial_provider.shutdown();
    run_offline_acceptance(&partial_directory, &partial_assessment);

    let mut throttled_target = serve(vec![FixtureResponse::html(TARGET_BODY)]);
    let mut throttled_provider = serve(vec![FixtureResponse::json_status(
        "429 Too Many Requests",
        b"[]",
    )]);
    let throttled_policy = write_policy(parent.path(), &throttled_provider.origin, true);
    let throttled_directory = parent.path().join("throttled-partial");
    let throttled = run_scan(
        &throttled_target,
        &throttled_directory,
        Some(&throttled_policy),
    );
    assert_success(&throttled, "throttled provider audit scan");
    let throttled_assessment = read_bundle(&throttled_directory);
    let throttled_audit = &throttled_assessment["recon_certspotter"];
    assert_eq!(throttled_audit["selected"], true);
    assert_eq!(throttled_audit["coverage"]["terminal"], "transport_failed");
    assert_eq!(throttled_audit["coverage"]["completeness"], "unknown");
    assert_eq!(throttled_audit["coverage"]["first_failure"], "throttled");
    assert_eq!(throttled_audit["coverage"]["request_attempt_count"], 1);
    assert_eq!(throttled_audit["coverage"]["request_admitted_count"], 1);
    assert_eq!(throttled_audit["coverage"]["response_completed_count"], 0);
    assert_eq!(throttled_audit["coverage"]["accepted_page_count"], 0);
    assert_eq!(throttled_audit["coverage"]["retained_name_count"], 0);
    assert_eq!(
        throttled_audit["hypotheses"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(throttled_provider.request_trace().len(), 1);
    throttled_target.shutdown();
    throttled_provider.shutdown();
    run_offline_acceptance(&throttled_directory, &throttled_assessment);

    let mut incomplete_target = serve(vec![FixtureResponse::html(TARGET_BODY)]);
    let mut undisclosed_provider = serve(vec![FixtureResponse::json(b"[]".to_vec())]);
    let incomplete_policy = write_policy(parent.path(), &undisclosed_provider.origin, true);
    let query = (0..65)
        .map(|index| format!("parameter_{index:02}=redacted"))
        .collect::<Vec<_>>()
        .join("&");
    let incomplete_url = format!("{}?{query}", incomplete_target.url);
    let incomplete_directory = parent.path().join("preexisting-incomplete");
    let incomplete = run_scan_url(
        &incomplete_url,
        &incomplete_directory,
        Some(&incomplete_policy),
    );
    assert!(
        !incomplete.status.success(),
        "pre-existing incomplete target unexpectedly completed"
    );
    assert!(
        !incomplete_directory.exists(),
        "pre-existing incomplete target published a reusable bundle"
    );
    assert!(
        undisclosed_provider.request_trace().is_empty(),
        "provider work ran even though the diagnostic contract cannot disclose its receipt"
    );
    incomplete_target.shutdown();
    undisclosed_provider.shutdown();

    eprintln!(
        "recon-certspotter-partial-acceptance page_limit_pages=2 page_limit_names=2 throttled_provider_requests=1 throttled_pages=0 throttled_names=0 preexisting_incomplete_provider_requests=0 verify_and_self_compare=passed"
    );
}
