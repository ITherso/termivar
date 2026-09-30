//! Real-process acceptance for the bounded template-evaluation review.
//!
//! The owned numeric-loopback fixture renders scanner-supplied values with the
//! exact, dev-only MiniJinja dependency. The positive case treats the value as
//! template source; the negative case binds the same value as data. Neither
//! case exposes an engine banner, a command primitive, file access, or an
//! outbound-interaction primitive to the product.

#![cfg(feature = "template-evaluation-review")]

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use minijinja::{context, Environment};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

const QUERY_NAME: &str = "termivar_fixture_input";
const ROOT_BODY: &str = "<!doctype html><html><body>owned-minijinja-fixture</body></html>";
const JSON_NAME: &str = "assessment.json";
const CAPABILITY_ID: &str = "web.review.template-evaluation.jinja-compatible-semantics@1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureMode {
    TemplateSource,
    ContextBound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestClass {
    Ordinary,
    OtherQuery,
    TemplateControl,
    TemplateCandidate,
}

#[derive(Clone, PartialEq, Eq)]
struct TemplatePairIdentity(Box<str>);

impl std::fmt::Debug for TemplatePairIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TemplatePairIdentity")
            .field("encoded_bytes", &self.0.len())
            .field("value", &"<scanner-owned-redacted>")
            .finish()
    }
}

impl TemplatePairIdentity {
    fn parse(value: &str) -> Option<Self> {
        if !(16..=32).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        Some(Self(value.into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestTrace {
    class: RequestClass,
    template_pair: Option<TemplatePairIdentity>,
}

impl RequestTrace {
    fn new(class: RequestClass, template_pair: Option<TemplatePairIdentity>) -> Self {
        Self {
            class,
            template_pair,
        }
    }
}

struct OwnedMiniJinjaServer {
    address: SocketAddr,
    url: String,
    requests: Arc<Mutex<Vec<RequestTrace>>>,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

struct StoppedFixture {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<RequestTrace>>>,
}

impl OwnedMiniJinjaServer {
    fn start(mode: FixtureMode) -> Self {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind owned numeric-loopback fixture");
        listener
            .set_nonblocking(true)
            .expect("configure bounded fixture listener");
        let address = listener.local_addr().expect("read fixture address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let worker_requests = Arc::clone(&requests);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        handle_connection(&mut stream, mode, worker_requests.as_ref());
                    },
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    },
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            url: format!("http://{address}/?{QUERY_NAME}=fixture-seed"),
            requests,
            shutdown,
            worker: Some(worker),
        }
    }

    fn stop(mut self) -> StoppedFixture {
        self.shutdown.store(true, Ordering::Release);
        self.worker
            .take()
            .expect("fixture worker")
            .join()
            .expect("fixture worker stopped cleanly");
        StoppedFixture {
            address: self.address,
            requests: self.requests,
        }
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    mode: FixtureMode,
    requests: &Mutex<Vec<RequestTrace>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request = Vec::with_capacity(4 * 1024);
    let mut chunk = [0_u8; 4 * 1024];
    while request.len() < 32 * 1024 {
        let Ok(count) = stream.read(&mut chunk) else {
            break;
        };
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&request);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let parsed = Url::parse(target).or_else(|_| {
        Url::parse("http://127.0.0.1/")
            .expect("fixed fixture origin")
            .join(target)
    });
    let query_value = parsed.ok().and_then(|url| {
        url.query_pairs()
            .find(|(name, _)| name == QUERY_NAME)
            .map(|(_, value)| value.into_owned())
    });
    let trace = classify_request(query_value.as_deref());
    requests.lock().expect("fixture request trace").push(trace);

    let body = match query_value {
        Some(value) => render_fixture_value(mode, &value),
        None => ROOT_BODY.to_owned(),
    };
    let response = format!(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n\r\n{}"
        ),
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn render_fixture_value(mode: FixtureMode, value: &str) -> String {
    let environment = Environment::new();
    let rendered = match mode {
        FixtureMode::TemplateSource => environment.render_str(value, ()),
        FixtureMode::ContextBound => {
            environment.render_str("{{ value }}", context!(value => value))
        },
    }
    .unwrap_or_else(|_| "template-rendering-unavailable".to_owned());
    format!("<!doctype html><html><body>{rendered}</body></html>")
}

fn classify_request(value: Option<&str>) -> RequestTrace {
    let Some(value) = value else {
        return RequestTrace::new(RequestClass::Ordinary, None);
    };

    if let Some(identity) = value
        .strip_prefix("termivar-template-")
        .and_then(|value| value.strip_suffix("-control-end"))
        .and_then(TemplatePairIdentity::parse)
    {
        return RequestTrace::new(RequestClass::TemplateControl, Some(identity));
    }

    let candidate = value
        .strip_prefix("termivar-template-")
        .and_then(|value| value.split_once("-{{'termivar_"))
        .and_then(|(outer, suffix)| {
            let inner = suffix.strip_suffix("'|upper}}-end")?;
            (outer == inner).then_some(outer)
        })
        .and_then(TemplatePairIdentity::parse);
    match candidate {
        Some(identity) => RequestTrace::new(RequestClass::TemplateCandidate, Some(identity)),
        None => RequestTrace::new(RequestClass::OtherQuery, None),
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
    command.env("NO_PROXY", "127.0.0.1,localhost");
    command.env("no_proxy", "127.0.0.1,localhost");
    command
}

fn run_scan(server: &OwnedMiniJinjaServer, destination: &Path, selected: bool) -> Output {
    let mut command = termivar();
    command
        .args(["scan", &server.url, "--profile", "web-review"])
        .arg("--report-dir")
        .arg(destination);
    if selected {
        command.arg("--template-evaluation-review");
    }
    command.output().expect("run actual Termivar CLI process")
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

fn exact_private_template_values(target: &str) -> Vec<String> {
    let mut values = Vec::new();
    let (primary, replay) = expected_template_pair_identities(target);
    for identity in [&primary, &replay] {
        values.push(format!("termivar-template-{}-control-end", identity.0));
        values.push(format!(
            "termivar-template-{}-{{{{'termivar_{}'|upper}}}}-end",
            identity.0, identity.0
        ));
        values.push(format!(
            "termivar-template-{}-TERMIVAR_{}-end",
            identity.0,
            identity.0.to_ascii_uppercase()
        ));
    }
    values.sort();
    values
}

#[derive(Debug, PartialEq, Eq)]
enum PrivateFixtureLeak {
    FixedFixtureValue,
    ExactTemplateValue,
}

fn private_fixture_leak(
    bytes: &[u8],
    local_path: &Path,
    target: &str,
) -> Option<PrivateFixtureLeak> {
    let text = String::from_utf8_lossy(bytes);
    let lower = text.to_ascii_lowercase();
    let local_path = local_path.to_string_lossy().into_owned();
    if exact_private_template_values(target)
        .into_iter()
        .any(|value| lower.contains(&value.to_ascii_lowercase()))
    {
        return Some(PrivateFixtureLeak::ExactTemplateValue);
    }
    let fixed_forbidden = [
        QUERY_NAME,
        "{{'termivar_",
        "'|upper}}",
        "owned-minijinja-fixture",
        "template-rendering-unavailable",
        "unknown filter",
        "minijinja",
        target,
        local_path.as_str(),
    ];
    if fixed_forbidden
        .into_iter()
        .filter(|value| !value.is_empty())
        .any(|value| lower.contains(&value.to_ascii_lowercase()))
    {
        return Some(PrivateFixtureLeak::FixedFixtureValue);
    }
    None
}

fn assert_private_values_absent(bytes: &[u8], local_path: &Path, target: &str, label: &str) {
    if let Some(leak) = private_fixture_leak(bytes, local_path, target) {
        panic!("{label} leaked a private fixture value classified as {leak:?}");
    }
}

fn read_bundle(directory: &Path, target: &str) -> Value {
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

    for name in &names {
        let bytes = fs::read(directory.join(name)).expect("read report member");
        assert_private_values_absent(&bytes, directory, target, &format!("report member {name}"));
    }
    serde_json::from_slice(
        &fs::read(directory.join(JSON_NAME)).expect("read bundled assessment JSON"),
    )
    .expect("parse bundled assessment JSON")
}

fn request_count(requests: &[RequestTrace], class: RequestClass) -> usize {
    requests
        .iter()
        .filter(|actual| actual.class == class)
        .count()
}

fn expected_template_pair_identities(target: &str) -> (TemplatePairIdentity, TemplatePairIdentity) {
    let target = Url::parse(target).expect("owned fixture target URL");
    let digest = Sha256::digest(target.origin().ascii_serialization().as_bytes());
    let identity = |bytes: &[u8]| {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("write lowercase hex into String");
        }
        TemplatePairIdentity::parse(&encoded).expect("fixed digest slice is a bounded identity")
    };
    (identity(&digest[..8]), identity(&digest[8..16]))
}

fn assert_two_distinct_template_pairs(requests: &[RequestTrace], target: &str) {
    let (primary, replay) = expected_template_pair_identities(target);
    assert_ne!(primary, replay, "primary and replay identities must differ");

    let template_requests = requests
        .iter()
        .filter(|request| {
            matches!(
                request.class,
                RequestClass::TemplateControl | RequestClass::TemplateCandidate
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        template_requests.len(),
        4,
        "selected review must emit exactly four recognized template legs"
    );

    for (label, identity) in [("primary", &primary), ("replay", &replay)] {
        let control_count = template_requests
            .iter()
            .filter(|request| {
                request.class == RequestClass::TemplateControl
                    && request.template_pair.as_ref() == Some(identity)
            })
            .count();
        let candidate_count = template_requests
            .iter()
            .filter(|request| {
                request.class == RequestClass::TemplateCandidate
                    && request.template_pair.as_ref() == Some(identity)
            })
            .count();
        assert_eq!(
            control_count, 1,
            "{label} identity must have exactly one control leg"
        );
        assert_eq!(
            candidate_count, 1,
            "{label} identity must have exactly one candidate leg"
        );
    }

    assert!(
        template_requests.iter().all(|request| {
            request.template_pair.as_ref() == Some(&primary)
                || request.template_pair.as_ref() == Some(&replay)
        }),
        "recognized template legs must belong to the exact primary/replay identities"
    );
}

fn assert_audit(assessment: &Value, outcome: &str, projected_item_count: u64) {
    let audit = assessment
        .get("template_evaluation_review")
        .expect("selected template-evaluation audit");
    assert_eq!(
        audit["schema"],
        "security.template-evaluation-review-audit/v1"
    );
    assert_eq!(audit["policy_id"], "termivar.template-evaluation-review/v1");
    assert_eq!(
        audit["family_id"],
        "web.review.template-evaluation.family.jinja-compatible-benign-expression@1"
    );
    assert_eq!(audit["outcome"], outcome);
    assert_eq!(audit["engine_identity"], "not_established");
    assert_eq!(
        audit["coverage"],
        json!({
            "selected_case_count": 2,
            "attempted_request_count": 4,
            "active_request_count": 2,
            "completed_response_count": 4,
            "committed_response_count": 4,
            "projected_item_count": projected_item_count,
        })
    );
    assert_eq!(
        audit["operations"],
        json!({
            "outbound_interaction": "not_performed",
            "os_execution": "not_performed",
            "file_access": "not_performed",
            "impact_validation": "not_performed",
        })
    );
    assert_eq!(
        audit["claim_limits"],
        json!([
            "engine_identity_not_established",
            "candidate_specific_evaluation_does_not_establish_template_engine_identity",
            "outbound_interaction_not_performed",
            "os_execution_not_performed",
            "file_access_not_performed",
            "impact_validation_not_performed",
            "vulnerability_confirmation_not_established",
        ])
    );
    assert!(audit.get("engine_version").is_none());
    assert!(audit.get("installed_version").is_none());
}

fn template_items(assessment: &Value) -> Vec<&Value> {
    assessment["items"]
        .as_array()
        .expect("assessment items")
        .iter()
        .filter(|item| item["capability_id"] == CAPABILITY_ID)
        .collect()
}

fn assert_positive_item(assessment: &Value) {
    let items = template_items(assessment);
    assert_eq!(items.len(), 1, "expected one template review item");
    let item = items[0];
    assert_eq!(
        item["title"],
        "Candidate-specific behavior consistent with Jinja-compatible expression semantics"
    );
    assert_eq!(item["disposition"], "needs_review");
    assert_eq!(item["claim_basis"], "differential");
    assert!(item["severity"].is_null());
    assert_eq!(item["confidence_ppm"], 1_000_000);
    assert_eq!(item["category"], "Template expression evaluation");
    assert_eq!(item["cwe"], "CWE-1336");
    assert_eq!(
        item["redacted_summary"],
        "Two bounded candidate/replay cases produced candidate-specific benign expression semantics while controls remained negative; template engine identity, operating-system execution, file access, outbound interaction, and impact remain unestablished."
    );
    assert_eq!(
        item["remediation"],
        json!({
            "id": "web.remediation.template-evaluation-review@1",
            "summary": "Review server-side template construction and bind untrusted values as data rather than compiling them as template source.",
        })
    );
    assert_eq!(item["evidence_count"], 12);
    assert_eq!(item["evidence_references"], json!([]));
    assert_eq!(
        item["control_evidence_references"].as_array().map(Vec::len),
        Some(6)
    );
    assert_eq!(
        item["candidate_evidence_references"]
            .as_array()
            .map(Vec::len),
        Some(6)
    );
    assert!(item["case_reference"].is_null());
    assert!(item["outcome_reference"].is_null());
    assert!(
        item["verification_stage"].is_null(),
        "knowledge-only NeedsReview item must not masquerade as a verifier transition"
    );
    for unsupported in [
        "engine",
        "engine_version",
        "installed_version",
        "os_execution",
        "file_access",
        "outbound_interaction",
        "impact",
    ] {
        assert!(item.get(unsupported).is_none());
    }
}

fn assert_offline_verify_and_self_compare(
    stopped: &StoppedFixture,
    directory: &Path,
    assessment: &Value,
    target: &str,
) {
    let request_count_before = stopped
        .requests
        .lock()
        .expect("stopped fixture trace")
        .len();

    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(directory)
        .args(["--format", "json"])
        .output()
        .expect("run Report Verify after fixture shutdown");
    assert_success(&verify, "offline Report Verify");
    assert_private_values_absent(&verify.stdout, directory, target, "Report Verify stdout");
    assert_private_values_absent(&verify.stderr, directory, target, "Report Verify stderr");
    let verification: Value =
        serde_json::from_slice(&verify.stdout).expect("parse Report Verify JSON");
    assert_eq!(verification["status"], "integrity_match");

    let report = directory.join(JSON_NAME);
    let comparison = termivar()
        .args(["report", "compare", "--before"])
        .arg(&report)
        .arg("--after")
        .arg(&report)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("run self-Compare after fixture shutdown");
    assert_success(&comparison, "offline self-Compare");
    assert_private_values_absent(&comparison.stdout, directory, target, "self-Compare stdout");
    assert_private_values_absent(&comparison.stderr, directory, target, "self-Compare stderr");
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
    let template = &comparison["template_evaluation_review_comparison"];
    assert_eq!(
        template["schema"],
        "termivar-template-evaluation-review-comparison/v1"
    );
    assert_eq!(template["status"], "compared");
    for facet in ["methodology", "coverage", "outcome"] {
        assert_eq!(template[facet]["status"], "unchanged");
    }

    assert_eq!(
        stopped
            .requests
            .lock()
            .expect("stopped fixture trace")
            .len(),
        request_count_before,
        "offline Verify/Compare changed the stopped fixture trace"
    );
    assert!(
        TcpStream::connect_timeout(&stopped.address, Duration::from_millis(100)).is_err(),
        "owned MiniJinja fixture was still listening during offline acceptance"
    );
}

#[test]
fn fixture_trace_accepts_only_exact_bounded_pair_grammar() {
    let nonce = "a1b2c3d4e5f60708";
    let identity = TemplatePairIdentity::parse(nonce).expect("literal bounded pair identity");
    assert_eq!(
        classify_request(Some("termivar-template-a1b2c3d4e5f60708-control-end")),
        RequestTrace::new(RequestClass::TemplateControl, Some(identity.clone()))
    );
    assert_eq!(
        classify_request(Some(
            "termivar-template-a1b2c3d4e5f60708-{{'termivar_a1b2c3d4e5f60708'|upper}}-end"
        )),
        RequestTrace::new(RequestClass::TemplateCandidate, Some(identity))
    );

    for malformed in [
        "termivar-template-short-control-end",
        "termivar-template-A1B2C3D4E5F60708-control-end",
        "termivar-template-a1b2c3d4e5f60708-{{'termivar_0011223344556677'|upper}}-end",
        "termivar-template-a1b2c3d4e5f60708-{{'termivar_a1b2c3d4e5f60708'|lower}}-end",
        "prefix-termivar-template-a1b2c3d4e5f60708-control-end",
        "termivar-template-a1b2c3d4e5f60708-control-end-suffix",
    ] {
        assert_eq!(
            classify_request(Some(malformed)),
            RequestTrace::new(RequestClass::OtherQuery, None),
            "malformed or loosely matching payload must not become a paired template leg"
        );
    }
    assert_eq!(
        classify_request(None),
        RequestTrace::new(RequestClass::Ordinary, None)
    );
}

#[test]
fn privacy_oracle_allows_public_schema_but_rejects_exact_nonce_bearing_values() {
    let target = "http://127.0.0.1:49152/";
    let mut expected_private_values = vec![
        "termivar-template-f294a29f58ad3e7c-control-end".to_owned(),
        "termivar-template-f294a29f58ad3e7c-{{'termivar_f294a29f58ad3e7c'|upper}}-end".to_owned(),
        "termivar-template-f294a29f58ad3e7c-TERMIVAR_F294A29F58AD3E7C-end".to_owned(),
        "termivar-template-cc64bb4c14c98fe0-control-end".to_owned(),
        "termivar-template-cc64bb4c14c98fe0-{{'termivar_cc64bb4c14c98fe0'|upper}}-end".to_owned(),
        "termivar-template-cc64bb4c14c98fe0-TERMIVAR_CC64BB4C14C98FE0-end".to_owned(),
    ];
    expected_private_values.sort();
    assert_eq!(
        exact_private_template_values(target),
        expected_private_values
    );

    let local_path = Path::new("bounded-private-report-dir");
    let public_schema = br#"{"schema":"termivar-template-evaluation-review-comparison/v1"}"#;
    assert_eq!(
        private_fixture_leak(public_schema, local_path, target),
        None,
        "the public comparison schema must not collide with the private fixture oracle"
    );
    assert_private_values_absent(
        public_schema,
        local_path,
        target,
        "public comparison schema",
    );

    for private_value in &expected_private_values {
        assert_eq!(
            private_fixture_leak(private_value.as_bytes(), local_path, target),
            Some(PrivateFixtureLeak::ExactTemplateValue),
            "the exact nonce-bearing fixture value must remain forbidden"
        );
    }

    assert_eq!(
        private_fixture_leak(b"{{'termivar_", local_path, target),
        Some(PrivateFixtureLeak::FixedFixtureValue),
        "the generic private candidate fragment remains independently forbidden"
    );

    let unrelated_nonce = b"termivar-template-0011223344556677-control-end";
    assert_eq!(
        private_fixture_leak(unrelated_nonce, local_path, target),
        None,
        "a literal mutation outside the observed request trace must not recreate the broad-prefix collision"
    );
}

#[test]
fn actual_cli_uses_two_replayed_minijinja_pairs_without_broadening_the_claim() {
    let parent = tempfile::tempdir().expect("create private report parent");

    let option_off_server = OwnedMiniJinjaServer::start(FixtureMode::TemplateSource);
    let option_off_target = option_off_server.url.clone();
    let option_off_directory = parent.path().join("option-off");
    let option_off = run_scan(&option_off_server, &option_off_directory, false);
    assert_success(&option_off, "option-off scan");
    assert_private_values_absent(
        &option_off.stdout,
        &option_off_directory,
        &option_off_target,
        "option-off stdout",
    );
    assert_private_values_absent(
        &option_off.stderr,
        &option_off_directory,
        &option_off_target,
        "option-off stderr",
    );
    let option_off_assessment = read_bundle(&option_off_directory, &option_off_target);
    assert!(option_off_assessment
        .get("template_evaluation_review")
        .is_none());
    assert!(template_items(&option_off_assessment).is_empty());
    let option_off = option_off_server.stop();
    let option_off_requests = option_off
        .requests
        .lock()
        .expect("option-off request trace")
        .clone();
    assert_eq!(
        request_count(&option_off_requests, RequestClass::TemplateControl),
        0
    );
    assert_eq!(
        request_count(&option_off_requests, RequestClass::TemplateCandidate),
        0
    );

    let positive_server = OwnedMiniJinjaServer::start(FixtureMode::TemplateSource);
    let positive_target = positive_server.url.clone();
    let positive_directory = parent.path().join("positive");
    let positive = run_scan(&positive_server, &positive_directory, true);
    assert_success(&positive, "positive MiniJinja scan");
    assert_private_values_absent(
        &positive.stdout,
        &positive_directory,
        &positive_target,
        "positive stdout",
    );
    assert_private_values_absent(
        &positive.stderr,
        &positive_directory,
        &positive_target,
        "positive stderr",
    );
    let positive_assessment = read_bundle(&positive_directory, &positive_target);
    assert_audit(&positive_assessment, "candidate_specific_evaluation", 1);
    assert_positive_item(&positive_assessment);
    let positive = positive_server.stop();
    let positive_requests = positive
        .requests
        .lock()
        .expect("positive request trace")
        .clone();
    assert_eq!(
        request_count(&positive_requests, RequestClass::TemplateControl),
        2
    );
    assert_eq!(
        request_count(&positive_requests, RequestClass::TemplateCandidate),
        2
    );
    assert_two_distinct_template_pairs(&positive_requests, &positive_target);
    assert_eq!(
        positive_requests.len(),
        option_off_requests.len() + 4,
        "selected review must add only its closed four-request schedule"
    );

    let context_bound_server = OwnedMiniJinjaServer::start(FixtureMode::ContextBound);
    let context_bound_target = context_bound_server.url.clone();
    let context_bound_directory = parent.path().join("context-bound");
    let context_bound = run_scan(&context_bound_server, &context_bound_directory, true);
    assert_success(&context_bound, "context-bound MiniJinja scan");
    assert_private_values_absent(
        &context_bound.stdout,
        &context_bound_directory,
        &context_bound_target,
        "context-bound stdout",
    );
    assert_private_values_absent(
        &context_bound.stderr,
        &context_bound_directory,
        &context_bound_target,
        "context-bound stderr",
    );
    let context_bound_assessment = read_bundle(&context_bound_directory, &context_bound_target);
    assert_audit(&context_bound_assessment, "literal_or_escaped", 0);
    assert!(template_items(&context_bound_assessment).is_empty());
    let context_bound = context_bound_server.stop();
    let context_bound_requests = context_bound
        .requests
        .lock()
        .expect("context-bound request trace")
        .clone();
    assert_eq!(
        request_count(&context_bound_requests, RequestClass::TemplateControl),
        2
    );
    assert_eq!(
        request_count(&context_bound_requests, RequestClass::TemplateCandidate),
        2
    );
    assert_two_distinct_template_pairs(&context_bound_requests, &context_bound_target);

    assert_offline_verify_and_self_compare(
        &positive,
        &positive_directory,
        &positive_assessment,
        &positive_target,
    );
    assert_offline_verify_and_self_compare(
        &context_bound,
        &context_bound_directory,
        &context_bound_assessment,
        &context_bound_target,
    );

    eprintln!(
        "template-evaluation-cli-acceptance option_off_requests={} selected_requests={} template_pair_identities=2 primary_replay_distinct=true per_pair_control=1 per_pair_candidate=1 template_control=2 template_candidate=2 active=2 committed=4 projected=1 outcome=candidate_specific_evaluation context_bound_outcome=literal_or_escaped engine_identity=not_established os_execution=not_performed file_access=not_performed outbound_interaction=not_performed impact_validation=not_performed verify=integrity_match self_compare=unchanged",
        option_off_requests.len(),
        positive_requests.len(),
    );
}
