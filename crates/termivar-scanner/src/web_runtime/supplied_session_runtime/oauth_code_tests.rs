//! Normal-orchestration regressions using original harmless loopback responses.
//! This is synthetic HTTP, not real-provider, OIDC, or interactive-login proof.

use super::*;
use crate::http_evidence::HttpEvidencePolicy;
use crate::runtime_budget::RuntimeBudget;
use crate::supplied_session_review::SuppliedSessionAuthorization;
use crate::web_runtime::{
    SuppliedSessionCoverage, SuppliedSessionResourceOutcome, WebAssessmentLimits,
    WebAssessmentRuntimeBuilder,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use url::Url;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CODE: &str = "SYNTHETIC-IMPORTED-CODE-CANARY";
const ACCESS: &str = "SYNTHETIC-OAUTH-BEARER-CANARY";
const TOKEN_BODY: &str = r#"{"access_token":"SYNTHETIC-OAUTH-BEARER-CANARY","token_type":"Bearer","expires_in":180,"scope":"canary-read"}"#;

#[derive(Clone, Copy)]
enum TokenMode {
    Complete,
    Hold,
    Partial,
    ShortLifetime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestTrace {
    role: &'static str,
    method: String,
    expected_bearer: bool,
    unexpected_authorization: bool,
    cookie: bool,
    exact_code_form: bool,
}

struct Fixture {
    application: Url,
    issuer: Url,
    trace: Arc<Mutex<Vec<RequestTrace>>>,
    token_seen: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn start(mode: TokenMode) -> Self {
        let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let application =
            Url::parse(&format!("http://{}/", app_listener.local_addr().unwrap())).unwrap();
        let issuer = Url::parse(&format!(
            "http://{}/issuer",
            idp_listener.local_addr().unwrap()
        ))
        .unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let token_seen = Arc::new(Notify::new());
        let mut tasks = Vec::new();
        for (listener, is_idp) in [(app_listener, false), (idp_listener, true)] {
            let trace = Arc::clone(&trace);
            let token_seen = Arc::clone(&token_seen);
            let redirect = application.join("callback").unwrap().to_string();
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else { return };
                    let request = tokio::time::timeout(Duration::from_secs(2), read_request(&mut stream))
                        .await.expect("owned request read deadline");
                    let (headers, body) = request.split_at(request.windows(4)
                        .position(|part| part == b"\r\n\r\n").unwrap() + 4);
                    let headers = std::str::from_utf8(headers).unwrap();
                    let mut first = headers.lines().next().unwrap().split_ascii_whitespace();
                    let method = first.next().unwrap().to_owned();
                    let path = first.next().unwrap();
                    let authorization = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization").then(|| value.trim())
                    });
                    let expected_bearer = authorization == Some("Bearer SYNTHETIC-OAUTH-BEARER-CANARY");
                    let cookie = headers.lines().any(|line| line.split_once(':')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case("cookie")));
                    let role = if is_idp {
                        assert_eq!(path, "/issuer/token", "IdP path must remain literal");
                        "idp"
                    } else {
                        match path {
                            "/app/health" => "health",
                            "/app/private/one" => "resource-one",
                            "/app/private/two" => "resource-two",
                            "/" => "ordinary",
                            _ => panic!("unexpected owned target route"),
                        }
                    };
                    let exact_code_form = if is_idp {
                        let fields: Vec<_> = url::form_urlencoded::parse(body).into_owned().collect();
                        fields.len() == 5
                            && fields.iter().filter(|(key, _)| key == "grant_type").count() == 1
                            && fields.iter().any(|(key, value)| key == "grant_type" && value == "authorization_code")
                            && fields.iter().any(|(key, value)| key == "client_id" && value == "owned-runtime-public")
                            && fields.iter().any(|(key, value)| key == "redirect_uri" && value == &redirect)
                            && fields.iter().any(|(key, value)| key == "code" && value == CODE)
                            && fields.iter().any(|(key, value)| key == "code_verifier" && value == VERIFIER)
                    } else { body.is_empty() };
                    {
                        let mut trace = trace.lock().await;
                        assert!(trace.len() < 32, "fixture request bound");
                        trace.push(RequestTrace {
                            role, method, expected_bearer,
                            unexpected_authorization: authorization.is_some() && !expected_bearer,
                            cookie, exact_code_form,
                        });
                    }
                    if is_idp {
                        match mode {
                            TokenMode::Complete | TokenMode::ShortLifetime => {
                                let body = if matches!(mode, TokenMode::ShortLifetime) {
                                    r#"{"access_token":"SYNTHETIC-OAUTH-BEARER-CANARY","token_type":"Bearer","expires_in":1,"scope":"canary-read"}"#
                                } else { TOKEN_BODY };
                                write_response(&mut stream, "application/json", body).await;
                                token_seen.notify_one();
                            },
                            TokenMode::Hold => {
                                token_seen.notify_one();
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            },
                            TokenMode::Partial => {
                                let prefix = "{\"access_token\":";
                                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{prefix}", TOKEN_BODY.len());
                                stream.write_all(head.as_bytes()).await.unwrap();
                                token_seen.notify_one();
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            },
                        }
                    } else {
                        if role == "resource-one" && matches!(mode, TokenMode::ShortLifetime) {
                            // This server never expires tokens: only the
                            // client's declared-lifetime bound is under test.
                            tokio::time::sleep(Duration::from_millis(1500)).await;
                        }
                        match role {
                            "health" => write_response(&mut stream, "application/json", r#"{"authenticated":true}"#).await,
                            "resource-one" | "resource-two" => write_response(&mut stream, "text/html", "PRIVATE-OAUTH-RESOURCE-CANARY").await,
                            _ => write_response(&mut stream, "text/html", "<!doctype html><main>owned public root</main>").await,
                        }
                    }
                }
            }));
        }
        Self {
            application,
            issuer,
            trace,
            token_seen,
            tasks,
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        assert!(request.len() <= 32 * 1024, "fixture input byte limit");
        if expected.is_some_and(|length| request.len() >= length) {
            return request;
        }
        let mut buffer = [0; 1024];
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "request ended before complete bounded body");
        request.extend_from_slice(&buffer[..read]);
        if expected.is_none() {
            if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                assert!(end <= 16 * 1024, "fixture header limit");
                let header = std::str::from_utf8(&request[..end]).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length <= 16 * 1024, "fixture body limit");
                expected = Some(end + 4 + length);
            }
        }
    }
}

async fn write_response(stream: &mut TcpStream, media: &str, body: &str) {
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn policy(application: &Url, issuer: &Url, alias: &str) -> SuppliedSessionPolicy {
    let endpoint = format!("{issuer}/token");
    let redirect = application.join("callback").unwrap();
    let source = format!(
        r#"schema = "security.supplied-session-policy/v5"
principal_alias = "{alias}"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 6
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 5000
[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "owned-numeric-loopback-http/v1"
issuer = "{issuer}"
token_endpoint = "{endpoint}"
client_id = "owned-runtime-public"
redirect_uri = "{redirect}"
scopes = ["canary-read"]
max_token_response_bytes = 8192
"#
    );
    SuppliedSessionPolicy::parse_toml(application, source.as_bytes()).unwrap()
}

fn grant(policy: &SuppliedSessionPolicy) -> SuppliedSessionOAuthGrant {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    grant_at(policy, now, now)
}

fn grant_at(
    policy: &SuppliedSessionPolicy,
    received: u64,
    parse_now: u64,
) -> SuppliedSessionOAuthGrant {
    let idp = policy.oauth_code_policy().unwrap();
    let source = format!("authorization_code\t{CODE}\ncode_verifier\t{VERIFIER}\ncode_challenge\t{CHALLENGE}\nissuer\t{}\nclient_id\towned-runtime-public\nredirect_uri\t{}\nscope\tcanary-read\nreceived_unix_seconds\t{received}\n", idp.issuer(), idp.redirect_uri());
    SuppliedSessionOAuthGrant::parse_tsv(
        policy,
        source.into_bytes(),
        i64::try_from(parse_now).unwrap(),
    )
    .unwrap()
}

fn assert_value_safe(audit: &super::super::WebAssessmentSuppliedSessionAudit) {
    let saved = serde_json::to_string(audit).unwrap();
    for forbidden in [CODE, VERIFIER, ACCESS, "PRIVATE-OAUTH-RESOURCE-CANARY"] {
        assert!(!saved.contains(forbidden), "private value entered audit");
        assert!(
            !saved.contains(&format!("{:x}", Sha256::digest(forbidden.as_bytes()))),
            "private-value hash entered audit"
        );
    }
    assert!(!saved.contains(&format!("{:x}", Sha256::digest(TOKEN_BODY.as_bytes()))));
}

#[tokio::test]
async fn normal_runtime_code_exchange_precedes_six_shared_requests_and_keeps_values_private() {
    let fixture = Fixture::start(TokenMode::Complete).await;
    let policy = policy(&fixture.application, &fixture.issuer, "owned-a");
    let input = grant(&policy);
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
        .with_supplied_session_review(policy, input)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let audit = report.supplied_session_audit().unwrap();
    assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::Complete);
    assert_eq!(audit.coverage(), SuppliedSessionCoverage::Complete);
    assert_eq!(audit.dispatched_request_count(), 6);
    assert_eq!(audit.committed_resource_count(), 2);
    assert_eq!(audit.checkpoints().len(), 3);
    assert_eq!(audit.resources().len(), 2);
    let code = audit.oauth_code().unwrap();
    assert_eq!(
        code.outcome(),
        SuppliedSessionOAuthCodeOutcome::CredentialCommitted
    );
    assert_eq!(code.request_admitted_count(), 1);
    assert_eq!(code.credential_commit_count(), 1);
    assert_eq!(code.response_bytes(), TOKEN_BODY.len() as u64);
    let id = EvidenceId::parse(code.evidence_reference().unwrap()).unwrap();
    assert_eq!(
        runtime.knowledge().inspect_evidence(&id, |evidence| {
            evidence.kind() == &EvidenceKind::Authentication
                && evidence.predicate().name() == ACQUISITION_PREDICATE
        }),
        Some(true)
    );
    let trace = fixture.trace.lock().await.clone();
    let roles: Vec<_> = trace
        .iter()
        .filter(|row| row.role != "ordinary")
        .map(|row| row.role)
        .collect();
    assert_eq!(
        roles,
        [
            "idp",
            "health",
            "resource-one",
            "health",
            "resource-two",
            "health"
        ]
    );
    assert!(trace.iter().any(|row| row.role == "ordinary"));
    assert!(trace
        .iter()
        .all(|row| !row.cookie && !row.unexpected_authorization && row.exact_code_form));
    assert!(trace
        .iter()
        .filter(|row| row.role == "idp")
        .all(|row| row.method == "POST" && !row.expected_bearer));
    assert!(trace
        .iter()
        .filter(|row| row.role != "idp")
        .all(|row| row.method == "GET" && row.expected_bearer == (row.role != "ordinary")));
    assert_eq!(
        usize::try_from(report.usage().total_requests()).unwrap(),
        trace.len()
    );
    assert_eq!(
        audit.response_bytes(),
        code.response_bytes()
            + audit
                .checkpoints()
                .iter()
                .map(|row| row.response_bytes())
                .sum::<u64>()
            + audit
                .resources()
                .iter()
                .map(|row| row.response_bytes())
                .sum::<u64>()
    );
    assert_value_safe(audit);
}

#[tokio::test]
async fn normal_runtime_code_exchange_consumes_same_parent_request_and_response_allowance() {
    for request_limit in [true, false] {
        let fixture = Fixture::start(TokenMode::Complete).await;
        let policy = policy(&fixture.application, &fixture.issuer, "owned-a");
        let input = grant(&policy);
        let builder = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
            .with_supplied_session_review(policy, input);
        let limits = if request_limit {
            WebAssessmentLimits::default()
                .with_max_total_requests(1)
                .unwrap()
        } else {
            WebAssessmentLimits::default()
                .with_max_total_response_bytes(32)
                .unwrap()
        };
        let mut runtime = builder.limits(limits).build().unwrap();
        let report = runtime.analyze().await.unwrap();
        let audit = report.supplied_session_audit().unwrap();
        let trace = fixture.trace.lock().await.clone();
        assert_eq!(
            trace.len(),
            1,
            "no health, ordinary fetch, retry, or resource after parent exhaustion"
        );
        assert_eq!(trace[0].role, "idp");
        assert_eq!(audit.dispatched_request_count(), 1);
        assert_eq!(audit.committed_resource_count(), 0);
        assert!(audit
            .resources()
            .iter()
            .all(|row| row.outcome() == SuppliedSessionResourceOutcome::NotDispatched));
        assert_eq!(report.usage().total_requests(), 1);
        if request_limit {
            assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::RuntimeLimit);
            assert_eq!(audit.oauth_code().unwrap().credential_commit_count(), 1);
        } else {
            assert_eq!(
                audit.outcome(),
                SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable
            );
            assert_eq!(audit.oauth_code().unwrap().credential_commit_count(), 0);
            assert!(report.usage().response_bytes() >= 32);
            assert!(report.usage().response_bytes() <= TOKEN_BODY.len() as u64);
        }
        assert_eq!(audit.response_bytes(), report.usage().response_bytes());
        assert_value_safe(audit);
    }
}

#[tokio::test]
async fn normal_runtime_pre_cancelled_code_selection_dispatches_nothing() {
    let fixture = Fixture::start(TokenMode::Complete).await;
    let policy = policy(&fixture.application, &fixture.issuer, "owned-a");
    let input = grant(&policy);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
        .cancellation_token(cancellation)
        .with_supplied_session_review(policy, input)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let audit = report.supplied_session_audit().unwrap();
    assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::Cancelled);
    assert_eq!(
        audit.oauth_code().unwrap().outcome(),
        SuppliedSessionOAuthCodeOutcome::Cancelled
    );
    assert_eq!(audit.dispatched_request_count(), 0);
    assert_eq!(audit.response_bytes(), 0);
    assert_eq!(report.usage().total_requests(), 0);
    assert!(fixture.trace.lock().await.is_empty());
    assert_eq!(runtime.knowledge().stats().evidence, 0);
}

#[tokio::test]
async fn normal_runtime_cancellation_during_one_redemption_has_no_retry_or_bearer_tail() {
    let fixture = Fixture::start(TokenMode::Hold).await;
    let policy = policy(&fixture.application, &fixture.issuer, "owned-a");
    let input = grant(&policy);
    let cancellation = CancellationToken::new();
    let seen = Arc::clone(&fixture.token_seen);
    let cancel = cancellation.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(2), seen.notified())
            .await
            .unwrap();
        cancel.cancel();
    });
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
        .cancellation_token(cancellation)
        .with_supplied_session_review(policy, input)
        .build()
        .unwrap();
    let report = tokio::time::timeout(Duration::from_secs(3), runtime.analyze())
        .await
        .unwrap()
        .unwrap();
    cancel_task.await.unwrap();
    let audit = report.supplied_session_audit().unwrap();
    assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::Cancelled);
    assert_eq!(audit.oauth_code().unwrap().credential_commit_count(), 0);
    assert_eq!(audit.oauth_code().unwrap().request_admitted_count(), 1);
    assert_eq!(report.usage().total_requests(), 1);
    let trace = fixture.trace.lock().await.clone();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].role, "idp");
    assert!(audit.checkpoints().is_empty());
    assert!(audit
        .resources()
        .iter()
        .all(|row| row.outcome() == SuppliedSessionResourceOutcome::NotDispatched));
    assert_value_safe(audit);
}

#[tokio::test]
async fn normal_runtime_parent_deadline_retains_partial_bytes_but_never_commits_a_token() {
    let fixture = Fixture::start(TokenMode::Partial).await;
    let policy = policy(&fixture.application, &fixture.issuer, "owned-a");
    let input = grant(&policy);
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
        .limits(
            WebAssessmentLimits::default()
                .with_max_wall_time(Duration::from_secs(1))
                .unwrap(),
        )
        .with_supplied_session_review(policy, input)
        .build()
        .unwrap();
    let report = tokio::time::timeout(Duration::from_secs(3), runtime.analyze())
        .await
        .unwrap()
        .unwrap();
    let audit = report.supplied_session_audit().unwrap();
    assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::RuntimeLimit);
    assert_eq!(
        audit.oauth_code().unwrap().outcome(),
        SuppliedSessionOAuthCodeOutcome::RuntimeLimit
    );
    assert_eq!(audit.oauth_code().unwrap().credential_commit_count(), 0);
    assert_eq!(audit.oauth_code().unwrap().request_admitted_count(), 1);
    assert!(audit.response_bytes() > 0);
    assert_eq!(audit.response_bytes(), report.usage().response_bytes());
    assert_eq!(report.usage().total_requests(), 1);
    assert!(audit.checkpoints().is_empty());
    assert_eq!(fixture.trace.lock().await.len(), 1);
    assert_value_safe(audit);
}

#[test]
fn normal_builder_rejects_ready_v5_and_grants_from_other_alias_or_idp() {
    let application = Url::parse("http://127.0.0.1:18080/").unwrap();
    let issuer = Url::parse("http://127.0.0.1:18081/issuer").unwrap();
    let selected = policy(&application, &issuer, "owned-a");
    assert!(WebAssessmentRuntimeBuilder::new(application.clone())
        .with_supplied_session_review(
            policy(&application, &issuer, "owned-a"),
            SuppliedSessionAuthorization::new("Bearer SYNTHETIC-READY-CANARY").unwrap()
        )
        .build()
        .is_err());
    for other in [
        policy(&application, &issuer, "owned-b"),
        policy(
            &application,
            &Url::parse("http://127.0.0.1:18082/issuer").unwrap(),
            "owned-a",
        ),
    ] {
        assert!(WebAssessmentRuntimeBuilder::new(application.clone())
            .with_supplied_session_review(other, grant(&selected))
            .build()
            .is_err());
    }
}

#[tokio::test]
async fn normal_runtime_without_code_selection_has_no_idp_or_credential_activity() {
    let fixture = Fixture::start(TokenMode::Complete).await;
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    assert!(report.supplied_session_audit().is_none());
    let trace = fixture.trace.lock().await.clone();
    assert!(!trace.is_empty());
    assert!(trace.iter().all(|row| row.role == "ordinary"
        && row.method == "GET"
        && !row.expected_bearer
        && !row.unexpected_authorization
        && !row.cookie));
    assert_eq!(
        usize::try_from(report.usage().total_requests()).unwrap(),
        trace.len()
    );
}

fn receipt_fixture() -> (
    SuppliedSessionPolicy,
    KnowledgeBase,
    CommittedOAuthCodeReceipt,
) {
    let application = Url::parse("http://127.0.0.1:18080/").unwrap();
    let issuer = Url::parse("http://127.0.0.1:18081/issuer").unwrap();
    let policy = policy(&application, &issuer, "owned-a");
    let knowledge = KnowledgeBase::new();
    let idp = policy.oauth_code_policy().unwrap();
    let reference = commit_value_safe_evidence(
        &policy,
        idp.binding_reference(),
        b"security.synthetic.oauth-receipt-regression.v1\0",
        "supplied-session-oauth-code-evidence-sha256",
        ACQUISITION_PREDICATE,
        "synthetic-receipt-authority-regression",
        "original value-free fixture".to_owned(),
        &knowledge,
    )
    .unwrap();
    let id = EvidenceId::parse(&reference).unwrap();
    let expected_evidence = knowledge.inspect_evidence(&id, Clone::clone).unwrap();
    let receipt = CommittedOAuthCodeReceipt {
        knowledge_authority: knowledge.authority().clone(),
        policy_reference: policy.policy_reference().to_owned(),
        application_reference: policy.application_reference().to_owned(),
        idp_reference: idp.binding_reference().to_owned(),
        evidence_reference: reference,
        principal_alias: policy.principal_alias().to_owned(),
        expected_evidence,
    };
    (policy, knowledge, receipt)
}

#[test]
fn committed_oauth_receipt_rejects_identical_evidence_copied_to_another_knowledge_authority() {
    let (policy, original, receipt) = receipt_fixture();
    assert!(receipt.is_valid_for(&policy, &original));
    assert!(
        receipt.is_valid_for(&policy, &original.clone()),
        "clone retains the same process-local authority"
    );
    let foreign = KnowledgeBase::new();
    foreign
        .insert_evidence(receipt.expected_evidence.clone())
        .unwrap();
    assert!(
        !receipt.is_valid_for(&policy, &foreign),
        "identical public evidence cannot transfer private acquisition authority"
    );
}

#[test]
fn committed_oauth_receipt_rejects_alias_policy_idp_application_and_reference_substitution() {
    let (policy, original, mut receipt) = receipt_fixture();
    let original_value = receipt.principal_alias.clone();
    receipt.principal_alias = "owned-b".to_owned();
    assert!(!receipt.is_valid_for(&policy, &original));
    receipt.principal_alias = original_value;
    for field in 0..4 {
        let (policy, original, mut receipt) = receipt_fixture();
        assert!(receipt.is_valid_for(&policy, &original));
        match field {
            0 => {
                receipt.policy_reference =
                    "supplied-session-policy-sha256:".to_owned() + &"0".repeat(64)
            },
            1 => {
                receipt.application_reference =
                    "supplied-session-application-sha256:".to_owned() + &"0".repeat(64)
            },
            2 => receipt.idp_reference = "oauth-code-policy-sha256:".to_owned() + &"0".repeat(64),
            _ => {
                receipt.evidence_reference =
                    "supplied-session-oauth-code-evidence-sha256:".to_owned() + &"0".repeat(64)
            },
        }
        assert!(
            !receipt.is_valid_for(&policy, &original),
            "bound reference substitution {field}"
        );
    }
}

#[test]
fn typed_oauth_audit_consistency_rejects_claim_accounting_and_commit_mutations() {
    let application = Url::parse("http://127.0.0.1:18080/").unwrap();
    let issuer = Url::parse("http://127.0.0.1:18081/issuer").unwrap();
    let policy = policy(&application, &issuer, "owned-a");
    let selected = SuppliedSessionOAuthCodeAudit::selected(&policy).unwrap();
    assert!(selected.is_consistent());

    // Original literal typed fixture. This proves consistency, not acquisition
    // authority: only the real runtime/knowledge receipt can authorize health.
    let mut committed = selected.clone();
    committed.request_attempt_count = 1;
    committed.request_admitted_count = 1;
    committed.response_completed_count = 1;
    committed.credential_commit_count = 1;
    committed.verifier_in_admitted_request = true;
    committed.status = Some(200);
    committed.body_state = super::super::SuppliedSessionBodyState::Complete;
    committed.response_bytes = 112;
    committed.configured_token_response_byte_limit = 8192;
    committed.token_response_validated = true;
    committed.response_scope_matched = Some(true);
    committed.declared_token_lifetime_seconds = Some(180);
    committed.refresh_token_returned = Some(false);
    committed.evidence_reference = Some(
        "supplied-session-oauth-code-evidence-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    );
    committed.outcome = SuppliedSessionOAuthCodeOutcome::CredentialCommitted;
    assert!(committed.is_consistent());

    let committed_mutations: &[fn(&mut SuppliedSessionOAuthCodeAudit)] = &[
        |audit| audit.authorization_initiated = true,
        |audit| audit.browser_callback_received = true,
        |audit| audit.state_nonce_verified = true,
        |audit| audit.oidc_identity_validation_performed = true,
        |audit| audit.token_signature_validation_performed = true,
        |audit| audit.profile = "unsupported",
        |audit| audit.transaction_context_assurance = "authenticated_transaction",
        |audit| audit.pkce_assurance = "remote_enforcement_proven",
        |audit| audit.token_interpretation = "verified_oidc_identity",
        |audit| audit.request_attempt_count = 2,
        |audit| audit.request_admitted_count = 2,
        |audit| audit.request_admitted_count = 0,
        |audit| audit.response_completed_count = 0,
        |audit| audit.response_completed_count = 2,
        |audit| audit.credential_commit_count = 0,
        |audit| audit.credential_commit_count = 2,
        |audit| audit.verifier_in_admitted_request = false,
        |audit| audit.status = Some(201),
        |audit| audit.status = None,
        |audit| audit.body_state = super::super::SuppliedSessionBodyState::Incomplete,
        |audit| audit.response_bytes = 0,
        |audit| audit.response_bytes = 8193,
        |audit| audit.response_scope_matched = Some(false),
        |audit| audit.response_scope_matched = None,
        |audit| audit.declared_token_lifetime_seconds = None,
        |audit| audit.declared_token_lifetime_seconds = Some(0),
        |audit| audit.declared_token_lifetime_seconds = Some(3601),
        |audit| audit.refresh_token_returned = None,
        |audit| audit.token_response_validated = false,
        |audit| audit.evidence_reference = None,
        |audit| audit.evidence_reference = Some("not-an-evidence-reference".to_owned()),
        |audit| audit.outcome = SuppliedSessionOAuthCodeOutcome::ResponseRejected,
    ];
    assert_eq!(committed_mutations.len(), 32);
    for (index, mutate) in committed_mutations.iter().enumerate() {
        let mut audit = committed.clone();
        mutate(&mut audit);
        assert!(
            !audit.is_consistent(),
            "impossible committed-state mutation {index}"
        );
    }
    let unavailable_mutations: &[fn(&mut SuppliedSessionOAuthCodeAudit)] = &[
        |audit| audit.status = Some(200),
        |audit| audit.response_bytes = 1,
        |audit| audit.response_scope_matched = Some(true),
        |audit| audit.credential_commit_count = 1,
        |audit| {
            audit.evidence_reference = Some(
            "supplied-session-oauth-code-evidence-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        )
        },
    ];
    assert_eq!(unavailable_mutations.len(), 5);
    for (index, mutate) in unavailable_mutations.iter().enumerate() {
        let mut audit = selected.clone();
        mutate(&mut audit);
        assert!(
            !audit.is_consistent(),
            "unavailable evidence mutation {index}"
        );
    }
}

#[tokio::test]
async fn normal_runtime_rechecks_imported_grant_freshness_at_real_dispatch_time() {
    let fixture = Fixture::start(TokenMode::Complete).await;
    let policy = policy(&fixture.application, &fixture.issuer, "owned-a");
    let historical_asserted_receipt = 1_700_000_000;
    // Parsing is valid at this supplied historic clock. The actual broker
    // must independently recheck current SystemTime immediately before POST.
    let input = grant_at(
        &policy,
        historical_asserted_receipt,
        historical_asserted_receipt,
    );
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
        .with_supplied_session_review(policy, input)
        .build()
        .unwrap();
    let report = runtime.analyze().await.unwrap();
    let audit = report.supplied_session_audit().unwrap();
    let code = audit.oauth_code().unwrap();
    assert_eq!(
        code.outcome(),
        SuppliedSessionOAuthCodeOutcome::GrantUnavailable
    );
    assert_eq!(code.request_attempt_count(), 1);
    assert_eq!(code.request_admitted_count(), 0);
    assert_eq!(code.credential_commit_count(), 0);
    assert_eq!(
        audit.outcome(),
        SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable
    );
    assert_eq!(audit.dispatched_request_count(), 0);
    assert_eq!(audit.dispatched_resource_count(), 0);
    assert_eq!(audit.response_bytes(), 0);
    assert!(audit.checkpoints().is_empty());
    assert!(audit
        .resources()
        .iter()
        .all(|row| row.outcome() == SuppliedSessionResourceOutcome::NotDispatched));
    let trace = fixture.trace.lock().await.clone();
    assert!(trace.iter().all(|row| row.role == "ordinary"
        && !row.expected_bearer
        && !row.unexpected_authorization));
    assert_eq!(
        usize::try_from(report.usage().total_requests()).unwrap(),
        trace.len()
    );
    assert_value_safe(audit);
}

#[tokio::test]
async fn normal_runtime_provider_declared_lifetime_narrows_use_without_claiming_server_expiry() {
    let fixture = Fixture::start(TokenMode::ShortLifetime).await;
    let policy = policy(&fixture.application, &fixture.issuer, "owned-a");
    let input = grant(&policy);
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.application.clone())
        .with_supplied_session_review(policy, input)
        .build()
        .unwrap();
    let report = tokio::time::timeout(Duration::from_secs(4), runtime.analyze())
        .await
        .unwrap()
        .unwrap();
    let audit = report.supplied_session_audit().unwrap();
    let code = audit.oauth_code().unwrap();
    assert_eq!(
        code.outcome(),
        SuppliedSessionOAuthCodeOutcome::CredentialCommitted
    );
    assert_eq!(code.declared_token_lifetime_seconds(), Some(1));
    assert_eq!(code.credential_commit_count(), 1);
    assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::RuntimeLimit);
    assert_eq!(audit.dispatched_request_count(), 3);
    assert_eq!(audit.dispatched_resource_count(), 1);
    assert_eq!(audit.committed_resource_count(), 0);
    assert_eq!(audit.checkpoints().len(), 1);
    assert_eq!(
        audit.checkpoints()[0].outcome(),
        super::super::SuppliedSessionHealthOutcome::Healthy
    );
    assert_eq!(
        audit.resources()[1].outcome(),
        SuppliedSessionResourceOutcome::NotDispatched
    );
    let trace = fixture.trace.lock().await.clone();
    let credential_roles: Vec<_> = trace
        .iter()
        .filter(|row| row.role != "ordinary")
        .map(|row| row.role)
        .collect();
    assert_eq!(credential_roles, ["idp", "health", "resource-one"]);
    assert_eq!(
        usize::try_from(report.usage().total_requests()).unwrap(),
        trace.len()
    );
    assert_value_safe(audit);
}

#[tokio::test]
async fn assessment_minted_code_broker_refuses_other_descriptors_and_a_second_post() {
    let fixture = Fixture::start(TokenMode::Complete).await;
    let selected = policy(&fixture.application, &fixture.issuer, "owned-a");
    let input = grant(&selected);
    let authority = SharedWebRuntimeAuthority::new_exact_origin(
        &fixture.application,
        HttpEvidencePolicy::new([fixture.application.clone()], Duration::from_secs(2), 8192)
            .unwrap(),
        RuntimeBudget::default().with_max_total_requests(1),
        CancellationToken::new(),
    )
    .unwrap();
    let broker = authority.mint_oauth_code_broker(&selected).unwrap();
    let descriptor = OAuthCodeRequestDescriptor::from_policy(&selected).unwrap();
    let wrong_idp = Url::parse("http://127.0.0.1:18082/other-issuer").unwrap();
    for other in [
        policy(&fixture.application, &fixture.issuer, "owned-b"),
        policy(&fixture.application, &wrong_idp, "owned-a"),
    ] {
        let other_descriptor = OAuthCodeRequestDescriptor::from_policy(&other).unwrap();
        let result = broker
            .collect(
                &other_descriptor,
                &selected,
                &input,
                DecisionExecutionLimits::new().with_max_response_body_bytes(8192),
            )
            .await;
        assert!(matches!(
            result,
            Err(OAuthCodeRequestError::InvalidDescriptor)
        ));
    }
    assert_eq!(
        authority.request_accounting().snapshot().total_requests(),
        0
    );
    assert!(fixture.trace.lock().await.is_empty());
    let response = broker
        .collect(
            &descriptor,
            &selected,
            &input,
            DecisionExecutionLimits::new().with_max_response_body_bytes(8192),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(response.complete && response.representation_supported);
    assert_eq!(response.body.as_slice(), TOKEN_BODY.as_bytes());
    let second = broker
        .collect(
            &descriptor,
            &selected,
            &input,
            DecisionExecutionLimits::new().with_max_response_body_bytes(8192),
        )
        .await;
    assert!(matches!(
        second,
        Err(OAuthCodeRequestError::AlreadyAttempted)
    ));
    assert_eq!(
        authority.request_accounting().snapshot().total_requests(),
        1
    );
    let trace = fixture.trace.lock().await.clone();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].role, "idp");
    assert_eq!(trace[0].method, "POST");
    assert!(trace[0].exact_code_form && !trace[0].cookie && !trace[0].unexpected_authorization);
}
