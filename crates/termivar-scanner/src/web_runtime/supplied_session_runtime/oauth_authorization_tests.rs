//! Original synthetic HTTP through normal runtime construction, not a real
//! identity provider, authenticated browser or OIDC acceptance claim.

use super::*;
use crate::{
    supplied_session_review::SuppliedSessionRuntimeInput,
    web_runtime::{SuppliedSessionAuditOutcome, WebAssessmentLimits, WebAssessmentRuntimeBuilder},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;

const TOKEN: &str = "SYNTHETIC-INITIATED-ACCESS-CANARY";
const CODE: &str = "SYNTHETIC-INITIATED-CODE-CANARY";

#[derive(Clone)]
struct Output {
    bytes: Arc<Mutex<Vec<u8>>>,
    ready: Arc<Notify>,
}
impl std::io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.ready.notify_one();
        Ok(())
    }
}

struct Fixture {
    app: Url,
    issuer: Url,
    callback: Url,
    trace: Arc<Mutex<Vec<(String, bool)>>>,
    challenge: Arc<Mutex<Option<String>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn start() -> Self {
        let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // The controller selects an unused test port before supplying an exact
        // registered URI; the product never substitutes port0/dynamic URLs.
        let callback = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let callback_url = Url::parse(&format!(
            "http://{}/termivar/oauth/callback",
            callback.local_addr().unwrap()
        ))
        .unwrap();
        drop(callback);
        let app_url = Url::parse(&format!("http://{}/", app.local_addr().unwrap())).unwrap();
        let issuer = Url::parse(&format!("http://{}/issuer", idp.local_addr().unwrap())).unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let challenge = Arc::new(Mutex::new(None::<String>));
        let mut tasks = Vec::new();
        for (listener, is_idp) in [(app, false), (idp, true)] {
            let trace = Arc::clone(&trace);
            let challenge = Arc::clone(&challenge);
            let callback = callback_url.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((mut stream,_)) = listener.accept().await else { return; };
                    let request = tokio::time::timeout(Duration::from_secs(2),read_request(&mut stream)).await.unwrap();
                    let split = request.windows(4).position(|s|s == b"\r\n\r\n").unwrap()+4;
                    let headers = std::str::from_utf8(&request[..split]).unwrap();
                    let first: Vec<_> = headers.lines().next().unwrap().split_ascii_whitespace().collect();
                    let path = first[1];
                    let auth = headers.lines().find_map(|line|line.split_once(':').filter(|(k,_)|k.eq_ignore_ascii_case("authorization")).map(|(_,v)|v.trim()));
                    let response = if is_idp {
                        assert_eq!((first[0],path),("POST","/issuer/token"));
                        assert!(auth.is_none(),"IdP must not inherit target credentials");
                        let fields: std::collections::BTreeMap<_,_> = url::form_urlencoded::parse(&request[split..]).into_owned().collect();
                        assert_eq!(fields.len(),5);
                        assert_eq!(fields["grant_type"],"authorization_code");
                        assert_eq!(fields["code"],CODE);
                        assert_eq!(fields["client_id"],"owned-public-client");
                        assert_eq!(fields["redirect_uri"],callback.as_str());
                        assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(fields["code_verifier"].as_bytes())), challenge.lock().unwrap().clone().unwrap());
                        ("application/json",format!(r#"{{"access_token":"{TOKEN}","token_type":"Bearer","expires_in":90,"scope":"canary-read"}}"#))
                    } else if path == "/app/health" {
                        assert_eq!(auth,Some(format!("Bearer {TOKEN}").as_str()));
                        ("application/json",r#"{"authenticated":true}"#.to_owned())
                    } else if path == "/app/private" {
                        assert_eq!(auth,Some(format!("Bearer {TOKEN}").as_str()));
                        ("text/html","<p>owned protected canary</p>".to_owned())
                    } else {
                        assert_eq!(path,"/"); assert!(auth.is_none());
                        ("text/html","<!doctype html><p>owned public root</p>".to_owned())
                    };
                    {
                        let mut rows = trace.lock().unwrap(); assert!(rows.len() < 32);
                        rows.push((if is_idp { "token".to_owned() } else {path.to_owned()}, auth.is_some()));
                    }
                    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.0,response.1.len(),response.1);
                    stream.write_all(reply.as_bytes()).await.unwrap();
                    let _ = stream.shutdown().await;
                }
            }));
        }
        Self {
            app: app_url,
            issuer,
            callback: callback_url,
            trace,
            challenge,
            tasks,
        }
    }

    fn policy(&self, wait_ms: u64) -> SuppliedSessionPolicy {
        let text = format!(
            r#"schema="security.supplied-session-policy/v7"
principal_alias="owned-user"
credential_mechanism="authorization_header"
credential_acquisition="client_initiated_oauth_pkce"
health_path="/app/health"
health_json_field="authenticated"
resources=["/app/private"]
max_session_requests=4
max_total_response_bytes=65536
max_response_body_bytes=8192
max_wall_time_ms=1500
[oauth_code]
profile="client-initiated-public-code-s256-bearer/v1"
transport_profile="owned-numeric-loopback-http/v1"
issuer="{}"
token_endpoint="{}/token"
client_id="owned-public-client"
redirect_uri="{}"
scopes=["canary-read"]
max_token_response_bytes=8192
[oauth_authorization]
profile="loopback-form-post-state/v1"
authorization_endpoint="{}/authorize"
max_wait_ms={wait_ms}
"#,
            self.issuer, self.issuer, self.callback, self.issuer
        );
        SuppliedSessionPolicy::parse_toml(&self.app, text.as_bytes()).unwrap()
    }
}

async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut expected = None;
    loop {
        assert!(bytes.len() < 16384);
        let mut chunk = [0; 1024];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&chunk[..n]);
        if expected.is_none() {
            if let Some(p) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                let head = std::str::from_utf8(&bytes[..p]).unwrap();
                let size = head
                    .lines()
                    .find_map(|l| {
                        l.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(size < 8192);
                expected = Some(p + 4 + size);
            }
        }
        if expected.is_some_and(|n| bytes.len() >= n) {
            return bytes;
        }
    }
}

async fn execute_case(mode: &str, budget: Option<u32>) {
    let fixture = Fixture::start().await;
    let output = Output {
        bytes: Arc::new(Mutex::new(Vec::new())),
        ready: Arc::new(Notify::new()),
    };
    let policy = fixture.policy(if mode == "timeout" { 80 } else { 2000 });
    let input = SuppliedSessionOAuthAuthorization::new(&policy, output.clone()).unwrap();
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let sender = if budget == Some(0) || mode == "timeout" {
        None
    } else {
        let output = output.clone();
        let callback = fixture.callback.clone();
        let issuer = fixture.issuer.clone();
        let challenge = Arc::clone(&fixture.challenge);
        let mode = mode.to_owned();
        Some(tokio::spawn(async move {
            output.ready.notified().await;
            if mode == "cancel" {
                cancel.cancel();
                return;
            }
            let value = String::from_utf8(output.bytes.lock().unwrap().clone()).unwrap();
            let authorization = Url::parse(value.trim_end()).unwrap();
            let params: std::collections::BTreeMap<_, _> =
                authorization.query_pairs().into_owned().collect();
            assert_eq!(params.len(), 8);
            assert_eq!(params["response_mode"], "form_post");
            assert_eq!(params["code_challenge_method"], "S256");
            assert!(!params.contains_key("code_verifier"));
            *challenge.lock().unwrap() = Some(params["code_challenge"].clone());
            let body = {
                let mut form = url::form_urlencoded::Serializer::new(String::new());
                form.append_pair("code", CODE)
                    .append_pair(
                        "state",
                        if mode == "wrong-state" {
                            "unrelated-state"
                        } else {
                            &params["state"]
                        },
                    )
                    .append_pair(
                        "iss",
                        if mode == "wrong-issuer" {
                            "http://127.0.0.1:1/foreign"
                        } else {
                            issuer.as_str()
                        },
                    );
                form.finish()
            };
            let mut stream = TcpStream::connect(("127.0.0.1", callback.port().unwrap()))
                .await
                .unwrap();
            let request = format!("POST /termivar/oauth/callback HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",callback.port().unwrap(),body.len());
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, REPLY);
        }))
    };
    let limits = match budget {
        Some(limit) => WebAssessmentLimits::default()
            .with_max_total_requests(limit)
            .unwrap(),
        None => WebAssessmentLimits::default(),
    };
    let mut runtime = WebAssessmentRuntimeBuilder::new(fixture.app.clone())
        .limits(limits)
        .cancellation_token(cancellation)
        .with_supplied_session_review(
            policy,
            SuppliedSessionRuntimeInput::OAuthAuthorization(Box::new(input)),
        )
        .build()
        .unwrap();
    let report = tokio::time::timeout(Duration::from_secs(5), runtime.analyze())
        .await
        .unwrap();
    if let Some(sender) = sender {
        sender.await.unwrap();
    }
    let audit = report
        .as_ref()
        .map(|r| r.supplied_session_audit().unwrap())
        .unwrap_or_else(|_| panic!("normal synthetic runtime should retain typed audit"));
    assert_eq!(audit.schema(), "security.supplied-session-audit/v7");
    assert!(audit.oauth_code().is_none());
    let auth = audit.oauth_authorization().unwrap();
    let exchange = audit.oauth_token_exchange().unwrap();
    assert!(auth.is_consistent());
    assert!(exchange.is_consistent());
    if mode == "positive" {
        assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::Complete);
        assert_eq!(auth.callback_commit_count(), 1);
        assert_eq!(exchange.credential_commit_count(), 1);
        assert_eq!(audit.dispatched_request_count(), 4);
        assert_eq!(audit.committed_resource_count(), 1);
        assert_eq!(auth.accepted_connection_count(), 1);
        assert_eq!(
            fixture
                .trace
                .lock()
                .unwrap()
                .iter()
                .filter(|(path, _)| path != "/")
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>(),
            ["token", "/app/health", "/app/private", "/app/health"]
        );
    } else if mode == "budget-one" {
        assert_eq!(auth.callback_commit_count(), 1);
        assert_eq!(exchange.request_admitted_count(), 0);
        assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::RuntimeLimit);
        assert!(fixture.trace.lock().unwrap().is_empty());
    } else {
        assert_eq!(auth.callback_commit_count(), 0);
        assert_eq!(exchange.request_admitted_count(), 0);
        assert_eq!(audit.committed_resource_count(), 0);
        assert!(fixture.trace.lock().unwrap().iter().all(|(p, _)| p == "/"));
    }
    let serialized = serde_json::to_string(audit).unwrap();
    for secret in [
        TOKEN,
        CODE,
        "code_verifier=",
        "state=",
        "http://127.0.0.1",
        "operator_declared_external_transaction",
    ] {
        assert!(
            !serialized.contains(secret),
            "private protocol material entered audit"
        );
    }
    let usage = report.as_ref().unwrap().usage();
    assert_eq!(
        usage.total_requests() as usize,
        fixture.trace.lock().unwrap().len() + usize::from(auth.reservation_count())
    );
    assert!(
        TcpStream::connect(("127.0.0.1", fixture.callback.port().unwrap()))
            .await
            .is_err(),
        "listener must be gone before report projection"
    );
    #[cfg(feature = "reporting")]
    if mode != "cancel" && budget.is_none() {
        let handoff = String::from_utf8(output.bytes.lock().unwrap().clone()).unwrap();
        let handoff = Url::parse(handoff.trim_end()).unwrap();
        let state = handoff
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let product = crate::ReportGenerator::compose_assessment(
            report.unwrap(),
            crate::web_runtime::ScanProfileV1::web_review().unwrap(),
        )
        .expect("normal V7 runtime must pass the central typed composition seam");
        for format in [
            crate::ReportFormat::Json,
            crate::ReportFormat::Html,
            crate::ReportFormat::Markdown,
            crate::ReportFormat::Csv,
        ] {
            let text = crate::ReportGenerator::generate_assessment(&product,format)
                .expect("normal V7 positive and selected-empty audits must render without weakening readers");
            for (class, value) in [("access", TOKEN), ("code", CODE), ("state", state.as_str())] {
                assert!(
                    !text.contains(value),
                    "private {class} value entered rendered {format:?}"
                );
                assert!(
                    !text.contains(&format!("{:x}", Sha256::digest(value.as_bytes()))),
                    "private {class} unkeyed digest entered rendered {format:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn normal_runtime_initiated_callback_commits_before_one_token_exchange() {
    execute_case("positive", None).await;
}
#[tokio::test]
async fn normal_runtime_wrong_state_and_issuer_never_redeem_or_send_target_credentials() {
    for mode in ["wrong-state", "wrong-issuer"] {
        execute_case(mode, None).await;
    }
}
#[tokio::test]
async fn normal_runtime_authorization_timeout_and_cancel_have_no_tail_or_reaccept() {
    for mode in ["timeout", "cancel"] {
        execute_case(mode, None).await;
    }
}

#[tokio::test]
async fn normal_runtime_callback_and_exchange_share_the_parent_attempt_allowance() {
    execute_case("budget-zero", Some(0)).await;
    execute_case("budget-one", Some(1)).await;
}
