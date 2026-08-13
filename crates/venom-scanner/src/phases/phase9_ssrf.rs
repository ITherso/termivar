//! # Phase 9: quarantined SSRF out-of-band probing
//!
//! This legacy phase can deliver an explicitly configured out-of-band (OOB)
//! callback URL through already observed query parameters. Delivery uses the
//! scan's shared, exact-origin, bounded HTTP authority. A completed request is
//! recorded as typed probe evidence; it carries no security conclusion.
//!
//! Callback collection is deliberately absent from the legacy contract. Until
//! a host-owned verifier can provide nonce-correlated callback evidence, this
//! phase emits an empty result. No default callback destinations or sensitive
//! target payloads are compiled into this module.

use async_trait::async_trait;
use url::Url;
use uuid::Uuid;
use venom_core::{
    ConfidenceScore, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate,
};

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    http_evidence::HttpProbeMethod,
};

const SSRF_PROBE_ACTION_ID: &str = "legacy.probe.ssrf-oob";
const SSRF_PROBE_PREDICATE_NAMESPACE: &str = "legacy.ssrf";
const SSRF_PROBE_PREDICATE_NAME: &str = "oob-probe-response-status";
const MAX_CALLBACK_DOMAIN_BYTES: usize = 253;
const MAX_SSRF_DELIVERY_REQUESTS: usize = 16;

/// Legacy SSRF probe configuration.
///
/// Without an OOB domain the phase is inert. Configuring a domain authorizes
/// only bounded delivery of a nonce-bearing callback URL to the exact scan
/// origin. It does not install a callback verifier or draw a security
/// conclusion.
pub struct SsrfScanner {
    oob_domain: Option<String>,
}

impl std::fmt::Debug for SsrfScanner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsrfScanner")
            .field("oob_domain_configured", &self.oob_domain.is_some())
            .finish()
    }
}

impl SsrfScanner {
    /// Creates an inert SSRF phase with no probe destination.
    pub const fn new() -> Self {
        Self { oob_domain: None }
    }

    /// Retains the pre-1.0 configuration shape for an opt-in OOB domain.
    ///
    /// The domain is validated before any request is dispatched. A bare DNS
    /// domain is required; URLs, IP literals, single-label names, and local or
    /// internal suffixes fail closed during execution.
    pub fn with_oob_domain(oob_domain: String) -> Self {
        Self {
            oob_domain: Some(oob_domain),
        }
    }
}

impl Default for SsrfScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for SsrfScanner {
    fn phase_number(&self) -> u8 {
        9
    }

    fn name(&self) -> &'static str {
        "SSRF Callback Probe Recorder"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        let Some(raw_domain) = self.oob_domain.as_deref() else {
            ctx.log("Phase 9: SSRF OOB probing skipped; no callback domain configured".to_owned());
            return Ok(Vec::new());
        };
        let callback_domain = validate_callback_domain(raw_domain)?;
        ctx.log(
            "Phase 9: bounded SSRF OOB probe delivery initiated; callback verification unavailable"
                .to_owned(),
        );

        let snapshot = ctx.discovery_snapshot();
        let mut receipts = Vec::new();
        'endpoints: for (endpoint, parameters) in snapshot.endpoints() {
            let endpoint = Url::parse(endpoint)?;
            for parameter in parameters {
                if receipts.len() >= MAX_SSRF_DELIVERY_REQUESTS {
                    break 'endpoints;
                }
                let nonce = Uuid::new_v4().simple().to_string();
                let callback_url = format!("http://{nonce}.{callback_domain}/");
                let probe_url = replace_query_parameter(&endpoint, parameter, &callback_url);
                let response = ctx
                    .verification_request(SSRF_PROBE_ACTION_ID, HttpProbeMethod::Get, probe_url)
                    .await?;

                receipts.push((nonce, response.status()));
            }
        }

        ctx.ensure_legacy_verification_commit(SSRF_PROBE_ACTION_ID)?;
        let evidence = receipts
            .iter()
            .map(|(nonce, status)| probe_receipt(ctx, nonce, *status))
            .collect::<Result<Vec<_>, _>>()?;
        ctx.knowledge()
            .insert_evidence_batch(evidence)
            .map_err(|_| receipt_error())?;

        ctx.log(format!(
            "Phase 9: SSRF OOB probing completed with {} probe receipts and an empty result",
            receipts.len()
        ));
        Ok(Vec::new())
    }
}

fn validate_callback_domain(raw: &str) -> Result<String, ScannerError> {
    if raw.is_empty()
        || raw.len() > MAX_CALLBACK_DOMAIN_BYTES
        || raw.trim() != raw
        || !raw.is_ascii()
        || raw.ends_with('.')
    {
        return Err(invalid_callback_domain());
    }

    let normalized = raw.to_ascii_lowercase();
    let labels = normalized.split('.').collect::<Vec<_>>();
    let forbidden_suffix = normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.ends_with(".local")
        || normalized.ends_with(".internal");
    let labels_valid = labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if forbidden_suffix || !labels_valid || normalized.parse::<std::net::IpAddr>().is_ok() {
        return Err(invalid_callback_domain());
    }
    Ok(normalized)
}

fn invalid_callback_domain() -> ScannerError {
    ScannerError::PayloadGenerationError(
        "SSRF OOB callback configuration is not an eligible DNS domain".to_owned(),
    )
}

fn replace_query_parameter(endpoint: &Url, name: &str, value: &str) -> Url {
    let retained = endpoint
        .query_pairs()
        .filter(|(existing, _)| existing != name)
        .map(|(existing, value)| (existing.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut mutated = endpoint.clone();
    mutated.set_query(None);
    mutated
        .query_pairs_mut()
        .extend_pairs(retained)
        .append_pair(name, value);
    mutated
}

fn probe_receipt(ctx: &ScanContext, nonce: &str, status: u16) -> Result<Evidence, ScannerError> {
    let subject = ctx.legacy_verification_subject()?;
    let predicate =
        KnowledgePredicate::new(SSRF_PROBE_PREDICATE_NAMESPACE, SSRF_PROBE_PREDICATE_NAME)
            .map_err(|_| receipt_error())?;
    let source = EvidenceSource::new(SSRF_PROBE_ACTION_ID, "bounded-oob-probe")
        .and_then(|source| source.with_correlation_id(nonce))
        .map_err(|_| receipt_error())?;
    let evidence_id = EvidenceId::parse(format!("evidence:legacy.ssrf.probe-receipt:{nonce}"))
        .map_err(|_| receipt_error())?;
    Ok(Evidence::with_id_at(
        evidence_id,
        subject,
        EvidenceKind::Http,
        predicate,
        EvidenceValue::Unsigned(u64::from(status)),
        source,
        ConfidenceScore::MAX,
        0,
    ))
}

fn receipt_error() -> ScannerError {
    ScannerError::PayloadGenerationError(
        "failed to record a typed SSRF OOB probe receipt".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;
    use crate::legacy_discovery::VerificationLimits;

    struct LocalFixture {
        target: Url,
        requests: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_fixture(status: u16, max_requests: usize) -> LocalFixture {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for _ in 0..max_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1_024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                observed.lock().unwrap().push(request);
                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    _ => "Response",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        LocalFixture {
            target: Url::parse(&format!("http://{address}/fetch?url=seed")).unwrap(),
            requests,
            task,
        }
    }

    fn context(target: Url, max_requests: u32) -> ScanContext {
        let (telemetry, _) = tokio::sync::mpsc::unbounded_channel();
        let limits = VerificationLimits::new()
            .with_max_requests(max_requests)
            .unwrap()
            .with_request_timeout(Duration::from_secs(2))
            .unwrap();
        ScanContext::new_with_verification_limits(target, reqwest::Client::new(), telemetry, limits)
    }

    fn probe_receipts(ctx: &ScanContext) -> Vec<Evidence> {
        let predicate =
            KnowledgePredicate::new(SSRF_PROBE_PREDICATE_NAMESPACE, SSRF_PROBE_PREDICATE_NAME)
                .unwrap();
        ctx.knowledge().evidence_for_predicate(&predicate)
    }

    #[test]
    fn stable_phase_identity_is_preserved() {
        let scanner = SsrfScanner::new();
        assert_eq!(scanner.phase_number(), 9);
        assert_eq!(scanner.name(), "SSRF Callback Probe Recorder");
    }

    #[test]
    fn default_profile_has_no_probe_destination() {
        assert!(SsrfScanner::default().oob_domain.is_none());
    }

    #[test]
    fn callback_domain_validation_is_fail_closed() {
        for invalid in [
            "",
            "localhost",
            "callback.local",
            "callback.internal",
            "192.0.2.1",
            "http://callback.example",
            "callback.example/path",
            " callback.example",
            "callback.example.",
            "-callback.example",
        ] {
            assert!(
                validate_callback_domain(invalid).is_err(),
                "unsafe callback domain was accepted: {invalid}"
            );
        }
        assert_eq!(
            validate_callback_domain("OOB.Example").unwrap(),
            "oob.example"
        );
    }

    #[test]
    fn debug_output_redacts_callback_domain() {
        let scanner = SsrfScanner::with_oob_domain("tenant.callbacks.invalid".to_owned());
        let debug = format!("{scanner:?}");

        assert!(debug.contains("oob_domain_configured: true"));
        assert!(!debug.contains("tenant"));
        assert!(!debug.contains("callbacks.invalid"));
    }

    #[test]
    fn query_mutation_replaces_only_the_selected_parameter() {
        let endpoint =
            Url::parse("https://example.test/fetch?mode=safe&url=old&url=older").unwrap();
        let mutated = replace_query_parameter(&endpoint, "url", "http://nonce.oob.example/");
        assert_eq!(
            mutated.as_str(),
            "https://example.test/fetch?mode=safe&url=http%3A%2F%2Fnonce.oob.example%2F"
        );
    }

    #[tokio::test]
    async fn no_configuration_dispatches_nothing() {
        let fixture = serve_fixture(200, 1).await;
        let ctx = context(fixture.target.clone(), 1);

        let findings = SsrfScanner::new().execute(&ctx).await.unwrap();

        assert!(findings.is_empty());
        assert!(probe_receipts(&ctx).is_empty());
        assert!(fixture.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn successful_delivery_is_typed_probe_evidence_with_an_empty_result() {
        let fixture = serve_fixture(200, 1).await;
        let ctx = context(fixture.target.clone(), 1);

        let findings = SsrfScanner::with_oob_domain("callbacks.invalid".to_owned())
            .execute(&ctx)
            .await
            .unwrap();

        assert!(findings.is_empty());
        let receipts = probe_receipts(&ctx);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].value(), &EvidenceValue::Unsigned(200));
        let nonce = receipts[0].source().correlation_id().unwrap();
        assert_eq!(nonce.len(), 32);
        assert_eq!(receipts[0].observed_at_ms(), 0);
        assert_eq!(
            receipts[0].subject(),
            &ctx.legacy_verification_subject().unwrap()
        );
        assert_eq!(
            receipts[0].id().as_str(),
            format!("evidence:legacy.ssrf.probe-receipt:{nonce}")
        );
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("callbacks.invalid"));
        assert!(requests[0].contains(nonce));
    }

    #[tokio::test]
    async fn authorization_statuses_never_imply_internal_reachability() {
        for status in [401, 403] {
            let fixture = serve_fixture(status, 1).await;
            let ctx = context(fixture.target.clone(), 1);

            let findings = SsrfScanner::with_oob_domain("callbacks.invalid".to_owned())
                .execute(&ctx)
                .await
                .unwrap();

            assert!(findings.is_empty());
            let receipts = probe_receipts(&ctx);
            assert_eq!(receipts.len(), 1);
            assert_eq!(
                receipts[0].value(),
                &EvidenceValue::Unsigned(u64::from(status))
            );
        }
    }

    #[tokio::test]
    async fn invalid_callback_configuration_fails_before_dispatch() {
        let fixture = serve_fixture(200, 1).await;
        let ctx = context(fixture.target.clone(), 1);

        let error = SsrfScanner::with_oob_domain("192.0.2.1".to_owned())
            .execute(&ctx)
            .await
            .unwrap_err();

        assert!(matches!(error, ScannerError::PayloadGenerationError(_)));
        assert!(fixture.requests.lock().unwrap().is_empty());
        assert!(probe_receipts(&ctx).is_empty());
    }

    #[tokio::test]
    async fn shared_request_budget_denial_creates_no_receipt() {
        let fixture = serve_fixture(200, 1).await;
        let ctx = context(fixture.target.clone(), 0);

        let error = SsrfScanner::with_oob_domain("callbacks.invalid".to_owned())
            .execute(&ctx)
            .await
            .unwrap_err();

        assert!(matches!(error, ScannerError::BudgetExceeded(_)));
        assert!(fixture.requests.lock().unwrap().is_empty());
        assert!(probe_receipts(&ctx).is_empty());
    }
}
