//! # Phase 7: bounded template-arithmetic observations
//!
//! This legacy-only phase uses nonce-scoped, non-destructive arithmetic
//! expressions. It compares an exact expected result with a baseline, a
//! syntactically similar non-evaluating control, and an exact replay. It does
//! not identify a template engine, attempt a sandbox escape, or claim code
//! execution.

use async_trait::async_trait;
use url::Url;
use uuid::Uuid;
use venom_core::{
    ConfidenceScore, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue, Hypothesis,
    KnowledgePredicate, OutcomeStatus, Probability, VerificationStage,
};

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    http_evidence::HttpProbeMethod,
    legacy_discovery::BoundedHttpResponse,
    ActiveVerifier, Expression, KnowledgeLayer, VerificationCase, VerificationReport,
    VerificationRule,
};

const SSTI_ACTION_ID: &str = "legacy.observer.template_arithmetic";
const TEMPLATE_CASE_ID: &str = "case:legacy.template-arithmetic";
const TEMPLATE_HYPOTHESIS_ID: &str = "hypothesis:legacy.template-arithmetic.review";
const MAX_SSTI_REQUESTS: usize = 16;
const REQUESTS_PER_PARAMETER: usize = 3;

/// Legacy template-arithmetic scanner.
#[derive(Debug)]
pub struct SstiScanner;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArithmeticProbe {
    payload: String,
    control: String,
    expected: String,
}

#[async_trait]
impl ScanPhase for SstiScanner {
    fn phase_number(&self) -> u8 {
        7
    }

    fn name(&self) -> &'static str {
        "Template Arithmetic Observer"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 7: bounded template-arithmetic probes initiated...".to_owned());
        let snapshot = ctx.discovery_snapshot();
        let mut findings = Vec::new();
        let mut accepted_signal = false;
        let mut requests = 0_usize;

        'endpoints: for (raw_endpoint, parameters) in snapshot.endpoints() {
            if parameters.is_empty()
                || MAX_SSTI_REQUESTS.saturating_sub(requests) < REQUESTS_PER_PARAMETER + 1
            {
                continue;
            }
            let Ok(endpoint) = Url::parse(raw_endpoint) else {
                continue;
            };
            let baseline = request(ctx, endpoint.clone(), &mut requests).await?;
            if !usable_text_response(&baseline) {
                continue;
            }

            for parameter in parameters {
                if MAX_SSTI_REQUESTS.saturating_sub(requests) < REQUESTS_PER_PARAMETER {
                    break 'endpoints;
                }
                let probe = ArithmeticProbe::randomized();
                let control = request(
                    ctx,
                    replace_parameter(&endpoint, parameter, &probe.control),
                    &mut requests,
                )
                .await?;
                let candidate_url = replace_parameter(&endpoint, parameter, &probe.payload);
                let candidate = request(ctx, candidate_url.clone(), &mut requests).await?;
                let replay = request(ctx, candidate_url, &mut requests).await?;

                if supports_template_arithmetic(&baseline, &control, &candidate, &replay, &probe) {
                    findings.push(arithmetic_observation(self, &endpoint, parameter));
                    accepted_signal = true;
                }
            }
        }

        ctx.ensure_legacy_verification_commit(SSTI_ACTION_ID)?;
        let reports = build_template_review_reports(ctx, accepted_signal)?;
        ctx.record_legacy_verification_reports(reports)?;

        ctx.log(format!(
            "Phase 7: bounded template-arithmetic probes completed with {} review observation(s) across {} request(s).",
            findings.len(), requests
        ));
        Ok(findings)
    }
}

fn build_template_review_reports(
    ctx: &ScanContext,
    accepted_signal: bool,
) -> Result<Vec<VerificationReport>, ScannerError> {
    if !accepted_signal {
        return Ok(Vec::new());
    }
    let subject = ctx.legacy_verification_subject()?;
    let anchor_predicate =
        KnowledgePredicate::new("legacy.verification", "manual-review-audit-anchor")
            .map_err(|_| invalid_verification_report())?;
    let prior = Probability::from_percent(50).map_err(|_| invalid_verification_report())?;
    let hypothesis = Hypothesis::with_id(
        TEMPLATE_HYPOTHESIS_ID,
        subject.clone(),
        anchor_predicate,
        EvidenceValue::Text("template-arithmetic-observation-review".to_owned()),
        prior,
    )
    .map_err(|_| invalid_verification_report())?;
    ctx.knowledge()
        .upsert_hypothesis(hypothesis)
        .map_err(|_| invalid_verification_report())?;
    let baseline = ctx.knowledge().snapshot_for_subject(&subject);

    let evidence = template_review_evidence(&subject)?;
    ctx.knowledge()
        .insert_evidence(evidence)
        .map_err(|_| invalid_verification_report())?;
    let after_probe = ctx.knowledge().snapshot_for_subject(&subject);

    let case = VerificationCase::new(
        TEMPLATE_CASE_ID,
        subject,
        SSTI_ACTION_ID,
        TEMPLATE_HYPOTHESIS_ID,
    )
    .map_err(|_| invalid_verification_report())?
    .without_hypothesis_transition();
    let predicate = KnowledgePredicate::new("legacy.template-arithmetic", "exact-nonce-result")
        .map_err(|_| invalid_verification_report())?;
    let rule = VerificationRule::new(
        "verify:legacy.template-arithmetic.needs-review",
        VerificationStage::Active,
        100,
        Expression::equals(
            KnowledgeLayer::Evidence,
            predicate,
            EvidenceValue::Boolean(true),
        ),
        OutcomeStatus::NeedsReview,
        Probability::from_percent(70).map_err(|_| invalid_verification_report())?,
        "A replayed exact template-arithmetic result requires manual review",
    )
    .map_err(|_| invalid_verification_report())?
    .scoped_to_action(SSTI_ACTION_ID)
    .map_err(|_| invalid_verification_report())?
    .with_case_correlated_evidence()
    .map_err(|_| invalid_verification_report())?;
    let mut verifier = ActiveVerifier::new();
    verifier
        .register(rule)
        .map_err(|_| invalid_verification_report())?;
    let report = verifier
        .verify_snapshots(&case, &baseline, &after_probe)
        .map_err(|_| invalid_verification_report())?;
    Ok(vec![report])
}

fn template_review_evidence(subject: &venom_core::EntityId) -> Result<Evidence, ScannerError> {
    let predicate = KnowledgePredicate::new("legacy.template-arithmetic", "exact-nonce-result")
        .map_err(|_| invalid_verification_report())?;
    let source = EvidenceSource::new(SSTI_ACTION_ID, "exact-arithmetic-review")
        .and_then(|source| source.with_correlation_id(TEMPLATE_CASE_ID))
        .map_err(|_| invalid_verification_report())?;
    let evidence_id = EvidenceId::parse("evidence:legacy.template-arithmetic")
        .map_err(|_| invalid_verification_report())?;
    Ok(Evidence::with_id_at(
        evidence_id,
        subject.clone(),
        EvidenceKind::Content,
        predicate,
        EvidenceValue::Boolean(true),
        source,
        ConfidenceScore::from_percent(70).map_err(|_| invalid_verification_report())?,
        0,
    ))
}

const fn invalid_verification_report() -> ScannerError {
    ScannerError::InvalidLegacyVerificationReport
}

impl ArithmeticProbe {
    fn randomized() -> Self {
        let random = Uuid::new_v4().as_u128();
        let left = 101 + u32::try_from(random & 0x7f).unwrap_or_default();
        let right = 211 + u32::try_from((random >> 16) & 0x7f).unwrap_or_default();
        let nonce = Uuid::new_v4().simple().to_string();
        Self::new(left, right, &nonce)
    }

    fn new(left: u32, right: u32, nonce: &str) -> Self {
        let prefix = format!("venom-ssti-{nonce}-begin-");
        let suffix = format!("-end-{nonce}");
        let expression = format!("{left}*{right}");
        let payload = [prefix.as_str(), "{{", expression.as_str(), "}}", &suffix].concat();
        let control = [prefix.as_str(), "{{", expression.as_str(), "}", &suffix].concat();
        let product = left.saturating_mul(right).to_string();
        let expected = [prefix.as_str(), product.as_str(), suffix.as_str()].concat();
        Self {
            payload,
            control,
            expected,
        }
    }
}

async fn request(
    ctx: &ScanContext,
    url: Url,
    requests: &mut usize,
) -> Result<BoundedHttpResponse, ScannerError> {
    debug_assert!(*requests < MAX_SSTI_REQUESTS);
    *requests += 1;
    ctx.verification_request(SSTI_ACTION_ID, HttpProbeMethod::Get, url)
        .await
}

fn replace_parameter(endpoint: &Url, parameter: &str, value: &str) -> Url {
    let retained = endpoint
        .query_pairs()
        .filter(|(name, _)| name != parameter)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut url = endpoint.clone();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair(parameter, value);
    url
}

fn endpoint_subject(endpoint: &Url) -> String {
    let mut subject = endpoint.clone();
    subject.set_query(None);
    subject.set_fragment(None);
    subject.to_string()
}

fn usable_text_response(response: &BoundedHttpResponse) -> bool {
    (200..300).contains(&response.status())
        && !response.body_truncated()
        && response.content_type().is_some_and(is_textual_content_type)
        && std::str::from_utf8(response.body()).is_ok()
}

fn is_textual_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type.starts_with("text/")
        || matches!(
            media_type.as_str(),
            "application/json"
                | "application/problem+json"
                | "application/xml"
                | "application/xhtml+xml"
        )
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

fn supports_template_arithmetic(
    baseline: &BoundedHttpResponse,
    control: &BoundedHttpResponse,
    candidate: &BoundedHttpResponse,
    replay: &BoundedHttpResponse,
    probe: &ArithmeticProbe,
) -> bool {
    if ![baseline, control, candidate, replay]
        .into_iter()
        .all(usable_text_response)
        || ![control, candidate, replay].into_iter().all(|response| {
            response.status() == baseline.status()
                && response.content_type() == baseline.content_type()
        })
        || candidate.body() != replay.body()
    {
        return false;
    }

    let expected = probe.expected.as_bytes();
    !contains_bytes(baseline.body(), expected)
        && !contains_bytes(control.body(), expected)
        && contains_exactly_once(candidate.body(), expected)
        && contains_exactly_once(replay.body(), expected)
        && !contains_bytes(candidate.body(), probe.payload.as_bytes())
        && !contains_bytes(replay.body(), probe.payload.as_bytes())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_exactly_once(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .filter(|window| *window == needle)
            .take(2)
            .count()
            == 1
}

fn arithmetic_observation(scanner: &SstiScanner, endpoint: &Url, parameter: &str) -> ScanFinding {
    ScanFinding {
        phase: scanner.phase_number(),
        module_name: scanner.name().to_owned(),
        severity: "INFO".to_owned(),
        description: "A nonce-scoped arithmetic expression produced its exact expected result while the baseline and malformed-expression control did not; manual review is required.".to_owned(),
        evidence: format!(
            "endpoint={} parameter={} candidate replay matched; no template-engine attribution or code-execution claim",
            endpoint_subject(endpoint), parameter
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;
    use crate::VerificationLimits;
    use venom_core::HypothesisState;

    struct LocalFixture {
        target: Url,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_fixture(
        max_requests: usize,
        handler: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> LocalFixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = Arc::clone(&requests);
        let handler = Arc::new(handler);
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
                    assert!(request.len() <= 16 * 1_024);
                }
                observed_requests.fetch_add(1, Ordering::SeqCst);
                let target = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap()
                    .to_owned();
                let body = handler(&target);
                let wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(wire.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let mut target = Url::parse(&format!("http://{address}/render")).unwrap();
        target.query_pairs_mut().append_pair("name", "known");
        LocalFixture {
            target,
            requests,
            task,
        }
    }

    fn scan_context(target: Url) -> ScanContext {
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::new_with_verification_limits(
            target,
            reqwest::Client::new(),
            telemetry,
            VerificationLimits::new().with_max_requests(4).unwrap(),
        )
    }

    fn query_value(target: &str, parameter: &str) -> String {
        Url::parse(&format!("http://fixture.test{target}"))
            .unwrap()
            .query_pairs()
            .find_map(|(name, value)| (name == parameter).then(|| value.into_owned()))
            .unwrap_or_default()
    }

    fn evaluate_arithmetic_payload(value: &str) -> String {
        let Some(open) = value.find("{{") else {
            return value.to_owned();
        };
        let Some(relative_close) = value[open + 2..].find("}}") else {
            return value.to_owned();
        };
        let close = open + 2 + relative_close;
        let expression = &value[open + 2..close];
        let Some((left, right)) = expression.split_once('*') else {
            return value.to_owned();
        };
        let (Ok(left), Ok(right)) = (left.parse::<u32>(), right.parse::<u32>()) else {
            return value.to_owned();
        };
        format!("{}{}{}", &value[..open], left * right, &value[close + 2..])
    }

    #[test]
    fn phase_identity_is_stable() {
        let scanner = SstiScanner;
        assert_eq!(scanner.phase_number(), 7);
        assert_eq!(scanner.name(), "Template Arithmetic Observer");
    }

    #[test]
    fn arithmetic_probe_uses_variable_operands_and_exact_nonce_marker() {
        let first = ArithmeticProbe::new(113, 227, "first");
        let second = ArithmeticProbe::new(127, 229, "second");
        assert_eq!(first.expected, "venom-ssti-first-begin-25651-end-first");
        assert_eq!(
            first.payload,
            "venom-ssti-first-begin-{{113*227}}-end-first"
        );
        assert_eq!(first.control, "venom-ssti-first-begin-{{113*227}-end-first");
        assert_ne!(first.expected, second.expected);
        assert!(!first.expected.contains("49"));
    }

    #[test]
    fn common_number_and_raw_reflection_do_not_match_exact_result() {
        let probe = ArithmeticProbe::new(113, 227, "nonce");
        assert!(!contains_bytes(
            b"ordinary page 49",
            probe.expected.as_bytes()
        ));
        assert!(!contains_bytes(
            probe.payload.as_bytes(),
            probe.expected.as_bytes()
        ));
    }

    #[tokio::test]
    async fn common_49_page_produces_no_observation() {
        let fixture = serve_fixture(4, |_| "documentation example: 7 * 7 = 49".to_owned()).await;
        let context = scan_context(fixture.target.clone());

        let findings = SstiScanner.execute(&context).await.unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn inert_payload_reflection_produces_no_observation() {
        let fixture = serve_fixture(4, |target| query_value(target, "name")).await;
        let context = scan_context(fixture.target.clone());

        let findings = SstiScanner.execute(&context).await.unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn exact_replayed_arithmetic_result_is_info_review_observation_only() {
        let fixture = serve_fixture(4, |target| {
            evaluate_arithmetic_payload(&query_value(target, "name"))
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = SstiScanner.execute(&context).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "INFO");
        let public_text = format!("{} {}", findings[0].description, findings[0].evidence);
        assert!(public_text.contains("manual review"));
        assert!(!public_text.to_ascii_lowercase().contains("confirmed"));
        assert!(!public_text.to_ascii_lowercase().contains("vulnerab"));
        assert!(!public_text.contains("{{"));
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn randomized_operands_keep_typed_projection_stable_and_private() {
        let fixture = serve_fixture(8, |target| {
            evaluate_arithmetic_payload(&query_value(target, "name"))
        })
        .await;
        let first_context = scan_context(fixture.target.clone());
        let second_context = scan_context(fixture.target.clone());

        SstiScanner.execute(&first_context).await.unwrap();
        SstiScanner.execute(&second_context).await.unwrap();

        let first = first_context.legacy_verification_outcomes_since(0);
        let second = second_context.legacy_verification_outcomes_since(0);
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].fingerprint(), second[0].fingerprint());
        assert_eq!(first[0].disposition(), OutcomeStatus::NeedsReview);
        assert_eq!(first[0].evidence_ids(), second[0].evidence_ids());
        let verified = first[0].verification_outcome().unwrap();
        assert_eq!(verified.case_id(), TEMPLATE_CASE_ID);
        assert_eq!(verified.stage(), VerificationStage::Active);
        assert_eq!(
            first_context
                .knowledge()
                .hypothesis(TEMPLATE_HYPOTHESIS_ID)
                .unwrap()
                .state(),
            HypothesisState::Proposed
        );
        let encoded = serde_json::to_string(&first[0]).unwrap();
        for secret in ["/render", "name=", "known", "{{", "venom-ssti-"] {
            assert!(!encoded.contains(secret));
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn url_mutation_replaces_only_the_named_parameter() {
        let endpoint = Url::parse("https://example.test/render?name=old&mode=safe").unwrap();
        let mutated = replace_parameter(&endpoint, "name", "a&b");
        assert_eq!(
            mutated.as_str(),
            "https://example.test/render?mode=safe&name=a%26b"
        );
        assert_eq!(endpoint.query(), Some("name=old&mode=safe"));
    }
}
