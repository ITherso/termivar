//! # Phase 5: bounded SQL-behavior observations
//!
//! This legacy-only phase performs conservative differential probes. It does
//! not treat an HTTP 500, a generic error string, or latency by itself as SQL
//! injection confirmation. Any retained signal is an informational
//! observation that requires review outside this phase.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

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

const SQLI_ACTION_ID: &str = "legacy.observer.sql_behavior";
const MAX_SQLI_REQUESTS: usize = 20;
const REQUESTS_PER_PARAMETER: usize = 9;
const TIMING_SAMPLE_PAIRS: usize = 3;
const MIN_MEDIAN_DELAY: Duration = Duration::from_millis(125);
const MIN_PAIRED_DELAY: Duration = Duration::from_millis(100);

/// Legacy SQL-behavior scanner.
#[derive(Debug)]
pub struct SqliScanner;

#[derive(Debug)]
struct TimedResponse {
    response: BoundedHttpResponse,
    elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlErrorFamily {
    SqlState,
    MySql,
    PostgreSql,
    Oracle,
    MicrosoftSqlServer,
    Sqlite,
}

impl SqlErrorFamily {
    const fn label(self) -> &'static str {
        match self {
            Self::SqlState => "SQLSTATE-shaped diagnostic",
            Self::MySql => "MySQL-shaped diagnostic",
            Self::PostgreSql => "PostgreSQL-shaped diagnostic",
            Self::Oracle => "Oracle-shaped diagnostic",
            Self::MicrosoftSqlServer => "SQL Server-shaped diagnostic",
            Self::Sqlite => "SQLite-shaped diagnostic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimingSummary {
    control_median: Duration,
    test_median: Duration,
    control_mad: Duration,
    test_mad: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SqlReviewKind {
    ReproducedDiagnostic,
    TimingDifferential,
}

impl SqlReviewKind {
    const fn slug(self) -> &'static str {
        match self {
            Self::ReproducedDiagnostic => "diagnostic",
            Self::TimingDifferential => "timing",
        }
    }

    const fn predicate_name(self) -> &'static str {
        match self {
            Self::ReproducedDiagnostic => "reproduced-db-diagnostic",
            Self::TimingDifferential => "robust-timing-differential",
        }
    }

    const fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::ReproducedDiagnostic => EvidenceKind::Http,
            Self::TimingDifferential => EvidenceKind::Timing,
        }
    }

    const fn source_method(self) -> &'static str {
        match self {
            Self::ReproducedDiagnostic => "differential-response-review",
            Self::TimingDifferential => "paired-timing-review",
        }
    }

    const fn confidence(self) -> u8 {
        match self {
            Self::ReproducedDiagnostic => 75,
            Self::TimingDifferential => 65,
        }
    }

    const fn rationale(self) -> &'static str {
        match self {
            Self::ReproducedDiagnostic => {
                "A reproduced database diagnostic differential requires manual review"
            },
            Self::TimingDifferential => {
                "A repeated paired timing differential requires manual review"
            },
        }
    }
}

#[async_trait]
impl ScanPhase for SqliScanner {
    fn phase_number(&self) -> u8 {
        5
    }

    fn name(&self) -> &'static str {
        "SQL Behavior Observer"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 5: bounded SQL-behavior probes initiated...".to_owned());
        let snapshot = ctx.discovery_snapshot();
        let mut findings = Vec::new();
        let mut review_signals = BTreeSet::new();
        let mut requests = 0_usize;

        'endpoints: for (raw_endpoint, parameters) in snapshot.endpoints() {
            if parameters.is_empty()
                || MAX_SQLI_REQUESTS.saturating_sub(requests) < REQUESTS_PER_PARAMETER + 1
            {
                continue;
            }
            let Ok(endpoint) = Url::parse(raw_endpoint) else {
                continue;
            };
            let baseline = request(ctx, endpoint.clone(), &mut requests).await?;
            if !usable_text_response(&baseline.response) {
                continue;
            }

            // Documentation pages and generic error templates commonly contain
            // database diagnostics. A pre-existing token invalidates every
            // differential for this endpoint rather than being projected as a
            // target behavior.
            if sql_error_family(baseline.response.body()).is_some() {
                ctx.log(format!(
                    "SQL probes skipped for {} because the baseline already contains a database diagnostic.",
                    endpoint_subject(&endpoint)
                ));
                continue;
            }

            for parameter in parameters {
                if MAX_SQLI_REQUESTS.saturating_sub(requests) < REQUESTS_PER_PARAMETER {
                    break 'endpoints;
                }
                let nonce = Uuid::new_v4().simple().to_string();

                let error_control =
                    replace_parameter(&endpoint, parameter, &format!("venom-sql-control-{nonce}"));
                let error_candidate =
                    replace_parameter(&endpoint, parameter, &format!("'venom-sql-{nonce}"));
                let control = request(ctx, error_control, &mut requests).await?;
                let candidate = request(ctx, error_candidate.clone(), &mut requests).await?;
                let replay = request(ctx, error_candidate, &mut requests).await?;

                if let Some(family) = reproduced_error_differential(
                    &baseline.response,
                    &control.response,
                    &candidate.response,
                    &replay.response,
                ) {
                    findings.push(error_observation(self, &endpoint, parameter, family));
                    review_signals.insert(SqlReviewKind::ReproducedDiagnostic);
                }

                let timing_nonce = Uuid::new_v4().simple().to_string();
                let timing_control = replace_parameter(
                    &endpoint,
                    parameter,
                    &format!("1' AND SL33P(0.25)=0-- {timing_nonce}"),
                );
                let timing_test = replace_parameter(
                    &endpoint,
                    parameter,
                    &format!("1' AND SLEEP(0.25)=0-- {timing_nonce}"),
                );
                let start_test_first = Uuid::new_v4().as_u128() & 1 == 1;
                let mut controls = Vec::with_capacity(TIMING_SAMPLE_PAIRS);
                let mut tests = Vec::with_capacity(TIMING_SAMPLE_PAIRS);
                let mut comparable = true;

                for round in 0..TIMING_SAMPLE_PAIRS {
                    let test_first = start_test_first ^ !round.is_multiple_of(2);
                    let (control_response, test_response) = if test_first {
                        let test = request(ctx, timing_test.clone(), &mut requests).await?;
                        let control = request(ctx, timing_control.clone(), &mut requests).await?;
                        (control, test)
                    } else {
                        let control = request(ctx, timing_control.clone(), &mut requests).await?;
                        let test = request(ctx, timing_test.clone(), &mut requests).await?;
                        (control, test)
                    };
                    comparable &= timing_pair_is_comparable(
                        &baseline.response,
                        &control_response.response,
                        &test_response.response,
                    );
                    controls.push(control_response.elapsed);
                    tests.push(test_response.elapsed);
                }

                if comparable {
                    if let Some(summary) = supported_timing_differential(&controls, &tests) {
                        findings.push(timing_observation(self, &endpoint, parameter, summary));
                        review_signals.insert(SqlReviewKind::TimingDifferential);
                    }
                }
            }
        }

        ctx.ensure_legacy_verification_commit(SQLI_ACTION_ID)?;
        let reports = build_sql_review_reports(ctx, &review_signals)?;
        ctx.record_legacy_verification_reports(reports)?;

        ctx.log(format!(
            "Phase 5: bounded SQL-behavior probes completed with {} review observation(s) across {} request(s).",
            findings.len(), requests
        ));
        Ok(findings)
    }
}

fn build_sql_review_reports(
    ctx: &ScanContext,
    signals: &BTreeSet<SqlReviewKind>,
) -> Result<Vec<VerificationReport>, ScannerError> {
    if signals.is_empty() {
        return Ok(Vec::new());
    }
    let subject = ctx.legacy_verification_subject()?;
    let anchor_predicate =
        KnowledgePredicate::new("legacy.verification", "manual-review-audit-anchor")
            .map_err(|_| invalid_verification_report())?;
    let prior = Probability::from_percent(50).map_err(|_| invalid_verification_report())?;
    let hypotheses = signals
        .iter()
        .map(|kind| {
            Hypothesis::with_id(
                hypothesis_id(*kind),
                subject.clone(),
                anchor_predicate.clone(),
                EvidenceValue::Text(format!("{}-observation-review", kind.slug())),
                prior,
            )
            .map_err(|_| invalid_verification_report())
        })
        .collect::<Result<Vec<_>, _>>()?;
    ctx.knowledge()
        .upsert_hypothesis_batch(hypotheses)
        .map_err(|_| invalid_verification_report())?;
    let baseline = ctx.knowledge().snapshot_for_subject(&subject);

    let evidence = signals
        .iter()
        .map(|kind| sql_review_evidence(&subject, *kind))
        .collect::<Result<Vec<_>, _>>()?;
    ctx.knowledge()
        .insert_evidence_batch(evidence)
        .map_err(|_| invalid_verification_report())?;
    let after_probe = ctx.knowledge().snapshot_for_subject(&subject);

    signals
        .iter()
        .map(|kind| {
            let case = VerificationCase::new(
                case_id(*kind),
                subject.clone(),
                SQLI_ACTION_ID,
                hypothesis_id(*kind),
            )
            .map_err(|_| invalid_verification_report())?
            .without_hypothesis_transition();
            let predicate = KnowledgePredicate::new("legacy.sql-behavior", kind.predicate_name())
                .map_err(|_| invalid_verification_report())?;
            let rule = VerificationRule::new(
                format!("verify:legacy.sql.{}.needs-review", kind.slug()),
                VerificationStage::Active,
                100,
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    predicate,
                    EvidenceValue::Boolean(true),
                ),
                OutcomeStatus::NeedsReview,
                Probability::from_percent(kind.confidence())
                    .map_err(|_| invalid_verification_report())?,
                kind.rationale(),
            )
            .map_err(|_| invalid_verification_report())?
            .scoped_to_action(SQLI_ACTION_ID)
            .map_err(|_| invalid_verification_report())?
            .with_case_correlated_evidence()
            .map_err(|_| invalid_verification_report())?;
            let mut verifier = ActiveVerifier::new();
            verifier
                .register(rule)
                .map_err(|_| invalid_verification_report())?;
            verifier
                .verify_snapshots(&case, &baseline, &after_probe)
                .map_err(|_| invalid_verification_report())
        })
        .collect()
}

fn sql_review_evidence(
    subject: &venom_core::EntityId,
    kind: SqlReviewKind,
) -> Result<Evidence, ScannerError> {
    let case_id = case_id(kind);
    let predicate = KnowledgePredicate::new("legacy.sql-behavior", kind.predicate_name())
        .map_err(|_| invalid_verification_report())?;
    let source = EvidenceSource::new(SQLI_ACTION_ID, kind.source_method())
        .and_then(|source| source.with_correlation_id(case_id))
        .map_err(|_| invalid_verification_report())?;
    let evidence_id = EvidenceId::parse(format!("evidence:legacy.sql.{}", kind.slug()))
        .map_err(|_| invalid_verification_report())?;
    Ok(Evidence::with_id_at(
        evidence_id,
        subject.clone(),
        kind.evidence_kind(),
        predicate,
        EvidenceValue::Boolean(true),
        source,
        ConfidenceScore::from_percent(kind.confidence())
            .map_err(|_| invalid_verification_report())?,
        0,
    ))
}

fn case_id(kind: SqlReviewKind) -> String {
    format!("case:legacy.sql.{}", kind.slug())
}

fn hypothesis_id(kind: SqlReviewKind) -> String {
    format!("hypothesis:legacy.sql.{}.review", kind.slug())
}

const fn invalid_verification_report() -> ScannerError {
    ScannerError::InvalidLegacyVerificationReport
}

async fn request(
    ctx: &ScanContext,
    url: Url,
    requests: &mut usize,
) -> Result<TimedResponse, ScannerError> {
    debug_assert!(*requests < MAX_SQLI_REQUESTS);
    *requests += 1;
    let started = Instant::now();
    let response = ctx
        .verification_request(SQLI_ACTION_ID, HttpProbeMethod::Get, url)
        .await?;
    Ok(TimedResponse {
        response,
        elapsed: started.elapsed(),
    })
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
    !response.body_truncated()
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

fn sql_error_family(body: &[u8]) -> Option<SqlErrorFamily> {
    let body = std::str::from_utf8(body).ok()?.to_ascii_lowercase();
    let patterns = [
        (SqlErrorFamily::SqlState, "sqlstate["),
        (
            SqlErrorFamily::MySql,
            "you have an error in your sql syntax",
        ),
        (SqlErrorFamily::MySql, "warning: mysql_"),
        (SqlErrorFamily::MySql, "mysql_fetch_"),
        (
            SqlErrorFamily::PostgreSql,
            "unterminated quoted string at or near",
        ),
        (SqlErrorFamily::PostgreSql, "warning: pg_query"),
        (SqlErrorFamily::Oracle, "ora-01756"),
        (
            SqlErrorFamily::MicrosoftSqlServer,
            "unclosed quotation mark after the character string",
        ),
        (
            SqlErrorFamily::MicrosoftSqlServer,
            "microsoft ole db provider for sql server",
        ),
        (SqlErrorFamily::Sqlite, "sqlite error"),
        (SqlErrorFamily::Sqlite, "sqlite_exception"),
    ];
    patterns
        .into_iter()
        .find_map(|(family, pattern)| body.contains(pattern).then_some(family))
}

fn reproduced_error_differential(
    baseline: &BoundedHttpResponse,
    control: &BoundedHttpResponse,
    candidate: &BoundedHttpResponse,
    replay: &BoundedHttpResponse,
) -> Option<SqlErrorFamily> {
    if ![baseline, control, candidate, replay]
        .into_iter()
        .all(usable_text_response)
        || sql_error_family(baseline.body()).is_some()
        || sql_error_family(control.body()).is_some()
        || candidate.status() != replay.status()
        || candidate.content_type() != replay.content_type()
    {
        return None;
    }
    let first = sql_error_family(candidate.body())?;
    (sql_error_family(replay.body()) == Some(first)).then_some(first)
}

fn timing_pair_is_comparable(
    baseline: &BoundedHttpResponse,
    control: &BoundedHttpResponse,
    test: &BoundedHttpResponse,
) -> bool {
    [baseline, control, test]
        .into_iter()
        .all(usable_text_response)
        && baseline.status() == control.status()
        && control.status() == test.status()
        && baseline.content_type() == control.content_type()
        && control.content_type() == test.content_type()
        && control.body() == test.body()
}

fn supported_timing_differential(
    controls: &[Duration],
    tests: &[Duration],
) -> Option<TimingSummary> {
    if controls.len() != TIMING_SAMPLE_PAIRS || tests.len() != TIMING_SAMPLE_PAIRS {
        return None;
    }
    let control_median = median(controls)?;
    let test_median = median(tests)?;
    let control_mad = median_absolute_deviation(controls, control_median)?;
    let test_mad = median_absolute_deviation(tests, test_median)?;
    let noise = control_mad.max(test_mad);
    let required_median = MIN_MEDIAN_DELAY.saturating_add(noise.saturating_mul(4));
    let paired_support = controls
        .iter()
        .zip(tests)
        .filter(|(control, test)| test.saturating_sub(**control) >= MIN_PAIRED_DELAY)
        .count();

    (test_median.saturating_sub(control_median) >= required_median && paired_support >= 2)
        .then_some(TimingSummary {
            control_median,
            test_median,
            control_mad,
            test_mad,
        })
}

fn median(samples: &[Duration]) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    let mut samples = samples.to_vec();
    samples.sort_unstable();
    Some(samples[samples.len() / 2])
}

fn median_absolute_deviation(samples: &[Duration], sample_median: Duration) -> Option<Duration> {
    let deviations = samples
        .iter()
        .map(|sample| sample.abs_diff(sample_median))
        .collect::<Vec<_>>();
    median(&deviations)
}

fn error_observation(
    scanner: &SqliScanner,
    endpoint: &Url,
    parameter: &str,
    family: SqlErrorFamily,
) -> ScanFinding {
    ScanFinding {
        phase: scanner.phase_number(),
        module_name: scanner.name().to_owned(),
        severity: "INFO".to_owned(),
        description: format!(
            "A reproduced, parameter-specific {} appeared only after a quote-shaped probe; manual review is required.",
            family.label()
        ),
        evidence: format!(
            "endpoint={} parameter={} baseline/control negative; candidate replay matched; this does not establish SQL injection",
            endpoint_subject(endpoint), parameter
        ),
    }
}

fn timing_observation(
    scanner: &SqliScanner,
    endpoint: &Url,
    parameter: &str,
    summary: TimingSummary,
) -> ScanFinding {
    ScanFinding {
        phase: scanner.phase_number(),
        module_name: scanner.name().to_owned(),
        severity: "INFO".to_owned(),
        description: "Repeated control/test probes produced a robust timing differential; manual review is required.".to_owned(),
        evidence: format!(
            "endpoint={} parameter={} samples={} control_median_ms={} test_median_ms={} control_mad_ms={} test_mad_ms={}; timing alone does not establish SQL injection",
            endpoint_subject(endpoint),
            parameter,
            TIMING_SAMPLE_PAIRS,
            summary.control_median.as_millis(),
            summary.test_median.as_millis(),
            summary.control_mad.as_millis(),
            summary.test_mad.as_millis()
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;
    use crate::VerificationLimits;
    use venom_core::{HypothesisState, RunStepStatus, SecuritySeverity};
    struct FixtureResponse {
        status: u16,
        body: String,
        delay: Duration,
    }

    impl FixtureResponse {
        fn ok(body: impl Into<String>) -> Self {
            Self {
                status: 200,
                body: body.into(),
                delay: Duration::ZERO,
            }
        }
    }

    struct LocalFixture {
        target: Url,
        requests: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_fixture(
        max_requests: usize,
        handler: impl Fn(&str) -> FixtureResponse + Send + Sync + 'static,
    ) -> LocalFixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = Arc::clone(&requests);
        let targets = Arc::new(Mutex::new(Vec::new()));
        let observed_targets = Arc::clone(&targets);
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
                observed_targets
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(target.clone());
                let response = handler(&target);
                tokio::time::sleep(response.delay).await;
                let reason = if response.status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                let wire = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    reason,
                    response.body.len(),
                    response.body
                );
                stream.write_all(wire.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let mut target = Url::parse(&format!("http://{address}/search")).unwrap();
        target.query_pairs_mut().append_pair("q", "known");
        LocalFixture {
            target,
            requests,
            targets,
            task,
        }
    }

    fn scan_context(target: Url) -> ScanContext {
        scan_context_with_requests(target, 10)
    }

    fn scan_context_with_requests(target: Url, max_requests: u32) -> ScanContext {
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::new_with_verification_limits(
            target,
            reqwest::Client::new(),
            telemetry,
            VerificationLimits::new()
                .with_max_requests(max_requests)
                .unwrap(),
        )
    }

    fn query_value(target: &str, parameter: &str) -> String {
        Url::parse(&format!("http://fixture.test{target}"))
            .unwrap()
            .query_pairs()
            .find_map(|(name, value)| (name == parameter).then(|| value.into_owned()))
            .unwrap_or_default()
    }

    #[test]
    fn phase_identity_is_stable() {
        let scanner = SqliScanner;
        assert_eq!(scanner.phase_number(), 5);
        assert_eq!(scanner.name(), "SQL Behavior Observer");
    }

    #[test]
    fn generic_syntax_text_is_not_a_database_signature() {
        assert_eq!(sql_error_family(b"Syntax error"), None);
        assert_eq!(
            sql_error_family(b"SQLSTATE[42000]: malformed query"),
            Some(SqlErrorFamily::SqlState)
        );
    }

    #[test]
    fn robust_timing_requires_repetition_and_rejects_noise() {
        let controls = [
            Duration::from_millis(10),
            Duration::from_millis(11),
            Duration::from_millis(12),
        ];
        let tests = [
            Duration::from_millis(210),
            Duration::from_millis(212),
            Duration::from_millis(211),
        ];
        assert!(supported_timing_differential(&controls, &tests).is_some());
        assert!(supported_timing_differential(&controls[..2], &tests[..2]).is_none());

        let noisy = [
            Duration::from_millis(10),
            Duration::from_millis(250),
            Duration::from_millis(11),
        ];
        assert!(supported_timing_differential(&controls, &noisy).is_none());
    }

    #[test]
    fn typed_signal_identity_is_independent_of_insertion_order() {
        let target = Url::parse("https://example.test/").unwrap();
        let forward_context = scan_context(target.clone());
        let mut forward = BTreeSet::new();
        forward.insert(SqlReviewKind::ReproducedDiagnostic);
        forward.insert(SqlReviewKind::TimingDifferential);
        let reports = build_sql_review_reports(&forward_context, &forward).unwrap();
        forward_context
            .record_legacy_verification_reports(reports)
            .unwrap();

        let reverse_context = scan_context(target);
        let mut reverse = BTreeSet::new();
        reverse.insert(SqlReviewKind::TimingDifferential);
        reverse.insert(SqlReviewKind::ReproducedDiagnostic);
        let reports = build_sql_review_reports(&reverse_context, &reverse).unwrap();
        reverse_context
            .record_legacy_verification_reports(reports)
            .unwrap();

        let identity = |context: &ScanContext| {
            context
                .legacy_verification_outcomes_since(0)
                .into_iter()
                .map(|record| {
                    (
                        record.action_id().to_owned(),
                        record.fingerprint().to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(identity(&forward_context), identity(&reverse_context));
        assert_eq!(identity(&forward_context).len(), 2);
    }

    #[tokio::test]
    async fn single_500_and_generic_syntax_produce_no_observation() {
        let fixture = serve_fixture(10, |target| {
            let value = query_value(target, "q");
            if value.starts_with("'venom-sql-") {
                FixtureResponse {
                    status: 500,
                    body: "Syntax error".to_owned(),
                    delay: Duration::ZERO,
                }
            } else {
                FixtureResponse::ok("ordinary page")
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = SqliScanner.execute(&context).await.unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn baseline_database_text_suppresses_every_probe_for_the_endpoint() {
        let fixture = serve_fixture(1, |_| {
            FixtureResponse::ok("Troubleshooting example: SQLSTATE[42000]")
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = SqliScanner.execute(&context).await.unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reproduced_specific_error_is_info_review_observation_only() {
        let fixture = serve_fixture(10, |target| {
            let value = query_value(target, "q");
            if value.starts_with("'venom-sql-") {
                FixtureResponse {
                    status: 500,
                    body: "SQLSTATE[42000]: quoted input rejected".to_owned(),
                    delay: Duration::ZERO,
                }
            } else {
                FixtureResponse::ok("ordinary page")
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = SqliScanner.execute(&context).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "INFO");
        let public_text = format!("{} {}", findings[0].description, findings[0].evidence);
        assert!(public_text.contains("manual review"));
        assert!(!public_text.to_ascii_lowercase().contains("confirmed"));
        assert!(!public_text.to_ascii_lowercase().contains("vulnerab"));
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn repeated_timing_differential_is_never_confirmation() {
        let fixture = serve_fixture(10, |target| {
            let value = query_value(target, "q");
            let delay = if value.contains("SLEEP(0.25)") {
                Duration::from_millis(220)
            } else {
                Duration::ZERO
            };
            FixtureResponse {
                status: 200,
                body: "ordinary page".to_owned(),
                delay,
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = SqliScanner.execute(&context).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "INFO");
        let public_text = format!("{} {}", findings[0].description, findings[0].evidence);
        assert!(public_text.contains("manual review"));
        assert!(!public_text.to_ascii_lowercase().contains("confirmed"));
        assert!(!public_text.to_ascii_lowercase().contains("vulnerab"));
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 10);

        let targets = fixture
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timing_kinds = targets[4..]
            .iter()
            .map(|target| query_value(target, "q").contains("SLEEP(0.25)"))
            .collect::<Vec<_>>();
        assert_ne!(timing_kinds[0], timing_kinds[1]);
        assert_ne!(timing_kinds[2], timing_kinds[3]);
        assert_ne!(timing_kinds[4], timing_kinds[5]);
        assert_ne!(timing_kinds[0], timing_kinds[2]);
        assert_eq!(timing_kinds[0], timing_kinds[4]);
    }

    #[tokio::test]
    async fn timing_projects_deterministic_needs_review_through_runner() {
        let fixture = serve_fixture(30, |target| {
            let value = query_value(target, "q");
            let delay = if value.contains("SLEEP(0.25)") {
                Duration::from_millis(220)
            } else {
                Duration::ZERO
            };
            FixtureResponse {
                status: 200,
                body: "ordinary page".to_owned(),
                delay,
            }
        })
        .await;

        let direct = SqliScanner
            .execute(&scan_context(fixture.target.clone()))
            .await
            .unwrap();
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].severity, "INFO");

        let mut runner = crate::ScanRunner::new();
        runner.register_phase(Box::new(SqliScanner));
        let first_context = scan_context(fixture.target.clone());
        let first_knowledge = first_context.clone();
        let first = runner.run_pipeline(first_context).await.unwrap();
        let second = runner
            .run_pipeline(scan_context(fixture.target.clone()))
            .await
            .unwrap();
        assert_eq!(first.outcomes().len(), 1);
        assert_eq!(second.outcomes().len(), 1);
        let first_review = first
            .outcomes()
            .iter()
            .find(|record| record.disposition() == OutcomeStatus::NeedsReview)
            .unwrap();
        let second_review = second
            .outcomes()
            .iter()
            .find(|record| record.disposition() == OutcomeStatus::NeedsReview)
            .unwrap();

        assert_eq!(first_review.severity(), SecuritySeverity::Info);
        assert_eq!(first_review.fingerprint(), second_review.fingerprint());
        assert_eq!(first_review.evidence_ids(), second_review.evidence_ids());
        assert_eq!(first_review.evidence_ids().len(), 1);
        let verified = first_review.verification_outcome().unwrap();
        assert_eq!(verified.status(), OutcomeStatus::NeedsReview);
        assert_eq!(verified.stage(), VerificationStage::Active);
        assert_eq!(verified.case_id(), "case:legacy.sql.timing");
        assert!(verified.verifier_rule_id().is_some());
        assert_eq!(verified.evidence_ids(), first_review.evidence_ids());
        assert_eq!(
            first_knowledge
                .knowledge()
                .hypothesis("hypothesis:legacy.sql.timing.review")
                .unwrap()
                .state(),
            HypothesisState::Proposed
        );

        let encoded = serde_json::to_string(first_review).unwrap();
        for secret in ["/search", "q=", "known", "SLEEP", "venom-sql-"] {
            assert!(!encoded.contains(secret));
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 30);
    }

    #[tokio::test]
    async fn budget_exhaustion_projects_no_typed_outcome() {
        let fixture = serve_fixture(5, |_| FixtureResponse::ok("ordinary page")).await;
        let context = scan_context_with_requests(fixture.target.clone(), 5);
        let retained = context.clone();
        let mut runner = crate::ScanRunner::new();
        runner.register_phase(Box::new(SqliScanner));

        let report = runner.run_pipeline(context).await.unwrap();

        assert!(report.outcomes().is_empty());
        assert_eq!(report.steps()[0].status(), RunStepStatus::BudgetExhausted);
        assert!(retained.legacy_verification_outcomes_since(0).is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn url_mutation_replaces_only_the_named_parameter() {
        let endpoint = Url::parse("https://example.test/search?q=old&mode=safe").unwrap();
        let mutated = replace_parameter(&endpoint, "q", "a&b");
        assert_eq!(
            mutated.as_str(),
            "https://example.test/search?mode=safe&q=a%26b"
        );
        assert_eq!(endpoint.query(), Some("q=old&mode=safe"));
    }
}
