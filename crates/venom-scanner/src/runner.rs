//! Typed orchestration for the opt-in historical phase scanner.
//!
//! `ScanRunner` polls each legacy phase as a structurally owned future so
//! cancellation, timeout, and panic boundaries are observable. Its public result is a
//! fail-closed [`RunReport`]: raw legacy findings are retained only as
//! zero-confidence informational `unknown` records, while corrected built-in
//! phases may project existing verifier-owned, knowledge-only `NeedsReview`
//! outcomes. Phase-one/custom direct-I/O accounting remains unmetered; elapsed
//! wall time is observed.

use std::{
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;
use futures::FutureExt;
use sha2::{Digest, Sha256};
use venom_core::{
    EntityId, ResourceAccounting, RunAccounting, RunOutcomeRecord, RunReport, RunReportError,
    RunReportInput, RunStatus, RunStepReport, RunStepStatus, RunStopCode, RunStopReason,
    ScanFinding, MAX_RUN_REPORT_STEPS,
};

use crate::{
    context::{legacy_subject_digest, ScanContext},
    contracts::ScanPhase,
    error::ScannerError,
    event_bus::{Event, EventType},
};

const LEGACY_UNKNOWN_RATIONALE: &str =
    "Legacy heuristic output has not passed verifier policy; its disposition is unknown.";
const LEGACY_REDACTED_SUMMARY: &str =
    "Legacy phase evidence is withheld at the typed report boundary.";

/// Orchestrates historical scan phases in deterministic phase-number order.
pub struct ScanRunner {
    phases: Vec<Arc<dyn ScanPhase>>,
}

#[derive(Debug)]
enum PhaseExecution {
    Succeeded(Vec<ScanFinding>),
    Failed,
    Panicked,
    JoinFailed,
    TimedOut,
    Cancelled,
    BudgetExhausted,
}

impl ScanRunner {
    /// Creates a new empty runner.
    pub fn new() -> Self {
        Self { phases: Vec::new() }
    }

    /// Registers a phase and preserves stable phase-number ordering.
    pub fn register_phase(&mut self, phase: Box<dyn ScanPhase>) {
        self.phases.push(Arc::from(phase));
        self.phases
            .sort_by_key(|phase| (phase.phase_number(), phase.name()));
    }

    /// Executes every registered phase and returns a typed, serializable report.
    ///
    /// Errors and timeouts are isolated to their phase and make the report
    /// partial (or failed when no phase succeeds). Host cancellation stops the
    /// active phase future and marks later phases skipped. Dropping this future
    /// also drops the active phase future instead of detaching it.
    pub async fn run_pipeline(&self, context: ScanContext) -> Result<RunReport, RunReportError> {
        if !context.runtime_authority_is_intact() {
            return Err(RunReportError::RunAuthorityMismatch);
        }
        if self.phases.len() > MAX_RUN_REPORT_STEPS {
            return Err(RunReportError::TooMany {
                field: "registered phases",
                actual: self.phases.len(),
                limit: MAX_RUN_REPORT_STEPS,
            });
        }
        if self.phases.windows(2).any(|pair| {
            pair[0].phase_number() == pair[1].phase_number() && pair[0].name() == pair[1].name()
        }) {
            return Err(RunReportError::DuplicateStepIdentity);
        }
        let run_started_at = Utc::now();
        let run_started = Instant::now();
        let context = Arc::new(context);
        let target = redacted_target(context.authorized_target());
        let authorized_origin = authorized_origin(context.authorized_target());
        let subject = subject_for_origin(&authorized_origin)?;
        // Validate every externally derived envelope field before a phase can
        // publish an event, perform I/O, or mutate shared state. The final
        // report construction cannot then discover a target/origin bound error
        // only after those effects occurred.
        let _validated_envelope = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(
                RunStopCode::NoEligibleAction,
                "Run envelope validated before legacy phase execution.",
            )?,
            target.clone(),
            authorized_origin.clone(),
            run_started_at,
            run_started_at,
        )?;
        let mut steps = Vec::with_capacity(self.phases.len());
        let mut outcomes = Vec::new();
        let mut successful_steps = 0_usize;
        let mut failed_steps = 0_usize;
        let mut saw_timeout = false;
        let mut saw_join_failure = false;
        let mut saw_budget_exhaustion = false;
        let mut cancelled = context.runtime_cancel_token().is_cancelled();

        if cancelled {
            append_skipped_steps(
                &mut steps,
                &self.phases,
                "Host cancellation prevented this legacy phase from starting.",
            )?;
        }

        for (index, phase) in self.phases.iter().enumerate() {
            if cancelled {
                break;
            }
            if context.runtime_cancel_token().is_cancelled() {
                append_skipped_steps(
                    &mut steps,
                    &self.phases[index..],
                    "Host cancellation prevented this legacy phase from starting.",
                )?;
                cancelled = true;
                break;
            }

            let phase_number = phase.phase_number();
            let step_ordinal = step_sequence(&steps)?;
            let action_id = phase_action_id(phase_number, phase.name(), step_ordinal);
            let started = Instant::now();
            let verification_checkpoint = context.legacy_verification_checkpoint();
            publish_started(&context, phase_number, &action_id);
            context.log(format!("legacy phase started: {action_id}"));

            let execution = execute_phase(
                Arc::clone(phase),
                Arc::clone(&context),
                Duration::from_secs(context.phase_timeout_secs),
            )
            .await;
            let duration_ms = duration_ms(started.elapsed());

            let (status, rationale) = match execution {
                PhaseExecution::Succeeded(findings) => {
                    successful_steps = successful_steps.saturating_add(1);
                    let verified_outcomes =
                        context.legacy_verification_outcomes_since(verification_checkpoint);
                    let has_verified_outcomes = !verified_outcomes.is_empty();
                    outcomes.extend(verified_outcomes);
                    if !has_verified_outcomes && !findings.is_empty() {
                        outcomes.push(outcome_from_legacy_findings(subject.clone(), &action_id)?);
                    }
                    (RunStepStatus::Succeeded, "Legacy phase returned normally.")
                },
                PhaseExecution::Failed => {
                    context.rollback_legacy_verification_outcomes(verification_checkpoint);
                    failed_steps = failed_steps.saturating_add(1);
                    (
                        RunStepStatus::Failed,
                        "Legacy phase returned an error; no result was accepted.",
                    )
                },
                PhaseExecution::Panicked | PhaseExecution::JoinFailed => {
                    context.rollback_legacy_verification_outcomes(verification_checkpoint);
                    failed_steps = failed_steps.saturating_add(1);
                    saw_join_failure = true;
                    (
                        RunStepStatus::Failed,
                        "Legacy phase execution did not complete normally; no result was accepted.",
                    )
                },
                PhaseExecution::TimedOut => {
                    context.rollback_legacy_verification_outcomes(verification_checkpoint);
                    failed_steps = failed_steps.saturating_add(1);
                    saw_timeout = true;
                    (
                        RunStepStatus::TimedOut,
                        "Legacy phase exceeded its deadline and was stopped.",
                    )
                },
                PhaseExecution::Cancelled => {
                    context.rollback_legacy_verification_outcomes(verification_checkpoint);
                    cancelled = true;
                    (
                        RunStepStatus::Cancelled,
                        "Host cancellation stopped the active legacy phase.",
                    )
                },
                PhaseExecution::BudgetExhausted => {
                    context.rollback_legacy_verification_outcomes(verification_checkpoint);
                    failed_steps = failed_steps.saturating_add(1);
                    saw_budget_exhaustion = true;
                    (
                        RunStepStatus::BudgetExhausted,
                        "A bounded legacy transport resource limit stopped this phase.",
                    )
                },
            };

            steps.push(RunStepReport::new(
                step_ordinal,
                action_id.clone(),
                status,
                duration_ms,
                Some(rationale.to_string()),
            )?);
            publish_finished(&context, phase_number, &action_id, status);
            context.log(format!(
                "legacy phase finished: {action_id} status={}",
                step_status_name(status)
            ));

            if cancelled {
                append_skipped_steps(
                    &mut steps,
                    &self.phases[index + 1..],
                    "Host cancellation prevented this legacy phase from starting.",
                )?;
                break;
            }
            if status == RunStepStatus::BudgetExhausted {
                append_skipped_steps(
                    &mut steps,
                    &self.phases[index + 1..],
                    "Bounded legacy transport budget exhaustion prevented this dependent phase from starting.",
                )?;
                break;
            }
        }

        let (status, stop_code, stop_detail) = if cancelled {
            classify_run(
                self.phases.is_empty(),
                successful_steps,
                failed_steps,
                saw_timeout,
                saw_join_failure,
                saw_budget_exhaustion,
                true,
            )
        } else {
            classify_run(
                self.phases.is_empty(),
                successful_steps,
                failed_steps,
                saw_timeout,
                saw_join_failure,
                saw_budget_exhaustion,
                cancelled,
            )
        };
        let run_completed_at = Utc::now().max(run_started_at);
        let report_input = RunReportInput::new(
            status,
            RunStopReason::new(stop_code, stop_detail)?,
            target,
            authorized_origin,
            run_started_at,
            run_completed_at,
        )?
        .with_accounting(RunAccounting::new(
            ResourceAccounting::unmetered(),
            ResourceAccounting::unmetered(),
            ResourceAccounting::unmetered(),
            ResourceAccounting::observed(duration_ms(run_started.elapsed())),
        ))
        .with_steps(steps)
        .with_outcomes(outcomes);
        RunReport::new(report_input)
    }
}

impl Default for ScanRunner {
    fn default() -> Self {
        Self::new()
    }
}

async fn execute_phase(
    phase: Arc<dyn ScanPhase>,
    context: Arc<ScanContext>,
    phase_timeout: Duration,
) -> PhaseExecution {
    if phase_timeout.is_zero() {
        return PhaseExecution::TimedOut;
    }
    let cancellation = context.runtime_cancel_token();
    let execution = AssertUnwindSafe(phase.execute(&context)).catch_unwind();
    tokio::pin!(execution);

    tokio::select! {
        biased;
        _ = cancellation.cancelled() => PhaseExecution::Cancelled,
        completed = &mut execution => classify_phase_result(completed),
        _ = tokio::time::sleep(phase_timeout) => PhaseExecution::TimedOut,
    }
}

fn classify_phase_result(
    completed: std::thread::Result<crate::Result<Vec<ScanFinding>>>,
) -> PhaseExecution {
    match completed {
        Ok(Ok(findings)) => PhaseExecution::Succeeded(findings),
        Ok(Err(ScannerError::TaskJoinFailed)) => PhaseExecution::JoinFailed,
        Ok(Err(ScannerError::Cancelled)) => PhaseExecution::Cancelled,
        Ok(Err(ScannerError::BudgetExceeded(_))) => PhaseExecution::BudgetExhausted,
        Ok(Err(_)) => PhaseExecution::Failed,
        Err(_) => PhaseExecution::Panicked,
    }
}

/// Collects a structurally owned worker set without accepting partial output.
///
/// Any join failure aborts and drains every remaining worker before returning a
/// constant-detail error. The original [`tokio::task::JoinError`] is intentionally dropped:
/// it can contain a target-controlled panic payload.
#[cfg(test)]
pub(crate) async fn collect_join_set<T: 'static>(
    tasks: &mut tokio::task::JoinSet<T>,
) -> crate::Result<Vec<T>> {
    let mut completed = Vec::with_capacity(tasks.len());
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(value) => completed.push(value),
            Err(_) => {
                tasks.shutdown().await;
                return Err(ScannerError::TaskJoinFailed);
            },
        }
    }
    Ok(completed)
}

fn append_skipped_steps(
    steps: &mut Vec<RunStepReport>,
    phases: &[Arc<dyn ScanPhase>],
    rationale: &str,
) -> Result<(), RunReportError> {
    for phase in phases {
        let ordinal = step_sequence(steps)?;
        steps.push(RunStepReport::new(
            ordinal,
            phase_action_id(phase.phase_number(), phase.name(), ordinal),
            RunStepStatus::Skipped,
            0,
            Some(rationale.to_string()),
        )?);
    }
    Ok(())
}

fn step_sequence(steps: &[RunStepReport]) -> Result<u32, RunReportError> {
    u32::try_from(steps.len() + 1).map_err(|_| RunReportError::TooMany {
        field: "run steps",
        actual: steps.len() + 1,
        limit: u32::MAX as usize,
    })
}

fn classify_run(
    no_phases: bool,
    successful_steps: usize,
    failed_steps: usize,
    saw_timeout: bool,
    saw_join_failure: bool,
    saw_budget_exhaustion: bool,
    cancelled: bool,
) -> (RunStatus, RunStopCode, &'static str) {
    if cancelled {
        return (
            RunStatus::Cancelled,
            RunStopCode::Cancelled,
            "Host cancellation stopped the legacy run.",
        );
    }
    if no_phases {
        return (
            RunStatus::Complete,
            RunStopCode::NoEligibleAction,
            "No legacy phases were registered.",
        );
    }
    if failed_steps == 0 {
        return (
            RunStatus::Complete,
            RunStopCode::Completed,
            "Every registered legacy phase returned normally.",
        );
    }
    if successful_steps > 0 {
        return (
            RunStatus::Partial,
            if saw_join_failure {
                RunStopCode::TaskJoinFailed
            } else if saw_budget_exhaustion {
                RunStopCode::BudgetExhausted
            } else if saw_timeout {
                RunStopCode::StepTimedOut
            } else {
                RunStopCode::StepFailed
            },
            "One or more legacy phases did not complete; successful phase output is partial.",
        );
    }
    if saw_join_failure {
        (
            RunStatus::Failed,
            RunStopCode::TaskJoinFailed,
            "No legacy phase completed successfully; at least one task failed to join.",
        )
    } else if saw_budget_exhaustion {
        (
            RunStatus::Failed,
            RunStopCode::BudgetExhausted,
            "No legacy phase completed successfully; a bounded transport budget was exhausted.",
        )
    } else if saw_timeout {
        (
            RunStatus::Failed,
            RunStopCode::StepTimedOut,
            "No legacy phase completed successfully; at least one phase timed out.",
        )
    } else {
        (
            RunStatus::Failed,
            RunStopCode::StepFailed,
            "No legacy phase completed successfully.",
        )
    }
}

fn outcome_from_legacy_findings(
    subject: EntityId,
    phase_action_id: &str,
) -> Result<RunOutcomeRecord, RunReportError> {
    let action_id = format!("{phase_action_id}.observations");
    RunOutcomeRecord::unresolved(
        subject,
        action_id,
        LEGACY_UNKNOWN_RATIONALE,
        LEGACY_REDACTED_SUMMARY,
    )
}

fn phase_action_id(phase: u8, name: &str, ordinal: u32) -> String {
    format!("{}.step.{ordinal}", stable_action_id("phase", phase, name))
}

fn stable_action_id(kind: &str, phase: u8, value: &str) -> String {
    let mut slug = String::with_capacity(32);
    for character in value.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric()
            || (matches!(character, '-' | '_' | '.') && !slug.is_empty())
        {
            slug.push(character);
        }
        if slug.len() >= 32 {
            break;
        }
    }
    let slug = slug.trim_matches(['-', '_', '.']);
    let slug = if slug.is_empty() { "unnamed" } else { slug };
    let digest = sha256_hex(&[value.as_bytes()]);
    format!("legacy.{kind}.{phase}.{slug}.{}", &digest[..12])
}

fn redacted_target(url: &url::Url) -> String {
    match serialized_authority(url) {
        Some(authority) if url.path() == "/" => format!("{authority}/"),
        Some(authority) => format!("{authority}/[path-redacted]"),
        None => format!("{}:[target-redacted]", url.scheme()),
    }
}

fn authorized_origin(url: &url::Url) -> String {
    serialized_authority(url).unwrap_or_else(|| format!("{}:[origin-unavailable]", url.scheme()))
}

fn serialized_authority(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    let host = if host.starts_with('[') && host.ends_with(']') {
        host.to_string()
    } else if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let port = url
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    Some(format!("{}://{host}{port}", url.scheme()))
}

fn subject_for_origin(origin: &str) -> Result<EntityId, RunReportError> {
    EntityId::new(format!(
        "authorized-origin:sha256:{}",
        legacy_subject_digest(origin)
    ))
    .map_err(|_| RunReportError::Blank { field: "subject" })
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn publish_started(context: &ScanContext, phase: u8, action_id: &str) {
    context.event_bus.publish(
        Event::builder(EventType::PhaseStarted, action_id)
            .data("phase_number", phase.to_string())
            .data("action_id", action_id)
            .build(),
    );
}

fn publish_finished(context: &ScanContext, phase: u8, action_id: &str, status: RunStepStatus) {
    let event_type = if status == RunStepStatus::Succeeded {
        EventType::PhaseCompleted
    } else {
        EventType::PhaseFailed
    };
    context.event_bus.publish(
        Event::builder(event_type, action_id)
            .data("phase_number", phase.to_string())
            .data("action_id", action_id)
            .data("status", step_status_name(status))
            .build(),
    );
}

fn step_status_name(status: RunStepStatus) -> &'static str {
    match status {
        RunStepStatus::Succeeded => "succeeded",
        RunStepStatus::Failed => "failed",
        RunStepStatus::TimedOut => "timed_out",
        RunStepStatus::Cancelled => "cancelled",
        RunStepStatus::Skipped => "skipped",
        RunStepStatus::BudgetExhausted => "budget_exhausted",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;
    use venom_core::{
        ConfidenceScore, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
        Hypothesis, KnowledgePredicate, OutcomeStatus, Probability, ResourceAccountingMode,
        RunStopCode, SecuritySeverity, VerificationStage, MAX_RUN_REPORT_TEXT_BYTES,
    };

    use super::*;
    use crate::{
        rules::{Expression, KnowledgeLayer},
        verification::{ActiveVerifier, VerificationCase, VerificationReport, VerificationRule},
        Result, ScannerError,
    };

    const TYPED_TEST_ACTION_ID: &str = "legacy.observer.template_arithmetic";
    const TYPED_TEST_CASE_ID: &str = "case:legacy.runner-test.review";
    const TYPED_TEST_HYPOTHESIS_ID: &str = "hypothesis:legacy.runner-test.review";

    fn invalid_bridge_error<T>(_error: T) -> ScannerError {
        ScannerError::InvalidLegacyVerificationReport
    }

    fn typed_review_report(context: &ScanContext) -> Result<VerificationReport> {
        let subject = context.legacy_verification_subject()?;
        let predicate = KnowledgePredicate::new("legacy.runner-test", "review-signal")
            .map_err(invalid_bridge_error)?;
        let hypothesis = Hypothesis::with_id(
            TYPED_TEST_HYPOTHESIS_ID,
            subject.clone(),
            KnowledgePredicate::new("legacy.runner-test", "audit-anchor")
                .map_err(invalid_bridge_error)?,
            EvidenceValue::Text("manual-review".to_owned()),
            Probability::from_percent(50).map_err(invalid_bridge_error)?,
        )
        .map_err(invalid_bridge_error)?;
        context
            .knowledge()
            .upsert_hypothesis(hypothesis)
            .map_err(invalid_bridge_error)?;
        let baseline = context.knowledge().snapshot_for_subject(&subject);

        let source = EvidenceSource::new(TYPED_TEST_ACTION_ID, "bounded-review-observation")
            .and_then(|source| source.with_correlation_id(TYPED_TEST_CASE_ID))
            .map_err(invalid_bridge_error)?;
        let evidence = Evidence::with_id_at(
            EvidenceId::parse("evidence:legacy.runner-test.review")
                .map_err(invalid_bridge_error)?,
            subject.clone(),
            EvidenceKind::Content,
            predicate.clone(),
            EvidenceValue::Boolean(true),
            source,
            ConfidenceScore::from_percent(70).map_err(invalid_bridge_error)?,
            0,
        );
        context
            .knowledge()
            .insert_evidence(evidence)
            .map_err(invalid_bridge_error)?;
        let after_probe = context.knowledge().snapshot_for_subject(&subject);

        let case = VerificationCase::new(
            TYPED_TEST_CASE_ID,
            subject,
            TYPED_TEST_ACTION_ID,
            TYPED_TEST_HYPOTHESIS_ID,
        )
        .map_err(invalid_bridge_error)?
        .without_hypothesis_transition();
        let rule = VerificationRule::new(
            "verify:legacy.runner-test.needs-review",
            VerificationStage::Active,
            100,
            Expression::equals(
                KnowledgeLayer::Evidence,
                predicate,
                EvidenceValue::Boolean(true),
            ),
            OutcomeStatus::NeedsReview,
            Probability::from_percent(70).map_err(invalid_bridge_error)?,
            "Bounded observation requires review",
        )
        .map_err(invalid_bridge_error)?
        .scoped_to_action(TYPED_TEST_ACTION_ID)
        .map_err(invalid_bridge_error)?
        .with_case_correlated_evidence()
        .map_err(invalid_bridge_error)?;
        let mut verifier = ActiveVerifier::new();
        verifier.register(rule).map_err(invalid_bridge_error)?;
        verifier
            .verify_snapshots(&case, &baseline, &after_probe)
            .map_err(invalid_bridge_error)
    }

    fn context(timeout_secs: u64, cancellation: CancellationToken) -> ScanContext {
        context_for_target(
            url::Url::parse(
                "https://user:secret@example.test/path-secret-3d83a1?q=secret#fragment",
            )
            .unwrap(),
            timeout_secs,
            cancellation,
        )
    }

    fn context_for_target(
        target: url::Url,
        timeout_secs: u64,
        cancellation: CancellationToken,
    ) -> ScanContext {
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::with_cancellation(
            target,
            reqwest::Client::new(),
            telemetry,
            timeout_secs,
            cancellation,
        )
    }

    fn raw_finding(
        phase: u8,
        module_name: &str,
        severity: &str,
        description: &str,
        evidence: &str,
    ) -> ScanFinding {
        ScanFinding {
            phase,
            module_name: module_name.to_string(),
            severity: severity.to_string(),
            description: description.to_string(),
            evidence: evidence.to_string(),
        }
    }

    async fn report_for_findings(findings: Vec<ScanFinding>) -> RunReport {
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(1, TestBehavior::Findings(findings)));
        runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn public_target_replacement_is_rejected_before_report_or_phase_effects() {
        let authorized = url::Url::parse("https://authorized.example.test/root").unwrap();
        let mut scan_context = context_for_target(authorized, 1, CancellationToken::new());
        scan_context.target = url::Url::parse("https://replacement.example.test/secret").unwrap();
        let executed = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(CountingPhase {
            executed: Arc::clone(&executed),
        }));

        let error = runner.run_pipeline(scan_context).await.unwrap_err();

        assert_eq!(error, RunReportError::RunAuthorityMismatch);
        assert!(!executed.load(Ordering::SeqCst));
    }

    fn outcome_identities(report: &RunReport) -> Vec<(String, String)> {
        report
            .outcomes()
            .iter()
            .map(|record| {
                (
                    record.action_id().to_string(),
                    record.fingerprint().to_string(),
                )
            })
            .collect()
    }

    struct TestPhase {
        number: u8,
        behavior: TestBehavior,
    }

    enum TestBehavior {
        Success,
        Error,
        Budget,
        Panic,
        ChildJoinFailure {
            sibling_entered: Arc<Notify>,
            sibling_dropped: Arc<AtomicBool>,
        },
        Pending {
            entered: Arc<Notify>,
            dropped: Arc<AtomicBool>,
        },
        Findings(Vec<ScanFinding>),
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl ScanPhase for TestPhase {
        fn phase_number(&self) -> u8 {
            self.number
        }

        fn name(&self) -> &'static str {
            "test-phase"
        }

        async fn execute(&self, _context: &ScanContext) -> Result<Vec<ScanFinding>> {
            match &self.behavior {
                TestBehavior::Success => Ok(vec![ScanFinding {
                    phase: self.number,
                    module_name: "custom module".to_string(),
                    severity: "HIGH".to_string(),
                    description: "unverified target-controlled claim".to_string(),
                    evidence: "Authorization: Bearer secret-value".to_string(),
                }]),
                TestBehavior::Error => Err(ScannerError::InvalidTarget),
                TestBehavior::Budget => Err(ScannerError::BudgetExceeded(
                    crate::RuntimeLimitExceeded::new(
                        crate::RuntimeBudgetDimension::TotalRequests,
                        1,
                        2,
                        Some("legacy.discovery.test".to_owned()),
                    ),
                )),
                TestBehavior::Panic => panic!("target-controlled panic detail"),
                TestBehavior::ChildJoinFailure {
                    sibling_entered,
                    sibling_dropped,
                } => {
                    let mut tasks = tokio::task::JoinSet::new();
                    let entered = Arc::clone(sibling_entered);
                    let dropped = Arc::clone(sibling_dropped);
                    tasks.spawn(async move {
                        let _drop_signal = DropSignal(dropped);
                        entered.notify_one();
                        pending::<()>().await;
                    });
                    sibling_entered.notified().await;

                    let aborted = tasks.spawn(pending::<()>());
                    aborted.abort();
                    let _completed = collect_join_set(&mut tasks).await?;
                    Ok(Vec::new())
                },
                TestBehavior::Pending { entered, dropped } => {
                    let _drop_signal = DropSignal(Arc::clone(dropped));
                    entered.notify_one();
                    pending().await
                },
                TestBehavior::Findings(findings) => Ok(findings.clone()),
            }
        }
    }

    fn phase(number: u8, behavior: TestBehavior) -> Box<dyn ScanPhase> {
        Box::new(TestPhase { number, behavior })
    }

    enum TypedBridgeBehavior {
        SuccessWithRawFinding,
        ErrorAfterRecord,
        PanicAfterRecord,
        JoinFailureAfterRecord,
        BudgetAfterRecord,
        DuplicateThenReturnRaw,
        PendingAfterRecord {
            entered: Arc<Notify>,
            dropped: Arc<AtomicBool>,
        },
    }

    struct TypedBridgePhase {
        behavior: TypedBridgeBehavior,
    }

    #[async_trait::async_trait]
    impl ScanPhase for TypedBridgePhase {
        fn phase_number(&self) -> u8 {
            7
        }

        fn name(&self) -> &'static str {
            "typed-bridge-test"
        }

        async fn execute(&self, context: &ScanContext) -> Result<Vec<ScanFinding>> {
            let report = typed_review_report(context)?;
            match &self.behavior {
                TypedBridgeBehavior::SuccessWithRawFinding => {
                    context.record_legacy_verification_reports(vec![report])?;
                    Ok(vec![raw_finding(
                        7,
                        "typed bridge test",
                        "HIGH",
                        "raw claim must not leak beside verifier output",
                        "Authorization: Bearer raw-secret",
                    )])
                },
                TypedBridgeBehavior::ErrorAfterRecord => {
                    context.record_legacy_verification_reports(vec![report])?;
                    Err(ScannerError::InvalidTarget)
                },
                TypedBridgeBehavior::PanicAfterRecord => {
                    context.record_legacy_verification_reports(vec![report])?;
                    panic!("typed bridge panic detail")
                },
                TypedBridgeBehavior::JoinFailureAfterRecord => {
                    context.record_legacy_verification_reports(vec![report])?;
                    Err(ScannerError::TaskJoinFailed)
                },
                TypedBridgeBehavior::BudgetAfterRecord => {
                    context.record_legacy_verification_reports(vec![report])?;
                    Err(ScannerError::BudgetExceeded(
                        crate::RuntimeLimitExceeded::new(
                            crate::RuntimeBudgetDimension::TotalRequests,
                            1,
                            2,
                            Some(TYPED_TEST_ACTION_ID.to_owned()),
                        ),
                    ))
                },
                TypedBridgeBehavior::DuplicateThenReturnRaw => {
                    context.record_legacy_verification_reports(vec![report.clone()])?;
                    context.record_legacy_verification_reports(vec![report])?;
                    Ok(vec![raw_finding(
                        7,
                        "typed bridge duplicate",
                        "HIGH",
                        "duplicate acceptance must not become output",
                        "duplicate raw secret",
                    )])
                },
                TypedBridgeBehavior::PendingAfterRecord { entered, dropped } => {
                    context.record_legacy_verification_reports(vec![report])?;
                    let _drop_signal = DropSignal(Arc::clone(dropped));
                    entered.notify_one();
                    pending().await
                },
            }
        }
    }

    fn typed_phase(behavior: TypedBridgeBehavior) -> Box<dyn ScanPhase> {
        Box::new(TypedBridgePhase { behavior })
    }

    #[tokio::test]
    async fn typed_and_unresolved_outcomes_share_one_origin_subject_identity() {
        let mut runner = ScanRunner::new();
        runner.register_phase(typed_phase(TypedBridgeBehavior::SuccessWithRawFinding));
        runner.register_phase(phase(
            8,
            TestBehavior::Findings(vec![raw_finding(
                8,
                "unresolved observation",
                "INFO",
                "bounded raw observation",
                "withheld",
            )]),
        ));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.outcomes().len(), 2);
        assert!(report
            .outcomes()
            .iter()
            .all(|outcome| outcome.subject() == report.outcomes()[0].subject()));
    }

    struct NamedPhase {
        name: &'static str,
    }

    #[async_trait::async_trait]
    impl ScanPhase for NamedPhase {
        fn phase_number(&self) -> u8 {
            7
        }

        fn name(&self) -> &'static str {
            self.name
        }

        async fn execute(&self, _context: &ScanContext) -> Result<Vec<ScanFinding>> {
            Ok(Vec::new())
        }
    }

    struct CountingPhase {
        executed: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl ScanPhase for CountingPhase {
        fn phase_number(&self) -> u8 {
            1
        }

        fn name(&self) -> &'static str {
            "counting"
        }

        async fn execute(&self, _context: &ScanContext) -> Result<Vec<ScanFinding>> {
            self.executed.store(true, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn excessive_phase_registration_fails_before_any_phase_executes() {
        let executed = Arc::new(AtomicBool::new(false));
        let phase: Arc<dyn ScanPhase> = Arc::new(CountingPhase {
            executed: Arc::clone(&executed),
        });
        let runner = ScanRunner {
            phases: vec![phase; MAX_RUN_REPORT_STEPS + 1],
        };

        let error = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            RunReportError::TooMany {
                field: "registered phases",
                actual: MAX_RUN_REPORT_STEPS + 1,
                limit: MAX_RUN_REPORT_STEPS,
            }
        );
        assert!(!executed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn equal_phase_numbers_use_stable_name_order() {
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(NamedPhase { name: "zeta" }));
        runner.register_phase(Box::new(NamedPhase { name: "alpha" }));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert!(report.steps()[0].action_id().contains("alpha"));
        assert!(report.steps()[1].action_id().contains("zeta"));
    }

    #[tokio::test]
    async fn registration_order_does_not_change_equal_number_steps() {
        async fn action_ids(names: [&'static str; 2]) -> Vec<String> {
            let mut runner = ScanRunner::new();
            for name in names {
                runner.register_phase(Box::new(NamedPhase { name }));
            }
            runner
                .run_pipeline(context(1, CancellationToken::new()))
                .await
                .unwrap()
                .steps()
                .iter()
                .map(|step| step.action_id().to_string())
                .collect()
        }

        assert_eq!(
            action_ids(["alpha", "zeta"]).await,
            action_ids(["zeta", "alpha"]).await
        );
    }

    #[tokio::test]
    async fn duplicate_phase_identity_fails_before_any_phase_executes() {
        let first_executed = Arc::new(AtomicBool::new(false));
        let second_executed = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(CountingPhase {
            executed: Arc::clone(&first_executed),
        }));
        runner.register_phase(Box::new(CountingPhase {
            executed: Arc::clone(&second_executed),
        }));

        let error = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap_err();

        assert_eq!(error, RunReportError::DuplicateStepIdentity);
        assert!(!first_executed.load(Ordering::SeqCst));
        assert!(!second_executed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn success_becomes_unknown_without_fabricated_evidence() {
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(1, TestBehavior::Success));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Complete);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Succeeded);
        assert_eq!(
            report.outcomes()[0].disposition(),
            venom_core::OutcomeStatus::Unknown
        );
        assert_eq!(report.outcomes()[0].severity(), SecuritySeverity::Info);
        assert_eq!(report.outcomes()[0].confidence(), Probability::ZERO);
        assert!(report.outcomes()[0].evidence_ids().is_empty());
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("secret-value"));
        assert!(!json.contains("unverified target-controlled claim"));
        assert!(!json.contains("user:secret"));
        assert!(!json.contains("path-secret-3d83a1"));
        assert!(!json.contains("q=secret"));
        assert!(!json.contains("fragment"));
        assert!(json.contains("unmetered"));
        assert_eq!(
            report.accounting().requests().mode(),
            ResourceAccountingMode::Unmetered
        );
        assert_eq!(
            report.accounting().wall_time_ms().mode(),
            ResourceAccountingMode::Observed
        );
    }

    #[tokio::test]
    async fn verifier_owned_needs_review_suppresses_raw_unknown_projection() {
        let mut runner = ScanRunner::new();
        runner.register_phase(typed_phase(TypedBridgeBehavior::SuccessWithRawFinding));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Complete);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Succeeded);
        assert_eq!(report.outcomes().len(), 1);
        let outcome = &report.outcomes()[0];
        assert_eq!(outcome.action_id(), TYPED_TEST_ACTION_ID);
        assert_eq!(outcome.disposition(), OutcomeStatus::NeedsReview);
        assert_eq!(outcome.severity(), SecuritySeverity::Info);
        assert_eq!(outcome.evidence_ids().len(), 1);
        assert_eq!(
            outcome.verification_outcome().unwrap().stage(),
            VerificationStage::Active
        );
        let wire = serde_json::to_string(&report).unwrap();
        assert!(!wire.contains("raw claim must not leak"));
        assert!(!wire.contains("raw-secret"));
        assert!(!report
            .outcomes()
            .iter()
            .any(|outcome| outcome.disposition() == OutcomeStatus::Unknown));
    }

    #[tokio::test]
    async fn failure_after_verifier_record_rolls_back_the_phase_ledger() {
        let scan_context = context(1, CancellationToken::new());
        let ledger_view = scan_context.clone();
        let mut runner = ScanRunner::new();
        runner.register_phase(typed_phase(TypedBridgeBehavior::ErrorAfterRecord));

        let report = runner.run_pipeline(scan_context).await.unwrap();

        assert_eq!(report.status(), RunStatus::Failed);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Failed);
        assert!(report.outcomes().is_empty());
        assert_eq!(ledger_view.legacy_verification_checkpoint(), 0);
    }

    #[tokio::test]
    async fn every_terminal_failure_after_verifier_record_rolls_back_the_phase_ledger() {
        for (behavior, expected_step, expected_stop) in [
            (
                TypedBridgeBehavior::PanicAfterRecord,
                RunStepStatus::Failed,
                RunStopCode::TaskJoinFailed,
            ),
            (
                TypedBridgeBehavior::JoinFailureAfterRecord,
                RunStepStatus::Failed,
                RunStopCode::TaskJoinFailed,
            ),
            (
                TypedBridgeBehavior::BudgetAfterRecord,
                RunStepStatus::BudgetExhausted,
                RunStopCode::BudgetExhausted,
            ),
        ] {
            let scan_context = context(1, CancellationToken::new());
            let ledger_view = scan_context.clone();
            let mut runner = ScanRunner::new();
            runner.register_phase(typed_phase(behavior));

            let report = runner.run_pipeline(scan_context).await.unwrap();

            assert_eq!(report.steps()[0].status(), expected_step);
            assert_eq!(report.stop_reason().code(), expected_stop);
            assert!(report.outcomes().is_empty());
            assert_eq!(ledger_view.legacy_verification_checkpoint(), 0);
        }
    }

    #[tokio::test]
    async fn timeout_after_verifier_record_rolls_back_the_phase_ledger() {
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let scan_context = context(1, CancellationToken::new());
        let ledger_view = scan_context.clone();
        let mut runner = ScanRunner::new();
        runner.register_phase(typed_phase(TypedBridgeBehavior::PendingAfterRecord {
            entered: Arc::clone(&entered),
            dropped: Arc::clone(&dropped),
        }));

        let report = runner.run_pipeline(scan_context).await.unwrap();

        assert_eq!(report.steps()[0].status(), RunStepStatus::TimedOut);
        assert_eq!(report.stop_reason().code(), RunStopCode::StepTimedOut);
        assert!(report.outcomes().is_empty());
        assert_eq!(ledger_view.legacy_verification_checkpoint(), 0);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn duplicate_verifier_fingerprint_fails_without_raw_unknown_leakage() {
        let scan_context = context(1, CancellationToken::new());
        let ledger_view = scan_context.clone();
        let mut runner = ScanRunner::new();
        runner.register_phase(typed_phase(TypedBridgeBehavior::DuplicateThenReturnRaw));

        let report = runner.run_pipeline(scan_context).await.unwrap();

        assert_eq!(report.status(), RunStatus::Failed);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Failed);
        assert!(report.outcomes().is_empty());
        assert_eq!(ledger_view.legacy_verification_checkpoint(), 0);
        let wire = serde_json::to_string(&report).unwrap();
        assert!(!wire.contains("duplicate acceptance"));
        assert!(!wire.contains("duplicate raw secret"));
    }

    #[tokio::test]
    async fn cancellation_after_verifier_record_rolls_back_the_phase_ledger() {
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let cancellation = CancellationToken::new();
        let scan_context = context(60, cancellation.clone());
        let ledger_view = scan_context.clone();
        let mut runner = ScanRunner::new();
        runner.register_phase(typed_phase(TypedBridgeBehavior::PendingAfterRecord {
            entered: Arc::clone(&entered),
            dropped: Arc::clone(&dropped),
        }));
        let task = tokio::spawn(async move { runner.run_pipeline(scan_context).await });

        entered.notified().await;
        assert_eq!(ledger_view.legacy_verification_checkpoint(), 1);
        cancellation.cancel();
        let report = task.await.unwrap().unwrap();

        assert_eq!(report.status(), RunStatus::Cancelled);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Cancelled);
        assert!(report.outcomes().is_empty());
        assert_eq!(ledger_view.legacy_verification_checkpoint(), 0);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn phase_error_is_failed_and_does_not_hide_later_success() {
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(1, TestBehavior::Error));
        runner.register_phase(phase(2, TestBehavior::Success));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Partial);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Failed);
        assert_eq!(report.steps()[1].status(), RunStepStatus::Succeeded);
    }

    #[tokio::test]
    async fn discovery_budget_exhaustion_is_typed_and_stops_dependent_phases() {
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(1, TestBehavior::Success));
        runner.register_phase(phase(2, TestBehavior::Budget));
        runner.register_phase(phase(3, TestBehavior::Success));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Partial);
        assert_eq!(report.stop_reason().code(), RunStopCode::BudgetExhausted);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Succeeded);
        assert_eq!(report.steps()[1].status(), RunStepStatus::BudgetExhausted);
        assert_eq!(report.steps()[2].status(), RunStepStatus::Skipped);
        assert_eq!(
            report.accounting().requests().mode(),
            ResourceAccountingMode::Unmetered,
            "remaining raw legacy phases keep the whole-run accounting contract unmetered"
        );
    }

    #[tokio::test]
    async fn phase_panic_is_a_failed_step_not_empty_success() {
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(1, TestBehavior::Panic));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Failed);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Failed);
        assert_eq!(report.stop_reason().code(), RunStopCode::TaskJoinFailed);
        assert!(report.outcomes().is_empty());
    }

    #[tokio::test]
    async fn child_join_failure_aborts_siblings_and_is_not_empty_success() {
        let sibling_entered = Arc::new(Notify::new());
        let sibling_dropped = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(
            1,
            TestBehavior::ChildJoinFailure {
                sibling_entered,
                sibling_dropped: Arc::clone(&sibling_dropped),
            },
        ));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Failed);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Failed);
        assert_eq!(report.stop_reason().code(), RunStopCode::TaskJoinFailed);
        assert!(report.outcomes().is_empty());
        assert!(sibling_dropped.load(Ordering::SeqCst));
        assert_eq!(
            report.steps()[0].detail(),
            Some("Legacy phase execution did not complete normally; no result was accepted.")
        );
    }

    #[tokio::test]
    async fn timeout_drops_the_owned_phase_future() {
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(
            1,
            TestBehavior::Pending {
                entered,
                dropped: Arc::clone(&dropped),
            },
        ));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Failed);
        assert_eq!(report.steps()[0].status(), RunStepStatus::TimedOut);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn zero_phase_timeout_denies_execution_before_polling() {
        let executed = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(CountingPhase {
            executed: Arc::clone(&executed),
        }));

        let report = runner
            .run_pipeline(context(0, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Failed);
        assert_eq!(report.stop_reason().code(), RunStopCode::StepTimedOut);
        assert_eq!(report.steps()[0].status(), RunStepStatus::TimedOut);
        assert!(!executed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn caller_timeout_drops_run_future_and_aborts_the_phase_task() {
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(
            1,
            TestBehavior::Pending {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            },
        ));

        let result = tokio::time::timeout(
            Duration::from_millis(25),
            runner.run_pipeline(context(60, CancellationToken::new())),
        )
        .await;

        assert!(result.is_err());
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_aborts_active_task_and_skips_remaining_phases() {
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let cancellation = CancellationToken::new();
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(
            1,
            TestBehavior::Pending {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            },
        ));
        runner.register_phase(phase(2, TestBehavior::Success));
        let run_cancellation = cancellation.clone();
        let task =
            tokio::spawn(async move { runner.run_pipeline(context(60, run_cancellation)).await });

        entered.notified().await;
        cancellation.cancel();
        let report = task.await.unwrap().unwrap();

        assert_eq!(report.status(), RunStatus::Cancelled);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Cancelled);
        assert_eq!(report.steps()[1].status(), RunStepStatus::Skipped);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn pre_cancelled_run_marks_every_phase_skipped() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(1, TestBehavior::Success));
        runner.register_phase(phase(2, TestBehavior::Success));

        let report = runner.run_pipeline(context(1, cancellation)).await.unwrap();

        assert_eq!(report.status(), RunStatus::Cancelled);
        assert_eq!(report.stop_reason().code(), RunStopCode::Cancelled);
        assert!(report
            .steps()
            .iter()
            .all(|step| step.status() == RunStepStatus::Skipped));
        assert!(report.outcomes().is_empty());
    }

    #[tokio::test]
    async fn pre_cancelled_empty_run_is_cancelled() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let report = ScanRunner::new()
            .run_pipeline(context(1, cancellation))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Cancelled);
        assert_eq!(report.stop_reason().code(), RunStopCode::Cancelled);
        assert!(report.steps().is_empty());
        assert!(report.outcomes().is_empty());
    }

    #[tokio::test]
    async fn invalid_report_envelope_fails_before_phase_execution() {
        let executed = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(CountingPhase {
            executed: Arc::clone(&executed),
        }));
        let scheme = "a".repeat(MAX_RUN_REPORT_TEXT_BYTES + 1);
        let target = url::Url::parse(&format!("{scheme}:opaque-target")).unwrap();

        let error = runner
            .run_pipeline(context_for_target(target, 1, CancellationToken::new()))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            RunReportError::TextTooLong {
                field: "run target",
                limit: MAX_RUN_REPORT_TEXT_BYTES,
            }
        );
        assert!(!executed.load(Ordering::SeqCst));
    }

    #[test]
    fn target_rendering_redacts_path_and_strips_credentials_query_and_fragment() {
        let raw_path = "/path-secret-b33791";
        let url = url::Url::parse(&format!(
            "https://user:secret@[2001:db8::1]:8443{raw_path}?q=token#fragment"
        ))
        .unwrap();
        let rendered = redacted_target(&url);

        assert_eq!(rendered, "https://[2001:db8::1]:8443/[path-redacted]");
        assert!(!rendered.contains(raw_path));
        assert_eq!(authorized_origin(&url), "https://[2001:db8::1]:8443");
    }

    #[test]
    fn different_non_root_paths_have_the_same_redacted_target() {
        let first = url::Url::parse("https://example.test/first-secret").unwrap();
        let second = url::Url::parse("https://example.test/second-secret/nested").unwrap();

        assert_eq!(redacted_target(&first), redacted_target(&second));
        assert_eq!(
            redacted_target(&first),
            "https://example.test/[path-redacted]"
        );
    }

    #[test]
    fn authority_less_target_contains_no_raw_value_or_digest() {
        let url = url::Url::parse("mailto:raw-recipient-secret@example.test").unwrap();

        assert_eq!(redacted_target(&url), "mailto:[target-redacted]");
    }

    #[test]
    fn authority_less_origins_use_a_constant_without_raw_values() {
        let first = url::Url::parse("mailto:first-origin-secret@example.test").unwrap();
        let second = url::Url::parse("mailto:second-origin-secret@example.test").unwrap();
        let first_origin = authorized_origin(&first);
        let second_origin = authorized_origin(&second);

        assert_eq!(first_origin, "mailto:[origin-unavailable]");
        assert_eq!(first_origin, second_origin);
        assert!(!first_origin.contains("first-origin-secret"));
        assert!(!second_origin.contains("second-origin-secret"));
    }

    #[test]
    fn root_target_path_is_preserved_exactly() {
        let url = url::Url::parse("https://example.test/?q=secret#fragment").unwrap();

        assert_eq!(redacted_target(&url), "https://example.test/");
    }

    #[test]
    fn fingerprints_are_stable_and_domain_framed() {
        assert_eq!(sha256_hex(&[b"ab", b"c"]), sha256_hex(&[b"ab", b"c"]));
        assert_ne!(sha256_hex(&[b"ab", b"c"]), sha256_hex(&[b"a", b"bc"]));
    }

    #[tokio::test]
    async fn equivalent_raw_sets_have_stable_projected_fingerprints() {
        let first = vec![
            raw_finding(1, "untrusted-module", "CRITICAL", "z", "secret-z"),
            raw_finding(1, "untrusted-module", "CRITICAL", "a", "secret-a"),
        ];
        let second = first.iter().rev().cloned().collect();
        let first_report = report_for_findings(first).await;
        let second_report = report_for_findings(second).await;

        assert_eq!(
            outcome_identities(&first_report),
            outcome_identities(&second_report)
        );
        assert_eq!(first_report.outcomes().len(), 1);
        assert!(first_report.outcomes()[0]
            .action_id()
            .ends_with(".observations"));
    }

    #[tokio::test]
    async fn adding_unrelated_raw_finding_does_not_change_phase_aggregate_identity() {
        let first = raw_finding(1, "module", "LOW", "first", "evidence-first");
        let second = raw_finding(1, "module", "LOW", "second", "evidence-second");
        let unrelated = raw_finding(1, "aaa", "INFO", "sorts first", "unrelated");
        let baseline = report_for_findings(vec![first.clone(), second.clone()]).await;
        let expanded = report_for_findings(vec![first, unrelated, second]).await;
        let baseline_identities = outcome_identities(&baseline);
        let expanded_identities = outcome_identities(&expanded);

        assert_eq!(baseline_identities.len(), 1);
        assert_eq!(expanded_identities.len(), 1);
        assert_eq!(baseline_identities, expanded_identities);
    }

    #[tokio::test]
    async fn same_count_different_raw_content_has_the_same_aggregate_identity() {
        let first = report_for_findings(vec![raw_finding(
            1,
            "module",
            "LOW",
            "description",
            "evidence-a",
        )])
        .await;
        let second = report_for_findings(vec![raw_finding(
            1,
            "module",
            "LOW",
            "description",
            "evidence-b",
        )])
        .await;

        assert_eq!(first.outcomes().len(), 1);
        assert_eq!(second.outcomes().len(), 1);
        assert_eq!(outcome_identities(&first), outcome_identities(&second));
    }

    #[tokio::test]
    async fn no_raw_field_contributes_to_public_aggregate_identity() {
        let baseline = raw_finding(1, "module", "LOW", "description", "evidence");
        let variants = [
            raw_finding(2, "module", "LOW", "description", "evidence"),
            raw_finding(1, "other", "LOW", "description", "evidence"),
            raw_finding(1, "module", "HIGH", "description", "evidence"),
            raw_finding(1, "module", "LOW", "other", "evidence"),
            raw_finding(1, "module", "LOW", "description", "other"),
        ];
        let baseline_report = report_for_findings(vec![baseline]).await;
        let baseline_identity = outcome_identities(&baseline_report);

        for variant in variants {
            let variant_report = report_for_findings(vec![variant]).await;
            assert_eq!(variant_report.outcomes().len(), 1);
            assert_eq!(outcome_identities(&variant_report), baseline_identity);
        }
    }

    #[tokio::test]
    async fn identical_raw_findings_collapse_to_one_phase_aggregate() {
        let duplicate = raw_finding(1, "module", "LOW", "duplicate", "same evidence");
        let report = report_for_findings(vec![duplicate.clone(), duplicate]).await;

        assert_eq!(report.outcomes().len(), 1);
    }

    #[tokio::test]
    async fn serialized_projection_does_not_expose_raw_finding_fields() {
        let raw_values = [
            "raw-module-secret-71c65e",
            "raw-severity-secret-6bbd49",
            "raw-description-secret-02a8a1",
            "raw-evidence-secret-30d38d",
        ];
        let report = report_for_findings(vec![raw_finding(
            1,
            raw_values[0],
            raw_values[1],
            raw_values[2],
            raw_values[3],
        )])
        .await;
        let serialized = serde_json::to_string(&report).unwrap();

        assert!(raw_values.iter().all(|value| !serialized.contains(value)));
    }

    #[tokio::test]
    async fn many_raw_findings_still_produce_one_complete_phase_aggregate() {
        let findings = (0..128)
            .map(|index| ScanFinding {
                phase: 1,
                module_name: "untrusted-module".to_string(),
                severity: "HIGH".to_string(),
                description: format!("unresolved-{index}"),
                evidence: "withheld".to_string(),
            })
            .collect();
        let mut runner = ScanRunner::new();
        runner.register_phase(phase(1, TestBehavior::Findings(findings)));

        let report = runner
            .run_pipeline(context(1, CancellationToken::new()))
            .await
            .unwrap();

        assert_eq!(report.status(), RunStatus::Complete);
        assert_eq!(report.stop_reason().code(), RunStopCode::Completed);
        assert_eq!(report.outcomes().len(), 1);
        assert!(report.steps()[0].status() == RunStepStatus::Succeeded);
    }
}
