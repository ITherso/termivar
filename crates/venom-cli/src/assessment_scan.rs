//! Additive CLI projection for explicitly selected deterministic scan profiles.
//!
//! The compatibility path with no profile remains in `decision_scan`. This module
//! owns separate versioned `web-assessment` surfaces used only after a validated
//! `venom.scan-profile/v1` contract is selected. It projects bounded runtime truth
//! into safe counts and deterministic opaque resource references; it never emits
//! response bodies, header values, credentials, cookie values, evidence payloads,
//! private error diagnostics, or `Debug` output.

use std::error::Error;

use serde::Serialize;
use url::Url;
use venom_scanner::web_runtime::{
    BuiltInScanProfile, ScanProfileScope, ScanProfileV1, WebAssessmentCompletion,
    WebAssessmentDefenseAudit, WebAssessmentDefenseBodyCoverage, WebAssessmentDefenseMode,
    WebAssessmentFailureReceipt, WebAssessmentForm, WebAssessmentFormMethod,
    WebAssessmentIncompleteReason, WebAssessmentMethod, WebAssessmentRunReport,
    WebAssessmentRuntime, WebAssessmentSubject, WebAssessmentSubjectOrigin,
    WebAssessmentSubjectReport, WebAssessmentUsage,
};
use venom_scanner::{
    DecisionLoopCommand, DecisionStopReason, ReportFormat, ReportGenerator, RuntimeBudgetDimension,
    RuntimeLimitExceeded, SemanticEntityType, SemanticExtractionResult,
    StandardWebDecisionFailureReceipt, StandardWebDecisionRuntimeError,
    StandardWebDecisionRuntimeTurn, TransportDispatchAudit,
};

use crate::decision_scan::{self, DecisionScanSummary, OutcomeView};

/// Original additive schema retained for the baseline profile contract.
pub(crate) const WEB_ASSESSMENT_SCHEMA_V1: &str = "web-assessment/v1";
/// Diagnostic audit used only when web-review is incomplete or fails after
/// starting. Completed items use the centralized rendered-assessment schema.
pub(crate) const WEB_ASSESSMENT_SCHEMA_V2: &str = "web-assessment/v2";

/// Stable status that the caller applies only after writing the complete document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssessmentScanPostRenderFailure {
    /// The runtime stopped honestly at a bounded, non-exhaustive boundary.
    Incomplete,
    /// A runtime that had already started returned a typed failure receipt.
    Failed,
}

impl AssessmentScanPostRenderFailure {
    /// Stable public message. The underlying private runtime diagnostic is never
    /// copied into stdout or this post-render error.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Incomplete => "profiled assessment did not complete within its authority",
            Self::Failed => "profiled assessment failed after execution started",
        }
    }
}

/// Fully rendered additive output and its post-render process status.
///
/// A caller must write `rendered` before returning `post_render_failure` as a
/// nonzero process result. Pre-start failures are returned directly by
/// [`run_profile_scan`] and produce no instance of this type.
#[derive(Debug)]
pub(crate) struct AssessmentScanExecution {
    rendered: String,
    report_artifact: Option<String>,
    post_render_failure: Option<AssessmentScanPostRenderFailure>,
}

impl AssessmentScanExecution {
    /// Consumes the result without requiring the caller to reach into the DTO.
    pub(crate) fn into_parts(
        self,
    ) -> (
        String,
        Option<String>,
        Option<AssessmentScanPostRenderFailure>,
    ) {
        (
            self.rendered,
            self.report_artifact,
            self.post_render_failure,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AssessmentDisposition {
    Complete,
    Incomplete,
    Failed,
}

impl AssessmentDisposition {
    const fn post_render_failure(self) -> Option<AssessmentScanPostRenderFailure> {
        match self {
            Self::Complete => None,
            Self::Incomplete => Some(AssessmentScanPostRenderFailure::Incomplete),
            Self::Failed => Some(AssessmentScanPostRenderFailure::Failed),
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }
}

#[derive(Serialize)]
struct WebAssessmentDocument {
    schema_version: &'static str,
    target_origin: String,
    disposition: AssessmentDisposition,
    incomplete_reasons: Vec<&'static str>,
    profile_contract: ScanProfileV1,
    assessment: AssessmentBody,
}

#[derive(Serialize)]
#[serde(tag = "scope", content = "report")]
enum AssessmentBody {
    #[serde(rename = "single-resource")]
    SingleResource(Box<SingleResourceReport>),
    #[serde(rename = "exact-origin")]
    ExactOrigin(Box<ExactOriginReport>),
}

#[derive(Serialize)]
struct SingleResourceReport {
    bootstrap_evidence_writes: usize,
    planning_turns: usize,
    verification_outcomes: Vec<VerificationOutcome>,
    conclusive_outcomes: usize,
    inconclusive_outcomes: usize,
    terminal: Option<TerminalRecord>,
    runtime_limit: Option<RuntimeLimitRecord>,
    usage: SingleResourceUsage,
    transport_dispatches: usize,
    experience_records: Option<usize>,
    unavailable_executor_routes: Option<usize>,
    started_failure: bool,
}

#[derive(Serialize)]
struct VerificationOutcome {
    action_id: String,
    status: &'static str,
    conclusive: bool,
}

#[derive(Serialize)]
struct TerminalRecord {
    command: &'static str,
    stop_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct RuntimeLimitRecord {
    dimension: &'static str,
    limit: u64,
    observed: u64,
    action_id: Option<String>,
}

#[derive(Serialize)]
struct SingleResourceUsage {
    total_requests: u64,
    active_verifications: u64,
    response_bytes: u64,
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct ExactOriginReport {
    subjects: Vec<SubjectRecord>,
    forms: Vec<FormRecord>,
    /// Version-2 product projection. Version 1 remains unchanged, and the
    /// separate `decision-scan/v1` compatibility document is never involved.
    assessment_items: AssessmentItemsReport,
    semantics: SemanticSummary,
    defense: DefenseSummary,
    usage: ExactOriginUsage,
    transport: TransportSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_inventory: Option<FailureInventory>,
}

#[derive(Serialize)]
struct SubjectRecord {
    /// Deterministic document-local reference. Raw paths are deliberately absent:
    /// opaque path segments can themselves contain credentials or reset tokens.
    subject_reference: String,
    method: &'static str,
    depth: u16,
    provenance: &'static str,
    query_parameter_names: Vec<String>,
    discovery_evidence_count: usize,
    executed: bool,
    decision: SubjectDecisionSummary,
}

#[derive(Default, Serialize)]
struct SubjectDecisionSummary {
    bootstrap_evidence_writes: usize,
    planning_turns: usize,
    verification_outcomes: usize,
    conclusive_outcomes: usize,
    inconclusive_outcomes: usize,
    unverified_evidence_writes: usize,
    terminal: Option<TerminalRecord>,
    runtime_limit: Option<RuntimeLimitRecord>,
    execution_failure_recorded: bool,
}

#[derive(Serialize)]
struct FormRecord {
    /// Deterministic document-local reference. The typed runtime retains the
    /// canonical document/action relationship; this safe projection does not copy
    /// either path into product output.
    form_reference: String,
    method: &'static str,
    query_parameter_names: Vec<String>,
    control_names: Vec<String>,
    evidence_count: usize,
}

#[derive(Default, Serialize)]
struct SemanticTypeCounts {
    endpoint: usize,
    domain: usize,
    ip_address: usize,
    auth_artifact: usize,
    header: usize,
    technology: usize,
    parameter: usize,
    user_role: usize,
    other: usize,
}

#[derive(Serialize)]
struct SemanticSummary {
    entity_count: usize,
    entity_types: SemanticTypeCounts,
    truncated: bool,
    dropped_entities: usize,
    dropped_attributes: usize,
    dropped_sources: usize,
}

#[derive(Serialize)]
struct DefenseSummary {
    mode: &'static str,
    observation_count: usize,
    metadata_only_observations: usize,
    complete_prefix_observations: usize,
    input_limited_observations: usize,
    challenge_observations: usize,
    rate_limit_observations: usize,
    transition_count: usize,
    candidate_block_transitions: usize,
    newly_rate_limited_transitions: usize,
    shadow_plan_count: usize,
    unchanged_actions: usize,
    deprioritized_actions: usize,
    suppressed_actions: usize,
}

#[derive(Serialize)]
struct ExactOriginUsage {
    retained_subjects: usize,
    executed_subjects: usize,
    retained_forms: usize,
    retained_unique_url_bytes: usize,
    total_requests: u32,
    active_verifications: u16,
    request_body_bytes: u64,
    response_bytes: u64,
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct TransportSummary {
    retained_dispatch_receipts: usize,
    omitted_dispatch_receipts: u64,
}

#[derive(Serialize)]
struct FailureInventory {
    consistent: bool,
    unrepresented_ledger_subjects: usize,
}

#[derive(Serialize)]
#[serde(tag = "projection_status", rename_all = "snake_case")]
enum AssessmentItemsReport {
    Unavailable {
        code: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        committed_passive_observations: Option<usize>,
    },
}

/// Runs an explicitly selected profile and builds the additive output entirely
/// in memory.
///
/// `format_is_json` deliberately avoids coupling this module to the CLI-local
/// `OutputFormat` enum. The absence-of-`--profile` compatibility path must never
/// call this function.
pub(crate) async fn run_profile_scan(
    target: Url,
    profile: ScanProfileV1,
    format_is_json: bool,
    report_format: Option<ReportFormat>,
    report_to_file: bool,
) -> Result<AssessmentScanExecution, Box<dyn Error>> {
    let target_origin = target.origin().ascii_serialization();
    match (profile.profile(), profile.scope()) {
        (BuiltInScanProfile::Baseline, ScanProfileScope::SingleResource) => {
            if report_format.is_some() || report_to_file {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "typed assessment reports require the web-review profile",
                )
                .into());
            }
            let document = run_baseline(target, target_origin, profile).await?;
            render_execution(document, format_is_json)
        },
        (BuiltInScanProfile::WebReview, ScanProfileScope::ExactOrigin) => {
            run_web_review(
                target,
                target_origin,
                profile,
                format_is_json,
                report_format,
                report_to_file,
            )
            .await
        },
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported scan-profile runtime composition",
        )
        .into()),
    }
}

async fn run_baseline(
    target: Url,
    target_origin: String,
    profile: ScanProfileV1,
) -> Result<WebAssessmentDocument, Box<dyn Error>> {
    match decision_scan::run_decision_scan(target).await {
        Ok(summary) => Ok(document_from_baseline_summary(
            target_origin,
            profile,
            &summary,
        )),
        Err(source) => {
            let receipt = source
                .downcast_ref::<StandardWebDecisionRuntimeError>()
                .and_then(StandardWebDecisionRuntimeError::failure_receipt);
            match receipt {
                Some(receipt) => Ok(document_from_baseline_failure(
                    target_origin,
                    profile,
                    receipt,
                )),
                None => Err(source),
            }
        },
    }
}

async fn run_web_review(
    target: Url,
    target_origin: String,
    profile: ScanProfileV1,
    format_is_json: bool,
    report_format: Option<ReportFormat>,
    report_to_file: bool,
) -> Result<AssessmentScanExecution, Box<dyn Error>> {
    let mut builder = WebAssessmentRuntime::builder(target).limits(profile.web_assessment_limits());
    if profile.defense_enforcement_enabled() {
        builder = builder.enable_defense_enforcement();
    }
    if profile.capabilities().low_risk_differential_review() {
        builder = builder.enable_low_risk_differential_review();
    }
    let mut runtime = builder.build()?;
    match runtime.analyze().await {
        Ok(report) if matches!(report.completion(), WebAssessmentCompletion::Complete) => {
            let format = report_format.unwrap_or(if format_is_json {
                ReportFormat::Json
            } else {
                ReportFormat::Markdown
            });
            let product = ReportGenerator::compose_assessment(report, profile)?;
            let rendered = ReportGenerator::generate_assessment(&product, format)?;
            Ok(if report_to_file {
                AssessmentScanExecution {
                    rendered: String::new(),
                    report_artifact: Some(rendered),
                    post_render_failure: None,
                }
            } else {
                AssessmentScanExecution {
                    rendered,
                    report_artifact: None,
                    post_render_failure: None,
                }
            })
        },
        Ok(report) => render_execution(
            document_from_web_review_report(target_origin, profile, &report),
            format_is_json,
        ),
        Err(source) => match source.failure_receipt() {
            Some(receipt) => render_execution(
                document_from_web_review_failure(target_origin, profile, receipt),
                format_is_json,
            ),
            None => Err(Box::new(source)),
        },
    }
}

fn render_execution(
    document: WebAssessmentDocument,
    format_is_json: bool,
) -> Result<AssessmentScanExecution, Box<dyn Error>> {
    let post_render_failure = document.disposition.post_render_failure();
    let mut rendered = if format_is_json {
        serde_json::to_string_pretty(&document)?
    } else {
        render_text(&document)
    };
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(AssessmentScanExecution {
        rendered,
        report_artifact: None,
        post_render_failure,
    })
}

fn document_from_baseline_summary(
    target_origin: String,
    profile: ScanProfileV1,
    summary: &DecisionScanSummary,
) -> WebAssessmentDocument {
    let mut incomplete_reasons = baseline_incomplete_reasons(summary);
    incomplete_reasons.sort_unstable();
    incomplete_reasons.dedup();
    let disposition = if incomplete_reasons.is_empty() {
        AssessmentDisposition::Complete
    } else {
        AssessmentDisposition::Incomplete
    };
    WebAssessmentDocument {
        schema_version: WEB_ASSESSMENT_SCHEMA_V1,
        target_origin,
        disposition,
        incomplete_reasons,
        profile_contract: profile,
        assessment: AssessmentBody::SingleResource(Box::new(SingleResourceReport {
            bootstrap_evidence_writes: summary.bootstrap_writes,
            planning_turns: summary.planning_turns,
            verification_outcomes: summary.outcomes.iter().map(outcome_from_view).collect(),
            conclusive_outcomes: summary.conclusive_outcomes,
            inconclusive_outcomes: summary.inconclusive_outcomes,
            terminal: Some(TerminalRecord {
                command: summary.terminal,
                stop_reason: summary.stop_reason,
            }),
            runtime_limit: summary
                .limit_exceeded
                .as_ref()
                .map(|limit| RuntimeLimitRecord {
                    dimension: limit.dimension,
                    limit: limit.limit,
                    observed: limit.observed,
                    action_id: limit.action_id.clone(),
                }),
            usage: SingleResourceUsage {
                total_requests: summary.total_requests,
                active_verifications: summary.active_verifications,
                response_bytes: summary.response_bytes,
                elapsed_ms: summary.elapsed_ms,
            },
            transport_dispatches: summary.dispatched.len(),
            experience_records: Some(summary.experience_records),
            unavailable_executor_routes: Some(summary.unavailable_routes.len()),
            started_failure: false,
        })),
    }
}

fn document_from_baseline_failure(
    target_origin: String,
    profile: ScanProfileV1,
    receipt: &StandardWebDecisionFailureReceipt,
) -> WebAssessmentDocument {
    let outcomes = outcomes_from_turns(receipt.completed_turns());
    let conclusive_outcomes = outcomes.iter().filter(|outcome| outcome.conclusive).count();
    let planning_turns = receipt
        .completed_turns()
        .iter()
        .filter(|turn| matches!(turn, StandardWebDecisionRuntimeTurn::Planning(_)))
        .count();
    let usage = receipt.usage();
    WebAssessmentDocument {
        schema_version: WEB_ASSESSMENT_SCHEMA_V1,
        target_origin,
        disposition: AssessmentDisposition::Failed,
        incomplete_reasons: vec!["started_runtime_failure"],
        profile_contract: profile,
        assessment: AssessmentBody::SingleResource(Box::new(SingleResourceReport {
            bootstrap_evidence_writes: receipt
                .bootstrap()
                .map_or(0, |bootstrap| bootstrap.writes().len()),
            planning_turns,
            inconclusive_outcomes: outcomes.len().saturating_sub(conclusive_outcomes),
            conclusive_outcomes,
            verification_outcomes: outcomes,
            terminal: None,
            runtime_limit: None,
            usage: SingleResourceUsage {
                total_requests: u64::from(usage.total_requests()),
                active_verifications: u64::from(usage.active_verifications()),
                response_bytes: usage.response_bytes(),
                elapsed_ms: usage.elapsed_ms(),
            },
            transport_dispatches: receipt.transport().receipts().len(),
            experience_records: None,
            unavailable_executor_routes: None,
            started_failure: true,
        })),
    }
}

fn classify_web_review_completion(
    completion: &WebAssessmentCompletion,
) -> (AssessmentDisposition, Vec<&'static str>) {
    let mut reasons = match completion {
        WebAssessmentCompletion::Complete => {
            return (AssessmentDisposition::Complete, Vec::new());
        },
        WebAssessmentCompletion::Incomplete { reasons } => reasons
            .iter()
            .map(incomplete_reason_code)
            .collect::<Vec<_>>(),
        _ => vec!["subject_execution_incomplete"],
    };
    if reasons.is_empty() {
        reasons.push("subject_execution_incomplete");
    }
    reasons.sort_unstable();
    reasons.dedup();
    (AssessmentDisposition::Incomplete, reasons)
}

fn document_from_web_review_report(
    target_origin: String,
    profile: ScanProfileV1,
    report: &WebAssessmentRunReport,
) -> WebAssessmentDocument {
    let (mut disposition, mut incomplete_reasons) =
        classify_web_review_completion(report.completion());
    if disposition == AssessmentDisposition::Complete {
        disposition = AssessmentDisposition::Incomplete;
        incomplete_reasons.push("assessment_item_projection_incomplete");
    }
    WebAssessmentDocument {
        schema_version: WEB_ASSESSMENT_SCHEMA_V2,
        target_origin,
        disposition,
        incomplete_reasons,
        profile_contract: profile,
        assessment: AssessmentBody::ExactOrigin(Box::new(ExactOriginReport {
            subjects: report
                .subjects()
                .iter()
                .enumerate()
                .map(|(index, report)| subject_record(index, report))
                .collect(),
            forms: report
                .forms()
                .iter()
                .enumerate()
                .map(|(index, form)| form_record(index, form))
                .collect(),
            assessment_items: AssessmentItemsReport::Unavailable {
                code: "incomplete_assessment_items_withheld",
                committed_passive_observations: None,
            },
            semantics: semantic_summary(report.semantics()),
            defense: defense_summary(report.defense()),
            usage: exact_origin_usage(report.usage()),
            transport: transport_summary(report.transport()),
            failure_inventory: None,
        })),
    }
}

fn document_from_web_review_failure(
    target_origin: String,
    profile: ScanProfileV1,
    receipt: &WebAssessmentFailureReceipt,
) -> WebAssessmentDocument {
    let mut incomplete_reasons: Vec<_> = receipt
        .incomplete_reasons()
        .iter()
        .map(incomplete_reason_code)
        .collect();
    incomplete_reasons.push("started_runtime_failure");
    incomplete_reasons.sort_unstable();
    incomplete_reasons.dedup();

    let mut subject_reports: Vec<_> = receipt
        .completed_subjects()
        .iter()
        .map(|report| (report.subject(), Some(report)))
        .collect();
    subject_reports.push((
        receipt.current_subject_report().subject(),
        Some(receipt.current_subject_report()),
    ));
    subject_reports.extend(
        receipt
            .pending_subjects()
            .iter()
            .map(|subject| (subject, None)),
    );
    let subjects = subject_reports
        .into_iter()
        .enumerate()
        .map(|(index, (subject, report))| match report {
            Some(report) => subject_record(index, report),
            None => pending_subject_record(index, subject),
        })
        .collect();

    WebAssessmentDocument {
        schema_version: WEB_ASSESSMENT_SCHEMA_V2,
        target_origin,
        disposition: AssessmentDisposition::Failed,
        incomplete_reasons,
        profile_contract: profile,
        assessment: AssessmentBody::ExactOrigin(Box::new(ExactOriginReport {
            subjects,
            forms: receipt
                .forms()
                .iter()
                .enumerate()
                .map(|(index, form)| form_record(index, form))
                .collect(),
            assessment_items: AssessmentItemsReport::Unavailable {
                code: "runtime_failed_before_item_projection",
                committed_passive_observations: Some(receipt.committed_passive_observations()),
            },
            semantics: semantic_summary(receipt.semantics()),
            defense: defense_summary(receipt.defense()),
            usage: exact_origin_usage(receipt.usage()),
            transport: transport_summary(receipt.transport()),
            failure_inventory: Some(FailureInventory {
                consistent: receipt.inventory_consistent(),
                unrepresented_ledger_subjects: receipt.unrepresented_ledger_subjects(),
            }),
        })),
    }
}

fn outcome_from_view(outcome: &OutcomeView) -> VerificationOutcome {
    VerificationOutcome {
        action_id: outcome.action_id.clone(),
        status: outcome.status,
        conclusive: outcome.conclusive,
    }
}

fn outcomes_from_turns(turns: &[StandardWebDecisionRuntimeTurn]) -> Vec<VerificationOutcome> {
    turns
        .iter()
        .filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Outcome { decision, .. } => {
                let verification = decision.verification();
                let status = verification.outcome().status();
                Some(VerificationOutcome {
                    action_id: verification.outcome().action_id().to_owned(),
                    status: outcome_status_code(status),
                    conclusive: verification.case().applies_hypothesis_transition()
                        && status.hypothesis_state().is_some(),
                })
            },
            _ => None,
        })
        .collect()
}

fn subject_record(index: usize, report: &WebAssessmentSubjectReport) -> SubjectRecord {
    let outcomes = outcomes_from_turns(report.turns());
    let conclusive_outcomes = outcomes.iter().filter(|outcome| outcome.conclusive).count();
    let decision = SubjectDecisionSummary {
        bootstrap_evidence_writes: report
            .bootstrap()
            .map_or(0, |bootstrap| bootstrap.writes().len()),
        planning_turns: report
            .turns()
            .iter()
            .filter(|turn| matches!(turn, StandardWebDecisionRuntimeTurn::Planning(_)))
            .count(),
        verification_outcomes: outcomes.len(),
        conclusive_outcomes,
        inconclusive_outcomes: outcomes.len().saturating_sub(conclusive_outcomes),
        unverified_evidence_writes: report
            .unverified_evidence()
            .map_or(0, |evidence| evidence.writes().len()),
        terminal: report.terminal().map(terminal_record),
        runtime_limit: report.limit_exceeded().map(runtime_limit_record),
        execution_failure_recorded: report.execution_failure().is_some(),
    };
    subject_with_decision(index, report.subject(), report.was_executed(), decision)
}

fn pending_subject_record(index: usize, subject: &WebAssessmentSubject) -> SubjectRecord {
    subject_with_decision(index, subject, false, SubjectDecisionSummary::default())
}

fn subject_with_decision(
    index: usize,
    subject: &WebAssessmentSubject,
    executed: bool,
    decision: SubjectDecisionSummary,
) -> SubjectRecord {
    SubjectRecord {
        subject_reference: format!("subject-{index:04}"),
        method: assessment_method_code(subject.method()),
        depth: subject.depth(),
        provenance: subject_origin_code(subject.origin()),
        query_parameter_names: subject.query_parameter_names().to_vec(),
        discovery_evidence_count: subject.evidence_ids().len(),
        executed,
        decision,
    }
}

fn form_record(index: usize, form: &WebAssessmentForm) -> FormRecord {
    FormRecord {
        form_reference: format!("form-{index:04}"),
        method: form_method_code(form.method()),
        query_parameter_names: form.query_parameter_names().to_vec(),
        control_names: form.control_names().to_vec(),
        evidence_count: form.evidence_ids().len(),
    }
}

fn semantic_summary(result: &SemanticExtractionResult) -> SemanticSummary {
    let mut entity_types = SemanticTypeCounts::default();
    for entity in &result.entities {
        match entity.entity_type() {
            SemanticEntityType::Endpoint => entity_types.endpoint += 1,
            SemanticEntityType::Domain => entity_types.domain += 1,
            SemanticEntityType::IpAddress => entity_types.ip_address += 1,
            SemanticEntityType::AuthArtifact => entity_types.auth_artifact += 1,
            SemanticEntityType::Header => entity_types.header += 1,
            SemanticEntityType::Technology => entity_types.technology += 1,
            SemanticEntityType::Parameter => entity_types.parameter += 1,
            SemanticEntityType::UserRole => entity_types.user_role += 1,
            _ => entity_types.other += 1,
        }
    }
    SemanticSummary {
        entity_count: result.entities.len(),
        entity_types,
        truncated: result.truncated,
        dropped_entities: result.dropped_entities,
        dropped_attributes: result.dropped_attributes,
        dropped_sources: result.dropped_sources,
    }
}

fn defense_summary(audit: &WebAssessmentDefenseAudit) -> DefenseSummary {
    let observations = audit.observations();
    let transitions = audit.transitions();
    let shadows = audit.shadow_plans();
    DefenseSummary {
        mode: defense_mode_code(audit.mode()),
        observation_count: observations.len(),
        metadata_only_observations: observations
            .iter()
            .filter(|observation| {
                observation.body_coverage() == WebAssessmentDefenseBodyCoverage::MetadataOnly
            })
            .count(),
        complete_prefix_observations: observations
            .iter()
            .filter(|observation| {
                observation.body_coverage() == WebAssessmentDefenseBodyCoverage::CompleteUtf8Prefix
            })
            .count(),
        input_limited_observations: observations
            .iter()
            .filter(|observation| observation.input_limit_reached())
            .count(),
        challenge_observations: observations
            .iter()
            .filter(|observation| observation.challenge_observed())
            .count(),
        rate_limit_observations: observations
            .iter()
            .filter(|observation| observation.rate_limit_observed())
            .count(),
        transition_count: transitions.len(),
        candidate_block_transitions: transitions
            .iter()
            .filter(|transition| transition.candidate_block_status_appeared())
            .count(),
        newly_rate_limited_transitions: transitions
            .iter()
            .filter(|transition| transition.newly_rate_limited())
            .count(),
        shadow_plan_count: shadows.len(),
        unchanged_actions: shadows
            .iter()
            .map(|shadow| shadow.delta().unchanged().len())
            .sum(),
        deprioritized_actions: shadows
            .iter()
            .map(|shadow| shadow.delta().deprioritized().len())
            .sum(),
        suppressed_actions: shadows
            .iter()
            .map(|shadow| shadow.delta().suppressed().len())
            .sum(),
    }
}

fn exact_origin_usage(usage: WebAssessmentUsage) -> ExactOriginUsage {
    ExactOriginUsage {
        retained_subjects: usage.retained_subjects(),
        executed_subjects: usage.executed_subjects(),
        retained_forms: usage.retained_forms(),
        retained_unique_url_bytes: usage.retained_unique_url_bytes(),
        total_requests: usage.total_requests(),
        active_verifications: usage.active_verifications(),
        request_body_bytes: usage.request_body_bytes(),
        response_bytes: usage.response_bytes(),
        elapsed_ms: usage.elapsed_ms(),
    }
}

fn transport_summary(transport: &TransportDispatchAudit) -> TransportSummary {
    TransportSummary {
        retained_dispatch_receipts: transport.receipts().len(),
        omitted_dispatch_receipts: transport.omitted_receipt_count(),
    }
}

fn terminal_record(command: &DecisionLoopCommand) -> TerminalRecord {
    match command {
        DecisionLoopCommand::ExecuteAction { .. } => TerminalRecord {
            command: "execute_action",
            stop_reason: None,
        },
        DecisionLoopCommand::CollectActiveEvidence { .. } => TerminalRecord {
            command: "collect_active_evidence",
            stop_reason: None,
        },
        DecisionLoopCommand::Replan => TerminalRecord {
            command: "replan",
            stop_reason: None,
        },
        DecisionLoopCommand::Complete { .. } => TerminalRecord {
            command: "complete",
            stop_reason: None,
        },
        DecisionLoopCommand::AwaitHumanReview { .. } => TerminalRecord {
            command: "await_human_review",
            stop_reason: None,
        },
        DecisionLoopCommand::Halt { reason } => TerminalRecord {
            command: "halt",
            stop_reason: Some(stop_reason_code(*reason)),
        },
        _ => TerminalRecord {
            command: "other",
            stop_reason: None,
        },
    }
}

fn runtime_limit_record(limit: &RuntimeLimitExceeded) -> RuntimeLimitRecord {
    RuntimeLimitRecord {
        dimension: runtime_dimension_code(limit.dimension()),
        limit: limit.limit(),
        observed: limit.observed(),
        action_id: limit.action_id().map(str::to_owned),
    }
}

fn baseline_incomplete_reasons(summary: &DecisionScanSummary) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if let Some(limit) = &summary.limit_exceeded {
        reasons.push(match limit.dimension {
            "total_requests" => "total_request_limit",
            "wall_time" => "wall_time_limit",
            "response_bytes" => "response_bytes_limit",
            "request_body_bytes" => "request_body_bytes_limit",
            "active_verifications" => "active_verification_limit",
            "same_action_attempts" => "same_action_attempt_limit",
            "consecutive_no_progress_turns" => "consecutive_no_progress_limit",
            _ => "runtime_budget_limit",
        });
    }
    match (summary.terminal, summary.stop_reason) {
        ("complete", _) | ("halt", Some("objective_complete" | "no_eligible_action")) => {},
        ("await_human_review", _) | ("halt", Some("human_review")) => {
            reasons.push("human_review_required");
        },
        ("halt", Some("adaptation_limit")) => reasons.push("adaptation_limit"),
        ("halt", Some("action_cycle_limit")) => reasons.push("action_cycle_limit"),
        ("halt", Some("cancelled_by_host")) => reasons.push("host_cancellation"),
        ("halt", Some("runtime_budget_limit")) if summary.limit_exceeded.is_none() => {
            reasons.push("runtime_budget_limit");
        },
        _ => reasons.push("subject_execution_incomplete"),
    }
    reasons
}

fn incomplete_reason_code(reason: &WebAssessmentIncompleteReason) -> &'static str {
    match reason {
        WebAssessmentIncompleteReason::SubjectLimit => "subject_limit",
        WebAssessmentIncompleteReason::DiscoveryDepthLimit => "discovery_depth_limit",
        WebAssessmentIncompleteReason::DocumentReferenceLimit => "document_reference_limit",
        WebAssessmentIncompleteReason::CanonicalUrlBytesLimit => "canonical_url_bytes_limit",
        WebAssessmentIncompleteReason::RetainedUrlBytesLimit => "retained_url_bytes_limit",
        WebAssessmentIncompleteReason::FormLimit => "form_limit",
        WebAssessmentIncompleteReason::FormControlLimit => "form_control_limit",
        WebAssessmentIncompleteReason::QueryParameterNameLimit => "query_parameter_name_limit",
        WebAssessmentIncompleteReason::ResponseBodyIncomplete => "response_body_incomplete",
        WebAssessmentIncompleteReason::PartialRepresentation => "partial_representation",
        WebAssessmentIncompleteReason::InvalidUtf8 => "invalid_utf8",
        WebAssessmentIncompleteReason::TotalRequestLimit => "total_request_limit",
        WebAssessmentIncompleteReason::ResponseBytesLimit => "response_bytes_limit",
        WebAssessmentIncompleteReason::RequestBodyBytesLimit => "request_body_bytes_limit",
        WebAssessmentIncompleteReason::WallTimeLimit => "wall_time_limit",
        WebAssessmentIncompleteReason::ActiveVerificationLimit => "active_verification_limit",
        WebAssessmentIncompleteReason::SameActionAttemptLimit => "same_action_attempt_limit",
        WebAssessmentIncompleteReason::ConsecutiveNoProgressLimit => {
            "consecutive_no_progress_limit"
        },
        WebAssessmentIncompleteReason::ActionCycleLimit => "action_cycle_limit",
        WebAssessmentIncompleteReason::AdaptationLimit => "adaptation_limit",
        WebAssessmentIncompleteReason::HumanReviewRequired => "human_review_required",
        WebAssessmentIncompleteReason::SubjectExecutionIncomplete => "subject_execution_incomplete",
        WebAssessmentIncompleteReason::HostCancellation => "host_cancellation",
        WebAssessmentIncompleteReason::SemanticExtractionLimit => "semantic_extraction_limit",
        WebAssessmentIncompleteReason::PassiveResponseProjectionLimit => {
            "passive_response_projection_limit"
        },
        WebAssessmentIncompleteReason::AssessmentSubjectIdentityUnavailable => {
            "assessment_subject_identity_unavailable"
        },
        WebAssessmentIncompleteReason::DifferentialReviewIncomplete => {
            "differential_review_incomplete"
        },
        _ => "other",
    }
}

fn stop_reason_code(reason: DecisionStopReason) -> &'static str {
    match reason {
        DecisionStopReason::ObjectiveComplete => "objective_complete",
        DecisionStopReason::NoEligibleAction => "no_eligible_action",
        DecisionStopReason::HumanReview => "human_review",
        DecisionStopReason::AdaptationLimit => "adaptation_limit",
        DecisionStopReason::ActionCycleLimit => "action_cycle_limit",
        DecisionStopReason::RuntimeBudgetLimit => "runtime_budget_limit",
        DecisionStopReason::CancelledByHost => "cancelled_by_host",
        _ => "other",
    }
}

fn runtime_dimension_code(dimension: RuntimeBudgetDimension) -> &'static str {
    match dimension {
        RuntimeBudgetDimension::TotalRequests => "total_requests",
        RuntimeBudgetDimension::WallTime => "wall_time",
        RuntimeBudgetDimension::ResponseBytes => "response_bytes",
        RuntimeBudgetDimension::RequestBodyBytes => "request_body_bytes",
        RuntimeBudgetDimension::ActiveVerifications => "active_verifications",
        RuntimeBudgetDimension::SameActionAttempts => "same_action_attempts",
        RuntimeBudgetDimension::ConsecutiveNoProgressTurns => "consecutive_no_progress_turns",
        _ => "other",
    }
}

fn outcome_status_code(status: venom_scanner::OutcomeStatus) -> &'static str {
    match status {
        venom_scanner::OutcomeStatus::Success => "success",
        venom_scanner::OutcomeStatus::Blocked => "blocked",
        venom_scanner::OutcomeStatus::Unknown => "unknown",
        venom_scanner::OutcomeStatus::FalsePositive => "false_positive",
        venom_scanner::OutcomeStatus::NeedsReview => "needs_review",
        venom_scanner::OutcomeStatus::ConfirmedNegative => "confirmed_negative",
        _ => "other",
    }
}

fn assessment_method_code(method: WebAssessmentMethod) -> &'static str {
    match method {
        WebAssessmentMethod::Get => "get",
        WebAssessmentMethod::Head => "head",
        _ => "other",
    }
}

fn form_method_code(method: WebAssessmentFormMethod) -> &'static str {
    match method {
        WebAssessmentFormMethod::Get => "get",
        WebAssessmentFormMethod::Post => "post",
        WebAssessmentFormMethod::Dialog => "dialog",
        _ => "other",
    }
}

fn subject_origin_code(origin: WebAssessmentSubjectOrigin) -> &'static str {
    match origin {
        WebAssessmentSubjectOrigin::AuthorizedRoot => "authorized_root",
        WebAssessmentSubjectOrigin::Discovered => "discovered",
        _ => "other",
    }
}

fn defense_mode_code(mode: WebAssessmentDefenseMode) -> &'static str {
    match mode {
        WebAssessmentDefenseMode::ObservationOnly => "observation_only",
        WebAssessmentDefenseMode::Enforced => "enforced",
    }
}

fn render_text(document: &WebAssessmentDocument) -> String {
    let mut lines = vec![
        "== web assessment (deterministic alpha) ==".to_owned(),
        format!("schema: {}", document.schema_version),
        format!("profile contract: {}", document.profile_contract.schema()),
        format!("profile: {}", document.profile_contract.profile().id()),
        format!("scope: {}", document.profile_contract.scope().id()),
        format!("target origin: {}", document.target_origin),
        format!("disposition: {}", document.disposition.code()),
    ];
    if document.incomplete_reasons.is_empty() {
        lines.push("incomplete reasons: none".to_owned());
    } else {
        lines.push(format!(
            "incomplete reasons: {}",
            document.incomplete_reasons.join(",")
        ));
    }
    match &document.assessment {
        AssessmentBody::SingleResource(report) => {
            lines.push("assessment scope: single-resource".to_owned());
            lines.push(format!(
                "evidence: {} bootstrap write(s)",
                report.bootstrap_evidence_writes
            ));
            lines.push(format!("planning: {} turn(s)", report.planning_turns));
            lines.push(format!(
                "verification outcomes: {} (conclusive {}, inconclusive {})",
                report.verification_outcomes.len(),
                report.conclusive_outcomes,
                report.inconclusive_outcomes
            ));
            lines.push(format!(
                "usage: requests={} active_verifications={} response_bytes={} elapsed_ms={}",
                report.usage.total_requests,
                report.usage.active_verifications,
                report.usage.response_bytes,
                report.usage.elapsed_ms
            ));
        },
        AssessmentBody::ExactOrigin(report) => {
            lines.push("assessment scope: exact-origin".to_owned());
            lines.push(format!(
                "inventory: subjects={} executed={} forms={}",
                report.usage.retained_subjects,
                report.usage.executed_subjects,
                report.usage.retained_forms
            ));
            append_assessment_item_lines(&mut lines, &report.assessment_items);
            lines.push(format!(
                "semantics: entities={} truncated={} dropped_entities={} dropped_attributes={} dropped_sources={}",
                report.semantics.entity_count,
                report.semantics.truncated,
                report.semantics.dropped_entities,
                report.semantics.dropped_attributes,
                report.semantics.dropped_sources
            ));
            lines.push(format!(
                "defense: mode={} observations={} transitions={} shadow_plans={} suppressed={} deprioritized={}",
                report.defense.mode,
                report.defense.observation_count,
                report.defense.transition_count,
                report.defense.shadow_plan_count,
                report.defense.suppressed_actions,
                report.defense.deprioritized_actions
            ));
            lines.push(format!(
                "usage: requests={} active_verifications={} response_bytes={} elapsed_ms={}",
                report.usage.total_requests,
                report.usage.active_verifications,
                report.usage.response_bytes,
                report.usage.elapsed_ms
            ));
        },
    }
    lines.join("\n")
}

fn append_assessment_item_lines(lines: &mut Vec<String>, report: &AssessmentItemsReport) {
    let AssessmentItemsReport::Unavailable {
        code,
        committed_passive_observations,
    } = report;
    if let Some(count) = committed_passive_observations {
        lines.push(format!(
            "assessment items: projection_status=unavailable code={code} committed_passive_observations={count}"
        ));
    } else {
        lines.push(format!(
            "assessment items: projection_status=unavailable code={code}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_baseline_document(disposition: AssessmentDisposition) -> WebAssessmentDocument {
        WebAssessmentDocument {
            schema_version: WEB_ASSESSMENT_SCHEMA_V1,
            target_origin: "https://example.test".to_owned(),
            disposition,
            incomplete_reasons: if disposition == AssessmentDisposition::Complete {
                Vec::new()
            } else {
                vec!["started_runtime_failure"]
            },
            profile_contract: ScanProfileV1::baseline().expect("built-in profile is valid"),
            assessment: AssessmentBody::SingleResource(Box::new(SingleResourceReport {
                bootstrap_evidence_writes: 0,
                planning_turns: 0,
                verification_outcomes: Vec::new(),
                conclusive_outcomes: 0,
                inconclusive_outcomes: 0,
                terminal: None,
                runtime_limit: None,
                usage: SingleResourceUsage {
                    total_requests: 0,
                    active_verifications: 0,
                    response_bytes: 0,
                    elapsed_ms: 0,
                },
                transport_dispatches: 0,
                experience_records: None,
                unavailable_executor_routes: None,
                started_failure: disposition == AssessmentDisposition::Failed,
            })),
        }
    }

    #[test]
    fn additive_json_has_distinct_schema_and_typed_profile() {
        let execution = render_execution(
            minimal_baseline_document(AssessmentDisposition::Complete),
            true,
        )
        .expect("safe DTO serializes");
        let value: serde_json::Value =
            serde_json::from_str(&execution.rendered).expect("rendered JSON parses");
        assert_eq!(value["schema_version"], WEB_ASSESSMENT_SCHEMA_V1);
        assert_eq!(
            value["profile_contract"]["schema"],
            venom_scanner::web_runtime::SCAN_PROFILE_V1_SCHEMA
        );
        assert_eq!(value["profile_contract"]["profile"], "baseline");
        assert_eq!(value["assessment"]["scope"], "single-resource");
        assert_eq!(execution.post_render_failure, None);
    }

    #[test]
    fn started_failure_renders_before_requesting_nonzero_exit() {
        let execution = render_execution(
            minimal_baseline_document(AssessmentDisposition::Failed),
            false,
        )
        .expect("text rendering is infallible");
        assert!(execution.rendered.contains("disposition: failed\n"));
        assert!(execution
            .rendered
            .contains("incomplete reasons: started_runtime_failure\n"));
        assert_eq!(
            execution.post_render_failure,
            Some(AssessmentScanPostRenderFailure::Failed)
        );
        assert!(!execution.rendered.contains("private diagnostic"));
    }

    #[test]
    fn typed_incomplete_with_no_reasons_still_fails_closed() {
        let completion = WebAssessmentCompletion::Incomplete {
            reasons: std::collections::BTreeSet::new(),
        };
        let (disposition, reasons) = classify_web_review_completion(&completion);
        assert_eq!(disposition, AssessmentDisposition::Incomplete);
        assert_eq!(reasons, ["subject_execution_incomplete"]);
        assert_eq!(
            disposition.post_render_failure(),
            Some(AssessmentScanPostRenderFailure::Incomplete)
        );
    }

    #[test]
    fn failure_item_projection_is_unavailable_not_empty_success() {
        let unavailable = AssessmentItemsReport::Unavailable {
            code: "runtime_failed_before_item_projection",
            committed_passive_observations: Some(3),
        };
        let value = serde_json::to_value(unavailable).expect("fixed failure receipt serializes");
        assert_eq!(value["projection_status"], "unavailable");
        assert_eq!(value["code"], "runtime_failed_before_item_projection");
        assert_eq!(value["committed_passive_observations"], 3);
        assert!(value.get("items").is_none());
        assert!(value.get("projected_item_count").is_none());
    }

    #[test]
    fn stable_reason_and_status_vocabularies_cover_every_current_runtime_boundary() {
        let incomplete = [
            (WebAssessmentIncompleteReason::SubjectLimit, "subject_limit"),
            (
                WebAssessmentIncompleteReason::DiscoveryDepthLimit,
                "discovery_depth_limit",
            ),
            (
                WebAssessmentIncompleteReason::DocumentReferenceLimit,
                "document_reference_limit",
            ),
            (
                WebAssessmentIncompleteReason::CanonicalUrlBytesLimit,
                "canonical_url_bytes_limit",
            ),
            (
                WebAssessmentIncompleteReason::RetainedUrlBytesLimit,
                "retained_url_bytes_limit",
            ),
            (WebAssessmentIncompleteReason::FormLimit, "form_limit"),
            (
                WebAssessmentIncompleteReason::FormControlLimit,
                "form_control_limit",
            ),
            (
                WebAssessmentIncompleteReason::QueryParameterNameLimit,
                "query_parameter_name_limit",
            ),
            (
                WebAssessmentIncompleteReason::ResponseBodyIncomplete,
                "response_body_incomplete",
            ),
            (
                WebAssessmentIncompleteReason::PartialRepresentation,
                "partial_representation",
            ),
            (WebAssessmentIncompleteReason::InvalidUtf8, "invalid_utf8"),
            (
                WebAssessmentIncompleteReason::TotalRequestLimit,
                "total_request_limit",
            ),
            (
                WebAssessmentIncompleteReason::ResponseBytesLimit,
                "response_bytes_limit",
            ),
            (
                WebAssessmentIncompleteReason::RequestBodyBytesLimit,
                "request_body_bytes_limit",
            ),
            (
                WebAssessmentIncompleteReason::WallTimeLimit,
                "wall_time_limit",
            ),
            (
                WebAssessmentIncompleteReason::ActiveVerificationLimit,
                "active_verification_limit",
            ),
            (
                WebAssessmentIncompleteReason::SameActionAttemptLimit,
                "same_action_attempt_limit",
            ),
            (
                WebAssessmentIncompleteReason::ConsecutiveNoProgressLimit,
                "consecutive_no_progress_limit",
            ),
            (
                WebAssessmentIncompleteReason::ActionCycleLimit,
                "action_cycle_limit",
            ),
            (
                WebAssessmentIncompleteReason::AdaptationLimit,
                "adaptation_limit",
            ),
            (
                WebAssessmentIncompleteReason::HumanReviewRequired,
                "human_review_required",
            ),
            (
                WebAssessmentIncompleteReason::SubjectExecutionIncomplete,
                "subject_execution_incomplete",
            ),
            (
                WebAssessmentIncompleteReason::HostCancellation,
                "host_cancellation",
            ),
            (
                WebAssessmentIncompleteReason::SemanticExtractionLimit,
                "semantic_extraction_limit",
            ),
            (
                WebAssessmentIncompleteReason::PassiveResponseProjectionLimit,
                "passive_response_projection_limit",
            ),
            (
                WebAssessmentIncompleteReason::AssessmentSubjectIdentityUnavailable,
                "assessment_subject_identity_unavailable",
            ),
            (
                WebAssessmentIncompleteReason::DifferentialReviewIncomplete,
                "differential_review_incomplete",
            ),
        ];
        for (reason, expected) in incomplete {
            assert_eq!(incomplete_reason_code(&reason), expected);
        }

        let stops = [
            (DecisionStopReason::ObjectiveComplete, "objective_complete"),
            (DecisionStopReason::NoEligibleAction, "no_eligible_action"),
            (DecisionStopReason::HumanReview, "human_review"),
            (DecisionStopReason::AdaptationLimit, "adaptation_limit"),
            (DecisionStopReason::ActionCycleLimit, "action_cycle_limit"),
            (
                DecisionStopReason::RuntimeBudgetLimit,
                "runtime_budget_limit",
            ),
            (DecisionStopReason::CancelledByHost, "cancelled_by_host"),
        ];
        for (reason, expected) in stops {
            assert_eq!(stop_reason_code(reason), expected);
        }

        let dimensions = [
            (RuntimeBudgetDimension::TotalRequests, "total_requests"),
            (RuntimeBudgetDimension::WallTime, "wall_time"),
            (RuntimeBudgetDimension::ResponseBytes, "response_bytes"),
            (
                RuntimeBudgetDimension::RequestBodyBytes,
                "request_body_bytes",
            ),
            (
                RuntimeBudgetDimension::ActiveVerifications,
                "active_verifications",
            ),
            (
                RuntimeBudgetDimension::SameActionAttempts,
                "same_action_attempts",
            ),
            (
                RuntimeBudgetDimension::ConsecutiveNoProgressTurns,
                "consecutive_no_progress_turns",
            ),
        ];
        for (dimension, expected) in dimensions {
            assert_eq!(runtime_dimension_code(dimension), expected);
        }

        let outcomes = [
            (venom_scanner::OutcomeStatus::Success, "success"),
            (venom_scanner::OutcomeStatus::Blocked, "blocked"),
            (venom_scanner::OutcomeStatus::Unknown, "unknown"),
            (
                venom_scanner::OutcomeStatus::FalsePositive,
                "false_positive",
            ),
            (venom_scanner::OutcomeStatus::NeedsReview, "needs_review"),
            (
                venom_scanner::OutcomeStatus::ConfirmedNegative,
                "confirmed_negative",
            ),
        ];
        for (status, expected) in outcomes {
            assert_eq!(outcome_status_code(status), expected);
        }
    }

    #[test]
    fn method_provenance_defense_and_terminal_tokens_remain_unambiguous() {
        assert_eq!(assessment_method_code(WebAssessmentMethod::Get), "get");
        assert_eq!(assessment_method_code(WebAssessmentMethod::Head), "head");
        assert_eq!(form_method_code(WebAssessmentFormMethod::Get), "get");
        assert_eq!(form_method_code(WebAssessmentFormMethod::Post), "post");
        assert_eq!(form_method_code(WebAssessmentFormMethod::Dialog), "dialog");
        assert_eq!(
            subject_origin_code(WebAssessmentSubjectOrigin::AuthorizedRoot),
            "authorized_root"
        );
        assert_eq!(
            subject_origin_code(WebAssessmentSubjectOrigin::Discovered),
            "discovered"
        );
        assert_eq!(
            defense_mode_code(WebAssessmentDefenseMode::ObservationOnly),
            "observation_only"
        );
        assert_eq!(
            defense_mode_code(WebAssessmentDefenseMode::Enforced),
            "enforced"
        );

        let replan = terminal_record(&DecisionLoopCommand::Replan);
        assert_eq!(replan.command, "replan");
        assert_eq!(replan.stop_reason, None);
        let halt = terminal_record(&DecisionLoopCommand::Halt {
            reason: DecisionStopReason::HumanReview,
        });
        assert_eq!(halt.command, "halt");
        assert_eq!(halt.stop_reason, Some("human_review"));
    }

    #[test]
    fn exact_origin_text_projection_reports_bounded_truth_without_private_values() {
        const SECRET: &str = "Bearer-do-not-render";
        let document = WebAssessmentDocument {
            schema_version: WEB_ASSESSMENT_SCHEMA_V2,
            target_origin: "https://example.test".to_owned(),
            disposition: AssessmentDisposition::Incomplete,
            incomplete_reasons: vec!["query_parameter_name_limit"],
            profile_contract: ScanProfileV1::web_review().expect("built-in profile is valid"),
            assessment: AssessmentBody::ExactOrigin(Box::new(ExactOriginReport {
                subjects: vec![SubjectRecord {
                    subject_reference: "subject-0001".to_owned(),
                    method: "get",
                    depth: 0,
                    provenance: "authorized_root",
                    query_parameter_names: vec![SECRET.to_owned()],
                    discovery_evidence_count: 1,
                    executed: true,
                    decision: SubjectDecisionSummary::default(),
                }],
                forms: vec![FormRecord {
                    form_reference: "form-0001".to_owned(),
                    method: "get",
                    query_parameter_names: vec![SECRET.to_owned()],
                    control_names: vec![SECRET.to_owned()],
                    evidence_count: 2,
                }],
                assessment_items: AssessmentItemsReport::Unavailable {
                    code: "incomplete_assessment_items_withheld",
                    committed_passive_observations: None,
                },
                semantics: SemanticSummary {
                    entity_count: 3,
                    entity_types: SemanticTypeCounts {
                        endpoint: 2,
                        parameter: 1,
                        ..SemanticTypeCounts::default()
                    },
                    truncated: true,
                    dropped_entities: 1,
                    dropped_attributes: 2,
                    dropped_sources: 3,
                },
                defense: DefenseSummary {
                    mode: "observation_only",
                    observation_count: 2,
                    metadata_only_observations: 1,
                    complete_prefix_observations: 1,
                    input_limited_observations: 0,
                    challenge_observations: 1,
                    rate_limit_observations: 0,
                    transition_count: 1,
                    candidate_block_transitions: 1,
                    newly_rate_limited_transitions: 0,
                    shadow_plan_count: 1,
                    unchanged_actions: 1,
                    deprioritized_actions: 1,
                    suppressed_actions: 1,
                },
                usage: ExactOriginUsage {
                    retained_subjects: 1,
                    executed_subjects: 1,
                    retained_forms: 1,
                    retained_unique_url_bytes: 20,
                    total_requests: 2,
                    active_verifications: 1,
                    request_body_bytes: 0,
                    response_bytes: 128,
                    elapsed_ms: 9,
                },
                transport: TransportSummary {
                    retained_dispatch_receipts: 2,
                    omitted_dispatch_receipts: 0,
                },
                failure_inventory: None,
            })),
        };

        let rendered = render_text(&document);
        assert!(rendered.contains("assessment scope: exact-origin"));
        assert!(rendered.contains("inventory: subjects=1 executed=1 forms=1"));
        assert!(rendered.contains("semantics: entities=3 truncated=true"));
        assert!(rendered.contains("defense: mode=observation_only observations=2"));
        assert!(rendered.contains(
            "assessment items: projection_status=unavailable code=incomplete_assessment_items_withheld"
        ));
        assert!(!rendered.contains("assessment item: subject="));
        assert!(rendered.contains("usage: requests=2 active_verifications=1"));
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains("https://example.test/private"));
    }
}
