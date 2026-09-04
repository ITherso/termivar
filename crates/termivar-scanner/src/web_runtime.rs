//! Host-facing runtime for the standard deterministic web decision stack.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B — this is `StandardWebDecisionRuntime`, invoked by
//!   the canonical `termivar scan`, its deprecated `decision-scan` alias, the
//!   `examples/decision_scan.rs` reference host, and external library hosts.
//! - **Default `termivar scan`:** yes.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The runtime owns composition and bounded command driving. Domain layers
//! remain independently testable and the caller remains responsible for
//! target authorization and HTTP evidence policy.

use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};

use termivar_core::{
    EntityId, EvidenceValue, HttpEvidencePredicate, OutcomeStatus, ReasoningModelError,
    VerificationStage,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::decision_runner::ContinuationAuthority;
use crate::http_evidence::CompleteHttpResponseObserver;
use crate::planner::ActionSuppressionContext;
#[cfg(feature = "authorization-review")]
use crate::rules::{Expression, KnowledgeLayer};
use crate::{
    AdaptationLimits, AdaptationRule, AdaptivePipelineError, BenefitScore, DecisionActionOrigin,
    DecisionEvidenceReceipt, DecisionExecutionClass, DecisionExecutionFailureReceipt,
    DecisionExecutionLimits, DecisionExecutionStage, DecisionExecutorRegistry, DecisionLoop,
    DecisionLoopCommand, DecisionLoopConfig, DecisionLoopError, DecisionOutcomeReport,
    DecisionPlanningReport, DecisionReasoningCommitReceipt, DecisionRunnerAdapter,
    DecisionRunnerError, DecisionRunnerTurn, DecisionSession, DecisionStopReason, ExperiencePolicy,
    ExperienceStore, ExperienceStoreError, HttpEvidenceError, HttpEvidenceExecutor,
    HttpEvidencePolicy, HttpHeaderPayloadBinding, HttpProbe, HttpProbeMethod, KnowledgeBase,
    KnowledgeWrite, OutcomeSelector, PipelineDirective, PlannerError, PlanningContext, RiskScore,
    RuntimeBudget, RuntimeBudgetDimension, RuntimeLimitExceeded, RuntimeUsage,
    StandardApiInstallReport, StandardApiReasoning, StandardApiReasoningError,
    StandardWebActionKind, StandardWebDecisionError, StandardWebDecisionInstallReport,
    StandardWebDecisionProfile, SubjectHttpProbeProvider, TransportDispatchAudit, VerificationCase,
    VerificationError, HTTP_EVIDENCE_EXECUTOR_ID,
};

mod api_visibility;
mod assessment_api_visibility;
mod assessment_defense;
mod assessment_item;
mod assessment_passive;
#[cfg(feature = "reporting")]
mod assessment_report;
mod assessment_review;
mod assessment_review_projection;
mod authority;
#[cfg(feature = "graphql-review")]
mod graphql_runtime;
#[cfg(feature = "openapi-review")]
mod openapi_runtime;
#[cfg(feature = "authorization-review")]
mod resource_authorization_runtime;
#[cfg(feature = "rest-review")]
mod rest_runtime;
mod scan_profile;
#[cfg(feature = "ssrf-oast-review")]
mod ssrf_oast_runtime;
mod web_assessment;
mod web_review_decision;
mod web_review_execution;

use assessment_defense::AssessmentDefenseController;
pub(crate) use assessment_defense::{
    project_assessment_defense_signal, AssessmentDefenseBodyCoverage,
    AssessmentDefenseProjectionContext, AssessmentDefenseSignal,
};
pub(crate) use assessment_review::AssessmentReviewObserverSet;
#[cfg(feature = "oast-native-provider")]
pub(crate) use authority::NativeOastProviderMintToken;
pub(crate) use authority::SharedWebRuntimeAuthority;
pub(crate) use web_assessment::AssessmentDiscoveryObserver;
use web_review_decision::NativeWebReviewDecisionProfile;
use web_review_execution::{
    NativeWebReviewExecutorProfile, NativeWebReviewQueryParameters, NativeWebReviewSeeds,
};

pub use api_visibility::{
    ApiVisibilityContextProbe, ApiVisibilityDifferentialAudit,
    ApiVisibilityDifferentialDisposition, ApiVisibilityDifferentialRequest,
    ApiVisibilityDifferentialRequestError, ApiVisibilityInconclusiveReason, ApiVisibilityLeg,
    ApiVisibilityLegReceipt, RuntimeApiVisibilityError, RuntimeApiVisibilityExecutionError,
    RuntimeApiVisibilityRunReport,
};
pub use assessment_api_visibility::{
    WebAssessmentAuthorizationContextError, WebAssessmentRootAuthorizationContext,
};
pub use assessment_item::{
    AssessmentBasis, AssessmentCaseReference, AssessmentConfirmationDenial,
    AssessmentDifferentialBasis, AssessmentDisposition, AssessmentEvidenceReference,
    AssessmentItem, AssessmentItemProjectionError, AssessmentObservationBasis,
    AssessmentOutcomeReference, AssessmentRemediation, AssessmentSubjectReference,
    AssessmentVerifierBasis, ASSESSMENT_ITEM_SCHEMA, MAX_ASSESSMENT_CAPABILITY_ID_BYTES,
    MAX_ASSESSMENT_DISPLAY_BYTES, MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES,
    MAX_ASSESSMENT_ITEM_SET_ITEMS,
};

#[cfg(feature = "reporting")]
pub use assessment_report::{
    AssessmentRunReport, AssessmentRunReportError, ASSESSMENT_RUN_REPORT_SCHEMA,
    MAX_ASSESSMENT_RUN_ITEMS,
};

#[cfg(feature = "openapi-review")]
pub use openapi_runtime::{
    OpenApiCandidateSource, OpenApiRuntimeOutcome, WebAssessmentOpenApiAudit,
    MAX_OPENAPI_REVIEW_ACTIVE_VERIFICATIONS, MAX_OPENAPI_REVIEW_DOCUMENTS,
    MAX_OPENAPI_REVIEW_REQUESTS, OPENAPI_REVIEW_ACTION_ID, OPENAPI_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "authorization-review")]
pub use resource_authorization_runtime::{
    WebAssessmentAuthorizationAudit, MAX_AUTHORIZATION_REVIEW_ACTIVE_VERIFICATIONS,
    MAX_AUTHORIZATION_REVIEW_REQUESTS, MAX_AUTHORIZATION_REVIEW_RESOURCES,
    RESOURCE_AUTHORIZATION_REVIEW_ACTION_ID, RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "rest-review")]
pub use rest_runtime::{
    RestObservedMediaClass, RestRuntimeOutcome, WebAssessmentRestAudit,
    MAX_REST_REVIEW_ACTIVE_VERIFICATIONS, MAX_REST_REVIEW_REQUESTS, MAX_REST_REVIEW_RESOURCES,
    REST_REVIEW_ACTION_ID, REST_REVIEW_CAPABILITY_ID,
};
#[cfg(feature = "scanning")]
pub use scan_profile::{
    BuiltInScanProfile, BuiltInScanProfileParseError, ScanProfileCapabilitiesV1,
    ScanProfileLimitsV1, ScanProfileScope, ScanProfileSelectionError, ScanProfileV1,
    ScanProfileV1Error, BASELINE_SCAN_PROFILE_ID, BASELINE_SCAN_PROFILE_MAX_TOTAL_REQUESTS,
    BASELINE_SCAN_PROFILE_MAX_TOTAL_RESPONSE_BYTES, BASELINE_SCAN_PROFILE_MAX_WALL_TIME_MS,
    SCAN_PROFILE_V1_SCHEMA, WEB_REVIEW_SCAN_PROFILE_ID,
};
#[cfg(feature = "ssrf-oast-review")]
pub use ssrf_oast_runtime::{
    SsrfOastRuntimeOutcome, WebAssessmentSsrfOastAudit, MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS,
    MAX_SSRF_OAST_REVIEW_PARAMETERS, MAX_SSRF_OAST_REVIEW_PROVIDER_REQUESTS,
    MAX_SSRF_OAST_REVIEW_REQUESTS, MAX_SSRF_OAST_REVIEW_RESOURCES, SSRF_OAST_REVIEW_ACTION_ID,
    SSRF_OAST_REVIEW_CAPABILITY_ID,
};
pub use web_assessment::{
    WebAssessmentCompletion, WebAssessmentDefenseAudit, WebAssessmentDefenseBodyCoverage,
    WebAssessmentDefenseMode, WebAssessmentDefenseObservation, WebAssessmentDefenseShadowPlan,
    WebAssessmentDefenseTransition, WebAssessmentFailureReceipt, WebAssessmentForm,
    WebAssessmentFormMethod, WebAssessmentIncompleteReason, WebAssessmentLimits,
    WebAssessmentLimitsError, WebAssessmentMethod, WebAssessmentRunReport, WebAssessmentRuntime,
    WebAssessmentRuntimeBuilder, WebAssessmentRuntimeError, WebAssessmentSubject,
    WebAssessmentSubjectOrigin, WebAssessmentSubjectReport, WebAssessmentUsage,
    DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS,
    DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES, DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM,
    DEFAULT_WEB_ASSESSMENT_MAX_DEPTH, DEFAULT_WEB_ASSESSMENT_MAX_FORMS,
    DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES, DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT,
    DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES, DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES,
    DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS, DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS,
    DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES, DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME,
    HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS, HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES,
    HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM, HARD_MAX_WEB_ASSESSMENT_DEPTH,
    HARD_MAX_WEB_ASSESSMENT_FORMS, HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES,
    HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT, HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES,
    HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES, HARD_MAX_WEB_ASSESSMENT_SUBJECTS,
    HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS, HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES,
    HARD_MAX_WEB_ASSESSMENT_WALL_TIME, WEB_ASSESSMENT_CONCURRENCY,
};

const DEFAULT_BUSINESS_VALUE_PERCENT: u8 = 80;
const DEFAULT_PLANNING_BUDGET: u64 = 100;
const DEFAULT_RISK_LIMIT_PERCENT: u8 = 40;
const DEFAULT_MAX_ACTION_CYCLES: u32 = 8;
const DEFAULT_FAILURE_LIMIT: u16 = 10;
pub(crate) const BOOTSTRAP_ACTION_ID: &str = "web.action.bootstrap.http-evidence";
pub(crate) const BOOTSTRAP_CASE_ID: &str = "case:web-runtime:bootstrap:http";
pub(crate) const BOOTSTRAP_HYPOTHESIS_ID: &str = "hypothesis:web-runtime:bootstrap";
/// Construction and execution failures for [`StandardWebDecisionRuntime`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StandardWebDecisionRuntimeError {
    /// A runtime instance was asked to execute its single-use session twice.
    #[error("standard web decision runtime has already started")]
    AlreadyStarted,

    /// A planner score or action policy was invalid.
    #[error(transparent)]
    Planner(#[from] PlannerError),

    /// Decision-loop configuration or state transition failed.
    #[error(transparent)]
    Decision(#[from] DecisionLoopError),

    /// Experience suppression policy was invalid.
    #[error(transparent)]
    Experience(#[from] ExperienceStoreError),

    /// A target-scoped reasoning identity was invalid.
    #[error(transparent)]
    Reasoning(#[from] ReasoningModelError),

    /// A bootstrap verification identity was invalid.
    #[error(transparent)]
    Verification(#[from] VerificationError),

    /// HTTP scope, resource, or collector construction failed.
    #[error(transparent)]
    Http(#[from] HttpEvidenceError),

    /// The standard reasoning, planning, execution, or verification profile failed.
    #[error(transparent)]
    Profile(#[from] StandardWebDecisionError),

    /// The optional JSON response-format and GraphQL surface profile failed to install.
    #[error(transparent)]
    ApiReasoning(#[from] StandardApiReasoningError),

    /// The closed native review reasoning/action/verifier catalog failed validation.
    #[error("native web-review decision profile could not be composed")]
    NativeWebReviewDecisionProfile,

    /// The closed native review executor and payload catalog failed validation.
    #[error("native web-review execution profile could not be composed")]
    NativeWebReviewExecutionProfile,

    /// The bounded authorization action/executor could not join the parent runtime.
    #[cfg(feature = "authorization-review")]
    #[error("resource authorization review could not be composed")]
    ResourceAuthorizationReviewComposition,

    /// An executor lookup, request, evidence commit, or runner transition failed.
    #[error(transparent)]
    Runner(#[from] DecisionRunnerError),

    /// Standard HTTP execution omitted or duplicated its resource telemetry.
    #[error(
        "execution case {case_id} emitted {observations} unsigned {predicate} observations; expected exactly one"
    )]
    ResponseUsageEvidence {
        /// Execution case whose correlated evidence was invalid.
        case_id: String,
        /// Stable response-body usage predicate.
        predicate: &'static str,
        /// Matching unsigned observations found in the committed snapshot.
        observations: usize,
        /// Durable evidence commit that exposed the telemetry violation.
        receipt: Box<DecisionEvidenceReceipt>,
    },

    /// Committed assessment-defense evidence failed its closed replay schema.
    #[error("committed assessment defense projection violated its closed schema")]
    AssessmentDefenseProjectionInvariant {
        /// Durable evidence commit rejected by the assessment replay boundary.
        receipt: Box<DecisionEvidenceReceipt>,
    },

    /// Assessment defense policy could not classify the exact authorized plan.
    #[error("assessment defense planning authority invariant failed")]
    AssessmentDefensePlanningInvariant,

    /// A non-execution command reached the transport-accounting boundary.
    #[error("runtime resource accounting requires an execution command")]
    ExecutionMetadataUnavailable,

    /// Execution failed after the single-use runtime had started.
    ///
    /// The receipt preserves every earlier completed turn and the resource
    /// accounting snapshot observed at the failure boundary. The nested source
    /// retains any current execution, evidence, or reasoning receipt.
    #[error("standard web decision runtime failed after it started: {source}")]
    RunFailed {
        /// Completed audit history and final resource usage before the error.
        receipt: Box<StandardWebDecisionFailureReceipt>,
        /// Typed failure raised at the current runtime boundary.
        #[source]
        source: Box<StandardWebDecisionRuntimeError>,
    },
}

impl StandardWebDecisionRuntimeError {
    /// Returns completed audit history captured when a started run failed.
    pub fn failure_receipt(&self) -> Option<&StandardWebDecisionFailureReceipt> {
        match self {
            Self::RunFailed { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    /// Removes the subject-local audit from a started failure without carrying
    /// its cumulative authority snapshots into an outer assessment receipt.
    pub(crate) fn into_assessment_failure(
        self,
    ) -> (
        StandardWebDecisionAssessmentFailureParts,
        StandardWebDecisionRuntimeError,
    ) {
        match self {
            Self::RunFailed { receipt, source } => (receipt.into_assessment_parts(), *source),
            source => (StandardWebDecisionAssessmentFailureParts::default(), source),
        }
    }

    /// Takes completed audit history captured when a started run failed.
    pub fn into_failure_receipt(self) -> Option<StandardWebDecisionFailureReceipt> {
        match self {
            Self::RunFailed { receipt, .. } => Some(*receipt),
            _ => None,
        }
    }

    /// Returns an executor-reported pre-commit failure receipt, when applicable.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        match self {
            Self::Runner(source) => source.execution_failure(),
            Self::RunFailed { source, .. } => source.execution_failure(),
            _ => None,
        }
    }

    /// Takes ownership of an executor-reported failure receipt without cloning it.
    pub fn into_execution_failure(self) -> Option<DecisionExecutionFailureReceipt> {
        match self {
            Self::Runner(source) => source.into_execution_failure(),
            Self::RunFailed { source, .. } => source.into_execution_failure(),
            _ => None,
        }
    }

    /// Returns evidence committed before this runtime error, when applicable.
    pub fn committed_evidence(&self) -> Option<&DecisionEvidenceReceipt> {
        match self {
            Self::Runner(source) => source.committed_evidence(),
            Self::ResponseUsageEvidence { receipt, .. } => Some(receipt),
            Self::AssessmentDefenseProjectionInvariant { receipt } => Some(receipt),
            Self::RunFailed { source, .. } => source.committed_evidence(),
            _ => None,
        }
    }

    /// Takes ownership of evidence committed before this error without cloning it.
    pub fn into_committed_evidence(self) -> Option<DecisionEvidenceReceipt> {
        match self {
            Self::Runner(source) => source.into_committed_evidence(),
            Self::ResponseUsageEvidence { receipt, .. } => Some(*receipt),
            Self::AssessmentDefenseProjectionInvariant { receipt } => Some(*receipt),
            Self::RunFailed { source, .. } => source.into_committed_evidence(),
            _ => None,
        }
    }

    /// Returns reasoning committed before a later planning failure, when applicable.
    pub fn committed_reasoning(&self) -> Option<&DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.committed_reasoning(),
            Self::Runner(source) => source.committed_reasoning(),
            Self::RunFailed { source, .. } => source.committed_reasoning(),
            _ => None,
        }
    }

    /// Takes a post-reasoning planning receipt without cloning it.
    pub fn into_committed_reasoning(self) -> Option<DecisionReasoningCommitReceipt> {
        match self {
            Self::Decision(source) => source.into_committed_reasoning(),
            Self::Runner(source) => source.into_committed_reasoning(),
            Self::RunFailed { source, .. } => source.into_committed_reasoning(),
            _ => None,
        }
    }
}

/// One non-terminal audit record produced while driving a runtime session.
#[derive(Debug)]
#[non_exhaustive]
pub enum StandardWebDecisionRuntimeTurn {
    /// Reasoning and utility planning selected the next command.
    Planning(Box<DecisionPlanningReport>),
    /// An executor committed evidence and the verifier classified the case.
    Outcome {
        /// Provenance-validated evidence commit receipt.
        evidence: Box<DecisionEvidenceReceipt>,
        /// Verification, adaptation, experience, and next-command report.
        decision: Box<DecisionOutcomeReport>,
    },
}

/// Completed audit history retained when a started runtime returns an error.
///
/// This process-local receipt covers work completed before the failing
/// boundary. Cause-specific receipts for the current boundary remain available
/// through [`StandardWebDecisionRuntimeError`] accessors.
#[derive(Debug)]
pub struct StandardWebDecisionFailureReceipt {
    bootstrap: Option<DecisionEvidenceReceipt>,
    completed_turns: Vec<StandardWebDecisionRuntimeTurn>,
    usage: RuntimeUsage,
    transport: TransportDispatchAudit,
}

impl StandardWebDecisionFailureReceipt {
    /// Returns bootstrap evidence committed before the later failure.
    pub fn bootstrap(&self) -> Option<&DecisionEvidenceReceipt> {
        self.bootstrap.as_ref()
    }

    /// Returns planning and outcome turns completed before the later failure.
    pub fn completed_turns(&self) -> &[StandardWebDecisionRuntimeTurn] {
        &self.completed_turns
    }

    /// Returns resource accounting observed at the failure boundary.
    pub fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns bounded per-dispatch transport receipts at the failure boundary.
    pub fn transport(&self) -> &TransportDispatchAudit {
        &self.transport
    }

    fn into_assessment_parts(self: Box<Self>) -> StandardWebDecisionAssessmentFailureParts {
        let Self {
            bootstrap,
            completed_turns,
            usage: _,
            transport: _,
        } = *self;
        StandardWebDecisionAssessmentFailureParts {
            bootstrap,
            turns: completed_turns,
        }
    }
}

/// Complete audit trail from bootstrap evidence to a terminal command.
#[derive(Debug)]
pub struct StandardWebDecisionRunReport {
    bootstrap: Option<DecisionEvidenceReceipt>,
    turns: Vec<StandardWebDecisionRuntimeTurn>,
    unverified_evidence: Option<DecisionEvidenceReceipt>,
    terminal: DecisionLoopCommand,
    usage: RuntimeUsage,
    transport: TransportDispatchAudit,
    limit_exceeded: Option<RuntimeLimitExceeded>,
    execution_failure: Option<DecisionExecutionFailureReceipt>,
}

/// Standard-run audit parts retained by one origin-assessment subject.
///
/// Usage and transport are intentionally absent. Every assessment subject uses
/// one shared authority, so only the outer assessment report may expose those
/// cumulative records.
pub(crate) struct StandardWebDecisionAssessmentParts {
    pub(crate) bootstrap: Option<DecisionEvidenceReceipt>,
    pub(crate) turns: Vec<StandardWebDecisionRuntimeTurn>,
    pub(crate) unverified_evidence: Option<DecisionEvidenceReceipt>,
    pub(crate) terminal: DecisionLoopCommand,
    pub(crate) limit_exceeded: Option<RuntimeLimitExceeded>,
    pub(crate) execution_failure: Option<DecisionExecutionFailureReceipt>,
}

/// Subject-local work preserved from a failed Standard runtime.
///
/// The global usage and transport snapshots are intentionally discarded; the
/// host assessment owns exactly one cumulative authority audit.
#[derive(Default)]
pub(crate) struct StandardWebDecisionAssessmentFailureParts {
    pub(crate) bootstrap: Option<DecisionEvidenceReceipt>,
    pub(crate) turns: Vec<StandardWebDecisionRuntimeTurn>,
}

impl StandardWebDecisionRunReport {
    /// Returns the initial GET evidence committed before reasoning starts.
    pub fn bootstrap(&self) -> Option<&DecisionEvidenceReceipt> {
        self.bootstrap.as_ref()
    }

    /// Returns non-terminal planning and outcome turns in execution order.
    pub fn turns(&self) -> &[StandardWebDecisionRuntimeTurn] {
        &self.turns
    }

    /// Returns evidence durably committed before verification was skipped.
    ///
    /// This is populated when execution committed its evidence batch before
    /// host cancellation or a response-byte threshold crossing halted the
    /// turn. The receipt stays outside [`Self::outcome_reports`] because no
    /// verifier outcome exists for this batch.
    pub fn unverified_evidence(&self) -> Option<&DecisionEvidenceReceipt> {
        self.unverified_evidence.as_ref()
    }

    /// Returns the command that ended the session.
    pub fn terminal(&self) -> &DecisionLoopCommand {
        &self.terminal
    }

    /// Returns the final resource accounting snapshot.
    pub fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns bounded, dispatch-ordered transport receipts for this run.
    pub fn transport(&self) -> &TransportDispatchAudit {
        &self.transport
    }

    /// Returns the structured runtime limit when the resource envelope stopped execution.
    pub fn limit_exceeded(&self) -> Option<&RuntimeLimitExceeded> {
        self.limit_exceeded.as_ref()
    }

    /// Returns the transport execution receipt when a broker-owned resource
    /// limit refused a dispatch after the semantic action had started.
    pub fn execution_failure(&self) -> Option<&DecisionExecutionFailureReceipt> {
        self.execution_failure.as_ref()
    }

    /// Iterates over planning audit reports in turn order.
    pub fn planning_reports(&self) -> impl Iterator<Item = &DecisionPlanningReport> {
        self.turns.iter().filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Planning(report) => Some(report.as_ref()),
            StandardWebDecisionRuntimeTurn::Outcome { .. } => None,
        })
    }

    /// Iterates over verified outcome reports in turn order.
    pub fn outcome_reports(&self) -> impl Iterator<Item = &DecisionOutcomeReport> {
        self.turns.iter().filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Outcome { decision, .. } => Some(decision.as_ref()),
            StandardWebDecisionRuntimeTurn::Planning(_) => None,
        })
    }

    pub(crate) fn into_assessment_parts(self) -> StandardWebDecisionAssessmentParts {
        StandardWebDecisionAssessmentParts {
            bootstrap: self.bootstrap,
            turns: self.turns,
            unverified_evidence: self.unverified_evidence,
            terminal: self.terminal,
            limit_exceeded: self.limit_exceeded,
            execution_failure: self.execution_failure,
        }
    }
}

/// Builder for one target-scoped [`StandardWebDecisionRuntime`].
pub struct StandardWebDecisionRuntimeBuilder {
    target: Url,
    http_policy: Option<HttpEvidencePolicy>,
    business_value_percent: u8,
    planning_budget: u64,
    risk_limit_percent: u8,
    adaptation_limits: AdaptationLimits,
    experience_failure_limit: u16,
    max_action_cycles: u32,
    experience: ExperienceStore,
    runtime_budget: RuntimeBudget,
    api_reasoning_enabled: bool,
    payload_binding: Option<HttpHeaderPayloadBinding>,
    cancellation: CancellationToken,
    bootstrap_probe_method: HttpProbeMethod,
    complete_response_observer: Option<Arc<dyn CompleteHttpResponseObserver>>,
    additional_suppressed_actions: BTreeSet<String>,
    assessment_defense_projection: bool,
    assessment_defense_enforcement: bool,
    native_web_review: Option<NativeWebReviewRuntimeConfig>,
    #[cfg(feature = "authorization-review")]
    resource_authorization_review:
        Option<resource_authorization_runtime::ResourceAuthorizationReviewConfig>,
    #[cfg(feature = "openapi-review")]
    openapi_review: Option<openapi_runtime::OpenApiReviewConfig>,
    #[cfg(feature = "rest-review")]
    rest_review: bool,
    #[cfg(feature = "ssrf-oast-review")]
    ssrf_oast_review: Option<ssrf_oast_runtime::SsrfOastReviewConfig>,
}

struct NativeWebReviewRuntimeConfig {
    seeds: NativeWebReviewSeeds,
    observer: Arc<dyn CompleteHttpResponseObserver>,
    redirect_query_parameter: Option<String>,
    reflection_query_parameter: Option<String>,
    sql_query_parameter: Option<String>,
    ssti_query_parameter: Option<String>,
    xss_query_parameter: Option<String>,
    xss_selection: Option<web_assessment::XssProbeSelection>,
    #[cfg(feature = "normalization-resilience")]
    normalization_query_parameter: Option<String>,
    #[cfg(feature = "normalization-resilience")]
    normalization_selection: Option<web_assessment::NormalizationTransformSelection>,
    structural_only: bool,
}

struct StandardWebDecisionRuntimePreflight {
    config: DecisionLoopConfig,
    subject: EntityId,
}

impl StandardWebDecisionRuntimeBuilder {
    /// Creates a builder with conservative deterministic defaults.
    pub fn new(target: Url) -> Self {
        Self {
            target,
            http_policy: None,
            business_value_percent: DEFAULT_BUSINESS_VALUE_PERCENT,
            planning_budget: DEFAULT_PLANNING_BUDGET,
            risk_limit_percent: DEFAULT_RISK_LIMIT_PERCENT,
            adaptation_limits: AdaptationLimits::default(),
            experience_failure_limit: DEFAULT_FAILURE_LIMIT,
            max_action_cycles: DEFAULT_MAX_ACTION_CYCLES,
            experience: ExperienceStore::new(),
            runtime_budget: RuntimeBudget::default(),
            api_reasoning_enabled: false,
            payload_binding: None,
            cancellation: CancellationToken::new(),
            bootstrap_probe_method: HttpProbeMethod::Get,
            complete_response_observer: None,
            additional_suppressed_actions: BTreeSet::new(),
            assessment_defense_projection: false,
            assessment_defense_enforcement: false,
            native_web_review: None,
            #[cfg(feature = "authorization-review")]
            resource_authorization_review: None,
            #[cfg(feature = "openapi-review")]
            openapi_review: None,
            #[cfg(feature = "rest-review")]
            rest_review: false,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast_review: None,
        }
    }

    /// Enables passive JSON response-format and GraphQL surface reasoning.
    ///
    /// This opt-in reuses evidence already collected by the runtime. It adds no
    /// request, executor, payload, visibility comparison, or planner action.
    pub fn enable_api_reasoning(mut self) -> Self {
        self.api_reasoning_enabled = true;
        self
    }

    /// Replaces the default single-origin HTTP evidence policy.
    pub fn http_policy(mut self, policy: HttpEvidencePolicy) -> Self {
        self.http_policy = Some(policy);
        self
    }

    /// Binds a header-valued payload strategy to the runtime's HTTP evidence
    /// executor.
    ///
    /// The bound executor shares the runtime's metered request broker, so any
    /// control or candidate artifact it derives and dispatches is accounted like
    /// every other request. This is strictly opt-in: without a binding the
    /// runtime materializes and dispatches no payload artifacts.
    pub fn with_payload_binding(mut self, binding: HttpHeaderPayloadBinding) -> Self {
        self.payload_binding = Some(binding);
        self
    }

    /// Sets target business value as an integer percentage.
    pub fn business_value(mut self, percent: u8) -> Self {
        self.business_value_percent = percent;
        self
    }

    /// Sets the planner's total action-cost budget.
    pub fn planning_budget(mut self, budget: u64) -> Self {
        self.planning_budget = budget;
        self
    }

    /// Sets the maximum accepted action risk as an integer percentage.
    pub fn risk_limit(mut self, percent: u8) -> Self {
        self.risk_limit_percent = percent;
        self
    }

    /// Replaces the adaptive transition limits.
    pub fn adaptation_limits(mut self, limits: AdaptationLimits) -> Self {
        self.adaptation_limits = limits;
        self
    }

    /// Sets the consecutive completed-failure suppression threshold.
    pub fn experience_failure_limit(mut self, limit: u16) -> Self {
        self.experience_failure_limit = limit;
        self
    }

    /// Sets the maximum number of passive action executions in one session.
    pub fn max_action_cycles(mut self, cycles: u32) -> Self {
        self.max_action_cycles = cycles;
        self
    }

    /// Seeds the runtime with experience retained by the host.
    pub fn experience_store(mut self, experience: ExperienceStore) -> Self {
        self.experience = experience;
        self
    }

    /// Replaces the complete runtime resource envelope.
    pub fn runtime_budget(mut self, budget: RuntimeBudget) -> Self {
        self.runtime_budget = budget;
        self
    }

    /// Replaces the host-owned cancellation token for this runtime.
    ///
    /// Cancellation is reported independently from wall-time and transport
    /// request timeouts. The host should retain a clone when it needs to stop
    /// [`StandardWebDecisionRuntime::analyze`] from another task.
    pub fn cancellation_token(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Installs the sealed assessment projection on the bootstrap request.
    ///
    /// HEAD subjects are metadata observations only: all post-bootstrap
    /// semantic actions are suppressed so they cannot silently become GET or
    /// OPTIONS work. GET subjects retain the standard decision behavior.
    pub(crate) fn with_assessment_response_observer(
        mut self,
        method: HttpProbeMethod,
        observer: Arc<dyn CompleteHttpResponseObserver>,
    ) -> Self {
        self.bootstrap_probe_method = method;
        self.complete_response_observer = Some(observer);
        self.assessment_defense_projection = true;
        if method == HttpProbeMethod::Head {
            self.additional_suppressed_actions.extend(
                StandardWebActionKind::all()
                    .into_iter()
                    .map(|kind| kind.action_id().to_owned()),
            );
        }
        self
    }

    pub(crate) fn with_assessment_defense_enforcement(mut self, enabled: bool) -> Self {
        self.assessment_defense_projection = true;
        self.assessment_defense_enforcement = enabled;
        self
    }

    /// Installs the one resource-authorization action into this parent subject
    /// runtime. The config remains move-only and no secondary runner is built.
    #[cfg(feature = "authorization-review")]
    pub(in crate::web_runtime) fn with_resource_authorization_review(
        mut self,
        config: resource_authorization_runtime::ResourceAuthorizationReviewConfig,
    ) -> Self {
        self.assessment_defense_projection = true;
        self.resource_authorization_review = Some(config);
        self
    }

    #[cfg(feature = "openapi-review")]
    pub(in crate::web_runtime) fn with_openapi_review(
        mut self,
        config: openapi_runtime::OpenApiReviewConfig,
    ) -> Self {
        self.assessment_defense_projection = true;
        self.openapi_review = Some(config);
        self
    }

    #[cfg(feature = "rest-review")]
    pub(in crate::web_runtime) fn with_rest_review(mut self) -> Self {
        self.assessment_defense_projection = true;
        self.rest_review = true;
        self
    }

    #[cfg(feature = "ssrf-oast-review")]
    pub(in crate::web_runtime) fn with_ssrf_oast_review(
        mut self,
        config: ssrf_oast_runtime::SsrfOastReviewConfig,
    ) -> Self {
        self.assessment_defense_projection = true;
        self.ssrf_oast_review = Some(config);
        self
    }

    /// Reuses this subject runtime for one opt-in matched native review pass.
    ///
    /// The native catalog is additive: the standard catalog keeps its existing
    /// execution semantics, and every executor receives the same broker and
    /// accounting authority during composition. A missing query parameter
    /// omits and suppresses only the redirect/reflection action rather than
    /// inventing transport input.
    pub(crate) fn with_native_web_review(
        mut self,
        seeds: NativeWebReviewSeeds,
        observer: Arc<dyn CompleteHttpResponseObserver>,
        redirect_query_parameter: Option<String>,
        reflection_query_parameter: Option<String>,
        sql_query_parameter: Option<String>,
        ssti_query_parameter: Option<String>,
    ) -> Self {
        self.assessment_defense_projection = true;
        self.native_web_review = Some(NativeWebReviewRuntimeConfig {
            seeds,
            observer,
            redirect_query_parameter,
            reflection_query_parameter,
            sql_query_parameter,
            ssti_query_parameter,
            xss_query_parameter: None,
            xss_selection: None,
            #[cfg(feature = "normalization-resilience")]
            normalization_query_parameter: None,
            #[cfg(feature = "normalization-resilience")]
            normalization_selection: None,
            structural_only: false,
        });
        self
    }

    pub(crate) fn with_native_structural_review(
        mut self,
        seeds: NativeWebReviewSeeds,
        observer: Arc<dyn CompleteHttpResponseObserver>,
        sql_query_parameter: Option<String>,
        ssti_query_parameter: Option<String>,
        reflection_query_parameter: Option<String>,
    ) -> Self {
        self.assessment_defense_projection = true;
        self.native_web_review = Some(NativeWebReviewRuntimeConfig {
            seeds,
            observer,
            redirect_query_parameter: None,
            reflection_query_parameter,
            sql_query_parameter,
            ssti_query_parameter,
            xss_query_parameter: None,
            xss_selection: None,
            #[cfg(feature = "normalization-resilience")]
            normalization_query_parameter: None,
            #[cfg(feature = "normalization-resilience")]
            normalization_selection: None,
            structural_only: true,
        });
        self
    }

    /// Composes one context-selected structural XSS pair under the existing
    /// shared authority. Standard semantic actions are suppressed for this
    /// bounded child pass; the bootstrap remains broker-accounted.
    pub(crate) fn with_native_xss_structural_review(
        mut self,
        seeds: NativeWebReviewSeeds,
        observer: Arc<dyn CompleteHttpResponseObserver>,
        query_parameter: String,
        selection: web_assessment::XssProbeSelection,
    ) -> Self {
        self.assessment_defense_projection = true;
        self.additional_suppressed_actions.extend(
            StandardWebActionKind::all()
                .into_iter()
                .map(|kind| kind.action_id().to_owned()),
        );
        self.native_web_review = Some(NativeWebReviewRuntimeConfig {
            seeds,
            observer,
            redirect_query_parameter: None,
            reflection_query_parameter: None,
            sql_query_parameter: None,
            ssti_query_parameter: None,
            xss_query_parameter: Some(query_parameter),
            xss_selection: Some(selection),
            #[cfg(feature = "normalization-resilience")]
            normalization_query_parameter: None,
            #[cfg(feature = "normalization-resilience")]
            normalization_selection: None,
            structural_only: true,
        });
        self
    }

    /// Composes one explicitly selected normalization transformed-candidate /
    /// replay pair under the existing exact-origin broker authority.
    ///
    /// Parent control and canonical-candidate requests are not repeated. The
    /// caller must build the observer from a committed
    /// [`assessment_review::NormalizationParentEvidence`] contract.
    #[cfg(feature = "normalization-resilience")]
    pub(in crate::web_runtime) fn with_native_normalization_resilience_review(
        mut self,
        seeds: NativeWebReviewSeeds,
        observer: Arc<dyn CompleteHttpResponseObserver>,
        query_parameter: String,
        selection: web_assessment::NormalizationTransformSelection,
    ) -> Self {
        self.assessment_defense_projection = true;
        self.additional_suppressed_actions.extend(
            StandardWebActionKind::all()
                .into_iter()
                .map(|kind| kind.action_id().to_owned()),
        );
        self.native_web_review = Some(NativeWebReviewRuntimeConfig {
            seeds,
            observer,
            redirect_query_parameter: None,
            reflection_query_parameter: None,
            sql_query_parameter: None,
            ssti_query_parameter: None,
            xss_query_parameter: None,
            xss_selection: None,
            normalization_query_parameter: Some(query_parameter),
            normalization_selection: Some(selection),
            structural_only: true,
        });
        self
    }

    /// Sets the total bootstrap, passive, active, adaptive, and retry request limit.
    pub fn max_total_requests(mut self, limit: u32) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_total_requests(limit);
        self
    }

    /// Sets the monotonic deadline for the complete runtime.
    pub fn max_wall_time(mut self, limit: Duration) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_wall_time(limit);
        self
    }

    /// Sets the cumulative transport-delivered response-body threshold.
    pub fn max_response_bytes(mut self, limit: u64) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_response_bytes(limit);
        self
    }

    /// Sets the maximum number of explicit active verification requests.
    pub fn max_active_verifications(mut self, limit: u16) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_active_verifications(limit);
        self
    }

    /// Sets the maximum number of attempts for one semantic action.
    pub fn max_same_action_attempts(mut self, limit: u16) -> Self {
        self.runtime_budget = self.runtime_budget.with_max_same_action_attempts(limit);
        self
    }

    /// Sets the maximum consecutive completed execution turns without progress.
    pub fn max_consecutive_no_progress_turns(mut self, limit: u16) -> Self {
        self.runtime_budget = self
            .runtime_budget
            .with_max_consecutive_no_progress_turns(limit);
        self
    }

    /// Validates policy and composes the complete standard runtime.
    pub fn build(self) -> Result<StandardWebDecisionRuntime, StandardWebDecisionRuntimeError> {
        let policy = match self.http_policy.clone() {
            Some(policy) => policy,
            None => HttpEvidencePolicy::for_origin(self.target.clone())?,
        };
        // Preserve the public builder's historical fail-fast order. Target,
        // scope, planning, decision, and subject validation all run before the
        // reqwest-backed authority is constructed.
        self.preflight(|target| policy.require_permitted_target(target))?;
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &self.target,
            policy,
            self.runtime_budget,
            self.cancellation.clone(),
        )?;
        // Delegate through the same subject-composition seam used by the
        // assessment runtime. Its second pure preflight validates the narrowed
        // authority but cannot change the already-established public error order.
        self.build_with_shared_authority(authority)
    }

    /// Composes one subject runtime under an already-created origin authority.
    ///
    /// The authority, rather than this builder's standalone policy/budget/token
    /// fields, owns all resource and network capability. This seam remains
    /// crate-private so an assessment can create many subject runtimes without
    /// exposing a public way to mix independent authorities.
    pub(crate) fn build_with_shared_authority(
        self,
        authority: SharedWebRuntimeAuthority,
    ) -> Result<StandardWebDecisionRuntime, StandardWebDecisionRuntimeError> {
        let preflight = self.preflight(|target| authority.authorize_target(target))?;
        self.compose_with_shared_authority(authority, preflight)
    }

    fn preflight(
        &self,
        authorize: impl FnOnce(&Url) -> Result<(), HttpEvidenceError>,
    ) -> Result<StandardWebDecisionRuntimePreflight, StandardWebDecisionRuntimeError> {
        #[cfg(feature = "rest-review")]
        if self.rest_review && self.openapi_review.is_none() {
            return Err(StandardWebDecisionRuntimeError::NativeWebReviewDecisionProfile);
        }
        let probe = HttpProbe::new(self.target.clone(), HttpProbeMethod::Get)?;
        authorize(probe.url())?;

        let planning = PlanningContext::new(
            BenefitScore::from_percent(self.business_value_percent)?,
            self.planning_budget,
            RiskScore::from_percent(self.risk_limit_percent)?,
        );
        #[cfg(feature = "authorization-review")]
        let max_action_cycles = self.max_action_cycles.saturating_add(
            u32::from(self.resource_authorization_review.is_some())
                * resource_authorization_runtime::AUTHORIZATION_REVIEW_ACTION_CYCLE_ALLOWANCE,
        );
        #[cfg(not(feature = "authorization-review"))]
        let max_action_cycles = self.max_action_cycles;
        #[cfg(feature = "openapi-review")]
        let max_action_cycles = max_action_cycles.saturating_add(
            u32::from(self.openapi_review.is_some())
                * openapi_runtime::OPENAPI_REVIEW_ACTION_CYCLE_ALLOWANCE,
        );
        #[cfg(feature = "rest-review")]
        let max_action_cycles = max_action_cycles.saturating_add(
            u32::from(self.rest_review) * rest_runtime::REST_REVIEW_ACTION_CYCLE_ALLOWANCE,
        );
        #[cfg(feature = "ssrf-oast-review")]
        let max_action_cycles = max_action_cycles.saturating_add(
            u32::from(self.ssrf_oast_review.is_some())
                * ssrf_oast_runtime::SSRF_OAST_REVIEW_ACTION_CYCLE_ALLOWANCE,
        );
        let config = DecisionLoopConfig::new(
            planning,
            self.adaptation_limits,
            ExperiencePolicy::new(self.experience_failure_limit)?,
            max_action_cycles,
        )?;
        let subject = EntityId::new(format!("endpoint:{}", self.target))?;
        Ok(StandardWebDecisionRuntimePreflight { config, subject })
    }

    fn compose_with_shared_authority(
        self,
        authority: SharedWebRuntimeAuthority,
        preflight: StandardWebDecisionRuntimePreflight,
    ) -> Result<StandardWebDecisionRuntime, StandardWebDecisionRuntimeError> {
        let StandardWebDecisionRuntimePreflight { config, subject } = preflight;
        let mut decision_loop = DecisionLoop::new(config);
        let mut executors = DecisionExecutorRegistry::new();

        let knowledge = authority.knowledge();
        let requests = authority.requests().clone();
        let profile = if self.assessment_defense_projection {
            StandardWebDecisionProfile::new_with_request_broker_and_assessment_projection(
                requests.clone(),
            )?
        } else {
            StandardWebDecisionProfile::new_with_request_broker(requests.clone())?
        };
        let installation = profile.install(knowledge, &mut decision_loop, &mut executors)?;

        #[cfg(feature = "authorization-review")]
        let resource_authorization_review = self
            .resource_authorization_review
            .map(|config| {
                authority
                    .authorize_target(config.execution_resource())
                    .map_err(|_| {
                        StandardWebDecisionRuntimeError::ResourceAuthorizationReviewComposition
                    })?;
                resource_authorization_runtime::ResourceAuthorizationRuntimeBinding::new(
                    config,
                    requests.clone(),
                    subject.clone(),
                )
                .map_err(|_| {
                    StandardWebDecisionRuntimeError::ResourceAuthorizationReviewComposition
                })
            })
            .transpose()?;
        #[cfg(feature = "ssrf-oast-review")]
        let ssrf_oast_review = self.ssrf_oast_review.map(|config| {
            ssrf_oast_runtime::SsrfOastRuntimeBinding::new(
                config,
                authority.clone(),
                subject.clone(),
            )
        });
        #[cfg(feature = "openapi-review")]
        let openapi_review = self.openapi_review.map(|config| {
            #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
            if let Some(ssrf) = ssrf_oast_review.as_ref() {
                return openapi_runtime::OpenApiRuntimeBinding::new_with_ssrf_selection(
                    config,
                    requests.clone(),
                    subject.clone(),
                    knowledge.clone(),
                    ssrf.selection_slot(),
                );
            }
            openapi_runtime::OpenApiRuntimeBinding::new(
                config,
                requests.clone(),
                subject.clone(),
                knowledge.clone(),
            )
        });
        #[cfg(feature = "rest-review")]
        let rest_review = self.rest_review.then(|| {
            let selection = openapi_review
                .as_ref()
                .expect("REST preflight requires the same-run OpenAPI binding")
                .rest_selection_slot();
            rest_runtime::RestReviewBinding::new(selection, requests.clone(), subject.clone())
        });
        let native_executor_profile = match self.native_web_review {
            Some(config) => {
                let profile = {
                    #[cfg(feature = "normalization-resilience")]
                    {
                        if let (Some(parameter), Some(selection)) = (
                            config.normalization_query_parameter,
                            config.normalization_selection,
                        ) {
                            NativeWebReviewExecutorProfile::new_structural_only(
                                requests.clone(),
                                self.target.clone(),
                                config.seeds,
                                config.observer,
                                NativeWebReviewQueryParameters::normalization_only(
                                    parameter, selection,
                                ),
                            )
                        } else if let (Some(parameter), Some(selection)) =
                            (config.xss_query_parameter, config.xss_selection)
                        {
                            NativeWebReviewExecutorProfile::new_structural_only(
                                requests.clone(),
                                self.target.clone(),
                                config.seeds,
                                config.observer,
                                NativeWebReviewQueryParameters::xss_only(parameter, selection),
                            )
                        } else if config.structural_only {
                            NativeWebReviewExecutorProfile::new_structural_only(
                                requests.clone(),
                                self.target.clone(),
                                config.seeds,
                                config.observer,
                                NativeWebReviewQueryParameters::structural(
                                    config.reflection_query_parameter,
                                    config.sql_query_parameter,
                                    config.ssti_query_parameter,
                                ),
                            )
                        } else {
                            NativeWebReviewExecutorProfile::new(
                                requests.clone(),
                                self.target.clone(),
                                config.seeds,
                                config.observer,
                                NativeWebReviewQueryParameters::full(
                                    config.redirect_query_parameter,
                                    config.reflection_query_parameter,
                                    config.sql_query_parameter,
                                    config.ssti_query_parameter,
                                ),
                            )
                        }
                    }
                    #[cfg(not(feature = "normalization-resilience"))]
                    {
                        if let (Some(parameter), Some(selection)) =
                            (config.xss_query_parameter, config.xss_selection)
                        {
                            NativeWebReviewExecutorProfile::new_structural_only(
                                requests.clone(),
                                self.target.clone(),
                                config.seeds,
                                config.observer,
                                NativeWebReviewQueryParameters::xss_only(parameter, selection),
                            )
                        } else if config.structural_only {
                            NativeWebReviewExecutorProfile::new_structural_only(
                                requests.clone(),
                                self.target.clone(),
                                config.seeds,
                                config.observer,
                                NativeWebReviewQueryParameters::structural(
                                    config.reflection_query_parameter,
                                    config.sql_query_parameter,
                                    config.ssti_query_parameter,
                                ),
                            )
                        } else {
                            NativeWebReviewExecutorProfile::new(
                                requests.clone(),
                                self.target.clone(),
                                config.seeds,
                                config.observer,
                                NativeWebReviewQueryParameters::full(
                                    config.redirect_query_parameter,
                                    config.reflection_query_parameter,
                                    config.sql_query_parameter,
                                    config.ssti_query_parameter,
                                ),
                            )
                        }
                    }
                };
                Some(profile.map_err(|_| {
                    StandardWebDecisionRuntimeError::NativeWebReviewExecutionProfile
                })?)
            },
            None => None,
        };
        let native_executor_actions = native_executor_profile
            .as_ref()
            .map(|profile| profile.actions().collect::<Vec<_>>())
            .unwrap_or_default();
        #[cfg(any(
            feature = "authorization-review",
            feature = "openapi-review",
            feature = "rest-review",
            feature = "ssrf-oast-review"
        ))]
        let mut native_review_actions = native_executor_actions.clone();
        #[cfg(not(any(
            feature = "authorization-review",
            feature = "openapi-review",
            feature = "rest-review",
            feature = "ssrf-oast-review"
        )))]
        let native_review_actions = native_executor_actions.clone();
        #[cfg(feature = "authorization-review")]
        if resource_authorization_review.is_some() {
            native_review_actions.push(
                crate::web_actions::NativeWebReviewActionKind::ResourceAuthorizationDifferential,
            );
        }
        #[cfg(feature = "openapi-review")]
        if openapi_review.is_some() {
            native_review_actions
                .push(crate::web_actions::NativeWebReviewActionKind::OpenApiDocumentReplay);
        }
        #[cfg(feature = "rest-review")]
        if rest_review.is_some() {
            native_review_actions
                .push(crate::web_actions::NativeWebReviewActionKind::RestReadOnlyReplay);
        }
        #[cfg(feature = "ssrf-oast-review")]
        if ssrf_oast_review.is_some() {
            native_review_actions
                .push(crate::web_actions::NativeWebReviewActionKind::SsrfOastQueryReview);
        }
        if !native_review_actions.is_empty() {
            let profile =
                NativeWebReviewDecisionProfile::for_actions(native_review_actions.iter().copied())
                    .map_err(|_| StandardWebDecisionRuntimeError::NativeWebReviewDecisionProfile)?;
            debug_assert_eq!(profile.actions().collect::<Vec<_>>(), native_review_actions);
            let report = profile
                .install(&mut decision_loop)
                .map_err(|_| StandardWebDecisionRuntimeError::NativeWebReviewDecisionProfile)?;
            #[cfg(feature = "rest-review")]
            let rest_count = usize::from(rest_review.is_some());
            #[cfg(not(feature = "rest-review"))]
            let rest_count = 0;
            #[cfg(feature = "ssrf-oast-review")]
            let ssrf_oast_count = usize::from(ssrf_oast_review.is_some());
            #[cfg(not(feature = "ssrf-oast-review"))]
            let ssrf_oast_count = 0;
            let non_rest_count = native_review_actions
                .len()
                .saturating_sub(rest_count)
                .saturating_sub(ssrf_oast_count);
            debug_assert_eq!(
                report.reasoning_rules_inserted,
                usize::from(non_rest_count > 0) + rest_count + ssrf_oast_count
            );
            debug_assert_eq!(report.actions_inserted, native_review_actions.len());
            #[cfg(feature = "authorization-review")]
            let authorization_count = usize::from(resource_authorization_review.is_some());
            #[cfg(not(feature = "authorization-review"))]
            let authorization_count = 0;
            #[cfg(feature = "openapi-review")]
            let openapi_count = usize::from(openapi_review.is_some());
            #[cfg(not(feature = "openapi-review"))]
            let openapi_count = 0;
            debug_assert_eq!(
                report.passive_rules_inserted,
                authorization_count
                    + (2 * openapi_count)
                    + (2 * rest_count)
                    + (2 * ssrf_oast_count)
            );
            debug_assert_eq!(
                report.active_rules_inserted,
                native_review_actions.len()
                    + authorization_count
                    + openapi_count
                    + rest_count
                    + ssrf_oast_count
            );
        }

        // Surface-B multi-objective continuation: install continuation rules ONLY
        // in this runtime's adaptive pipeline. The generic AdaptivePipeline
        // fallback is unchanged, so library hosts keep single-objective semantics.
        for rule in standard_web_continuation_rules().map_err(DecisionLoopError::Adaptive)? {
            decision_loop
                .adaptive_mut()
                .register(rule)
                .map_err(DecisionLoopError::Adaptive)?;
        }
        #[cfg(feature = "authorization-review")]
        if resource_authorization_review.is_some() {
            decision_loop
                .adaptive_mut()
                .register(
                    resource_authorization_terminal_adaptation_rule()
                        .map_err(DecisionLoopError::Adaptive)?,
                )
                .map_err(DecisionLoopError::Adaptive)?;
        }
        let api_reasoning_installation = if self.api_reasoning_enabled {
            let profile = StandardApiReasoning::new()?;
            Some(profile.install(knowledge, decision_loop.rules_mut())?)
        } else {
            None
        };
        let http_evidence = HttpEvidenceExecutor::new_with_request_broker(
            requests.clone(),
            Arc::new(SubjectHttpProbeProvider::new(self.bootstrap_probe_method)),
        )?;
        let http_evidence = match self.payload_binding {
            Some(binding) => http_evidence.with_payload_binding(binding),
            None => http_evidence,
        };
        let http_evidence = match self.complete_response_observer {
            Some(observer) => http_evidence.with_complete_response_observer(observer),
            None => http_evidence,
        };
        let http_evidence = if self.assessment_defense_projection {
            http_evidence.with_assessment_defense_projection()
        } else {
            http_evidence
        };
        executors.register(Arc::new(http_evidence))?;

        if let Some(profile) = native_executor_profile {
            debug_assert_eq!(
                profile.actions().collect::<Vec<_>>(),
                native_executor_actions
            );
            let report = profile
                .install(&mut executors)
                .map_err(|_| StandardWebDecisionRuntimeError::NativeWebReviewExecutionProfile)?;
            debug_assert_eq!(report.executors_inserted(), native_executor_actions.len());
        }

        #[cfg(feature = "authorization-review")]
        if let Some(binding) = resource_authorization_review.as_ref() {
            binding
                .install_into_parent_registry(&mut executors)
                .map_err(|_| {
                    StandardWebDecisionRuntimeError::ResourceAuthorizationReviewComposition
                })?;
        }
        #[cfg(feature = "openapi-review")]
        if let Some(binding) = openapi_review.as_ref() {
            binding
                .install_into_parent_registry(&mut executors)
                .map_err(|_| StandardWebDecisionRuntimeError::NativeWebReviewExecutionProfile)?;
        }
        #[cfg(feature = "rest-review")]
        if let Some(binding) = rest_review.as_ref() {
            binding
                .install_into_parent_registry(&mut executors)
                .map_err(|_| StandardWebDecisionRuntimeError::NativeWebReviewExecutionProfile)?;
        }
        #[cfg(feature = "ssrf-oast-review")]
        if let Some(binding) = ssrf_oast_review.as_ref() {
            binding
                .install_into_parent_registry(&mut executors)
                .map_err(|_| StandardWebDecisionRuntimeError::NativeWebReviewExecutionProfile)?;
        }

        let mut unsupported_actions: BTreeSet<_> = StandardWebActionKind::all()
            .into_iter()
            .filter(|kind| !executors.contains(kind.executor_id()))
            .map(|kind| kind.action_id().to_owned())
            .collect();
        unsupported_actions.extend(self.additional_suppressed_actions);

        Ok(StandardWebDecisionRuntime {
            target: self.target,
            subject: subject.clone(),
            installation,
            api_reasoning_installation,
            unsupported_actions,
            decision_loop,
            runner: DecisionRunnerAdapter::new(executors),
            experience: self.experience,
            session: DecisionSession::new(subject),
            authority,
            usage: RuntimeUsage::default(),
            started: false,
            assessment_defense: self
                .assessment_defense_projection
                .then(|| AssessmentDefenseController::new(self.assessment_defense_enforcement)),
            #[cfg(feature = "authorization-review")]
            resource_authorization_review,
            #[cfg(feature = "openapi-review")]
            openapi_review,
            #[cfg(feature = "rest-review")]
            rest_review,
            #[cfg(feature = "ssrf-oast-review")]
            ssrf_oast_review,
        })
    }
}

/// Single-use target runtime for evidence collection and deterministic decisions.
///
/// # Examples
///
/// ```rust,no_run
/// use url::Url;
/// use termivar_scanner::StandardWebDecisionRuntime;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let target = Url::parse("https://example.test/")?;
/// let mut runtime = StandardWebDecisionRuntime::builder(target)
///     .planning_budget(100)
///     .risk_limit(40)
///     .max_action_cycles(8)
///     .enable_api_reasoning()
///     .build()?;
///
/// let report = runtime.analyze().await?;
/// println!("terminal command: {:?}", report.terminal());
/// # Ok(())
/// # }
/// ```
pub struct StandardWebDecisionRuntime {
    target: Url,
    subject: EntityId,
    installation: StandardWebDecisionInstallReport,
    api_reasoning_installation: Option<StandardApiInstallReport>,
    unsupported_actions: BTreeSet<String>,
    decision_loop: DecisionLoop,
    runner: DecisionRunnerAdapter,
    experience: ExperienceStore,
    session: DecisionSession,
    authority: SharedWebRuntimeAuthority,
    usage: RuntimeUsage,
    started: bool,
    assessment_defense: Option<AssessmentDefenseController>,
    #[cfg(feature = "authorization-review")]
    resource_authorization_review:
        Option<resource_authorization_runtime::ResourceAuthorizationRuntimeBinding>,
    #[cfg(feature = "openapi-review")]
    openapi_review: Option<openapi_runtime::OpenApiRuntimeBinding>,
    #[cfg(feature = "rest-review")]
    rest_review: Option<rest_runtime::RestReviewBinding>,
    #[cfg(feature = "ssrf-oast-review")]
    ssrf_oast_review: Option<ssrf_oast_runtime::SsrfOastRuntimeBinding>,
}

impl StandardWebDecisionRuntime {
    /// Starts a target-scoped runtime builder.
    pub fn builder(target: Url) -> StandardWebDecisionRuntimeBuilder {
        StandardWebDecisionRuntimeBuilder::new(target)
    }

    /// Returns the authorized target supplied by the host.
    pub fn target(&self) -> &Url {
        &self.target
    }

    /// Returns the stable endpoint subject used by every runtime layer.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the standard profile installation receipt.
    pub fn installation(&self) -> StandardWebDecisionInstallReport {
        self.installation
    }

    /// Returns the passive API reasoning installation receipt when enabled.
    pub fn api_reasoning_installation(&self) -> Option<StandardApiInstallReport> {
        self.api_reasoning_installation
    }

    /// Returns actions omitted because no executor was installed for them.
    pub fn unsupported_actions(&self) -> &BTreeSet<String> {
        &self.unsupported_actions
    }

    /// Returns the runtime knowledge base for audit and reporting.
    pub fn knowledge(&self) -> &KnowledgeBase {
        self.authority.knowledge()
    }

    /// Returns learned target-scoped outcomes.
    pub fn experience(&self) -> &ExperienceStore {
        &self.experience
    }

    /// Returns the replayable session state.
    pub fn session(&self) -> &DecisionSession {
        &self.session
    }

    /// Returns the immutable resource envelope for this session.
    pub const fn budget(&self) -> RuntimeBudget {
        self.authority.budget()
    }

    /// Returns current resource accounting, including failed request attempts.
    pub fn usage(&self) -> &RuntimeUsage {
        &self.usage
    }

    /// Returns a clone of the host-owned cancellation token.
    ///
    /// Cancelling the returned token stops this single-use runtime at its next
    /// async or deterministic planning boundary.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.authority.cancellation_token()
    }

    /// Returns whether execution has been attempted.
    pub fn has_started(&self) -> bool {
        self.started
    }

    /// Consumes the runtime and returns its learned experience.
    pub fn into_experience(self) -> ExperienceStore {
        self.experience
    }

    fn action_suppression_context(&self) -> Result<ActionSuppressionContext, ()> {
        let defense = match &self.assessment_defense {
            Some(controller) => controller
                .defense_suppressed_actions(&self.subject, self.decision_loop.planner())?,
            None => BTreeSet::new(),
        };
        Ok(ActionSuppressionContext::new(
            self.unsupported_actions.clone(),
            defense,
        ))
    }

    fn ingest_assessment_defense(
        &mut self,
        receipt: &DecisionEvidenceReceipt,
        require_projection: bool,
    ) -> Result<(), ()> {
        let Some(controller) = self.assessment_defense.as_mut() else {
            return Ok(());
        };
        controller.ingest_receipt(receipt, self.authority.knowledge(), require_projection)
    }

    fn record_assessment_defense_shadow(
        &mut self,
        report: &DecisionPlanningReport,
    ) -> Result<(), ()> {
        let Some(controller) = self.assessment_defense.as_mut() else {
            return Ok(());
        };
        let planner = self.decision_loop.planner().clone();
        controller.record_shadow(report, &planner)
    }

    pub(crate) fn assessment_defense_controller(&self) -> Option<&AssessmentDefenseController> {
        self.assessment_defense.as_ref()
    }

    pub(crate) fn assessment_planner(&self) -> &crate::AttackPlanner {
        self.decision_loop.planner()
    }

    #[cfg(feature = "authorization-review")]
    pub(in crate::web_runtime) fn take_resource_authorization_review(
        &mut self,
    ) -> Option<resource_authorization_runtime::ResourceAuthorizationRuntimeBinding> {
        self.resource_authorization_review.take()
    }

    #[cfg(feature = "openapi-review")]
    pub(in crate::web_runtime) fn take_openapi_review(
        &mut self,
    ) -> Option<openapi_runtime::OpenApiRuntimeBinding> {
        self.openapi_review.take()
    }

    #[cfg(feature = "rest-review")]
    pub(in crate::web_runtime) fn take_rest_review(
        &mut self,
    ) -> Option<rest_runtime::RestReviewBinding> {
        self.rest_review.take()
    }

    #[cfg(feature = "ssrf-oast-review")]
    pub(in crate::web_runtime) fn take_ssrf_oast_review(
        &mut self,
    ) -> Option<ssrf_oast_runtime::SsrfOastRuntimeBinding> {
        self.ssrf_oast_review.take()
    }

    /// Collects bootstrap evidence and drives commands to a terminal state.
    ///
    /// The runtime is single-use even when execution returns an error. This
    /// prevents a caller from replaying a partially committed network session
    /// under the same deterministic case identities.
    pub async fn analyze(
        &mut self,
    ) -> Result<StandardWebDecisionRunReport, StandardWebDecisionRuntimeError> {
        if self.started {
            return Err(StandardWebDecisionRuntimeError::AlreadyStarted);
        }
        self.started = true;
        let timing = self.authority.start();
        let started_at = timing.started_at();
        let deadline = timing.deadline();
        let mut turns = Vec::new();

        if self.authority.cancellation().is_cancelled() {
            return Ok(self.cancellation_report(None, turns, None, started_at));
        }

        let bootstrap_case = match VerificationCase::new(
            BOOTSTRAP_CASE_ID,
            self.subject.clone(),
            BOOTSTRAP_ACTION_ID,
            BOOTSTRAP_HYPOTHESIS_ID,
        ) {
            Ok(case) => case,
            Err(source) => {
                return Err(self.run_failed(None, turns, source.into(), started_at));
            },
        };
        let bootstrap_command = DecisionLoopCommand::ExecuteAction {
            case: bootstrap_case,
            executor: Some(HTTP_EVIDENCE_EXECUTOR_ID.to_owned()),
            origin: DecisionActionOrigin::Bootstrap,
            delay_ms: None,
        };
        let (bootstrap_action_id, bootstrap_stage) = match execution_metadata(&bootstrap_command) {
            Ok(metadata) => metadata,
            Err(source) => {
                return Err(self.run_failed(None, turns, source, started_at));
            },
        };
        // Bootstrap is always the transport-bound HTTP evidence probe.
        let bootstrap_limits = match self.reserve_execution(
            bootstrap_action_id,
            bootstrap_stage,
            DecisionExecutionClass::TransportBound,
            started_at,
        ) {
            Ok(limits) => limits,
            Err(limit) => {
                if self.authority.cancellation().is_cancelled() {
                    return Ok(self.cancellation_report(None, turns, None, started_at));
                }
                return Ok(self.limit_report(None, turns, limit, started_at));
            },
        };
        if self.authority.cancellation().is_cancelled() {
            return Ok(self.cancellation_report(None, turns, None, started_at));
        }
        let bootstrap_result = await_execution(
            self.authority.cancellation(),
            deadline,
            self.runner.execute_command_with_limits(
                &bootstrap_command,
                self.authority.knowledge(),
                bootstrap_limits,
            ),
        )
        .await;
        let bootstrap = match bootstrap_result {
            RuntimeExecution::Completed(Ok(receipt)) => {
                self.refresh_elapsed(started_at);
                receipt
            },
            RuntimeExecution::Completed(Err(error)) => {
                self.refresh_elapsed(started_at);
                if let Some(limit) = error.runtime_limit().cloned() {
                    let failure = error.into_execution_failure();
                    return Ok(
                        self.limit_report_with_failure(None, turns, limit, failure, started_at)
                    );
                }
                return Err(self.run_failed(None, turns, error.into(), started_at));
            },
            RuntimeExecution::Cancelled => {
                return Ok(self.cancellation_report(None, turns, None, started_at));
            },
            RuntimeExecution::WallTimeExceeded => {
                let limit = self.wall_limit(started_at);
                return Ok(self.limit_report(None, turns, limit, started_at));
            },
        };
        let bootstrap = match self
            .validate_response_usage_evidence(bootstrap, DecisionExecutionClass::TransportBound)
        {
            Ok(receipt) => receipt,
            Err(source) => {
                let committed_bootstrap = source.committed_evidence().cloned();
                return Err(self.run_failed(committed_bootstrap, turns, source, started_at));
            },
        };
        if self.ingest_assessment_defense(&bootstrap, true).is_err() {
            let source = StandardWebDecisionRuntimeError::AssessmentDefenseProjectionInvariant {
                receipt: Box::new(bootstrap),
            };
            let committed_bootstrap = source.committed_evidence().cloned();
            return Err(self.run_failed(committed_bootstrap, turns, source, started_at));
        }
        if let Some(limit) = self.response_limit_if_exceeded(BOOTSTRAP_ACTION_ID) {
            return Ok(self.limit_report(Some(bootstrap), turns, limit, started_at));
        }
        let bootstrap = Some(bootstrap);

        if self.authority.cancellation().is_cancelled() {
            return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
        }

        let mut command = DecisionLoopCommand::Replan;
        // Deterministic representatives for the synthesized aggregate terminal:
        // the first success case, and the first unresolved (blocked /
        // active-inconclusive) case, in dispatch order.
        let mut representative_success: Option<VerificationCase> = None;
        let mut representative_unresolved: Option<VerificationCase> = None;
        let terminal = loop {
            match &command {
                DecisionLoopCommand::Replan => {
                    if self.authority.cancellation().is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    if let Some(limit) = self.wall_limit_if_reached(started_at) {
                        return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                    }
                    let suppressions = match self.action_suppression_context() {
                        Ok(value) => value,
                        Err(()) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                StandardWebDecisionRuntimeError::AssessmentDefensePlanningInvariant,
                                started_at,
                            ));
                        },
                    };
                    let planning = match self.decision_loop.plan_next_with_action_suppressions(
                        self.authority.knowledge(),
                        &self.experience,
                        &mut self.session,
                        &suppressions,
                    ) {
                        Ok(planning) => planning,
                        Err(source) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                source.into(),
                                started_at,
                            ));
                        },
                    };
                    if self.record_assessment_defense_shadow(&planning).is_err() {
                        return Err(self.run_failed(
                            bootstrap,
                            turns,
                            StandardWebDecisionRuntimeError::AssessmentDefensePlanningInvariant,
                            started_at,
                        ));
                    }
                    command = planning.command().clone();
                    turns.push(StandardWebDecisionRuntimeTurn::Planning(Box::new(planning)));
                    if self.authority.cancellation().is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    if is_terminal(&command) {
                        break command.clone();
                    }
                    if let Some(limit) = self.wall_limit_if_reached(started_at) {
                        return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                    }
                },
                DecisionLoopCommand::ExecuteAction { .. }
                | DecisionLoopCommand::CollectActiveEvidence { .. } => {
                    if self.authority.cancellation().is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    let predispatch_suppressions = match self.action_suppression_context() {
                        Ok(value) => value,
                        Err(()) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                StandardWebDecisionRuntimeError::AssessmentDefensePlanningInvariant,
                                started_at,
                            ));
                        },
                    };
                    match self
                        .runner
                        .validate_command_suppression(&command, &predispatch_suppressions)
                    {
                        Err(source @ DecisionRunnerError::ActionSuppressedByDefense { .. }) => {
                            if let Err(source) =
                                self.decision_loop.validate_execution_command_authority(
                                    self.authority.knowledge(),
                                    &command,
                                )
                            {
                                return Err(self.run_failed(
                                    bootstrap,
                                    turns,
                                    source.into(),
                                    started_at,
                                ));
                            }
                            match self.runner.replan_defense_suppressed_command(
                                &command,
                                &mut self.session,
                                &predispatch_suppressions,
                            ) {
                                Ok(true) => {
                                    command = DecisionLoopCommand::Replan;
                                    continue;
                                },
                                Ok(false) => {
                                    return Err(self.run_failed(
                                        bootstrap,
                                        turns,
                                        source.into(),
                                        started_at,
                                    ));
                                },
                                Err(source) => {
                                    return Err(self.run_failed(
                                        bootstrap,
                                        turns,
                                        source.into(),
                                        started_at,
                                    ));
                                },
                            }
                        },
                        Err(source) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                source.into(),
                                started_at,
                            ));
                        },
                        Ok(()) => {},
                    }
                    let (action_id, previous_stage) = match execution_metadata(&command) {
                        Ok(metadata) => metadata,
                        Err(source) => {
                            return Err(self.run_failed(bootstrap, turns, source, started_at));
                        },
                    };
                    let execution_class = match self.runner.execution_class_for_command(&command) {
                        Ok(class) => class,
                        Err(source) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                source.into(),
                                started_at,
                            ));
                        },
                    };
                    let completed_action_id = action_id.to_owned();
                    let limits = match self.reserve_execution(
                        action_id,
                        previous_stage,
                        execution_class,
                        started_at,
                    ) {
                        Ok(limits) => limits,
                        Err(limit) => {
                            if self.authority.cancellation().is_cancelled() {
                                return Ok(
                                    self.cancellation_report(bootstrap, turns, None, started_at)
                                );
                            }
                            return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                        },
                    };
                    if self.authority.cancellation().is_cancelled() {
                        return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                    }
                    let evidence_result = await_execution(
                        self.authority.cancellation(),
                        deadline,
                        self.runner.execute_session_command_with_limits(
                            &command,
                            self.authority.knowledge(),
                            &self.session,
                            limits,
                        ),
                    )
                    .await;
                    let evidence = match evidence_result {
                        RuntimeExecution::Completed(Ok(receipt)) => {
                            self.refresh_elapsed(started_at);
                            receipt
                        },
                        RuntimeExecution::Completed(Err(error)) => {
                            self.refresh_elapsed(started_at);
                            if let Some(limit) = error.runtime_limit().cloned() {
                                let failure = error.into_execution_failure();
                                return Ok(self.limit_report_with_failure(
                                    bootstrap, turns, limit, failure, started_at,
                                ));
                            }
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                error.into(),
                                started_at,
                            ));
                        },
                        RuntimeExecution::Cancelled => {
                            return Ok(self.cancellation_report(bootstrap, turns, None, started_at));
                        },
                        RuntimeExecution::WallTimeExceeded => {
                            let limit = self.wall_limit(started_at);
                            return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                        },
                    };
                    let evidence =
                        match self.validate_response_usage_evidence(evidence, execution_class) {
                            Ok(receipt) => receipt,
                            Err(source) => {
                                return Err(self.run_failed(bootstrap, turns, source, started_at));
                            },
                        };
                    if self
                        .ingest_assessment_defense(
                            &evidence,
                            execution_class == DecisionExecutionClass::TransportBound,
                        )
                        .is_err()
                    {
                        let source =
                            StandardWebDecisionRuntimeError::AssessmentDefenseProjectionInvariant {
                                receipt: Box::new(evidence),
                            };
                        return Err(self.run_failed(bootstrap, turns, source, started_at));
                    }
                    // Cumulative response-byte enforcement is a transport concern;
                    // a local-knowledge action delivers no response bytes.
                    if execution_class == DecisionExecutionClass::TransportBound {
                        if let Some(limit) = self.response_limit_if_exceeded(&completed_action_id) {
                            return Ok(self.limit_report_with_unverified_evidence(
                                bootstrap, turns, evidence, limit, started_at,
                            ));
                        }
                    }
                    if self.authority.cancellation().is_cancelled() {
                        return Ok(self.cancellation_report(
                            bootstrap,
                            turns,
                            Some(evidence),
                            started_at,
                        ));
                    }
                    let resume_suppressions = match self.action_suppression_context() {
                        Ok(value) => value,
                        Err(()) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                StandardWebDecisionRuntimeError::AssessmentDefensePlanningInvariant,
                                started_at,
                            ));
                        },
                    };
                    let runner_turn = self.runner.resume_session_command_with_action_suppressions(
                        &self.decision_loop,
                        &command,
                        self.authority.knowledge(),
                        &mut self.experience,
                        &mut self.session,
                        ContinuationAuthority::new(evidence, &resume_suppressions),
                    );
                    self.refresh_elapsed(started_at);
                    let runner_turn = match runner_turn {
                        Ok(turn) => turn,
                        Err(source) => {
                            return Err(self.run_failed(
                                bootstrap,
                                turns,
                                source.into(),
                                started_at,
                            ));
                        },
                    };
                    match runner_turn {
                        DecisionRunnerTurn::Planning(planning) => {
                            if self.record_assessment_defense_shadow(&planning).is_err() {
                                return Err(self.run_failed(
                                    bootstrap,
                                    turns,
                                    StandardWebDecisionRuntimeError::
                                        AssessmentDefensePlanningInvariant,
                                    started_at,
                                ));
                            }
                            command = planning.command().clone();
                            turns.push(StandardWebDecisionRuntimeTurn::Planning(planning));
                            if is_terminal(&command) {
                                break command.clone();
                            }
                            if self.authority.cancellation().is_cancelled() {
                                return Ok(
                                    self.cancellation_report(bootstrap, turns, None, started_at)
                                );
                            }
                        },
                        DecisionRunnerTurn::Outcome { evidence, decision } => {
                            command = decision.command().clone();
                            let progressed =
                                outcome_made_progress(previous_stage, &command, decision.as_ref());
                            self.usage.record_execution_progress(progressed);
                            classify_continuation_case(
                                decision.as_ref(),
                                &mut representative_success,
                                &mut representative_unresolved,
                            );
                            turns.push(StandardWebDecisionRuntimeTurn::Outcome {
                                evidence,
                                decision,
                            });
                            if is_terminal(&command) {
                                break command.clone();
                            }
                            if self.authority.cancellation().is_cancelled() {
                                return Ok(
                                    self.cancellation_report(bootstrap, turns, None, started_at)
                                );
                            }
                            if self.usage.consecutive_no_progress_turns()
                                >= self.authority.budget().max_consecutive_no_progress_turns()
                                && !progressed
                            {
                                let limit = RuntimeLimitExceeded::new(
                                    RuntimeBudgetDimension::ConsecutiveNoProgressTurns,
                                    u64::from(
                                        self.authority.budget().max_consecutive_no_progress_turns(),
                                    ),
                                    u64::from(self.usage.consecutive_no_progress_turns()),
                                    Some(completed_action_id),
                                );
                                return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                            }
                            if let Some(limit) = self.wall_limit_if_reached(started_at) {
                                return Ok(self.limit_report(bootstrap, turns, limit, started_at));
                            }
                        },
                        DecisionRunnerTurn::Terminal(terminal) => break terminal,
                    }
                },
                DecisionLoopCommand::Complete { .. }
                | DecisionLoopCommand::AwaitHumanReview { .. }
                | DecisionLoopCommand::Halt { .. } => break command.clone(),
            }
        };

        // Synthesize the aggregate terminal from the recorded outcomes, and keep
        // the session state in agreement with it.
        let terminal = self.finalize_multi_objective_terminal(
            terminal,
            representative_success,
            representative_unresolved,
        );

        self.refresh_elapsed(started_at);

        Ok(StandardWebDecisionRunReport {
            bootstrap,
            turns,
            unverified_evidence: None,
            terminal,
            usage: self.usage.clone(),
            transport: self.authority.request_accounting().dispatch_audit(),
            limit_exceeded: None,
            execution_failure: None,
        })
    }

    /// Synthesizes the aggregate terminal for a multi-objective session once
    /// automated work is exhausted, and keeps `session().state()` in agreement.
    ///
    /// Synthesis applies ONLY to natural exhaustion (`Halt { NoEligibleAction }`).
    /// Every hard safety terminal — cycle/adaptation limits reaching here, and
    /// the budget/wall-time/cancellation reports that return earlier — is
    /// absolute and returned unchanged. Uses the existing terminal vocabulary:
    /// unresolved cases -> `AwaitHumanReview`; else a success -> `Complete`; else
    /// the untouched `Halt { NoEligibleAction }`.
    fn finalize_multi_objective_terminal(
        &mut self,
        terminal: DecisionLoopCommand,
        representative_success: Option<VerificationCase>,
        representative_unresolved: Option<VerificationCase>,
    ) -> DecisionLoopCommand {
        if !matches!(
            terminal,
            DecisionLoopCommand::Halt {
                reason: DecisionStopReason::NoEligibleAction
            }
        ) {
            return terminal;
        }
        if let Some(case) = representative_unresolved {
            self.session.finalize_human_review();
            DecisionLoopCommand::AwaitHumanReview { case }
        } else if let Some(case) = representative_success {
            self.session.finalize_objective_complete();
            DecisionLoopCommand::Complete { case }
        } else {
            terminal
        }
    }

    fn run_failed(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        completed_turns: Vec<StandardWebDecisionRuntimeTurn>,
        source: StandardWebDecisionRuntimeError,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRuntimeError {
        self.refresh_elapsed(started_at);
        StandardWebDecisionRuntimeError::RunFailed {
            receipt: Box::new(StandardWebDecisionFailureReceipt {
                bootstrap,
                completed_turns,
                usage: self.usage.clone(),
                transport: self.authority.request_accounting().dispatch_audit(),
            }),
            source: Box::new(source),
        }
    }

    fn reserve_execution(
        &mut self,
        action_id: &str,
        stage: DecisionExecutionStage,
        execution_class: DecisionExecutionClass,
        started_at: tokio::time::Instant,
    ) -> Result<DecisionExecutionLimits, RuntimeLimitExceeded> {
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Err(limit);
        }
        // The transport-bound path is preserved byte-for-byte: request preflight,
        // then the semantic action-attempt guard, then the response allowance.
        // The local-knowledge path applies only the semantic guard — no request
        // preflight and no response-byte allowance, because it makes no request.
        match execution_class {
            DecisionExecutionClass::TransportBound => {
                self.sync_request_accounting();
                let preflight = self
                    .authority
                    .request_accounting()
                    .preflight(action_id, stage)?;
                self.reserve_action_attempt(action_id)?;
                Ok(DecisionExecutionLimits::new()
                    .with_max_response_body_bytes(preflight.remaining_response_bytes()))
            },
            DecisionExecutionClass::LocalKnowledge => {
                self.reserve_action_attempt(action_id)?;
                Ok(DecisionExecutionLimits::new())
            },
        }
    }

    /// Enforces and reserves the semantic same-action-attempt guard, which
    /// applies to every execution class.
    fn reserve_action_attempt(&mut self, action_id: &str) -> Result<(), RuntimeLimitExceeded> {
        let attempts = self.usage.same_action_attempts(action_id);
        if attempts >= self.authority.budget().max_same_action_attempts() {
            return Err(RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::SameActionAttempts,
                u64::from(self.authority.budget().max_same_action_attempts()),
                u64::from(attempts).saturating_add(1),
                Some(action_id.to_owned()),
            ));
        }
        self.usage.reserve_action_attempt(action_id);
        Ok(())
    }

    fn validate_response_usage_evidence(
        &mut self,
        receipt: DecisionEvidenceReceipt,
        execution_class: DecisionExecutionClass,
    ) -> Result<DecisionEvidenceReceipt, StandardWebDecisionRuntimeError> {
        // HTTP response telemetry is a transport-bound invariant only. A
        // local-knowledge action performs no request and emits no response-body
        // observation, so the requirement does not apply to it.
        if execution_class == DecisionExecutionClass::LocalKnowledge {
            return Ok(receipt);
        }
        let response_body_bytes =
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge();
        let correlated: Vec<_> = receipt
            .evidence()
            .iter()
            .filter(|evidence| {
                evidence.source().correlation_id() == Some(receipt.case().id())
                    && evidence.predicate() == &response_body_bytes
            })
            .filter_map(|evidence| match evidence.value() {
                EvidenceValue::Unsigned(bytes) => Some(*bytes),
                _ => None,
            })
            .collect();
        if correlated.len() != 1 {
            return Err(StandardWebDecisionRuntimeError::ResponseUsageEvidence {
                case_id: receipt.case().id().to_owned(),
                predicate: HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.dotted(),
                observations: correlated.len(),
                receipt: Box::new(receipt),
            });
        }
        Ok(receipt)
    }

    fn response_limit_if_exceeded(&mut self, action_id: &str) -> Option<RuntimeLimitExceeded> {
        self.sync_request_accounting();
        let observed = self.usage.response_bytes();
        (observed > self.authority.budget().max_response_bytes()).then(|| {
            RuntimeLimitExceeded::new(
                RuntimeBudgetDimension::ResponseBytes,
                self.authority.budget().max_response_bytes(),
                observed,
                Some(action_id.to_owned()),
            )
        })
    }

    fn sync_request_accounting(&mut self) {
        self.usage
            .sync_request_accounting(self.authority.request_accounting().snapshot());
    }

    fn refresh_elapsed(&mut self, started_at: tokio::time::Instant) {
        self.sync_request_accounting();
        self.usage.set_elapsed(started_at.elapsed());
    }

    fn wall_limit_if_reached(
        &mut self,
        started_at: tokio::time::Instant,
    ) -> Option<RuntimeLimitExceeded> {
        self.refresh_elapsed(started_at);
        (started_at.elapsed() >= self.authority.budget().max_wall_time())
            .then(|| self.wall_limit(started_at))
    }

    fn wall_limit(&mut self, started_at: tokio::time::Instant) -> RuntimeLimitExceeded {
        self.refresh_elapsed(started_at);
        RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::WallTime,
            self.authority.budget().max_wall_time_ms(),
            self.usage
                .elapsed_ms()
                .max(self.authority.budget().max_wall_time_ms()),
            None,
        )
    }

    fn limit_report(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        limit: RuntimeLimitExceeded,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.limit_report_with_failure(bootstrap, turns, limit, None, started_at)
    }

    fn limit_report_with_failure(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        limit: RuntimeLimitExceeded,
        execution_failure: Option<DecisionExecutionFailureReceipt>,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.refresh_elapsed(started_at);
        self.session.halt_for_runtime_budget();
        StandardWebDecisionRunReport {
            bootstrap,
            turns,
            unverified_evidence: None,
            terminal: DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::RuntimeBudgetLimit,
            },
            usage: self.usage.clone(),
            transport: self.authority.request_accounting().dispatch_audit(),
            limit_exceeded: Some(limit),
            execution_failure,
        }
    }

    fn limit_report_with_unverified_evidence(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        evidence: DecisionEvidenceReceipt,
        limit: RuntimeLimitExceeded,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.refresh_elapsed(started_at);
        self.session.halt_for_runtime_budget();
        StandardWebDecisionRunReport {
            bootstrap,
            turns,
            unverified_evidence: Some(evidence),
            terminal: DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::RuntimeBudgetLimit,
            },
            usage: self.usage.clone(),
            transport: self.authority.request_accounting().dispatch_audit(),
            limit_exceeded: Some(limit),
            execution_failure: None,
        }
    }

    fn cancellation_report(
        &mut self,
        bootstrap: Option<DecisionEvidenceReceipt>,
        turns: Vec<StandardWebDecisionRuntimeTurn>,
        unverified_evidence: Option<DecisionEvidenceReceipt>,
        started_at: tokio::time::Instant,
    ) -> StandardWebDecisionRunReport {
        self.refresh_elapsed(started_at);
        self.session.halt_for_host_cancellation();
        StandardWebDecisionRunReport {
            bootstrap,
            turns,
            unverified_evidence,
            terminal: DecisionLoopCommand::Halt {
                reason: crate::DecisionStopReason::CancelledByHost,
            },
            usage: self.usage.clone(),
            transport: self.authority.request_accounting().dispatch_audit(),
            limit_exceeded: None,
            execution_failure: None,
        }
    }
}

enum RuntimeExecution<T> {
    Completed(T),
    Cancelled,
    WallTimeExceeded,
}

async fn await_execution<F, T>(
    cancellation: &CancellationToken,
    deadline: Option<tokio::time::Instant>,
    execution: F,
) -> RuntimeExecution<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(execution);
    match deadline {
        Some(deadline) => {
            tokio::select! {
                // A ready execution result wins so a receipt produced by an
                // already-completed evidence commit is never discarded. When
                // both stop signals are ready, explicit host cancellation is
                // more specific than the wall-time fallback.
                biased;
                result = &mut execution => RuntimeExecution::Completed(result),
                () = cancellation.cancelled() => RuntimeExecution::Cancelled,
                () = tokio::time::sleep_until(deadline) => RuntimeExecution::WallTimeExceeded,
            }
        },
        None => {
            tokio::select! {
                biased;
                result = &mut execution => RuntimeExecution::Completed(result),
                () = cancellation.cancelled() => RuntimeExecution::Cancelled,
            }
        },
    }
}

fn execution_metadata(
    command: &DecisionLoopCommand,
) -> Result<(&str, DecisionExecutionStage), StandardWebDecisionRuntimeError> {
    match command {
        DecisionLoopCommand::ExecuteAction { case, .. } => {
            Ok((case.action_id(), DecisionExecutionStage::Passive))
        },
        DecisionLoopCommand::CollectActiveEvidence { case } => {
            Ok((case.action_id(), DecisionExecutionStage::Active))
        },
        DecisionLoopCommand::Replan
        | DecisionLoopCommand::Complete { .. }
        | DecisionLoopCommand::AwaitHumanReview { .. }
        | DecisionLoopCommand::Halt { .. } => {
            Err(StandardWebDecisionRuntimeError::ExecutionMetadataUnavailable)
        },
    }
}

fn is_terminal(command: &DecisionLoopCommand) -> bool {
    matches!(
        command,
        DecisionLoopCommand::Complete { .. }
            | DecisionLoopCommand::AwaitHumanReview { .. }
            | DecisionLoopCommand::Halt { .. }
    )
}

/// Records a representative case for the aggregate terminal when a continuation
/// rule suppressed this action. A suppressed `Success` is a completed objective;
/// a suppressed `Blocked` or active-inconclusive (`Unknown`/`NeedsReview`) is an
/// unresolved case pending human review. `FalsePositive`/`ConfirmedNegative`
/// (also carried on `Replan { suppress }` by the unchanged fallback) are
/// conclusive negatives and count as neither. First-in-dispatch-order wins.
fn classify_continuation_case(
    decision: &DecisionOutcomeReport,
    representative_success: &mut Option<VerificationCase>,
    representative_unresolved: &mut Option<VerificationCase>,
) {
    if !matches!(
        decision.adaptive().directive(),
        PipelineDirective::Replan {
            suppress_current_action: true
        }
    ) {
        return;
    }
    let report = decision.verification();
    match report.outcome().status() {
        OutcomeStatus::Success => {
            representative_success.get_or_insert_with(|| report.case().clone());
        },
        OutcomeStatus::Blocked => {
            representative_unresolved.get_or_insert_with(|| report.case().clone());
        },
        OutcomeStatus::Unknown | OutcomeStatus::NeedsReview
            if report.outcome().stage() == VerificationStage::Active =>
        {
            representative_unresolved.get_or_insert_with(|| report.case().clone());
        },
        _ => {},
    }
}

/// Surface-B multi-objective continuation rules.
///
/// After an action reaches a terminal-worthy outcome, suppress it (via the
/// existing adaptation-ledger suppression carried by `Replan { suppress_current_
/// action: true }`) and replan, so the runtime can pursue another eligible
/// discovery objective instead of stopping at the first. Outcome classification
/// is never altered — only the follow-on directive. Passive inconclusive
/// outcomes still escalate through the unchanged fallback
/// (`AwaitActiveVerification`); false-positive / confirmed-negative also keep the
/// unchanged fallback (`Replan { suppress }`).
fn standard_web_continuation_rules() -> Result<Vec<AdaptationRule>, AdaptivePipelineError> {
    let suppress = PipelineDirective::Replan {
        suppress_current_action: true,
    };
    Ok(vec![
        AdaptationRule::new(
            "web.continue.success",
            OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::Success]))?,
            700,
            None,
            suppress.clone(),
            "record the success and continue to any other eligible objective",
            u16::MAX,
        )?,
        AdaptationRule::new(
            "web.continue.blocked",
            OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::Blocked]))?,
            700,
            None,
            suppress.clone(),
            "record the blocked outcome and continue to any other eligible objective",
            u16::MAX,
        )?,
        AdaptationRule::new(
            "web.continue.active-inconclusive",
            OutcomeSelector::new(
                BTreeSet::from([OutcomeStatus::Unknown, OutcomeStatus::NeedsReview]),
                BTreeSet::from([VerificationStage::Active]),
            )?,
            700,
            None,
            suppress,
            "record the inconclusive outcome after active verification and continue",
            u16::MAX,
        )?,
    ])
}

#[cfg(feature = "authorization-review")]
fn resource_authorization_terminal_adaptation_rule() -> Result<AdaptationRule, AdaptivePipelineError>
{
    AdaptationRule::new(
        "web.authorization-review.stop-after-terminal-phase@1",
        OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::Blocked]))?,
        1_000,
        Some(Expression::equals(
            KnowledgeLayer::Evidence,
            crate::web_actions::authorization_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(true),
        )),
        PipelineDirective::Halt,
        "stop optional network work after authorization review defense, rate-limit, or incomplete transport evidence",
        1,
    )
}

fn outcome_made_progress(
    previous_stage: DecisionExecutionStage,
    next_command: &DecisionLoopCommand,
    outcome: &DecisionOutcomeReport,
) -> bool {
    let hypothesis_changed = matches!(
        outcome.hypothesis_write(),
        Some(KnowledgeWrite::Inserted | KnowledgeWrite::Updated)
    );
    let escalated_to_active = previous_stage == DecisionExecutionStage::Passive
        && matches!(
            next_command,
            DecisionLoopCommand::CollectActiveEvidence { .. }
        );
    let conclusive = matches!(
        outcome.verification().outcome().status(),
        OutcomeStatus::Success | OutcomeStatus::FalsePositive | OutcomeStatus::ConfirmedNegative
    );
    // A suppression-driven replan is genuine forward progress: the source action
    // is newly added to the adaptation suppression set, so the automated
    // candidate set strictly shrinks. This is NOT true of arbitrary replans —
    // only of `Replan { suppress_current_action: true }`.
    let suppressed_source = matches!(
        outcome.adaptive().directive(),
        PipelineDirective::Replan {
            suppress_current_action: true
        }
    );
    hypothesis_changed || escalated_to_active || conclusive || suppressed_source
}

#[cfg(test)]
#[path = "web_runtime_tests.rs"]
mod tests;
