//! Parent-native query-only SSRF review backed by the narrowing OAST provider.
//!
//! The binding owns no independent authority. Target requests use the parent
//! exact-origin broker and provider work is minted exactly once from the same
//! parent budget, cancellation token, and deadline.

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    HttpEvidencePredicate, KnowledgePredicate,
};
use termivar_oast::{CallbackId, PublicOrigin};

use super::{
    assessment_defense::{project_assessment_defense_signal, AssessmentDefenseProjectionContext},
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext, StableAssessmentSubjectId,
    },
    SharedWebRuntimeAuthority,
};
use crate::{
    http_evidence::HttpRequestBrokerError,
    native_oast_provider::{
        NativeOastProviderAdapter, NativeOastProviderConfiguration, NativeOastProviderErrorKind,
        NativeOastProviderLimits, NativeOastProviderOperation,
    },
    oast::{OastCorrelationId, OastEventDisposition},
    ssrf_oast_review::{
        evaluate_ssrf_oast_review, SsrfOastAdminToken, SsrfOastCandidateSelection,
        SsrfOastCandidateSource, SsrfOastCorrelationBinding, SsrfOastCorrelationEntropy,
        SsrfOastCorrelationMaterial, SsrfOastMutationPlan, SsrfOastObservedEvent,
        SsrfOastQueryCandidate, SsrfOastReviewFacts, SsrfOastReviewOutcome, SsrfOastReviewPolicy,
        SsrfOastTargetLeg, SsrfOastTerminalState, MAX_SSRF_OAST_PROVIDER_REQUESTS,
        SSRF_OAST_ACTIVE_VERIFICATIONS, SSRF_OAST_TARGET_REQUESTS,
    },
    DecisionActionExecutor, DecisionActionOrigin, DecisionExecutionFailureKind,
    DecisionExecutionRequest, DecisionExecutionStage, DecisionExecutorError,
    DecisionExecutorRegistry, HttpProbe, HttpProbeMethod, KnowledgeBase, RuntimeLimitExceeded,
    TransportDispatchAudit, TransportDispatchOutcome, VerificationCase,
};

pub const SSRF_OAST_REVIEW_ACTION_ID: &str = "web.review.ssrf.oast-query@1";
pub const SSRF_OAST_REVIEW_CAPABILITY_ID: &str = "ssrf.oast-repeated-outbound-interaction@1";
pub const MAX_SSRF_OAST_REVIEW_RESOURCES: usize = 1;
pub const MAX_SSRF_OAST_REVIEW_PARAMETERS: usize = 1;
pub const MAX_SSRF_OAST_REVIEW_REQUESTS: usize = SSRF_OAST_TARGET_REQUESTS;
pub const MAX_SSRF_OAST_REVIEW_PROVIDER_REQUESTS: usize = MAX_SSRF_OAST_PROVIDER_REQUESTS;
pub const MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS: usize = SSRF_OAST_ACTIVE_VERIFICATIONS;
pub(super) const SSRF_OAST_REVIEW_ACTION_CYCLE_ALLOWANCE: u32 = 1;

const SSRF_OAST_EXECUTOR_ID: &str = "http.ssrf-oast-review";
const SSRF_OAST_EVIDENCE_NAMESPACE: &str = "web.ssrf-oast-review.transport";
const CONTROL_COMPLETE: &str = "control-complete";
const PROVIDER_REGISTERED: &str = "provider-registered";
const ALLOCATIONS_COMPLETE: &str = "allocations-complete";
const PREFLIGHT_CLEAN: &str = "preflight-clean";
const CANDIDATE_DISPATCHED: &str = "candidate-dispatched";
const CANDIDATE_CALLBACK_CORRELATED: &str = "candidate-callback-correlated";
const REPLAY_DISPATCHED: &str = "replay-dispatched";
const REPLAY_CALLBACK_CORRELATED: &str = "replay-callback-correlated";
const REPEATED_CALLBACKS_CORRELATED: &str = "repeated-callbacks-correlated";
const CLEANUP_VERIFIED: &str = "cleanup-verified";
const TARGET_ACCOUNTING_COMPLETE: &str = "target-accounting-complete";
const PROVIDER_ACCOUNTING_COMPLETE: &str = "provider-accounting-complete";
const MAX_POST_DISPATCH_POLLS: u16 = 7;
const PROVIDER_REQUEST_BYTES: u64 = 64 * 1024;
const PROVIDER_RESPONSE_BYTES: u64 = 1024 * 1024;

const SSRF_OAST_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        SSRF_OAST_REVIEW_CAPABILITY_ID,
        "Repeated out-of-band interaction observed",
        "server-side request behavior",
        "Two independently allocated callback targets received exact correlated HTTP interactions after candidate and replay query mutations; exploitability and business impact require review.",
        None,
        1_000_000,
        Some("CWE-918"),
        "web.remediation.outbound-request-policy@1",
        "Constrain server-side outbound destinations and manually validate the exact request path before treating this observation as a vulnerability.",
    );

/// Closed, raw-free runtime conclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SsrfOastRuntimeOutcome {
    NotEligible,
    ControlIncomplete,
    RegistrationIncomplete,
    AllocationIncomplete,
    PreflightContaminated,
    TargetNotDispatched,
    NoCallback,
    CandidateOnly,
    ReplayOnly,
    WrongCallback,
    EventIdentityConflict,
    CorrelationMismatch,
    DuplicateOnly,
    CleanupIncomplete,
    DefensiveInterference,
    RateLimited,
    ProviderAuthenticationFailed,
    MalformedProviderResponse,
    PollExhausted,
    Expired,
    Cancelled,
    BudgetExhausted,
    Truncated,
    Incomplete,
    RepeatedCallbacksObserved,
}

impl From<SsrfOastReviewOutcome> for SsrfOastRuntimeOutcome {
    fn from(value: SsrfOastReviewOutcome) -> Self {
        match value {
            SsrfOastReviewOutcome::NotEligible => Self::NotEligible,
            SsrfOastReviewOutcome::ControlIncomplete => Self::ControlIncomplete,
            SsrfOastReviewOutcome::RegistrationIncomplete => Self::RegistrationIncomplete,
            SsrfOastReviewOutcome::AllocationIncomplete => Self::AllocationIncomplete,
            SsrfOastReviewOutcome::PreflightContaminated => Self::PreflightContaminated,
            SsrfOastReviewOutcome::TargetNotDispatched => Self::TargetNotDispatched,
            SsrfOastReviewOutcome::NoCallback => Self::NoCallback,
            SsrfOastReviewOutcome::CandidateOnly => Self::CandidateOnly,
            SsrfOastReviewOutcome::ReplayOnly => Self::ReplayOnly,
            SsrfOastReviewOutcome::WrongCallback => Self::WrongCallback,
            SsrfOastReviewOutcome::EventIdentityConflict => Self::EventIdentityConflict,
            SsrfOastReviewOutcome::CorrelationMismatch => Self::CorrelationMismatch,
            SsrfOastReviewOutcome::DuplicateOnly => Self::DuplicateOnly,
            SsrfOastReviewOutcome::CleanupIncomplete => Self::CleanupIncomplete,
            SsrfOastReviewOutcome::DefensiveInterference => Self::DefensiveInterference,
            SsrfOastReviewOutcome::RateLimited => Self::RateLimited,
            SsrfOastReviewOutcome::ProviderAuthenticationFailed => {
                Self::ProviderAuthenticationFailed
            },
            SsrfOastReviewOutcome::MalformedProviderResponse => Self::MalformedProviderResponse,
            SsrfOastReviewOutcome::PollExhausted => Self::PollExhausted,
            SsrfOastReviewOutcome::Expired => Self::Expired,
            SsrfOastReviewOutcome::Cancelled => Self::Cancelled,
            SsrfOastReviewOutcome::BudgetExhausted => Self::BudgetExhausted,
            SsrfOastReviewOutcome::Truncated => Self::Truncated,
            SsrfOastReviewOutcome::Incomplete => Self::Incomplete,
            SsrfOastReviewOutcome::RepeatedCallbacksObserved => Self::RepeatedCallbacksObserved,
        }
    }
}

/// Redaction-safe audit retained by the one composed assessment report.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct WebAssessmentSsrfOastAudit {
    outcome: SsrfOastRuntimeOutcome,
    policy_id: String,
    candidate_source: Option<&'static str>,
    target_request_count: u8,
    provider_request_count: u8,
    active_verification_count: u8,
    preflight_clean: bool,
    candidate_callback_observed: bool,
    replay_callback_observed: bool,
    cleanup_verified: bool,
    item_projected: bool,
}

impl WebAssessmentSsrfOastAudit {
    pub const fn outcome(&self) -> SsrfOastRuntimeOutcome {
        self.outcome
    }
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    pub const fn candidate_source(&self) -> Option<&'static str> {
        self.candidate_source
    }
    pub const fn target_request_count(&self) -> u8 {
        self.target_request_count
    }
    pub const fn provider_request_count(&self) -> u8 {
        self.provider_request_count
    }
    pub const fn active_verification_count(&self) -> u8 {
        self.active_verification_count
    }
    pub const fn preflight_clean(&self) -> bool {
        self.preflight_clean
    }
    pub const fn candidate_callback_observed(&self) -> bool {
        self.candidate_callback_observed
    }
    pub const fn replay_callback_observed(&self) -> bool {
        self.replay_callback_observed
    }
    pub const fn cleanup_verified(&self) -> bool {
        self.cleanup_verified
    }
    pub const fn item_projected(&self) -> bool {
        self.item_projected
    }
}

impl fmt::Debug for WebAssessmentSsrfOastAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebAssessmentSsrfOastAudit")
            .field("outcome", &self.outcome)
            .field("policy_id", &self.policy_id)
            .field("candidate_source", &self.candidate_source)
            .field("target_request_count", &self.target_request_count)
            .field("provider_request_count", &self.provider_request_count)
            .field("active_verification_count", &self.active_verification_count)
            .field("preflight_clean", &self.preflight_clean)
            .field(
                "candidate_callback_observed",
                &self.candidate_callback_observed,
            )
            .field("replay_callback_observed", &self.replay_callback_observed)
            .field("cleanup_verified", &self.cleanup_verified)
            .field("item_projected", &self.item_projected)
            .finish()
    }
}

pub(super) struct SsrfOastReviewConfig {
    policy: SsrfOastReviewPolicy,
    administrator: SsrfOastAdminToken,
    selection: StableSsrfOastSelectionSlot,
}

impl SsrfOastReviewConfig {
    pub(super) fn new(
        policy: SsrfOastReviewPolicy,
        administrator: SsrfOastAdminToken,
        selection: SsrfOastCandidateSelection,
    ) -> Self {
        Self {
            policy,
            administrator,
            selection: StableSsrfOastSelectionSlot::new(selection),
        }
    }
}

impl fmt::Debug for SsrfOastReviewConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SsrfOastReviewConfig(<redacted>)")
    }
}

#[derive(Clone, Default)]
pub(super) struct StableSsrfOastSelectionSlot {
    candidate: Arc<Mutex<Option<SsrfOastQueryCandidate>>>,
}

impl StableSsrfOastSelectionSlot {
    fn new(selection: SsrfOastCandidateSelection) -> Self {
        let candidate = match selection {
            SsrfOastCandidateSelection::Selected(candidate) => Some(*candidate),
            SsrfOastCandidateSelection::NotEligible => None,
        };
        Self {
            candidate: Arc::new(Mutex::new(candidate)),
        }
    }

    #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
    pub(super) fn commit_openapi(
        &self,
        selection: SsrfOastCandidateSelection,
    ) -> Result<(), SsrfOastRuntimeInvariantError> {
        let SsrfOastCandidateSelection::Selected(candidate) = selection else {
            return Ok(());
        };
        let mut slot = self
            .candidate
            .lock()
            .map_err(|_| SsrfOastRuntimeInvariantError::Catalog)?;
        if slot.is_none() {
            *slot = Some(*candidate);
        }
        Ok(())
    }

    fn take(&self) -> Result<Option<SsrfOastQueryCandidate>, SsrfOastRuntimeInvariantError> {
        self.candidate
            .lock()
            .map_err(|_| SsrfOastRuntimeInvariantError::Catalog)
            .map(|mut value| value.take())
    }
}

impl fmt::Debug for StableSsrfOastSelectionSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StableSsrfOastSelectionSlot(<redacted-single-assignment>)")
    }
}

pub(super) struct SsrfOastRuntimeBinding {
    executor: Arc<SsrfOastDecisionExecutor>,
    subject: EntityId,
}

impl SsrfOastRuntimeBinding {
    pub(super) fn new(
        config: SsrfOastReviewConfig,
        authority: SharedWebRuntimeAuthority,
        subject: EntityId,
    ) -> Self {
        let executor = Arc::new(SsrfOastDecisionExecutor {
            authority,
            policy: config.policy,
            administrator: Mutex::new(Some(config.administrator)),
            selection: config.selection,
            subject: subject.clone(),
            state: Mutex::new(SsrfOastExecutionState::default()),
        });
        Self { executor, subject }
    }

    #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
    pub(super) fn selection_slot(&self) -> StableSsrfOastSelectionSlot {
        self.executor.selection.clone()
    }

    pub(super) fn install_into_parent_registry(
        &self,
        registry: &mut DecisionExecutorRegistry,
    ) -> Result<(), SsrfOastRuntimeInvariantError> {
        let before = registry.len();
        let executor: Arc<dyn DecisionActionExecutor> = self.executor.clone();
        registry
            .register(executor)
            .map_err(|_| SsrfOastRuntimeInvariantError::Catalog)?;
        for stage in [
            DecisionExecutionStage::Passive,
            DecisionExecutionStage::Active,
        ] {
            registry
                .route_action(stage, SSRF_OAST_REVIEW_ACTION_ID, SSRF_OAST_EXECUTOR_ID)
                .map_err(|_| SsrfOastRuntimeInvariantError::Catalog)?;
        }
        if registry.len() != before + 1 {
            return Err(SsrfOastRuntimeInvariantError::Catalog);
        }
        Ok(())
    }

    pub(super) fn finalize(
        self,
        knowledge: &KnowledgeBase,
        transport: &TransportDispatchAudit,
        forced_terminal: Option<SsrfOastTerminalState>,
        forced_limit: Option<RuntimeLimitExceeded>,
    ) -> Result<SsrfOastRuntimeResult, SsrfOastRuntimeInvariantError> {
        if transport.omitted_receipt_count() != 0 {
            return Err(SsrfOastRuntimeInvariantError::Catalog);
        }
        let receipts = transport
            .receipts()
            .iter()
            .filter(|receipt| receipt.action_id() == SSRF_OAST_REVIEW_ACTION_ID)
            .collect::<Vec<_>>();
        if !target_receipt_prefix_is_valid(&receipts) {
            return Err(SsrfOastRuntimeInvariantError::Catalog);
        }
        let mut state = self.executor.take_state()?;
        if let Some(terminal) = forced_terminal {
            if let Some(facts) = state.facts.as_mut() {
                facts.terminal = Some(terminal);
            }
        }
        let target_count = u8::try_from(receipts.len()).unwrap_or(u8::MAX);
        let target_accounting_complete = receipts.len() == SSRF_OAST_TARGET_REQUESTS
            && receipts
                .iter()
                .all(|receipt| target_dispatch_outcome_is_accounted(receipt.outcome()));
        if let Some(facts) = state.facts.as_mut() {
            facts.target_accounting_complete = target_accounting_complete;
        }
        let outcome = match state.facts.as_ref() {
            Some(facts) => evaluate_ssrf_oast_review(facts)
                .map_err(|_| SsrfOastRuntimeInvariantError::Catalog)?,
            None => {
                if state.terminal.is_some() {
                    SsrfOastReviewOutcome::Incomplete
                } else {
                    SsrfOastReviewOutcome::NotEligible
                }
            },
        };
        let projected = outcome.projects_item();
        if projected
            && (state.evidence_ids.is_empty()
                || state
                    .evidence_ids
                    .iter()
                    .any(|id| knowledge.evidence(id).is_none()))
        {
            return Err(SsrfOastRuntimeInvariantError::Catalog);
        }
        let audit = audit(
            &self.executor.policy,
            &state,
            outcome.into(),
            target_count,
            projected,
        );
        let committed = CommittedSsrfOastReview {
            subject: self.subject,
            parameter_identity: state.parameter_identity,
            outcome: outcome.into(),
            evidence_ids: state.evidence_ids,
            audit,
        };
        if matches!(
            outcome,
            SsrfOastReviewOutcome::Cancelled
                | SsrfOastReviewOutcome::BudgetExhausted
                | SsrfOastReviewOutcome::Truncated
                | SsrfOastReviewOutcome::Incomplete
        ) {
            return Ok(SsrfOastRuntimeResult::Stopped {
                audit: committed.audit,
                runtime_limit: forced_limit.or(state.runtime_limit),
            });
        }
        Ok(SsrfOastRuntimeResult::Complete(committed))
    }
}

fn target_receipt_prefix_is_valid(receipts: &[&crate::TransportDispatchReceipt]) -> bool {
    receipts.len() <= SSRF_OAST_TARGET_REQUESTS
        && receipts.iter().enumerate().all(|(index, receipt)| {
            let expected_stage = if index == 1 {
                DecisionExecutionStage::Active
            } else {
                DecisionExecutionStage::Passive
            };
            let expected_origin = (expected_stage == DecisionExecutionStage::Passive)
                .then_some(DecisionActionOrigin::Planned);
            receipt.stage() == expected_stage
                && receipt.origin() == expected_origin
                && receipt.request_body_bytes() == 0
        })
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SsrfOastRuntimeInvariantError {
    #[error("SSRF OAST runtime invariant failed")]
    Catalog,
}

pub(super) enum SsrfOastRuntimeResult {
    Complete(CommittedSsrfOastReview),
    Stopped {
        audit: WebAssessmentSsrfOastAudit,
        runtime_limit: Option<RuntimeLimitExceeded>,
    },
}

pub(super) struct CommittedSsrfOastReview {
    subject: EntityId,
    parameter_identity: Option<String>,
    outcome: SsrfOastRuntimeOutcome,
    evidence_ids: Vec<EvidenceId>,
    audit: WebAssessmentSsrfOastAudit,
}

impl CommittedSsrfOastReview {
    pub(super) const fn audit(&self) -> &WebAssessmentSsrfOastAudit {
        &self.audit
    }
}

#[derive(Default)]
struct SsrfOastExecutionState {
    prepared: Option<PreparedSsrfOast>,
    facts: Option<SsrfOastReviewFacts>,
    terminal: Option<SsrfOastTerminalState>,
    runtime_limit: Option<RuntimeLimitExceeded>,
    provider_request_count: u8,
    source: Option<SsrfOastCandidateSource>,
    parameter_identity: Option<String>,
    evidence_ids: Vec<EvidenceId>,
    cleanup_verified: bool,
}

struct PreparedSsrfOast {
    provider: NativeOastProviderAdapter,
    plan: SsrfOastMutationPlan,
    candidate_callback: CallbackId,
    replay_callback: CallbackId,
    candidate_correlation: OastCorrelationId,
    replay_correlation: OastCorrelationId,
    facts: SsrfOastReviewFacts,
}

struct ProviderTerminalContext {
    source: SsrfOastCandidateSource,
    parameter_identity: String,
    cleanup_verified: bool,
}

struct SsrfOastDecisionExecutor {
    authority: SharedWebRuntimeAuthority,
    policy: SsrfOastReviewPolicy,
    administrator: Mutex<Option<SsrfOastAdminToken>>,
    selection: StableSsrfOastSelectionSlot,
    subject: EntityId,
    state: Mutex<SsrfOastExecutionState>,
}

impl SsrfOastDecisionExecutor {
    fn take_state(&self) -> Result<SsrfOastExecutionState, SsrfOastRuntimeInvariantError> {
        Ok(std::mem::take(
            &mut *self
                .state
                .lock()
                .map_err(|_| SsrfOastRuntimeInvariantError::Catalog)?,
        ))
    }

    fn stop(
        &self,
        terminal: SsrfOastTerminalState,
        limit: Option<RuntimeLimitExceeded>,
    ) -> Result<(), DecisionExecutorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST state is unavailable"))?;
        if state.terminal.replace(terminal).is_some() {
            return Err(DecisionExecutorError::new(
                "SSRF OAST terminal state is duplicated",
            ));
        }
        state.runtime_limit = limit;
        Ok(())
    }

    async fn execute_passive(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let Some(candidate) = self
            .selection
            .take()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST selection failed"))?
        else {
            self.stop(SsrfOastTerminalState::Incomplete, None)?;
            return phase_evidence(request, 0, SsrfOastLifecycleEvidence::terminal(), None);
        };
        self.authority
            .authorize_target(candidate.execution_resource())
            .map_err(|_| DecisionExecutorError::new("SSRF OAST target authority failed"))?;
        let source = candidate.source();
        let parameter_identity = candidate.parameter_id().to_owned();
        let control_seed = random_entropy()?;
        let correlation = SsrfOastCorrelationMaterial::derive(
            &self.policy,
            &candidate,
            SsrfOastCorrelationBinding::new(
                self.subject.as_str(),
                SSRF_OAST_REVIEW_ACTION_ID,
                request.case().id(),
            ),
            SsrfOastCorrelationEntropy::new(
                random_entropy()?,
                random_entropy()?,
                random_entropy()?,
            ),
        )
        .map_err(|_| DecisionExecutorError::new("SSRF OAST correlation derivation failed"))?;
        let (epoch, candidate_token, replay_token) = correlation.into_parts();
        let control_url = candidate
            .control_execution_url(control_seed)
            .map_err(|_| DecisionExecutorError::new("SSRF OAST control construction failed"))?;
        let control_response = match collect_target(
            &self.authority,
            request,
            DecisionExecutionStage::Passive,
            Some(DecisionActionOrigin::Planned),
            &control_url,
        )
        .await
        {
            Ok(response) => response,
            Err(TargetFailure::Limit(limit)) => {
                self.stop(SsrfOastTerminalState::BudgetExhausted, Some(limit))?;
                return phase_evidence(request, 0, SsrfOastLifecycleEvidence::terminal(), None);
            },
            Err(TargetFailure::TimeoutAfterDispatch | TargetFailure::Transport) => {
                self.stop(SsrfOastTerminalState::Incomplete, None)?;
                return phase_evidence(request, 0, SsrfOastLifecycleEvidence::terminal(), None);
            },
        };
        let control_bytes = u64::try_from(control_response.body().len()).unwrap_or(u64::MAX);
        let signal = control_response.ssrf_oast_defense_signal();
        let terminal = classify_target_response(&control_response, &control_url, &signal);
        if let Some(terminal) = terminal {
            self.stop(terminal, None)?;
            return phase_evidence(
                request,
                control_bytes,
                SsrfOastLifecycleEvidence::terminal(),
                Some((&signal, control_response.status())),
            );
        }

        let administrator = self
            .administrator
            .lock()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST credential is unavailable"))?
            .take()
            .ok_or_else(|| {
                DecisionExecutorError::new("SSRF OAST credential was already consumed")
            })?;
        let limits = NativeOastProviderLimits::new(
            1,
            2,
            u16::try_from(MAX_SSRF_OAST_PROVIDER_REQUESTS).unwrap_or(u16::MAX),
            8,
            PROVIDER_REQUEST_BYTES,
            PROVIDER_RESPONSE_BYTES,
            self.policy.lifetime_ms(),
        )
        .map_err(|_| DecisionExecutorError::new("SSRF OAST provider limits failed"))?;
        let configuration = provider_configuration(
            self.policy.provider_origin(),
            &assessment_identity(&self.subject),
            epoch.into_bytes(),
            administrator.into_bytes(),
            limits,
        )
        .map_err(|_| DecisionExecutorError::new("SSRF OAST provider configuration failed"))?;
        let candidate_case = callback_case(request, "candidate")?;
        let replay_case = callback_case(request, "replay")?;
        let mut provider = match self.authority.mint_native_oast_provider(configuration) {
            Ok(provider) => provider,
            Err(error) => {
                self.stop(provider_terminal(error.kind()), None)?;
                return phase_evidence(
                    request,
                    control_bytes,
                    SsrfOastLifecycleEvidence {
                        control_complete: true,
                        phase_terminal: true,
                        ..SsrfOastLifecycleEvidence::default()
                    },
                    Some((&signal, control_response.status())),
                );
            },
        };
        if let Err(error) = provider.register().await {
            self.store_provider_terminal(
                provider,
                None,
                provider_terminal(error.kind()),
                None,
                ProviderTerminalContext {
                    source,
                    parameter_identity,
                    cleanup_verified: false,
                },
            )?;
            return phase_evidence(
                request,
                control_bytes,
                SsrfOastLifecycleEvidence {
                    control_complete: true,
                    phase_terminal: true,
                    ..SsrfOastLifecycleEvidence::default()
                },
                Some((&signal, control_response.status())),
            );
        }
        let candidate_allocation = match provider
            .allocate_callback(candidate_case, candidate_token)
            .await
        {
            Ok(allocation) => allocation,
            Err(error) => {
                let terminal = provider_terminal(error.kind());
                let cleanup_verified = cleanup_provider(&mut provider).await;
                self.store_provider_terminal(
                    provider,
                    None,
                    terminal,
                    None,
                    ProviderTerminalContext {
                        source,
                        parameter_identity,
                        cleanup_verified,
                    },
                )?;
                return phase_evidence(
                    request,
                    control_bytes,
                    SsrfOastLifecycleEvidence {
                        control_complete: true,
                        provider_registered: true,
                        cleanup_verified,
                        phase_terminal: true,
                        ..SsrfOastLifecycleEvidence::default()
                    },
                    Some((&signal, control_response.status())),
                );
            },
        };
        let replay_allocation = match provider.allocate_callback(replay_case, replay_token).await {
            Ok(allocation) => allocation,
            Err(error) => {
                let terminal = provider_terminal(error.kind());
                let cleanup_verified = cleanup_provider(&mut provider).await;
                self.store_provider_terminal(
                    provider,
                    None,
                    terminal,
                    None,
                    ProviderTerminalContext {
                        source,
                        parameter_identity,
                        cleanup_verified,
                    },
                )?;
                return phase_evidence(
                    request,
                    control_bytes,
                    SsrfOastLifecycleEvidence {
                        control_complete: true,
                        provider_registered: true,
                        cleanup_verified,
                        phase_terminal: true,
                        ..SsrfOastLifecycleEvidence::default()
                    },
                    Some((&signal, control_response.status())),
                );
            },
        };
        let candidate_callback = candidate_allocation.callback_id().clone();
        let replay_callback = replay_allocation.callback_id().clone();
        let candidate_correlation = candidate_allocation
            .correlation_receipt()
            .correlation_id()
            .clone();
        let replay_correlation = replay_allocation
            .correlation_receipt()
            .correlation_id()
            .clone();
        let mut facts = SsrfOastReviewFacts::new(&candidate_callback, &replay_callback);
        facts.control_complete = true;
        facts.provider_registered = true;
        facts.allocations_complete = true;
        facts.correlations_distinct = candidate_correlation != replay_correlation;
        facts.same_correlation_scope = true;
        let plan = match mutation_plan(
            candidate,
            control_seed,
            candidate_allocation.target(),
            replay_allocation.target(),
            self.policy.provider_origin(),
        ) {
            Ok(plan) => plan,
            Err(_) => {
                facts.terminal = Some(SsrfOastTerminalState::MalformedProviderResponse);
                facts.cleanup_verified = cleanup_provider(&mut provider).await;
                facts.provider_accounting_complete = provider_accounting_is_complete(&provider);
                let lifecycle = SsrfOastLifecycleEvidence::from_facts(&facts, true);
                self.store_provider_terminal(
                    provider,
                    Some(facts),
                    SsrfOastTerminalState::MalformedProviderResponse,
                    None,
                    ProviderTerminalContext {
                        source,
                        parameter_identity,
                        cleanup_verified: lifecycle.cleanup_verified,
                    },
                )?;
                return phase_evidence(
                    request,
                    control_bytes,
                    lifecycle,
                    Some((&signal, control_response.status())),
                );
            },
        };
        let preflight = match provider.poll().await {
            Ok(preflight) => preflight,
            Err(error) => {
                let terminal = provider_terminal(error.kind());
                facts.terminal = Some(terminal);
                facts.cleanup_verified = cleanup_provider(&mut provider).await;
                facts.provider_accounting_complete = provider_accounting_is_complete(&provider);
                let lifecycle = SsrfOastLifecycleEvidence::from_facts(&facts, true);
                self.store_provider_terminal(
                    provider,
                    Some(facts),
                    terminal,
                    None,
                    ProviderTerminalContext {
                        source,
                        parameter_identity,
                        cleanup_verified: lifecycle.cleanup_verified,
                    },
                )?;
                return phase_evidence(
                    request,
                    control_bytes,
                    lifecycle,
                    Some((&signal, control_response.status())),
                );
            },
        };
        let preflight_clean = preflight
            .correlation_receipts()
            .iter()
            .all(|receipt| receipt.accepted_events() == 0 && receipt.duplicate_events() == 0);
        facts.preflight_clean = preflight_clean;
        if !preflight_clean {
            facts.cleanup_verified = cleanup_provider(&mut provider).await;
            facts.provider_accounting_complete = provider_accounting_is_complete(&provider);
            facts.terminal = None;
            let lifecycle = SsrfOastLifecycleEvidence::from_facts(&facts, true);
            let mut state = self
                .state
                .lock()
                .map_err(|_| DecisionExecutorError::new("SSRF OAST state is unavailable"))?;
            state.cleanup_verified = facts.cleanup_verified;
            state.facts = Some(facts);
            state.provider_request_count =
                u8::try_from(provider.receipts().len()).unwrap_or(u8::MAX);
            state.source = Some(source);
            state.parameter_identity = Some(parameter_identity);
            return phase_evidence(
                request,
                control_bytes,
                lifecycle,
                Some((&signal, control_response.status())),
            );
        }
        let provider_count = u8::try_from(provider.receipts().len()).unwrap_or(u8::MAX);
        let mut state = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST state is unavailable"))?;
        state.prepared = Some(PreparedSsrfOast {
            provider,
            plan,
            candidate_callback,
            replay_callback,
            candidate_correlation,
            replay_correlation,
            facts,
        });
        state.provider_request_count = provider_count;
        state.source = Some(source);
        state.parameter_identity = Some(parameter_identity);
        let lifecycle = SsrfOastLifecycleEvidence::from_facts(
            &state
                .prepared
                .as_ref()
                .expect("prepared SSRF OAST state is present")
                .facts,
            false,
        );
        let evidence = phase_evidence(
            request,
            control_bytes,
            lifecycle,
            Some((&signal, control_response.status())),
        )?;
        state.evidence_ids.extend(ssrf_evidence_ids(&evidence));
        Ok(evidence)
    }

    async fn execute_active(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let mut prepared = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST state is unavailable"))?
            .prepared
            .take()
            .ok_or_else(|| DecisionExecutorError::new("SSRF OAST passive state is incomplete"))?;
        let mut response_bytes = 0_u64;
        let candidate_url = prepared
            .plan
            .execution_url(SsrfOastTargetLeg::Candidate)
            .clone();
        let candidate_response = collect_target(
            &self.authority,
            request,
            DecisionExecutionStage::Active,
            None,
            &candidate_url,
        )
        .await;
        let mut last_signal = match candidate_response {
            Ok(response) => {
                response_bytes = response_bytes
                    .saturating_add(u64::try_from(response.body().len()).unwrap_or(u64::MAX));
                let signal = response.ssrf_oast_defense_signal();
                if let Some(terminal) = classify_target_response(&response, &candidate_url, &signal)
                {
                    prepared.facts.terminal = Some(terminal);
                }
                prepared.facts.candidate_dispatched = true;
                Some((signal, response.status()))
            },
            Err(TargetFailure::TimeoutAfterDispatch) => {
                prepared.facts.candidate_dispatched = true;
                prepared.facts.terminal = Some(SsrfOastTerminalState::TargetTimeoutAfterDispatch);
                None
            },
            Err(TargetFailure::Limit(limit)) => {
                prepared.facts.terminal = Some(SsrfOastTerminalState::BudgetExhausted);
                let lifecycle = self.store_active_terminal(prepared, Some(limit)).await?;
                return phase_evidence(request, 0, lifecycle, None);
            },
            Err(TargetFailure::Transport) => {
                prepared.facts.terminal = Some(SsrfOastTerminalState::Incomplete);
                let lifecycle = self.store_active_terminal(prepared, None).await?;
                return phase_evidence(request, 0, lifecycle, None);
            },
        };
        if polling_may_continue(&prepared.facts) {
            poll_for_events(
                &mut prepared,
                self.policy.polls_per_leg(),
                self.policy.poll_interval_ms(),
                true,
                self.authority.cancellation(),
            )
            .await?;
        }
        let replay_url = prepared
            .plan
            .execution_url(SsrfOastTargetLeg::Replay)
            .clone();
        if polling_may_continue(&prepared.facts) {
            match collect_target(
                &self.authority,
                request,
                DecisionExecutionStage::Passive,
                Some(DecisionActionOrigin::Planned),
                &replay_url,
            )
            .await
            {
                Ok(response) => {
                    response_bytes = response_bytes
                        .saturating_add(u64::try_from(response.body().len()).unwrap_or(u64::MAX));
                    let signal = response.ssrf_oast_defense_signal();
                    if let Some(terminal) =
                        classify_target_response(&response, &replay_url, &signal)
                    {
                        prepared.facts.terminal = Some(terminal);
                    }
                    prepared.facts.replay_dispatched = true;
                    last_signal = Some((signal, response.status()));
                },
                Err(TargetFailure::TimeoutAfterDispatch) => {
                    prepared.facts.replay_dispatched = true;
                    prepared.facts.terminal =
                        Some(SsrfOastTerminalState::TargetTimeoutAfterDispatch);
                },
                Err(TargetFailure::Limit(limit)) => {
                    prepared.facts.terminal = Some(SsrfOastTerminalState::BudgetExhausted);
                    let lifecycle = self.store_active_terminal(prepared, Some(limit)).await?;
                    return phase_evidence(request, response_bytes, lifecycle, None);
                },
                Err(TargetFailure::Transport) => {
                    prepared.facts.terminal = Some(SsrfOastTerminalState::Incomplete);
                },
            }
        }
        if polling_may_continue(&prepared.facts) {
            let used = prepared
                .provider
                .receipts()
                .iter()
                .filter(|receipt| receipt.operation() == NativeOastProviderOperation::Poll)
                .count();
            let remaining =
                usize::from(MAX_POST_DISPATCH_POLLS).saturating_sub(used.saturating_sub(1));
            let polls = usize::from(self.policy.polls_per_leg()).min(remaining) as u16;
            poll_for_events(
                &mut prepared,
                polls,
                self.policy.poll_interval_ms(),
                false,
                self.authority.cancellation(),
            )
            .await?;
        }
        prepared.facts.cleanup_verified = cleanup_provider(&mut prepared.provider).await;
        prepared.facts.provider_accounting_complete =
            provider_accounting_is_complete(&prepared.provider);
        prepared.facts.target_accounting_complete =
            current_target_accounting_is_complete(&self.authority);
        let provider_count = u8::try_from(prepared.provider.receipts().len()).unwrap_or(u8::MAX);
        let terminal = prepared.facts.terminal.is_some()
            && !matches!(
                prepared.facts.terminal,
                Some(SsrfOastTerminalState::TargetTimeoutAfterDispatch)
            );
        let lifecycle = SsrfOastLifecycleEvidence::from_facts(&prepared.facts, terminal);
        let evidence = phase_evidence(
            request,
            response_bytes,
            lifecycle,
            last_signal
                .as_ref()
                .map(|(signal, status)| (signal, *status)),
        )?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST state is unavailable"))?;
        state.provider_request_count = provider_count;
        state.terminal = prepared.facts.terminal;
        state.cleanup_verified = prepared.facts.cleanup_verified;
        state.evidence_ids.extend(ssrf_evidence_ids(&evidence));
        state.facts = Some(prepared.facts);
        Ok(evidence)
    }

    async fn store_active_terminal(
        &self,
        mut prepared: PreparedSsrfOast,
        limit: Option<RuntimeLimitExceeded>,
    ) -> Result<SsrfOastLifecycleEvidence, DecisionExecutorError> {
        prepared.facts.cleanup_verified = cleanup_provider(&mut prepared.provider).await;
        prepared.facts.provider_accounting_complete =
            provider_accounting_is_complete(&prepared.provider);
        prepared.facts.target_accounting_complete =
            current_target_accounting_is_complete(&self.authority);
        let lifecycle = SsrfOastLifecycleEvidence::from_facts(&prepared.facts, true);
        let mut state = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST state is unavailable"))?;
        state.provider_request_count =
            u8::try_from(prepared.provider.receipts().len()).unwrap_or(u8::MAX);
        state.terminal = prepared.facts.terminal;
        state.runtime_limit = limit;
        state.cleanup_verified = prepared.facts.cleanup_verified;
        state.facts = Some(prepared.facts);
        Ok(lifecycle)
    }

    fn store_provider_terminal(
        &self,
        provider: NativeOastProviderAdapter,
        facts: Option<SsrfOastReviewFacts>,
        terminal: SsrfOastTerminalState,
        limit: Option<RuntimeLimitExceeded>,
        context: ProviderTerminalContext,
    ) -> Result<(), DecisionExecutorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("SSRF OAST state is unavailable"))?;
        state.provider_request_count = u8::try_from(provider.receipts().len()).unwrap_or(u8::MAX);
        state.terminal = Some(terminal);
        state.runtime_limit = limit;
        state.source = Some(context.source);
        state.parameter_identity = Some(context.parameter_identity);
        state.cleanup_verified = context.cleanup_verified;
        state.facts = facts;
        Ok(())
    }
}

#[async_trait]
impl DecisionActionExecutor for SsrfOastDecisionExecutor {
    fn id(&self) -> &str {
        SSRF_OAST_EXECUTOR_ID
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        if request.case().action_id() != SSRF_OAST_REVIEW_ACTION_ID
            || request.case().subject() != &self.subject
            || request.case().payload_strategy().is_some()
            || request.case().applies_hypothesis_transition()
            || request.delay_ms().is_some()
            || (request.stage() == DecisionExecutionStage::Passive && request.origin().is_none())
            || (request.stage() == DecisionExecutionStage::Active && request.origin().is_some())
        {
            return Err(DecisionExecutorError::new(
                "SSRF OAST executor route contract failed",
            ));
        }
        match request.stage() {
            DecisionExecutionStage::Passive => self.execute_passive(request).await,
            DecisionExecutionStage::Active => self.execute_active(request).await,
        }
    }
}

enum TargetFailure {
    Limit(RuntimeLimitExceeded),
    TimeoutAfterDispatch,
    Transport,
}

async fn collect_target(
    authority: &SharedWebRuntimeAuthority,
    request: &DecisionExecutionRequest,
    stage: DecisionExecutionStage,
    origin: Option<DecisionActionOrigin>,
    url: &url::Url,
) -> Result<crate::http_evidence::CollectedHttpResponse, TargetFailure> {
    let probe =
        HttpProbe::new(url.clone(), HttpProbeMethod::Get).map_err(|_| TargetFailure::Transport)?;
    authority
        .requests()
        .collect_for_runtime(
            SSRF_OAST_REVIEW_ACTION_ID,
            stage,
            origin,
            request.limits(),
            &probe,
        )
        .await
        .map_err(|error| {
            if let HttpRequestBrokerError::RuntimeLimit(limit) = error {
                return TargetFailure::Limit(limit);
            }
            if error.failure_kind() == DecisionExecutionFailureKind::RequestTimeout {
                TargetFailure::TimeoutAfterDispatch
            } else {
                TargetFailure::Transport
            }
        })
}

fn polling_may_continue(facts: &SsrfOastReviewFacts) -> bool {
    facts.terminal.is_none()
        || matches!(
            facts.terminal,
            Some(SsrfOastTerminalState::TargetTimeoutAfterDispatch)
        )
}

async fn cleanup_provider(provider: &mut NativeOastProviderAdapter) -> bool {
    provider
        .cleanup()
        .await
        .as_ref()
        .is_ok_and(|receipt| receipt.cleanup_verified())
}

fn provider_accounting_is_complete(provider: &NativeOastProviderAdapter) -> bool {
    let receipts = provider.receipts();
    receipts.len() >= 5
        && receipts.len() <= MAX_SSRF_OAST_PROVIDER_REQUESTS
        && receipts
            .iter()
            .enumerate()
            .all(|(index, receipt)| usize::from(receipt.request_count()) == index + 1)
        && receipts
            .first()
            .is_some_and(|receipt| receipt.operation() == NativeOastProviderOperation::Register)
        && receipts.get(1).is_some_and(|receipt| {
            receipt.operation() == NativeOastProviderOperation::AllocateCallback
        })
        && receipts.get(2).is_some_and(|receipt| {
            receipt.operation() == NativeOastProviderOperation::AllocateCallback
        })
        && receipts
            .get(3)
            .is_some_and(|receipt| receipt.operation() == NativeOastProviderOperation::Poll)
        && receipts[4..receipts.len() - 1]
            .iter()
            .all(|receipt| receipt.operation() == NativeOastProviderOperation::Poll)
        && receipts
            .last()
            .is_some_and(|receipt| receipt.operation() == NativeOastProviderOperation::Cleanup)
}

fn current_target_accounting_is_complete(authority: &SharedWebRuntimeAuthority) -> bool {
    let audit = authority.request_accounting().dispatch_audit();
    let receipts = audit
        .receipts()
        .iter()
        .filter(|receipt| receipt.action_id() == SSRF_OAST_REVIEW_ACTION_ID)
        .collect::<Vec<_>>();
    audit.omitted_receipt_count() == 0
        && target_receipt_prefix_is_valid(&receipts)
        && receipts.len() == SSRF_OAST_TARGET_REQUESTS
        && receipts
            .iter()
            .all(|receipt| target_dispatch_outcome_is_accounted(receipt.outcome()))
}

const fn target_dispatch_outcome_is_accounted(outcome: TransportDispatchOutcome) -> bool {
    matches!(
        outcome,
        TransportDispatchOutcome::Completed | TransportDispatchOutcome::RequestTimeout
    )
}

fn classify_target_response(
    response: &crate::http_evidence::CollectedHttpResponse,
    expected: &url::Url,
    signal: &super::AssessmentDefenseSignal,
) -> Option<SsrfOastTerminalState> {
    if response.final_url() != expected || (300..400).contains(&response.status()) {
        return Some(SsrfOastTerminalState::Incomplete);
    }
    if response.body_truncated() {
        return Some(SsrfOastTerminalState::Incomplete);
    }
    if !response.body_complete() {
        return Some(SsrfOastTerminalState::Incomplete);
    }
    if signal.state().is_rate_limited() {
        return Some(SsrfOastTerminalState::RateLimited);
    }
    if signal.state().is_challenged() {
        return Some(SsrfOastTerminalState::DefensiveInterference);
    }
    None
}

async fn poll_for_events(
    prepared: &mut PreparedSsrfOast,
    polls: u16,
    interval_ms: u64,
    candidate_phase: bool,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<(), DecisionExecutorError> {
    for _ in 0..polls {
        tokio::select! {
            _ = cancellation.cancelled() => {
                prepared.facts.terminal = Some(SsrfOastTerminalState::Cancelled);
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(interval_ms)) => {}
        }
        let page = match prepared.provider.poll().await {
            Ok(page) => page,
            Err(error) => {
                prepared.facts.terminal = Some(provider_terminal(error.kind()));
                return Ok(());
            },
        };
        reduce_poll(prepared, &page, candidate_phase);
        if !polling_may_continue(&prepared.facts) {
            break;
        }
        if prepared.facts.candidate_event.is_some()
            && (!candidate_phase || prepared.facts.replay_event.is_some())
        {
            break;
        }
    }
    Ok(())
}

fn reduce_poll(
    prepared: &mut PreparedSsrfOast,
    page: &crate::native_oast_provider::NativeOastPollOutcome,
    candidate_phase: bool,
) {
    for receipt in page.correlation_receipts() {
        let is_candidate = receipt.correlation_id() == &prepared.candidate_correlation;
        let is_replay = receipt.correlation_id() == &prepared.replay_correlation;
        if !is_candidate && !is_replay {
            prepared.facts.terminal = Some(SsrfOastTerminalState::MalformedProviderResponse);
            continue;
        }
        if candidate_phase && is_replay && receipt.accepted_events() > 0 {
            prepared.facts.terminal = Some(SsrfOastTerminalState::MalformedProviderResponse);
        }
        for event in receipt.event_receipts() {
            match event.disposition() {
                OastEventDisposition::Accepted => {
                    let observed = if is_candidate {
                        SsrfOastObservedEvent::from_reduced(
                            &prepared.candidate_callback,
                            event.event_key(),
                        )
                    } else {
                        SsrfOastObservedEvent::from_reduced(
                            &prepared.replay_callback,
                            event.event_key(),
                        )
                    };
                    let target = if is_candidate {
                        &mut prepared.facts.candidate_event
                    } else {
                        &mut prepared.facts.replay_event
                    };
                    if target.replace(observed).is_some() {
                        prepared.facts.terminal =
                            Some(SsrfOastTerminalState::MalformedProviderResponse);
                    }
                },
                OastEventDisposition::DuplicateSuppressed => {
                    if (is_candidate && prepared.facts.candidate_event.is_none())
                        || (is_replay && prepared.facts.replay_event.is_none())
                    {
                        prepared.facts.duplicate_only_substitution = true;
                    }
                },
            }
        }
    }
}

fn provider_terminal(kind: NativeOastProviderErrorKind) -> SsrfOastTerminalState {
    match kind {
        NativeOastProviderErrorKind::Cancelled => SsrfOastTerminalState::Cancelled,
        NativeOastProviderErrorKind::DeadlineExceeded
        | NativeOastProviderErrorKind::ProviderExpired => SsrfOastTerminalState::Expired,
        NativeOastProviderErrorKind::RuntimeBudget(_)
        | NativeOastProviderErrorKind::ParentBudgetTooSmall
        | NativeOastProviderErrorKind::RequestLimit
        | NativeOastProviderErrorKind::ResponseByteLimit
        | NativeOastProviderErrorKind::RequestByteLimit => SsrfOastTerminalState::BudgetExhausted,
        NativeOastProviderErrorKind::PollLimit => SsrfOastTerminalState::PollExhausted,
        NativeOastProviderErrorKind::ProviderRejected => {
            SsrfOastTerminalState::ProviderAuthenticationFailed
        },
        NativeOastProviderErrorKind::ProviderResponseInvalid
        | NativeOastProviderErrorKind::ProviderSessionMismatch
        | NativeOastProviderErrorKind::ProviderCallbackMismatch
        | NativeOastProviderErrorKind::ProviderPageIncomplete
        | NativeOastProviderErrorKind::CorrelationRejected => {
            SsrfOastTerminalState::MalformedProviderResponse
        },
        _ => SsrfOastTerminalState::Incomplete,
    }
}

fn callback_case(
    request: &DecisionExecutionRequest,
    role: &str,
) -> Result<VerificationCase, DecisionExecutorError> {
    VerificationCase::new(
        format!("{}:{role}", request.case().id()),
        request.case().subject().clone(),
        request.case().action_id(),
        request.case().hypothesis_id(),
    )
    .map(VerificationCase::without_hypothesis_transition)
    .map_err(|_| DecisionExecutorError::new("SSRF OAST callback case failed"))
}

fn random_entropy() -> Result<[u8; 32], DecisionExecutorError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| DecisionExecutorError::new("SSRF OAST entropy source failed"))?;
    Ok(bytes)
}

fn provider_configuration(
    origin: &PublicOrigin,
    assessment_id: &str,
    epoch: [u8; 32],
    administrator: Vec<u8>,
    limits: NativeOastProviderLimits,
) -> Result<NativeOastProviderConfiguration, crate::native_oast_provider::NativeOastProviderError> {
    #[cfg(test)]
    if origin.as_str().starts_with("http://") {
        return NativeOastProviderConfiguration::for_loopback(
            origin.clone(),
            assessment_id,
            epoch,
            administrator,
            limits,
        );
    }
    NativeOastProviderConfiguration::new(
        origin.as_str(),
        assessment_id,
        epoch,
        administrator,
        limits,
    )
}

fn mutation_plan(
    candidate: SsrfOastQueryCandidate,
    control_seed: [u8; 32],
    candidate_target: &termivar_oast::CallbackTarget,
    replay_target: &termivar_oast::CallbackTarget,
    provider: &PublicOrigin,
) -> Result<SsrfOastMutationPlan, crate::ssrf_oast_review::SsrfOastContractError> {
    #[cfg(test)]
    if provider.as_str().starts_with("http://") {
        return SsrfOastMutationPlan::new_for_loopback(
            candidate,
            control_seed,
            candidate_target,
            replay_target,
            provider,
        );
    }
    SsrfOastMutationPlan::new(
        candidate,
        control_seed,
        candidate_target,
        replay_target,
        provider,
    )
}

fn assessment_identity(subject: &EntityId) -> String {
    let digest = Sha256::digest(subject.as_str().as_bytes());
    format!("assessment-{:x}", digest)
}

#[derive(Clone, Copy, Default)]
struct SsrfOastLifecycleEvidence {
    control_complete: bool,
    provider_registered: bool,
    allocations_complete: bool,
    preflight_clean: bool,
    candidate_dispatched: bool,
    candidate_callback_correlated: bool,
    replay_dispatched: bool,
    replay_callback_correlated: bool,
    repeated_callbacks_correlated: bool,
    cleanup_verified: bool,
    target_accounting_complete: bool,
    provider_accounting_complete: bool,
    phase_terminal: bool,
}

impl SsrfOastLifecycleEvidence {
    const fn terminal() -> Self {
        Self {
            phase_terminal: true,
            ..Self::default_const()
        }
    }

    const fn default_const() -> Self {
        Self {
            control_complete: false,
            provider_registered: false,
            allocations_complete: false,
            preflight_clean: false,
            candidate_dispatched: false,
            candidate_callback_correlated: false,
            replay_dispatched: false,
            replay_callback_correlated: false,
            repeated_callbacks_correlated: false,
            cleanup_verified: false,
            target_accounting_complete: false,
            provider_accounting_complete: false,
            phase_terminal: false,
        }
    }

    fn from_facts(facts: &SsrfOastReviewFacts, phase_terminal: bool) -> Self {
        Self {
            control_complete: facts.control_complete,
            provider_registered: facts.provider_registered,
            allocations_complete: facts.allocations_complete,
            preflight_clean: facts.preflight_clean,
            candidate_dispatched: facts.candidate_dispatched,
            candidate_callback_correlated: facts.candidate_event.is_some(),
            replay_dispatched: facts.replay_dispatched,
            replay_callback_correlated: facts.replay_event.is_some(),
            repeated_callbacks_correlated: evaluate_ssrf_oast_review(facts)
                .is_ok_and(SsrfOastReviewOutcome::projects_item),
            cleanup_verified: facts.cleanup_verified,
            target_accounting_complete: facts.target_accounting_complete,
            provider_accounting_complete: facts.provider_accounting_complete,
            phase_terminal,
        }
    }

    const fn candidate_ready(self) -> bool {
        self.control_complete
            && self.provider_registered
            && self.allocations_complete
            && self.preflight_clean
            && !self.phase_terminal
    }
}

fn phase_evidence(
    request: &DecisionExecutionRequest,
    response_bytes: u64,
    lifecycle: SsrfOastLifecycleEvidence,
    defense: Option<(&super::AssessmentDefenseSignal, u16)>,
) -> Result<Vec<Evidence>, DecisionExecutorError> {
    let mut evidence = vec![
        make_evidence(
            request,
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            EvidenceValue::Unsigned(response_bytes),
            "response-body-size",
        )?,
        make_evidence(
            request,
            EvidenceKind::Custom("ssrf-oast-phase".into()),
            crate::web_actions::ssrf_oast_review_candidate_ready_predicate(),
            EvidenceValue::Boolean(lifecycle.candidate_ready()),
            "candidate-ready",
        )?,
        make_evidence(
            request,
            EvidenceKind::Custom("ssrf-oast-phase".into()),
            crate::web_actions::ssrf_oast_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(lifecycle.phase_terminal),
            "phase-terminal",
        )?,
    ];
    for (name, value) in [
        (CONTROL_COMPLETE, lifecycle.control_complete),
        (PROVIDER_REGISTERED, lifecycle.provider_registered),
        (ALLOCATIONS_COMPLETE, lifecycle.allocations_complete),
        (PREFLIGHT_CLEAN, lifecycle.preflight_clean),
        (CANDIDATE_DISPATCHED, lifecycle.candidate_dispatched),
        (
            CANDIDATE_CALLBACK_CORRELATED,
            lifecycle.candidate_callback_correlated,
        ),
        (REPLAY_DISPATCHED, lifecycle.replay_dispatched),
        (
            REPLAY_CALLBACK_CORRELATED,
            lifecycle.replay_callback_correlated,
        ),
        (
            REPEATED_CALLBACKS_CORRELATED,
            lifecycle.repeated_callbacks_correlated,
        ),
        (CLEANUP_VERIFIED, lifecycle.cleanup_verified),
        (
            TARGET_ACCOUNTING_COMPLETE,
            lifecycle.target_accounting_complete,
        ),
        (
            PROVIDER_ACCOUNTING_COMPLETE,
            lifecycle.provider_accounting_complete,
        ),
    ] {
        evidence.push(make_evidence(
            request,
            EvidenceKind::Custom("ssrf-oast-lifecycle".into()),
            KnowledgePredicate::new(SSRF_OAST_EVIDENCE_NAMESPACE, name)
                .map_err(|_| DecisionExecutorError::new("SSRF OAST predicate failed"))?,
            EvidenceValue::Boolean(value),
            name,
        )?);
    }
    if request.stage() == DecisionExecutionStage::Active && !lifecycle.phase_terminal {
        evidence.push(make_evidence(
            request,
            EvidenceKind::Custom("native-web-review-response".into()),
            crate::web_actions::native_web_review_response_marker_predicate(),
            EvidenceValue::Boolean(true),
            "complete",
        )?);
    }
    if let Some((signal, status)) = defense {
        let base = make_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge(),
            EvidenceValue::Unsigned(u64::from(status)),
            "response-status",
        )?;
        let parents = vec![evidence[0].id().clone(), base.id().clone()];
        evidence.push(base);
        evidence.extend(
            project_assessment_defense_signal(
                signal,
                AssessmentDefenseProjectionContext {
                    subject: request.case().subject(),
                    case_id: request.case().id(),
                    executor_id: SSRF_OAST_EXECUTOR_ID,
                    reliability: ConfidenceScore::MAX,
                    parents,
                },
            )
            .map_err(|_| DecisionExecutorError::new("SSRF OAST defense projection failed"))?,
        );
    }
    Ok(evidence)
}

fn make_evidence(
    request: &DecisionExecutionRequest,
    kind: EvidenceKind,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    method: &'static str,
) -> Result<Evidence, DecisionExecutorError> {
    Ok(Evidence::new(
        request.case().subject().clone(),
        kind,
        predicate,
        value,
        EvidenceSource::new(SSRF_OAST_EXECUTOR_ID, method)
            .and_then(|source| source.with_correlation_id(request.case().id()))
            .map_err(|_| DecisionExecutorError::new("SSRF OAST evidence source failed"))?,
        ConfidenceScore::MAX,
    ))
}

fn ssrf_evidence_ids(evidence: &[Evidence]) -> Vec<EvidenceId> {
    evidence
        .iter()
        .filter(|item| item.predicate().namespace() == SSRF_OAST_EVIDENCE_NAMESPACE)
        .map(|item| item.id().clone())
        .collect()
}

fn audit(
    policy: &SsrfOastReviewPolicy,
    state: &SsrfOastExecutionState,
    outcome: SsrfOastRuntimeOutcome,
    target_requests: u8,
    projected: bool,
) -> WebAssessmentSsrfOastAudit {
    let facts = state.facts.as_ref();
    WebAssessmentSsrfOastAudit {
        outcome,
        policy_id: policy.policy_id().to_wire(),
        candidate_source: state.source.map(SsrfOastCandidateSource::as_str),
        target_request_count: target_requests,
        provider_request_count: state.provider_request_count,
        active_verification_count: u8::from(target_requests >= 2),
        preflight_clean: facts.is_some_and(|facts| facts.preflight_clean),
        candidate_callback_observed: facts.is_some_and(|facts| facts.candidate_event.is_some()),
        replay_callback_observed: facts.is_some_and(|facts| facts.replay_event.is_some()),
        cleanup_verified: facts.map_or(state.cleanup_verified, |facts| facts.cleanup_verified),
        item_projected: projected,
    }
}

pub(super) fn project_ssrf_oast_item(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    review: &CommittedSsrfOastReview,
) -> Result<(), AssessmentItemProjectionError> {
    if review.outcome != SsrfOastRuntimeOutcome::RepeatedCallbacksObserved {
        return Ok(());
    }
    if !positive_evidence_contract(knowledge, &review.evidence_ids) {
        return Err(AssessmentItemProjectionError::MissingEvidence);
    }
    let parameter = review
        .parameter_identity
        .clone()
        .ok_or(AssessmentItemProjectionError::InvalidStableSubjectIdentity)?;
    let target = AssessmentItemTarget::ssrf_oast_query(parameter.clone())?;
    if !context.has_subject(&review.subject) {
        context.register_subject(
            review.subject.clone(),
            StableAssessmentSubjectId::new(parameter)?,
            Vec::new(),
        )?;
    }
    for evidence_id in &review.evidence_ids {
        context.register_evidence(knowledge, evidence_id)?;
    }
    let midpoint = review.evidence_ids.len() / 2;
    context.project_differential(
        &SSRF_OAST_CAPABILITY,
        knowledge,
        &review.subject,
        &target,
        &review.evidence_ids[..midpoint],
        &review.evidence_ids[midpoint..],
    )?;
    Ok(())
}

fn positive_evidence_contract(knowledge: &KnowledgeBase, evidence_ids: &[EvidenceId]) -> bool {
    evidence_ids.len().is_multiple_of(2)
        && [
            CONTROL_COMPLETE,
            PROVIDER_REGISTERED,
            ALLOCATIONS_COMPLETE,
            PREFLIGHT_CLEAN,
            CANDIDATE_DISPATCHED,
            CANDIDATE_CALLBACK_CORRELATED,
            REPLAY_DISPATCHED,
            REPLAY_CALLBACK_CORRELATED,
            REPEATED_CALLBACKS_CORRELATED,
            CLEANUP_VERIFIED,
            TARGET_ACCOUNTING_COMPLETE,
            PROVIDER_ACCOUNTING_COMPLETE,
        ]
        .into_iter()
        .all(|name| {
            evidence_ids.iter().any(|id| {
                knowledge.evidence(id).is_some_and(|evidence| {
                    evidence.predicate().namespace() == SSRF_OAST_EVIDENCE_NAMESPACE
                        && evidence.predicate().name() == name
                        && evidence.value() == &EvidenceValue::Boolean(true)
                        && evidence.source().component() == SSRF_OAST_EXECUTOR_ID
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use termivar_oast::{
        serve_provider_on_listener, AdminToken, LoopbackBind, ProviderConfig, ProviderLimits,
        ProviderState,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex as AsyncMutex,
        task::JoinHandle,
    };

    use crate::{
        ssrf_oast_review::{
            SsrfOastAdminToken, SsrfOastReviewPolicy, MIN_SSRF_OAST_ADMIN_TOKEN_BYTES,
        },
        web_runtime::{AssessmentDisposition, WebAssessmentRuntime},
    };

    const ADMIN_SECRET: &[u8] = b"SSRF-OAST-RUNTIME-ADMIN-MUST-NOT-LEAK-91C8";

    struct LoopbackFixture {
        target: url::Url,
        target_requests: Arc<AsyncMutex<Vec<String>>>,
        target_task: JoinHandle<()>,
        provider_task: JoinHandle<()>,
        provider_origin: PublicOrigin,
    }

    impl Drop for LoopbackFixture {
        fn drop(&mut self) {
            self.target_task.abort();
            self.provider_task.abort();
        }
    }

    async fn loopback_fixture() -> LoopbackFixture {
        let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider_address = provider_listener.local_addr().unwrap();
        let provider_origin = PublicOrigin::from_test_loopback(provider_address).unwrap();
        let provider = ProviderState::new(
            ProviderConfig::new(
                LoopbackBind::new(provider_address).unwrap(),
                provider_origin.clone(),
                ProviderLimits::new(
                    1,
                    2,
                    termivar_oast::HARD_MAX_EVENTS_PER_SESSION,
                    8,
                    termivar_oast::HARD_MAX_POLL_EVENTS_PER_RESPONSE,
                    20_000,
                    16,
                )
                .unwrap(),
            ),
            AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
        )
        .unwrap();
        let provider_task = tokio::spawn(async move {
            let _ = serve_provider_on_listener(provider_listener, provider).await;
        });

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target_requests = Arc::new(AsyncMutex::new(Vec::new()));
        let recorded = target_requests.clone();
        let target_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = target_listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1_024];
                    let Ok(read) = stream.read(&mut chunk).await else {
                        break;
                    };
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                recorded.lock().await.push(line.clone());
                let request_target = line.split_whitespace().nth(1).unwrap_or("/");
                let parsed = url::Url::parse(&format!("http://fixture.invalid{request_target}"));
                if let Ok(parsed) = parsed {
                    if let Some((_, callback)) =
                        parsed.query_pairs().find(|(name, _)| name == "url")
                    {
                        if let Ok(callback) = url::Url::parse(callback.as_ref()) {
                            let is_inert = callback
                                .host_str()
                                .is_some_and(|host| host.ends_with(".invalid"));
                            if !is_inert {
                                let client = reqwest::Client::builder()
                                    .redirect(reqwest::redirect::Policy::none())
                                    .build()
                                    .unwrap();
                                let _ = client.get(callback).send().await;
                            }
                        }
                    }
                }
                let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}";
                let _ = stream.write_all(response).await;
                let _ = stream.shutdown().await;
            }
        });
        LoopbackFixture {
            target: url::Url::parse(&format!(
                "http://{target_address}/proxy?url=https%3A%2F%2Fseed.example.invalid%2F"
            ))
            .unwrap(),
            target_requests,
            target_task,
            provider_task,
            provider_origin,
        }
    }

    #[test]
    fn provider_request_arithmetic_never_exceeds_twelve() {
        assert_eq!(1 + 2 + 1 + usize::from(MAX_POST_DISPATCH_POLLS) + 1, 12);
        assert_eq!(MAX_SSRF_OAST_REVIEW_REQUESTS, 3);
        assert_eq!(MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS, 1);
    }

    #[test]
    fn provider_errors_reduce_to_closed_terminal_classes() {
        use crate::RuntimeBudgetDimension;

        for (kind, expected) in [
            (
                NativeOastProviderErrorKind::Cancelled,
                SsrfOastTerminalState::Cancelled,
            ),
            (
                NativeOastProviderErrorKind::DeadlineExceeded,
                SsrfOastTerminalState::Expired,
            ),
            (
                NativeOastProviderErrorKind::PollLimit,
                SsrfOastTerminalState::PollExhausted,
            ),
            (
                NativeOastProviderErrorKind::ProviderRejected,
                SsrfOastTerminalState::ProviderAuthenticationFailed,
            ),
            (
                NativeOastProviderErrorKind::ProviderResponseInvalid,
                SsrfOastTerminalState::MalformedProviderResponse,
            ),
            (
                NativeOastProviderErrorKind::RuntimeBudget(RuntimeBudgetDimension::TotalRequests),
                SsrfOastTerminalState::BudgetExhausted,
            ),
            (
                NativeOastProviderErrorKind::InvalidLifecycle,
                SsrfOastTerminalState::Incomplete,
            ),
        ] {
            assert_eq!(provider_terminal(kind), expected);
        }
    }

    #[test]
    fn every_domain_outcome_has_one_closed_runtime_projection() {
        use SsrfOastReviewOutcome as Domain;
        use SsrfOastRuntimeOutcome as Runtime;

        for (domain, runtime) in [
            (Domain::NotEligible, Runtime::NotEligible),
            (Domain::ControlIncomplete, Runtime::ControlIncomplete),
            (
                Domain::RegistrationIncomplete,
                Runtime::RegistrationIncomplete,
            ),
            (Domain::AllocationIncomplete, Runtime::AllocationIncomplete),
            (
                Domain::PreflightContaminated,
                Runtime::PreflightContaminated,
            ),
            (Domain::TargetNotDispatched, Runtime::TargetNotDispatched),
            (Domain::NoCallback, Runtime::NoCallback),
            (Domain::CandidateOnly, Runtime::CandidateOnly),
            (Domain::ReplayOnly, Runtime::ReplayOnly),
            (Domain::WrongCallback, Runtime::WrongCallback),
            (
                Domain::EventIdentityConflict,
                Runtime::EventIdentityConflict,
            ),
            (Domain::CorrelationMismatch, Runtime::CorrelationMismatch),
            (Domain::DuplicateOnly, Runtime::DuplicateOnly),
            (Domain::CleanupIncomplete, Runtime::CleanupIncomplete),
            (
                Domain::DefensiveInterference,
                Runtime::DefensiveInterference,
            ),
            (Domain::RateLimited, Runtime::RateLimited),
            (
                Domain::ProviderAuthenticationFailed,
                Runtime::ProviderAuthenticationFailed,
            ),
            (
                Domain::MalformedProviderResponse,
                Runtime::MalformedProviderResponse,
            ),
            (Domain::PollExhausted, Runtime::PollExhausted),
            (Domain::Expired, Runtime::Expired),
            (Domain::Cancelled, Runtime::Cancelled),
            (Domain::BudgetExhausted, Runtime::BudgetExhausted),
            (Domain::Truncated, Runtime::Truncated),
            (Domain::Incomplete, Runtime::Incomplete),
            (
                Domain::RepeatedCallbacksObserved,
                Runtime::RepeatedCallbacksObserved,
            ),
        ] {
            assert_eq!(SsrfOastRuntimeOutcome::from(domain), runtime);
        }
    }

    #[test]
    fn lifecycle_gate_requires_clean_preflight_and_stops_on_non_timeout_terminal() {
        let candidate: CallbackId = "AQEBAQEBAQEBAQEBAQEBAQ".parse().unwrap();
        let replay: CallbackId = "AgICAgICAgICAgICAgICAg".parse().unwrap();
        let mut facts = SsrfOastReviewFacts::new(&candidate, &replay);
        facts.control_complete = true;
        facts.provider_registered = true;
        facts.allocations_complete = true;
        facts.preflight_clean = true;
        let lifecycle = SsrfOastLifecycleEvidence::from_facts(&facts, false);
        assert!(lifecycle.candidate_ready());
        assert!(polling_may_continue(&facts));

        facts.terminal = Some(SsrfOastTerminalState::TargetTimeoutAfterDispatch);
        assert!(polling_may_continue(&facts));
        facts.terminal = Some(SsrfOastTerminalState::Cancelled);
        assert!(!polling_may_continue(&facts));

        facts.terminal = None;
        facts.preflight_clean = false;
        assert!(!SsrfOastLifecycleEvidence::from_facts(&facts, false).candidate_ready());
        assert!(!SsrfOastLifecycleEvidence::terminal().candidate_ready());
    }

    #[test]
    fn post_dispatch_timeout_preserves_callback_eligibility_but_pre_dispatch_failure_does_not() {
        use crate::oast::OastEventKey;

        assert!(target_dispatch_outcome_is_accounted(
            TransportDispatchOutcome::RequestTimeout
        ));
        assert!(!target_dispatch_outcome_is_accounted(
            TransportDispatchOutcome::TransportFailure
        ));

        let candidate: CallbackId = "AQEBAQEBAQEBAQEBAQEBAQ".parse().unwrap();
        let replay: CallbackId = "AgICAgICAgICAgICAgICAg".parse().unwrap();
        let mut facts = SsrfOastReviewFacts::new(&candidate, &replay);
        facts.control_complete = true;
        facts.provider_registered = true;
        facts.allocations_complete = true;
        facts.preflight_clean = true;
        facts.candidate_dispatched = true;
        facts.replay_dispatched = true;
        facts.candidate_event = Some(SsrfOastObservedEvent::from_reduced(
            &candidate,
            &OastEventKey::new([3; 32]).unwrap(),
        ));
        facts.replay_event = Some(SsrfOastObservedEvent::from_reduced(
            &replay,
            &OastEventKey::new([4; 32]).unwrap(),
        ));
        facts.correlations_distinct = true;
        facts.same_correlation_scope = true;
        facts.cleanup_verified = true;
        facts.target_accounting_complete = [
            TransportDispatchOutcome::Completed,
            TransportDispatchOutcome::RequestTimeout,
            TransportDispatchOutcome::Completed,
        ]
        .into_iter()
        .all(target_dispatch_outcome_is_accounted);
        facts.provider_accounting_complete = true;
        facts.terminal = Some(SsrfOastTerminalState::TargetTimeoutAfterDispatch);
        assert_eq!(
            evaluate_ssrf_oast_review(&facts).unwrap(),
            SsrfOastReviewOutcome::RepeatedCallbacksObserved
        );

        facts.terminal = None;
        facts.replay_dispatched = false;
        facts.target_accounting_complete =
            target_dispatch_outcome_is_accounted(TransportDispatchOutcome::TransportFailure);
        assert_eq!(
            evaluate_ssrf_oast_review(&facts).unwrap(),
            SsrfOastReviewOutcome::TargetNotDispatched
        );
    }

    #[test]
    fn audit_is_raw_free_and_uses_exact_bounded_counts() {
        let target =
            url::Url::parse("http://127.0.0.1:41001/proxy?url=https://seed.invalid/").unwrap();
        let provider =
            PublicOrigin::from_test_loopback("127.0.0.1:41002".parse().unwrap()).unwrap();
        let policy = SsrfOastReviewPolicy::for_loopback(target, provider, 1, 250, 5_000).unwrap();
        let candidate: CallbackId = "AQEBAQEBAQEBAQEBAQEBAQ".parse().unwrap();
        let replay: CallbackId = "AgICAgICAgICAgICAgICAg".parse().unwrap();
        let mut facts = SsrfOastReviewFacts::new(&candidate, &replay);
        facts.preflight_clean = true;
        facts.cleanup_verified = true;
        let state = SsrfOastExecutionState {
            facts: Some(facts),
            provider_request_count: 7,
            source: Some(SsrfOastCandidateSource::ObservedUrlQuery),
            cleanup_verified: true,
            ..SsrfOastExecutionState::default()
        };
        let audit = audit(
            &policy,
            &state,
            SsrfOastRuntimeOutcome::NoCallback,
            3,
            false,
        );
        assert_eq!(audit.outcome(), SsrfOastRuntimeOutcome::NoCallback);
        assert_eq!(audit.candidate_source(), Some("observed_url_query"));
        assert_eq!(audit.target_request_count(), 3);
        assert_eq!(audit.provider_request_count(), 7);
        assert_eq!(audit.active_verification_count(), 1);
        assert!(audit.preflight_clean());
        assert!(audit.cleanup_verified());
        assert!(!audit.candidate_callback_observed());
        assert!(!audit.replay_callback_observed());
        assert!(!audit.item_projected());
        let rendered = format!("{audit:?}");
        assert!(!rendered.contains("seed.invalid"));
        assert!(!rendered.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn loopback_target_reaches_two_distinct_callbacks_and_projects_one_item() {
        assert!(ADMIN_SECRET.len() >= MIN_SSRF_OAST_ADMIN_TOKEN_BYTES);
        let fixture = loopback_fixture().await;
        let policy = SsrfOastReviewPolicy::for_loopback(
            fixture.target.clone(),
            fixture.provider_origin.clone(),
            1,
            250,
            5_000,
        )
        .unwrap();
        let administrator = SsrfOastAdminToken::new(ADMIN_SECRET.to_vec()).unwrap();
        let mut runtime = WebAssessmentRuntime::builder(fixture.target.clone())
            .with_ssrf_oast_review(policy, administrator)
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();

        let audit = report.ssrf_oast_review_audit().unwrap();
        assert_eq!(
            audit.outcome(),
            SsrfOastRuntimeOutcome::RepeatedCallbacksObserved
        );
        assert_eq!(audit.target_request_count(), 3);
        assert_eq!(audit.active_verification_count(), 1);
        assert!(audit.preflight_clean());
        assert!(audit.candidate_callback_observed());
        assert!(audit.replay_callback_observed());
        assert!(audit.cleanup_verified());
        assert!(audit.item_projected());
        assert!(audit.provider_request_count() <= 12);
        let item = report
            .assessment_items()
            .iter()
            .find(|item| item.capability_id() == SSRF_OAST_REVIEW_CAPABILITY_ID)
            .unwrap();
        assert_eq!(item.disposition(), AssessmentDisposition::NeedsReview);
        assert_eq!(report.usage().active_verifications(), 1);

        let requests = fixture.target_requests.lock().await;
        assert_eq!(requests.len(), 4);
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains('?'))
                .count(),
            3
        );
        let debug = format!("{report:?}");
        assert!(!debug.contains(std::str::from_utf8(ADMIN_SECRET).unwrap()));
        assert!(!debug.contains("seed.example.invalid"));
    }
}
