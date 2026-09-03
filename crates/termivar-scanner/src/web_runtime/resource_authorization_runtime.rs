//! Explicitly enabled four-view authorization differential orchestration.
//!
//! This child owns neither transport nor budget authority. It installs one
//! executor under the parent [`WebAssessmentRuntime`], dispatches four fixed
//! bodyless GET legs through isolated views of the shared broker, reduces each
//! complete response through the transport-neutral authorization comparator,
//! and retains only typed, redaction-safe receipts.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate,
};

use super::{
    assessment_defense::{
        project_assessment_defense_signal, AssessmentDefenseBodyCoverage,
        AssessmentDefenseProjectionContext, AssessmentDefenseSignal,
    },
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext,
    },
};
use crate::{
    authorization_review::{
        AuthorizationDifferentialError, AuthorizationDifferentialResult,
        AuthorizationPrincipalExecutionHandoff, AuthorizationPrincipalPair,
        AuthorizationPrincipalPairProof, AuthorizationResourceScopeId,
        AuthorizationReviewBodyState, AuthorizationReviewMediaClass, AuthorizationReviewOutcome,
        AuthorizationReviewPolicy, AuthorizationReviewPolicyId, AuthorizationReviewView,
        AuthorizationReviewViewError, AuthorizationViewReceiptId, AuthorizationViewRole,
    },
    defense::DefenseState,
    http_evidence::{AuthorizationResponseDefense, HttpRequestBroker, HttpRequestBrokerError},
    DecisionActionExecutor, DecisionActionOrigin, DecisionExecutionRequest, DecisionExecutionStage,
    DecisionExecutorError, DecisionExecutorRegistry, KnowledgeBase, RuntimeLimitExceeded,
    TransportDispatchAudit, TransportDispatchOutcome,
};

/// The one optional native action installed by Resource Authorization Review V1.
pub const RESOURCE_AUTHORIZATION_REVIEW_ACTION_ID: &str =
    "web.review.authorization.resource-differential";
/// Stable AssessmentItem capability emitted only by exact positive truth.
pub const RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID: &str =
    "authorization.resource-cross-principal-equivalence@1";
/// V1 selects exactly one operator-declared resource.
pub const MAX_AUTHORIZATION_REVIEW_RESOURCES: usize = 1;
/// V1 dispatches exactly four independently accounted request legs.
pub const MAX_AUTHORIZATION_REVIEW_REQUESTS: usize = 4;
/// The four request legs form one logical active verification.
pub const MAX_AUTHORIZATION_REVIEW_ACTIVE_VERIFICATIONS: usize = 1;
/// One exact extra planner cycle reserved only when the optional native action is installed.
pub(super) const AUTHORIZATION_REVIEW_ACTION_CYCLE_ALLOWANCE: u32 = 1;

const RESOURCE_AUTHORIZATION_EXECUTOR_ID: &str = "http.authorization-resource-review";
const RESOURCE_AUTHORIZATION_EVIDENCE_NAMESPACE: &str = "web.authorization-review.transport";
const RESOURCE_AUTHORIZATION_RECEIPT_DOMAIN: &[u8] =
    b"security.authorization-review.response-receipt.v1\0";
const RESOURCE_AUTHORIZATION_REQUEST_DOMAIN: &[u8] =
    b"security.authorization-review.request-template.v1\0";

pub(super) const AUTHORIZATION_DEFENSE_STATUS_PREDICATE: &str = "defense-status";
pub(super) const AUTHORIZATION_DEFENSE_CHALLENGE_PREDICATE: &str = "defense-challenge";
pub(super) const AUTHORIZATION_DEFENSE_RATE_LIMIT_PREDICATE: &str = "defense-rate-limit";
pub(super) const AUTHORIZATION_DEFENSE_SCOPE_PREDICATE: &str = "defense-resource-scope";
pub(super) const AUTHORIZATION_NO_RESPONSE_TERMINAL_PREDICATE: &str = "no-response-terminal";

const RESOURCE_AUTHORIZATION_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID,
        "Unexpected cross-principal resource equivalence observed",
        "Authorization review",
        "Under an operator-declared primary-only policy, two distinct authenticated principal contexts repeatedly received equivalent selected JSON resource representations.",
        None,
        900_000,
        None,
        "authorization.resource-policy-review@1",
        "Review the intended resource-level authorization policy and verify server-side ownership, tenant, and role checks for the selected resource.",
    );

/// Redaction-safe audit embedded in the composed assessment report.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct WebAssessmentAuthorizationAudit {
    policy_id: AuthorizationReviewPolicyId,
    selected_path_count: u8,
    ignored_path_count: u8,
    request_count: u8,
    outcome: AuthorizationReviewOutcome,
    primary_stable: Option<bool>,
    peer_stable: Option<bool>,
    cross_resources_equivalent: Option<bool>,
    item_projected: bool,
}

impl WebAssessmentAuthorizationAudit {
    /// Returns the stable policy identity; it contains no resource or credential material.
    pub const fn policy_id(&self) -> AuthorizationReviewPolicyId {
        self.policy_id
    }

    /// Returns the number of selected JSON Pointer paths without exposing them.
    pub const fn selected_path_count(&self) -> u8 {
        self.selected_path_count
    }

    /// Returns the number of ignored JSON Pointer paths without exposing them.
    pub const fn ignored_path_count(&self) -> u8 {
        self.ignored_path_count
    }

    /// Returns the exact number of broker-dispatched legs.
    pub const fn request_count(&self) -> u8 {
        self.request_count
    }

    /// Returns the typed, non-boolean differential outcome.
    pub const fn outcome(&self) -> AuthorizationReviewOutcome {
        self.outcome
    }

    /// Returns whether the two primary views were fully equivalent.
    pub const fn primary_stable(&self) -> Option<bool> {
        self.primary_stable
    }

    /// Returns whether the two peer views were fully equivalent.
    pub const fn peer_stable(&self) -> Option<bool> {
        self.peer_stable
    }

    /// Returns whether both cross-principal rounds had equal resource fingerprints.
    pub const fn cross_resources_equivalent(&self) -> Option<bool> {
        self.cross_resources_equivalent
    }

    /// Returns whether the common projection authority emitted the review item.
    pub const fn item_projected(&self) -> bool {
        self.item_projected
    }

    fn from_result(
        policy: &AuthorizationReviewPolicy,
        request_count: usize,
        result: &AuthorizationDifferentialResult,
    ) -> Self {
        Self {
            policy_id: result.policy_id(),
            selected_path_count: u8::try_from(policy.selected_path_count()).unwrap_or(u8::MAX),
            ignored_path_count: u8::try_from(policy.ignored_path_count()).unwrap_or(u8::MAX),
            request_count: u8::try_from(request_count).unwrap_or(u8::MAX),
            outcome: result.outcome(),
            primary_stable: result.primary_stability().map(|value| value.all()),
            peer_stable: result.peer_stability().map(|value| value.all()),
            cross_resources_equivalent: result
                .cross_candidate()
                .zip(result.cross_replay())
                .map(|(candidate, replay)| candidate.resources() && replay.resources()),
            item_projected: result.outcome()
                == AuthorizationReviewOutcome::StableCrossPrincipalEquivalence,
        }
    }

    fn stopped(
        policy: &AuthorizationReviewPolicy,
        request_count: usize,
        outcome: AuthorizationReviewOutcome,
    ) -> Self {
        Self {
            policy_id: policy.policy_id(),
            selected_path_count: u8::try_from(policy.selected_path_count()).unwrap_or(u8::MAX),
            ignored_path_count: u8::try_from(policy.ignored_path_count()).unwrap_or(u8::MAX),
            request_count: u8::try_from(request_count).unwrap_or(u8::MAX),
            outcome,
            primary_stable: None,
            peer_stable: None,
            cross_resources_equivalent: None,
            item_projected: false,
        }
    }
}

impl fmt::Debug for WebAssessmentAuthorizationAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentAuthorizationAudit")
            .field("policy_id", &self.policy_id)
            .field("selected_path_count", &self.selected_path_count)
            .field("ignored_path_count", &self.ignored_path_count)
            .field("request_count", &self.request_count)
            .field("outcome", &self.outcome)
            .field("primary_stable", &self.primary_stable)
            .field("peer_stable", &self.peer_stable)
            .field(
                "cross_resources_equivalent",
                &self.cross_resources_equivalent,
            )
            .field("item_projected", &self.item_projected)
            .finish()
    }
}

/// Move-only runtime configuration consumed by the sole assessment root.
pub(super) struct ResourceAuthorizationReviewConfig {
    policy: AuthorizationReviewPolicy,
    principals: AuthorizationPrincipalExecutionHandoff,
}

impl ResourceAuthorizationReviewConfig {
    pub(super) fn new(
        policy: AuthorizationReviewPolicy,
        principals: AuthorizationPrincipalPair,
    ) -> Self {
        Self {
            policy,
            principals: principals.into_execution_handoff(),
        }
    }

    pub(super) fn execution_resource(&self) -> &url::Url {
        self.policy.execution_resource()
    }
}

impl fmt::Debug for ResourceAuthorizationReviewConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceAuthorizationReviewConfig(<redacted>)")
    }
}

/// Parent-installed executor binding for the one optional native action.
///
/// The binding owns the move-only principal material, but it does not own a
/// registry, runner, broker, budget, authority, or report. Those remain under
/// [`WebAssessmentRuntime`](super::WebAssessmentRuntime).
pub(super) struct ResourceAuthorizationRuntimeBinding {
    policy: Arc<AuthorizationReviewPolicy>,
    proof: AuthorizationPrincipalPairProof,
    subject: EntityId,
    executor: Arc<ResourceAuthorizationDecisionExecutor>,
}

impl ResourceAuthorizationRuntimeBinding {
    /// Builds the move-only child binding without creating transport, budget,
    /// runner, or registry authority.
    pub(super) fn new(
        config: ResourceAuthorizationReviewConfig,
        requests: HttpRequestBroker,
        subject: EntityId,
    ) -> Result<Self, ResourceAuthorizationRuntimeInvariantError> {
        let ResourceAuthorizationReviewConfig { policy, principals } = config;
        let AuthorizationPrincipalExecutionHandoff {
            primary_authorization,
            peer_authorization,
            proof,
        } = principals;
        let policy = Arc::new(policy);
        let executor = Arc::new(ResourceAuthorizationDecisionExecutor {
            requests,
            policy: Arc::clone(&policy),
            subject: subject.clone(),
            primary_authorization,
            peer_authorization,
            state: Mutex::new(ResourceAuthorizationExecutionState::default()),
        });
        Ok(Self {
            policy,
            proof,
            subject,
            executor,
        })
    }

    /// Installs one executor and two routes into the registry already owned by
    /// the parent [`StandardWebDecisionRuntime`](super::StandardWebDecisionRuntime).
    pub(super) fn install_into_parent_registry(
        &self,
        registry: &mut DecisionExecutorRegistry,
    ) -> Result<(), ResourceAuthorizationRuntimeInvariantError> {
        let before = registry.len();
        let registered: Arc<dyn DecisionActionExecutor> = self.executor.clone();
        registry
            .register(registered)
            .map_err(|_| ResourceAuthorizationRuntimeInvariantError::Catalog)?;
        for stage in [
            DecisionExecutionStage::Passive,
            DecisionExecutionStage::Active,
        ] {
            registry
                .route_action(
                    stage,
                    RESOURCE_AUTHORIZATION_REVIEW_ACTION_ID,
                    RESOURCE_AUTHORIZATION_EXECUTOR_ID,
                )
                .map_err(|_| ResourceAuthorizationRuntimeInvariantError::Catalog)?;
        }
        (registry.len() == before.saturating_add(1)
            && registry.contains(RESOURCE_AUTHORIZATION_EXECUTOR_ID))
        .then_some(())
        .ok_or(ResourceAuthorizationRuntimeInvariantError::Catalog)
    }

    /// Finalizes already committed parent-runner evidence. This method performs
    /// no I/O and creates no detached report or execution lifecycle.
    pub(super) fn finalize(
        self,
        knowledge: &KnowledgeBase,
        transport: &TransportDispatchAudit,
        forced_outcome: Option<AuthorizationReviewOutcome>,
        forced_runtime_limit: Option<RuntimeLimitExceeded>,
    ) -> Result<ResourceAuthorizationRuntimeResult, ResourceAuthorizationRuntimeInvariantError>
    {
        if transport.omitted_receipt_count() != 0 {
            return Err(ResourceAuthorizationRuntimeInvariantError::Catalog);
        }
        let authorization_receipts = transport
            .receipts()
            .iter()
            .filter(|receipt| receipt.action_id() == RESOURCE_AUTHORIZATION_REVIEW_ACTION_ID)
            .collect::<Vec<_>>();
        let request_count = authorization_receipts.len();
        if request_count > MAX_AUTHORIZATION_REVIEW_REQUESTS {
            return Err(ResourceAuthorizationRuntimeInvariantError::Catalog);
        }
        if !authorization_transport_prefix_is_valid(&authorization_receipts) {
            return Err(ResourceAuthorizationRuntimeInvariantError::Catalog);
        }
        let state = self.executor.take_state()?;
        let terminal = forced_outcome.or(state.terminal);
        let runtime_limit = if forced_outcome.is_some() {
            forced_runtime_limit
        } else {
            state.runtime_limit
        };
        if let Some(outcome) = terminal {
            return Ok(ResourceAuthorizationRuntimeResult::Stopped {
                audit: WebAssessmentAuthorizationAudit::stopped(
                    &self.policy,
                    request_count,
                    outcome,
                ),
                runtime_limit,
            });
        }
        let mut captured = state.captured;
        let exact_roles = [
            AuthorizationViewRole::PrimaryCandidate,
            AuthorizationViewRole::PeerCandidate,
            AuthorizationViewRole::PrimaryReplay,
            AuthorizationViewRole::PeerReplay,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let captured_roles = captured.keys().copied().collect::<BTreeSet<_>>();
        if request_count == 0 && captured_roles.is_empty() {
            return Ok(ResourceAuthorizationRuntimeResult::Stopped {
                audit: WebAssessmentAuthorizationAudit::stopped(
                    &self.policy,
                    0,
                    AuthorizationReviewOutcome::NotEligible,
                ),
                runtime_limit: None,
            });
        }
        if request_count != MAX_AUTHORIZATION_REVIEW_REQUESTS || captured_roles != exact_roles {
            return Ok(ResourceAuthorizationRuntimeResult::Stopped {
                audit: WebAssessmentAuthorizationAudit::stopped(
                    &self.policy,
                    request_count,
                    AuthorizationReviewOutcome::Incomplete,
                ),
                runtime_limit: None,
            });
        }
        let primary_candidate = take_role(&mut captured, AuthorizationViewRole::PrimaryCandidate)?;
        let peer_candidate = take_role(&mut captured, AuthorizationViewRole::PeerCandidate)?;
        let primary_replay = take_role(&mut captured, AuthorizationViewRole::PrimaryReplay)?;
        let peer_replay = take_role(&mut captured, AuthorizationViewRole::PeerReplay)?;
        if !captured.is_empty()
            || authorization_receipts.iter().any(|receipt| {
                receipt.request_body_bytes() != 0
                    || receipt.outcome() != TransportDispatchOutcome::Completed
            })
        {
            return Err(ResourceAuthorizationRuntimeInvariantError::Catalog);
        }
        let result = AuthorizationDifferentialResult::compare(
            &self.policy,
            self.proof,
            [
                &primary_candidate.view,
                &peer_candidate.view,
                &primary_replay.view,
                &peer_replay.view,
            ],
        )?;
        let primary_evidence_ids = vec![
            primary_candidate.evidence_id.clone(),
            primary_replay.evidence_id.clone(),
        ];
        let peer_evidence_ids = vec![
            peer_candidate.evidence_id.clone(),
            peer_replay.evidence_id.clone(),
        ];
        let unique = primary_evidence_ids
            .iter()
            .chain(peer_evidence_ids.iter())
            .collect::<BTreeSet<_>>();
        if unique.len() != MAX_AUTHORIZATION_REVIEW_REQUESTS
            || unique
                .iter()
                .any(|evidence_id| knowledge.evidence(evidence_id).is_none())
        {
            return Err(ResourceAuthorizationRuntimeInvariantError::Catalog);
        }
        let audit =
            WebAssessmentAuthorizationAudit::from_result(&self.policy, request_count, &result);
        Ok(ResourceAuthorizationRuntimeResult::Complete(Box::new(
            CommittedResourceAuthorizationReview {
                subject: self.subject,
                policy_id: self.policy.policy_id(),
                resource_scope_id: self.policy.resource_scope_id(),
                result,
                primary_evidence_ids,
                peer_evidence_ids,
                audit,
            },
        )))
    }
}

fn authorization_transport_prefix_is_valid(receipts: &[&crate::TransportDispatchReceipt]) -> bool {
    receipts.iter().enumerate().all(|(index, receipt)| {
        let expected_stage = if index == 2 {
            DecisionExecutionStage::Active
        } else {
            DecisionExecutionStage::Passive
        };
        let expected_origin = (expected_stage == DecisionExecutionStage::Passive)
            .then_some(DecisionActionOrigin::Planned);
        receipt.stage() == expected_stage && receipt.origin() == expected_origin
    })
}

impl fmt::Debug for ResourceAuthorizationRuntimeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceAuthorizationRuntimeBinding(<redacted>)")
    }
}

/// Internal composition failures are code-contract failures, not target behavior.
#[derive(Debug, thiserror::Error)]
pub(super) enum ResourceAuthorizationRuntimeInvariantError {
    #[error("authorization review execution catalog violated its closed contract")]
    Catalog,
    #[error("authorization review view reduction failed")]
    View(#[from] AuthorizationReviewViewError),
    #[error("authorization review differential contract failed")]
    Differential(#[from] AuthorizationDifferentialError),
    #[error("authorization review evidence construction failed")]
    Evidence(#[from] termivar_core::ReasoningModelError),
    #[error("authorization review evidence commit failed")]
    Knowledge(#[from] crate::KnowledgeBaseError),
}

pub(super) enum ResourceAuthorizationRuntimeResult {
    Complete(Box<CommittedResourceAuthorizationReview>),
    Stopped {
        audit: WebAssessmentAuthorizationAudit,
        runtime_limit: Option<RuntimeLimitExceeded>,
    },
}

/// Exact committed comparison truth consumed by the common item projection.
pub(super) struct CommittedResourceAuthorizationReview {
    subject: EntityId,
    policy_id: AuthorizationReviewPolicyId,
    resource_scope_id: AuthorizationResourceScopeId,
    result: AuthorizationDifferentialResult,
    primary_evidence_ids: Vec<EvidenceId>,
    peer_evidence_ids: Vec<EvidenceId>,
    audit: WebAssessmentAuthorizationAudit,
}

impl CommittedResourceAuthorizationReview {
    pub(super) const fn outcome(&self) -> AuthorizationReviewOutcome {
        self.result.outcome()
    }

    pub(super) const fn audit(&self) -> &WebAssessmentAuthorizationAudit {
        &self.audit
    }
}

impl fmt::Debug for CommittedResourceAuthorizationReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedResourceAuthorizationReview")
            .field("subject", &"<pseudonymous>")
            .field("policy_id", &self.policy_id)
            .field("resource_scope_id", &self.resource_scope_id)
            .field("outcome", &self.result.outcome())
            .field("evidence_count", &4)
            .field("audit", &self.audit)
            .finish()
    }
}

struct CapturedAuthorizationLeg {
    view: AuthorizationReviewView,
    evidence_id: EvidenceId,
}

#[derive(Default)]
struct ResourceAuthorizationExecutionState {
    captured: BTreeMap<AuthorizationViewRole, CapturedAuthorizationLeg>,
    terminal: Option<AuthorizationReviewOutcome>,
    runtime_limit: Option<RuntimeLimitExceeded>,
}

struct ResourceAuthorizationDecisionExecutor {
    requests: HttpRequestBroker,
    policy: Arc<AuthorizationReviewPolicy>,
    subject: EntityId,
    primary_authorization: String,
    peer_authorization: String,
    state: Mutex<ResourceAuthorizationExecutionState>,
}

impl ResourceAuthorizationDecisionExecutor {
    fn roles_for_stage(stage: DecisionExecutionStage) -> [AuthorizationViewRole; 2] {
        match stage {
            DecisionExecutionStage::Passive => [
                AuthorizationViewRole::PrimaryCandidate,
                AuthorizationViewRole::PeerCandidate,
            ],
            DecisionExecutionStage::Active => [
                AuthorizationViewRole::PrimaryReplay,
                AuthorizationViewRole::PeerReplay,
            ],
        }
    }

    fn authorization_for(&self, role: AuthorizationViewRole) -> &str {
        match role {
            AuthorizationViewRole::PrimaryCandidate | AuthorizationViewRole::PrimaryReplay => {
                &self.primary_authorization
            },
            AuthorizationViewRole::PeerCandidate | AuthorizationViewRole::PeerReplay => {
                &self.peer_authorization
            },
        }
    }

    fn take_state(
        &self,
    ) -> Result<ResourceAuthorizationExecutionState, ResourceAuthorizationRuntimeInvariantError>
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ResourceAuthorizationRuntimeInvariantError::Catalog)?;
        Ok(std::mem::take(&mut *state))
    }

    fn phase_is_ready(&self, stage: DecisionExecutionStage) -> Result<bool, DecisionExecutorError> {
        let state = self.state.lock().map_err(|_| {
            DecisionExecutorError::new("authorization capture state is unavailable")
        })?;
        let expected = match stage {
            DecisionExecutionStage::Passive => {
                state.captured.is_empty() && state.terminal.is_none()
            },
            DecisionExecutionStage::Active => {
                state.terminal.is_none()
                    && state
                        .captured
                        .contains_key(&AuthorizationViewRole::PrimaryCandidate)
                    && state
                        .captured
                        .contains_key(&AuthorizationViewRole::PeerCandidate)
                    && !state
                        .captured
                        .contains_key(&AuthorizationViewRole::PrimaryReplay)
                    && !state
                        .captured
                        .contains_key(&AuthorizationViewRole::PeerReplay)
            },
        };
        Ok(expected)
    }

    fn commit_leg(
        &self,
        role: AuthorizationViewRole,
        leg: CapturedAuthorizationLeg,
    ) -> Result<(), DecisionExecutorError> {
        let replaced = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("authorization capture state is unavailable"))?
            .captured
            .insert(role, leg);
        if replaced.is_some() {
            return Err(DecisionExecutorError::new(
                "authorization review attempted a duplicate leg",
            ));
        }
        Ok(())
    }

    fn stop(&self, outcome: AuthorizationReviewOutcome) -> Result<(), DecisionExecutorError> {
        let mut state = self.state.lock().map_err(|_| {
            DecisionExecutorError::new("authorization capture state is unavailable")
        })?;
        if state.terminal.replace(outcome).is_some() {
            return Err(DecisionExecutorError::new(
                "authorization review attempted a duplicate terminal state",
            ));
        }
        Ok(())
    }

    fn stop_at_runtime_limit(
        &self,
        limit: RuntimeLimitExceeded,
    ) -> Result<(), DecisionExecutorError> {
        let mut state = self.state.lock().map_err(|_| {
            DecisionExecutorError::new("authorization capture state is unavailable")
        })?;
        if state
            .terminal
            .replace(AuthorizationReviewOutcome::BudgetExhausted)
            .is_some()
            || state.runtime_limit.replace(limit).is_some()
        {
            return Err(DecisionExecutorError::new(
                "authorization review attempted a duplicate terminal state",
            ));
        }
        Ok(())
    }
}

impl Drop for ResourceAuthorizationDecisionExecutor {
    fn drop(&mut self) {
        self.primary_authorization.clear();
        self.peer_authorization.clear();
    }
}

#[async_trait]
impl DecisionActionExecutor for ResourceAuthorizationDecisionExecutor {
    fn id(&self) -> &str {
        RESOURCE_AUTHORIZATION_EXECUTOR_ID
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        if request.case().action_id() != RESOURCE_AUTHORIZATION_REVIEW_ACTION_ID
            || request.case().subject() != &self.subject
            || request.case().applies_hypothesis_transition()
            || request.case().payload_strategy().is_some()
            || request.delay_ms().is_some()
            || (request.stage() == DecisionExecutionStage::Passive && request.origin().is_none())
            || (request.stage() == DecisionExecutionStage::Active && request.origin().is_some())
            || !self.phase_is_ready(request.stage())?
        {
            return Err(DecisionExecutorError::new(
                "authorization executor request violated its closed route contract",
            ));
        }

        let roles = Self::roles_for_stage(request.stage());
        let mut evidence = Vec::new();
        let mut response_bytes = 0_u64;
        let mut last_defense = None;
        for role in roles {
            // Each role receives a fresh pool but retains the parent's exact
            // policy and accounting broker. Cookie, redirect, retry, and
            // connection-bound authentication state cannot cross roles.
            let isolated = match self.requests.isolated() {
                Ok(isolated) => isolated,
                Err(_) => {
                    self.stop(AuthorizationReviewOutcome::Incomplete)?;
                    break;
                },
            };
            let transport_stage = if role == AuthorizationViewRole::PrimaryReplay {
                DecisionExecutionStage::Active
            } else {
                DecisionExecutionStage::Passive
            };
            let origin = (transport_stage == DecisionExecutionStage::Passive)
                .then_some(DecisionActionOrigin::Planned);
            let response = isolated
                .collect_authorized_json_get_for_runtime(
                    RESOURCE_AUTHORIZATION_REVIEW_ACTION_ID,
                    transport_stage,
                    origin,
                    request.limits(),
                    self.policy.execution_resource(),
                    self.authorization_for(role),
                )
                .await;
            let response = match response {
                Ok(response) => response,
                Err(HttpRequestBrokerError::RuntimeLimit(limit)) => {
                    self.stop_at_runtime_limit(limit)?;
                    break;
                },
                Err(HttpRequestBrokerError::Http(_)) => {
                    self.stop(AuthorizationReviewOutcome::Incomplete)?;
                    break;
                },
            };
            response_bytes = response_bytes
                .saturating_add(u64::try_from(response.body().len()).unwrap_or(u64::MAX));
            let captured = capture_response(
                &self.policy,
                &self.subject,
                request.case().id(),
                role,
                response,
            )?;
            last_defense = Some(captured.defense);
            let terminal = terminal_outcome_for_state(captured.leg.view.state());
            evidence.push(captured.evidence);
            self.commit_leg(role, captured.leg)?;
            if let Some(outcome) = terminal {
                self.stop(outcome)?;
                break;
            }
        }
        let terminal = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("authorization capture state is unavailable"))?
            .terminal;
        append_phase_evidence(
            &mut evidence,
            &self.policy,
            request,
            response_bytes,
            last_defense,
            terminal,
        )?;
        Ok(evidence)
    }
}

struct CapturedResponse {
    leg: CapturedAuthorizationLeg,
    evidence: Evidence,
    defense: AuthorizationPhaseDefense,
}

#[derive(Clone, Copy)]
struct AuthorizationPhaseDefense {
    status: u16,
    classification: AuthorizationResponseDefense,
}

fn capture_response(
    policy: &AuthorizationReviewPolicy,
    subject: &EntityId,
    correlation_id: &str,
    role: AuthorizationViewRole,
    response: crate::http_evidence::CollectedHttpResponse,
) -> Result<CapturedResponse, DecisionExecutorError> {
    if response.final_url() != policy.execution_resource() {
        return Err(DecisionExecutorError::new(
            "authorization review transport changed the exact resource",
        ));
    }
    let media_type = response.normalized_media_type();
    let media_class = if response.has_json_compatible_media_type() {
        AuthorizationReviewMediaClass::JsonCompatible
    } else if matches!(
        media_type.as_deref(),
        Some("text/html" | "application/xhtml+xml")
    ) {
        AuthorizationReviewMediaClass::Html
    } else if media_type.is_some() {
        AuthorizationReviewMediaClass::Other
    } else {
        AuthorizationReviewMediaClass::Missing
    };
    let status = response.status();
    let response_digest: [u8; 32] = Sha256::digest(response.body()).into();
    let receipt_digest = view_receipt_digest(policy, role, status, media_class, response_digest);
    let receipt_id = AuthorizationViewReceiptId::from_digest(receipt_digest);
    let defense = response.authorization_response_defense();
    let view = if response.body_truncated() {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::Truncated,
            receipt_id,
        )
    } else if !response.body_complete() {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::Incomplete,
            receipt_id,
        )
    } else if defense == AuthorizationResponseDefense::RateLimited {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::RateLimited,
            receipt_id,
        )
    } else if defense == AuthorizationResponseDefense::Challenge {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::DefensiveInterference,
            receipt_id,
        )
    } else if (300..400).contains(&status) {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::Redirect,
            receipt_id,
        )
    } else if (500..600).contains(&status) {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::ServerError,
            receipt_id,
        )
    } else if media_class == AuthorizationReviewMediaClass::Html {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::Html,
            receipt_id,
        )
    } else if media_class != AuthorizationReviewMediaClass::JsonCompatible {
        AuthorizationReviewView::terminal(
            policy,
            role,
            Some(status),
            media_class,
            AuthorizationReviewBodyState::UnsupportedMedia,
            receipt_id,
        )
    } else {
        match serde_json::from_slice::<serde_json::Value>(response.body()) {
            Ok(json) => {
                AuthorizationReviewView::capture_json(policy, role, status, &json, receipt_id)
            },
            Err(_) => AuthorizationReviewView::terminal(
                policy,
                role,
                Some(status),
                media_class,
                AuthorizationReviewBodyState::MalformedJson,
                receipt_id,
            ),
        }
    }
    .map_err(|_| DecisionExecutorError::new("authorization response reduction failed"))?;

    let request_digest = request_template_digest(policy, role);
    let evidence = Evidence::new(
        subject.clone(),
        EvidenceKind::Custom("authorization-review-leg".to_owned()),
        KnowledgePredicate::new(RESOURCE_AUTHORIZATION_EVIDENCE_NAMESPACE, "leg").map_err(
            |_| DecisionExecutorError::new("authorization evidence predicate is invalid"),
        )?,
        EvidenceValue::TextList(vec![
            format!("role={}", role_name(role)),
            format!("policy={}", policy.policy_id()),
            format!("resource={}", policy.resource_scope_id()),
            format!("request={}", encode_digest(request_digest)),
            format!("response={}", encode_digest(response_digest)),
            format!("receipt={}", encode_digest(receipt_digest)),
            format!("status={status}"),
            format!("media={}", media_name(media_class)),
            format!("state={}", state_name(view.state())),
        ]),
        EvidenceSource::new(RESOURCE_AUTHORIZATION_EXECUTOR_ID, "bounded-json-view")
            .and_then(|source| source.with_correlation_id(correlation_id))
            .map_err(|_| DecisionExecutorError::new("authorization evidence source is invalid"))?,
        ConfidenceScore::MAX,
    );
    let evidence_id = evidence.id().clone();
    Ok(CapturedResponse {
        leg: CapturedAuthorizationLeg { view, evidence_id },
        evidence,
        defense: AuthorizationPhaseDefense {
            status,
            classification: defense,
        },
    })
}

fn take_role(
    captured: &mut BTreeMap<AuthorizationViewRole, CapturedAuthorizationLeg>,
    role: AuthorizationViewRole,
) -> Result<CapturedAuthorizationLeg, ResourceAuthorizationRuntimeInvariantError> {
    captured
        .remove(&role)
        .ok_or(ResourceAuthorizationRuntimeInvariantError::Catalog)
}

fn terminal_outcome_for_state(
    state: AuthorizationReviewBodyState,
) -> Option<AuthorizationReviewOutcome> {
    Some(match state {
        AuthorizationReviewBodyState::CompleteJson => return None,
        AuthorizationReviewBodyState::RateLimited => AuthorizationReviewOutcome::RateLimited,
        AuthorizationReviewBodyState::DefensiveInterference => {
            AuthorizationReviewOutcome::DefensiveInterference
        },
        AuthorizationReviewBodyState::Redirect => AuthorizationReviewOutcome::RedirectObserved,
        AuthorizationReviewBodyState::UnsupportedMedia | AuthorizationReviewBodyState::Html => {
            AuthorizationReviewOutcome::UnsupportedMedia
        },
        AuthorizationReviewBodyState::MalformedJson => AuthorizationReviewOutcome::MalformedJson,
        AuthorizationReviewBodyState::Truncated => AuthorizationReviewOutcome::Truncated,
        AuthorizationReviewBodyState::BudgetExhausted => {
            AuthorizationReviewOutcome::BudgetExhausted
        },
        AuthorizationReviewBodyState::Cancelled => AuthorizationReviewOutcome::Cancelled,
        AuthorizationReviewBodyState::ServerError | AuthorizationReviewBodyState::Incomplete => {
            AuthorizationReviewOutcome::Incomplete
        },
    })
}

fn append_phase_evidence(
    evidence: &mut Vec<Evidence>,
    policy: &AuthorizationReviewPolicy,
    request: &DecisionExecutionRequest,
    response_bytes: u64,
    defense: Option<AuthorizationPhaseDefense>,
    terminal: Option<AuthorizationReviewOutcome>,
) -> Result<(), DecisionExecutorError> {
    let source = |method: &'static str| {
        EvidenceSource::new(RESOURCE_AUTHORIZATION_EXECUTOR_ID, method)
            .and_then(|source| source.with_correlation_id(request.case().id()))
            .map_err(|_| DecisionExecutorError::new("authorization evidence source is invalid"))
    };
    let direct = |kind: EvidenceKind,
                  predicate: KnowledgePredicate,
                  value: EvidenceValue,
                  method: &'static str|
     -> Result<Evidence, DecisionExecutorError> {
        Ok(Evidence::new(
            request.case().subject().clone(),
            kind,
            predicate,
            value,
            source(method)?,
            ConfidenceScore::MAX,
        ))
    };
    evidence.push(direct(
        EvidenceKind::Content,
        termivar_core::HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
        EvidenceValue::Unsigned(response_bytes),
        "response-body-size",
    )?);
    let no_response_terminal = defense.is_none() && terminal.is_some();
    evidence.push(direct(
        EvidenceKind::Custom("authorization-review-phase".to_owned()),
        KnowledgePredicate::new(
            RESOURCE_AUTHORIZATION_EVIDENCE_NAMESPACE,
            AUTHORIZATION_NO_RESPONSE_TERMINAL_PREDICATE,
        )
        .map_err(|_| DecisionExecutorError::new("authorization predicate is invalid"))?,
        EvidenceValue::Boolean(no_response_terminal),
        "phase-terminal",
    )?);
    evidence.push(direct(
        EvidenceKind::Custom("authorization-review-phase".to_owned()),
        crate::web_actions::authorization_review_phase_terminal_predicate(),
        EvidenceValue::Boolean(terminal.is_some()),
        "phase-terminal",
    )?);

    if request.stage() == DecisionExecutionStage::Active && terminal.is_none() {
        evidence.push(direct(
            EvidenceKind::Custom("native-web-review-response".to_owned()),
            crate::web_actions::native_web_review_response_marker_predicate(),
            EvidenceValue::Boolean(true),
            "pair-complete",
        )?);
    }

    let Some(defense) = defense else {
        return Ok(());
    };
    let (challenged, rate_limited) = match defense.classification {
        AuthorizationResponseDefense::Clear => (false, false),
        AuthorizationResponseDefense::Challenge => (true, false),
        AuthorizationResponseDefense::RateLimited => (false, true),
    };
    let status = defense.status;
    let base = [
        (
            AUTHORIZATION_DEFENSE_STATUS_PREDICATE,
            EvidenceValue::Unsigned(u64::from(status)),
        ),
        (
            AUTHORIZATION_DEFENSE_CHALLENGE_PREDICATE,
            EvidenceValue::Boolean(challenged),
        ),
        (
            AUTHORIZATION_DEFENSE_RATE_LIMIT_PREDICATE,
            EvidenceValue::Boolean(rate_limited),
        ),
        (
            AUTHORIZATION_DEFENSE_SCOPE_PREDICATE,
            EvidenceValue::Text(policy.resource_scope_id().to_wire()),
        ),
    ];
    let mut parents = Vec::with_capacity(base.len() + 1);
    parents.push(
        evidence
            .iter()
            .find(|item| {
                item.predicate()
                    == &termivar_core::HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED
                        .into_knowledge()
            })
            .ok_or_else(|| DecisionExecutorError::new("authorization byte evidence is missing"))?
            .id()
            .clone(),
    );
    for (name, value) in base {
        let item = direct(
            EvidenceKind::Custom("authorization-review-defense-base".to_owned()),
            KnowledgePredicate::new(RESOURCE_AUTHORIZATION_EVIDENCE_NAMESPACE, name)
                .map_err(|_| DecisionExecutorError::new("authorization predicate is invalid"))?,
            value,
            "defense-base",
        )?;
        parents.push(item.id().clone());
        evidence.push(item);
    }
    let signal = AssessmentDefenseSignal::new(
        DefenseState::from_authorization_projection(status, challenged, rate_limited),
        AssessmentDefenseBodyCoverage::MetadataOnly,
        false,
    );
    evidence.extend(
        project_assessment_defense_signal(
            &signal,
            AssessmentDefenseProjectionContext {
                subject: request.case().subject(),
                case_id: request.case().id(),
                executor_id: RESOURCE_AUTHORIZATION_EXECUTOR_ID,
                reliability: ConfidenceScore::MAX,
                parents,
            },
        )
        .map_err(|_| DecisionExecutorError::new("authorization defense projection failed"))?,
    );
    Ok(())
}

fn view_receipt_digest(
    policy: &AuthorizationReviewPolicy,
    role: AuthorizationViewRole,
    status: u16,
    media: AuthorizationReviewMediaClass,
    response_digest: [u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_framed(&mut digest, RESOURCE_AUTHORIZATION_RECEIPT_DOMAIN);
    update_framed(&mut digest, &policy.policy_id().as_bytes());
    update_framed(&mut digest, &policy.resource_scope_id().as_bytes());
    update_framed(&mut digest, role_name(role).as_bytes());
    update_framed(&mut digest, &status.to_be_bytes());
    update_framed(&mut digest, media_name(media).as_bytes());
    update_framed(&mut digest, &response_digest);
    digest.finalize().into()
}

fn request_template_digest(
    policy: &AuthorizationReviewPolicy,
    role: AuthorizationViewRole,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_framed(&mut digest, RESOURCE_AUTHORIZATION_REQUEST_DOMAIN);
    update_framed(&mut digest, &policy.policy_id().as_bytes());
    update_framed(&mut digest, &policy.resource_scope_id().as_bytes());
    update_framed(&mut digest, b"GET");
    update_framed(&mut digest, b"application/json");
    let principal_role: &[u8] = match role {
        AuthorizationViewRole::PrimaryCandidate | AuthorizationViewRole::PrimaryReplay => {
            b"primary".as_slice()
        },
        AuthorizationViewRole::PeerCandidate | AuthorizationViewRole::PeerReplay => {
            b"peer".as_slice()
        },
    };
    update_framed(&mut digest, principal_role);
    digest.finalize().into()
}

fn update_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn encode_digest(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn role_name(role: AuthorizationViewRole) -> &'static str {
    match role {
        AuthorizationViewRole::PrimaryCandidate => "primary_candidate",
        AuthorizationViewRole::PeerCandidate => "peer_candidate",
        AuthorizationViewRole::PrimaryReplay => "primary_replay",
        AuthorizationViewRole::PeerReplay => "peer_replay",
    }
}

const fn media_name(media: AuthorizationReviewMediaClass) -> &'static str {
    match media {
        AuthorizationReviewMediaClass::JsonCompatible => "json_compatible",
        AuthorizationReviewMediaClass::Html => "html",
        AuthorizationReviewMediaClass::Other => "other",
        AuthorizationReviewMediaClass::Missing => "missing",
    }
}

const fn state_name(state: AuthorizationReviewBodyState) -> &'static str {
    match state {
        AuthorizationReviewBodyState::CompleteJson => "complete_json",
        AuthorizationReviewBodyState::UnsupportedMedia => "unsupported_media",
        AuthorizationReviewBodyState::Html => "html",
        AuthorizationReviewBodyState::Redirect => "redirect",
        AuthorizationReviewBodyState::RateLimited => "rate_limited",
        AuthorizationReviewBodyState::ServerError => "server_error",
        AuthorizationReviewBodyState::MalformedJson => "malformed_json",
        AuthorizationReviewBodyState::Truncated => "truncated",
        AuthorizationReviewBodyState::Incomplete => "incomplete",
        AuthorizationReviewBodyState::BudgetExhausted => "budget_exhausted",
        AuthorizationReviewBodyState::Cancelled => "cancelled",
        AuthorizationReviewBodyState::DefensiveInterference => "defensive_interference",
    }
}

/// Projects at most one review-only item from exact positive four-view truth.
pub(super) fn project_resource_authorization_item(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    review: &CommittedResourceAuthorizationReview,
) -> Result<(), AssessmentItemProjectionError> {
    let all = review
        .primary_evidence_ids
        .iter()
        .chain(review.peer_evidence_ids.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    if all.len() != MAX_AUTHORIZATION_REVIEW_REQUESTS {
        return Err(AssessmentItemProjectionError::DuplicateEvidenceReference);
    }
    for evidence_id in all {
        context.register_evidence(knowledge, &evidence_id)?;
    }
    if review.outcome() == AuthorizationReviewOutcome::StableCrossPrincipalEquivalence {
        let mut target_digest = Sha256::new();
        update_framed(
            &mut target_digest,
            b"security.authorization-review.item-target.v1\0",
        );
        update_framed(&mut target_digest, &review.policy_id.as_bytes());
        update_framed(&mut target_digest, &review.resource_scope_id.as_bytes());
        update_framed(
            &mut target_digest,
            crate::authorization_review::AUTHORIZATION_REVIEW_ALGORITHM_VERSION.as_bytes(),
        );
        let target = AssessmentItemTarget::authorization_resource(format!(
            "authorization-resource@1:{}",
            encode_digest(target_digest.finalize().into())
        ))?;
        context.project_differential(
            &RESOURCE_AUTHORIZATION_CAPABILITY,
            knowledge,
            &review.subject,
            &target,
            &review.primary_evidence_ids,
            &review.peer_evidence_ids,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_catalog_and_audit_debug_are_bounded() {
        assert_eq!(MAX_AUTHORIZATION_REVIEW_RESOURCES, 1);
        assert_eq!(MAX_AUTHORIZATION_REVIEW_REQUESTS, 4);
        assert_eq!(MAX_AUTHORIZATION_REVIEW_ACTIVE_VERIFICATIONS, 1);
        assert_eq!(
            ResourceAuthorizationDecisionExecutor::roles_for_stage(DecisionExecutionStage::Passive),
            [
                AuthorizationViewRole::PrimaryCandidate,
                AuthorizationViewRole::PeerCandidate
            ]
        );
        assert_eq!(
            ResourceAuthorizationDecisionExecutor::roles_for_stage(DecisionExecutionStage::Active),
            [
                AuthorizationViewRole::PrimaryReplay,
                AuthorizationViewRole::PeerReplay
            ]
        );
    }

    #[test]
    fn request_identity_is_role_stable_and_credential_free() {
        let origin = url::Url::parse("https://example.test/").unwrap();
        let source = br#"
schema = "security.authorization-review-policy/v1"
resource = "/api/accounts/42"
resource_handle = "account-self-profile"
expectation = "primary-only"
method = "GET"
[comparison]
selected_paths = ["/data/account"]
ignored_paths = []
unordered_array_paths = []
max_diff_paths = 8
"#;
        let policy = AuthorizationReviewPolicy::parse_toml(&origin, source).unwrap();
        assert_eq!(
            request_template_digest(&policy, AuthorizationViewRole::PrimaryCandidate),
            request_template_digest(&policy, AuthorizationViewRole::PrimaryReplay)
        );
        assert_ne!(
            request_template_digest(&policy, AuthorizationViewRole::PrimaryCandidate),
            request_template_digest(&policy, AuthorizationViewRole::PeerCandidate)
        );
    }
}
