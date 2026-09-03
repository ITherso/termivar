//! Parent-native, explicitly enabled REST read-only surface observation.
//!
//! This module owns no transport authority. The binding installs one executor
//! into the parent decision registry and every wire leg is dispatched through
//! the parent assessment's exact-origin request broker and runtime budget.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use venom_core::{
    ApiSurfaceKind, ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource,
    EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
};

use super::{
    assessment_defense::{project_assessment_defense_signal, AssessmentDefenseProjectionContext},
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext,
    },
};
use crate::api_evidence::{ApiExactReplayComparison, ApiVisibilityEvidenceError};
use crate::{http_evidence::HttpRequestBroker, http_evidence::HttpRequestBrokerError};
use crate::{
    rest_review::{RestDocumentedResponseClass, RestOperationSelection},
    ApiVisibilityComparator, ApiVisibilityView, DecisionActionExecutor, DecisionActionOrigin,
    DecisionExecutionRequest, DecisionExecutionStage, DecisionExecutorError,
    DecisionExecutorRegistry, HttpProbe, HttpProbeMethod, KnowledgeBase, RuntimeLimitExceeded,
    TransportDispatchAudit, TransportDispatchOutcome,
};

pub const REST_REVIEW_ACTION_ID: &str = "web.review.rest.readonly-replay@1";
pub const REST_REVIEW_CAPABILITY_ID: &str = "api.rest-readonly-surface-observed@1";
pub const MAX_REST_REVIEW_RESOURCES: usize = 1;
pub const MAX_REST_REVIEW_REQUESTS: usize = 2;
pub const MAX_REST_REVIEW_ACTIVE_VERIFICATIONS: usize = 1;
pub(super) const REST_REVIEW_ACTION_CYCLE_ALLOWANCE: u32 = 1;

const REST_REVIEW_EXECUTOR_ID: &str = "http.rest-review";
const REST_REVIEW_EVIDENCE_NAMESPACE: &str = "web.rest-review.transport";
const REST_REVIEW_ACCEPT: &str = "application/json";
const REST_REVIEW_BODY_DIGEST_DOMAIN: &[u8] = b"security.rest-review.body-receipt.v1\0";

const REST_REVIEW_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        REST_REVIEW_CAPABILITY_ID,
        "REST operation surface observed",
        "API surface",
        "Two anonymous exact-origin GET requests reproduced the same bounded JSON resource structure.",
        900_000,
        "api.rest-readonly-surface-review@1",
        "Confirm that anonymously exposing this documented read-only operation matches deployment policy.",
    );

/// Closed runtime outcome for one selected read-only REST operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestRuntimeOutcome {
    NotEligible,
    SurfaceObserved,
    ReplayMismatch,
    CompleteNonJson,
    Redirect,
    AuthenticationRequired,
    Forbidden,
    NotFound,
    RateLimited,
    DefensiveInterference,
    ServerError,
    UnsupportedMedia,
    Truncated,
    Incomplete,
    Cancelled,
    BudgetExhausted,
}

/// Reduced media class retained by the public assessment audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestObservedMediaClass {
    JsonCompatible,
    Text,
    Unsupported,
    Unknown,
}

/// Bounded, raw-value-free audit for the optional REST child.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct WebAssessmentRestAudit {
    outcome: RestRuntimeOutcome,
    request_count: u8,
    active_verification_count: u8,
    eligible_operation_count: u32,
    selected_operation_identity: Option<String>,
    documented_response: Option<RestDocumentedResponseClass>,
    observed_media: RestObservedMediaClass,
    status_class: Option<u8>,
    replay_stable: bool,
    item_projected: bool,
}

impl WebAssessmentRestAudit {
    pub const fn outcome(&self) -> RestRuntimeOutcome {
        self.outcome
    }

    pub const fn request_count(&self) -> u8 {
        self.request_count
    }

    pub const fn active_verification_count(&self) -> u8 {
        self.active_verification_count
    }

    pub const fn eligible_operation_count(&self) -> u32 {
        self.eligible_operation_count
    }

    pub fn selected_operation_identity(&self) -> Option<&str> {
        self.selected_operation_identity.as_deref()
    }

    pub const fn documented_response(&self) -> Option<RestDocumentedResponseClass> {
        self.documented_response
    }

    pub const fn observed_media(&self) -> RestObservedMediaClass {
        self.observed_media
    }

    pub const fn status_class(&self) -> Option<u8> {
        self.status_class
    }

    pub const fn replay_stable(&self) -> bool {
        self.replay_stable
    }

    pub const fn item_projected(&self) -> bool {
        self.item_projected
    }
}

impl fmt::Debug for WebAssessmentRestAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentRestAudit")
            .field("outcome", &self.outcome)
            .field("request_count", &self.request_count)
            .field("active_verification_count", &self.active_verification_count)
            .field("eligible_operation_count", &self.eligible_operation_count)
            .field(
                "selected_operation_identity",
                &self
                    .selected_operation_identity
                    .as_ref()
                    .map(|_| "<stable-digest>"),
            )
            .field("documented_response", &self.documented_response)
            .field("observed_media", &self.observed_media)
            .field("status_class", &self.status_class)
            .field("replay_stable", &self.replay_stable)
            .field("item_projected", &self.item_projected)
            .finish()
    }
}

/// Single-assignment handoff populated only after OpenAPI candidate/replay
/// agreement. Clones share the same slot; no clone grants transport authority.
#[derive(Clone, Default)]
pub(super) struct StableRestSelectionSlot {
    selection: Arc<Mutex<Option<RestOperationSelection>>>,
}

impl StableRestSelectionSlot {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn commit(
        &self,
        selection: RestOperationSelection,
    ) -> Result<(), RestRuntimeInvariantError> {
        let mut slot = self
            .selection
            .lock()
            .map_err(|_| RestRuntimeInvariantError::Catalog)?;
        if slot.is_some() {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        *slot = Some(selection);
        Ok(())
    }

    pub(super) fn selection(
        &self,
    ) -> Result<Option<RestOperationSelection>, RestRuntimeInvariantError> {
        self.selection
            .lock()
            .map_err(|_| RestRuntimeInvariantError::Catalog)
            .map(|selection| selection.clone())
    }
}

impl fmt::Debug for StableRestSelectionSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableRestSelectionSlot(<redacted-single-assignment>)")
    }
}

/// Parent-owned binding for one optional REST action.
pub(super) struct RestReviewBinding {
    executor: Arc<RestDecisionExecutor>,
    subject: EntityId,
}

impl RestReviewBinding {
    pub(super) fn new(
        selection: StableRestSelectionSlot,
        requests: HttpRequestBroker,
        subject: EntityId,
    ) -> Self {
        let executor = Arc::new(RestDecisionExecutor {
            requests,
            selection,
            subject: subject.clone(),
            state: Mutex::new(RestExecutionState::default()),
        });
        Self { executor, subject }
    }

    pub(super) fn install_into_parent_registry(
        &self,
        registry: &mut DecisionExecutorRegistry,
    ) -> Result<(), RestRuntimeInvariantError> {
        let before = registry.len();
        let executor: Arc<dyn DecisionActionExecutor> = self.executor.clone();
        registry
            .register(executor)
            .map_err(|_| RestRuntimeInvariantError::Catalog)?;
        for stage in [
            DecisionExecutionStage::Passive,
            DecisionExecutionStage::Active,
        ] {
            registry
                .route_action(stage, REST_REVIEW_ACTION_ID, REST_REVIEW_EXECUTOR_ID)
                .map_err(|_| RestRuntimeInvariantError::Catalog)?;
        }
        if registry.len() != before + 1 {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        Ok(())
    }

    pub(super) fn finalize(
        self,
        knowledge: &KnowledgeBase,
        transport: &TransportDispatchAudit,
        forced_outcome: Option<RestRuntimeOutcome>,
        forced_runtime_limit: Option<RuntimeLimitExceeded>,
    ) -> Result<RestRuntimeResult, RestRuntimeInvariantError> {
        if transport.omitted_receipt_count() != 0 {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let selection = self.executor.selection.selection()?;
        let receipts = transport
            .receipts()
            .iter()
            .filter(|receipt| receipt.action_id() == REST_REVIEW_ACTION_ID)
            .collect::<Vec<_>>();
        if !rest_transport_prefix_is_valid(&receipts) {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let state = self.executor.take_state()?;
        if !captured_rest_prefix_reconciles(&state, &receipts) {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let request_count = u8::try_from(receipts.len()).unwrap_or(u8::MAX);
        let terminal = forced_outcome.or(state.terminal);
        let runtime_limit = if forced_outcome.is_some() {
            forced_runtime_limit
        } else {
            state.runtime_limit
        };

        if let Some(outcome) = terminal {
            let audit = audit(
                selection.as_ref(),
                outcome,
                request_count,
                state.terminal_observation,
                false,
            );
            if matches!(
                outcome,
                RestRuntimeOutcome::Truncated
                    | RestRuntimeOutcome::Incomplete
                    | RestRuntimeOutcome::BudgetExhausted
                    | RestRuntimeOutcome::Cancelled
            ) {
                return Ok(RestRuntimeResult::Stopped {
                    audit,
                    runtime_limit,
                });
            }
            return Ok(RestRuntimeResult::Complete(CommittedRestReview {
                subject: self.subject,
                target_identity: selection
                    .as_ref()
                    .map(|selected| selected.target_identity().to_owned()),
                outcome,
                evidence_ids: state
                    .legs
                    .values()
                    .flat_map(|leg| leg.evidence_ids.iter().cloned())
                    .collect(),
                audit,
            }));
        }

        let Some(selection) = selection else {
            return Ok(RestRuntimeResult::Complete(CommittedRestReview {
                subject: self.subject,
                target_identity: None,
                outcome: RestRuntimeOutcome::NotEligible,
                evidence_ids: Vec::new(),
                audit: audit(
                    None,
                    RestRuntimeOutcome::NotEligible,
                    request_count,
                    None,
                    false,
                ),
            }));
        };
        let (Some(candidate), Some(replay)) = (
            state.legs.get(&DecisionExecutionStage::Passive),
            state.legs.get(&DecisionExecutionStage::Active),
        ) else {
            return Ok(RestRuntimeResult::Stopped {
                audit: audit(
                    Some(&selection),
                    RestRuntimeOutcome::Incomplete,
                    request_count,
                    None,
                    false,
                ),
                runtime_limit: None,
            });
        };
        if receipts.len() != MAX_REST_REVIEW_REQUESTS
            || receipts
                .iter()
                .zip([candidate, replay])
                .any(|(receipt, leg)| {
                    receipt.outcome() != TransportDispatchOutcome::Completed
                        || receipt.response_bytes() != leg.response_bytes
                })
        {
            return Ok(RestRuntimeResult::Stopped {
                audit: audit(
                    Some(&selection),
                    RestRuntimeOutcome::Incomplete,
                    request_count,
                    None,
                    false,
                ),
                runtime_limit: None,
            });
        }

        let comparison = ApiVisibilityComparator::default()
            .compare_exact_replay(&candidate.view, &replay.view)
            .map_err(|_| RestRuntimeInvariantError::Catalog)?;
        let projected = comparison.all_equivalent();
        let outcome = if projected {
            RestRuntimeOutcome::SurfaceObserved
        } else {
            RestRuntimeOutcome::ReplayMismatch
        };
        let evidence_ids = state
            .legs
            .values()
            .flat_map(|leg| leg.evidence_ids.iter().cloned())
            .collect::<Vec<_>>();
        if evidence_ids.is_empty()
            || evidence_ids
                .iter()
                .any(|evidence_id| knowledge.evidence(evidence_id).is_none())
        {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let audit = audit(
            Some(&selection),
            outcome,
            request_count,
            Some(replay.audit_observation()),
            projected,
        );
        Ok(RestRuntimeResult::Complete(CommittedRestReview {
            subject: self.subject,
            target_identity: Some(selection.target_identity().to_owned()),
            outcome,
            evidence_ids,
            audit,
        }))
    }
}

fn rest_transport_prefix_is_valid(receipts: &[&crate::TransportDispatchReceipt]) -> bool {
    receipts.len() <= MAX_REST_REVIEW_REQUESTS
        && receipts.iter().enumerate().all(|(index, receipt)| {
            let expected_stage = if index == 0 {
                DecisionExecutionStage::Passive
            } else {
                DecisionExecutionStage::Active
            };
            let expected_origin = (expected_stage == DecisionExecutionStage::Passive)
                .then_some(DecisionActionOrigin::Planned);
            receipt.stage() == expected_stage
                && receipt.origin() == expected_origin
                && receipt.request_body_bytes() == 0
        })
}

fn captured_rest_prefix_reconciles(
    state: &RestExecutionState,
    receipts: &[&crate::TransportDispatchReceipt],
) -> bool {
    state.legs.iter().all(|(stage, leg)| {
        let index = match stage {
            DecisionExecutionStage::Passive => 0,
            DecisionExecutionStage::Active => 1,
        };
        receipts.get(index).is_some_and(|receipt| {
            receipt.outcome() == TransportDispatchOutcome::Completed
                && receipt.response_bytes() == leg.response_bytes
        })
    })
}

#[derive(Debug, thiserror::Error)]
pub(super) enum RestRuntimeInvariantError {
    #[error("REST review catalog invariant failed")]
    Catalog,
}

pub(super) enum RestRuntimeResult {
    Complete(CommittedRestReview),
    Stopped {
        audit: WebAssessmentRestAudit,
        runtime_limit: Option<RuntimeLimitExceeded>,
    },
}

pub(super) struct CommittedRestReview {
    subject: EntityId,
    target_identity: Option<String>,
    outcome: RestRuntimeOutcome,
    evidence_ids: Vec<EvidenceId>,
    audit: WebAssessmentRestAudit,
}

impl CommittedRestReview {
    pub(super) const fn audit(&self) -> &WebAssessmentRestAudit {
        &self.audit
    }
}

struct RestLeg {
    view: ApiVisibilityView,
    response_bytes: u64,
    media: RestObservedMediaClass,
    evidence_ids: Vec<EvidenceId>,
}

impl RestLeg {
    fn audit_observation(&self) -> RestAuditObservation {
        RestAuditObservation {
            media: self.media,
            status_class: Some((self.view.status() / 100) as u8),
        }
    }
}

#[derive(Clone, Copy)]
struct RestAuditObservation {
    media: RestObservedMediaClass,
    status_class: Option<u8>,
}

impl Default for RestAuditObservation {
    fn default() -> Self {
        Self {
            media: RestObservedMediaClass::Unknown,
            status_class: None,
        }
    }
}

impl RestAuditObservation {
    fn new(status: u16, media: RestObservedMediaClass) -> Self {
        Self {
            media,
            status_class: Some((status / 100) as u8),
        }
    }
}

#[derive(Default)]
struct RestExecutionState {
    legs: BTreeMap<DecisionExecutionStage, RestLeg>,
    terminal: Option<RestRuntimeOutcome>,
    terminal_observation: Option<RestAuditObservation>,
    runtime_limit: Option<RuntimeLimitExceeded>,
}

struct RestDecisionExecutor {
    requests: HttpRequestBroker,
    selection: StableRestSelectionSlot,
    subject: EntityId,
    state: Mutex<RestExecutionState>,
}

impl RestDecisionExecutor {
    fn take_state(&self) -> Result<RestExecutionState, RestRuntimeInvariantError> {
        Ok(std::mem::take(
            &mut *self
                .state
                .lock()
                .map_err(|_| RestRuntimeInvariantError::Catalog)?,
        ))
    }

    fn stop(
        &self,
        outcome: RestRuntimeOutcome,
        runtime_limit: Option<RuntimeLimitExceeded>,
        observation: Option<RestAuditObservation>,
    ) -> Result<(), DecisionExecutorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("REST review state is unavailable"))?;
        if state.terminal.is_some() || state.runtime_limit.is_some() {
            return Err(DecisionExecutorError::new(
                "REST review terminal state is duplicated",
            ));
        }
        state.terminal = Some(outcome);
        state.terminal_observation = observation;
        state.runtime_limit = runtime_limit;
        Ok(())
    }
}

#[async_trait]
impl DecisionActionExecutor for RestDecisionExecutor {
    fn id(&self) -> &str {
        REST_REVIEW_EXECUTOR_ID
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        if request.case().action_id() != REST_REVIEW_ACTION_ID
            || request.case().subject() != &self.subject
            || request.case().payload_strategy().is_some()
            || request.case().applies_hypothesis_transition()
            || request.delay_ms().is_some()
            || !matches!(
                request.stage(),
                DecisionExecutionStage::Passive | DecisionExecutionStage::Active
            )
        {
            return Err(DecisionExecutorError::new(
                "REST executor route contract failed",
            ));
        }
        {
            let state = self
                .state
                .lock()
                .map_err(|_| DecisionExecutorError::new("REST review state is unavailable"))?;
            let phase_ready = match request.stage() {
                DecisionExecutionStage::Passive => {
                    state.legs.is_empty() && state.terminal.is_none()
                },
                DecisionExecutionStage::Active => {
                    state.legs.contains_key(&DecisionExecutionStage::Passive)
                        && !state.legs.contains_key(&DecisionExecutionStage::Active)
                        && state.terminal.is_none()
                },
            };
            if !phase_ready {
                return Err(DecisionExecutorError::new(
                    "REST executor phase contract failed",
                ));
            }
        }

        let Some(selection) = self
            .selection
            .selection()
            .map_err(|_| DecisionExecutorError::new("REST selection is unavailable"))?
        else {
            self.stop(RestRuntimeOutcome::NotEligible, None, None)?;
            return phase_terminal_evidence(request);
        };
        let probe = HttpProbe::new(selection.execution_url().clone(), HttpProbeMethod::Get)
            .and_then(|probe| probe.with_header("accept", REST_REVIEW_ACCEPT))
            .map_err(|_| DecisionExecutorError::new("REST request construction failed"))?;
        let response = match self
            .requests
            .collect_for_runtime(
                REST_REVIEW_ACTION_ID,
                request.stage(),
                request.origin(),
                request.limits(),
                &probe,
            )
            .await
        {
            Ok(response) => response,
            Err(HttpRequestBrokerError::RuntimeLimit(limit)) => {
                self.stop(RestRuntimeOutcome::BudgetExhausted, Some(limit), None)?;
                return phase_terminal_evidence(request);
            },
            Err(HttpRequestBrokerError::Http(_)) => {
                self.stop(RestRuntimeOutcome::Incomplete, None, None)?;
                return phase_terminal_evidence(request);
            },
        };

        let status = response.status();
        let signal = response.openapi_defense_signal();
        let media = observed_media_class(response.normalized_media_type().as_deref());
        let terminal =
            if response.final_url() != selection.execution_url() || (300..400).contains(&status) {
                Some(RestRuntimeOutcome::Redirect)
            } else if response.body_truncated() {
                Some(RestRuntimeOutcome::Truncated)
            } else if !response.body_complete() {
                Some(RestRuntimeOutcome::Incomplete)
            } else if signal.state().is_rate_limited() || status == 429 {
                Some(RestRuntimeOutcome::RateLimited)
            } else if signal.state().is_challenged() {
                Some(RestRuntimeOutcome::DefensiveInterference)
            } else {
                status_outcome(status)
            };
        if let Some(outcome) = terminal {
            self.stop(
                outcome,
                None,
                Some(RestAuditObservation::new(status, media)),
            )?;
            return transport_evidence(request, &response, None, None, true);
        }
        if !response.has_json_compatible_media_type() {
            let outcome = match media {
                RestObservedMediaClass::Text => RestRuntimeOutcome::CompleteNonJson,
                RestObservedMediaClass::Unsupported | RestObservedMediaClass::Unknown => {
                    RestRuntimeOutcome::UnsupportedMedia
                },
                RestObservedMediaClass::JsonCompatible => unreachable!("media was checked above"),
            };
            self.stop(
                outcome,
                None,
                Some(RestAuditObservation::new(status, media)),
            )?;
            return transport_evidence(request, &response, None, None, true);
        }
        let json: serde_json::Value = match serde_json::from_slice(response.body()) {
            Ok(json) => json,
            Err(_) => {
                self.stop(
                    RestRuntimeOutcome::Incomplete,
                    None,
                    Some(RestAuditObservation::new(status, media)),
                )?;
                return transport_evidence(request, &response, None, None, true);
            },
        };
        let context_id = rest_leg_identity(request.stage());
        let view = match ApiVisibilityComparator::default().capture_view(
            context_id,
            selection.target_identity(),
            ApiSurfaceKind::JsonHttp,
            status,
            &json,
        ) {
            Ok(view) => view,
            Err(
                ApiVisibilityEvidenceError::DepthLimitExceeded { .. }
                | ApiVisibilityEvidenceError::NodeLimitExceeded { .. }
                | ApiVisibilityEvidenceError::FieldLimitExceeded { .. }
                | ApiVisibilityEvidenceError::CanonicalBytesLimitExceeded { .. },
            ) => {
                self.stop(
                    RestRuntimeOutcome::Incomplete,
                    None,
                    Some(RestAuditObservation::new(status, media)),
                )?;
                return transport_evidence(request, &response, None, None, true);
            },
            Err(_) => {
                return Err(DecisionExecutorError::new("REST JSON view capture failed"));
            },
        };
        drop(json);

        let comparison = if request.stage() == DecisionExecutionStage::Active {
            let state = self
                .state
                .lock()
                .map_err(|_| DecisionExecutorError::new("REST review state is unavailable"))?;
            let candidate = state
                .legs
                .get(&DecisionExecutionStage::Passive)
                .ok_or_else(|| DecisionExecutorError::new("REST candidate view is missing"))?;
            Some(
                ApiVisibilityComparator::default()
                    .compare_exact_replay(&candidate.view, &view)
                    .map_err(|_| DecisionExecutorError::new("REST replay comparison failed"))?,
            )
        } else {
            None
        };
        let evidence = transport_evidence(
            request,
            &response,
            Some(&selection),
            comparison.as_ref(),
            false,
        )?;
        let evidence_ids = evidence
            .iter()
            .filter(|evidence| {
                evidence.predicate().namespace() == REST_REVIEW_EVIDENCE_NAMESPACE
                    && matches!(
                        evidence.predicate().name(),
                        "view" | "status-equivalent" | "fields-equivalent" | "resources-equivalent"
                    )
            })
            .map(|evidence| evidence.id().clone())
            .collect::<Vec<_>>();
        if evidence_ids.is_empty() {
            return Err(DecisionExecutorError::new("REST evidence is missing"));
        }
        let response_bytes = u64::try_from(response.body().len()).unwrap_or(u64::MAX);
        let replaced = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("REST review state is unavailable"))?
            .legs
            .insert(
                request.stage(),
                RestLeg {
                    view,
                    response_bytes,
                    media,
                    evidence_ids,
                },
            );
        if replaced.is_some() {
            return Err(DecisionExecutorError::new("REST review leg is duplicated"));
        }
        Ok(evidence)
    }
}

fn observed_media_class(media: Option<&str>) -> RestObservedMediaClass {
    match media {
        Some("application/json") => RestObservedMediaClass::JsonCompatible,
        Some(value) if value.ends_with("+json") => RestObservedMediaClass::JsonCompatible,
        Some(value) if value.starts_with("text/") => RestObservedMediaClass::Text,
        Some(_) => RestObservedMediaClass::Unsupported,
        None => RestObservedMediaClass::Unknown,
    }
}

fn status_outcome(status: u16) -> Option<RestRuntimeOutcome> {
    match status {
        200..=299 => None,
        401 => Some(RestRuntimeOutcome::AuthenticationRequired),
        403 => Some(RestRuntimeOutcome::Forbidden),
        404 => Some(RestRuntimeOutcome::NotFound),
        429 => Some(RestRuntimeOutcome::RateLimited),
        500..=599 => Some(RestRuntimeOutcome::ServerError),
        _ => Some(RestRuntimeOutcome::Incomplete),
    }
}

fn phase_terminal_evidence(
    request: &DecisionExecutionRequest,
) -> Result<Vec<Evidence>, DecisionExecutorError> {
    Ok(vec![
        make_evidence(
            request,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            EvidenceValue::Unsigned(0),
            "response-body-size",
        )?,
        make_evidence(
            request,
            crate::web_actions::rest_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(true),
            "phase-terminal",
        )?,
    ])
}

fn make_evidence(
    request: &DecisionExecutionRequest,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    method: &str,
) -> Result<Evidence, DecisionExecutorError> {
    Ok(Evidence::new(
        request.case().subject().clone(),
        EvidenceKind::Custom("rest-review".into()),
        predicate,
        value,
        EvidenceSource::new(REST_REVIEW_EXECUTOR_ID, method)
            .and_then(|source| source.with_correlation_id(request.case().id()))
            .map_err(|_| DecisionExecutorError::new("REST evidence source failed"))?,
        ConfidenceScore::MAX,
    ))
}

fn make_typed_evidence(
    request: &DecisionExecutionRequest,
    kind: EvidenceKind,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    method: &str,
) -> Result<Evidence, DecisionExecutorError> {
    Ok(Evidence::new(
        request.case().subject().clone(),
        kind,
        predicate,
        value,
        EvidenceSource::new(REST_REVIEW_EXECUTOR_ID, method)
            .and_then(|source| source.with_correlation_id(request.case().id()))
            .map_err(|_| DecisionExecutorError::new("REST evidence source failed"))?,
        ConfidenceScore::MAX,
    ))
}

fn transport_evidence(
    request: &DecisionExecutionRequest,
    response: &crate::http_evidence::CollectedHttpResponse,
    selection: Option<&RestOperationSelection>,
    comparison: Option<&ApiExactReplayComparison>,
    terminal: bool,
) -> Result<Vec<Evidence>, DecisionExecutorError> {
    let mut digest = Sha256::new();
    digest.update(REST_REVIEW_BODY_DIGEST_DOMAIN);
    digest.update(response.body());
    let digest = format!("{:x}", digest.finalize());
    let signal = response.openapi_defense_signal();
    let mut evidence = vec![
        make_typed_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::REQUEST_METHOD.into_knowledge(),
            EvidenceValue::Text("GET".into()),
            "request-method",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::REQUEST_URL.into_knowledge(),
            EvidenceValue::Text(response.final_url().to_string()),
            "request-url",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge(),
            EvidenceValue::Unsigned(u64::from(response.status())),
            "response-status",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_FINAL_URL.into_knowledge(),
            EvidenceValue::Text(response.final_url().to_string()),
            "response-final-url",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            EvidenceValue::Unsigned(u64::try_from(response.body().len()).unwrap_or(u64::MAX)),
            "response-body-size",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED.into_knowledge(),
            EvidenceValue::Boolean(response.body_truncated()),
            "response-body-truncation",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::Content,
            HttpEvidencePredicate::RESPONSE_BODY_SHA256.into_knowledge(),
            EvidenceValue::Text(digest.clone()),
            "response-body-sha256",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::RateLimit,
            HttpEvidencePredicate::RATE_LIMIT_DETECTED.into_knowledge(),
            EvidenceValue::Boolean(response.status() == 429),
            "rate-limit-status",
        )?,
        make_typed_evidence(
            request,
            EvidenceKind::RateLimit,
            HttpEvidencePredicate::RATE_LIMIT_ADVERTISED.into_knowledge(),
            EvidenceValue::Boolean(signal.state().has_rate_limit_headers()),
            "rate-limit-headers",
        )?,
        make_evidence(
            request,
            crate::web_actions::rest_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(terminal),
            "phase-terminal",
        )?,
    ];
    let defense_parents = evidence[..9]
        .iter()
        .map(|evidence| evidence.id().clone())
        .collect();
    if let Some(media) = response.normalized_media_type() {
        evidence.push(make_typed_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge(),
            EvidenceValue::Text(media),
            "response-media-type",
        )?);
        evidence.push(make_typed_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into_knowledge(),
            EvidenceValue::Boolean(response.has_json_compatible_media_type()),
            "response-media-type-json-compatibility",
        )?);
    }
    if let Some(selection) = selection {
        let leg_identity = rest_leg_identity(request.stage());
        evidence.push(make_evidence(
            request,
            KnowledgePredicate::new(REST_REVIEW_EVIDENCE_NAMESPACE, "view")
                .map_err(|_| DecisionExecutorError::new("REST predicate failed"))?,
            EvidenceValue::TextList(vec![
                format!("leg={leg_identity}"),
                format!("operation={}", selection.operation_id().as_str()),
                format!("target={}", selection.target_identity()),
                format!("status={}", response.status()),
                "method=GET".into(),
                format!(
                    "media={}",
                    observed_media_name(observed_media_class(
                        response.normalized_media_type().as_deref()
                    ))
                ),
                format!("complete={}", response.body_complete()),
                format!("truncated={}", response.body_truncated()),
                format!("response={digest}"),
                format!("rate_limited={}", signal.state().is_rate_limited()),
                format!("challenged={}", signal.state().is_challenged()),
            ]),
            leg_identity,
        )?);
    }
    if let Some(comparison) = comparison {
        for (name, equivalent) in [
            ("status-equivalent", comparison.status()),
            ("fields-equivalent", comparison.fields()),
            ("resources-equivalent", comparison.resources()),
        ] {
            evidence.push(make_evidence(
                request,
                KnowledgePredicate::new(REST_REVIEW_EVIDENCE_NAMESPACE, name)
                    .map_err(|_| DecisionExecutorError::new("REST predicate failed"))?,
                EvidenceValue::Boolean(equivalent),
                name,
            )?);
        }
    }
    if !terminal {
        evidence.push(make_evidence(
            request,
            crate::web_actions::native_web_review_response_marker_predicate(),
            EvidenceValue::Boolean(true),
            "complete",
        )?);
    }
    evidence.extend(
        project_assessment_defense_signal(
            &signal,
            AssessmentDefenseProjectionContext {
                subject: request.case().subject(),
                case_id: request.case().id(),
                executor_id: REST_REVIEW_EXECUTOR_ID,
                reliability: ConfidenceScore::MAX,
                parents: defense_parents,
            },
        )
        .map_err(|_| DecisionExecutorError::new("REST defense projection failed"))?,
    );
    Ok(evidence)
}

fn rest_leg_identity(stage: DecisionExecutionStage) -> &'static str {
    match stage {
        DecisionExecutionStage::Passive => "rest-review:candidate",
        DecisionExecutionStage::Active => "rest-review:replay",
    }
}

fn observed_media_name(media: RestObservedMediaClass) -> &'static str {
    match media {
        RestObservedMediaClass::JsonCompatible => "json-compatible",
        RestObservedMediaClass::Text => "text",
        RestObservedMediaClass::Unsupported => "unsupported",
        RestObservedMediaClass::Unknown => "unknown",
    }
}

fn audit(
    selection: Option<&RestOperationSelection>,
    outcome: RestRuntimeOutcome,
    requests: u8,
    observation: Option<RestAuditObservation>,
    projected: bool,
) -> WebAssessmentRestAudit {
    WebAssessmentRestAudit {
        outcome,
        request_count: requests,
        active_verification_count: u8::from(requests == MAX_REST_REVIEW_REQUESTS as u8),
        eligible_operation_count: selection
            .map_or(0, RestOperationSelection::eligible_operation_count),
        selected_operation_identity: selection
            .map(|selected| selected.operation_id().as_str().to_owned()),
        documented_response: selection.map(RestOperationSelection::documented_response),
        observed_media: observation.unwrap_or_default().media,
        status_class: observation.and_then(|observation| observation.status_class),
        replay_stable: projected,
        item_projected: projected,
    }
}

pub(super) fn project_rest_item(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    review: &CommittedRestReview,
) -> Result<(), AssessmentItemProjectionError> {
    for evidence_id in &review.evidence_ids {
        context.register_evidence(knowledge, evidence_id)?;
    }
    if review.outcome == RestRuntimeOutcome::SurfaceObserved {
        let target_identity = review
            .target_identity
            .clone()
            .ok_or(AssessmentItemProjectionError::InvalidStableSubjectIdentity)?;
        let target = AssessmentItemTarget::rest_operation(target_identity)?;
        context.project_observation(
            &REST_REVIEW_CAPABILITY,
            knowledge,
            &review.subject,
            &target,
            &review.evidence_ids,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        openapi_review::{parse_openapi_document, OpenApiParseOutcome},
        rest_review::{select_rest_operation, RestOperationSelectionOutcome},
    };
    use url::Url;

    fn selection() -> RestOperationSelection {
        let origin = Url::parse("https://example.test/openapi.json").unwrap();
        let document = br#"{
          "openapi":"3.1.0",
          "paths":{"/health":{"get":{"responses":{"200":{"content":{"application/json":{}}}}}}}
        }"#;
        let OpenApiParseOutcome::Complete(document) = parse_openapi_document(document, &origin)
        else {
            panic!("fixture must parse");
        };
        let RestOperationSelectionOutcome::Selected(selection) =
            select_rest_operation(&document, &origin)
        else {
            panic!("fixture must select one operation");
        };
        selection
    }

    #[test]
    fn stable_selection_slot_is_clone_shared_single_assignment_and_redacted() {
        let slot = StableRestSelectionSlot::new();
        let clone = slot.clone();
        let selected = selection();
        let secret_url = selected.execution_url().to_string();
        slot.commit(selected.clone()).unwrap();
        assert_eq!(clone.selection().unwrap(), Some(selected.clone()));
        assert!(matches!(
            clone.commit(selected),
            Err(RestRuntimeInvariantError::Catalog)
        ));
        let debug = format!("{slot:?}");
        assert!(!debug.contains(&secret_url));
        assert!(!debug.contains("/health"));
    }

    #[test]
    fn status_and_media_classification_are_closed_and_conservative() {
        assert_eq!(status_outcome(200), None);
        assert_eq!(
            status_outcome(401),
            Some(RestRuntimeOutcome::AuthenticationRequired)
        );
        assert_eq!(status_outcome(403), Some(RestRuntimeOutcome::Forbidden));
        assert_eq!(status_outcome(404), Some(RestRuntimeOutcome::NotFound));
        assert_eq!(status_outcome(429), Some(RestRuntimeOutcome::RateLimited));
        assert_eq!(status_outcome(503), Some(RestRuntimeOutcome::ServerError));
        assert_eq!(status_outcome(418), Some(RestRuntimeOutcome::Incomplete));
        assert_eq!(
            observed_media_class(Some("application/problem+json")),
            RestObservedMediaClass::JsonCompatible
        );
        assert_eq!(
            observed_media_class(Some("text/html")),
            RestObservedMediaClass::Text
        );
        assert_eq!(
            observed_media_class(Some("application/octet-stream")),
            RestObservedMediaClass::Unsupported
        );
        assert_eq!(observed_media_class(None), RestObservedMediaClass::Unknown);
        assert_eq!(
            rest_leg_identity(DecisionExecutionStage::Passive),
            "rest-review:candidate"
        );
        assert_eq!(
            rest_leg_identity(DecisionExecutionStage::Active),
            "rest-review:replay"
        );
        assert_ne!(
            rest_leg_identity(DecisionExecutionStage::Passive),
            rest_leg_identity(DecisionExecutionStage::Active)
        );
    }

    #[test]
    fn audit_debug_never_exposes_operation_identity() {
        let selected = selection();
        let audit = audit(
            Some(&selected),
            RestRuntimeOutcome::SurfaceObserved,
            2,
            None,
            true,
        );
        let debug = format!("{audit:?}");
        assert!(!debug.contains(selected.operation_id().as_str()));
        assert!(!debug.contains(selected.execution_url().path()));
        assert_eq!(audit.request_count(), 2);
        assert_eq!(audit.active_verification_count(), 1);
        assert!(audit.replay_stable() && audit.item_projected());
    }
}
