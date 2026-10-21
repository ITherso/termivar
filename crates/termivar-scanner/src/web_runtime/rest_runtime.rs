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
use termivar_core::{
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
    TransportDispatchOutcome,
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
const REST_CLASSIFICATION_ALGORITHM: &str = "web.rest-review.value-free-classification";

#[derive(Clone, Copy)]
enum RestResponsePrivacy {
    HistoricalDigests,
    #[cfg(feature = "secret-exposure-review")]
    ValueFree,
}

impl RestResponsePrivacy {
    fn is_value_free(self) -> bool {
        match self {
            Self::HistoricalDigests => false,
            #[cfg(feature = "secret-exposure-review")]
            Self::ValueFree => true,
        }
    }
}

#[cfg(feature = "secret-exposure-review")]
pub(super) fn rest_privacy_route_is_valid(
    case: &crate::VerificationCase,
    stage: DecisionExecutionStage,
    executor: &str,
) -> bool {
    executor == REST_REVIEW_EXECUTOR_ID
        && case.action_id() == REST_REVIEW_ACTION_ID
        && !case.applies_hypothesis_transition()
        && case.payload_strategy().is_none()
        && matches!(
            stage,
            DecisionExecutionStage::Passive | DecisionExecutionStage::Active
        )
}

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
        value_free: bool,
    ) -> Self {
        let privacy = RestResponsePrivacy::HistoricalDigests;
        #[cfg(feature = "secret-exposure-review")]
        let privacy = if value_free {
            RestResponsePrivacy::ValueFree
        } else {
            privacy
        };
        #[cfg(not(feature = "secret-exposure-review"))]
        debug_assert!(!value_free);
        let executor = Arc::new(RestDecisionExecutor {
            requests,
            selection,
            subject: subject.clone(),
            privacy,
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
        standard: &super::StandardWebDecisionRunReport,
        forced_outcome: Option<RestRuntimeOutcome>,
        forced_runtime_limit: Option<RuntimeLimitExceeded>,
    ) -> Result<RestRuntimeResult, RestRuntimeInvariantError> {
        let transport = standard.transport();
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
        #[cfg(feature = "secret-exposure-review")]
        let committed = if self.executor.privacy.is_value_free() {
            validate_value_free_rest_commits(
                standard,
                knowledge,
                &self.subject,
                selection.as_ref(),
                &state,
            )?
        } else {
            true
        };
        #[cfg(not(feature = "secret-exposure-review"))]
        let committed = true;
        if !captured_rest_prefix_reconciles(&state, &receipts) {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let request_count = u8::try_from(receipts.len()).unwrap_or(u8::MAX);
        let terminal = forced_outcome.or(if committed {
            state.terminal
        } else {
            Some(RestRuntimeOutcome::Incomplete)
        });
        let runtime_limit = if forced_outcome.is_some() {
            forced_runtime_limit
        } else {
            state.runtime_limit
        };

        if let Some(outcome) = terminal {
            let audit = audit_for_privacy(
                selection.as_ref(),
                outcome,
                request_count,
                state.terminal_observation,
                false,
                self.executor.privacy,
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
                privacy: self.executor.privacy,
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
                privacy: self.executor.privacy,
                target_identity: None,
                outcome: RestRuntimeOutcome::NotEligible,
                evidence_ids: Vec::new(),
                audit: audit_for_privacy(
                    None,
                    RestRuntimeOutcome::NotEligible,
                    request_count,
                    None,
                    false,
                    self.executor.privacy,
                ),
            }));
        };
        let (Some(candidate), Some(replay)) = (
            state.legs.get(&DecisionExecutionStage::Passive),
            state.legs.get(&DecisionExecutionStage::Active),
        ) else {
            return Ok(RestRuntimeResult::Stopped {
                audit: audit_for_privacy(
                    Some(&selection),
                    RestRuntimeOutcome::Incomplete,
                    request_count,
                    None,
                    false,
                    self.executor.privacy,
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
                audit: audit_for_privacy(
                    Some(&selection),
                    RestRuntimeOutcome::Incomplete,
                    request_count,
                    None,
                    false,
                    self.executor.privacy,
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
        let audit = audit_for_privacy(
            Some(&selection),
            outcome,
            request_count,
            Some(replay.audit_observation()),
            projected,
            self.executor.privacy,
        );
        Ok(RestRuntimeResult::Complete(CommittedRestReview {
            subject: self.subject,
            privacy: self.executor.privacy,
            target_identity: Some(selection.target_identity().to_owned()),
            outcome,
            evidence_ids,
            audit,
        }))
    }
}

/// Staged views are not projection authority until the normal runner's exact
/// write-set and closed response lineage have committed to this assessment.
#[cfg(feature = "secret-exposure-review")]
fn validate_value_free_rest_commits(
    standard: &super::StandardWebDecisionRunReport,
    knowledge: &KnowledgeBase,
    subject: &EntityId,
    selection: Option<&RestOperationSelection>,
    state: &RestExecutionState,
) -> Result<bool, RestRuntimeInvariantError> {
    use crate::{KnowledgeWrite, StandardWebDecisionRuntimeTurn};
    use std::collections::BTreeSet;
    let receipts = standard
        .turns()
        .iter()
        .filter_map(|turn| match turn {
            StandardWebDecisionRuntimeTurn::Outcome { evidence, .. } => Some(evidence.as_ref()),
            StandardWebDecisionRuntimeTurn::Planning(_) => None,
        })
        .chain(standard.unverified_evidence())
        .filter(|receipt| {
            receipt.case().action_id() == REST_REVIEW_ACTION_ID
                || receipt.executor_id() == REST_REVIEW_EXECUTOR_ID
        })
        .collect::<Vec<_>>();
    if receipts.len() > MAX_REST_REVIEW_REQUESTS {
        return Err(RestRuntimeInvariantError::Catalog);
    }
    let mut committed = BTreeSet::new();
    let mut terminal_committed = false;
    for (index, receipt) in receipts.into_iter().enumerate() {
        let expected_stage = if index == 0 {
            DecisionExecutionStage::Passive
        } else {
            DecisionExecutionStage::Active
        };
        if !rest_privacy_route_is_valid(receipt.case(), receipt.stage(), receipt.executor_id())
            || receipt.case().subject() != subject
            || receipt.stage() != expected_stage
            || receipt.evidence().len() != receipt.writes().len()
        {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let mut ids = BTreeSet::new();
        for (item, write) in receipt.write_set() {
            if !matches!(write, KnowledgeWrite::Inserted | KnowledgeWrite::Unchanged)
                || item.subject() != subject
                || item.source().component() != REST_REVIEW_EXECUTOR_ID
                || item.source().correlation_id() != Some(receipt.case().id())
                || item.reliability() != ConfidenceScore::MAX
                || !ids.insert(item.id())
                || knowledge.evidence(item.id()).as_ref() != Some(item)
                || item.predicate() == &HttpEvidencePredicate::RESPONSE_BODY_SHA256.into_knowledge()
            {
                return Err(RestRuntimeInvariantError::Catalog);
            }
        }
        let phase = rest_receipt_fact(
            receipt,
            &crate::web_actions::rest_review_phase_terminal_predicate(),
        )?;
        if phase.kind() != &EvidenceKind::Custom("rest-review".to_owned())
            || !phase.origin().is_direct()
            || phase.source().method() != "phase-terminal"
        {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let response_received = receipt.evidence().iter().any(|item| {
            item.predicate() == &HttpEvidencePredicate::REQUEST_METHOD.into_knowledge()
        });
        if !response_received {
            let bytes = rest_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            )?;
            if state.terminal.is_none()
                || state.legs.contains_key(&receipt.stage())
                || receipt.evidence().len() != 2
                || bytes.kind() != &EvidenceKind::Custom("rest-review".to_owned())
                || !bytes.origin().is_direct()
                || bytes.source().method() != "response-body-size"
                || bytes.value() != &EvidenceValue::Unsigned(0)
                || phase.value() != &EvidenceValue::Boolean(true)
            {
                return Err(RestRuntimeInvariantError::Catalog);
            }
            terminal_committed = true;
            continue;
        }
        let selected = selection.ok_or(RestRuntimeInvariantError::Catalog)?;
        let parents = super::secret_exposure::rest_response_privacy_parent_ids(
            receipt.evidence(),
            receipt.case(),
            receipt.stage(),
            receipt.executor_id(),
        )
        .ok_or(RestRuntimeInvariantError::Catalog)?;
        let lineage_predicate = KnowledgePredicate::new(
            super::secret_exposure::SECRET_EXPOSURE_NAMESPACE,
            super::secret_exposure::ACTIVE_REVIEW_BODY_LINEAGE,
        )
        .map_err(|_| RestRuntimeInvariantError::Catalog)?;
        let lineage = rest_receipt_fact(receipt, &lineage_predicate)?;
        if !super::secret_exposure::is_active_review_body_privacy_lineage(
            lineage,
            subject,
            receipt.case().id(),
            REST_REVIEW_EXECUTOR_ID,
            &parents,
        ) {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        for predicate in [
            HttpEvidencePredicate::REQUEST_URL,
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
        ] {
            if rest_receipt_fact(receipt, &predicate.into_knowledge())?.value()
                != &EvidenceValue::Text(selected.execution_url().to_string())
            {
                return Err(RestRuntimeInvariantError::Catalog);
            }
        }
        let fixed_predicates = [
            HttpEvidencePredicate::REQUEST_METHOD,
            HttpEvidencePredicate::REQUEST_URL,
            HttpEvidencePredicate::RESPONSE_STATUS,
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            HttpEvidencePredicate::RATE_LIMIT_DETECTED,
            HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE,
        ]
        .map(|predicate| predicate.into_knowledge());
        for (predicate, kind, method) in [
            (
                HttpEvidencePredicate::RATE_LIMIT_DETECTED,
                EvidenceKind::RateLimit,
                "rate-limit-status",
            ),
            (
                HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
                EvidenceKind::RateLimit,
                "rate-limit-headers",
            ),
        ] {
            let item = rest_receipt_fact(receipt, &predicate.into_knowledge())?;
            if item.kind() != &kind
                || !item.origin().is_direct()
                || item.source().method() != method
                || !matches!(item.value(), EvidenceValue::Boolean(_))
            {
                return Err(RestRuntimeInvariantError::Catalog);
            }
        }
        let media_predicate = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
        let compatibility_predicate =
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into_knowledge();
        let media = receipt
            .evidence()
            .iter()
            .find(|item| item.predicate() == &media_predicate);
        let mut compatibility = receipt
            .evidence()
            .iter()
            .filter(|item| item.predicate() == &compatibility_predicate);
        match (media, compatibility.next()) {
            (Some(media), Some(compatible)) => {
                let EvidenceValue::Text(media_type) = media.value() else {
                    return Err(RestRuntimeInvariantError::Catalog);
                };
                if compatibility.next().is_some()
                    || compatible.kind() != &EvidenceKind::Http
                    || !compatible.origin().is_direct()
                    || compatible.source().method() != "response-media-type-json-compatibility"
                    || compatible.value()
                        != &EvidenceValue::Boolean(
                            crate::http_evidence::json_compatible_media_type(media_type),
                        )
                {
                    return Err(RestRuntimeInvariantError::Catalog);
                }
            },
            (None, None) => {},
            _ => return Err(RestRuntimeInvariantError::Catalog),
        }
        if receipt.evidence().iter().any(|item| {
            let rest_fact = item.predicate().namespace() == REST_REVIEW_EVIDENCE_NAMESPACE
                && matches!(
                    item.predicate().name(),
                    "view"
                        | "phase-terminal"
                        | "status-equivalent"
                        | "fields-equivalent"
                        | "resources-equivalent"
                );
            let known_fact = fixed_predicates.contains(item.predicate())
                || rest_fact
                || item.predicate() == &lineage_predicate
                || item.predicate()
                    == &crate::web_actions::native_web_review_response_marker_predicate()
                || item.predicate().namespace()
                    == super::assessment_defense::ASSESSMENT_DEFENSE_NAMESPACE;
            !known_fact
                || (item.predicate().namespace()
                    == super::secret_exposure::SECRET_EXPOSURE_NAMESPACE
                    && item.predicate() != &lineage_predicate)
                || (item.predicate().namespace() == REST_REVIEW_EVIDENCE_NAMESPACE
                    && !matches!(
                        item.predicate().name(),
                        "view"
                            | "phase-terminal"
                            | "status-equivalent"
                            | "fields-equivalent"
                            | "resources-equivalent"
                    ))
        }) {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let view_predicate = KnowledgePredicate::new(REST_REVIEW_EVIDENCE_NAMESPACE, "view")
            .map_err(|_| RestRuntimeInvariantError::Catalog)?;
        let completion_predicate =
            crate::web_actions::native_web_review_response_marker_predicate();
        let completion = receipt
            .evidence()
            .iter()
            .filter(|item| item.predicate() == &completion_predicate)
            .collect::<Vec<_>>();
        let classifications = receipt
            .evidence()
            .iter()
            .filter(|item| {
                item.predicate().namespace() == REST_REVIEW_EVIDENCE_NAMESPACE
                    && item.predicate().name() != "phase-terminal"
            })
            .collect::<Vec<_>>();
        let wire = standard
            .transport()
            .receipts()
            .iter()
            .filter(|item| item.action_id() == REST_REVIEW_ACTION_ID)
            .nth(index)
            .ok_or(RestRuntimeInvariantError::Catalog)?;
        let bytes = rest_receipt_fact(
            receipt,
            &HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
        )?;
        let Some(leg) = state.legs.get(&receipt.stage()) else {
            if state.terminal.is_none()
                || !classifications.is_empty()
                || !completion.is_empty()
                || phase.value() != &EvidenceValue::Boolean(true)
                || !matches!(
                    wire.outcome(),
                    TransportDispatchOutcome::Completed
                        | TransportDispatchOutcome::ResponseBudgetReached
                )
                || !matches!(bytes.value(), EvidenceValue::Unsigned(value) if *value <= wire.response_bytes())
            {
                return Err(RestRuntimeInvariantError::Catalog);
            }
            terminal_committed = true;
            continue;
        };
        let mut expected_parents = BTreeSet::new();
        for item in receipt
            .evidence()
            .iter()
            .filter(|item| fixed_predicates.contains(item.predicate()) || item.id() == phase.id())
        {
            if !item.origin().is_direct() {
                return Err(RestRuntimeInvariantError::Catalog);
            }
            expected_parents.insert(item.id().clone());
        }
        expected_parents.insert(lineage.id().clone());
        let expected_parents = expected_parents.into_iter().collect::<Vec<_>>();
        let view = rest_receipt_fact(receipt, &view_predicate)?;
        let expected_view = EvidenceValue::TextList(vec![
            format!("leg={}", rest_leg_identity(receipt.stage())),
            format!("status={}", leg.view.status()),
            "method=GET".to_owned(),
            format!("media={}", observed_media_name(leg.media)),
            "complete=true".to_owned(),
            "truncated=false".to_owned(),
            "rate_limited=false".to_owned(),
            "challenged=false".to_owned(),
        ]);
        if completion.len() != 1
            || !completion[0].origin().is_direct()
            || completion[0].source().method() != "complete"
            || completion[0].value() != &EvidenceValue::Boolean(true)
            || phase.value() != &EvidenceValue::Boolean(false)
            || bytes.value() != &EvidenceValue::Unsigned(leg.response_bytes)
            || wire.outcome() != TransportDispatchOutcome::Completed
            || wire.response_bytes() != leg.response_bytes
            || rest_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED.into_knowledge(),
            )?
            .value()
                != &EvidenceValue::Boolean(false)
            || rest_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RATE_LIMIT_DETECTED.into_knowledge(),
            )?
            .value()
                != &EvidenceValue::Boolean(false)
            || rest_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge(),
            )?
            .value()
                != &EvidenceValue::Unsigned(u64::from(leg.view.status()))
            || rest_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into_knowledge(),
            )?
            .value()
                != &EvidenceValue::Boolean(true)
            || view.value() != &expected_view
            || view.source().method() != rest_leg_identity(receipt.stage())
            || !valid_rest_classification(view, &expected_parents)
        {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        let mut expected_ids = vec![view.id().clone()];
        if receipt.stage() == DecisionExecutionStage::Active {
            let candidate = state
                .legs
                .get(&DecisionExecutionStage::Passive)
                .ok_or(RestRuntimeInvariantError::Catalog)?;
            if !committed.contains(&DecisionExecutionStage::Passive) {
                return Err(RestRuntimeInvariantError::Catalog);
            }
            let comparison = ApiVisibilityComparator::default()
                .compare_exact_replay(&candidate.view, &leg.view)
                .map_err(|_| RestRuntimeInvariantError::Catalog)?;
            for (name, expected) in [
                ("status-equivalent", comparison.status()),
                ("fields-equivalent", comparison.fields()),
                ("resources-equivalent", comparison.resources()),
            ] {
                let predicate = KnowledgePredicate::new(REST_REVIEW_EVIDENCE_NAMESPACE, name)
                    .map_err(|_| RestRuntimeInvariantError::Catalog)?;
                let item = rest_receipt_fact(receipt, &predicate)?;
                if item.source().method() != name
                    || item.value() != &EvidenceValue::Boolean(expected)
                    || !valid_rest_classification(item, &expected_parents)
                {
                    return Err(RestRuntimeInvariantError::Catalog);
                }
                expected_ids.push(item.id().clone());
            }
        }
        if classifications.len() != expected_ids.len() || leg.evidence_ids != expected_ids {
            return Err(RestRuntimeInvariantError::Catalog);
        }
        committed.insert(receipt.stage());
    }
    Ok(state.legs.keys().all(|stage| committed.contains(stage))
        && (state.terminal.is_none() || terminal_committed))
}

#[cfg(feature = "secret-exposure-review")]
fn valid_rest_classification(item: &Evidence, parents: &[EvidenceId]) -> bool {
    item.kind() == &EvidenceKind::Custom("rest-review".to_owned())
        && item.origin().derivation().is_some_and(|derivation| {
            derivation.algorithm().name() == REST_CLASSIFICATION_ALGORITHM
                && derivation.algorithm().version() == 1
                && derivation.parents() == parents
        })
}

#[cfg(feature = "secret-exposure-review")]
fn rest_receipt_fact<'a>(
    receipt: &'a crate::DecisionEvidenceReceipt,
    predicate: &KnowledgePredicate,
) -> Result<&'a Evidence, RestRuntimeInvariantError> {
    let mut matches = receipt
        .evidence()
        .iter()
        .filter(|item| item.predicate() == predicate);
    let item = matches.next().ok_or(RestRuntimeInvariantError::Catalog)?;
    if matches.next().is_some() {
        return Err(RestRuntimeInvariantError::Catalog);
    }
    Ok(item)
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
    privacy: RestResponsePrivacy,
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
    privacy: RestResponsePrivacy,
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
            return transport_evidence(request, &response, None, None, true, self.privacy);
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
            return transport_evidence(request, &response, None, None, true, self.privacy);
        }
        let json: serde_json::Value = match serde_json::from_slice(response.body()) {
            Ok(json) => json,
            Err(_) => {
                self.stop(
                    RestRuntimeOutcome::Incomplete,
                    None,
                    Some(RestAuditObservation::new(status, media)),
                )?;
                return transport_evidence(request, &response, None, None, true, self.privacy);
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
                return transport_evidence(request, &response, None, None, true, self.privacy);
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
            self.privacy,
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
    privacy: RestResponsePrivacy,
) -> Result<Vec<Evidence>, DecisionExecutorError> {
    let digest = (!privacy.is_value_free()).then(|| {
        let mut digest = Sha256::new();
        digest.update(REST_REVIEW_BODY_DIGEST_DOMAIN);
        digest.update(response.body());
        format!("{:x}", digest.finalize())
    });
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
    if let Some(digest) = digest.as_ref() {
        // Preserve historical evidence ordering and exact domain-separated hash.
        evidence.insert(
            6,
            make_typed_evidence(
                request,
                EvidenceKind::Content,
                HttpEvidencePredicate::RESPONSE_BODY_SHA256.into_knowledge(),
                EvidenceValue::Text(digest.clone()),
                "response-body-sha256",
            )?,
        );
    }
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
    if privacy.is_value_free() {
        #[cfg(feature = "secret-exposure-review")]
        evidence.push(
            super::secret_exposure::project_rest_body_privacy_lineage(
                request,
                &evidence,
                REST_REVIEW_EXECUTOR_ID,
                ConfidenceScore::MAX,
            )
            .map_err(|_| DecisionExecutorError::new("REST privacy lineage failed"))?,
        );
        #[cfg(not(feature = "secret-exposure-review"))]
        return Err(DecisionExecutorError::new(
            "REST privacy selection is unavailable",
        ));
    }
    let fixed_predicates = [
        HttpEvidencePredicate::REQUEST_METHOD,
        HttpEvidencePredicate::REQUEST_URL,
        HttpEvidencePredicate::RESPONSE_STATUS,
        HttpEvidencePredicate::RESPONSE_FINAL_URL,
        HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
        HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
        HttpEvidencePredicate::RESPONSE_BODY_SHA256,
        HttpEvidencePredicate::RATE_LIMIT_DETECTED,
        HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
    ]
    .map(|predicate| predicate.into_knowledge());
    let defense_parents = evidence
        .iter()
        .filter(|item| {
            #[cfg(not(feature = "secret-exposure-review"))]
            let privacy_parent = false;
            #[cfg(feature = "secret-exposure-review")]
            let privacy_parent = privacy.is_value_free()
                && item.predicate().namespace()
                    == super::secret_exposure::SECRET_EXPOSURE_NAMESPACE
                && item.predicate().name() == super::secret_exposure::ACTIVE_REVIEW_BODY_LINEAGE;
            fixed_predicates.contains(item.predicate()) || privacy_parent
        })
        .map(|item| item.id().clone())
        .collect();
    let classification_parents = evidence
        .iter()
        .map(|item| item.id().clone())
        .collect::<Vec<_>>();
    if let Some(selection) = selection {
        let leg_identity = rest_leg_identity(request.stage());
        let mut values = vec![
            format!("leg={leg_identity}"),
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
            format!("rate_limited={}", signal.state().is_rate_limited()),
            format!("challenged={}", signal.state().is_challenged()),
        ];
        if let Some(digest) = digest.as_ref() {
            values.insert(
                1,
                format!("operation={}", selection.operation_id().as_str()),
            );
            values.insert(2, format!("target={}", selection.target_identity()));
            values.insert(8, format!("response={digest}"));
        }
        let item = make_evidence(
            request,
            KnowledgePredicate::new(REST_REVIEW_EVIDENCE_NAMESPACE, "view")
                .map_err(|_| DecisionExecutorError::new("REST predicate failed"))?,
            EvidenceValue::TextList(values),
            leg_identity,
        )?;
        evidence.push(classification_evidence(
            item,
            &classification_parents,
            privacy,
        )?);
    }
    if let Some(comparison) = comparison {
        for (name, equivalent) in [
            ("status-equivalent", comparison.status()),
            ("fields-equivalent", comparison.fields()),
            ("resources-equivalent", comparison.resources()),
        ] {
            let item = make_evidence(
                request,
                KnowledgePredicate::new(REST_REVIEW_EVIDENCE_NAMESPACE, name)
                    .map_err(|_| DecisionExecutorError::new("REST predicate failed"))?,
                EvidenceValue::Boolean(equivalent),
                name,
            )?;
            evidence.push(classification_evidence(
                item,
                &classification_parents,
                privacy,
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

fn classification_evidence(
    item: Evidence,
    parents: &[EvidenceId],
    privacy: RestResponsePrivacy,
) -> Result<Evidence, DecisionExecutorError> {
    if !privacy.is_value_free() {
        return Ok(item);
    }
    let derivation = termivar_core::EvidenceDerivation::new(
        parents.to_vec(),
        termivar_core::DerivationAlgorithm::new(REST_CLASSIFICATION_ALGORITHM, 1)
            .map_err(|_| DecisionExecutorError::new("REST classification algorithm failed"))?,
    )
    .map_err(|_| DecisionExecutorError::new("REST classification provenance failed"))?;
    Ok(item.derived_from(derivation))
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

fn audit_for_privacy(
    selection: Option<&RestOperationSelection>,
    outcome: RestRuntimeOutcome,
    requests: u8,
    observation: Option<RestAuditObservation>,
    projected: bool,
    privacy: RestResponsePrivacy,
) -> WebAssessmentRestAudit {
    let mut audit = audit(selection, outcome, requests, observation, projected);
    if privacy.is_value_free() {
        audit.selected_operation_identity = None;
    }
    audit
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
        let target = if review.privacy.is_value_free() {
            AssessmentItemTarget::Subject
        } else {
            let target_identity = review
                .target_identity
                .clone()
                .ok_or(AssessmentItemProjectionError::InvalidStableSubjectIdentity)?;
            AssessmentItemTarget::rest_operation(target_identity)?
        };
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

    // PRIVATE integration snippet: insert inside rest_runtime.rs's final cfg(test)
    // module. Original synthetic committed-receipt oracles, NOT captured HTTP.
    // This file has not been compiled or executed by its author.
    #[cfg(feature = "secret-exposure-review")]
    mod privacy_tests {
        use super::*;
        use crate::{
            runtime_budget::RequestAccountingBroker, ActionCost, AdaptationLimits, AttackAction,
            BenefitScore, DecisionEvidenceReceipt, DecisionLoop, DecisionLoopCommand,
            DecisionLoopConfig, DecisionOutcomeReport, DecisionRunnerAdapter, DecisionSession,
            DecisionStopReason, ExperiencePolicy, ExperienceStore, Expression, HypothesisSelector,
            KnowledgeLayer, KnowledgeWrite, PlanningContext, RequiredStrength, RiskScore,
            RuntimeBudget, RuntimeUsage, StandardWebDecisionRunReport,
            StandardWebDecisionRuntimeTurn, VerificationCase, VerificationTarget,
        };
        use std::collections::BTreeSet;
        use termivar_core::{DerivationAlgorithm, EvidenceDerivation, Probability};

        const CASE: &str = "case:synthetic-rest-privacy";
        const RESOURCE: &str = "https://example.test/health";

        struct LiteralExecutor {
            id: &'static str,
            batch: Vec<Evidence>,
        }

        #[async_trait]
        impl DecisionActionExecutor for LiteralExecutor {
            fn id(&self) -> &str {
                self.id
            }

            async fn execute(
                &self,
                _request: &DecisionExecutionRequest,
            ) -> Result<Vec<Evidence>, DecisionExecutorError> {
                assert!(self.batch.len() <= 32);
                Ok(self.batch.clone())
            }
        }

        fn subject() -> EntityId {
            EntityId::new("endpoint:https://example.test/").unwrap()
        }

        fn fact(
            kind: EvidenceKind,
            predicate: KnowledgePredicate,
            value: EvidenceValue,
            method: &str,
        ) -> Evidence {
            Evidence::new(
                subject(),
                kind,
                predicate,
                value,
                EvidenceSource::new("http.rest-review", method)
                    .unwrap()
                    .with_correlation_id(CASE)
                    .unwrap(),
                ConfidenceScore::MAX,
            )
        }

        fn custom(name: &str, value: EvidenceValue, method: &str) -> Evidence {
            fact(
                EvidenceKind::Custom("rest-review".to_owned()),
                KnowledgePredicate::new("web.rest-review.transport", name).unwrap(),
                value,
                method,
            )
        }

        fn no_response_batch() -> Vec<Evidence> {
            vec![
                fact(
                    EvidenceKind::Custom("rest-review".to_owned()),
                    HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
                    EvidenceValue::Unsigned(0),
                    "response-body-size",
                ),
                fact(
                    EvidenceKind::Custom("rest-review".to_owned()),
                    crate::web_actions::rest_review_phase_terminal_predicate(),
                    EvidenceValue::Boolean(true),
                    "phase-terminal",
                ),
            ]
        }

        fn received_batch(parsed: bool, stage: DecisionExecutionStage) -> Vec<Evidence> {
            // These literal values describe one original eight-byte JSON representation.
            // No producer/proof helper supplies the expected view or classification.
            let rows = [
                (
                    HttpEvidencePredicate::REQUEST_METHOD,
                    EvidenceKind::Http,
                    EvidenceValue::Text("GET".to_owned()),
                    "request-method",
                ),
                (
                    HttpEvidencePredicate::REQUEST_URL,
                    EvidenceKind::Http,
                    EvidenceValue::Text(RESOURCE.to_owned()),
                    "request-url",
                ),
                (
                    HttpEvidencePredicate::RESPONSE_STATUS,
                    EvidenceKind::Http,
                    EvidenceValue::Unsigned(if parsed { 200 } else { 404 }),
                    "response-status",
                ),
                (
                    HttpEvidencePredicate::RESPONSE_FINAL_URL,
                    EvidenceKind::Http,
                    EvidenceValue::Text(RESOURCE.to_owned()),
                    "response-final-url",
                ),
                (
                    HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
                    EvidenceKind::Content,
                    EvidenceValue::Unsigned(8),
                    "response-body-size",
                ),
                (
                    HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
                    EvidenceKind::Content,
                    EvidenceValue::Boolean(false),
                    "response-body-truncation",
                ),
                (
                    HttpEvidencePredicate::RATE_LIMIT_DETECTED,
                    EvidenceKind::RateLimit,
                    EvidenceValue::Boolean(false),
                    "rate-limit-status",
                ),
                (
                    HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
                    EvidenceKind::RateLimit,
                    EvidenceValue::Boolean(false),
                    "rate-limit-headers",
                ),
            ];
            let mut batch = rows
                .into_iter()
                .map(|(predicate, kind, value, method)| {
                    fact(kind, predicate.into_knowledge(), value, method)
                })
                .collect::<Vec<_>>();
            batch.push(fact(
                EvidenceKind::Custom("rest-review".to_owned()),
                crate::web_actions::rest_review_phase_terminal_predicate(),
                EvidenceValue::Boolean(!parsed),
                "phase-terminal",
            ));
            batch.push(fact(
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge(),
                EvidenceValue::Text("application/json".to_owned()),
                "response-media-type",
            ));
            batch.push(fact(
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into_knowledge(),
                EvidenceValue::Boolean(true),
                "response-media-type-json-compatibility",
            ));
            // Six closed HTTP transport roots and the optional media root, independently
            // specified here. A compatibility assertion is NOT a byte-lineage root.
            let parents: Vec<_> = [0, 1, 2, 3, 4, 5, 9]
                .into_iter()
                .map(|index| batch[index].id().clone())
                .collect();
            batch.push(
                fact(
                    EvidenceKind::Custom("passive-secret-exposure".to_owned()),
                    KnowledgePredicate::new("web.secret-exposure", "active_review_body_lineage")
                        .unwrap(),
                    EvidenceValue::Boolean(true),
                    "active-review-body-digest-privacy-guard",
                )
                .derived_from(
                    EvidenceDerivation::new(
                        parents,
                        DerivationAlgorithm::new(
                            "web.secret-exposure.active-review-body-digest-privacy-guard",
                            1,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ),
            );
            if parsed {
                let parents = batch
                    .iter()
                    .map(|item| item.id().clone())
                    .collect::<Vec<_>>();
                let (identity, view) = match stage {
                    DecisionExecutionStage::Passive => (
                        "rest-review:candidate",
                        vec![
                            "leg=rest-review:candidate",
                            "status=200",
                            "method=GET",
                            "media=json-compatible",
                            "complete=true",
                            "truncated=false",
                            "rate_limited=false",
                            "challenged=false",
                        ],
                    ),
                    DecisionExecutionStage::Active => (
                        "rest-review:replay",
                        vec![
                            "leg=rest-review:replay",
                            "status=200",
                            "method=GET",
                            "media=json-compatible",
                            "complete=true",
                            "truncated=false",
                            "rate_limited=false",
                            "challenged=false",
                        ],
                    ),
                };
                batch.push(
                    custom(
                        "view",
                        EvidenceValue::TextList(view.into_iter().map(str::to_owned).collect()),
                        identity,
                    )
                    .derived_from(
                        EvidenceDerivation::new(
                            parents.clone(),
                            DerivationAlgorithm::new(
                                "web.rest-review.value-free-classification",
                                1,
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                );
                if stage == DecisionExecutionStage::Active {
                    // Independent stable-replay oracle: the same literal JSON and status
                    // on both legs imply all three true; no production compare is called.
                    for name in [
                        "status-equivalent",
                        "fields-equivalent",
                        "resources-equivalent",
                    ] {
                        batch.push(
                            custom(name, EvidenceValue::Boolean(true), name).derived_from(
                                EvidenceDerivation::new(
                                    parents.clone(),
                                    DerivationAlgorithm::new(
                                        "web.rest-review.value-free-classification",
                                        1,
                                    )
                                    .unwrap(),
                                )
                                .unwrap(),
                            ),
                        );
                    }
                }
                batch.push(fact(
                    EvidenceKind::Custom("rest-review".to_owned()),
                    crate::web_actions::native_web_review_response_marker_predicate(),
                    EvidenceValue::Boolean(true),
                    "complete",
                ));
            }
            batch
        }

        fn replace(
            item: &Evidence,
            kind: EvidenceKind,
            value: EvidenceValue,
            source: EvidenceSource,
            parents: Option<Vec<EvidenceId>>,
        ) -> Evidence {
            let mut result = Evidence::with_id_at(
                item.id().clone(),
                item.subject().clone(),
                kind,
                item.predicate().clone(),
                value,
                source,
                item.reliability(),
                item.observed_at_ms(),
            );
            if let Some(original) = item.origin().derivation() {
                result = result.derived_from(
                    EvidenceDerivation::new(
                        parents.unwrap_or_else(|| original.parents().to_vec()),
                        original.algorithm().clone(),
                    )
                    .unwrap(),
                );
            }
            result
        }

        async fn commit_route(
            knowledge: &KnowledgeBase,
            batch: Vec<Evidence>,
            action: &str,
            executor: &'static str,
            stage: DecisionExecutionStage,
        ) -> DecisionEvidenceReceipt {
            // The ordinary runner commits even alternate-route fixtures; rejection by
            // the narrower REST gate is not merely a failed executor setup.
            let batch = if executor == "http.rest-review" {
                batch
            } else {
                batch
                    .into_iter()
                    .map(|item| {
                        let source = EvidenceSource::new(executor, item.source().method())
                            .unwrap()
                            .with_correlation_id(CASE)
                            .unwrap();
                        replace(
                            &item,
                            item.kind().clone(),
                            item.value().clone(),
                            source,
                            None,
                        )
                    })
                    .collect()
            };
            let mut registry = DecisionExecutorRegistry::new();
            registry
                .register(Arc::new(LiteralExecutor {
                    id: executor,
                    batch,
                }))
                .unwrap();
            registry.route_action(stage, action, executor).unwrap();
            let case = VerificationCase::new(CASE, subject(), action, "hypothesis:synthetic-rest")
                .unwrap()
                .without_hypothesis_transition();
            let command = match stage {
                DecisionExecutionStage::Passive => DecisionLoopCommand::ExecuteAction {
                    case,
                    executor: None,
                    origin: DecisionActionOrigin::Planned,
                    delay_ms: None,
                },
                DecisionExecutionStage::Active => {
                    DecisionLoopCommand::CollectActiveEvidence { case }
                },
            };
            DecisionRunnerAdapter::new(registry)
                .execute_command(&command, knowledge)
                .await
                .unwrap()
        }

        async fn committed(batch: Vec<Evidence>) -> (KnowledgeBase, DecisionEvidenceReceipt) {
            let knowledge = KnowledgeBase::new();
            let receipt = commit_route(
                &knowledge,
                batch,
                "web.review.rest.readonly-replay@1",
                "http.rest-review",
                DecisionExecutionStage::Passive,
            )
            .await;
            (knowledge, receipt)
        }

        fn report(
            receipt: Option<DecisionEvidenceReceipt>,
            received: bool,
        ) -> StandardWebDecisionRunReport {
            let accounting = RequestAccountingBroker::new(RuntimeBudget::default());
            if received {
                let mut lease = accounting
                    .try_begin(
                        "web.review.rest.readonly-replay@1",
                        DecisionExecutionStage::Passive,
                        Some(DecisionActionOrigin::Planned),
                    )
                    .unwrap();
                assert_eq!(lease.observe_response_bytes(8), 8);
                lease.finish(TransportDispatchOutcome::Completed);
            }
            StandardWebDecisionRunReport {
                bootstrap: None,
                turns: Vec::new(),
                unverified_evidence: receipt,
                terminal: DecisionLoopCommand::Halt {
                    reason: DecisionStopReason::NoEligibleAction,
                },
                usage: RuntimeUsage::default(),
                transport: accounting.dispatch_audit(),
                limit_exceeded: None,
                execution_failure: None,
            }
        }

        fn terminal_state() -> RestExecutionState {
            RestExecutionState {
                legs: BTreeMap::new(),
                terminal: Some(RestRuntimeOutcome::NotFound),
                terminal_observation: Some(RestAuditObservation::new(
                    404,
                    RestObservedMediaClass::JsonCompatible,
                )),
                runtime_limit: None,
            }
        }

        fn parsed_leg(batch: &[Evidence], stage: DecisionExecutionStage) -> RestLeg {
            let identity = match stage {
                DecisionExecutionStage::Passive => "rest-review:candidate",
                DecisionExecutionStage::Active => "rest-review:replay",
            };
            let names: &[&str] = if stage == DecisionExecutionStage::Passive {
                &["view"]
            } else {
                &[
                    "view",
                    "status-equivalent",
                    "fields-equivalent",
                    "resources-equivalent",
                ]
            };
            RestLeg {
                // capture_view stages private state only. It is not the expected report,
                // lineage, or comparison oracle and does not perform transport.
                view: ApiVisibilityComparator::default()
                    .capture_view(
                        identity,
                        super::selection().target_identity(),
                        ApiSurfaceKind::JsonHttp,
                        200,
                        &serde_json::json!({"ok": 1}),
                    )
                    .unwrap(),
                response_bytes: 8,
                media: RestObservedMediaClass::JsonCompatible,
                evidence_ids: names
                    .iter()
                    .map(|name| {
                        batch
                            .iter()
                            .find(|item| {
                                item.predicate().namespace() == "web.rest-review.transport"
                                    && item.predicate().name() == *name
                            })
                            .unwrap()
                            .id()
                            .clone()
                    })
                    .collect(),
            }
        }

        fn parsed_state(batch: &[Evidence]) -> RestExecutionState {
            RestExecutionState {
                legs: BTreeMap::from([(
                    DecisionExecutionStage::Passive,
                    parsed_leg(batch, DecisionExecutionStage::Passive),
                )]),
                ..RestExecutionState::default()
            }
        }

        fn validate(
            receipt: Option<DecisionEvidenceReceipt>,
            knowledge: &KnowledgeBase,
            state: &RestExecutionState,
            received: bool,
        ) -> Result<bool, RestRuntimeInvariantError> {
            validate_value_free_rest_commits(
                &report(receipt, received),
                knowledge,
                &subject(),
                Some(&super::selection()),
                state,
            )
        }

        fn mutation(
            template: &DecisionEvidenceReceipt,
            batch: Vec<Evidence>,
        ) -> (KnowledgeBase, DecisionEvidenceReceipt) {
            let knowledge = KnowledgeBase::new();
            let writes = knowledge.insert_evidence_batch(batch.clone()).unwrap();
            let receipt = template.with_test_committed_batch(
                batch,
                writes,
                knowledge.snapshot_for_subject(&subject()),
            );
            (knowledge, receipt)
        }

        // A real decision result is only a holder for the report's committed-turn
        // shape. Neither its result nor its planner manufactures the REST oracle.
        fn decision_holder(
            knowledge: &KnowledgeBase,
            receipt: &DecisionEvidenceReceipt,
        ) -> DecisionOutcomeReport {
            let planning = PlanningContext::new(
                BenefitScore::from_percent(90).unwrap(),
                100,
                RiskScore::from_percent(50).unwrap(),
            );
            let config = DecisionLoopConfig::new(
                planning,
                AdaptationLimits::default(),
                ExperiencePolicy::default(),
                1,
            )
            .unwrap();
            let mut decision = DecisionLoop::new(config);
            let predicate = KnowledgePredicate::new("synthetic", "rest-holder").unwrap();
            let holder_hypothesis = termivar_core::Hypothesis::with_id(
                "hypothesis:synthetic-rest",
                subject(),
                predicate.clone(),
                EvidenceValue::Boolean(true),
                Probability::from_percent(50).unwrap(),
            )
            .unwrap();
            knowledge.upsert_hypothesis(holder_hypothesis).unwrap();
            let action = AttackAction::new(
                "web.review.rest.readonly-replay@1",
                "http.rest-review",
                Expression::equals(
                    KnowledgeLayer::Hypothesis,
                    predicate.clone(),
                    EvidenceValue::Boolean(true),
                ),
                HypothesisSelector::new(
                    predicate,
                    EvidenceValue::Boolean(true),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(80).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(10).unwrap(),
                BTreeSet::new(),
            )
            .unwrap()
            .with_verification_target(VerificationTarget::KnowledgeOnly);
            decision.planner_mut().register(action).unwrap();
            let mut wire = serde_json::to_value(DecisionSession::new(subject())).unwrap();
            wire["action_cycles"] = serde_json::json!(1);
            wire["state"] =
                serde_json::json!({"state": "awaiting_passive", "case": receipt.case()});
            let mut session: DecisionSession = serde_json::from_value(wire).unwrap();
            // Explicit host refusal prevents any further automated work for
            // this holder-only outcome; it is not a REST evidence oracle.
            let suppressions = crate::planner::ActionSuppressionContext::new(
                BTreeSet::new(),
                BTreeSet::from(["web.review.rest.readonly-replay@1".to_owned()]),
            );
            decision
                .submit_passive_with_action_suppressions(
                    knowledge,
                    &mut ExperienceStore::new(),
                    &mut session,
                    &suppressions,
                )
                .unwrap()
        }

        #[tokio::test]
        async fn rest_privacy_commits_require_receipts_and_accept_literal_candidate_replay_and_terminals(
        ) {
            let knowledge = KnowledgeBase::new();
            assert!(!validate(None, &knowledge, &terminal_state(), false).unwrap());
            let candidate = received_batch(true, DecisionExecutionStage::Passive);
            assert!(!validate(None, &knowledge, &parsed_state(&candidate), true).unwrap());
            let (knowledge, receipt) = committed(no_response_batch()).await;
            assert!(validate(Some(receipt), &knowledge, &terminal_state(), false).unwrap());
            let (knowledge, receipt) =
                committed(received_batch(false, DecisionExecutionStage::Passive)).await;
            assert!(validate(Some(receipt), &knowledge, &terminal_state(), true).unwrap());

            let replay = received_batch(true, DecisionExecutionStage::Active);
            let state = RestExecutionState {
                legs: BTreeMap::from([
                    (
                        DecisionExecutionStage::Passive,
                        parsed_leg(&candidate, DecisionExecutionStage::Passive),
                    ),
                    (
                        DecisionExecutionStage::Active,
                        parsed_leg(&replay, DecisionExecutionStage::Active),
                    ),
                ]),
                ..RestExecutionState::default()
            };
            let (knowledge, first) = committed(candidate).await;
            let holder = decision_holder(&knowledge, &first);
            let second = commit_route(
                &knowledge,
                replay,
                "web.review.rest.readonly-replay@1",
                "http.rest-review",
                DecisionExecutionStage::Active,
            )
            .await;
            let accounting = RequestAccountingBroker::new(RuntimeBudget::default());
            for stage in [
                DecisionExecutionStage::Passive,
                DecisionExecutionStage::Active,
            ] {
                let mut lease = accounting
                    .try_begin(
                        "web.review.rest.readonly-replay@1",
                        stage,
                        (stage == DecisionExecutionStage::Passive)
                            .then_some(DecisionActionOrigin::Planned),
                    )
                    .unwrap();
                assert_eq!(lease.observe_response_bytes(8), 8);
                lease.finish(TransportDispatchOutcome::Completed);
            }
            let mut standard = report(Some(second), false);
            standard
                .turns
                .push(StandardWebDecisionRuntimeTurn::Outcome {
                    evidence: Box::new(first),
                    decision: Box::new(holder),
                });
            standard.transport = accounting.dispatch_audit();
            assert!(validate_value_free_rest_commits(
                &standard,
                &knowledge,
                &subject(),
                Some(&super::selection()),
                &state
            )
            .unwrap());
            // Merely staging an extra leg cannot authorize it when only the candidate
            // receipt was committed. This is not a fabricated successful replay.
            let staged_candidate = received_batch(true, DecisionExecutionStage::Passive);
            let staged_replay = received_batch(true, DecisionExecutionStage::Active);
            let staged_state = RestExecutionState {
                legs: BTreeMap::from([
                    (
                        DecisionExecutionStage::Passive,
                        parsed_leg(&staged_candidate, DecisionExecutionStage::Passive),
                    ),
                    (
                        DecisionExecutionStage::Active,
                        parsed_leg(&staged_replay, DecisionExecutionStage::Active),
                    ),
                ]),
                ..RestExecutionState::default()
            };
            let (knowledge, first) = committed(staged_candidate).await;
            assert!(!validate(Some(first), &knowledge, &staged_state, true).unwrap());
        }

        #[tokio::test]
        async fn rest_privacy_commits_reject_rate_contradiction() {
            let batch = received_batch(true, DecisionExecutionStage::Passive);
            let state = parsed_state(&batch);
            let (_, template) = committed(batch.clone()).await;
            let mut contradicted = batch.clone();
            let item = &batch[6];
            contradicted[6] = replace(
                item,
                item.kind().clone(),
                EvidenceValue::Boolean(true),
                item.source().clone(),
                None,
            );
            let (knowledge, receipt) = mutation(&template, contradicted);
            assert!(
                validate(Some(receipt), &knowledge, &state, true).is_err(),
                "a committed rate-limit=true cannot support a positive rate_limited=false view"
            );
        }

        #[tokio::test]
        async fn rest_privacy_commits_reject_terminal_media_spoofs() {
            let batch = received_batch(false, DecisionExecutionStage::Passive);
            let (_, template) = committed(batch.clone()).await;
            let compatibility = &batch[10];
            let wrong_source = EvidenceSource::new("http.rest-review", "synthetic-wrong-method")
                .unwrap()
                .with_correlation_id(CASE)
                .unwrap();
            let replacements = [
                replace(
                    compatibility,
                    EvidenceKind::Content,
                    compatibility.value().clone(),
                    compatibility.source().clone(),
                    None,
                ),
                replace(
                    compatibility,
                    compatibility.kind().clone(),
                    compatibility.value().clone(),
                    wrong_source,
                    None,
                ),
                replace(
                    compatibility,
                    compatibility.kind().clone(),
                    EvidenceValue::Text("true".to_owned()),
                    compatibility.source().clone(),
                    None,
                ),
                replace(
                    compatibility,
                    compatibility.kind().clone(),
                    EvidenceValue::Unsigned(1),
                    compatibility.source().clone(),
                    None,
                ),
                replace(
                    compatibility,
                    compatibility.kind().clone(),
                    EvidenceValue::Text("null".to_owned()),
                    compatibility.source().clone(),
                    None,
                ),
            ];
            for replacement in replacements {
                let mut changed = batch.clone();
                changed[10] = replacement;
                let (knowledge, receipt) = mutation(&template, changed);
                assert!(validate(Some(receipt), &knowledge, &terminal_state(), true).is_err());
            }
            let mut missing = batch.clone();
            missing.remove(10);
            let (knowledge, receipt) = mutation(&template, missing);
            assert!(validate(Some(receipt), &knowledge, &terminal_state(), true).is_err());
            let mut duplicate = batch;
            duplicate.push(fact(
                EvidenceKind::Http,
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into_knowledge(),
                EvidenceValue::Boolean(true),
                "response-media-type-json-compatibility",
            ));
            let (knowledge, receipt) = mutation(&template, duplicate);
            assert!(validate(Some(receipt), &knowledge, &terminal_state(), true).is_err());
            // Core EvidenceValue is a tagged typed enum, so JSON null cannot become an
            // evidence row at all; Text("null") above separately tests a wrong typed row.
            assert!(serde_json::from_value::<EvidenceValue>(serde_json::Value::Null).is_err());
        }

        #[tokio::test]
        async fn rest_privacy_commits_reject_wrong_route_stage_executor_subject_and_write_authority(
        ) {
            for (action, executor, stage) in [
                (
                    "synthetic.other-action",
                    "http.rest-review",
                    DecisionExecutionStage::Passive,
                ),
                (
                    "web.review.rest.readonly-replay@1",
                    "synthetic.other-executor",
                    DecisionExecutionStage::Passive,
                ),
                (
                    "web.review.rest.readonly-replay@1",
                    "http.rest-review",
                    DecisionExecutionStage::Active,
                ),
            ] {
                let knowledge = KnowledgeBase::new();
                let receipt =
                    commit_route(&knowledge, no_response_batch(), action, executor, stage).await;
                assert!(validate(Some(receipt), &knowledge, &terminal_state(), false).is_err());
            }
            let (knowledge, receipt) = committed(no_response_batch()).await;
            assert!(validate_value_free_rest_commits(
                &report(Some(receipt), false),
                &knowledge,
                &EntityId::new("endpoint:https://sibling.invalid/").unwrap(),
                Some(&super::selection()),
                &terminal_state()
            )
            .is_err());
            let batch = received_batch(true, DecisionExecutionStage::Passive);
            let state = parsed_state(&batch);
            let (knowledge, receipt) = committed(batch).await;
            assert!(validate_value_free_rest_commits(
                &report(Some(receipt), true),
                &knowledge,
                &subject(),
                None,
                &state
            )
            .is_err());

            let batch = received_batch(true, DecisionExecutionStage::Passive);
            let state = parsed_state(&batch);
            let (knowledge, receipt) = committed(batch.clone()).await;
            assert!(validate(Some(receipt.clone()), &KnowledgeBase::new(), &state, true).is_err());
            let mut duplicate = batch;
            duplicate.push(duplicate[0].clone());
            let duplicated = receipt.with_test_committed_batch(
                duplicate.clone(),
                vec![KnowledgeWrite::Unchanged; duplicate.len()],
                knowledge.snapshot_for_subject(&subject()),
            );
            assert!(validate(Some(duplicated), &knowledge, &state, true).is_err());
            let wrong_writes = receipt.with_test_committed_batch(
                receipt.evidence().to_vec(),
                Vec::new(),
                knowledge.snapshot_for_subject(&subject()),
            );
            assert!(validate(Some(wrong_writes), &knowledge, &state, true).is_err());
        }

        #[tokio::test]
        async fn rest_privacy_commits_reject_content_identities_unknown_facts_and_lost_derivation_parents(
        ) {
            let batch = received_batch(true, DecisionExecutionStage::Passive);
            let state = parsed_state(&batch);
            let (_, template) = committed(batch.clone()).await;
            for extra in [
                fact(
                    EvidenceKind::Content,
                    HttpEvidencePredicate::RESPONSE_BODY_SHA256.into_knowledge(),
                    EvidenceValue::Text("a".repeat(64)),
                    "response-body-sha256",
                ),
                custom(
                    "semantic_digest",
                    EvidenceValue::Text("synthetic-unkeyed-content-identity".to_owned()),
                    "semantic-digest",
                ),
                fact(
                    EvidenceKind::Custom("passive-secret-exposure".to_owned()),
                    KnowledgePredicate::new("web.secret-exposure", "response_body_lineage")
                        .unwrap(),
                    EvidenceValue::Boolean(true),
                    "synthetic-extra-lineage",
                ),
            ] {
                let mut changed = batch.clone();
                changed.push(extra);
                let (knowledge, receipt) = mutation(&template, changed);
                assert!(validate(Some(receipt), &knowledge, &state, true).is_err());
            }
            for index in [11, 12] {
                let mut changed = batch.clone();
                let item = &batch[index];
                let parents = item.origin().derivation().unwrap().parents()[1..].to_vec();
                changed[index] = replace(
                    item,
                    item.kind().clone(),
                    item.value().clone(),
                    item.source().clone(),
                    Some(parents),
                );
                let (knowledge, receipt) = mutation(&template, changed);
                assert!(validate(Some(receipt), &knowledge, &state, true).is_err());
            }
        }
    }
}
