//! Parent-native, explicitly enabled OpenAPI document observation.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use termivar_core::predicates::WebDiscoveryEvidencePredicate;
use termivar_core::{
    ConfidenceScore, DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId,
    EvidenceKind, EvidenceSource, EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
};
use url::Url;

#[cfg(feature = "rest-review")]
use super::rest_runtime::StableRestSelectionSlot;
#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
use super::ssrf_oast_runtime::StableSsrfOastSelectionSlot;
use super::{
    assessment_defense::{project_assessment_defense_signal, AssessmentDefenseProjectionContext},
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext,
    },
};
#[cfg(feature = "rest-review")]
use crate::rest_review::{
    select_rest_operation, RestOperationSelection, RestOperationSelectionOutcome,
};
#[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
use crate::ssrf_oast_review::{
    select_openapi_document_query_candidate, SsrfOastCandidateSelection, SsrfOastQueryCandidate,
};
use crate::{
    http_evidence::{HttpRequestBroker, HttpRequestBrokerError},
    openapi_review::{
        parse_openapi_document, OpenApiHttpMethod, OpenApiParseOutcome, OpenApiVersion,
    },
    DecisionActionExecutor, DecisionActionOrigin, DecisionExecutionRequest, DecisionExecutionStage,
    DecisionExecutorError, DecisionExecutorRegistry, HttpProbe, HttpProbeMethod, KnowledgeBase,
    RuleEngine, RuntimeLimitExceeded, StandardApiReasoning, TransportDispatchOutcome,
    HTTP_EVIDENCE_EXECUTOR_ID,
};

pub const OPENAPI_REVIEW_ACTION_ID: &str = "web.review.openapi.document-replay@1";
pub const OPENAPI_REVIEW_CAPABILITY_ID: &str = "api.openapi-contract-observed@1";
pub const MAX_OPENAPI_REVIEW_DOCUMENTS: usize = 1;
pub const MAX_OPENAPI_REVIEW_REQUESTS: usize = 2;
pub const MAX_OPENAPI_REVIEW_ACTIVE_VERIFICATIONS: usize = 1;
pub(super) const OPENAPI_REVIEW_ACTION_CYCLE_ALLOWANCE: u32 = 1;

const OPENAPI_EXECUTOR_ID: &str = "http.openapi-review";
const OPENAPI_EVIDENCE_NAMESPACE: &str = "web.openapi-review.transport";
const OPENAPI_ACCEPT: &str = "application/vnd.oai.openapi+json, application/json, application/yaml, application/x-yaml, text/yaml, text/plain";
const OPENAPI_DOCUMENT_ID_DOMAIN: &[u8] = b"security.openapi-review.document-target.v1\0";
const MAX_OPENAPI_CANDIDATE_HINTS: usize = 64;
const MAX_OPENAPI_CANDIDATE_URL_BYTES: usize = 8 * 1024;
const MAX_OPENAPI_CANDIDATE_PATH_BYTES: usize = 1024;

/// An assessment selection, never inferred from a remote document or match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenApiResponsePrivacy {
    HistoricalDigests,
    #[cfg(feature = "secret-exposure-review")]
    ValueFree,
}

impl OpenApiResponsePrivacy {
    fn is_value_free(self) -> bool {
        match self {
            Self::HistoricalDigests => false,
            #[cfg(feature = "secret-exposure-review")]
            Self::ValueFree => true,
        }
    }
}

const OPENAPI_CLASSIFICATION_ALGORITHM: &str = "web.openapi-review.value-free-classification";

#[cfg(feature = "secret-exposure-review")]
pub(super) fn openapi_privacy_route_is_valid(
    case: &crate::VerificationCase,
    stage: DecisionExecutionStage,
    executor_id: &str,
) -> bool {
    executor_id == OPENAPI_EXECUTOR_ID
        && case.action_id() == OPENAPI_REVIEW_ACTION_ID
        && !case.applies_hypothesis_transition()
        && case.payload_strategy().is_none()
        && matches!(
            stage,
            DecisionExecutionStage::Passive | DecisionExecutionStage::Active
        )
}

const OPENAPI_CAPABILITY: AssessmentCapabilityDescriptor = AssessmentCapabilityDescriptor::informational(
    OPENAPI_REVIEW_CAPABILITY_ID,
    "OpenAPI contract observed",
    "API surface",
    "Two anonymous exact-origin GET requests reproduced the same bounded OpenAPI contract metadata.",
    900_000,
    "api.openapi-contract-review@1",
    "Confirm that publishing this OpenAPI contract matches deployment policy.",
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenApiRuntimeOutcome {
    NotEligible,
    DocumentObserved,
    Swagger20MetadataOnly,
    UnsupportedVersion,
    ReplayMismatch,
    UnsupportedMedia,
    Malformed,
    LimitExceeded,
    TooLarge,
    RedirectObserved,
    RateLimited,
    DefensiveInterference,
    HttpError,
    Truncated,
    Incomplete,
    BudgetExhausted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenApiCandidateSource {
    DiscoveredOpenApiJson,
    DiscoveredOpenApiYaml,
    DiscoveredSwaggerJson,
    DiscoveredSwaggerYaml,
    ConventionalOpenApiJson,
}
impl OpenApiCandidateSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiscoveredOpenApiJson => "discovered_openapi_json",
            Self::DiscoveredOpenApiYaml => "discovered_openapi_yaml",
            Self::DiscoveredSwaggerJson => "discovered_swagger_json",
            Self::DiscoveredSwaggerYaml => "discovered_swagger_yaml",
            Self::ConventionalOpenApiJson => "conventional_openapi_json",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct WebAssessmentOpenApiAudit {
    outcome: OpenApiRuntimeOutcome,
    candidate_source: OpenApiCandidateSource,
    request_count: u8,
    active_verification_count: u8,
    version: Option<&'static str>,
    semantic_digest: Option<String>,
    path_count: u32,
    operation_count: u32,
    get_operation_count: u32,
    write_operation_count: u32,
    path_parameter_count: u32,
    query_parameter_count: u32,
    explicit_auth_operation_count: u32,
    anonymous_operation_count: u32,
    url_like_operation_count: u32,
    multipart_operation_count: u32,
    deprecated_operation_count: u32,
    replay_matched: bool,
    item_projected: bool,
}

impl WebAssessmentOpenApiAudit {
    pub const fn outcome(&self) -> OpenApiRuntimeOutcome {
        self.outcome
    }
    pub const fn candidate_source(&self) -> OpenApiCandidateSource {
        self.candidate_source
    }
    pub const fn request_count(&self) -> u8 {
        self.request_count
    }
    pub const fn active_verification_count(&self) -> u8 {
        self.active_verification_count
    }
    pub const fn version(&self) -> Option<&'static str> {
        self.version
    }
    pub fn semantic_digest(&self) -> Option<&str> {
        self.semantic_digest.as_deref()
    }
    pub const fn path_count(&self) -> u32 {
        self.path_count
    }
    pub const fn operation_count(&self) -> u32 {
        self.operation_count
    }
    pub const fn get_operation_count(&self) -> u32 {
        self.get_operation_count
    }
    pub const fn write_operation_count(&self) -> u32 {
        self.write_operation_count
    }
    pub const fn path_parameter_count(&self) -> u32 {
        self.path_parameter_count
    }
    pub const fn query_parameter_count(&self) -> u32 {
        self.query_parameter_count
    }
    pub const fn explicit_auth_operation_count(&self) -> u32 {
        self.explicit_auth_operation_count
    }
    pub const fn anonymous_operation_count(&self) -> u32 {
        self.anonymous_operation_count
    }
    pub const fn url_like_operation_count(&self) -> u32 {
        self.url_like_operation_count
    }
    pub const fn multipart_operation_count(&self) -> u32 {
        self.multipart_operation_count
    }
    pub const fn deprecated_operation_count(&self) -> u32 {
        self.deprecated_operation_count
    }
    pub const fn replay_matched(&self) -> bool {
        self.replay_matched
    }
    pub const fn item_projected(&self) -> bool {
        self.item_projected
    }
}

impl fmt::Debug for WebAssessmentOpenApiAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebAssessmentOpenApiAudit")
            .field("outcome", &self.outcome)
            .field("candidate_source", &self.candidate_source)
            .field("request_count", &self.request_count)
            .field("active_verification_count", &self.active_verification_count)
            .field("version", &self.version)
            .field("path_count", &self.path_count)
            .field("operation_count", &self.operation_count)
            .field("get_operation_count", &self.get_operation_count)
            .field("write_operation_count", &self.write_operation_count)
            .field("path_parameter_count", &self.path_parameter_count)
            .field("query_parameter_count", &self.query_parameter_count)
            .field(
                "explicit_auth_operation_count",
                &self.explicit_auth_operation_count,
            )
            .field("anonymous_operation_count", &self.anonymous_operation_count)
            .field("url_like_operation_count", &self.url_like_operation_count)
            .field("multipart_operation_count", &self.multipart_operation_count)
            .field(
                "deprecated_operation_count",
                &self.deprecated_operation_count,
            )
            .field("replay_matched", &self.replay_matched)
            .field("item_projected", &self.item_projected)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct OpenApiCandidate {
    url: Url,
    source: OpenApiCandidateSource,
    identity: String,
}

impl fmt::Debug for OpenApiCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenApiCandidate(<exact-origin-redacted>)")
    }
}

pub(super) fn select_openapi_candidate(
    origin: &Url,
    hints: impl IntoIterator<Item = Url>,
) -> Option<OpenApiCandidate> {
    let mut candidates = hints
        .into_iter()
        .take(MAX_OPENAPI_CANDIDATE_HINTS)
        .filter_map(|url| {
            if !candidate_url_is_allowed(origin, &url) {
                return None;
            }
            let name = url.path_segments()?.next_back()?;
            let source = match name.to_ascii_lowercase().as_str() {
                "openapi.json" => OpenApiCandidateSource::DiscoveredOpenApiJson,
                "openapi.yaml" | "openapi.yml" => OpenApiCandidateSource::DiscoveredOpenApiYaml,
                "swagger.json" => OpenApiCandidateSource::DiscoveredSwaggerJson,
                "swagger.yaml" | "swagger.yml" => OpenApiCandidateSource::DiscoveredSwaggerYaml,
                _ => return None,
            };
            Some((source, url))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|(left_source, left), (right_source, right)| {
        candidate_rank(*left_source)
            .cmp(&candidate_rank(*right_source))
            .then_with(|| left.as_str().cmp(right.as_str()))
    });
    let (source, url) = candidates.into_iter().next().unwrap_or_else(|| {
        (
            OpenApiCandidateSource::ConventionalOpenApiJson,
            origin
                .join("/openapi.json")
                .expect("absolute fallback path is valid"),
        )
    });
    if !candidate_url_is_allowed(origin, &url) {
        return None;
    }
    Some(OpenApiCandidate {
        identity: document_identity(&url),
        url,
        source,
    })
}

fn candidate_url_is_allowed(origin: &Url, url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.origin() == origin.origin()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.as_str().len() <= MAX_OPENAPI_CANDIDATE_URL_BYTES
        && url.path().len() <= MAX_OPENAPI_CANDIDATE_PATH_BYTES
}

fn committed_discovery_hints(knowledge: &KnowledgeBase, subject: &EntityId) -> Vec<Url> {
    knowledge
        .evidence_for_subject(subject)
        .into_iter()
        .filter_map(|evidence| {
            let expected_method = if evidence.predicate()
                == &WebDiscoveryEvidencePredicate::GET_ROUTE.into_knowledge()
            {
                "get-route"
            } else if evidence.predicate()
                == &WebDiscoveryEvidencePredicate::HEAD_ROUTE.into_knowledge()
            {
                "head-route"
            } else if evidence.predicate()
                == &WebDiscoveryEvidencePredicate::GET_FORM_ACTION.into_knowledge()
            {
                "get-form-action"
            } else if evidence.predicate()
                == &WebDiscoveryEvidencePredicate::POST_FORM_ACTION.into_knowledge()
            {
                "post-form-action"
            } else if evidence.predicate()
                == &WebDiscoveryEvidencePredicate::DIALOG_FORM_ACTION.into_knowledge()
            {
                "dialog-form-action"
            } else {
                return None;
            };
            if evidence.kind() != &EvidenceKind::Content
                || evidence.source().component() != HTTP_EVIDENCE_EXECUTOR_ID
                || evidence.source().method() != expected_method
                || evidence.source().correlation_id() != Some(super::BOOTSTRAP_CASE_ID)
                || evidence.origin().derivation().is_none()
            {
                return None;
            }
            let EvidenceValue::Text(value) = evidence.value() else {
                return None;
            };
            Url::parse(value).ok()
        })
        .take(MAX_OPENAPI_CANDIDATE_HINTS)
        .collect()
}

const fn candidate_rank(source: OpenApiCandidateSource) -> u8 {
    match source {
        OpenApiCandidateSource::DiscoveredOpenApiJson => 0,
        OpenApiCandidateSource::DiscoveredOpenApiYaml => 1,
        OpenApiCandidateSource::DiscoveredSwaggerJson => 2,
        OpenApiCandidateSource::DiscoveredSwaggerYaml => 3,
        OpenApiCandidateSource::ConventionalOpenApiJson => 4,
    }
}

fn document_identity(url: &Url) -> String {
    let mut digest = Sha256::new();
    digest.update(OPENAPI_DOCUMENT_ID_DOMAIN);
    digest.update(url.path().as_bytes());
    format!("openapi-document@1:{:x}", digest.finalize())
}

fn observed_document_identity(candidate_identity: &str, semantic_digest: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"security.openapi-review.observed-document.v1\0");
    digest.update(crate::openapi_review::OPENAPI_CATALOG_ALGORITHM.as_bytes());
    digest.update(candidate_identity.as_bytes());
    digest.update(semantic_digest.as_bytes());
    format!("openapi-observed@1:{:x}", digest.finalize())
}

pub(super) struct OpenApiReviewConfig {
    candidate: OpenApiCandidate,
    privacy: OpenApiResponsePrivacy,
}
impl OpenApiReviewConfig {
    pub(super) fn new(candidate: OpenApiCandidate) -> Self {
        Self {
            candidate,
            privacy: OpenApiResponsePrivacy::HistoricalDigests,
        }
    }

    #[cfg(feature = "secret-exposure-review")]
    pub(super) fn with_value_free_response_privacy(mut self) -> Self {
        self.privacy = OpenApiResponsePrivacy::ValueFree;
        self
    }
}

pub(super) struct OpenApiRuntimeBinding {
    executor: Arc<OpenApiDecisionExecutor>,
    subject: EntityId,
}

impl OpenApiRuntimeBinding {
    pub(super) fn new(
        config: OpenApiReviewConfig,
        requests: HttpRequestBroker,
        subject: EntityId,
        knowledge: KnowledgeBase,
    ) -> Self {
        Self::new_internal(
            config,
            requests,
            subject,
            knowledge,
            #[cfg(feature = "ssrf-oast-review")]
            None,
        )
    }

    #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
    pub(super) fn new_with_ssrf_selection(
        config: OpenApiReviewConfig,
        requests: HttpRequestBroker,
        subject: EntityId,
        knowledge: KnowledgeBase,
        ssrf_selection: StableSsrfOastSelectionSlot,
    ) -> Self {
        Self::new_internal(config, requests, subject, knowledge, Some(ssrf_selection))
    }

    fn new_internal(
        config: OpenApiReviewConfig,
        requests: HttpRequestBroker,
        subject: EntityId,
        knowledge: KnowledgeBase,
        #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
        ssrf_selection: Option<StableSsrfOastSelectionSlot>,
    ) -> Self {
        let candidate = config.candidate;
        let executor = Arc::new(OpenApiDecisionExecutor {
            requests,
            privacy: config.privacy,
            candidate: Mutex::new(candidate),
            subject: subject.clone(),
            knowledge,
            state: Mutex::new(OpenApiExecutionState::default()),
            #[cfg(feature = "rest-review")]
            rest_selection: StableRestSelectionSlot::new(),
            #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
            ssrf_selection,
        });
        Self { executor, subject }
    }
    #[cfg(feature = "rest-review")]
    pub(super) fn rest_selection_slot(&self) -> StableRestSelectionSlot {
        self.executor.rest_selection.clone()
    }
    #[cfg(feature = "rest-review")]
    pub(super) fn response_privacy_is_value_free(&self) -> bool {
        self.executor.privacy.is_value_free()
    }
    pub(super) fn install_into_parent_registry(
        &self,
        registry: &mut DecisionExecutorRegistry,
    ) -> Result<(), OpenApiRuntimeInvariantError> {
        let before = registry.len();
        let executor: Arc<dyn DecisionActionExecutor> = self.executor.clone();
        registry
            .register(executor)
            .map_err(|_| OpenApiRuntimeInvariantError::Catalog)?;
        for stage in [
            DecisionExecutionStage::Passive,
            DecisionExecutionStage::Active,
        ] {
            registry
                .route_action(stage, OPENAPI_REVIEW_ACTION_ID, OPENAPI_EXECUTOR_ID)
                .map_err(|_| OpenApiRuntimeInvariantError::Catalog)?;
        }
        if registry.len() != before + 1 {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        Ok(())
    }
    pub(super) fn finalize(
        self,
        knowledge: &KnowledgeBase,
        standard: &super::StandardWebDecisionRunReport,
        forced_outcome: Option<OpenApiRuntimeOutcome>,
        forced_runtime_limit: Option<RuntimeLimitExceeded>,
    ) -> Result<OpenApiRuntimeResult, OpenApiRuntimeInvariantError> {
        let transport = standard.transport();
        if transport.omitted_receipt_count() != 0 {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        let selected_candidate = self
            .executor
            .candidate
            .lock()
            .map_err(|_| OpenApiRuntimeInvariantError::Catalog)?
            .clone();
        let receipts = transport
            .receipts()
            .iter()
            .filter(|r| r.action_id() == OPENAPI_REVIEW_ACTION_ID)
            .collect::<Vec<_>>();
        if !openapi_transport_prefix_is_valid(&receipts) {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        let state = self.executor.take_state()?;
        #[cfg(feature = "secret-exposure-review")]
        let committed_legs = if self.executor.privacy.is_value_free() {
            validate_value_free_openapi_commits(
                standard,
                knowledge,
                &self.subject,
                &selected_candidate,
                &state,
            )?
        } else {
            true
        };
        #[cfg(not(feature = "secret-exposure-review"))]
        let committed_legs = true;
        if !captured_openapi_prefix_reconciles(&state, &receipts) {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        let request_count = u8::try_from(receipts.len()).unwrap_or(u8::MAX);
        let state_terminal = state.terminal;
        let terminal = forced_outcome.or_else(|| {
            committed_legs
                .then(|| state_terminal.as_ref().map(|(outcome, _)| *outcome))
                .flatten()
        });
        let runtime_limit = if forced_outcome.is_some() {
            forced_runtime_limit
        } else {
            state_terminal.and_then(|(_, limit)| limit)
        };
        if let Some(outcome) = terminal {
            let audit = audit(
                selected_candidate.source,
                outcome,
                request_count,
                None,
                false,
            );
            if matches!(
                outcome,
                OpenApiRuntimeOutcome::Incomplete
                    | OpenApiRuntimeOutcome::Truncated
                    | OpenApiRuntimeOutcome::LimitExceeded
                    | OpenApiRuntimeOutcome::TooLarge
                    | OpenApiRuntimeOutcome::BudgetExhausted
                    | OpenApiRuntimeOutcome::Cancelled
            ) {
                return Ok(OpenApiRuntimeResult::Stopped {
                    audit,
                    runtime_limit,
                });
            }
            return Ok(OpenApiRuntimeResult::Complete(CommittedOpenApiReview {
                subject: self.subject,
                privacy: self.executor.privacy,
                target_identity: selected_candidate.identity,
                outcome,
                evidence_ids: Vec::new(),
                audit,
            }));
        }
        let (Some(candidate), Some(replay)) = (
            state.legs.get(&DecisionExecutionStage::Passive),
            state.legs.get(&DecisionExecutionStage::Active),
        ) else {
            return Ok(OpenApiRuntimeResult::Stopped {
                audit: audit(
                    selected_candidate.source,
                    if receipts.is_empty() {
                        OpenApiRuntimeOutcome::NotEligible
                    } else {
                        OpenApiRuntimeOutcome::Incomplete
                    },
                    request_count,
                    None,
                    false,
                ),
                runtime_limit: None,
            });
        };
        if !committed_legs
            || receipts.len() != MAX_OPENAPI_REVIEW_REQUESTS
            || receipts
                .iter()
                .zip([candidate, replay])
                .any(|(receipt, leg)| {
                    receipt.outcome() != TransportDispatchOutcome::Completed
                        || receipt.response_bytes() != leg.response_bytes
                })
        {
            return Ok(OpenApiRuntimeResult::Stopped {
                audit: audit(
                    selected_candidate.source,
                    OpenApiRuntimeOutcome::Incomplete,
                    request_count,
                    None,
                    false,
                ),
                runtime_limit: None,
            });
        }
        let outcome = if candidate.semantically_matches(replay) {
            OpenApiRuntimeOutcome::DocumentObserved
        } else {
            OpenApiRuntimeOutcome::ReplayMismatch
        };
        let projected = outcome == OpenApiRuntimeOutcome::DocumentObserved;
        let mut audit = audit(
            selected_candidate.source,
            outcome,
            request_count,
            Some(candidate),
            projected,
        );
        if self.executor.privacy.is_value_free() {
            audit.semantic_digest = None;
        }
        let evidence_ids = vec![
            candidate
                .evidence_id
                .clone()
                .ok_or(OpenApiRuntimeInvariantError::Catalog)?,
            replay
                .evidence_id
                .clone()
                .ok_or(OpenApiRuntimeInvariantError::Catalog)?,
        ];
        if evidence_ids
            .iter()
            .any(|id| knowledge.evidence(id).is_none())
        {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        if projected {
            commit_api_reasoning_inputs(knowledge, &self.subject)?;
        }
        let target_identity = if self.executor.privacy.is_value_free() {
            selected_candidate.identity
        } else {
            observed_document_identity(&selected_candidate.identity, &candidate.digest)
        };
        Ok(OpenApiRuntimeResult::Complete(CommittedOpenApiReview {
            subject: self.subject,
            privacy: self.executor.privacy,
            target_identity,
            outcome,
            evidence_ids,
            audit,
        }))
    }
}

/// Executor state is staged before the runner commits. It is usable for a
/// public projection only after exact receipt/write-set reconciliation. A
/// cancelled final dispatch may legitimately have no committed receipt.
#[cfg(feature = "secret-exposure-review")]
fn validate_value_free_openapi_commits(
    standard: &super::StandardWebDecisionRunReport,
    knowledge: &KnowledgeBase,
    subject: &EntityId,
    candidate: &OpenApiCandidate,
    state: &OpenApiExecutionState,
) -> Result<bool, OpenApiRuntimeInvariantError> {
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
            receipt.case().action_id() == OPENAPI_REVIEW_ACTION_ID
                || receipt.executor_id() == OPENAPI_EXECUTOR_ID
        })
        .collect::<Vec<_>>();
    if receipts.len() > MAX_OPENAPI_REVIEW_REQUESTS {
        return Err(OpenApiRuntimeInvariantError::Catalog);
    }
    let mut committed = BTreeSet::new();
    let mut terminal_committed = false;
    for (index, receipt) in receipts.into_iter().enumerate() {
        let expected_stage = if index == 0 {
            DecisionExecutionStage::Passive
        } else {
            DecisionExecutionStage::Active
        };
        if !openapi_privacy_route_is_valid(receipt.case(), receipt.stage(), receipt.executor_id())
            || receipt.case().subject() != subject
            || receipt.stage() != expected_stage
            || receipt.evidence().len() != receipt.writes().len()
        {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        let mut ids = BTreeSet::new();
        for (item, write) in receipt.write_set() {
            if !matches!(write, KnowledgeWrite::Inserted | KnowledgeWrite::Unchanged)
                || item.subject() != subject
                || item.source().component() != OPENAPI_EXECUTOR_ID
                || item.source().correlation_id() != Some(receipt.case().id())
                || item.reliability() != ConfidenceScore::MAX
                || !ids.insert(item.id())
                || knowledge.evidence(item.id()).as_ref() != Some(item)
                || item.predicate() == &HttpEvidencePredicate::RESPONSE_BODY_SHA256.into_knowledge()
            {
                return Err(OpenApiRuntimeInvariantError::Catalog);
            }
        }
        let response_received = receipt.evidence().iter().any(|item| {
            item.predicate() == &HttpEvidencePredicate::REQUEST_METHOD.into_knowledge()
        });
        if !response_received {
            // No-body failure is deliberately NOT a fabricated body lineage.
            let bytes = openapi_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            )?;
            let terminal = openapi_receipt_fact(
                receipt,
                &crate::web_actions::openapi_review_phase_terminal_predicate(),
            )?;
            if state.terminal.is_none()
                || receipt.evidence().len() != 2
                || state.legs.contains_key(&receipt.stage())
                || bytes.kind() != &EvidenceKind::Custom("openapi-review".to_owned())
                || terminal.kind() != &EvidenceKind::Custom("openapi-review".to_owned())
                || !bytes.origin().is_direct()
                || !terminal.origin().is_direct()
                || bytes.source().method() != "response-body-size"
                || terminal.source().method() != "phase-terminal"
                || bytes.value() != &EvidenceValue::Unsigned(0)
                || terminal.value() != &EvidenceValue::Boolean(true)
            {
                return Err(OpenApiRuntimeInvariantError::Catalog);
            }
            terminal_committed = true;
            continue;
        }
        let parents = super::secret_exposure::openapi_response_privacy_parent_ids(
            receipt.evidence(),
            receipt.case(),
            receipt.stage(),
            receipt.executor_id(),
        )
        .ok_or(OpenApiRuntimeInvariantError::Catalog)?;
        let lineage_predicate = KnowledgePredicate::new(
            super::secret_exposure::SECRET_EXPOSURE_NAMESPACE,
            super::secret_exposure::ACTIVE_REVIEW_BODY_LINEAGE,
        )?;
        let lineage = openapi_receipt_fact(receipt, &lineage_predicate)?;
        if receipt.evidence().iter().any(|item| {
            let known_openapi_fact = match item.predicate().name() {
                "document" | "phase-terminal" => true,
                // This pre-existing readiness marker is emitted in a build
                // containing REST even if the REST consumer is not selected.
                // It is a fixed boolean, never a catalogue content identity.
                #[cfg(feature = "rest-review")]
                "rest-catalog-ready" => {
                    receipt.stage() == DecisionExecutionStage::Active
                        && item.kind() == &EvidenceKind::Custom("openapi-review".to_owned())
                        && item.source().method() == "rest-catalog-ready"
                        && item.origin().is_direct()
                        && item.value() == &EvidenceValue::Boolean(true)
                },
                _ => false,
            };
            (item.predicate().namespace() == super::secret_exposure::SECRET_EXPOSURE_NAMESPACE
                && item.predicate() != &lineage_predicate)
                || (item.predicate().namespace() == OPENAPI_EVIDENCE_NAMESPACE
                    && !known_openapi_fact)
        }) {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        if !super::secret_exposure::is_active_review_body_privacy_lineage(
            lineage,
            subject,
            receipt.case().id(),
            OPENAPI_EXECUTOR_ID,
            &parents,
        ) {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        for predicate in [
            HttpEvidencePredicate::REQUEST_URL,
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
        ] {
            if openapi_receipt_fact(receipt, &predicate.into_knowledge())?.value()
                != &EvidenceValue::Text(candidate.url.to_string())
            {
                return Err(OpenApiRuntimeInvariantError::Catalog);
            }
        }
        let document_predicate = KnowledgePredicate::new(OPENAPI_EVIDENCE_NAMESPACE, "document")?;
        let document_count = receipt
            .evidence()
            .iter()
            .filter(|item| item.predicate() == &document_predicate)
            .count();
        let terminal = openapi_receipt_fact(
            receipt,
            &crate::web_actions::openapi_review_phase_terminal_predicate(),
        )?;
        if terminal.kind() != &EvidenceKind::Custom("openapi-review".to_owned())
            || terminal.source().method() != "phase-terminal"
            || !terminal.origin().is_direct()
        {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        let completion = receipt
            .evidence()
            .iter()
            .filter(|item| {
                item.predicate()
                    == &crate::web_actions::native_web_review_response_marker_predicate()
            })
            .collect::<Vec<_>>();
        let Some(leg) = state.legs.get(&receipt.stage()) else {
            let wire = standard
                .transport()
                .receipts()
                .iter()
                .filter(|item| item.action_id() == OPENAPI_REVIEW_ACTION_ID)
                .nth(index)
                .ok_or(OpenApiRuntimeInvariantError::Catalog)?;
            let bytes = openapi_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            )?;
            if state.terminal.is_none()
                || document_count != 0
                || !completion.is_empty()
                || terminal.value() != &EvidenceValue::Boolean(true)
                || !matches!(
                    wire.outcome(),
                    TransportDispatchOutcome::Completed
                        | TransportDispatchOutcome::ResponseBudgetReached
                )
                || !matches!(bytes.value(), EvidenceValue::Unsigned(value) if *value <= wire.response_bytes())
            {
                return Err(OpenApiRuntimeInvariantError::Catalog);
            }
            terminal_committed = true;
            continue;
        };
        let document = openapi_receipt_fact(receipt, &document_predicate)?;
        let derivation = document
            .origin()
            .derivation()
            .ok_or(OpenApiRuntimeInvariantError::Catalog)?;
        let expected_summary = EvidenceValue::TextList(vec![
            format!("version={}", leg.version.unwrap_or("unknown")),
            format!("paths={}", leg.paths),
            format!("operations={}", leg.operations),
        ]);
        let phase = crate::web_actions::openapi_review_phase_terminal_predicate();
        let direct_predicates = [
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
        let mut expected_parents = BTreeSet::new();
        for item in receipt.evidence().iter().filter(|item| {
            direct_predicates.contains(item.predicate()) || item.predicate() == &phase
        }) {
            if !item.origin().is_direct() || item.reliability() != document.reliability() {
                return Err(OpenApiRuntimeInvariantError::Catalog);
            }
            expected_parents.insert(item.id().clone());
        }
        expected_parents.insert(lineage.id().clone());
        if leg.evidence_id.as_ref() != Some(document.id())
            || completion.len() != 1
            || completion[0].value() != &EvidenceValue::Boolean(true)
            || !completion[0].origin().is_direct()
            || completion[0].source().method() != "complete"
            || document.kind() != &EvidenceKind::Custom("openapi-review".to_owned())
            || document.source().method() != "document"
            || document.value() != &expected_summary
            || derivation.algorithm().name() != OPENAPI_CLASSIFICATION_ALGORITHM
            || derivation.algorithm().version() != 1
            || derivation.parents() != expected_parents.into_iter().collect::<Vec<_>>()
            || lineage.reliability() != document.reliability()
            || openapi_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
            )?
            .value()
                != &EvidenceValue::Unsigned(leg.response_bytes)
            || openapi_receipt_fact(
                receipt,
                &HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED.into_knowledge(),
            )?
            .value()
                != &EvidenceValue::Boolean(false)
            || openapi_receipt_fact(receipt, &phase)?.value() != &EvidenceValue::Boolean(false)
        {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        committed.insert(receipt.stage());
    }
    Ok(state.legs.keys().all(|stage| committed.contains(stage))
        && (state.terminal.is_none() || terminal_committed))
}

#[cfg(feature = "secret-exposure-review")]
fn openapi_receipt_fact<'a>(
    receipt: &'a crate::DecisionEvidenceReceipt,
    predicate: &KnowledgePredicate,
) -> Result<&'a Evidence, OpenApiRuntimeInvariantError> {
    let mut rows = receipt
        .evidence()
        .iter()
        .filter(|item| item.predicate() == predicate);
    let item = rows.next().ok_or(OpenApiRuntimeInvariantError::Catalog)?;
    if rows.next().is_some() {
        return Err(OpenApiRuntimeInvariantError::Catalog);
    }
    Ok(item)
}

fn openapi_transport_prefix_is_valid(receipts: &[&crate::TransportDispatchReceipt]) -> bool {
    receipts.len() <= MAX_OPENAPI_REVIEW_REQUESTS
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

fn captured_openapi_prefix_reconciles(
    state: &OpenApiExecutionState,
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

fn commit_api_reasoning_inputs(
    knowledge: &KnowledgeBase,
    subject: &EntityId,
) -> Result<(), OpenApiRuntimeInvariantError> {
    let mut rules = RuleEngine::new();
    StandardApiReasoning::new()
        .and_then(|profile| profile.install(knowledge, &mut rules).map(|_| ()))
        .map_err(|_| OpenApiRuntimeInvariantError::Catalog)?;
    rules
        .apply(knowledge, subject)
        .map_err(|_| OpenApiRuntimeInvariantError::Catalog)?;
    Ok(())
}

fn audit(
    source: OpenApiCandidateSource,
    outcome: OpenApiRuntimeOutcome,
    requests: u8,
    leg: Option<&OpenApiLeg>,
    projected: bool,
) -> WebAssessmentOpenApiAudit {
    WebAssessmentOpenApiAudit {
        outcome,
        candidate_source: source,
        request_count: requests,
        active_verification_count: u8::from(requests >= 2),
        version: leg.and_then(|l| l.version),
        semantic_digest: leg.map(|l| l.digest.clone()),
        path_count: leg.map_or(0, |l| l.paths),
        operation_count: leg.map_or(0, |l| l.operations),
        get_operation_count: leg.map_or(0, |l| l.get_operations),
        write_operation_count: leg.map_or(0, |l| l.write_operations),
        path_parameter_count: leg.map_or(0, |l| l.path_parameters),
        query_parameter_count: leg.map_or(0, |l| l.query_parameters),
        explicit_auth_operation_count: leg.map_or(0, |l| l.explicit_auth),
        anonymous_operation_count: leg.map_or(0, |l| l.anonymous),
        url_like_operation_count: leg.map_or(0, |l| l.url_like),
        multipart_operation_count: leg.map_or(0, |l| l.multipart),
        deprecated_operation_count: leg.map_or(0, |l| l.deprecated),
        replay_matched: projected,
        item_projected: projected,
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum OpenApiRuntimeInvariantError {
    #[error("OpenAPI review catalog invariant failed")]
    Catalog,
    #[error("OpenAPI evidence identity failed")]
    Evidence(#[from] termivar_core::ReasoningModelError),
}
pub(super) enum OpenApiRuntimeResult {
    Complete(CommittedOpenApiReview),
    Stopped {
        audit: WebAssessmentOpenApiAudit,
        runtime_limit: Option<RuntimeLimitExceeded>,
    },
}
pub(super) struct CommittedOpenApiReview {
    subject: EntityId,
    privacy: OpenApiResponsePrivacy,
    target_identity: String,
    outcome: OpenApiRuntimeOutcome,
    evidence_ids: Vec<EvidenceId>,
    audit: WebAssessmentOpenApiAudit,
}
impl CommittedOpenApiReview {
    pub(super) const fn audit(&self) -> &WebAssessmentOpenApiAudit {
        &self.audit
    }
}

#[derive(Clone)]
struct OpenApiLeg {
    digest: String,
    version: Option<&'static str>,
    paths: u32,
    operations: u32,
    get_operations: u32,
    write_operations: u32,
    path_parameters: u32,
    query_parameters: u32,
    explicit_auth: u32,
    anonymous: u32,
    url_like: u32,
    multipart: u32,
    deprecated: u32,
    response_bytes: u64,
    evidence_id: Option<EvidenceId>,
    #[cfg(feature = "rest-review")]
    rest_selection: Option<RestOperationSelection>,
    #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
    ssrf_selection: Option<SsrfOastQueryCandidate>,
}
impl OpenApiLeg {
    fn semantically_matches(&self, other: &Self) -> bool {
        self.digest == other.digest
            && self.version == other.version
            && self.paths == other.paths
            && self.operations == other.operations
            && self.get_operations == other.get_operations
            && self.write_operations == other.write_operations
            && self.path_parameters == other.path_parameters
            && self.query_parameters == other.query_parameters
            && self.explicit_auth == other.explicit_auth
            && self.anonymous == other.anonymous
            && self.url_like == other.url_like
            && self.multipart == other.multipart
            && self.deprecated == other.deprecated
            && {
                #[cfg(feature = "rest-review")]
                {
                    self.rest_selection == other.rest_selection
                }
                #[cfg(not(feature = "rest-review"))]
                {
                    true
                }
            }
            && {
                #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
                {
                    self.ssrf_selection == other.ssrf_selection
                }
                #[cfg(not(all(feature = "ssrf-oast-review", feature = "openapi-review")))]
                {
                    true
                }
            }
    }
}
#[derive(Default)]
struct OpenApiExecutionState {
    legs: BTreeMap<DecisionExecutionStage, OpenApiLeg>,
    terminal: Option<(OpenApiRuntimeOutcome, Option<RuntimeLimitExceeded>)>,
}
struct OpenApiDecisionExecutor {
    requests: HttpRequestBroker,
    privacy: OpenApiResponsePrivacy,
    candidate: Mutex<OpenApiCandidate>,
    subject: EntityId,
    knowledge: KnowledgeBase,
    state: Mutex<OpenApiExecutionState>,
    #[cfg(feature = "rest-review")]
    rest_selection: StableRestSelectionSlot,
    #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
    ssrf_selection: Option<StableSsrfOastSelectionSlot>,
}

impl OpenApiDecisionExecutor {
    fn take_state(&self) -> Result<OpenApiExecutionState, OpenApiRuntimeInvariantError> {
        Ok(std::mem::take(
            &mut *self
                .state
                .lock()
                .map_err(|_| OpenApiRuntimeInvariantError::Catalog)?,
        ))
    }
    fn stop(
        &self,
        outcome: OpenApiRuntimeOutcome,
        limit: Option<RuntimeLimitExceeded>,
    ) -> Result<(), DecisionExecutorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("OpenAPI review state is unavailable"))?;
        if state.terminal.replace((outcome, limit)).is_some() {
            return Err(DecisionExecutorError::new(
                "OpenAPI review terminal state is duplicated",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl DecisionActionExecutor for OpenApiDecisionExecutor {
    fn id(&self) -> &str {
        OPENAPI_EXECUTOR_ID
    }
    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        if request.case().action_id() != OPENAPI_REVIEW_ACTION_ID
            || request.case().subject() != &self.subject
            || request.case().payload_strategy().is_some()
            || request.case().applies_hypothesis_transition()
            || !matches!(
                request.stage(),
                DecisionExecutionStage::Passive | DecisionExecutionStage::Active
            )
        {
            return Err(DecisionExecutorError::new(
                "OpenAPI executor route contract failed",
            ));
        }
        let candidate = {
            let mut selected = self
                .candidate
                .lock()
                .map_err(|_| DecisionExecutorError::new("OpenAPI candidate is unavailable"))?;
            if request.stage() == DecisionExecutionStage::Passive {
                let hints = committed_discovery_hints(&self.knowledge, &self.subject);
                *selected = select_openapi_candidate(&selected.url, hints).ok_or_else(|| {
                    DecisionExecutorError::new("OpenAPI candidate selection failed")
                })?;
            }
            selected.clone()
        };
        let probe = HttpProbe::new(candidate.url.clone(), HttpProbeMethod::Get)
            .and_then(|p| p.with_header("accept", OPENAPI_ACCEPT))
            .map_err(|_| DecisionExecutorError::new("OpenAPI request construction failed"))?;
        let response = match self
            .requests
            .collect_for_runtime(
                OPENAPI_REVIEW_ACTION_ID,
                request.stage(),
                request.origin(),
                request.limits(),
                &probe,
            )
            .await
        {
            Ok(r) => r,
            Err(HttpRequestBrokerError::RuntimeLimit(limit)) => {
                self.stop(OpenApiRuntimeOutcome::BudgetExhausted, Some(limit))?;
                return phase_terminal_evidence(request);
            },
            Err(HttpRequestBrokerError::Http(_)) => {
                self.stop(OpenApiRuntimeOutcome::Incomplete, None)?;
                return phase_terminal_evidence(request);
            },
        };
        let status = response.status();
        if response.final_url() != &candidate.url {
            self.stop(OpenApiRuntimeOutcome::RedirectObserved, None)?;
            return transport_evidence(request, &response, None, true, self.privacy);
        }
        let defense_signal = response.openapi_defense_signal();
        let defensive = defense_signal.state().is_challenged();
        let rate_limited = defense_signal.state().is_rate_limited();
        let media = response.normalized_media_type();
        let media_allowed =
            response.has_json_compatible_media_type() || media.as_deref() == Some("text/plain");
        let terminal = if response.body_truncated() {
            Some(OpenApiRuntimeOutcome::Truncated)
        } else if !response.body_complete() {
            Some(OpenApiRuntimeOutcome::Incomplete)
        } else if rate_limited {
            Some(OpenApiRuntimeOutcome::RateLimited)
        } else if defensive {
            Some(OpenApiRuntimeOutcome::DefensiveInterference)
        } else if (300..400).contains(&status) {
            Some(OpenApiRuntimeOutcome::RedirectObserved)
        } else if !(200..300).contains(&status) {
            Some(OpenApiRuntimeOutcome::HttpError)
        } else if !media_allowed {
            Some(OpenApiRuntimeOutcome::UnsupportedMedia)
        } else {
            None
        };
        if let Some(outcome) = terminal {
            self.stop(outcome, None)?;
            return transport_evidence(request, &response, None, true, self.privacy);
        }
        let parsed = parse_openapi_document(response.body(), &candidate.url);
        let leg = match parsed {
            OpenApiParseOutcome::Complete(doc) => {
                #[cfg(feature = "rest-review")]
                let rest_selection = match select_rest_operation(&doc, &candidate.url) {
                    RestOperationSelectionOutcome::Selected(selection) => Some(selection),
                    RestOperationSelectionOutcome::NoEligibleOperation => None,
                };
                #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
                let ssrf_selection = select_openapi_document_query_candidate(&doc, &candidate.url);
                let summary = doc.catalog().summary();
                let get = doc
                    .catalog()
                    .operations()
                    .iter()
                    .filter(|op| op.method() == OpenApiHttpMethod::Get)
                    .count();
                let write = doc
                    .catalog()
                    .operations()
                    .iter()
                    .filter(|op| {
                        matches!(
                            op.method(),
                            OpenApiHttpMethod::Post
                                | OpenApiHttpMethod::Put
                                | OpenApiHttpMethod::Patch
                                | OpenApiHttpMethod::Delete
                        )
                    })
                    .count();
                let deprecated = doc
                    .catalog()
                    .operations()
                    .iter()
                    .filter(|op| op.deprecated())
                    .count();
                OpenApiLeg {
                    digest: doc.semantic_digest().to_owned(),
                    version: doc.version().map(version_name),
                    paths: u32::try_from(doc.path_count()).unwrap_or(u32::MAX),
                    operations: u32::try_from(doc.operation_count()).unwrap_or(u32::MAX),
                    get_operations: u32::try_from(get).unwrap_or(u32::MAX),
                    write_operations: u32::try_from(write).unwrap_or(u32::MAX),
                    path_parameters: u32::try_from(summary.path_parameter_count)
                        .unwrap_or(u32::MAX),
                    query_parameters: u32::try_from(summary.query_parameter_count)
                        .unwrap_or(u32::MAX),
                    explicit_auth: u32::try_from(summary.explicit_auth_operation_count)
                        .unwrap_or(u32::MAX),
                    anonymous: u32::try_from(summary.anonymous_operation_count).unwrap_or(u32::MAX),
                    url_like: u32::try_from(doc.catalog().with_url_like_input().len())
                        .unwrap_or(u32::MAX),
                    multipart: u32::try_from(summary.multipart_operation_count).unwrap_or(u32::MAX),
                    deprecated: u32::try_from(deprecated).unwrap_or(u32::MAX),
                    response_bytes: u64::try_from(response.body().len()).unwrap_or(u64::MAX),
                    evidence_id: None,
                    #[cfg(feature = "rest-review")]
                    rest_selection,
                    #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
                    ssrf_selection,
                }
            },
            OpenApiParseOutcome::Swagger20MetadataOnly => {
                self.stop(OpenApiRuntimeOutcome::Swagger20MetadataOnly, None)?;
                return transport_evidence(request, &response, None, true, self.privacy);
            },
            OpenApiParseOutcome::UnsupportedVersion => {
                self.stop(OpenApiRuntimeOutcome::UnsupportedVersion, None)?;
                return transport_evidence(request, &response, None, true, self.privacy);
            },
            OpenApiParseOutcome::Malformed => {
                self.stop(OpenApiRuntimeOutcome::Malformed, None)?;
                return transport_evidence(request, &response, None, true, self.privacy);
            },
            OpenApiParseOutcome::LimitExceeded => {
                self.stop(OpenApiRuntimeOutcome::LimitExceeded, None)?;
                return transport_evidence(request, &response, None, true, self.privacy);
            },
            OpenApiParseOutcome::TooLarge => {
                self.stop(OpenApiRuntimeOutcome::TooLarge, None)?;
                return transport_evidence(request, &response, None, true, self.privacy);
            },
        };
        #[cfg(feature = "rest-review")]
        let stable_rest_catalog = if request.stage() == DecisionExecutionStage::Active {
            let state = self
                .state
                .lock()
                .map_err(|_| DecisionExecutorError::new("OpenAPI review state is unavailable"))?;
            state
                .legs
                .get(&DecisionExecutionStage::Passive)
                .is_some_and(|candidate_leg| candidate_leg.semantically_matches(&leg))
        } else {
            false
        };
        #[cfg(feature = "rest-review")]
        let stable_rest_selection = stable_rest_catalog
            .then(|| leg.rest_selection.clone())
            .flatten();
        #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
        let stable_ssrf_selection = if request.stage() == DecisionExecutionStage::Active {
            let state = self
                .state
                .lock()
                .map_err(|_| DecisionExecutorError::new("OpenAPI review state is unavailable"))?;
            state
                .legs
                .get(&DecisionExecutionStage::Passive)
                .filter(|candidate_leg| candidate_leg.semantically_matches(&leg))
                .and_then(|_| leg.ssrf_selection.clone())
        } else {
            None
        };
        let mut evidence = transport_evidence(request, &response, Some(&leg), false, self.privacy)?;
        #[cfg(feature = "rest-review")]
        if stable_rest_catalog {
            let ready = make_evidence(
                request,
                crate::web_actions::rest_review_catalog_ready_predicate(),
                EvidenceValue::Boolean(true),
                "rest-catalog-ready",
            )?;
            let first_defense = evidence
                .iter()
                .position(|item| {
                    item.predicate().namespace()
                        == super::assessment_defense::ASSESSMENT_DEFENSE_NAMESPACE
                })
                .unwrap_or(evidence.len());
            evidence.insert(first_defense, ready);
        }
        let classification = evidence
            .iter()
            .find(|e| {
                e.predicate().namespace() == OPENAPI_EVIDENCE_NAMESPACE
                    && e.predicate().name() == "document"
            })
            .ok_or_else(|| DecisionExecutorError::new("OpenAPI evidence is missing"))?
            .id()
            .clone();
        let mut stored = leg;
        stored.evidence_id = Some(classification);
        let replaced = self
            .state
            .lock()
            .map_err(|_| DecisionExecutorError::new("OpenAPI review state is unavailable"))?
            .legs
            .insert(request.stage(), stored);
        if replaced.is_some() {
            return Err(DecisionExecutorError::new(
                "OpenAPI review leg is duplicated",
            ));
        }
        #[cfg(feature = "rest-review")]
        if let Some(selection) = stable_rest_selection {
            self.rest_selection
                .commit(selection)
                .map_err(|_| DecisionExecutorError::new("REST selection handoff failed"))?;
        }
        #[cfg(all(feature = "ssrf-oast-review", feature = "openapi-review"))]
        if let (Some(slot), Some(selection)) = (&self.ssrf_selection, stable_ssrf_selection) {
            slot.commit_openapi(SsrfOastCandidateSelection::Selected(Box::new(selection)))
                .map_err(|_| DecisionExecutorError::new("SSRF OAST selection handoff failed"))?;
        }
        Ok(evidence)
    }
}

fn version_name(version: OpenApiVersion) -> &'static str {
    match version {
        OpenApiVersion::OpenApi30 => "3.0",
        OpenApiVersion::OpenApi31 => "3.1",
    }
}
fn marker(request: &DecisionExecutionRequest) -> Result<Evidence, DecisionExecutorError> {
    make_evidence(
        request,
        crate::web_actions::native_web_review_response_marker_predicate(),
        EvidenceValue::Boolean(true),
        "complete",
    )
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
            crate::web_actions::openapi_review_phase_terminal_predicate(),
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
        EvidenceKind::Custom("openapi-review".into()),
        predicate,
        value,
        EvidenceSource::new(OPENAPI_EXECUTOR_ID, method)
            .and_then(|s| s.with_correlation_id(request.case().id()))
            .map_err(|_| DecisionExecutorError::new("OpenAPI evidence source failed"))?,
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
        EvidenceSource::new(OPENAPI_EXECUTOR_ID, method)
            .and_then(|s| s.with_correlation_id(request.case().id()))
            .map_err(|_| DecisionExecutorError::new("OpenAPI evidence source failed"))?,
        ConfidenceScore::MAX,
    ))
}

fn transport_evidence(
    request: &DecisionExecutionRequest,
    response: &crate::http_evidence::CollectedHttpResponse,
    leg: Option<&OpenApiLeg>,
    terminal: bool,
    privacy: OpenApiResponsePrivacy,
) -> Result<Vec<Evidence>, DecisionExecutorError> {
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
            crate::web_actions::openapi_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(terminal),
            "phase-terminal",
        )?,
    ];
    if !privacy.is_value_free() {
        // Preserve historical evidence ordering and values when S04 is absent.
        evidence.insert(
            6,
            make_typed_evidence(
                request,
                EvidenceKind::Content,
                HttpEvidencePredicate::RESPONSE_BODY_SHA256.into_knowledge(),
                EvidenceValue::Text(format!("{:x}", Sha256::digest(response.body()))),
                "response-body-sha256",
            )?,
        );
    }
    if let Some(media) = response.normalized_media_type() {
        evidence.push(make_typed_evidence(
            request,
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge(),
            EvidenceValue::Text(media.clone()),
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
            super::secret_exposure::project_openapi_body_privacy_lineage(
                request,
                &evidence,
                OPENAPI_EXECUTOR_ID,
                ConfidenceScore::MAX,
            )
            .map_err(|_| DecisionExecutorError::new("OpenAPI privacy lineage failed"))?,
        );
        #[cfg(not(feature = "secret-exposure-review"))]
        return Err(DecisionExecutorError::new(
            "OpenAPI privacy selection is unavailable",
        ));
    }
    // Defense consumes only the fixed response facts plus exactly one body
    // identity. Optional media and semantic facts are not additional parents.
    let base_predicates = [
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
            let lineage = false;
            #[cfg(feature = "secret-exposure-review")]
            let lineage = lineage
                || (item.predicate().namespace()
                    == super::secret_exposure::SECRET_EXPOSURE_NAMESPACE
                    && item.predicate().name()
                        == super::secret_exposure::ACTIVE_REVIEW_BODY_LINEAGE);
            base_predicates.contains(item.predicate()) || lineage
        })
        .map(|item| item.id().clone())
        .collect();
    if let Some(leg) = leg {
        let mut summary = vec![
            format!("version={}", leg.version.unwrap_or("unknown")),
            format!("paths={}", leg.paths),
            format!("operations={}", leg.operations),
        ];
        if !privacy.is_value_free() {
            summary.insert(0, format!("digest={}", leg.digest));
        }
        let document = make_evidence(
            request,
            KnowledgePredicate::new(OPENAPI_EVIDENCE_NAMESPACE, "document")
                .map_err(|_| DecisionExecutorError::new("OpenAPI predicate failed"))?,
            EvidenceValue::TextList(summary),
            "document",
        )?;
        let document = if privacy.is_value_free() {
            document.derived_from(
                EvidenceDerivation::new(
                    evidence.iter().map(|item| item.id().clone()),
                    DerivationAlgorithm::new(OPENAPI_CLASSIFICATION_ALGORITHM, 1).map_err(
                        |_| DecisionExecutorError::new("OpenAPI classification algorithm failed"),
                    )?,
                )
                .map_err(|_| DecisionExecutorError::new("OpenAPI classification lineage failed"))?,
            )
        } else {
            document
        };
        evidence.push(document);
    }
    if !terminal {
        evidence.push(marker(request)?);
    }
    evidence.extend(
        project_assessment_defense_signal(
            &signal,
            AssessmentDefenseProjectionContext {
                subject: request.case().subject(),
                case_id: request.case().id(),
                executor_id: OPENAPI_EXECUTOR_ID,
                reliability: ConfidenceScore::MAX,
                parents: defense_parents,
            },
        )
        .map_err(|_| DecisionExecutorError::new("OpenAPI defense projection failed"))?,
    );
    if terminal { /* terminal response intentionally omits completion marker */ }
    Ok(evidence)
}

pub(super) fn project_openapi_item(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    review: &CommittedOpenApiReview,
) -> Result<(), AssessmentItemProjectionError> {
    for id in &review.evidence_ids {
        context.register_evidence(knowledge, id)?;
    }
    if review.outcome == OpenApiRuntimeOutcome::DocumentObserved {
        let target = if review.privacy.is_value_free() {
            AssessmentItemTarget::Subject
        } else {
            AssessmentItemTarget::openapi_document(review.target_identity.clone())?
        };
        context.project_observation(
            &OPENAPI_CAPABILITY,
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
    #[cfg(feature = "secret-exposure-review")]
    mod privacy_tests {
        //! Independent synthetic receipt oracles. No HTTP response or wire trace is
        //! claimed: the ordinary runner commits literal batches, and the accounting
        //! broker supplies a test-owned lease for the received-response cases.

        use super::*;
        use crate::{
            runtime_budget::RequestAccountingBroker, DecisionEvidenceReceipt, DecisionLoopCommand,
            DecisionRunnerAdapter, DecisionStopReason, KnowledgeWrite, RuntimeBudget, RuntimeUsage,
            StandardWebDecisionRunReport, VerificationCase,
        };

        const CASE: &str = "case:synthetic-openapi-privacy";
        const RESOURCE: &str = "https://fixture.invalid/openapi.json";

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
            EntityId::new("endpoint:https://fixture.invalid/").unwrap()
        }

        fn candidate() -> OpenApiCandidate {
            OpenApiCandidate {
                url: Url::parse(RESOURCE).unwrap(),
                source: OpenApiCandidateSource::ConventionalOpenApiJson,
                identity: "synthetic-url-identity".to_owned(),
            }
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
                EvidenceSource::new("http.openapi-review", method)
                    .unwrap()
                    .with_correlation_id(CASE)
                    .unwrap(),
                ConfidenceScore::MAX,
            )
        }

        fn custom(name: &str, value: EvidenceValue, method: &str) -> Evidence {
            fact(
                EvidenceKind::Custom("openapi-review".to_owned()),
                KnowledgePredicate::new("web.openapi-review.transport", name).unwrap(),
                value,
                method,
            )
        }

        fn terminal_batch() -> Vec<Evidence> {
            vec![
                fact(
                    EvidenceKind::Custom("openapi-review".to_owned()),
                    HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED.into_knowledge(),
                    EvidenceValue::Unsigned(0),
                    "response-body-size",
                ),
                fact(
                    EvidenceKind::Custom("openapi-review".to_owned()),
                    crate::web_actions::openapi_review_phase_terminal_predicate(),
                    EvidenceValue::Boolean(true),
                    "phase-terminal",
                ),
            ]
        }

        fn received_batch(parsed: bool) -> Vec<Evidence> {
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
                    EvidenceValue::Unsigned(7),
                    "response-body-size",
                ),
                (
                    HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
                    EvidenceKind::Content,
                    EvidenceValue::Boolean(false),
                    "response-body-truncation",
                ),
            ];
            let mut batch = rows
                .into_iter()
                .map(|(p, k, v, m)| fact(k, p.into_knowledge(), v, m))
                .collect::<Vec<_>>();
            let privacy_parents = batch
                .iter()
                .map(|item| item.id().clone())
                .collect::<Vec<_>>();
            for (predicate, method) in [
                (
                    HttpEvidencePredicate::RATE_LIMIT_DETECTED,
                    "rate-limit-status",
                ),
                (
                    HttpEvidencePredicate::RATE_LIMIT_ADVERTISED,
                    "rate-limit-headers",
                ),
            ] {
                batch.push(fact(
                    EvidenceKind::RateLimit,
                    predicate.into_knowledge(),
                    EvidenceValue::Boolean(false),
                    method,
                ));
            }
            batch.push(fact(
                EvidenceKind::Custom("openapi-review".to_owned()),
                crate::web_actions::openapi_review_phase_terminal_predicate(),
                EvidenceValue::Boolean(!parsed),
                "phase-terminal",
            ));
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
                        privacy_parents,
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
                batch.push(
                    custom(
                        "document",
                        EvidenceValue::TextList(vec![
                            "version=3.1".to_owned(),
                            "paths=1".to_owned(),
                            "operations=1".to_owned(),
                        ]),
                        "document",
                    )
                    .derived_from(
                        EvidenceDerivation::new(
                            parents,
                            DerivationAlgorithm::new(
                                "web.openapi-review.value-free-classification",
                                1,
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                );
                batch.push(fact(
                    EvidenceKind::Custom("openapi-review".to_owned()),
                    crate::web_actions::native_web_review_response_marker_predicate(),
                    EvidenceValue::Boolean(true),
                    "complete",
                ));
            }
            batch
        }

        async fn committed_route(
            batch: Vec<Evidence>,
            action: &str,
            executor: &'static str,
            stage: DecisionExecutionStage,
            transitioned: bool,
        ) -> (KnowledgeBase, DecisionEvidenceReceipt) {
            // Wrong-executor tests still pass the runner's own provenance check. The
            // receipt is genuinely committed for that other executor, then rejected
            // by the narrower OpenAPI consumer rather than failing in test setup.
            let batch = if executor == "http.openapi-review" {
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
            let case =
                VerificationCase::new(CASE, subject(), action, "hypothesis:synthetic-openapi")
                    .unwrap();
            let case = if transitioned {
                case
            } else {
                case.without_hypothesis_transition()
            };
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
            let knowledge = KnowledgeBase::new();
            let receipt = DecisionRunnerAdapter::new(registry)
                .execute_command(&command, &knowledge)
                .await
                .unwrap();
            (knowledge, receipt)
        }

        async fn committed(batch: Vec<Evidence>) -> (KnowledgeBase, DecisionEvidenceReceipt) {
            committed_route(
                batch,
                "web.review.openapi.document-replay@1",
                "http.openapi-review",
                DecisionExecutionStage::Passive,
                false,
            )
            .await
        }

        fn report(
            receipt: Option<DecisionEvidenceReceipt>,
            received: bool,
        ) -> StandardWebDecisionRunReport {
            let accounting = RequestAccountingBroker::new(RuntimeBudget::default());
            if received {
                let mut lease = accounting
                    .try_begin(
                        "web.review.openapi.document-replay@1",
                        DecisionExecutionStage::Passive,
                        Some(DecisionActionOrigin::Planned),
                    )
                    .unwrap();
                assert_eq!(lease.observe_response_bytes(7), 7);
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

        fn terminal_state() -> OpenApiExecutionState {
            OpenApiExecutionState {
                legs: BTreeMap::new(),
                terminal: Some((OpenApiRuntimeOutcome::Incomplete, None)),
            }
        }

        fn parsed_state(batch: &[Evidence]) -> OpenApiExecutionState {
            let document = batch
                .iter()
                .find(|item| {
                    item.predicate().namespace() == "web.openapi-review.transport"
                        && item.predicate().name() == "document"
                })
                .unwrap();
            let leg = OpenApiLeg {
                digest: "private-synthetic-catalogue-not-exported".to_owned(),
                version: Some("3.1"),
                paths: 1,
                operations: 1,
                get_operations: 1,
                write_operations: 0,
                path_parameters: 0,
                query_parameters: 0,
                explicit_auth: 0,
                anonymous: 1,
                url_like: 0,
                multipart: 0,
                deprecated: 0,
                response_bytes: 7,
                evidence_id: Some(document.id().clone()),
                #[cfg(feature = "rest-review")]
                rest_selection: None,
                #[cfg(feature = "ssrf-oast-review")]
                ssrf_selection: None,
            };
            OpenApiExecutionState {
                legs: BTreeMap::from([(DecisionExecutionStage::Passive, leg)]),
                terminal: None,
            }
        }

        fn validate(
            receipt: Option<DecisionEvidenceReceipt>,
            knowledge: &KnowledgeBase,
            state: &OpenApiExecutionState,
            received: bool,
        ) -> Result<bool, OpenApiRuntimeInvariantError> {
            validate_value_free_openapi_commits(
                &report(receipt, received),
                knowledge,
                &subject(),
                &candidate(),
                state,
            )
        }

        fn mutation(
            template: &DecisionEvidenceReceipt,
            batch: Vec<Evidence>,
        ) -> (KnowledgeBase, DecisionEvidenceReceipt) {
            let knowledge = KnowledgeBase::new();
            let writes = knowledge.insert_evidence_batch(batch.clone()).unwrap();
            let snapshot = knowledge.snapshot_for_subject(template.case().subject());
            (
                knowledge,
                template.with_test_committed_batch(batch, writes, snapshot),
            )
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

        #[tokio::test]
        async fn openapi_privacy_commit_requires_receipts_not_staged_terminal_or_leg_state() {
            let knowledge = KnowledgeBase::new();
            assert!(!validate(None, &knowledge, &terminal_state(), false).unwrap());
            let batch = received_batch(true);
            assert!(!validate(None, &knowledge, &parsed_state(&batch), true).unwrap());
            let (knowledge, receipt) = committed(terminal_batch()).await;
            assert!(validate(Some(receipt), &knowledge, &terminal_state(), false).unwrap());
            let (knowledge, receipt) = committed(received_batch(false)).await;
            assert!(validate(Some(receipt), &knowledge, &terminal_state(), true).unwrap());
            let state = parsed_state(&batch);
            let (knowledge, receipt) = committed(batch).await;
            assert!(validate(Some(receipt), &knowledge, &state, true).unwrap());
        }

        #[tokio::test]
        async fn openapi_privacy_commit_rejects_lost_knowledge_duplicate_ids_and_write_mismatch() {
            let batch = received_batch(true);
            let state = parsed_state(&batch);
            let (knowledge, receipt) = committed(batch.clone()).await;
            assert!(validate(Some(receipt.clone()), &KnowledgeBase::new(), &state, true).is_err());
            let mut duplicate = batch;
            duplicate.push(duplicate[0].clone());
            let duplicate_receipt = receipt.with_test_committed_batch(
                duplicate.clone(),
                vec![KnowledgeWrite::Unchanged; duplicate.len()],
                knowledge.snapshot_for_subject(&subject()),
            );
            assert!(validate(Some(duplicate_receipt), &knowledge, &state, true).is_err());
            let bad = receipt.with_test_committed_batch(
                receipt.evidence().to_vec(),
                Vec::new(),
                knowledge.snapshot_for_subject(&subject()),
            );
            assert!(validate(Some(bad), &knowledge, &state, true).is_err());
        }

        #[tokio::test]
        async fn openapi_privacy_commit_rejects_wrong_route_executor_stage_and_subject() {
            for (action, executor, stage) in [
                (
                    "synthetic.other-action",
                    "http.openapi-review",
                    DecisionExecutionStage::Passive,
                ),
                (
                    "web.review.openapi.document-replay@1",
                    "synthetic.other-executor",
                    DecisionExecutionStage::Passive,
                ),
                (
                    "web.review.openapi.document-replay@1",
                    "http.openapi-review",
                    DecisionExecutionStage::Active,
                ),
            ] {
                let (knowledge, receipt) =
                    committed_route(terminal_batch(), action, executor, stage, false).await;
                assert!(validate(Some(receipt), &knowledge, &terminal_state(), false).is_err());
            }
            let (knowledge, receipt) = committed(terminal_batch()).await;
            let different = EntityId::new("endpoint:https://sibling.invalid/").unwrap();
            assert!(validate_value_free_openapi_commits(
                &report(Some(receipt), false),
                &knowledge,
                &different,
                &candidate(),
                &terminal_state(),
            )
            .is_err());
        }

        #[tokio::test]
        async fn openapi_privacy_commit_rejects_additional_public_identity_facts() {
            let batch = received_batch(true);
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
                    EvidenceValue::Text("unkeyed-body-derived-identity".to_owned()),
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
        }

        #[tokio::test]
        async fn openapi_privacy_commit_rejects_classification_lineage_and_terminal_mutations() {
            let batch = received_batch(true);
            let state = parsed_state(&batch);
            let (_, template) = committed(batch.clone()).await;
            let document_index = batch
                .iter()
                .position(|item| item.source().method() == "document")
                .unwrap();
            let lineage_index = batch
                .iter()
                .position(|item| item.predicate().name() == "active_review_body_lineage")
                .unwrap();
            for index in [document_index, lineage_index] {
                let mut changed = batch.clone();
                let original = &changed[index];
                let parents = original.origin().derivation().unwrap().parents()[1..].to_vec();
                changed[index] = replace(
                    original,
                    original.kind().clone(),
                    original.value().clone(),
                    original.source().clone(),
                    Some(parents),
                );
                let (knowledge, receipt) = mutation(&template, changed);
                assert!(validate(Some(receipt), &knowledge, &state, true).is_err());
            }
            let mut changed = batch.clone();
            changed[document_index] = replace(
                &batch[document_index],
                batch[document_index].kind().clone(),
                EvidenceValue::TextList(vec![
                    "version=3.1".to_owned(),
                    "paths=2".to_owned(),
                    "operations=1".to_owned(),
                ]),
                batch[document_index].source().clone(),
                None,
            );
            let (knowledge, receipt) = mutation(&template, changed);
            assert!(validate(Some(receipt), &knowledge, &state, true).is_err());

            let terminal = terminal_batch();
            let (_, template) = committed(terminal.clone()).await;
            for (index, value, kind, method) in [
                (
                    0,
                    EvidenceValue::Unsigned(1),
                    EvidenceKind::Custom("openapi-review".to_owned()),
                    "response-body-size",
                ),
                (
                    1,
                    EvidenceValue::Boolean(false),
                    EvidenceKind::Custom("openapi-review".to_owned()),
                    "phase-terminal",
                ),
                (
                    0,
                    EvidenceValue::Unsigned(0),
                    EvidenceKind::Content,
                    "response-body-size",
                ),
                (
                    1,
                    EvidenceValue::Boolean(true),
                    EvidenceKind::Custom("openapi-review".to_owned()),
                    "wrong-method",
                ),
            ] {
                let mut changed = terminal.clone();
                let source = EvidenceSource::new("http.openapi-review", method)
                    .unwrap()
                    .with_correlation_id(CASE)
                    .unwrap();
                changed[index] = replace(&terminal[index], kind, value, source, None);
                let (knowledge, receipt) = mutation(&template, changed);
                assert!(validate(Some(receipt), &knowledge, &terminal_state(), false).is_err());
            }
        }
    }
    use super::*;
    use termivar_core::{ApiKnowledgePredicate, ApiResponseFormat};

    #[test]
    fn selector_prefers_discovered_json_and_never_fans_out() {
        let root = Url::parse("https://example.test/base").unwrap();
        let selected = select_openapi_candidate(
            &root,
            [
                Url::parse("https://example.test/swagger.json").unwrap(),
                Url::parse("https://example.test/openapi.json").unwrap(),
                Url::parse("https://evil.invalid/openapi.json").unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            selected.source,
            OpenApiCandidateSource::DiscoveredOpenApiJson
        );
        assert_eq!(selected.url.path(), "/openapi.json");
    }
    #[test]
    fn selector_uses_one_fixed_fallback() {
        let root = Url::parse("https://example.test/nested").unwrap();
        let selected = select_openapi_candidate(&root, []).unwrap();
        assert_eq!(selected.url.as_str(), "https://example.test/openapi.json");
        assert_eq!(
            selected.source,
            OpenApiCandidateSource::ConventionalOpenApiJson
        );
    }

    #[test]
    fn selector_rejects_candidates_outside_the_path_and_url_bounds() {
        let root = Url::parse("https://example.test/").unwrap();
        let overlong_path = format!(
            "https://example.test/{}/openapi.json",
            "a".repeat(MAX_OPENAPI_CANDIDATE_PATH_BYTES)
        );
        let selected =
            select_openapi_candidate(&root, [Url::parse(&overlong_path).unwrap()]).unwrap();
        assert_eq!(
            selected.source,
            OpenApiCandidateSource::ConventionalOpenApiJson
        );
        assert_eq!(selected.url.path(), "/openapi.json");
        assert!(selected.url.as_str().len() <= MAX_OPENAPI_CANDIDATE_URL_BYTES);
        assert!(selected.url.path().len() <= MAX_OPENAPI_CANDIDATE_PATH_BYTES);
    }

    #[test]
    fn selector_rejects_cross_origin_credentials_queries_and_fragments() {
        let root = Url::parse("https://example.test/root").unwrap();
        for hint in [
            "https://elsewhere.invalid/openapi.json",
            "https://user:secret@example.test/openapi.json",
            "https://example.test/openapi.json?variant=1",
            "https://example.test/openapi.json#fragment",
            "ftp://example.test/openapi.json",
        ] {
            let selected = select_openapi_candidate(&root, [Url::parse(hint).unwrap()]).unwrap();
            assert_eq!(
                selected.source,
                OpenApiCandidateSource::ConventionalOpenApiJson
            );
            assert_eq!(selected.url.as_str(), "https://example.test/openapi.json");
        }
    }

    #[test]
    fn committed_json_evidence_feeds_the_existing_transport_neutral_reasoner() {
        for (json_compatible, expected) in [(true, true), (false, false)] {
            let knowledge = KnowledgeBase::new();
            let subject = EntityId::new(format!(
                "openapi-reasoning-fixture:{}",
                u8::from(json_compatible)
            ))
            .unwrap();
            let source = EvidenceSource::new(OPENAPI_EXECUTOR_ID, "response-json")
                .unwrap()
                .with_correlation_id("case:openapi-reasoning-fixture")
                .unwrap();
            knowledge
                .insert_evidence(Evidence::new(
                    subject.clone(),
                    EvidenceKind::Http,
                    HttpEvidencePredicate::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE.into_knowledge(),
                    EvidenceValue::Boolean(json_compatible),
                    source,
                    ConfidenceScore::MAX,
                ))
                .unwrap();

            commit_api_reasoning_inputs(&knowledge, &subject).unwrap();

            let snapshot = knowledge.snapshot_for_subject(&subject);
            let predicate = ApiKnowledgePredicate::RESPONSE_FORMAT.into_knowledge();
            let json = EvidenceValue::from(ApiResponseFormat::Json);
            assert_eq!(
                snapshot.hypotheses().iter().any(|hypothesis| {
                    hypothesis.predicate() == &predicate && hypothesis.value() == &json
                }),
                expected
            );
        }
    }
}
