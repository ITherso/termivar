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
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    HttpEvidencePredicate, KnowledgePredicate,
};
use url::Url;

#[cfg(feature = "rest-review")]
use super::rest_runtime::StableRestSelectionSlot;
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
use crate::{
    http_evidence::{HttpRequestBroker, HttpRequestBrokerError},
    openapi_review::{
        parse_openapi_document, OpenApiHttpMethod, OpenApiParseOutcome, OpenApiVersion,
    },
    DecisionActionExecutor, DecisionActionOrigin, DecisionExecutionRequest, DecisionExecutionStage,
    DecisionExecutorError, DecisionExecutorRegistry, HttpProbe, HttpProbeMethod, KnowledgeBase,
    RuleEngine, RuntimeLimitExceeded, StandardApiReasoning, TransportDispatchAudit,
    TransportDispatchOutcome, HTTP_EVIDENCE_EXECUTOR_ID,
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
}
impl OpenApiReviewConfig {
    pub(super) fn new(candidate: OpenApiCandidate) -> Self {
        Self { candidate }
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
        let candidate = config.candidate;
        let executor = Arc::new(OpenApiDecisionExecutor {
            requests,
            candidate: Mutex::new(candidate),
            subject: subject.clone(),
            knowledge,
            state: Mutex::new(OpenApiExecutionState::default()),
            #[cfg(feature = "rest-review")]
            rest_selection: StableRestSelectionSlot::new(),
        });
        Self { executor, subject }
    }
    #[cfg(feature = "rest-review")]
    pub(super) fn rest_selection_slot(&self) -> StableRestSelectionSlot {
        self.executor.rest_selection.clone()
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
        transport: &TransportDispatchAudit,
        forced_outcome: Option<OpenApiRuntimeOutcome>,
        forced_runtime_limit: Option<RuntimeLimitExceeded>,
    ) -> Result<OpenApiRuntimeResult, OpenApiRuntimeInvariantError> {
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
        if !captured_openapi_prefix_reconciles(&state, &receipts) {
            return Err(OpenApiRuntimeInvariantError::Catalog);
        }
        let request_count = u8::try_from(receipts.len()).unwrap_or(u8::MAX);
        let state_terminal = state.terminal;
        let terminal =
            forced_outcome.or_else(|| state_terminal.as_ref().map(|(outcome, _)| *outcome));
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
        if receipts.len() != MAX_OPENAPI_REVIEW_REQUESTS
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
        let audit = audit(
            selected_candidate.source,
            outcome,
            request_count,
            Some(candidate),
            projected,
        );
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
        let target_identity =
            observed_document_identity(&selected_candidate.identity, &candidate.digest);
        Ok(OpenApiRuntimeResult::Complete(CommittedOpenApiReview {
            subject: self.subject,
            target_identity,
            outcome,
            evidence_ids,
            audit,
        }))
    }
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
    }
}
#[derive(Default)]
struct OpenApiExecutionState {
    legs: BTreeMap<DecisionExecutionStage, OpenApiLeg>,
    terminal: Option<(OpenApiRuntimeOutcome, Option<RuntimeLimitExceeded>)>,
}
struct OpenApiDecisionExecutor {
    requests: HttpRequestBroker,
    candidate: Mutex<OpenApiCandidate>,
    subject: EntityId,
    knowledge: KnowledgeBase,
    state: Mutex<OpenApiExecutionState>,
    #[cfg(feature = "rest-review")]
    rest_selection: StableRestSelectionSlot,
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
            return transport_evidence(request, &response, None, true);
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
            return transport_evidence(request, &response, None, true);
        }
        let parsed = parse_openapi_document(response.body(), &candidate.url);
        let leg = match parsed {
            OpenApiParseOutcome::Complete(doc) => {
                #[cfg(feature = "rest-review")]
                let rest_selection = match select_rest_operation(&doc, &candidate.url) {
                    RestOperationSelectionOutcome::Selected(selection) => Some(selection),
                    RestOperationSelectionOutcome::NoEligibleOperation => None,
                };
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
                }
            },
            OpenApiParseOutcome::Swagger20MetadataOnly => {
                self.stop(OpenApiRuntimeOutcome::Swagger20MetadataOnly, None)?;
                return transport_evidence(request, &response, None, true);
            },
            OpenApiParseOutcome::UnsupportedVersion => {
                self.stop(OpenApiRuntimeOutcome::UnsupportedVersion, None)?;
                return transport_evidence(request, &response, None, true);
            },
            OpenApiParseOutcome::Malformed => {
                self.stop(OpenApiRuntimeOutcome::Malformed, None)?;
                return transport_evidence(request, &response, None, true);
            },
            OpenApiParseOutcome::LimitExceeded => {
                self.stop(OpenApiRuntimeOutcome::LimitExceeded, None)?;
                return transport_evidence(request, &response, None, true);
            },
            OpenApiParseOutcome::TooLarge => {
                self.stop(OpenApiRuntimeOutcome::TooLarge, None)?;
                return transport_evidence(request, &response, None, true);
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
        let mut evidence = transport_evidence(request, &response, Some(&leg), false)?;
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
) -> Result<Vec<Evidence>, DecisionExecutorError> {
    let digest = format!("{:x}", Sha256::digest(response.body()));
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
            EvidenceValue::Text(digest),
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
            crate::web_actions::openapi_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(terminal),
            "phase-terminal",
        )?,
    ];
    let defense_parents = evidence[..9].iter().map(|item| item.id().clone()).collect();
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
    if let Some(leg) = leg {
        evidence.push(make_evidence(
            request,
            KnowledgePredicate::new(OPENAPI_EVIDENCE_NAMESPACE, "document")
                .map_err(|_| DecisionExecutorError::new("OpenAPI predicate failed"))?,
            EvidenceValue::TextList(vec![
                format!("digest={}", leg.digest),
                format!("version={}", leg.version.unwrap_or("unknown")),
                format!("paths={}", leg.paths),
                format!("operations={}", leg.operations),
            ]),
            "document",
        )?);
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
        let target = AssessmentItemTarget::openapi_document(review.target_identity.clone())?;
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
