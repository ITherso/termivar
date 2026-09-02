//! Explicitly enabled GraphQL transport orchestration for one exact origin.
//!
//! The transport-neutral parser, catalog, and operation builder live in
//! `crate::graphql_review`. This module alone joins those contracts to the
//! assessment's shared broker, knowledge authority, and item projection.

use std::{
    collections::BTreeSet,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use url::Url;
use venom_core::{
    ConfidenceScore, DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId,
    EvidenceKind, EvidenceSource, EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
};

use super::{
    assessment_defense::AssessmentDefenseController,
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext, StableAssessmentScopeId, StableAssessmentSubjectId,
    },
    await_execution, RuntimeExecution, SharedWebRuntimeAuthority,
};
use crate::{
    defense::DefenseInteractionClass,
    graphql_review::{
        bound_runtime_graphql_endpoint_hints, classify_graphql_transport_outcome,
        select_graphql_endpoint, GraphqlAssessmentKind, GraphqlEndpoint, GraphqlEndpointHint,
        GraphqlEndpointSource, GraphqlErrorCategory, GraphqlFallbackPolicy,
        GraphqlMaximumAuthority, GraphqlMaximumDisposition, GraphqlOperation, GraphqlOperationRole,
        GraphqlOperationSet, GraphqlResponseClassification, GraphqlResponseClassifier,
        GraphqlResponseInput, GraphqlResponseKind, GraphqlReviewCatalog,
        GraphqlReviewContractError, GraphqlReviewOutcome, GRAPHQL_REVIEW_ALGORITHM_VERSION,
        MAX_GRAPHQL_ACTIVE_VERIFICATIONS, MAX_GRAPHQL_CHILD_REQUESTS,
        MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES, MAX_GRAPHQL_RESPONSE_BYTES,
        MAX_GRAPHQL_SELECTED_ENDPOINTS,
    },
    http_evidence::{
        project_graphql_transport_response, CollectedHttpResponse, HttpRequestBroker,
        HttpRequestBrokerError,
    },
    DecisionActionExecutor, DecisionActionOrigin, DecisionEvidenceReceipt, DecisionExecutionLimits,
    DecisionExecutionRequest, DecisionExecutionStage, DecisionExecutorError,
    DecisionExecutorRegistry, DecisionLoopCommand, DecisionRunnerAdapter, DecisionRunnerError,
    KnowledgeBase, KnowledgeBaseError, RuleEngine, RuleEngineError, RuntimeBudgetDimension,
    StandardApiReasoning, StandardApiReasoningError, VerificationCase,
};

pub(super) const GRAPHQL_CONTROL_ACTION_ID: &str = "web.review.graphql.control";
pub(super) const GRAPHQL_CANDIDATE_ACTION_ID: &str = "web.review.graphql.introspection";
pub(super) const GRAPHQL_REPLAY_ACTION_ID: &str = "web.review.graphql.introspection-replay";

const GRAPHQL_RESPONSE_DIGEST_DOMAIN: &[u8] = b"graphql-review-response/v1";
const GRAPHQL_EXECUTOR_ID: &str = "http.graphql-review";
const GRAPHQL_TRANSPORT_EVIDENCE_NAMESPACE: &str = "web.graphql.transport";
const GRAPHQL_TRANSPORT_CLASSIFICATION_ALGORITHM: &str = "web.graphql.transport-classification";
const GRAPHQL_HYPOTHESIS_ID: &str = "hypothesis:web.graphql.surface";
const GRAPHQL_CONTROL_CASE_ID: &str = "case:web.graphql.control";
const GRAPHQL_CANDIDATE_CASE_ID: &str = "case:web.graphql.introspection";
const GRAPHQL_REPLAY_CASE_ID: &str = "case:web.graphql.introspection-replay";

const GRAPHQL_SURFACE_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "graphql.surface-observed@1",
        "GraphQL response surface observed",
        "API surface",
        "A bounded anonymous control operation produced a correlated GraphQL response envelope.",
        900_000,
        "graphql.surface-review@1",
        "Confirm that the anonymous GraphQL endpoint exposure matches deployment policy.",
    );

const GRAPHQL_INTROSPECTION_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "graphql.anonymous-root-introspection@1",
        "Anonymous GraphQL schema-root introspection available",
        "API surface",
        "Two distinct bounded anonymous operations reproduced schema-root introspection metadata.",
        950_000,
        "graphql.introspection-policy@1",
        "Confirm that anonymous schema-root introspection is intended for this deployment.",
    );

/// A deterministic reason the optional child could not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GraphqlRuntimeStop {
    Cancelled,
    RuntimeLimit(RuntimeBudgetDimension),
    TransportIncomplete,
}

/// Internal composition errors indicate code/knowledge invariants, not target behavior.
#[derive(Debug, thiserror::Error)]
pub(super) enum GraphqlRuntimeInvariantError {
    #[error("GraphQL review contract composition failed")]
    Contract(#[from] GraphqlReviewContractError),
    #[error("GraphQL review reasoning composition failed")]
    ApiReasoning(#[from] StandardApiReasoningError),
    #[error("GraphQL review rule evaluation failed")]
    RuleEngine(#[from] RuleEngineError),
    #[error("GraphQL review evidence construction failed")]
    Reasoning(#[from] venom_core::ReasoningModelError),
    #[error("GraphQL review evidence commit failed")]
    Knowledge(#[from] KnowledgeBaseError),
    #[error("GraphQL review execution catalog violated its closed V1 contract")]
    Catalog,
}

/// One redaction-safe execution receipt. Raw operations and responses are never retained.
#[derive(Clone, Eq, PartialEq)]
struct GraphqlLegReceipt {
    role: GraphqlOperationRole,
    request_digest: [u8; 32],
    response_digest: [u8; 32],
    response_bytes: usize,
    exact_graphql_media: bool,
    classification: GraphqlResponseKind,
    introspection_roots: Option<(bool, bool, bool)>,
    replay_matches_candidate_roots: Option<bool>,
    classification_evidence_id: Option<EvidenceId>,
    request_url_evidence_id: Option<EvidenceId>,
}

impl fmt::Debug for GraphqlLegReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphqlLegReceipt")
            .field("role", &self.role)
            .field("request_digest", &"<digest>")
            .field("response_digest", &"<digest>")
            .field("response_bytes", &self.response_bytes)
            .field("exact_graphql_media", &self.exact_graphql_media)
            .field("classification", &self.classification)
            .field("introspection_roots", &self.introspection_roots)
            .field(
                "replay_matches_candidate_roots",
                &self.replay_matches_candidate_roots,
            )
            .field(
                "has_classification_evidence",
                &self.classification_evidence_id.is_some(),
            )
            .field(
                "has_request_url_evidence",
                &self.request_url_evidence_id.is_some(),
            )
            .finish()
    }
}

/// Committed review truth consumed by the common AssessmentItem projection context.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct CommittedGraphqlReview {
    endpoint: Url,
    endpoint_source: GraphqlEndpointSource,
    subject: EntityId,
    outcome: GraphqlReviewOutcome,
    legs: Vec<GraphqlLegReceipt>,
    surface_evidence_ids: Vec<EvidenceId>,
    introspection_evidence_ids: Vec<EvidenceId>,
}

impl fmt::Debug for CommittedGraphqlReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedGraphqlReview")
            .field("endpoint", &"<exact-origin-redacted>")
            .field("endpoint_source", &self.endpoint_source)
            .field("subject", &"<redacted>")
            .field("outcome", &self.outcome)
            .field("leg_count", &self.legs.len())
            .field("surface_evidence_count", &self.surface_evidence_ids.len())
            .field(
                "introspection_evidence_count",
                &self.introspection_evidence_ids.len(),
            )
            .finish()
    }
}

impl CommittedGraphqlReview {
    pub(super) fn subject(&self) -> &EntityId {
        &self.subject
    }

    pub(super) fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub(super) const fn outcome(&self) -> GraphqlReviewOutcome {
        self.outcome
    }

    fn all_item_evidence_ids(&self) -> BTreeSet<EvidenceId> {
        self.surface_evidence_ids
            .iter()
            .chain(self.introspection_evidence_ids.iter())
            .cloned()
            .collect()
    }
}

pub(super) struct CompletedGraphqlRuntime {
    review: CommittedGraphqlReview,
    defense: AssessmentDefenseController,
    receipts: Vec<DecisionEvidenceReceipt>,
}

impl CompletedGraphqlRuntime {
    pub(super) fn review(&self) -> &CommittedGraphqlReview {
        &self.review
    }

    pub(super) fn defense(&self) -> &AssessmentDefenseController {
        &self.defense
    }

    pub(super) fn replay_defense(
        &self,
        knowledge: &KnowledgeBase,
        enforcement_enabled: bool,
    ) -> Result<AssessmentDefenseController, ()> {
        replay_graphql_defense(&self.receipts, knowledge, enforcement_enabled)
    }

    pub(super) fn into_review(self) -> CommittedGraphqlReview {
        self.review
    }
}

pub(super) struct StoppedGraphqlRuntime {
    stop: GraphqlRuntimeStop,
    defense: AssessmentDefenseController,
    receipts: Vec<DecisionEvidenceReceipt>,
}

impl StoppedGraphqlRuntime {
    pub(super) const fn stop(&self) -> GraphqlRuntimeStop {
        self.stop
    }

    pub(super) fn defense(&self) -> &AssessmentDefenseController {
        &self.defense
    }

    pub(super) fn replay_defense(
        &self,
        knowledge: &KnowledgeBase,
        enforcement_enabled: bool,
    ) -> Result<AssessmentDefenseController, ()> {
        replay_graphql_defense(&self.receipts, knowledge, enforcement_enabled)
    }
}

fn replay_graphql_defense(
    receipts: &[DecisionEvidenceReceipt],
    knowledge: &KnowledgeBase,
    enforcement_enabled: bool,
) -> Result<AssessmentDefenseController, ()> {
    let mut replay = AssessmentDefenseController::new(enforcement_enabled);
    for receipt in receipts {
        replay.ingest_receipt(receipt, knowledge, true)?;
    }
    Ok(replay)
}

pub(super) enum GraphqlRuntimeResult {
    NotEligible,
    Complete(CompletedGraphqlRuntime),
    Stopped(StoppedGraphqlRuntime),
}

struct GraphqlDecisionExecutor {
    requests: HttpRequestBroker,
    endpoint: Url,
    control: GraphqlOperation,
    candidate: GraphqlOperation,
    replay: GraphqlOperation,
    classifier: GraphqlResponseClassifier,
    candidate_root_identity: Mutex<Option<[u8; 32]>>,
}

impl GraphqlDecisionExecutor {
    fn operation_for(&self, action_id: &str) -> Option<&GraphqlOperation> {
        match action_id {
            GRAPHQL_CONTROL_ACTION_ID => Some(&self.control),
            GRAPHQL_CANDIDATE_ACTION_ID => Some(&self.candidate),
            GRAPHQL_REPLAY_ACTION_ID => Some(&self.replay),
            _ => None,
        }
    }

    fn bind_transient_root_identity(
        &self,
        role: GraphqlOperationRole,
        root_identity: Option<[u8; 32]>,
    ) -> Result<Option<bool>, DecisionExecutorError> {
        let mut candidate = self.candidate_root_identity.lock().map_err(|_| {
            DecisionExecutorError::new("GraphQL transient replay state is unavailable")
        })?;
        match role {
            GraphqlOperationRole::Control => {
                *candidate = None;
                Ok(None)
            },
            GraphqlOperationRole::IntrospectionCandidate => {
                *candidate = root_identity;
                Ok(None)
            },
            GraphqlOperationRole::IntrospectionReplay => Ok(root_identity.map(|replay| {
                candidate
                    .as_ref()
                    .is_some_and(|candidate| *candidate == replay)
            })),
        }
    }
}

#[async_trait]
impl DecisionActionExecutor for GraphqlDecisionExecutor {
    fn id(&self) -> &str {
        GRAPHQL_EXECUTOR_ID
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let operation = self
            .operation_for(request.case().action_id())
            .ok_or_else(|| {
                DecisionExecutorError::new("GraphQL executor received an unknown action")
            })?;
        let expected_stage = match operation.role() {
            GraphqlOperationRole::Control | GraphqlOperationRole::IntrospectionCandidate => {
                DecisionExecutionStage::Passive
            },
            GraphqlOperationRole::IntrospectionReplay => DecisionExecutionStage::Active,
        };
        let expected_subject = EntityId::new(format!("graphql-endpoint:{}", self.endpoint))
            .map_err(|_| DecisionExecutorError::new("GraphQL endpoint identity is invalid"))?;
        if request.stage() != expected_stage
            || request.case().subject() != &expected_subject
            || request.case().applies_hypothesis_transition()
            || request.case().payload_strategy().is_some()
        {
            return Err(DecisionExecutorError::new(
                "GraphQL executor request violated its closed route contract",
            ));
        }
        let response = self
            .requests
            .collect_anonymous_graphql_json_for_runtime(
                request.case().action_id(),
                request.stage(),
                request.origin(),
                request.limits(),
                &self.endpoint,
                operation.body(),
            )
            .await
            .map_err(HttpRequestBrokerError::into_decision_executor_error)?;
        let mut classified = classify_response(self.classifier, operation, &response);
        classified.receipt.replay_matches_candidate_roots =
            self.bind_transient_root_identity(operation.role(), classified.root_identity_digest)?;
        let summary = classified.receipt;
        let reliability = self.requests.policy().reliability();
        let (graphql_observations, graphql_classification) =
            graphql_transport_observations(request, &summary, reliability)?;
        project_graphql_transport_response(
            GRAPHQL_EXECUTOR_ID,
            request,
            &self.endpoint,
            response,
            reliability,
            graphql_observations,
            graphql_classification,
        )
        .map_err(crate::http_evidence::into_decision_executor_error)
    }
}

fn graphql_transport_observations(
    request: &DecisionExecutionRequest,
    summary: &GraphqlLegReceipt,
    reliability: ConfidenceScore,
) -> Result<(Vec<Evidence>, Evidence), DecisionExecutorError> {
    let source = |property: &str| {
        EvidenceSource::new(GRAPHQL_EXECUTOR_ID, property)
            .and_then(|source| source.with_correlation_id(request.case().id()))
            .map_err(|_| DecisionExecutorError::new("GraphQL evidence identity is invalid"))
    };
    let observation = |property: &str, value: EvidenceValue| {
        Ok::<_, DecisionExecutorError>(Evidence::new(
            request.case().subject().clone(),
            EvidenceKind::Custom("graphql-transport-observation".to_owned()),
            KnowledgePredicate::new(GRAPHQL_TRANSPORT_EVIDENCE_NAMESPACE, property)
                .map_err(|_| DecisionExecutorError::new("GraphQL evidence predicate is invalid"))?,
            value,
            source(property)?,
            reliability,
        ))
    };
    let mut evidence = vec![
        observation(
            "role",
            EvidenceValue::Text(role_name(summary.role).to_owned()),
        )?,
        observation(
            "request_digest",
            EvidenceValue::Text(encode_digest(summary.request_digest)),
        )?,
        observation(
            "response_digest",
            EvidenceValue::Text(encode_digest(summary.response_digest)),
        )?,
        observation(
            "response_bytes",
            EvidenceValue::Unsigned(u64::try_from(summary.response_bytes).unwrap_or(u64::MAX)),
        )?,
        observation(
            "exact_graphql_media",
            EvidenceValue::Boolean(summary.exact_graphql_media),
        )?,
    ];
    if let Some((query, mutation, subscription)) = summary.introspection_roots {
        evidence.push(observation(
            "query_root_present",
            EvidenceValue::Boolean(query),
        )?);
        evidence.push(observation(
            "mutation_root_present",
            EvidenceValue::Boolean(mutation),
        )?);
        evidence.push(observation(
            "subscription_root_present",
            EvidenceValue::Boolean(subscription),
        )?);
    }
    if let Some(matches) = summary.replay_matches_candidate_roots {
        evidence.push(observation(
            "replay_matches_candidate_roots",
            EvidenceValue::Boolean(matches),
        )?);
    }
    let classification = observation(
        "classification",
        EvidenceValue::Text(classification_code(summary.classification).to_owned()),
    )?;
    Ok((evidence, classification))
}

fn classification_code(classification: GraphqlResponseKind) -> &'static str {
    match classification {
        GraphqlResponseKind::ExactControlEnvelope => "exact-control-envelope",
        GraphqlResponseKind::ExactIntrospectionEnvelope => "exact-introspection-envelope",
        GraphqlResponseKind::StructuredGraphqlErrors(
            GraphqlErrorCategory::IntrospectionRestricted,
        ) => "errors-introspection-restricted",
        GraphqlResponseKind::StructuredGraphqlErrors(GraphqlErrorCategory::ValidationError) => {
            "errors-validation"
        },
        GraphqlResponseKind::StructuredGraphqlErrors(GraphqlErrorCategory::ParseError) => {
            "errors-parse"
        },
        GraphqlResponseKind::StructuredGraphqlErrors(GraphqlErrorCategory::UnknownGraphqlError) => {
            "errors-unknown"
        },
        GraphqlResponseKind::GenericJson => "generic-json",
        GraphqlResponseKind::Html => "html",
        GraphqlResponseKind::UnsupportedMedia => "unsupported-media",
        GraphqlResponseKind::MalformedJson => "malformed-json",
        GraphqlResponseKind::Ambiguous => "ambiguous",
        GraphqlResponseKind::Incomplete => "incomplete",
        GraphqlResponseKind::Truncated => "truncated",
    }
}

fn encode_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

const fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Derives bounded endpoint hints from already committed discovery truth.
pub(super) fn graphql_endpoint_hints(
    authorized_origin: &Url,
    knowledge: &KnowledgeBase,
    subjects: impl IntoIterator<Item = Url>,
    form_actions: impl IntoIterator<Item = Url>,
) -> Vec<GraphqlEndpointHint> {
    let mut hints = Vec::new();
    for url in subjects {
        if let Ok(Some(hint)) = GraphqlEndpointHint::exact_path(url.clone()) {
            hints.push(hint);
        }
        let Ok(subject) = EntityId::new(format!("endpoint:{url}")) else {
            continue;
        };
        let exact_media = knowledge
            .evidence_for_subject(&subject)
            .iter()
            .any(|evidence| {
                evidence.predicate() == &HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge()
                    && evidence.value()
                        == &EvidenceValue::Text("application/graphql-response+json".to_owned())
            });
        if exact_media {
            if let Ok(Some(hint)) =
                GraphqlEndpointHint::response_media(url, "application/graphql-response+json")
            {
                hints.push(hint);
            }
        }
    }
    for action in form_actions {
        if let Ok(Some(hint)) = GraphqlEndpointHint::discovered_reference(action) {
            hints.push(hint);
        }
    }
    bound_runtime_graphql_endpoint_hints(authorized_origin, hints)
}

/// Executes at most one fixed three-operation review through shared authority.
pub(super) async fn execute_graphql_review(
    authority: &SharedWebRuntimeAuthority,
    authorized_root: &Url,
    hints: Vec<GraphqlEndpointHint>,
    response_body_limit: usize,
    defense_enforcement: bool,
) -> Result<GraphqlRuntimeResult, GraphqlRuntimeInvariantError> {
    let catalog = GraphqlReviewCatalog::v1();
    if catalog.executable().is_none()
        || catalog
            .entries()
            .iter()
            .filter(|entry| {
                entry.availability == crate::graphql_review::GraphqlReviewAvailability::Executable
            })
            .count()
            != 1
        || MAX_GRAPHQL_SELECTED_ENDPOINTS != 1
        || MAX_GRAPHQL_ACTIVE_VERIFICATIONS != 1
        || MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES != 3
        || GraphqlFallbackPolicy::all()
            != [
                GraphqlFallbackPolicy::Disabled,
                GraphqlFallbackPolicy::GraphqlOnly,
                GraphqlFallbackPolicy::ApiGraphqlOnly,
                GraphqlFallbackPolicy::GraphqlThenApiGraphql,
            ]
    {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    let Some(endpoint) = select_graphql_endpoint(
        authorized_root,
        hints,
        GraphqlFallbackPolicy::GraphqlThenApiGraphql,
    )?
    else {
        return Ok(GraphqlRuntimeResult::NotEligible);
    };
    authority.authorize_target(endpoint.url()).map_err(|_| {
        GraphqlRuntimeInvariantError::Contract(GraphqlReviewContractError::InvalidEndpoint)
    })?;

    let operations = GraphqlOperationSet::v1(&endpoint)?;
    let ordered = operations.ordered();
    if ordered.map(GraphqlOperation::role)
        != [
            GraphqlOperationRole::Control,
            GraphqlOperationRole::IntrospectionCandidate,
            GraphqlOperationRole::IntrospectionReplay,
        ]
        || ordered
            .iter()
            .any(|operation| operation.endpoint_binding() != endpoint.binding_digest())
        || ordered[0].operation_name() == ordered[1].operation_name()
        || ordered[1].operation_name() == ordered[2].operation_name()
        || ordered[0].operation_name() == ordered[2].operation_name()
    {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    let classifier = GraphqlResponseClassifier::default();
    let endpoint_subject = EntityId::new(format!("graphql-endpoint:{}", endpoint.url()))?;
    let executor = Arc::new(GraphqlDecisionExecutor {
        requests: authority.requests().clone(),
        endpoint: endpoint.url().clone(),
        control: operations.control().clone(),
        candidate: operations.candidate().clone(),
        replay: operations.replay().clone(),
        classifier,
        candidate_root_identity: Mutex::new(None),
    });
    let mut executors = DecisionExecutorRegistry::new();
    executors
        .register(executor)
        .map_err(|_| GraphqlRuntimeInvariantError::Catalog)?;
    for (stage, action_id) in [
        (DecisionExecutionStage::Passive, GRAPHQL_CONTROL_ACTION_ID),
        (DecisionExecutionStage::Passive, GRAPHQL_CANDIDATE_ACTION_ID),
        (DecisionExecutionStage::Active, GRAPHQL_REPLAY_ACTION_ID),
    ] {
        executors
            .route_action(stage, action_id, GRAPHQL_EXECUTOR_ID)
            .map_err(|_| GraphqlRuntimeInvariantError::Catalog)?;
    }
    let runner = DecisionRunnerAdapter::new(executors);
    let graphql_response_limit = response_body_limit.min(MAX_GRAPHQL_RESPONSE_BYTES);
    let per_request_limits = DecisionExecutionLimits::new()
        .with_max_response_body_bytes(u64::try_from(graphql_response_limit).unwrap_or(u64::MAX));
    let timing = authority.start();
    let mut legs = Vec::with_capacity(MAX_GRAPHQL_CHILD_REQUESTS);
    let mut receipts = Vec::with_capacity(MAX_GRAPHQL_CHILD_REQUESTS);
    let mut defense = AssessmentDefenseController::new(defense_enforcement);
    let dispatch = GraphqlDispatchContext {
        authority,
        endpoint_subject: &endpoint_subject,
        runner: &runner,
        limits: per_request_limits,
        deadline: timing.deadline(),
    };

    let control = match dispatch_leg(
        &dispatch,
        operations.control(),
        GRAPHQL_CONTROL_ACTION_ID,
        DecisionExecutionStage::Passive,
        Some(DecisionActionOrigin::Bootstrap),
    )
    .await?
    {
        DispatchedLeg::Receipt { leg, receipt } => {
            defense
                .ingest_receipt(&receipt, authority.knowledge(), true)
                .map_err(|_| GraphqlRuntimeInvariantError::Catalog)?;
            receipts.push(*receipt);
            leg
        },
        DispatchedLeg::Stopped(stop) => {
            return Ok(GraphqlRuntimeResult::Stopped(StoppedGraphqlRuntime {
                stop,
                defense,
                receipts,
            }));
        },
    };
    let control_classification = control.classification;
    legs.push(control);

    // A generic/HTML/malformed control never authorizes deeper protocol work.
    if control_classification != GraphqlResponseKind::ExactControlEnvelope {
        let committed = commit_graphql_review(
            authority.knowledge(),
            endpoint,
            legs,
            classify_graphql_transport_outcome(
                control_classification,
                GraphqlResponseKind::UnsupportedMedia,
                GraphqlResponseKind::UnsupportedMedia,
                None,
            ),
        )?;
        return Ok(GraphqlRuntimeResult::Complete(CompletedGraphqlRuntime {
            review: committed,
            defense,
            receipts,
        }));
    }

    if !defense
        .permits_optional_interaction(&endpoint_subject, DefenseInteractionClass::DifferentialRead)
    {
        let committed = commit_graphql_review(
            authority.knowledge(),
            endpoint,
            legs,
            classify_graphql_transport_outcome(
                control_classification,
                GraphqlResponseKind::UnsupportedMedia,
                GraphqlResponseKind::UnsupportedMedia,
                None,
            ),
        )?;
        return Ok(GraphqlRuntimeResult::Complete(CompletedGraphqlRuntime {
            review: committed,
            defense,
            receipts,
        }));
    }

    let candidate = match dispatch_leg(
        &dispatch,
        operations.candidate(),
        GRAPHQL_CANDIDATE_ACTION_ID,
        DecisionExecutionStage::Passive,
        Some(DecisionActionOrigin::Planned),
    )
    .await?
    {
        DispatchedLeg::Receipt { leg, receipt } => {
            defense
                .ingest_receipt(&receipt, authority.knowledge(), true)
                .map_err(|_| GraphqlRuntimeInvariantError::Catalog)?;
            receipts.push(*receipt);
            leg
        },
        DispatchedLeg::Stopped(stop) => {
            return Ok(GraphqlRuntimeResult::Stopped(StoppedGraphqlRuntime {
                stop,
                defense,
                receipts,
            }));
        },
    };
    let candidate_classification = candidate.classification;
    legs.push(candidate);

    if !defense.permits_optional_interaction(
        &endpoint_subject,
        DefenseInteractionClass::ActiveVerification,
    ) {
        let committed = commit_graphql_review(
            authority.knowledge(),
            endpoint,
            legs,
            classify_graphql_transport_outcome(
                control_classification,
                candidate_classification,
                GraphqlResponseKind::UnsupportedMedia,
                None,
            ),
        )?;
        return Ok(GraphqlRuntimeResult::Complete(CompletedGraphqlRuntime {
            review: committed,
            defense,
            receipts,
        }));
    }

    let candidate_needs_replay = matches!(
        candidate_classification,
        GraphqlResponseKind::ExactIntrospectionEnvelope
            | GraphqlResponseKind::StructuredGraphqlErrors(_)
    );
    if !candidate_needs_replay {
        let committed = commit_graphql_review(
            authority.knowledge(),
            endpoint,
            legs,
            classify_graphql_transport_outcome(
                control_classification,
                candidate_classification,
                GraphqlResponseKind::UnsupportedMedia,
                None,
            ),
        )?;
        return Ok(GraphqlRuntimeResult::Complete(CompletedGraphqlRuntime {
            review: committed,
            defense,
            receipts,
        }));
    }

    let replay = match dispatch_leg(
        &dispatch,
        operations.replay(),
        GRAPHQL_REPLAY_ACTION_ID,
        DecisionExecutionStage::Active,
        None,
    )
    .await?
    {
        DispatchedLeg::Receipt { leg, receipt } => {
            defense
                .ingest_receipt(&receipt, authority.knowledge(), true)
                .map_err(|_| GraphqlRuntimeInvariantError::Catalog)?;
            receipts.push(*receipt);
            leg
        },
        DispatchedLeg::Stopped(stop) => {
            return Ok(GraphqlRuntimeResult::Stopped(StoppedGraphqlRuntime {
                stop,
                defense,
                receipts,
            }));
        },
    };
    let replay_classification = replay.classification;
    let replay_matches_candidate_roots = replay.replay_matches_candidate_roots;
    legs.push(replay);
    let outcome = classify_graphql_transport_outcome(
        control_classification,
        candidate_classification,
        replay_classification,
        replay_matches_candidate_roots,
    );
    Ok(GraphqlRuntimeResult::Complete(CompletedGraphqlRuntime {
        review: commit_graphql_review(authority.knowledge(), endpoint, legs, outcome)?,
        defense,
        receipts,
    }))
}

enum DispatchedLeg {
    Receipt {
        leg: GraphqlLegReceipt,
        receipt: Box<DecisionEvidenceReceipt>,
    },
    Stopped(GraphqlRuntimeStop),
}

struct GraphqlDispatchContext<'a> {
    authority: &'a SharedWebRuntimeAuthority,
    endpoint_subject: &'a EntityId,
    runner: &'a DecisionRunnerAdapter,
    limits: DecisionExecutionLimits,
    deadline: Option<tokio::time::Instant>,
}

async fn dispatch_leg(
    context: &GraphqlDispatchContext<'_>,
    operation: &GraphqlOperation,
    action_id: &str,
    stage: DecisionExecutionStage,
    origin: Option<DecisionActionOrigin>,
) -> Result<DispatchedLeg, GraphqlRuntimeInvariantError> {
    if context.authority.cancellation().is_cancelled() {
        return Ok(DispatchedLeg::Stopped(GraphqlRuntimeStop::Cancelled));
    }
    if context
        .deadline
        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    {
        return Ok(DispatchedLeg::Stopped(GraphqlRuntimeStop::RuntimeLimit(
            RuntimeBudgetDimension::WallTime,
        )));
    }
    let case_id = match operation.role() {
        GraphqlOperationRole::Control => GRAPHQL_CONTROL_CASE_ID,
        GraphqlOperationRole::IntrospectionCandidate => GRAPHQL_CANDIDATE_CASE_ID,
        GraphqlOperationRole::IntrospectionReplay => GRAPHQL_REPLAY_CASE_ID,
    };
    let case = VerificationCase::new(
        case_id,
        context.endpoint_subject.clone(),
        action_id,
        GRAPHQL_HYPOTHESIS_ID,
    )
    .map_err(|_| GraphqlRuntimeInvariantError::Catalog)?
    .without_hypothesis_transition();
    let command = match (stage, origin) {
        (DecisionExecutionStage::Passive, Some(origin)) => DecisionLoopCommand::ExecuteAction {
            case,
            executor: None,
            origin,
            delay_ms: None,
        },
        (DecisionExecutionStage::Active, None) => {
            DecisionLoopCommand::CollectActiveEvidence { case }
        },
        _ => return Err(GraphqlRuntimeInvariantError::Catalog),
    };
    let execution = context.runner.execute_command_with_limits(
        &command,
        context.authority.knowledge(),
        context.limits,
    );
    let receipt = match await_execution(
        context.authority.cancellation(),
        context.deadline,
        execution,
    )
    .await
    {
        RuntimeExecution::Completed(Ok(receipt)) => receipt,
        RuntimeExecution::Completed(Err(error)) => {
            if let Some(limit) = error.runtime_limit() {
                return Ok(DispatchedLeg::Stopped(GraphqlRuntimeStop::RuntimeLimit(
                    limit.dimension(),
                )));
            }
            return match error {
                DecisionRunnerError::Executor { .. } => Ok(DispatchedLeg::Stopped(
                    GraphqlRuntimeStop::TransportIncomplete,
                )),
                _ => Err(GraphqlRuntimeInvariantError::Catalog),
            };
        },
        RuntimeExecution::Cancelled => {
            return Ok(DispatchedLeg::Stopped(GraphqlRuntimeStop::Cancelled));
        },
        RuntimeExecution::WallTimeExceeded => {
            return Ok(DispatchedLeg::Stopped(GraphqlRuntimeStop::RuntimeLimit(
                RuntimeBudgetDimension::WallTime,
            )));
        },
    };
    let leg = leg_from_decision_receipt(&receipt, operation)?;
    Ok(DispatchedLeg::Receipt {
        leg,
        receipt: Box::new(receipt),
    })
}

fn leg_from_decision_receipt(
    receipt: &DecisionEvidenceReceipt,
    operation: &GraphqlOperation,
) -> Result<GraphqlLegReceipt, GraphqlRuntimeInvariantError> {
    let role = transport_text(receipt, "role")?;
    let request_digest = transport_digest(receipt, "request_digest")?;
    let response_digest = transport_digest(receipt, "response_digest")?;
    let response_bytes = usize::try_from(transport_unsigned(receipt, "response_bytes")?)
        .map_err(|_| GraphqlRuntimeInvariantError::Catalog)?;
    let exact_graphql_media = transport_boolean(receipt, "exact_graphql_media")?;
    let classification_code = transport_text(receipt, "classification")?;
    if role != role_name(operation.role()) || request_digest != operation.body_digest() {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    let (classification, introspection_roots, replay_matches_candidate_roots) =
        if classification_code == "exact-introspection-envelope" {
            let query = transport_boolean(receipt, "query_root_present")?;
            let mutation = transport_boolean(receipt, "mutation_root_present")?;
            let subscription = transport_boolean(receipt, "subscription_root_present")?;
            let replay_matches = match operation.role() {
                GraphqlOperationRole::IntrospectionCandidate => {
                    if transport_value(receipt, "replay_matches_candidate_roots").is_some() {
                        return Err(GraphqlRuntimeInvariantError::Catalog);
                    }
                    None
                },
                GraphqlOperationRole::IntrospectionReplay => Some(transport_boolean(
                    receipt,
                    "replay_matches_candidate_roots",
                )?),
                GraphqlOperationRole::Control => {
                    return Err(GraphqlRuntimeInvariantError::Catalog);
                },
            };
            (
                GraphqlResponseKind::ExactIntrospectionEnvelope,
                Some((query, mutation, subscription)),
                replay_matches,
            )
        } else {
            if [
                "query_root_present",
                "mutation_root_present",
                "subscription_root_present",
                "replay_matches_candidate_roots",
            ]
            .into_iter()
            .any(|property| transport_value(receipt, property).is_some())
            {
                return Err(GraphqlRuntimeInvariantError::Catalog);
            }
            (
                classification_from_code(classification_code)
                    .ok_or(GraphqlRuntimeInvariantError::Catalog)?,
                None,
                None,
            )
        };
    let classification_evidence = transport_evidence(receipt, "classification")?;
    let classification_derivation = classification_evidence
        .origin()
        .derivation()
        .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
    if classification_evidence.subject() != receipt.case().subject()
        || classification_evidence.source().component() != GRAPHQL_EXECUTOR_ID
        || classification_evidence.source().correlation_id() != Some(receipt.case().id())
        || classification_derivation.algorithm().name()
            != GRAPHQL_TRANSPORT_CLASSIFICATION_ALGORITHM
        || classification_derivation.algorithm().version() != 1
    {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    let direct_transport_properties = [
        "role",
        "request_digest",
        "response_digest",
        "response_bytes",
        "exact_graphql_media",
        "query_root_present",
        "mutation_root_present",
        "subscription_root_present",
        "replay_matches_candidate_roots",
    ];
    let mut expected_parents = BTreeSet::new();
    for evidence in receipt.evidence().iter().filter(|evidence| {
        evidence.predicate().namespace() == GRAPHQL_TRANSPORT_EVIDENCE_NAMESPACE
            && evidence.predicate().name() != "classification"
    }) {
        if !direct_transport_properties.contains(&evidence.predicate().name())
            || !evidence.origin().is_direct()
            || evidence.reliability() != classification_evidence.reliability()
        {
            return Err(GraphqlRuntimeInvariantError::Catalog);
        }
        expected_parents.insert(evidence.id().clone());
    }
    for descriptor in [
        HttpEvidencePredicate::REQUEST_URL,
        HttpEvidencePredicate::RESPONSE_STATUS,
        HttpEvidencePredicate::RESPONSE_FINAL_URL,
        HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
        HttpEvidencePredicate::RESPONSE_BODY_SHA256,
    ] {
        let evidence = receipt_evidence(receipt, &descriptor.into_knowledge())?;
        if !evidence.origin().is_direct()
            || evidence.reliability() != classification_evidence.reliability()
        {
            return Err(GraphqlRuntimeInvariantError::Catalog);
        }
        expected_parents.insert(evidence.id().clone());
    }
    if classification_derivation.parents() != expected_parents.into_iter().collect::<Vec<_>>() {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    let request_url_evidence = receipt_evidence(
        receipt,
        &HttpEvidencePredicate::REQUEST_URL.into_knowledge(),
    )?;
    Ok(GraphqlLegReceipt {
        role: operation.role(),
        request_digest,
        response_digest,
        response_bytes,
        exact_graphql_media,
        classification,
        introspection_roots,
        replay_matches_candidate_roots,
        classification_evidence_id: Some(classification_evidence.id().clone()),
        request_url_evidence_id: Some(request_url_evidence.id().clone()),
    })
}

fn receipt_evidence<'a>(
    receipt: &'a DecisionEvidenceReceipt,
    predicate: &KnowledgePredicate,
) -> Result<&'a Evidence, GraphqlRuntimeInvariantError> {
    let mut matches = receipt
        .evidence()
        .iter()
        .filter(|evidence| evidence.predicate() == predicate);
    let evidence = matches
        .next()
        .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
    if matches.next().is_some() {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    Ok(evidence)
}

fn transport_evidence<'a>(
    receipt: &'a DecisionEvidenceReceipt,
    property: &str,
) -> Result<&'a Evidence, GraphqlRuntimeInvariantError> {
    let predicate = KnowledgePredicate::new(GRAPHQL_TRANSPORT_EVIDENCE_NAMESPACE, property)?;
    receipt_evidence(receipt, &predicate)
}

fn transport_value<'a>(
    receipt: &'a DecisionEvidenceReceipt,
    property: &str,
) -> Option<&'a EvidenceValue> {
    transport_evidence(receipt, property)
        .ok()
        .map(Evidence::value)
}

fn transport_text<'a>(
    receipt: &'a DecisionEvidenceReceipt,
    property: &str,
) -> Result<&'a str, GraphqlRuntimeInvariantError> {
    match transport_value(receipt, property) {
        Some(EvidenceValue::Text(value)) => Ok(value),
        _ => Err(GraphqlRuntimeInvariantError::Catalog),
    }
}

fn transport_boolean(
    receipt: &DecisionEvidenceReceipt,
    property: &str,
) -> Result<bool, GraphqlRuntimeInvariantError> {
    match transport_value(receipt, property) {
        Some(EvidenceValue::Boolean(value)) => Ok(*value),
        _ => Err(GraphqlRuntimeInvariantError::Catalog),
    }
}

fn transport_unsigned(
    receipt: &DecisionEvidenceReceipt,
    property: &str,
) -> Result<u64, GraphqlRuntimeInvariantError> {
    match transport_value(receipt, property) {
        Some(EvidenceValue::Unsigned(value)) => Ok(*value),
        _ => Err(GraphqlRuntimeInvariantError::Catalog),
    }
}

fn transport_digest(
    receipt: &DecisionEvidenceReceipt,
    property: &str,
) -> Result<[u8; 32], GraphqlRuntimeInvariantError> {
    decode_digest(transport_text(receipt, property)?).ok_or(GraphqlRuntimeInvariantError::Catalog)
}

fn classification_from_code(code: &str) -> Option<GraphqlResponseKind> {
    Some(match code {
        "exact-control-envelope" => GraphqlResponseKind::ExactControlEnvelope,
        "errors-introspection-restricted" => GraphqlResponseKind::StructuredGraphqlErrors(
            GraphqlErrorCategory::IntrospectionRestricted,
        ),
        "errors-validation" => {
            GraphqlResponseKind::StructuredGraphqlErrors(GraphqlErrorCategory::ValidationError)
        },
        "errors-parse" => {
            GraphqlResponseKind::StructuredGraphqlErrors(GraphqlErrorCategory::ParseError)
        },
        "errors-unknown" => {
            GraphqlResponseKind::StructuredGraphqlErrors(GraphqlErrorCategory::UnknownGraphqlError)
        },
        "generic-json" => GraphqlResponseKind::GenericJson,
        "html" => GraphqlResponseKind::Html,
        "unsupported-media" => GraphqlResponseKind::UnsupportedMedia,
        "malformed-json" => GraphqlResponseKind::MalformedJson,
        "ambiguous" => GraphqlResponseKind::Ambiguous,
        "incomplete" => GraphqlResponseKind::Incomplete,
        "truncated" => GraphqlResponseKind::Truncated,
        _ => return None,
    })
}

struct ClassifiedGraphqlLeg {
    receipt: GraphqlLegReceipt,
    root_identity_digest: Option<[u8; 32]>,
}

fn classify_response(
    classifier: GraphqlResponseClassifier,
    operation: &GraphqlOperation,
    response: &CollectedHttpResponse,
) -> ClassifiedGraphqlLeg {
    let media_type = response.normalized_media_type();
    let mut classification = classifier.classify(GraphqlResponseInput {
        media_type: media_type.as_deref(),
        body: response.body(),
        complete: response.body_complete(),
        truncated: response.body_truncated(),
        operation,
    });
    // A redirect or other non-success status cannot prove a successful
    // scanner-owned control or introspection envelope, even if it carries a
    // look-alike JSON body. Structured GraphQL errors remain classifiable so
    // an already observed endpoint can record a bounded restriction outcome.
    if !(200..300).contains(&response.status())
        && matches!(
            classification,
            GraphqlResponseClassification::ExactControlEnvelope
                | GraphqlResponseClassification::ExactIntrospectionEnvelope(_)
        )
    {
        classification = GraphqlResponseClassification::Ambiguous;
    }
    let (introspection_roots, root_identity_digest) = match classification {
        GraphqlResponseClassification::ExactIntrospectionEnvelope(shape) => (
            Some((
                shape.query_root_present(),
                shape.mutation_root_present(),
                shape.subscription_root_present(),
            )),
            Some(shape.root_identity_digest()),
        ),
        _ => (None, None),
    };
    let mut digest = Sha256::new();
    update_framed(&mut digest, GRAPHQL_RESPONSE_DIGEST_DOMAIN);
    update_framed(&mut digest, response.body());
    ClassifiedGraphqlLeg {
        receipt: GraphqlLegReceipt {
            role: operation.role(),
            request_digest: operation.body_digest(),
            response_digest: digest.finalize().into(),
            response_bytes: response.body().len(),
            exact_graphql_media: media_type.as_deref() == Some("application/graphql-response+json"),
            classification: classification.kind(),
            introspection_roots,
            replay_matches_candidate_roots: None,
            classification_evidence_id: None,
            request_url_evidence_id: None,
        },
        root_identity_digest,
    }
}

fn commit_graphql_review(
    knowledge: &KnowledgeBase,
    endpoint: GraphqlEndpoint,
    legs: Vec<GraphqlLegReceipt>,
    outcome: GraphqlReviewOutcome,
) -> Result<CommittedGraphqlReview, GraphqlRuntimeInvariantError> {
    let subject = EntityId::new(format!("graphql-endpoint:{}", endpoint.url()))?;
    let mut surface_evidence_ids = Vec::new();
    let mut introspection_evidence_ids = Vec::new();

    for leg in &legs {
        let item_classification = match (leg.role, leg.classification) {
            (GraphqlOperationRole::Control, GraphqlResponseKind::ExactControlEnvelope) => {
                Some(GraphqlOperationRole::Control)
            },
            (
                GraphqlOperationRole::IntrospectionCandidate,
                GraphqlResponseKind::ExactIntrospectionEnvelope,
            ) => Some(GraphqlOperationRole::IntrospectionCandidate),
            (
                GraphqlOperationRole::IntrospectionReplay,
                GraphqlResponseKind::ExactIntrospectionEnvelope,
            ) => Some(GraphqlOperationRole::IntrospectionReplay),
            _ => None,
        };
        let Some(item_classification) = item_classification else {
            continue;
        };
        let id = leg
            .classification_evidence_id
            .as_ref()
            .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
        let evidence = knowledge
            .evidence(id)
            .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
        let classification_predicate =
            KnowledgePredicate::new(GRAPHQL_TRANSPORT_EVIDENCE_NAMESPACE, "classification")?;
        let derivation = evidence
            .origin()
            .derivation()
            .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
        if evidence.subject() != &subject
            || evidence.predicate() != &classification_predicate
            || evidence.value()
                != &EvidenceValue::Text(classification_code(leg.classification).to_owned())
            || evidence.source().component() != GRAPHQL_EXECUTOR_ID
            || evidence.source().correlation_id()
                != Some(match item_classification {
                    GraphqlOperationRole::Control => GRAPHQL_CONTROL_CASE_ID,
                    GraphqlOperationRole::IntrospectionCandidate => GRAPHQL_CANDIDATE_CASE_ID,
                    GraphqlOperationRole::IntrospectionReplay => GRAPHQL_REPLAY_CASE_ID,
                })
            || derivation.algorithm().name() != GRAPHQL_TRANSPORT_CLASSIFICATION_ALGORITHM
            || derivation.algorithm().version() != 1
        {
            return Err(GraphqlRuntimeInvariantError::Catalog);
        }
        if item_classification == GraphqlOperationRole::Control {
            surface_evidence_ids.push(id.clone());
        } else {
            introspection_evidence_ids.push(id.clone());
        }
    }

    validate_graphql_item_evidence_shape(&surface_evidence_ids, &introspection_evidence_ids)?;

    if !surface_evidence_ids.is_empty() {
        commit_api_reasoning_inputs(knowledge, &subject, &endpoint, &legs)?;
    }

    Ok(CommittedGraphqlReview {
        endpoint: endpoint.url().clone(),
        endpoint_source: endpoint.source(),
        subject,
        outcome,
        legs,
        surface_evidence_ids,
        introspection_evidence_ids,
    })
}

fn validate_graphql_item_evidence_shape(
    surface: &[EvidenceId],
    introspection: &[EvidenceId],
) -> Result<(), GraphqlRuntimeInvariantError> {
    let total = surface
        .len()
        .checked_add(introspection.len())
        .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
    let unique = surface.iter().chain(introspection).collect::<BTreeSet<_>>();
    if surface.len() > 1
        || introspection.len() > 2
        || total > MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES
        || unique.len() != total
    {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    Ok(())
}

fn commit_api_reasoning_inputs(
    knowledge: &KnowledgeBase,
    subject: &EntityId,
    endpoint: &GraphqlEndpoint,
    legs: &[GraphqlLegReceipt],
) -> Result<(), GraphqlRuntimeInvariantError> {
    let control = legs
        .iter()
        .find(|leg| {
            leg.role == GraphqlOperationRole::Control
                && leg.classification == GraphqlResponseKind::ExactControlEnvelope
        })
        .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
    let request_url_id = control
        .request_url_evidence_id
        .as_ref()
        .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
    let request_url = knowledge
        .evidence(request_url_id)
        .ok_or(GraphqlRuntimeInvariantError::Catalog)?;
    if request_url.subject() != subject
        || request_url.predicate() != &HttpEvidencePredicate::REQUEST_URL.into_knowledge()
        || request_url.value() != &EvidenceValue::Text(endpoint.url().to_string())
        || request_url.source().component() != GRAPHQL_EXECUTOR_ID
        || request_url.source().correlation_id() != Some(GRAPHQL_CONTROL_CASE_ID)
        || !request_url.origin().is_direct()
    {
        return Err(GraphqlRuntimeInvariantError::Catalog);
    }
    if endpoint
        .url()
        .path_segments()
        .is_some_and(|segments| segments.into_iter().any(|segment| segment == "graphql"))
    {
        let id = deterministic_api_evidence_id(endpoint, "path-segment")?;
        let source = EvidenceSource::new(GRAPHQL_REVIEW_ALGORITHM_VERSION, "api-path-segment")?
            .with_correlation_id(GRAPHQL_CONTROL_CASE_ID)?;
        let derivation = EvidenceDerivation::new(
            [request_url.id().clone()],
            DerivationAlgorithm::new("web.graphql.api-path-segment", 1)?,
        )?;
        knowledge.insert_evidence(
            Evidence::with_id_at(
                id,
                subject.clone(),
                EvidenceKind::Http,
                HttpEvidencePredicate::REQUEST_PATH_SEGMENT.into_knowledge(),
                EvidenceValue::Text("graphql".to_owned()),
                source,
                request_url.reliability(),
                0,
            )
            .derived_from(derivation),
        )?;
    }
    if control.exact_graphql_media {
        let media_predicate = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
        let matching_media = knowledge
            .evidence_for_subject(subject)
            .into_iter()
            .filter(|evidence| {
                evidence.predicate() == &media_predicate
                    && evidence.value()
                        == &EvidenceValue::Text("application/graphql-response+json".to_owned())
                    && evidence.source().component() == GRAPHQL_EXECUTOR_ID
                    && evidence.source().correlation_id() == Some(GRAPHQL_CONTROL_CASE_ID)
            })
            .count();
        if matching_media != 1 {
            return Err(GraphqlRuntimeInvariantError::Catalog);
        }
    }
    let mut rules = RuleEngine::new();
    StandardApiReasoning::new()?.install(knowledge, &mut rules)?;
    rules.apply(knowledge, subject)?;
    Ok(())
}

fn deterministic_api_evidence_id(
    endpoint: &GraphqlEndpoint,
    property: &str,
) -> Result<EvidenceId, venom_core::ReasoningModelError> {
    let mut digest = Sha256::new();
    update_framed(&mut digest, b"graphql-api-reasoning-evidence/v1");
    update_framed(&mut digest, &endpoint.binding_digest());
    update_framed(&mut digest, property.as_bytes());
    EvidenceId::parse(format!("graphql-api:{:x}", digest.finalize()))
}

const fn role_name(role: GraphqlOperationRole) -> &'static str {
    match role {
        GraphqlOperationRole::Control => "control",
        GraphqlOperationRole::IntrospectionCandidate => "candidate",
        GraphqlOperationRole::IntrospectionReplay => "replay",
    }
}

fn update_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

pub(super) fn register_graphql_subject(
    context: &mut AssessmentProjectionContext,
    scope: &StableAssessmentScopeId,
    review: &CommittedGraphqlReview,
) -> Result<(), AssessmentItemProjectionError> {
    let stable_id =
        StableAssessmentSubjectId::from_anonymous_graphql_endpoint(scope, review.endpoint())?;
    context.register_subject(review.subject().clone(), stable_id, Vec::new())?;
    Ok(())
}

pub(super) fn project_graphql_items(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    review: &CommittedGraphqlReview,
) -> Result<(), AssessmentItemProjectionError> {
    let total_evidence = review
        .surface_evidence_ids
        .len()
        .checked_add(review.introspection_evidence_ids.len())
        .ok_or(AssessmentItemProjectionError::TooManyEvidenceReferences)?;
    if total_evidence > MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES {
        return Err(AssessmentItemProjectionError::TooManyEvidenceReferences);
    }
    let all_evidence = review.all_item_evidence_ids();
    if all_evidence.len() != total_evidence {
        return Err(AssessmentItemProjectionError::DuplicateEvidenceReference);
    }
    for evidence_id in all_evidence {
        context.register_evidence(knowledge, &evidence_id)?;
    }
    let target = AssessmentItemTarget::subject();
    if !review.surface_evidence_ids.is_empty() {
        context.project_observation(
            graphql_capability(GraphqlAssessmentKind::SurfaceObserved),
            knowledge,
            review.subject(),
            &target,
            &review.surface_evidence_ids,
        )?;
    }
    if review.outcome() == GraphqlReviewOutcome::IntrospectionAvailable
        && review.introspection_evidence_ids.len() == 2
    {
        let mut evidence = review.surface_evidence_ids.clone();
        evidence.extend(review.introspection_evidence_ids.iter().cloned());
        context.project_observation(
            graphql_capability(GraphqlAssessmentKind::AnonymousRootIntrospectionAvailable),
            knowledge,
            review.subject(),
            &target,
            &evidence,
        )?;
    }
    Ok(())
}

fn graphql_capability(kind: GraphqlAssessmentKind) -> &'static AssessmentCapabilityDescriptor {
    match (kind, kind.maximum_disposition(), kind.maximum_authority()) {
        (
            GraphqlAssessmentKind::SurfaceObserved,
            GraphqlMaximumDisposition::Informational,
            GraphqlMaximumAuthority::KnowledgeOnly,
        ) => &GRAPHQL_SURFACE_CAPABILITY,
        (
            GraphqlAssessmentKind::AnonymousRootIntrospectionAvailable,
            GraphqlMaximumDisposition::Informational,
            GraphqlMaximumAuthority::KnowledgeOnly,
        ) => &GRAPHQL_INTROSPECTION_CAPABILITY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql_review::{GraphqlEndpointHint, GraphqlFallbackPolicy};
    use venom_core::{ApiKnowledgePredicate, ApiSurfaceKind};

    #[test]
    fn endpoint_hints_are_bounded_and_debug_is_redacted() {
        let root = Url::parse("https://example.test/").unwrap();
        let endpoint = select_graphql_endpoint(
            &root,
            Vec::<GraphqlEndpointHint>::new(),
            GraphqlFallbackPolicy::GraphqlOnly,
        )
        .unwrap()
        .unwrap();
        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("example.test"));
        assert!(!debug.contains("/graphql"));
    }

    #[test]
    fn committed_debug_never_exposes_endpoint_or_evidence_identity() {
        let endpoint = Url::parse("https://example.test/graphql").unwrap();
        let review = CommittedGraphqlReview {
            endpoint,
            endpoint_source: GraphqlEndpointSource::ConventionalGraphqlFallback,
            subject: EntityId::new("graphql-endpoint:redacted").unwrap(),
            outcome: GraphqlReviewOutcome::EndpointObserved,
            legs: Vec::new(),
            surface_evidence_ids: vec![EvidenceId::parse(
                "GRAPHQL-REVIEW-MUST-NOT-LEAK-SECRET-1F92A7",
            )
            .unwrap()],
            introspection_evidence_ids: Vec::new(),
        };
        let debug = format!("{review:?}");
        assert!(!debug.contains("example.test"));
        assert!(!debug.contains("GRAPHQL-REVIEW-MUST-NOT-LEAK-SECRET-1F92A7"));
    }

    #[test]
    fn committed_control_evidence_feeds_the_existing_transport_neutral_reasoner() {
        let root = Url::parse("https://example.test/").unwrap();
        let endpoint =
            select_graphql_endpoint(
                &root,
                [GraphqlEndpointHint::exact_path(
                    Url::parse("https://example.test/graphql").unwrap(),
                )
                .unwrap()
                .unwrap()],
                GraphqlFallbackPolicy::Disabled,
            )
            .unwrap()
            .unwrap();
        let knowledge = KnowledgeBase::new();
        let subject = EntityId::new(format!("graphql-endpoint:{}", endpoint.url())).unwrap();
        let reliability = ConfidenceScore::from_percent(73).unwrap();
        let source = EvidenceSource::new(GRAPHQL_EXECUTOR_ID, "request-url")
            .unwrap()
            .with_correlation_id(GRAPHQL_CONTROL_CASE_ID)
            .unwrap();
        let request_url = Evidence::new(
            subject.clone(),
            EvidenceKind::Http,
            HttpEvidencePredicate::REQUEST_URL.into_knowledge(),
            EvidenceValue::Text(endpoint.url().to_string()),
            source.clone(),
            reliability,
        );
        let request_url_id = request_url.id().clone();
        let media = Evidence::new(
            subject.clone(),
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge(),
            EvidenceValue::Text("application/graphql-response+json".to_owned()),
            source,
            reliability,
        );
        knowledge
            .insert_evidence_batch(vec![request_url, media])
            .unwrap();
        commit_api_reasoning_inputs(
            &knowledge,
            &subject,
            &endpoint,
            vec![GraphqlLegReceipt {
                role: GraphqlOperationRole::Control,
                request_digest: [1; 32],
                response_digest: [2; 32],
                response_bytes: 44,
                exact_graphql_media: true,
                classification: GraphqlResponseKind::ExactControlEnvelope,
                introspection_roots: None,
                replay_matches_candidate_roots: None,
                classification_evidence_id: None,
                request_url_evidence_id: Some(request_url_id.clone()),
            }]
            .as_slice(),
        )
        .unwrap();

        let snapshot = knowledge.snapshot_for_subject(&subject);
        let surface = ApiKnowledgePredicate::SURFACE_KIND.into_knowledge();
        let graphql = EvidenceValue::from(ApiSurfaceKind::GraphQl);
        let _hypothesis = snapshot
            .hypotheses()
            .iter()
            .find(|hypothesis| hypothesis.predicate() == &surface && hypothesis.value() == &graphql)
            .expect("the existing API reasoner consumes committed GraphQL path/media evidence");
        let media_count = snapshot
            .evidence()
            .iter()
            .filter(|evidence| {
                evidence.predicate() == &HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge()
            })
            .count();
        assert_eq!(media_count, 1);
        let path = snapshot
            .evidence()
            .iter()
            .find(|evidence| {
                evidence.predicate()
                    == &HttpEvidencePredicate::REQUEST_PATH_SEGMENT.into_knowledge()
            })
            .unwrap();
        assert_eq!(path.reliability(), reliability);
        assert!(path
            .origin()
            .derivation()
            .unwrap()
            .references_parent(&request_url_id));
    }

    #[test]
    fn graphql_item_evidence_ceiling_accepts_three_and_rejects_four() {
        let evidence = (0..4)
            .map(|index| EvidenceId::parse(format!("graphql-evidence-{index}")).unwrap())
            .collect::<Vec<_>>();
        assert!(validate_graphql_item_evidence_shape(&evidence[..1], &evidence[1..3]).is_ok());
        assert_eq!(MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES, 3);
        assert!(validate_graphql_item_evidence_shape(&evidence[..1], &evidence[1..]).is_err());
    }
}
