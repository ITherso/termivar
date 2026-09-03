use termivar_core::{ApiVisibilityObservation, EntityId, Evidence};

use crate::{
    api_observation::{
        model::{ApiObservationCommitReceipt, ApiObservationError, ApiObservationReceipt},
        MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES,
    },
    knowledge::KnowledgeBase,
    rules::RuleEngine,
};

/// Accepts one host-paired visibility observation and applies installed rules.
///
/// The expected resource is checked before any write. Evidence and its sole
/// `api.visibility.resource-scope` relation are then inserted atomically, and
/// rules are applied to the isolated comparison subject. If reasoning fails,
/// the observation pair remains committed and the error carries its
/// receipt; callers must not infer rollback from a failed return value. The
/// host remains responsible for persistence beyond this in-memory store.
///
/// This boundary validates scope and canonical storage shape, not producer
/// identity or truth. Predicate names and deterministic digests are public and
/// are not signatures. The host must authenticate the producer, authorize the
/// comparison, and keep raw credentials and response values outside this API.
///
/// # Examples
///
/// ```rust
/// use termivar_core::{
///     ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension,
///     ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EntityId,
/// };
/// use termivar_scanner::{
///     KnowledgeBase, RuleEngine, StandardApiReasoning,
///     ingest_api_visibility_observation,
/// };
///
/// let resource = EntityId::new("resource:account-42")?;
/// let observation = ApiVisibilityComparison::new(
///     "comparison-17",
///     ApiSurfaceKind::JsonHttp,
///     ApiVisibilityPairKind::AuthorizationContext,
///     ApiVisibilityResult::Different,
///     ApiVisibilityDimension::Fields,
///     "anonymous-view",
///     "member-view",
///     resource.as_str(),
/// )?
/// .with_observed_at_ms(1_800_000_000_000)
/// .to_observation("host.api-comparator", ConfidenceScore::MAX)?;
/// let knowledge = KnowledgeBase::new();
/// let mut rules = RuleEngine::new();
/// StandardApiReasoning::new()?.install(&knowledge, &mut rules)?;
///
/// let receipt = ingest_api_visibility_observation(
///     observation,
///     &resource,
///     &knowledge,
///     &rules,
/// )?;
/// assert_eq!(receipt.commit().resource_scope(), &resource);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn ingest_api_visibility_observation(
    observation: ApiVisibilityObservation,
    expected_resource: &EntityId,
    knowledge: &KnowledgeBase,
    rules: &RuleEngine,
) -> Result<ApiObservationReceipt, ApiObservationError> {
    if observation.resource_scope() != expected_resource {
        return Err(ApiObservationError::ResourceMismatch {
            expected: expected_resource.clone(),
            actual: observation.resource_scope().clone(),
        });
    }
    validate_observation_bounds(observation.evidence())?;

    let comparison_subject = observation.evidence().subject().clone();
    let resource_scope = observation.resource_scope().clone();
    let evidence_id = observation.evidence().id().clone();
    let relation_id = observation.scope_relation().id().clone();
    let (evidence, relation) = observation.into_parts();
    let (evidence_write, relation_write) =
        knowledge.insert_evidence_with_relation(evidence, relation)?;
    let commit = ApiObservationCommitReceipt {
        comparison_subject,
        resource_scope,
        evidence_id,
        relation_id,
        evidence_write,
        relation_write,
    };

    rules
        .apply(knowledge, commit.comparison_subject())
        .map(|applications| ApiObservationReceipt {
            commit: commit.clone(),
            applications,
        })
        .map_err(|source| ApiObservationError::ReasoningAfterCommit {
            commit: Box::new(commit),
            source,
        })
}

fn validate_observation_bounds(evidence: &Evidence) -> Result<(), ApiObservationError> {
    let actual = evidence.source().component().len();
    if actual > MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES {
        return Err(ApiObservationError::ObservationLimitExceeded {
            field: "source.component",
            actual,
            maximum: MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES,
        });
    }
    Ok(())
}
