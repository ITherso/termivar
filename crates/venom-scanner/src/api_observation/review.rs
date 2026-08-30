use serde::{Deserialize, Serialize};
use std::fmt;
use venom_core::{
    ApiEvidencePredicate, ApiKnowledgePredicate, ApiVisibilityBoundaryKind, ApiVisibilityDimension,
    ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceValue, Hypothesis, HypothesisState,
    HypothesisStrength, KnowledgePredicate, KnowledgeRelation, RelationId, RelationKind,
};

use crate::{knowledge::KnowledgeBase, rules::hypothesis_id_for_rule};

#[cfg(feature = "scanning")]
use super::model::ApiObservationCommitReceipt;
use super::{
    API_VISIBILITY_EVIDENCE_KIND, API_VISIBILITY_RELATION, API_VISIBILITY_SOURCE_METHOD,
    AUTHORIZATION_BOUNDARY_RULE, COMPARISON_EVIDENCE_PREFIX, COMPARISON_RELATION_PREFIX,
    COMPARISON_SUBJECT_PREFIX, MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES,
    MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES, UI_API_BOUNDARY_RULE,
};

/// Canonical paired observation and its reviewable boundary hypotheses.
///
/// An equivalent comparison remains visible with an empty hypothesis list. A
/// difference can contain one canonical-shaped boundary hypothesis for that
/// isolated comparison subject. The projection validates the standard rule ID
/// and semantic fields, but does not attest which rule installation produced
/// the record. Surface and response-format hypotheses are intentionally
/// excluded from this resource-scoped read model.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityReview {
    resource_scope: EntityId,
    comparison_subject: EntityId,
    relation_id: RelationId,
    evidence: Evidence,
    boundary_hypotheses: Vec<Hypothesis>,
}

/// Deterministic handling state for one canonical API visibility review.
///
/// This is a review disposition, not a vulnerability verdict and not a
/// [`crate::DecisionLoopCommand`]. A difference reaches [`Self::AwaitHumanReview`]
/// only when the standard reasoning profile produced the exact weak, supported,
/// evidence-bound boundary hypothesis. Missing reasoning remains explicitly
/// unresolved instead of being promoted to a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApiVisibilityReviewDisposition {
    /// The canonical comparison evidence described equivalent views.
    NoDifferenceObserved,
    /// A difference exists but no canonical review hypothesis was materialized.
    UnresolvedDifference,
    /// A canonical weak boundary hypothesis requires an authorized human review.
    AwaitHumanReview,
}

impl fmt::Debug for ApiVisibilityReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityReview")
            .field("resource_scope", &"<redacted>")
            .field("comparison_subject", &"<redacted>")
            .field("relation_id", &"<redacted>")
            .field("evidence", &"<redacted>")
            .field("boundary_hypothesis_count", &self.boundary_hypotheses.len())
            .finish()
    }
}

impl ApiVisibilityReview {
    /// Returns the resource selected by the host's pairing contract.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns the isolated comparison subject.
    pub fn comparison_subject(&self) -> &EntityId {
        &self.comparison_subject
    }

    /// Returns the resource-scope relation identity.
    pub fn relation_id(&self) -> &RelationId {
        &self.relation_id
    }

    /// Returns the structurally canonical paired-comparison evidence.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Returns only canonical-shaped API visibility-boundary hypotheses.
    pub fn boundary_hypotheses(&self) -> &[Hypothesis] {
        &self.boundary_hypotheses
    }

    /// Classifies this read model without turning a difference into a finding.
    pub fn disposition(&self) -> ApiVisibilityReviewDisposition {
        if expected_boundary_rule(&self.evidence).is_none() {
            ApiVisibilityReviewDisposition::NoDifferenceObserved
        } else if self.boundary_hypotheses.len() == 1 {
            ApiVisibilityReviewDisposition::AwaitHumanReview
        } else {
            ApiVisibilityReviewDisposition::UnresolvedDifference
        }
    }
}

#[cfg(feature = "scanning")]
pub(crate) fn api_visibility_review_for_commit(
    knowledge: &KnowledgeBase,
    commit: &ApiObservationCommitReceipt,
) -> Option<ApiVisibilityReview> {
    let relation = knowledge.relation(commit.relation_id())?;
    project_api_visibility_review(knowledge, commit.resource_scope(), &relation).filter(|review| {
        review.comparison_subject() == commit.comparison_subject()
            && review.evidence().id() == commit.evidence_id()
    })
}

pub(super) fn project_api_visibility_review(
    knowledge: &KnowledgeBase,
    resource_scope: &EntityId,
    relation: &KnowledgeRelation,
) -> Option<ApiVisibilityReview> {
    if !matches!(relation.kind(), RelationKind::Custom(kind) if kind == API_VISIBILITY_RELATION)
        || relation.to() != resource_scope
        || relation.evidence_ids().len() != 1
    {
        return None;
    }
    let evidence_id = relation.evidence_ids().iter().next()?;
    let evidence = knowledge
        .inspect_evidence(evidence_id, |evidence| {
            (is_canonical_comparison(evidence, relation) && is_bounded_review_evidence(evidence))
                .then(|| evidence.clone())
        })
        .flatten()?;
    let boundary_hypotheses = canonical_boundary_hypothesis(knowledge, &evidence)
        .into_iter()
        .collect();
    Some(ApiVisibilityReview {
        resource_scope: resource_scope.clone(),
        comparison_subject: evidence.subject().clone(),
        relation_id: relation.id().clone(),
        evidence,
        boundary_hypotheses,
    })
}

fn is_bounded_review_evidence(evidence: &Evidence) -> bool {
    evidence.source().component().len() <= MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES
}

fn is_canonical_comparison(evidence: &Evidence, relation: &venom_core::KnowledgeRelation) -> bool {
    let Some(digest) = evidence
        .subject()
        .as_str()
        .strip_prefix(COMPARISON_SUBJECT_PREFIX)
    else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && evidence.id().as_str() == format!("{COMPARISON_EVIDENCE_PREFIX}{digest}")
        && relation.id().as_str() == format!("{COMPARISON_RELATION_PREFIX}{digest}")
        && relation.from() == evidence.subject()
        && relation.evidence_ids().len() == 1
        && relation.evidence_ids().contains(evidence.id())
        && relation.confidence() == evidence.reliability()
        && evidence.reliability() != ConfidenceScore::NONE
        && matches!(evidence.kind(), EvidenceKind::Custom(kind) if kind == API_VISIBILITY_EVIDENCE_KIND)
        && evidence.source().method() == API_VISIBILITY_SOURCE_METHOD
        && evidence.source().correlation_id() == Some(evidence.subject().as_str())
        && is_visibility_predicate(evidence.predicate())
        && is_visibility_dimension(evidence.value())
}

fn is_visibility_predicate(predicate: &KnowledgePredicate) -> bool {
    [
        ApiEvidencePredicate::JSON_UI_API_DIFFERENCE,
        ApiEvidencePredicate::JSON_UI_API_EQUIVALENT,
        ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_DIFFERENCE,
        ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_EQUIVALENT,
        ApiEvidencePredicate::GRAPHQL_UI_API_DIFFERENCE,
        ApiEvidencePredicate::GRAPHQL_UI_API_EQUIVALENT,
        ApiEvidencePredicate::GRAPHQL_AUTHORIZATION_CONTEXT_DIFFERENCE,
        ApiEvidencePredicate::GRAPHQL_AUTHORIZATION_CONTEXT_EQUIVALENT,
    ]
    .into_iter()
    .any(|descriptor| descriptor.into_knowledge() == *predicate)
}

fn is_visibility_dimension(value: &EvidenceValue) -> bool {
    ApiVisibilityDimension::all()
        .into_iter()
        .any(|dimension| EvidenceValue::from(dimension) == *value)
}

fn expected_boundary_rule(
    evidence: &Evidence,
) -> Option<(ApiVisibilityBoundaryKind, &'static str)> {
    match evidence.predicate() {
        predicate
            if predicate == &ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge()
                || predicate
                    == &ApiEvidencePredicate::GRAPHQL_UI_API_DIFFERENCE.into_knowledge() =>
        {
            Some((ApiVisibilityBoundaryKind::UiApi, UI_API_BOUNDARY_RULE))
        },
        predicate
            if predicate
                == &ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_DIFFERENCE
                    .into_knowledge()
                || predicate
                    == &ApiEvidencePredicate::GRAPHQL_AUTHORIZATION_CONTEXT_DIFFERENCE
                        .into_knowledge() =>
        {
            Some((
                ApiVisibilityBoundaryKind::AuthorizationContext,
                AUTHORIZATION_BOUNDARY_RULE,
            ))
        },
        _ => None,
    }
}

fn canonical_boundary_hypothesis(
    knowledge: &KnowledgeBase,
    evidence: &Evidence,
) -> Option<Hypothesis> {
    let (_, rule_id) = expected_boundary_rule(evidence)?;
    let hypothesis_id = hypothesis_id_for_rule(rule_id, evidence.subject());
    knowledge
        .inspect_hypothesis(&hypothesis_id, |hypothesis| {
            (is_canonical_boundary_hypothesis(hypothesis, evidence)
                && is_bounded_boundary_hypothesis(hypothesis))
            .then(|| hypothesis.clone())
        })
        .flatten()
}

fn is_bounded_boundary_hypothesis(hypothesis: &Hypothesis) -> bool {
    hypothesis.belief().evidence().iter().all(|observation| {
        observation.rationale().len() <= MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES
    }) && hypothesis
        .belief()
        .updates()
        .iter()
        .all(|update| update.rationale().len() <= MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES)
}

fn is_canonical_boundary_hypothesis(hypothesis: &Hypothesis, evidence: &Evidence) -> bool {
    let Some((boundary, rule_id)) = expected_boundary_rule(evidence) else {
        return false;
    };
    if hypothesis.subject() != evidence.subject()
        || hypothesis.predicate() != &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()
        || hypothesis.strength() != HypothesisStrength::Weak
        || hypothesis.state() != HypothesisState::Supported
        || hypothesis.belief().evidence().len() != 1
        || hypothesis.belief().evidence()[0].evidence_id() != evidence.id()
    {
        return false;
    }

    hypothesis.value() == &EvidenceValue::from(boundary)
        && hypothesis.id() == hypothesis_id_for_rule(rule_id, evidence.subject())
}
