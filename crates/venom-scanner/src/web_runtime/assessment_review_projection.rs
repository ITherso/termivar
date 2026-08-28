//! Claim-safe product projection for committed native web-review pairs.
//!
//! The matched-pair ledger owns response interpretation and verifier replay.
//! This module can only map its closed candidate vocabulary into the existing
//! assessment projection authority. No candidate handled here has a
//! confirmation-capable descriptor or a verifier projection path.

use std::collections::BTreeSet;

use thiserror::Error;
use venom_core::{EntityId, EvidenceId};

use crate::KnowledgeBase;

use super::{
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext, MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES,
    },
    assessment_review::{
        AssessmentReviewCandidate, CommittedAssessmentReviewLedger, CorsStatusRelationship,
        NativeReviewDisposition, ReviewReflectionContext,
    },
};

const MAX_NATIVE_REVIEW_PROJECTION_ITEMS: usize = 3;

const CORS_CREDENTIALS_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.cors.credentialed-external-origin@1",
        "Credentialed CORS response accepted an external origin",
        "cross-origin-policy",
        "Matched control and candidate responses indicate credentialed cross-origin access for the scanner-generated review origin.",
        None,
        1_000_000,
        Some("CWE-942"),
        "web.remediation.cors-origin-policy@1",
        "Authorize credentialed cross-origin access only for explicitly trusted origins and validate the complete response policy.",
    );

const OPEN_REDIRECT_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.redirect.candidate-specific-external@1",
        "Candidate-specific external redirect was observed",
        "redirect-policy",
        "A matched control and candidate pair returned the exact scanner-generated external destination without following the redirect.",
        None,
        1_000_000,
        Some("CWE-601"),
        "web.remediation.redirect-destination@1",
        "Resolve redirects through an explicit allowlist or server-owned destination identifier instead of accepting an arbitrary destination.",
    );

const DANGEROUS_REFLECTION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.reflection.dangerous-html-context@1",
        "Exact candidate reflection reached a dangerous HTML context",
        "reflection-context",
        "The exact scanner-generated candidate was absent from the control and appeared in a dangerous HTML parsing context; browser execution was not tested.",
        None,
        1_000_000,
        None,
        "web.remediation.contextual-output-encoding@1",
        "Apply output encoding for the destination context and validate the rendered behavior with an authorized browser-level review.",
    );

const INERT_REFLECTION_OBSERVATION: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.review.reflection.inert-context@1",
        "Exact candidate reflection appeared in an inert HTML context",
        "reflection-context",
        "The exact scanner-generated candidate appeared only in an inert HTML context; no script execution was tested.",
        1_000_000,
        "web.remediation.reflection-review@1",
        "Review whether reflecting this input is necessary and preserve context-appropriate output encoding.",
    );

const TEXT_REFLECTION_OBSERVATION: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.review.reflection.text-context@1",
        "Exact candidate reflection appeared in HTML text",
        "reflection-context",
        "The exact scanner-generated candidate appeared as HTML text; no script execution was tested.",
        1_000_000,
        "web.remediation.reflection-review@1",
        "Review whether reflecting this input is necessary and preserve context-appropriate output encoding.",
    );

const ATTRIBUTE_REFLECTION_OBSERVATION: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "web.review.reflection.attribute-context@1",
        "Exact candidate reflection appeared in an HTML attribute",
        "reflection-context",
        "The exact scanner-generated candidate appeared in an HTML attribute; no script execution was tested.",
        1_000_000,
        "web.remediation.contextual-output-encoding@1",
        "Apply output encoding for the destination attribute context and validate the rendered behavior separately.",
    );

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeReviewProjectionBasis {
    Observation,
    Differential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeReviewProjectionKind {
    CorsCredentialedExternalOrigin,
    CandidateSpecificExternalRedirect,
    InertReflection,
    TextReflection,
    AttributeReflection,
    DangerousReflection,
}

impl NativeReviewProjectionKind {
    const fn capability(self) -> &'static AssessmentCapabilityDescriptor {
        match self {
            Self::CorsCredentialedExternalOrigin => &CORS_CREDENTIALS_REVIEW,
            Self::CandidateSpecificExternalRedirect => &OPEN_REDIRECT_REVIEW,
            Self::InertReflection => &INERT_REFLECTION_OBSERVATION,
            Self::TextReflection => &TEXT_REFLECTION_OBSERVATION,
            Self::AttributeReflection => &ATTRIBUTE_REFLECTION_OBSERVATION,
            Self::DangerousReflection => &DANGEROUS_REFLECTION_REVIEW,
        }
    }

    const fn basis(self) -> NativeReviewProjectionBasis {
        match self {
            Self::InertReflection | Self::TextReflection | Self::AttributeReflection => {
                NativeReviewProjectionBasis::Observation
            },
            Self::CorsCredentialedExternalOrigin
            | Self::CandidateSpecificExternalRedirect
            | Self::DangerousReflection => NativeReviewProjectionBasis::Differential,
        }
    }
}

struct PlannedAssessmentReviewItem {
    kind: NativeReviewProjectionKind,
    subject: EntityId,
    target: AssessmentItemTarget,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

/// Fail-closed errors from reducing a committed review candidate into the
/// product item vocabulary. Variants deliberately retain no URL, query value,
/// response field, body, credential, or case identity.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum AssessmentReviewItemProjectionError {
    #[error("committed native review candidate violates its projection contract")]
    CandidateContract,
    #[error("native review item count exceeds its compiled maximum")]
    ItemLimit,
    #[error(transparent)]
    Item(#[from] AssessmentItemProjectionError),
}

/// Adds review items to an existing assessment projection context.
///
/// The caller owns subject registration and later consumes the same context
/// for both passive and native-review items. This avoids minting an unrelated
/// reference space or merging independently projected item sets.
pub(crate) fn project_assessment_review_items(
    context: &mut AssessmentProjectionContext,
    ledger: &CommittedAssessmentReviewLedger,
    knowledge: &KnowledgeBase,
    authorized_root_subject: &EntityId,
) -> Result<usize, AssessmentReviewItemProjectionError> {
    let candidates = ledger.candidates();
    if candidates.len() > MAX_NATIVE_REVIEW_PROJECTION_ITEMS {
        return Err(AssessmentReviewItemProjectionError::ItemLimit);
    }
    let mut plans = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        if candidate.subject() != authorized_root_subject {
            return Err(AssessmentReviewItemProjectionError::CandidateContract);
        }
        plans.push(plan_candidate(candidate)?);
    }
    project_plans(context, knowledge, authorized_root_subject, &plans)?;
    Ok(plans.len())
}

fn plan_candidate(
    candidate: &AssessmentReviewCandidate,
) -> Result<PlannedAssessmentReviewItem, AssessmentReviewItemProjectionError> {
    let (kind, target) = match candidate {
        AssessmentReviewCandidate::Cors(_) => {
            if candidate.disposition() != NativeReviewDisposition::NeedsReview
                || candidate.query_parameter().is_some()
                || candidate.reflection_context().is_some()
                || candidate.cors_status_relationship()
                    != Some(CorsStatusRelationship::MatchedSuccessful)
            {
                return Err(AssessmentReviewItemProjectionError::CandidateContract);
            }
            (
                NativeReviewProjectionKind::CorsCredentialedExternalOrigin,
                AssessmentItemTarget::subject(),
            )
        },
        AssessmentReviewCandidate::Redirect(_) => {
            if candidate.disposition() != NativeReviewDisposition::NeedsReview
                || candidate.reflection_context().is_some()
                || candidate.cors_status_relationship().is_some()
            {
                return Err(AssessmentReviewItemProjectionError::CandidateContract);
            }
            let query_parameter = candidate
                .query_parameter()
                .ok_or(AssessmentReviewItemProjectionError::CandidateContract)?;
            (
                NativeReviewProjectionKind::CandidateSpecificExternalRedirect,
                AssessmentItemTarget::query_parameter(query_parameter)?,
            )
        },
        AssessmentReviewCandidate::Reflection(_) => {
            if candidate.cors_status_relationship().is_some() {
                return Err(AssessmentReviewItemProjectionError::CandidateContract);
            }
            let query_parameter = candidate
                .query_parameter()
                .ok_or(AssessmentReviewItemProjectionError::CandidateContract)?;
            let kind = match (candidate.reflection_context(), candidate.disposition()) {
                (Some(ReviewReflectionContext::Inert), NativeReviewDisposition::Informational) => {
                    NativeReviewProjectionKind::InertReflection
                },
                (Some(ReviewReflectionContext::Text), NativeReviewDisposition::Informational) => {
                    NativeReviewProjectionKind::TextReflection
                },
                (
                    Some(ReviewReflectionContext::Attribute),
                    NativeReviewDisposition::Informational,
                ) => NativeReviewProjectionKind::AttributeReflection,
                (
                    Some(ReviewReflectionContext::Dangerous),
                    NativeReviewDisposition::NeedsReview,
                ) => NativeReviewProjectionKind::DangerousReflection,
                _ => return Err(AssessmentReviewItemProjectionError::CandidateContract),
            };
            (
                kind,
                AssessmentItemTarget::query_parameter(query_parameter)?,
            )
        },
    };
    let plan = PlannedAssessmentReviewItem {
        kind,
        subject: candidate.subject().clone(),
        target,
        control_evidence_ids: candidate.control_evidence_ids().to_vec(),
        candidate_evidence_ids: candidate.candidate_evidence_ids().to_vec(),
    };
    validate_plan(&plan)?;
    Ok(plan)
}

fn validate_plan(
    plan: &PlannedAssessmentReviewItem,
) -> Result<(), AssessmentReviewItemProjectionError> {
    if plan.control_evidence_ids.is_empty()
        || plan.candidate_evidence_ids.is_empty()
        || plan
            .control_evidence_ids
            .len()
            .saturating_add(plan.candidate_evidence_ids.len())
            > MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES
    {
        return Err(AssessmentReviewItemProjectionError::CandidateContract);
    }
    let mut identities = BTreeSet::new();
    for evidence_id in plan
        .control_evidence_ids
        .iter()
        .chain(&plan.candidate_evidence_ids)
    {
        if !identities.insert(evidence_id) {
            return Err(AssessmentReviewItemProjectionError::CandidateContract);
        }
    }
    Ok(())
}

fn project_plans(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    authorized_root_subject: &EntityId,
    plans: &[PlannedAssessmentReviewItem],
) -> Result<(), AssessmentReviewItemProjectionError> {
    if plans.len() > MAX_NATIVE_REVIEW_PROJECTION_ITEMS
        || plans
            .iter()
            .any(|plan| &plan.subject != authorized_root_subject)
    {
        return Err(AssessmentReviewItemProjectionError::CandidateContract);
    }
    for plan in plans {
        validate_plan(plan)?;
    }

    // Differential items retain both matched legs. Informational reflection
    // items make only the candidate observation visible: their product text
    // does not assert a control relationship, while the sealed ledger may
    // still require a clean control before authorizing that conservative
    // observation. Register each referenced identity once in deterministic
    // order.
    let evidence_ids = plans
        .iter()
        .flat_map(|plan| {
            let control = matches!(plan.kind.basis(), NativeReviewProjectionBasis::Differential)
                .then_some(plan.control_evidence_ids.as_slice())
                .unwrap_or_default();
            control.iter().chain(&plan.candidate_evidence_ids)
        })
        .collect::<BTreeSet<_>>();
    for evidence_id in evidence_ids {
        context.register_evidence(knowledge, evidence_id)?;
    }

    for plan in plans {
        match plan.kind.basis() {
            NativeReviewProjectionBasis::Observation => {
                context.project_observation(
                    plan.kind.capability(),
                    knowledge,
                    &plan.subject,
                    &plan.target,
                    &plan.candidate_evidence_ids,
                )?;
            },
            NativeReviewProjectionBasis::Differential => context.project_differential(
                plan.kind.capability(),
                knowledge,
                &plan.subject,
                &plan.target,
                &plan.control_evidence_ids,
                &plan.candidate_evidence_ids,
            )?,
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "assessment_review_projection_tests.rs"]
mod tests;
