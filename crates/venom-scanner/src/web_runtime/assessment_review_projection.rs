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

const MAX_NATIVE_REVIEW_PROJECTION_ITEMS: usize = 5;

const SSTI_STRUCTURAL_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.ssti.structural-evaluation@1",
        "Repeatable server-side template arithmetic evaluation behavior",
        "template-expression-evaluation",
        "Two independent matched arithmetic pairs produced their exact candidate-specific computed values; no command execution or stronger template-engine verification was attempted.",
        None,
        1_000_000,
        Some("CWE-1336"),
        "web.remediation.template-input-separation@1",
        "Keep untrusted input out of template source and review the exact rendering path manually before treating this behavioral signal as a vulnerability.",
    );

const SQL_STRUCTURAL_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.sql.structural-differential@1",
        "Repeatable SQL parser-oriented structural difference",
        "sql-structural-behavior",
        "Two independent matched pairs produced the same candidate-specific status-class and normalized body-structure change; no database access or exploitation was confirmed.",
        None,
        1_000_000,
        Some("CWE-89"),
        "web.remediation.sql-parameterization@1",
        "Review server-side query construction and use parameterized statements; validate the exact cause manually before treating this as a vulnerability.",
    );

const XSS_STRUCTURAL_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.xss.structural-boundary@1",
        "Context-specific reflected syntax changed parsed structure",
        "xss-structural-control",
        "A matched non-executing probe produced candidate-specific parser-visible structural control in a compatible reflected-input context; JavaScript or browser execution was not tested.",
        None,
        1_000_000,
        Some("CWE-79"),
        "web.remediation.contextual-output-encoding@1",
        "Apply encoding for the exact output context and separately authorize execution verification before treating this structural signal as exploitable XSS.",
    );

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

const URI_REFLECTION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.reflection.uri-attribute-context@1",
        "Reflected input reached a URI-bearing HTML attribute",
        "reflection-context",
        "The scanner marker was absent from the control and appeared in a URI-bearing attribute; executable URI behavior was not tested.",
        None,
        1_000_000,
        None,
        "web.remediation.contextual-output-encoding@1",
        "Apply context-appropriate encoding and constrain URI destinations and schemes before a separately authorized execution review.",
    );

const STYLE_REFLECTION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.reflection.style-context@1",
        "Reflected input reached an HTML style context",
        "reflection-context",
        "The scanner marker was absent from the control and appeared in a style attribute or style element; CSS execution or exfiltration was not tested.",
        None,
        1_000_000,
        None,
        "web.remediation.contextual-output-encoding@1",
        "Keep untrusted input out of CSS source and apply encoding appropriate to the exact style context.",
    );

const EVENT_HANDLER_REFLECTION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.reflection.event-handler-context@1",
        "Reflected input reached an inline event-handler attribute",
        "reflection-context",
        "The scanner marker was absent from the control and appeared in an inline event-handler attribute; JavaScript execution was not tested.",
        None,
        1_000_000,
        None,
        "web.remediation.contextual-output-encoding@1",
        "Do not place untrusted data in inline event handlers; use data-only DOM APIs and separately authorize any execution verification.",
    );

const SCRIPT_REFLECTION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.reflection.script-element-context@1",
        "Reflected input reached script element content",
        "reflection-context",
        "The scanner marker was absent from the control and appeared in script element content; JavaScript grammar and execution were not tested.",
        None,
        1_000_000,
        None,
        "web.remediation.contextual-output-encoding@1",
        "Keep untrusted input out of script source and serialize data with a context-safe mechanism.",
    );

const EMBEDDED_HTML_REFLECTION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.reflection.embedded-html-attribute-context@1",
        "Reflected input reached an embedded-HTML attribute",
        "reflection-context",
        "The scanner marker was absent from the control and appeared in an attribute interpreted as embedded HTML; browser execution was not tested.",
        None,
        1_000_000,
        None,
        "web.remediation.contextual-output-encoding@1",
        "Avoid placing untrusted input in embedded HTML and apply an allowlist-based sanitizer when markup is required.",
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
    UriAttributeReflection,
    StyleReflection,
    EventHandlerReflection,
    ScriptElementReflection,
    EmbeddedHtmlReflection,
    SqlStructuralDifferential,
    SstiStructuralEvaluation,
    XssStructuralBoundary,
}

impl NativeReviewProjectionKind {
    const fn capability(self) -> &'static AssessmentCapabilityDescriptor {
        match self {
            Self::CorsCredentialedExternalOrigin => &CORS_CREDENTIALS_REVIEW,
            Self::CandidateSpecificExternalRedirect => &OPEN_REDIRECT_REVIEW,
            Self::InertReflection => &INERT_REFLECTION_OBSERVATION,
            Self::TextReflection => &TEXT_REFLECTION_OBSERVATION,
            Self::AttributeReflection => &ATTRIBUTE_REFLECTION_OBSERVATION,
            Self::UriAttributeReflection => &URI_REFLECTION_REVIEW,
            Self::StyleReflection => &STYLE_REFLECTION_REVIEW,
            Self::EventHandlerReflection => &EVENT_HANDLER_REFLECTION_REVIEW,
            Self::ScriptElementReflection => &SCRIPT_REFLECTION_REVIEW,
            Self::EmbeddedHtmlReflection => &EMBEDDED_HTML_REFLECTION_REVIEW,
            Self::SqlStructuralDifferential => &SQL_STRUCTURAL_REVIEW,
            Self::SstiStructuralEvaluation => &SSTI_STRUCTURAL_REVIEW,
            Self::XssStructuralBoundary => &XSS_STRUCTURAL_REVIEW,
        }
    }

    const fn basis(self) -> NativeReviewProjectionBasis {
        match self {
            Self::InertReflection | Self::TextReflection | Self::AttributeReflection => {
                NativeReviewProjectionBasis::Observation
            },
            Self::CorsCredentialedExternalOrigin
            | Self::CandidateSpecificExternalRedirect
            | Self::UriAttributeReflection
            | Self::StyleReflection
            | Self::EventHandlerReflection
            | Self::ScriptElementReflection
            | Self::EmbeddedHtmlReflection
            | Self::SqlStructuralDifferential => NativeReviewProjectionBasis::Differential,
            Self::SstiStructuralEvaluation => NativeReviewProjectionBasis::Differential,
            Self::XssStructuralBoundary => NativeReviewProjectionBasis::Differential,
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
                (
                    Some(ReviewReflectionContext::HtmlComment),
                    NativeReviewDisposition::Informational,
                ) => NativeReviewProjectionKind::InertReflection,
                (
                    Some(ReviewReflectionContext::HtmlText),
                    NativeReviewDisposition::Informational,
                ) => NativeReviewProjectionKind::TextReflection,
                (
                    Some(ReviewReflectionContext::AttributeValue),
                    NativeReviewDisposition::Informational,
                ) => NativeReviewProjectionKind::AttributeReflection,
                (
                    Some(ReviewReflectionContext::UriAttribute),
                    NativeReviewDisposition::NeedsReview,
                ) => NativeReviewProjectionKind::UriAttributeReflection,
                (
                    Some(
                        ReviewReflectionContext::StyleAttribute
                        | ReviewReflectionContext::StyleElementContent,
                    ),
                    NativeReviewDisposition::NeedsReview,
                ) => NativeReviewProjectionKind::StyleReflection,
                (
                    Some(ReviewReflectionContext::EventHandlerAttribute),
                    NativeReviewDisposition::NeedsReview,
                ) => NativeReviewProjectionKind::EventHandlerReflection,
                (
                    Some(ReviewReflectionContext::ScriptElementContent),
                    NativeReviewDisposition::NeedsReview,
                ) => NativeReviewProjectionKind::ScriptElementReflection,
                (
                    Some(ReviewReflectionContext::EmbeddedHtmlAttribute),
                    NativeReviewDisposition::NeedsReview,
                ) => NativeReviewProjectionKind::EmbeddedHtmlReflection,
                _ => return Err(AssessmentReviewItemProjectionError::CandidateContract),
            };
            (
                kind,
                AssessmentItemTarget::query_parameter(query_parameter)?,
            )
        },
        AssessmentReviewCandidate::SqlStructural(_) => {
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
                NativeReviewProjectionKind::SqlStructuralDifferential,
                AssessmentItemTarget::query_parameter(query_parameter)?,
            )
        },
        AssessmentReviewCandidate::SstiStructural(_) => {
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
                NativeReviewProjectionKind::SstiStructuralEvaluation,
                AssessmentItemTarget::query_parameter(query_parameter)?,
            )
        },
        AssessmentReviewCandidate::XssStructural(_) => {
            if candidate.disposition() != NativeReviewDisposition::NeedsReview
                || candidate.reflection_context().is_some()
                || candidate.cors_status_relationship().is_some()
                || candidate.xss_family().is_none()
            {
                return Err(AssessmentReviewItemProjectionError::CandidateContract);
            }
            let query_parameter = candidate
                .query_parameter()
                .ok_or(AssessmentReviewItemProjectionError::CandidateContract)?;
            (
                NativeReviewProjectionKind::XssStructuralBoundary,
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
