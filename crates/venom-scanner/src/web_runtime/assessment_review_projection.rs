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

#[cfg(feature = "normalization-resilience")]
use super::web_assessment::XssProbeFamily;

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

#[cfg(feature = "normalization-resilience")]
const HTML_TEXT_TOKEN_CASE_NORMALIZATION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.normalization-resilience.xss.html-text-boundary.html-token-case@1",
        "Equivalent HTML token-case representation reached the same inert structure",
        "defense-normalization-gap",
        "A transformed representation and distinct replay reproduced the same inert application parser semantics while the canonical candidate produced candidate-specific defensive blocking; neither XSS execution nor a WAF bypass was confirmed.",
        None,
        1_000_000,
        None,
        "web.remediation.defense-normalization-consistency@1",
        "Align defensive and application normalization for equivalent HTML syntax and manually review the exact rule and parser boundary.",
    );

#[cfg(feature = "normalization-resilience")]
const ATTRIBUTE_VALUE_INTER_TOKEN_TAB_NORMALIZATION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.normalization-resilience.xss.attribute-value-boundary.html-inter-token-tab@1",
        "Equivalent HTML whitespace representation reached the same inert structure",
        "defense-normalization-gap",
        "A transformed representation and distinct replay reproduced the same inert application parser semantics while the canonical candidate produced candidate-specific defensive blocking; neither XSS execution nor a WAF bypass was confirmed.",
        None,
        1_000_000,
        None,
        "web.remediation.defense-normalization-consistency@1",
        "Align defensive and application normalization for equivalent HTML whitespace and manually review the exact rule and parser boundary.",
    );

#[cfg(feature = "normalization-resilience")]
const URI_ATTRIBUTE_INTER_TOKEN_TAB_NORMALIZATION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.normalization-resilience.xss.uri-attribute-boundary.html-inter-token-tab@1",
        "Equivalent URI-attribute whitespace representation reached the same inert structure",
        "defense-normalization-gap",
        "A transformed representation and distinct replay reproduced the same inert application parser semantics while the canonical candidate produced candidate-specific defensive blocking; neither XSS execution nor a WAF bypass was confirmed.",
        None,
        1_000_000,
        None,
        "web.remediation.defense-normalization-consistency@1",
        "Align defensive and application normalization for equivalent URI-attribute syntax and manually review the exact rule and parser boundary.",
    );

#[cfg(feature = "normalization-resilience")]
const EVENT_HANDLER_INTER_TOKEN_TAB_NORMALIZATION_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "web.review.normalization-resilience.xss.event-handler-attribute-boundary.html-inter-token-tab@1",
        "Equivalent event-handler-attribute whitespace representation reached the same inert structure",
        "defense-normalization-gap",
        "A transformed representation and distinct replay reproduced the same inert application parser semantics while the canonical candidate produced candidate-specific defensive blocking; neither XSS execution nor a WAF bypass was confirmed.",
        None,
        1_000_000,
        None,
        "web.remediation.defense-normalization-consistency@1",
        "Align defensive and application normalization for equivalent event-handler-attribute syntax and manually review the exact rule and parser boundary.",
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
    #[cfg(feature = "normalization-resilience")]
    NormalizationHtmlTextTokenCase,
    #[cfg(feature = "normalization-resilience")]
    NormalizationAttributeValueInterTokenTab,
    #[cfg(feature = "normalization-resilience")]
    NormalizationUriAttributeInterTokenTab,
    #[cfg(feature = "normalization-resilience")]
    NormalizationEventHandlerAttributeInterTokenTab,
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
            #[cfg(feature = "normalization-resilience")]
            Self::NormalizationHtmlTextTokenCase => &HTML_TEXT_TOKEN_CASE_NORMALIZATION_REVIEW,
            #[cfg(feature = "normalization-resilience")]
            Self::NormalizationAttributeValueInterTokenTab => {
                &ATTRIBUTE_VALUE_INTER_TOKEN_TAB_NORMALIZATION_REVIEW
            },
            #[cfg(feature = "normalization-resilience")]
            Self::NormalizationUriAttributeInterTokenTab => {
                &URI_ATTRIBUTE_INTER_TOKEN_TAB_NORMALIZATION_REVIEW
            },
            #[cfg(feature = "normalization-resilience")]
            Self::NormalizationEventHandlerAttributeInterTokenTab => {
                &EVENT_HANDLER_INTER_TOKEN_TAB_NORMALIZATION_REVIEW
            },
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
            #[cfg(feature = "normalization-resilience")]
            Self::NormalizationHtmlTextTokenCase
            | Self::NormalizationAttributeValueInterTokenTab
            | Self::NormalizationUriAttributeInterTokenTab
            | Self::NormalizationEventHandlerAttributeInterTokenTab => {
                NativeReviewProjectionBasis::Differential
            },
        }
    }
}

#[derive(Clone)]
struct PlannedAssessmentReviewItem {
    kind: NativeReviewProjectionKind,
    subject: EntityId,
    target: AssessmentItemTarget,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
}

struct PlannedAssessmentReviewLedgerBatch {
    expected_subject: EntityId,
    plans: Vec<PlannedAssessmentReviewItem>,
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

/// Adds every committed native-review ledger to one assessment projection.
///
/// The caller owns subject registration and later consumes the same context
/// for passive and native-review items. All ledgers are planned before any
/// native evidence is registered, so prerequisite evidence shared by an
/// originating reflection item and a selected child item receives exactly one
/// document-local reference. The underlying registration API remains one-shot
/// and deliberately rejects accidental duplicate registration.
pub(crate) fn project_assessment_review_ledgers(
    context: &mut AssessmentProjectionContext,
    ledgers: &[&CommittedAssessmentReviewLedger],
    knowledge: &KnowledgeBase,
) -> Result<usize, AssessmentReviewItemProjectionError> {
    let mut batches = Vec::with_capacity(ledgers.len());
    for ledger in ledgers {
        batches.push(plan_ledger(ledger)?);
    }
    project_batches(context, knowledge, &batches)
}

fn plan_ledger(
    ledger: &CommittedAssessmentReviewLedger,
) -> Result<PlannedAssessmentReviewLedgerBatch, AssessmentReviewItemProjectionError> {
    let candidates = ledger.candidates();
    if candidates.len() > MAX_NATIVE_REVIEW_PROJECTION_ITEMS {
        return Err(AssessmentReviewItemProjectionError::ItemLimit);
    }
    let mut plans = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        if candidate.subject() != ledger.subject() {
            return Err(AssessmentReviewItemProjectionError::CandidateContract);
        }
        plans.push(plan_candidate(candidate)?);
    }
    Ok(PlannedAssessmentReviewLedgerBatch {
        expected_subject: ledger.subject().clone(),
        plans,
    })
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
        #[cfg(feature = "normalization-resilience")]
        AssessmentReviewCandidate::Normalization(_) => {
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
            let transform = candidate
                .normalization_transform()
                .ok_or(AssessmentReviewItemProjectionError::CandidateContract)?;
            let kind = match (transform.id(), transform.revision(), candidate.xss_family()) {
                ("xss.html-token-case", 1, Some(XssProbeFamily::HtmlTextBoundary)) => {
                    NativeReviewProjectionKind::NormalizationHtmlTextTokenCase
                },
                ("xss.html-inter-token-tab", 1, Some(XssProbeFamily::AttributeValueBoundary)) => {
                    NativeReviewProjectionKind::NormalizationAttributeValueInterTokenTab
                },
                ("xss.html-inter-token-tab", 1, Some(XssProbeFamily::UriAttributeBoundary)) => {
                    NativeReviewProjectionKind::NormalizationUriAttributeInterTokenTab
                },
                (
                    "xss.html-inter-token-tab",
                    1,
                    Some(XssProbeFamily::EventHandlerAttributeBoundary),
                ) => NativeReviewProjectionKind::NormalizationEventHandlerAttributeInterTokenTab,
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

#[cfg(test)]
fn project_plans(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    expected_subject: &EntityId,
    plans: &[PlannedAssessmentReviewItem],
) -> Result<(), AssessmentReviewItemProjectionError> {
    let batch = PlannedAssessmentReviewLedgerBatch {
        expected_subject: expected_subject.clone(),
        plans: plans.to_vec(),
    };
    project_batches(context, knowledge, std::slice::from_ref(&batch)).map(|_| ())
}

fn project_batches(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    batches: &[PlannedAssessmentReviewLedgerBatch],
) -> Result<usize, AssessmentReviewItemProjectionError> {
    let mut item_count = 0usize;
    for batch in batches {
        if batch.plans.len() > MAX_NATIVE_REVIEW_PROJECTION_ITEMS
            || batch
                .plans
                .iter()
                .any(|plan| plan.subject != batch.expected_subject)
        {
            return Err(AssessmentReviewItemProjectionError::CandidateContract);
        }
        for plan in &batch.plans {
            validate_plan(plan)?;
            context.preflight_evidence_projection(
                knowledge,
                &plan.subject,
                &plan.target,
                &plan.control_evidence_ids,
            )?;
            context.preflight_evidence_projection(
                knowledge,
                &plan.subject,
                &plan.target,
                &plan.candidate_evidence_ids,
            )?;
        }
        item_count = item_count
            .checked_add(batch.plans.len())
            .ok_or(AssessmentReviewItemProjectionError::ItemLimit)?;
    }

    // Differential items retain both matched legs. Informational reflection
    // items make only the candidate observation visible: their product text
    // does not assert a control relationship, while the sealed ledger may
    // still require a clean control before authorizing that conservative
    // observation. Planning deduplicates product-visible identities globally;
    // strict context registration remains one-shot and non-idempotent.
    let evidence_ids = batches
        .iter()
        .flat_map(|batch| {
            batch.plans.iter().flat_map(|plan| {
                let control =
                    matches!(plan.kind.basis(), NativeReviewProjectionBasis::Differential)
                        .then_some(plan.control_evidence_ids.as_slice())
                        .unwrap_or_default();
                control.iter().chain(&plan.candidate_evidence_ids)
            })
        })
        .collect::<BTreeSet<_>>();
    for evidence_id in evidence_ids {
        context.register_evidence(knowledge, evidence_id)?;
    }

    for batch in batches {
        for plan in &batch.plans {
            match plan.kind.basis() {
                NativeReviewProjectionBasis::Observation => context.project_observation(
                    plan.kind.capability(),
                    knowledge,
                    &plan.subject,
                    &plan.target,
                    &plan.candidate_evidence_ids,
                )?,
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
    }
    Ok(item_count)
}

#[cfg(test)]
#[path = "assessment_review_projection_tests.rs"]
mod tests;
