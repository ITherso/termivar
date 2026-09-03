//! Root-scoped authorization-context review for the bounded assessment runtime.
//!
//! This module composes the existing API visibility comparator under the
//! assessment's shared authority. It never creates a second broker or budget,
//! never serializes credential material, and projects only the comparator's
//! single canonical paired-comparison evidence object.

use std::fmt;

use termivar_core::{ApiVisibilityDimension, EntityId};
use thiserror::Error;
use url::Url;

use crate::{
    ApiAuthorizationContextPairStrategy, ApiComparisonProfile, ApiObservationCommitReceipt,
    ApiVisibilityContextProbe, ApiVisibilityDifferentialDisposition,
    ApiVisibilityDifferentialRequest, ApiVisibilityReview, ApiVisibilityReviewDisposition,
    HttpProbe, HttpProbeMethod, PayloadSeed, PayloadStrategy, PayloadStrategyLimits,
    PayloadVariantRole, RuntimeApiVisibilityExecutionError, StandardWebDecisionRuntime,
    API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME,
};

use super::{
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentProjectionContext,
    },
    SharedWebRuntimeAuthority,
};

const ROOT_COMPARISON_ID: &str = "web-assessment-root-authorization-context@1";
const ANONYMOUS_CONTEXT_ID: &str = "context:web-assessment:anonymous";
const AUTHORIZED_CONTEXT_ID: &str = "context:web-assessment:host-authorized";

const API_AUTHORIZATION_VISIBILITY_REVIEW: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "api.review.authorization-context.visibility-difference@1",
        "Authorization contexts returned different JSON visibility",
        "api-authorization-context",
        "One atomic anonymous/authorized JSON comparison indicates a visibility difference that may be intentional and requires policy review.",
        None,
        1_000_000,
        None,
        "api.remediation.authorization-context-policy@1",
        "Review the intended authorization policy for this resource and verify that each context receives only its permitted fields.",
    );

/// Host-supplied complete `Authorization` header value for the authorized root.
///
/// The value is accepted only as bounded, visible ASCII through the existing
/// `api.authorization.context-pair@1` strategy. This type intentionally
/// implements neither `Clone` nor `Serialize`; its debug representation is
/// fully redacted.
pub struct WebAssessmentRootAuthorizationContext {
    candidate_header_value: String,
}

impl WebAssessmentRootAuthorizationContext {
    /// Validates one complete header value without performing network I/O.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, WebAssessmentAuthorizationContextError> {
        let limits = PayloadStrategyLimits::default();
        let seed = PayloadSeed::new(value, limits)
            .map_err(|_| WebAssessmentAuthorizationContextError::InvalidValue)?;
        let strategy = ApiAuthorizationContextPairStrategy::new();
        let control = strategy
            .derive_one(PayloadVariantRole::Control, &seed, limits)
            .map_err(|_| WebAssessmentAuthorizationContextError::InvalidValue)?;
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits)
            .map_err(|_| WebAssessmentAuthorizationContextError::InvalidValue)?;
        if !control.as_bytes().is_empty()
            || control.role() != PayloadVariantRole::Control
            || candidate.role() != PayloadVariantRole::Candidate
        {
            return Err(WebAssessmentAuthorizationContextError::InvalidValue);
        }
        let candidate_header_value = String::from_utf8(candidate.as_bytes().to_vec())
            .map_err(|_| WebAssessmentAuthorizationContextError::InvalidValue)?;
        Ok(Self {
            candidate_header_value,
        })
    }

    fn into_candidate_header_value(self) -> String {
        self.candidate_header_value
    }
}

impl fmt::Debug for WebAssessmentRootAuthorizationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebAssessmentRootAuthorizationContext(<redacted>)")
    }
}

/// Static, value-free authorization-context validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum WebAssessmentAuthorizationContextError {
    #[error("authorization context is not a bounded safe HTTP header value")]
    InvalidValue,
}

pub(super) struct RootApiVisibilityRuntime {
    runtime: StandardWebDecisionRuntime,
    request: Option<ApiVisibilityDifferentialRequest>,
}

impl fmt::Debug for RootApiVisibilityRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootApiVisibilityRuntime")
            .field("runtime", &"<shared-authority>")
            .field("request", &"<redacted>")
            .finish()
    }
}

impl RootApiVisibilityRuntime {
    pub(super) async fn execute(
        &mut self,
    ) -> Result<RootApiVisibilityOutcome, RuntimeApiVisibilityExecutionError> {
        let request = self
            .request
            .take()
            .ok_or(RuntimeApiVisibilityExecutionError::AlreadyStarted)?;
        let report = self.runtime.run_api_visibility_pair(request).await?;
        Ok(RootApiVisibilityOutcome::from_report(&report))
    }
}

pub(super) fn build_root_api_visibility_runtime(
    target: &Url,
    resource_scope: EntityId,
    authority: SharedWebRuntimeAuthority,
    context: WebAssessmentRootAuthorizationContext,
) -> Result<RootApiVisibilityRuntime, RootApiVisibilityCompositionError> {
    let control = HttpProbe::new(target.clone(), HttpProbeMethod::Get)
        .and_then(|probe| probe.with_header("accept", "application/json"))
        .map_err(|_| RootApiVisibilityCompositionError)?;
    let candidate = HttpProbe::new(target.clone(), HttpProbeMethod::Get)
        .and_then(|probe| probe.with_header("accept", "application/json"))
        .and_then(|probe| {
            probe.with_header(
                API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME,
                context.into_candidate_header_value(),
            )
        })
        .map_err(|_| RootApiVisibilityCompositionError)?;
    let request = ApiVisibilityDifferentialRequest::new(
        ROOT_COMPARISON_ID,
        resource_scope,
        ApiVisibilityContextProbe::new(ANONYMOUS_CONTEXT_ID, control)
            .map_err(|_| RootApiVisibilityCompositionError)?,
        ApiVisibilityContextProbe::new(AUTHORIZED_CONTEXT_ID, candidate)
            .map_err(|_| RootApiVisibilityCompositionError)?,
        [API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME],
        ApiComparisonProfile::default(),
        ApiVisibilityDimension::Fields,
        // CLI hosts have no trusted wall-clock observation authority. Runtime
        // classification and fingerprints deliberately do not depend on this.
        0,
    )
    .map_err(|_| RootApiVisibilityCompositionError)?;
    let runtime = StandardWebDecisionRuntime::builder(target.clone())
        .enable_api_reasoning()
        .build_with_shared_authority(authority)
        .map_err(|_| RootApiVisibilityCompositionError)?;
    Ok(RootApiVisibilityRuntime {
        runtime,
        request: Some(request),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("root API authorization-context review could not be composed safely")]
pub(super) struct RootApiVisibilityCompositionError;

#[derive(Clone)]
pub(super) struct CommittedAssessmentApiVisibility {
    commit: ApiObservationCommitReceipt,
    review: ApiVisibilityReview,
}

impl fmt::Debug for CommittedAssessmentApiVisibility {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedAssessmentApiVisibility")
            .field("commit", &"<redacted>")
            .field("review", &"<redacted>")
            .finish()
    }
}

impl CommittedAssessmentApiVisibility {
    pub(super) fn commit(&self) -> &ApiObservationCommitReceipt {
        &self.commit
    }

    pub(super) fn review(&self) -> &ApiVisibilityReview {
        &self.review
    }
}

#[derive(Debug)]
pub(super) enum RootApiVisibilityOutcome {
    NoDifference,
    NeedsReview(Box<CommittedAssessmentApiVisibility>),
    Incomplete,
    Cancelled,
    RuntimeLimit(crate::RuntimeBudgetDimension),
    ContractMismatch,
}

impl RootApiVisibilityOutcome {
    fn from_report(report: &crate::RuntimeApiVisibilityRunReport) -> Self {
        match report.disposition() {
            ApiVisibilityDifferentialDisposition::NoDifferenceObserved => {
                if exact_committed_review(
                    report,
                    ApiVisibilityReviewDisposition::NoDifferenceObserved,
                )
                .is_some()
                {
                    Self::NoDifference
                } else {
                    Self::ContractMismatch
                }
            },
            ApiVisibilityDifferentialDisposition::AwaitHumanReview => {
                exact_committed_review(report, ApiVisibilityReviewDisposition::AwaitHumanReview)
                    .map(|committed| Self::NeedsReview(Box::new(committed)))
                    .unwrap_or(Self::ContractMismatch)
            },
            ApiVisibilityDifferentialDisposition::UnresolvedDifference => {
                if exact_committed_review(
                    report,
                    ApiVisibilityReviewDisposition::UnresolvedDifference,
                )
                .is_some()
                {
                    Self::Incomplete
                } else {
                    Self::ContractMismatch
                }
            },
            ApiVisibilityDifferentialDisposition::Inconclusive => Self::Incomplete,
            ApiVisibilityDifferentialDisposition::CancelledByHost => Self::Cancelled,
            ApiVisibilityDifferentialDisposition::RuntimeBudgetLimit => report
                .limit_exceeded()
                .map(|limit| Self::RuntimeLimit(limit.dimension()))
                .unwrap_or(Self::ContractMismatch),
        }
    }
}

fn exact_committed_review(
    report: &crate::RuntimeApiVisibilityRunReport,
    expected: ApiVisibilityReviewDisposition,
) -> Option<CommittedAssessmentApiVisibility> {
    let observation = report.observation()?;
    let review = report.review()?;
    (review.disposition() == expected
        && review.resource_scope() == observation.commit().resource_scope()
        && review.comparison_subject() == observation.commit().comparison_subject()
        && review.relation_id() == observation.commit().relation_id()
        && review.evidence().id() == observation.commit().evidence_id())
    .then(|| CommittedAssessmentApiVisibility {
        commit: observation.commit().clone(),
        review: review.clone(),
    })
}

pub(super) fn project_api_visibility_item(
    context: &mut AssessmentProjectionContext,
    knowledge: &crate::KnowledgeBase,
    authorized_root_subject: &EntityId,
    committed: &CommittedAssessmentApiVisibility,
) -> Result<(), AssessmentItemProjectionError> {
    context.project_api_visibility_paired_comparison(
        &API_AUTHORIZATION_VISIBILITY_REVIEW,
        knowledge,
        authorized_root_subject,
        committed.commit(),
        committed.review(),
    )
}
