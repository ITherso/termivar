//! Runtime-owned facade for authorized, host-paired API visibility evidence.

use thiserror::Error;
use venom_core::{ApiVisibilityObservation, EntityId};

use super::StandardWebDecisionRuntime;
use crate::{
    api_visibility_reviews_for_resource, ingest_api_visibility_observation,
    ApiObservationCommitReceipt, ApiObservationError, ApiObservationReceipt,
    ApiVisibilityReviewPage, ApiVisibilityReviewQuery,
};

mod differential;

pub use differential::{
    ApiVisibilityContextProbe, ApiVisibilityDifferentialAudit,
    ApiVisibilityDifferentialDisposition, ApiVisibilityDifferentialRequest,
    ApiVisibilityDifferentialRequestError, ApiVisibilityInconclusiveReason, ApiVisibilityLeg,
    ApiVisibilityLegReceipt, RuntimeApiVisibilityExecutionError, RuntimeApiVisibilityRunReport,
};

/// Failure while using paired API visibility reasoning through a web runtime.
///
/// The wrapper preserves the standalone observation boundary's post-commit
/// receipt. A failed return value therefore does not imply that an observation
/// was rolled back.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeApiVisibilityError {
    /// The runtime was built without API reasoning enabled.
    #[error("API visibility reasoning is disabled for this runtime")]
    ApiReasoningDisabled,

    /// Observation validation, storage, or reasoning failed.
    #[error(transparent)]
    Observation(#[from] ApiObservationError),
}

impl RuntimeApiVisibilityError {
    /// Returns the observation committed before a later reasoning failure.
    pub fn committed_observation(&self) -> Option<&ApiObservationCommitReceipt> {
        match self {
            Self::Observation(source) => source.committed_observation(),
            Self::ApiReasoningDisabled => None,
        }
    }

    /// Takes ownership of an observation committed before a later failure.
    pub fn into_committed_observation(self) -> Option<ApiObservationCommitReceipt> {
        match self {
            Self::Observation(source) => source.into_committed_observation(),
            Self::ApiReasoningDisabled => None,
        }
    }
}

impl StandardWebDecisionRuntime {
    /// Commits one authorized, host-paired API visibility observation.
    ///
    /// The runtime must have API reasoning enabled. Disabled runtimes reject
    /// the call before any write. The host remains responsible for authenticating
    /// the producer, authorizing both compared contexts, and asserting that
    /// `expected_resource` is the same logical resource in both views.
    ///
    /// This boundary accepts no raw response, URL, header, credential, or
    /// principal. It preserves the observation's isolated comparison subject
    /// and never rewrites it to the runtime endpoint subject. Ingestion performs
    /// no request and does not change runtime usage, experience, planning, or
    /// decision-session state. Exact replay remains idempotent.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use url::Url;
    /// use venom_scanner::{
    ///     ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension,
    ///     ApiVisibilityPairKind, ApiVisibilityResult, ApiVisibilityReviewQuery,
    ///     ConfidenceScore, EntityId, StandardWebDecisionRuntime,
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
    /// .to_observation("host.api-comparator", ConfidenceScore::MAX)?;
    /// let mut runtime = StandardWebDecisionRuntime::builder(
    ///     Url::parse("https://example.test/api/accounts/42")?,
    /// )
    /// .enable_api_reasoning()
    /// .build()?;
    ///
    /// runtime.ingest_api_visibility(observation, &resource)?;
    /// let page = runtime.api_visibility_reviews(
    ///     &resource,
    ///     &ApiVisibilityReviewQuery::default(),
    /// )?;
    /// assert_eq!(page.reviews().len(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn ingest_api_visibility(
        &mut self,
        observation: ApiVisibilityObservation,
        expected_resource: &EntityId,
    ) -> Result<ApiObservationReceipt, RuntimeApiVisibilityError> {
        if self.api_reasoning_installation.is_none() {
            return Err(RuntimeApiVisibilityError::ApiReasoningDisabled);
        }

        ingest_api_visibility_observation(
            observation,
            expected_resource,
            self.authority.knowledge(),
            self.decision_loop.rules(),
        )
        .map_err(Into::into)
    }

    /// Returns one cursor-bounded page of paired-visibility reviews.
    ///
    /// Review projection is available only when API reasoning was explicitly
    /// enabled. It reads the runtime's comparison subjects without feeding
    /// their hypotheses into the endpoint planner or decision session.
    pub fn api_visibility_reviews(
        &self,
        resource: &EntityId,
        query: &ApiVisibilityReviewQuery,
    ) -> Result<ApiVisibilityReviewPage, RuntimeApiVisibilityError> {
        if self.api_reasoning_installation.is_none() {
            return Err(RuntimeApiVisibilityError::ApiReasoningDisabled);
        }

        Ok(api_visibility_reviews_for_resource(
            self.authority.knowledge(),
            resource,
            query,
        ))
    }
}

#[cfg(test)]
mod tests;
