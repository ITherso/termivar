//! Metered execution for one host-authorized API visibility pair.

use sha2::{Digest, Sha256};
use termivar_core::{ApiSurfaceKind, ApiVisibilityPairKind};

use super::super::super::{await_execution, RuntimeExecution, StandardWebDecisionRuntime};
use super::{
    encode_digest, update_framed, ApiVisibilityDifferentialAudit,
    ApiVisibilityDifferentialDisposition, ApiVisibilityDifferentialRequest,
    ApiVisibilityInconclusiveReason, ApiVisibilityLeg, ApiVisibilityLegReceipt,
    RuntimeApiVisibilityExecutionError, RuntimeApiVisibilityRunReport,
};
use crate::{
    api_observation::{api_visibility_review_for_commit, ingest_api_visibility_observation},
    ApiObservationReceipt, ApiVisibilityComparator, ApiVisibilityReview,
    ApiVisibilityReviewDisposition, DecisionExecutionClass, DecisionExecutionFailureKind,
    DecisionExecutionStage, ProfiledApiVisibilityComparison, ProfiledApiVisibilityError,
    RuntimeLimitExceeded,
};

const CONTROL_ACTION_ID: &str = "api.visibility.authorization-context.control";
const CANDIDATE_ACTION_ID: &str = "api.visibility.authorization-context.candidate";
const OBSERVATION_COMPONENT: &str = "runtime.api-visibility-differential";
const RESPONSE_DIGEST_DOMAIN: &[u8] = b"venom.api-visibility.response-body.v1\0";

impl StandardWebDecisionRuntime {
    /// Executes one authorized, same-target JSON authorization-context pair.
    ///
    /// Both legs use isolated broker pools backed by the runtime's shared
    /// accounting authority, are charged as active verifications, and are
    /// independently cancellation/budget bounded. Only
    /// two complete JSON views reach Comparator V3 and atomic observation
    /// ingestion. A difference can yield
    /// [`ApiVisibilityDifferentialDisposition::AwaitHumanReview`], never a
    /// vulnerability verdict or decision-loop success.
    ///
    /// Once pre-I/O configuration and target checks pass, this operation
    /// consumes the runtime's single-use execution right even on cancellation
    /// or transport failure. Use another runtime instance for the standard
    /// endpoint analysis workflow.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use url::Url;
    /// use termivar_scanner::{
    ///     ApiComparisonProfile, ApiVisibilityContextProbe,
    ///     ApiVisibilityDifferentialRequest, ApiVisibilityDimension, EntityId,
    ///     HttpProbe, HttpProbeMethod, StandardWebDecisionRuntime,
    /// };
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let target = Url::parse("https://example.test/api/account")?;
    /// let control = HttpProbe::new(target.clone(), HttpProbeMethod::Get)?
    ///     .with_header("authorization", "Bearer control-context")?;
    /// let candidate = HttpProbe::new(target.clone(), HttpProbeMethod::Get)?
    ///     .with_header("authorization", "Bearer candidate-context")?;
    /// let request = ApiVisibilityDifferentialRequest::new(
    ///     "comparison-1",
    ///     EntityId::new("resource:account")?,
    ///     ApiVisibilityContextProbe::new("context:control", control)?,
    ///     ApiVisibilityContextProbe::new("context:candidate", candidate)?,
    ///     ["authorization"],
    ///     ApiComparisonProfile::default(),
    ///     ApiVisibilityDimension::Fields,
    ///     1_800_000_000_000,
    /// )?;
    /// let mut runtime = StandardWebDecisionRuntime::builder(target)
    ///     .enable_api_reasoning()
    ///     .build()?;
    ///
    /// let report = runtime.run_api_visibility_pair(request).await?;
    /// assert_eq!(report.audit().usage().total_requests(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_api_visibility_pair(
        &mut self,
        request: ApiVisibilityDifferentialRequest,
    ) -> Result<RuntimeApiVisibilityRunReport, RuntimeApiVisibilityExecutionError> {
        if self.started {
            return Err(RuntimeApiVisibilityExecutionError::AlreadyStarted);
        }
        if self.api_reasoning_installation.is_none() {
            return Err(RuntimeApiVisibilityExecutionError::ApiReasoningDisabled);
        }
        if request.control.probe.url() != &self.target
            || request.candidate.probe.url() != &self.target
        {
            return Err(RuntimeApiVisibilityExecutionError::RuntimeTargetMismatch);
        }

        // Each principal receives a distinct connection pool. Accounting and
        // policy remain shared, but connection-bound server state cannot flow
        // from the control request into the candidate request.
        let control_requests = self
            .authority
            .requests()
            .isolated()
            .map_err(|source| RuntimeApiVisibilityExecutionError::TransportSetup { source })?;
        let candidate_requests = self
            .authority
            .requests()
            .isolated()
            .map_err(|source| RuntimeApiVisibilityExecutionError::TransportSetup { source })?;
        let evidence_reliability = self.authority.requests().policy().reliability();

        self.started = true;
        let timing = self.authority.start();
        let started_at = timing.started_at();
        let deadline = timing.deadline();
        let mut audit = ApiVisibilityDifferentialAudit::for_request(&request);
        if self.authority.cancellation().is_cancelled() {
            return Ok(self.visibility_cancelled_report(audit, None, started_at));
        }

        let control_limits = match self.reserve_execution(
            CONTROL_ACTION_ID,
            DecisionExecutionStage::Active,
            DecisionExecutionClass::TransportBound,
            started_at,
        ) {
            Ok(limits) => limits,
            Err(limit) => {
                return Ok(self.visibility_limit_report(
                    audit,
                    Some(ApiVisibilityLeg::Control),
                    limit,
                    started_at,
                ));
            },
        };
        let control_result = await_execution(
            self.authority.cancellation(),
            deadline,
            control_requests.collect_for_runtime(
                CONTROL_ACTION_ID,
                DecisionExecutionStage::Active,
                None,
                control_limits,
                &request.control.probe,
            ),
        )
        .await;
        let control_response = match control_result {
            RuntimeExecution::Completed(Ok(response)) => response,
            RuntimeExecution::Completed(Err(error)) => {
                return Ok(self.visibility_collection_report(
                    audit,
                    ApiVisibilityLeg::Control,
                    error,
                    started_at,
                ));
            },
            RuntimeExecution::Cancelled => {
                return Ok(self.visibility_cancelled_report(
                    audit,
                    Some(ApiVisibilityLeg::Control),
                    started_at,
                ));
            },
            RuntimeExecution::WallTimeExceeded => {
                let limit = self.wall_limit(started_at);
                return Ok(self.visibility_limit_report(
                    audit,
                    Some(ApiVisibilityLeg::Control),
                    limit,
                    started_at,
                ));
            },
        };
        audit.control = Some(leg_receipt(
            ApiVisibilityLeg::Control,
            &control_response,
            &request.request_template_sha256,
        ));
        self.refresh_elapsed(started_at);
        if let Some(limit) = self.response_limit_if_exceeded(CONTROL_ACTION_ID) {
            return Ok(self.visibility_limit_report(
                audit,
                Some(ApiVisibilityLeg::Control),
                limit,
                started_at,
            ));
        }
        if self.authority.cancellation().is_cancelled() {
            return Ok(self.visibility_cancelled_report(
                audit,
                Some(ApiVisibilityLeg::Control),
                started_at,
            ));
        }
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Ok(self.visibility_limit_report(
                audit,
                Some(ApiVisibilityLeg::Control),
                limit,
                started_at,
            ));
        }
        let control_document = match response_document(&control_response) {
            Ok(document) => document,
            Err(reason) => {
                return Ok(self.visibility_inconclusive_report(
                    audit,
                    ApiVisibilityLeg::Control,
                    reason,
                    started_at,
                ));
            },
        };
        let comparator = ApiVisibilityComparator::default();
        let control_view = match comparator.capture_profiled_view(
            &request.profile,
            request.control.context_id.as_str(),
            request.resource_scope.as_str(),
            ApiSurfaceKind::JsonHttp,
            control_response.status(),
            &control_document,
        ) {
            Ok(view) => view,
            Err(_) => {
                return Ok(self.visibility_inconclusive_report(
                    audit,
                    ApiVisibilityLeg::Control,
                    ApiVisibilityInconclusiveReason::CanonicalizationRejected,
                    started_at,
                ));
            },
        };
        drop(control_document);
        drop(control_response);

        if self.authority.cancellation().is_cancelled() {
            return Ok(self.visibility_cancelled_report(
                audit,
                Some(ApiVisibilityLeg::Candidate),
                started_at,
            ));
        }
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Ok(self.visibility_limit_report(
                audit,
                Some(ApiVisibilityLeg::Candidate),
                limit,
                started_at,
            ));
        }
        let candidate_limits = match self.reserve_execution(
            CANDIDATE_ACTION_ID,
            DecisionExecutionStage::Active,
            DecisionExecutionClass::TransportBound,
            started_at,
        ) {
            Ok(limits) => limits,
            Err(limit) => {
                return Ok(self.visibility_limit_report(
                    audit,
                    Some(ApiVisibilityLeg::Candidate),
                    limit,
                    started_at,
                ));
            },
        };
        let candidate_result = await_execution(
            self.authority.cancellation(),
            deadline,
            candidate_requests.collect_for_runtime(
                CANDIDATE_ACTION_ID,
                DecisionExecutionStage::Active,
                None,
                candidate_limits,
                &request.candidate.probe,
            ),
        )
        .await;
        let candidate_response = match candidate_result {
            RuntimeExecution::Completed(Ok(response)) => response,
            RuntimeExecution::Completed(Err(error)) => {
                return Ok(self.visibility_collection_report(
                    audit,
                    ApiVisibilityLeg::Candidate,
                    error,
                    started_at,
                ));
            },
            RuntimeExecution::Cancelled => {
                return Ok(self.visibility_cancelled_report(
                    audit,
                    Some(ApiVisibilityLeg::Candidate),
                    started_at,
                ));
            },
            RuntimeExecution::WallTimeExceeded => {
                let limit = self.wall_limit(started_at);
                return Ok(self.visibility_limit_report(
                    audit,
                    Some(ApiVisibilityLeg::Candidate),
                    limit,
                    started_at,
                ));
            },
        };
        audit.candidate = Some(leg_receipt(
            ApiVisibilityLeg::Candidate,
            &candidate_response,
            &request.request_template_sha256,
        ));
        self.refresh_elapsed(started_at);
        if let Some(limit) = self.response_limit_if_exceeded(CANDIDATE_ACTION_ID) {
            return Ok(self.visibility_limit_report(
                audit,
                Some(ApiVisibilityLeg::Candidate),
                limit,
                started_at,
            ));
        }
        if self.authority.cancellation().is_cancelled() {
            return Ok(self.visibility_cancelled_report(
                audit,
                Some(ApiVisibilityLeg::Candidate),
                started_at,
            ));
        }
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Ok(self.visibility_limit_report(
                audit,
                Some(ApiVisibilityLeg::Candidate),
                limit,
                started_at,
            ));
        }
        let candidate_document = match response_document(&candidate_response) {
            Ok(document) => document,
            Err(reason) => {
                return Ok(self.visibility_inconclusive_report(
                    audit,
                    ApiVisibilityLeg::Candidate,
                    reason,
                    started_at,
                ));
            },
        };
        let candidate_view = match comparator.capture_profiled_view(
            &request.profile,
            request.candidate.context_id.as_str(),
            request.resource_scope.as_str(),
            ApiSurfaceKind::JsonHttp,
            candidate_response.status(),
            &candidate_document,
        ) {
            Ok(view) => view,
            Err(_) => {
                return Ok(self.visibility_inconclusive_report(
                    audit,
                    ApiVisibilityLeg::Candidate,
                    ApiVisibilityInconclusiveReason::CanonicalizationRejected,
                    started_at,
                ));
            },
        };
        drop(candidate_document);
        drop(candidate_response);

        if self.authority.cancellation().is_cancelled() {
            return Ok(self.visibility_cancelled_report(
                audit,
                Some(ApiVisibilityLeg::Candidate),
                started_at,
            ));
        }
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Ok(self.visibility_limit_report(
                audit,
                Some(ApiVisibilityLeg::Candidate),
                limit,
                started_at,
            ));
        }

        let comparison = match comparator.compare_profiled(
            &request.profile,
            request.comparison_id.into_string(),
            ApiVisibilityPairKind::AuthorizationContext,
            request.dimension,
            &control_view,
            &candidate_view,
            request.observed_at_ms,
        ) {
            Ok(comparison) => comparison,
            Err(source) => {
                return Err(RuntimeApiVisibilityExecutionError::Comparison {
                    audit: Box::new(self.finish_visibility_audit(audit, started_at)),
                    source,
                });
            },
        };
        if self.authority.cancellation().is_cancelled() {
            return Ok(self.visibility_cancelled_after_comparison_report(
                audit, comparison, None, None, started_at,
            ));
        }
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Ok(self.visibility_limit_after_comparison_report(
                audit, comparison, None, None, limit, started_at,
            ));
        }

        let observation = match comparison
            .to_observation(OBSERVATION_COMPONENT, evidence_reliability)
            .map_err(ProfiledApiVisibilityError::from)
        {
            Ok(observation) => observation,
            Err(source) => {
                return Err(RuntimeApiVisibilityExecutionError::ObservationBuild {
                    audit: Box::new(self.finish_visibility_audit(audit, started_at)),
                    comparison: Box::new(comparison),
                    source,
                });
            },
        };
        let observation = match ingest_api_visibility_observation(
            observation,
            &request.resource_scope,
            self.authority.knowledge(),
            self.decision_loop.rules(),
        ) {
            Ok(observation) => observation,
            Err(source) => {
                return Err(RuntimeApiVisibilityExecutionError::Observation {
                    audit: Box::new(self.finish_visibility_audit(audit, started_at)),
                    comparison: Box::new(comparison),
                    source,
                });
            },
        };
        let Some(review) =
            api_visibility_review_for_commit(self.authority.knowledge(), observation.commit())
        else {
            return Err(RuntimeApiVisibilityExecutionError::ReviewProjection {
                audit: Box::new(self.finish_visibility_audit(audit, started_at)),
                comparison: Box::new(comparison),
                observation: Box::new(observation),
            });
        };
        let disposition = match review.disposition() {
            ApiVisibilityReviewDisposition::NoDifferenceObserved => {
                ApiVisibilityDifferentialDisposition::NoDifferenceObserved
            },
            ApiVisibilityReviewDisposition::UnresolvedDifference => {
                ApiVisibilityDifferentialDisposition::UnresolvedDifference
            },
            ApiVisibilityReviewDisposition::AwaitHumanReview => {
                ApiVisibilityDifferentialDisposition::AwaitHumanReview
            },
        };
        if self.authority.cancellation().is_cancelled() {
            return Ok(self.visibility_cancelled_after_comparison_report(
                audit,
                comparison,
                Some(observation),
                Some(review),
                started_at,
            ));
        }
        if let Some(limit) = self.wall_limit_if_reached(started_at) {
            return Ok(self.visibility_limit_after_comparison_report(
                audit,
                comparison,
                Some(observation),
                Some(review),
                limit,
                started_at,
            ));
        }
        let audit = self.finish_visibility_audit(audit, started_at);
        Ok(RuntimeApiVisibilityRunReport {
            disposition,
            stopped_leg: None,
            inconclusive_reason: None,
            audit,
            comparison: Some(comparison),
            observation: Some(observation),
            review: Some(review),
            limit_exceeded: None,
        })
    }

    fn finish_visibility_audit(
        &mut self,
        mut audit: ApiVisibilityDifferentialAudit,
        started_at: tokio::time::Instant,
    ) -> ApiVisibilityDifferentialAudit {
        self.refresh_elapsed(started_at);
        audit.usage = self.usage.clone();
        audit.transport = self.authority.request_accounting().dispatch_audit();
        audit
    }

    fn visibility_cancelled_report(
        &mut self,
        audit: ApiVisibilityDifferentialAudit,
        stopped_leg: Option<ApiVisibilityLeg>,
        started_at: tokio::time::Instant,
    ) -> RuntimeApiVisibilityRunReport {
        RuntimeApiVisibilityRunReport {
            disposition: ApiVisibilityDifferentialDisposition::CancelledByHost,
            stopped_leg,
            inconclusive_reason: None,
            audit: self.finish_visibility_audit(audit, started_at),
            comparison: None,
            observation: None,
            review: None,
            limit_exceeded: None,
        }
    }

    fn visibility_limit_report(
        &mut self,
        audit: ApiVisibilityDifferentialAudit,
        stopped_leg: Option<ApiVisibilityLeg>,
        limit: RuntimeLimitExceeded,
        started_at: tokio::time::Instant,
    ) -> RuntimeApiVisibilityRunReport {
        RuntimeApiVisibilityRunReport {
            disposition: ApiVisibilityDifferentialDisposition::RuntimeBudgetLimit,
            stopped_leg,
            inconclusive_reason: None,
            audit: self.finish_visibility_audit(audit, started_at),
            comparison: None,
            observation: None,
            review: None,
            limit_exceeded: Some(limit),
        }
    }

    fn visibility_cancelled_after_comparison_report(
        &mut self,
        audit: ApiVisibilityDifferentialAudit,
        comparison: ProfiledApiVisibilityComparison,
        observation: Option<ApiObservationReceipt>,
        review: Option<ApiVisibilityReview>,
        started_at: tokio::time::Instant,
    ) -> RuntimeApiVisibilityRunReport {
        RuntimeApiVisibilityRunReport {
            disposition: ApiVisibilityDifferentialDisposition::CancelledByHost,
            stopped_leg: None,
            inconclusive_reason: None,
            audit: self.finish_visibility_audit(audit, started_at),
            comparison: Some(comparison),
            observation,
            review,
            limit_exceeded: None,
        }
    }

    fn visibility_limit_after_comparison_report(
        &mut self,
        audit: ApiVisibilityDifferentialAudit,
        comparison: ProfiledApiVisibilityComparison,
        observation: Option<ApiObservationReceipt>,
        review: Option<ApiVisibilityReview>,
        limit: RuntimeLimitExceeded,
        started_at: tokio::time::Instant,
    ) -> RuntimeApiVisibilityRunReport {
        RuntimeApiVisibilityRunReport {
            disposition: ApiVisibilityDifferentialDisposition::RuntimeBudgetLimit,
            stopped_leg: None,
            inconclusive_reason: None,
            audit: self.finish_visibility_audit(audit, started_at),
            comparison: Some(comparison),
            observation,
            review,
            limit_exceeded: Some(limit),
        }
    }

    fn visibility_inconclusive_report(
        &mut self,
        audit: ApiVisibilityDifferentialAudit,
        stopped_leg: ApiVisibilityLeg,
        reason: ApiVisibilityInconclusiveReason,
        started_at: tokio::time::Instant,
    ) -> RuntimeApiVisibilityRunReport {
        RuntimeApiVisibilityRunReport {
            disposition: ApiVisibilityDifferentialDisposition::Inconclusive,
            stopped_leg: Some(stopped_leg),
            inconclusive_reason: Some(reason),
            audit: self.finish_visibility_audit(audit, started_at),
            comparison: None,
            observation: None,
            review: None,
            limit_exceeded: None,
        }
    }

    fn visibility_collection_report(
        &mut self,
        audit: ApiVisibilityDifferentialAudit,
        stopped_leg: ApiVisibilityLeg,
        error: crate::http_evidence::HttpRequestBrokerError,
        started_at: tokio::time::Instant,
    ) -> RuntimeApiVisibilityRunReport {
        let kind = error.failure_kind();
        if let Some(limit) = error.into_runtime_limit() {
            return self.visibility_limit_report(audit, Some(stopped_leg), limit, started_at);
        }
        self.visibility_inconclusive_report(
            audit,
            stopped_leg,
            inconclusive_reason(kind),
            started_at,
        )
    }
}
fn leg_receipt(
    leg: ApiVisibilityLeg,
    response: &crate::http_evidence::CollectedHttpResponse,
    request_template_sha256: &str,
) -> ApiVisibilityLegReceipt {
    let mut hasher = Sha256::new();
    hasher.update(RESPONSE_DIGEST_DOMAIN);
    update_framed(&mut hasher, response.body());
    ApiVisibilityLegReceipt {
        leg,
        status: response.status(),
        retained_body_bytes: u64::try_from(response.body().len()).unwrap_or(u64::MAX),
        body_truncated: response.body_truncated(),
        json_compatible_media_type: response.has_json_compatible_media_type(),
        request_template_sha256: request_template_sha256.to_owned(),
        response_body_sha256: encode_digest(hasher.finalize().as_slice()),
    }
}

fn response_document(
    response: &crate::http_evidence::CollectedHttpResponse,
) -> Result<serde_json::Value, ApiVisibilityInconclusiveReason> {
    if response.status() == 429 {
        return Err(ApiVisibilityInconclusiveReason::RateLimited);
    }
    if response.status() >= 500 {
        return Err(ApiVisibilityInconclusiveReason::ServerError);
    }
    if response.body_truncated() {
        return Err(ApiVisibilityInconclusiveReason::TruncatedResponse);
    }
    if !response.has_json_compatible_media_type() {
        return Err(ApiVisibilityInconclusiveReason::NonJsonResponse);
    }
    serde_json::from_slice(response.body())
        .map_err(|_| ApiVisibilityInconclusiveReason::MalformedJson)
}

fn inconclusive_reason(kind: DecisionExecutionFailureKind) -> ApiVisibilityInconclusiveReason {
    match kind {
        DecisionExecutionFailureKind::NotApplicable => {
            ApiVisibilityInconclusiveReason::NotApplicable
        },
        DecisionExecutionFailureKind::BlockedByPolicy => {
            ApiVisibilityInconclusiveReason::BlockedByPolicy
        },
        DecisionExecutionFailureKind::TransportFailure => {
            ApiVisibilityInconclusiveReason::TransportFailure
        },
        DecisionExecutionFailureKind::RequestTimeout => {
            ApiVisibilityInconclusiveReason::RequestTimeout
        },
        _ => ApiVisibilityInconclusiveReason::ExecutorFailure,
    }
}
