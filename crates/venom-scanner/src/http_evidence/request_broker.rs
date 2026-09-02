use reqwest::{
    header::{HeaderName, HeaderValue},
    redirect::Policy as RedirectPolicy,
    Client,
};

#[cfg(feature = "graphql-review")]
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Method,
};

#[cfg(feature = "graphql-review")]
use crate::graphql_review::MAX_GRAPHQL_REQUEST_JSON_BYTES;

use crate::{
    runtime_budget::{RequestAccountingBroker, RequestAccountingLease, TransportDispatchOutcome},
    DecisionActionOrigin, DecisionExecutionFailureKind, DecisionExecutionLimits,
    DecisionExecutionRequest, DecisionExecutionStage, DecisionExecutorError, RuntimeLimitExceeded,
};

use super::{elapsed_ms, CollectedHttpResponse, HttpEvidenceError, HttpEvidencePolicy, HttpProbe};

#[cfg(feature = "graphql-review")]
const GRAPHQL_RESPONSE_ACCEPT: &str = "application/graphql-response+json, application/json";

/// Internal transport failure that preserves host budget denial separately
/// from HTTP policy and network failures.
#[derive(Debug)]
pub(crate) enum HttpRequestBrokerError {
    Http(HttpEvidenceError),
    RuntimeLimit(RuntimeLimitExceeded),
}

impl HttpRequestBrokerError {
    pub(crate) fn into_decision_executor_error(self) -> DecisionExecutorError {
        match self {
            Self::Http(error) => super::into_decision_executor_error(error),
            Self::RuntimeLimit(limit) => DecisionExecutorError::from_runtime_limit(limit),
        }
    }

    pub(crate) fn failure_kind(&self) -> DecisionExecutionFailureKind {
        match self {
            Self::Http(error) => super::execution_failure_kind(error),
            Self::RuntimeLimit(_) => DecisionExecutionFailureKind::BlockedByPolicy,
        }
    }

    pub(crate) fn into_runtime_limit(self) -> Option<RuntimeLimitExceeded> {
        match self {
            Self::RuntimeLimit(limit) => Some(limit),
            Self::Http(_) => None,
        }
    }
}

impl From<HttpEvidenceError> for HttpRequestBrokerError {
    fn from(error: HttpEvidenceError) -> Self {
        Self::Http(error)
    }
}

impl From<RuntimeLimitExceeded> for HttpRequestBrokerError {
    fn from(limit: RuntimeLimitExceeded) -> Self {
        Self::RuntimeLimit(limit)
    }
}

/// Redirect-disabled HTTP transport shared by one or more evidence executors.
///
/// The optional accounting authority records logical reqwest dispatches and
/// every response-body byte delivered to the collector. Retention remains
/// separately bounded. Clones share both the connection pool and accounting.
#[derive(Clone)]
pub(crate) struct HttpRequestBroker {
    client: Client,
    policy: HttpEvidencePolicy,
    accounting: Option<RequestAccountingBroker>,
}

impl HttpRequestBroker {
    /// Creates the broker used by bounded runtimes.
    pub(crate) fn new_metered(
        policy: HttpEvidencePolicy,
        accounting: RequestAccountingBroker,
    ) -> Result<Self, HttpEvidenceError> {
        Self::build(policy, Some(accounting))
    }

    /// Creates an explicitly unmetered broker for legacy standalone APIs.
    ///
    /// Bounded runtimes must never call this constructor.
    pub(crate) fn new_unmetered(policy: HttpEvidencePolicy) -> Result<Self, HttpEvidenceError> {
        Self::build(policy, None)
    }

    fn build(
        policy: HttpEvidencePolicy,
        accounting: Option<RequestAccountingBroker>,
    ) -> Result<Self, HttpEvidenceError> {
        let client = Client::builder()
            .redirect(RedirectPolicy::none())
            // A broker lease represents exactly one wire attempt. Semantic
            // retries re-enter the broker and acquire their own lease.
            .retry(reqwest::retry::never())
            .build()
            .map_err(HttpEvidenceError::Client)?;
        Ok(Self {
            client,
            policy,
            accounting,
        })
    }

    pub(crate) fn policy(&self) -> &HttpEvidencePolicy {
        &self.policy
    }

    /// Creates a fresh connection pool under the same immutable policy and
    /// shared accounting authority.
    ///
    /// Authorization-context comparisons use one isolated broker per leg so
    /// connection-bound server state cannot bleed between principals while
    /// every dispatch and body byte remains charged to the same runtime.
    pub(crate) fn isolated(&self) -> Result<Self, HttpEvidenceError> {
        Self::build(self.policy.clone(), self.accounting.clone())
    }

    pub(super) async fn collect(
        &self,
        decision: &DecisionExecutionRequest,
        probe: &HttpProbe,
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        self.collect_for_runtime(
            decision.case().action_id(),
            decision.stage(),
            decision.origin(),
            decision.limits(),
            probe,
        )
        .await
    }

    pub(crate) async fn collect_for_runtime(
        &self,
        action_id: &str,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        limits: DecisionExecutionLimits,
        probe: &HttpProbe,
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        self.validate_target(probe.url())?;

        // Provider resolution, policy validation, and request construction are
        // deliberately complete before a transport dispatch is accounted.
        let request = self.build_request(probe)?;
        self.collect_built_request(action_id, stage, origin, limits, request)
            .await
    }

    /// Dispatches one fixed-shape, anonymous GraphQL JSON request through the
    /// assessment's existing exact-origin and accounting authority.
    ///
    /// This deliberately is not a general POST surface: callers cannot add
    /// headers, credentials, cookies, query parameters, or an opaque body.
    #[cfg(feature = "graphql-review")]
    pub(crate) async fn collect_anonymous_graphql_json_for_runtime(
        &self,
        action_id: &str,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        limits: DecisionExecutionLimits,
        target: &url::Url,
        body: &[u8],
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        self.validate_target(target)?;
        let request = self.build_anonymous_graphql_json_request(target, body)?;
        self.collect_built_request(action_id, stage, origin, limits, request)
            .await
    }

    #[cfg(test)]
    pub(super) async fn collect_buffered_request_for_test(
        &self,
        decision: &DecisionExecutionRequest,
        request: reqwest::Request,
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        self.validate_target(request.url())?;
        self.collect_built_request(
            decision.case().action_id(),
            decision.stage(),
            decision.origin(),
            decision.limits(),
            request,
        )
        .await
    }

    fn validate_target(&self, target: &url::Url) -> Result<(), HttpEvidenceError> {
        self.policy.require_permitted_target(target)
    }

    async fn collect_built_request(
        &self,
        action_id: &str,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        limits: DecisionExecutionLimits,
        request: reqwest::Request,
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        let request_body_bytes = metered_request_body_bytes(&request)?;
        let execution_body_limit = limits
            .max_response_body_bytes()
            .map(|limit| usize::try_from(limit).unwrap_or(usize::MAX))
            .unwrap_or(usize::MAX);
        let body_limit = self.policy.max_body_bytes().min(execution_body_limit);
        let started = tokio::time::Instant::now();
        // Acquiring the lease immediately before entering reqwest is the
        // transport-accounting boundary. Keeping the lease outside the timeout
        // future lets every exit classify the same dispatch receipt.
        let mut accounting_lease =
            self.begin_accounting(action_id, stage, origin, request_body_bytes)?;

        let collected = tokio::time::timeout(self.policy.request_timeout(), async {
            let mut response = self
                .client
                .execute(request)
                .await
                .map_err(HttpEvidenceError::Request)?;
            let ttfb_ms = elapsed_ms(started.elapsed());
            let status = response.status();
            let final_url = response.url().clone();
            let version = format!("{:?}", response.version());
            let headers = response.headers().clone();
            let expected_body_bytes = response.content_length();
            let accounting_capacity = accounting_lease
                .as_ref()
                .map(|lease| {
                    usize::try_from(lease.remaining_response_bytes()).unwrap_or(usize::MAX)
                })
                .unwrap_or(usize::MAX);
            let mut body = Vec::with_capacity(
                expected_body_bytes
                    .and_then(|length| usize::try_from(length).ok())
                    .unwrap_or(0)
                    .min(body_limit)
                    .min(accounting_capacity),
            );
            let mut truncated = false;
            let mut body_complete = false;

            loop {
                // Metered collectors serialize body reads. This makes the
                // unavoidable transport overrun at most one delivered chunk
                // across every in-flight response sharing this authority.
                let _read_guard = match accounting_lease.as_ref() {
                    Some(lease) => Some(lease.acquire_response_read().await),
                    None => None,
                };
                let per_request_remaining = body_limit.saturating_sub(body.len());
                let session_remaining = accounting_lease
                    .as_ref()
                    .map(|lease| {
                        usize::try_from(lease.remaining_response_bytes()).unwrap_or(usize::MAX)
                    })
                    .unwrap_or(usize::MAX);
                if per_request_remaining == 0 || session_remaining == 0 {
                    let retained = u64::try_from(body.len()).unwrap_or(u64::MAX);
                    truncated = expected_body_bytes.is_none_or(|expected| retained < expected);
                    break;
                }

                let Some(chunk) = response.chunk().await.map_err(HttpEvidenceError::Request)?
                else {
                    body_complete = true;
                    break;
                };
                let session_retention =
                    observe_response_bytes(accounting_lease.as_mut(), chunk.len());
                let retained = session_retention.min(per_request_remaining);
                body.extend_from_slice(&chunk[..retained]);
                if retained < chunk.len() {
                    truncated = true;
                    break;
                }
            }

            Ok::<CollectedHttpResponse, HttpEvidenceError>(CollectedHttpResponse {
                status,
                final_url,
                version,
                headers,
                body,
                body_truncated: truncated,
                body_complete,
                ttfb_ms,
                total_ms: elapsed_ms(started.elapsed()),
            })
        })
        .await;

        match collected {
            Ok(Ok(response)) => {
                let outcome = if accounting_lease
                    .as_ref()
                    .is_some_and(RequestAccountingLease::response_budget_reached)
                {
                    TransportDispatchOutcome::ResponseBudgetReached
                } else {
                    TransportDispatchOutcome::Completed
                };
                finish_accounting(&mut accounting_lease, outcome);
                Ok(response)
            },
            Ok(Err(error)) => {
                finish_accounting(
                    &mut accounting_lease,
                    TransportDispatchOutcome::TransportFailure,
                );
                Err(error.into())
            },
            Err(_) => {
                finish_accounting(
                    &mut accounting_lease,
                    TransportDispatchOutcome::RequestTimeout,
                );
                Err(HttpEvidenceError::Timeout {
                    timeout_ms: self.policy.request_timeout_ms,
                }
                .into())
            },
        }
    }

    fn begin_accounting(
        &self,
        action_id: &str,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        request_body_bytes: u64,
    ) -> Result<Option<RequestAccountingLease>, RuntimeLimitExceeded> {
        self.accounting
            .as_ref()
            .map(|accounting| {
                accounting.try_begin_with_request_body_bytes(
                    action_id,
                    stage,
                    origin,
                    request_body_bytes,
                )
            })
            .transpose()
    }

    fn build_request(&self, probe: &HttpProbe) -> Result<reqwest::Request, HttpEvidenceError> {
        let mut request = self
            .client
            .request(probe.method().as_reqwest(), probe.url().clone());
        for (name, value) in probe.headers() {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| HttpEvidenceError::InvalidHeaderName { name: name.clone() })?;
            let value = HeaderValue::from_str(value).map_err(|_| {
                HttpEvidenceError::InvalidHeaderValue {
                    name: name.as_str().to_owned(),
                }
            })?;
            request = request.header(name, value);
        }
        request.build().map_err(HttpEvidenceError::Request)
    }

    #[cfg(feature = "graphql-review")]
    fn build_anonymous_graphql_json_request(
        &self,
        target: &url::Url,
        body: &[u8],
    ) -> Result<reqwest::Request, HttpEvidenceError> {
        if body.len() > MAX_GRAPHQL_REQUEST_JSON_BYTES {
            return Err(HttpEvidenceError::GraphqlReviewRequestBodyLimit);
        }
        self.client
            .request(Method::POST, target.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, GRAPHQL_RESPONSE_ACCEPT)
            .body(body.to_vec())
            .build()
            .map_err(HttpEvidenceError::Request)
    }
}

fn finish_accounting(
    lease: &mut Option<RequestAccountingLease>,
    outcome: TransportDispatchOutcome,
) {
    if let Some(lease) = lease {
        lease.finish(outcome);
    }
}

fn metered_request_body_bytes(request: &reqwest::Request) -> Result<u64, HttpEvidenceError> {
    match request.body() {
        None => Ok(0),
        Some(body) => body
            .as_bytes()
            .map(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or(HttpEvidenceError::UnmeteredRequestBody),
    }
}

fn observe_response_bytes(lease: Option<&mut RequestAccountingLease>, observed: usize) -> usize {
    let Some(lease) = lease else {
        return observed;
    };
    let retained = lease.observe_response_bytes(u64::try_from(observed).unwrap_or(u64::MAX));
    usize::try_from(retained).unwrap_or(observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_meter_counts_buffered_bytes_and_bodyless_requests() {
        let client = Client::new();
        let bodyless = client.get("https://example.test").build().unwrap();
        let buffered = client
            .post("https://example.test")
            .body("candidate")
            .build()
            .unwrap();

        assert_eq!(metered_request_body_bytes(&bodyless).unwrap(), 0);
        assert_eq!(metered_request_body_bytes(&buffered).unwrap(), 9);
    }

    #[cfg(feature = "graphql-review")]
    #[test]
    fn graphql_review_request_has_one_closed_anonymous_protocol_shape() {
        let target = url::Url::parse("https://example.test/graphql").unwrap();
        let broker = HttpRequestBroker::new_unmetered(
            HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
        )
        .unwrap();
        let body = br#"{"query":"query VenomControl { v: __typename }"}"#;
        let request = broker
            .build_anonymous_graphql_json_request(&target, body)
            .unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.url(), &target);
        assert_eq!(
            request.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            request.headers().get(ACCEPT).unwrap(),
            GRAPHQL_RESPONSE_ACCEPT
        );
        assert!(request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
        assert!(request.headers().get(reqwest::header::COOKIE).is_none());
        assert_eq!(
            request.body().and_then(reqwest::Body::as_bytes),
            Some(body.as_slice())
        );
        assert!(matches!(
            broker.build_anonymous_graphql_json_request(
                &target,
                &vec![b'x'; MAX_GRAPHQL_REQUEST_JSON_BYTES + 1]
            ),
            Err(HttpEvidenceError::GraphqlReviewRequestBodyLimit)
        ));
    }
}
