use reqwest::{
    header::{HeaderName, HeaderValue},
    redirect::Policy as RedirectPolicy,
    Client,
};

use crate::{
    runtime_budget::{RequestAccountingBroker, RequestAccountingLease},
    DecisionExecutionRequest, DecisionExecutorError, RuntimeLimitExceeded,
};

use super::{elapsed_ms, CollectedHttpResponse, HttpEvidenceError, HttpEvidencePolicy, HttpProbe};

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
/// retained response-body bytes. Clones share both the reqwest connection pool
/// and the host-owned accounting state.
#[derive(Clone)]
pub(crate) struct HttpRequestBroker {
    client: Client,
    policy: HttpEvidencePolicy,
    accounting: Option<RequestAccountingBroker>,
}

impl HttpRequestBroker {
    pub(crate) fn new(
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

    pub(super) async fn collect(
        &self,
        decision: &DecisionExecutionRequest,
        probe: &HttpProbe,
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        super::validate_http_url(probe.url())?;
        if !self.policy.permits(probe.url())? {
            return Err(HttpEvidenceError::TargetOutsidePolicy {
                url: probe.url().to_string(),
            }
            .into());
        }

        // Provider resolution, policy validation, and request construction are
        // deliberately complete before a transport dispatch is accounted.
        let request = self.build_request(probe)?;
        let execution_body_limit = decision
            .limits()
            .max_response_body_bytes()
            .map(|limit| usize::try_from(limit).unwrap_or(usize::MAX))
            .unwrap_or(usize::MAX);
        let body_limit = self.policy.max_body_bytes().min(execution_body_limit);
        let started = tokio::time::Instant::now();

        tokio::time::timeout(self.policy.request_timeout(), async {
            // This is the accounting boundary: a successful lease is acquired
            // immediately before the logical request enters reqwest.
            let mut accounting_lease = self.begin_accounting(decision)?;
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
            let accounting_capacity = accounting_lease
                .as_ref()
                .map(|lease| {
                    usize::try_from(lease.remaining_response_bytes()).unwrap_or(usize::MAX)
                })
                .unwrap_or(usize::MAX);
            let mut body = Vec::with_capacity(
                response
                    .content_length()
                    .and_then(|length| usize::try_from(length).ok())
                    .unwrap_or(0)
                    .min(body_limit)
                    .min(accounting_capacity),
            );
            let mut truncated = false;

            while let Some(chunk) = response.chunk().await.map_err(HttpEvidenceError::Request)? {
                let per_request_remaining = body_limit.saturating_sub(body.len());
                let requested = chunk.len().min(per_request_remaining);
                let retained = claim_response_bytes(accounting_lease.as_mut(), requested);
                body.extend_from_slice(&chunk[..retained]);
                if retained < chunk.len() {
                    truncated = true;
                    break;
                }
            }

            Ok(CollectedHttpResponse {
                status,
                final_url,
                version,
                headers,
                body,
                body_truncated: truncated,
                ttfb_ms,
                total_ms: elapsed_ms(started.elapsed()),
            })
        })
        .await
        .map_err(|_| HttpEvidenceError::Timeout {
            timeout_ms: self.policy.request_timeout_ms,
        })?
    }

    fn begin_accounting(
        &self,
        decision: &DecisionExecutionRequest,
    ) -> Result<Option<RequestAccountingLease>, RuntimeLimitExceeded> {
        self.accounting
            .as_ref()
            .map(|accounting| {
                accounting.try_begin(
                    decision.case().action_id(),
                    decision.stage(),
                    decision.origin(),
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
}

fn claim_response_bytes(lease: Option<&mut RequestAccountingLease>, requested: usize) -> usize {
    let Some(lease) = lease else {
        return requested;
    };
    let retained = lease.claim_response_bytes(u64::try_from(requested).unwrap_or(u64::MAX));
    usize::try_from(retained).unwrap_or(requested)
}
