use reqwest::{
    header::{HeaderName, HeaderValue},
    redirect::Policy as RedirectPolicy,
    Client,
};

#[cfg(any(feature = "graphql-review", feature = "authorization-review"))]
use reqwest::header::ACCEPT;
#[cfg(any(
    feature = "graphql-review",
    feature = "authorization-review",
    feature = "wordpress-review"
))]
use reqwest::Method;

#[cfg(feature = "authorization-review")]
use reqwest::header::AUTHORIZATION;
#[cfg(feature = "graphql-review")]
use reqwest::header::CONTENT_TYPE;

#[cfg(feature = "graphql-review")]
use crate::graphql_review::MAX_GRAPHQL_REQUEST_JSON_BYTES;
#[cfg(feature = "wordpress-review")]
use crate::wordpress_review::valid_slug;

use crate::{
    runtime_budget::{RequestAccountingBroker, RequestAccountingLease, TransportDispatchOutcome},
    DecisionActionOrigin, DecisionExecutionFailureKind, DecisionExecutionLimits,
    DecisionExecutionRequest, DecisionExecutionStage, DecisionExecutorError, RuntimeLimitExceeded,
};

use super::{elapsed_ms, CollectedHttpResponse, HttpEvidenceError, HttpEvidencePolicy, HttpProbe};

#[cfg(feature = "graphql-review")]
const GRAPHQL_RESPONSE_ACCEPT: &str = "application/graphql-response+json, application/json";

/// Closed policy revision understood by the broker-owned WordPress metadata
/// admission descriptor.
#[cfg(feature = "wordpress-review")]
pub(crate) const WORDPRESS_METADATA_DISCOVERY_POLICY_ID: &str =
    "termivar.wordpress-deployment-aware-metadata-discovery/v1";

/// Metadata resource shapes that the WordPress discovery transport may fetch.
#[cfg(feature = "wordpress-review")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WordPressMetadataResourceKind {
    RestIndex,
    ThemeStylesheet { slug: String },
    PluginReadme { slug: String },
}

/// Evidence/declaration basis that admitted a metadata resource.
#[cfg(feature = "wordpress-review")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WordPressMetadataRequestSource {
    StructuredAdvertisement,
    OperatorQualifiedAdvertisement,
    ObservedConventional,
    ExplicitOperator,
    SameThemeBaseParent,
}

/// Broker-owned proof that one URL is the exact metadata resource admitted
/// for one selected application and one resolved role base.
///
/// Fields stay private so callers cannot pass an arbitrary same-origin URL to
/// the WordPress transport seam. Construction validates the complete binding,
/// and dispatch repeats that validation before request accounting.
#[cfg(feature = "wordpress-review")]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct WordPressMetadataRequestDescriptor {
    policy_id: &'static str,
    application_url: url::Url,
    role_base_url: url::Url,
    target: url::Url,
    resource_kind: WordPressMetadataResourceKind,
    source: WordPressMetadataRequestSource,
    source_evidence_count: usize,
}

#[cfg(feature = "wordpress-review")]
impl WordPressMetadataRequestDescriptor {
    #[cfg(test)]
    pub(crate) fn new(
        policy_id: &'static str,
        application_url: &url::Url,
        role_base_url: &url::Url,
        target: &url::Url,
        resource_kind: WordPressMetadataResourceKind,
        source: WordPressMetadataRequestSource,
    ) -> Result<Self, HttpEvidenceError> {
        Self::from_source_evidence(
            policy_id,
            application_url,
            role_base_url,
            target,
            resource_kind,
            source,
            1,
        )
    }

    pub(crate) fn from_source_evidence(
        policy_id: &'static str,
        application_url: &url::Url,
        role_base_url: &url::Url,
        target: &url::Url,
        resource_kind: WordPressMetadataResourceKind,
        source: WordPressMetadataRequestSource,
        source_evidence_count: usize,
    ) -> Result<Self, HttpEvidenceError> {
        let descriptor = Self {
            policy_id,
            application_url: application_url.clone(),
            role_base_url: role_base_url.clone(),
            target: target.clone(),
            resource_kind,
            source,
            source_evidence_count,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> Result<(), HttpEvidenceError> {
        let admitted = self.policy_id == WORDPRESS_METADATA_DISCOVERY_POLICY_ID
            && self.source_evidence_count > 0
            && wordpress_metadata_directory_is_safe(&self.application_url)
            && wordpress_metadata_directory_is_safe(&self.role_base_url)
            && wordpress_metadata_resource_is_safe(&self.target)
            && self.application_url.origin() == self.role_base_url.origin()
            && self.application_url.origin() == self.target.origin()
            && match (&self.resource_kind, self.source) {
                (
                    WordPressMetadataResourceKind::RestIndex,
                    WordPressMetadataRequestSource::StructuredAdvertisement,
                ) => {
                    self.role_base_url == self.application_url
                        && wordpress_rest_index_is_exact(&self.role_base_url, &self.target)
                },
                (
                    WordPressMetadataResourceKind::RestIndex,
                    WordPressMetadataRequestSource::OperatorQualifiedAdvertisement,
                ) => wordpress_rest_index_is_exact(&self.role_base_url, &self.target),
                (
                    WordPressMetadataResourceKind::ThemeStylesheet { slug },
                    WordPressMetadataRequestSource::ObservedConventional,
                ) => {
                    wordpress_role_is_within_application(&self.application_url, &self.role_base_url)
                        && wordpress_conventional_role_is_exact(&self.role_base_url, "themes")
                        && wordpress_component_resource_is_exact(
                            &self.role_base_url,
                            slug,
                            "style.css",
                            &self.target,
                        )
                },
                (
                    WordPressMetadataResourceKind::PluginReadme { slug },
                    WordPressMetadataRequestSource::ObservedConventional,
                ) => {
                    wordpress_role_is_within_application(&self.application_url, &self.role_base_url)
                        && wordpress_conventional_role_is_exact(&self.role_base_url, "plugins")
                        && wordpress_component_resource_is_exact(
                            &self.role_base_url,
                            slug,
                            "readme.txt",
                            &self.target,
                        )
                },
                (
                    WordPressMetadataResourceKind::ThemeStylesheet { slug },
                    WordPressMetadataRequestSource::ExplicitOperator,
                ) => {
                    self.role_base_url.path() != "/"
                        && wordpress_component_resource_is_exact(
                            &self.role_base_url,
                            slug,
                            "style.css",
                            &self.target,
                        )
                },
                (
                    WordPressMetadataResourceKind::PluginReadme { slug },
                    WordPressMetadataRequestSource::ExplicitOperator,
                ) => {
                    self.role_base_url.path() != "/"
                        && wordpress_component_resource_is_exact(
                            &self.role_base_url,
                            slug,
                            "readme.txt",
                            &self.target,
                        )
                },
                (
                    WordPressMetadataResourceKind::ThemeStylesheet { slug },
                    WordPressMetadataRequestSource::SameThemeBaseParent,
                ) => {
                    self.role_base_url.path() != "/"
                        && wordpress_component_resource_is_exact(
                            &self.role_base_url,
                            slug,
                            "style.css",
                            &self.target,
                        )
                },
                _ => false,
            };
        if admitted {
            Ok(())
        } else {
            Err(HttpEvidenceError::InvalidWordPressMetadataRequest)
        }
    }

    fn target(&self) -> &url::Url {
        &self.target
    }
}

#[cfg(feature = "wordpress-review")]
fn wordpress_metadata_directory_is_safe(url: &url::Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().starts_with('/')
        && url.path().ends_with('/')
        && wordpress_metadata_path_is_safe(url.path())
}

#[cfg(feature = "wordpress-review")]
fn wordpress_metadata_resource_is_safe(url: &url::Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.path().starts_with('/')
        && wordpress_metadata_path_is_safe(url.path())
}

#[cfg(feature = "wordpress-review")]
fn wordpress_metadata_path_is_safe(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    !path.contains('\\')
        && !segments.iter().skip(1).enumerate().any(|(index, segment)| {
            (segment.is_empty() && index + 2 < segments.len())
                || matches!(*segment, "." | "..")
                || ["%2e", "%2f", "%5c", "%25"]
                    .iter()
                    .any(|encoded| segment.to_ascii_lowercase().contains(encoded))
        })
}

#[cfg(feature = "wordpress-review")]
fn wordpress_role_is_within_application(
    application_url: &url::Url,
    role_base_url: &url::Url,
) -> bool {
    role_base_url.path().starts_with(application_url.path())
}

#[cfg(feature = "wordpress-review")]
fn wordpress_conventional_role_is_exact(role_base_url: &url::Url, collection: &str) -> bool {
    role_base_url
        .path()
        .strip_suffix('/')
        .is_some_and(|path| path.ends_with(&format!("/wp-content/{collection}")))
}

#[cfg(feature = "wordpress-review")]
fn wordpress_component_resource_is_exact(
    role_base_url: &url::Url,
    slug: &str,
    filename: &str,
    target: &url::Url,
) -> bool {
    valid_slug(slug)
        && target.query().is_none()
        && role_base_url
            .join(&format!("{slug}/{filename}"))
            .ok()
            .is_some_and(|expected| expected == *target)
}

#[cfg(feature = "wordpress-review")]
fn wordpress_rest_index_is_exact(role_base_url: &url::Url, target: &url::Url) -> bool {
    let pretty = role_base_url
        .join("wp-json/")
        .ok()
        .is_some_and(|expected| expected == *target && target.query().is_none());
    let plain_path = target.path() == role_base_url.path()
        || role_base_url
            .join("index.php")
            .ok()
            .is_some_and(|expected| expected.path() == target.path());
    pretty
        || (plain_path
            && target
                .query()
                .is_some_and(super::wordpress_rest_route_query_is_admitted))
}

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
    #[cfg(feature = "wordpress-review")]
    anonymous_no_proxy_client: Client,
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
        // WordPress public-metadata discovery has a stricter, anonymous
        // transport shape than ordinary assessment probes. In particular it
        // must not inherit a process-level proxy or proxy credentials. Keep a
        // separate pool so the normal broker behavior remains unchanged.
        #[cfg(feature = "wordpress-review")]
        let anonymous_no_proxy_client = Client::builder()
            .redirect(RedirectPolicy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(HttpEvidenceError::Client)?;
        Ok(Self {
            client,
            #[cfg(feature = "wordpress-review")]
            anonymous_no_proxy_client,
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
        self.collect_built_request(&self.client, action_id, stage, origin, limits, request)
            .await
    }

    /// Dispatches one fixed-shape anonymous, bodyless WordPress metadata GET.
    ///
    /// This path shares the parent assessment's exact-origin policy and
    /// accounting broker, but uses a no-proxy connection pool and accepts no
    /// caller headers, cookies, credentials, request body, or alternate method.
    #[cfg(feature = "wordpress-review")]
    pub(crate) async fn collect_anonymous_wordpress_get_for_runtime(
        &self,
        action_id: &str,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        limits: DecisionExecutionLimits,
        descriptor: &WordPressMetadataRequestDescriptor,
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        descriptor.validate()?;
        let target = descriptor.target();
        self.validate_target(target)?;
        let request = self.build_anonymous_wordpress_get_request(target)?;
        self.collect_built_request(
            &self.anonymous_no_proxy_client,
            action_id,
            stage,
            origin,
            limits,
            request,
        )
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
        self.collect_built_request(&self.client, action_id, stage, origin, limits, request)
            .await
    }

    /// Dispatches one fixed bodyless authenticated JSON GET under the parent
    /// assessment's exact-origin policy and shared accounting authority.
    ///
    /// The complete `Authorization` value comes from the already validated,
    /// move-only principal contract. No arbitrary header map, body, cookie, or
    /// alternate method is accepted by this seam.
    #[cfg(feature = "authorization-review")]
    pub(crate) async fn collect_authorized_json_get_for_runtime(
        &self,
        action_id: &str,
        stage: DecisionExecutionStage,
        origin: Option<DecisionActionOrigin>,
        limits: DecisionExecutionLimits,
        target: &url::Url,
        authorization: &str,
    ) -> Result<CollectedHttpResponse, HttpRequestBrokerError> {
        self.validate_target(target)?;
        let authorization = HeaderValue::from_str(authorization).map_err(|_| {
            HttpEvidenceError::InvalidHeaderValue {
                name: "authorization".to_owned(),
            }
        })?;
        let request = self
            .client
            .request(Method::GET, target.clone())
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, authorization)
            .build()
            .map_err(HttpEvidenceError::Request)?;
        self.collect_built_request(&self.client, action_id, stage, origin, limits, request)
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
            &self.client,
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
        client: &Client,
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
            let mut response = client
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

    #[cfg(feature = "wordpress-review")]
    fn build_anonymous_wordpress_get_request(
        &self,
        target: &url::Url,
    ) -> Result<reqwest::Request, HttpEvidenceError> {
        self.anonymous_no_proxy_client
            .request(Method::GET, target.clone())
            .build()
            .map_err(HttpEvidenceError::Request)
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

    #[cfg(feature = "wordpress-review")]
    #[test]
    fn wordpress_discovery_request_has_one_closed_anonymous_protocol_shape() {
        let application = url::Url::parse("https://example.test/blog/").unwrap();
        let target = url::Url::parse("https://example.test/blog/wp-json/").unwrap();
        let descriptor = WordPressMetadataRequestDescriptor::new(
            WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
            &application,
            &application,
            &target,
            WordPressMetadataResourceKind::RestIndex,
            WordPressMetadataRequestSource::StructuredAdvertisement,
        )
        .unwrap();
        let broker = HttpRequestBroker::new_unmetered(
            HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
        )
        .unwrap();
        let request = broker
            .build_anonymous_wordpress_get_request(descriptor.target())
            .unwrap();

        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.url(), &target);
        assert!(request.headers().is_empty());
        assert!(request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
        assert!(request.headers().get(reqwest::header::COOKIE).is_none());
        assert!(request
            .headers()
            .get(reqwest::header::PROXY_AUTHORIZATION)
            .is_none());
        assert!(request.body().is_none());
    }

    #[cfg(feature = "wordpress-review")]
    #[test]
    fn wordpress_metadata_descriptor_admits_only_exact_role_resources() {
        let application = url::Url::parse("https://example.test/blog/").unwrap();
        let theme_base = url::Url::parse("https://example.test/blog/wp-content/themes/").unwrap();
        let plugin_base = url::Url::parse("https://example.test/modules/").unwrap();
        let core_base = url::Url::parse("https://example.test/cms/").unwrap();

        for descriptor in [
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &application,
                &application.join("wp-json/").unwrap(),
                WordPressMetadataResourceKind::RestIndex,
                WordPressMetadataRequestSource::StructuredAdvertisement,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &core_base,
                &core_base.join("index.php?rest_route=%2F").unwrap(),
                WordPressMetadataResourceKind::RestIndex,
                WordPressMetadataRequestSource::OperatorQualifiedAdvertisement,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &theme_base,
                &theme_base.join("child-theme/style.css").unwrap(),
                WordPressMetadataResourceKind::ThemeStylesheet {
                    slug: "child-theme".to_owned(),
                },
                WordPressMetadataRequestSource::ObservedConventional,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &theme_base,
                &theme_base.join("parent-theme/style.css").unwrap(),
                WordPressMetadataResourceKind::ThemeStylesheet {
                    slug: "parent-theme".to_owned(),
                },
                WordPressMetadataRequestSource::SameThemeBaseParent,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &plugin_base,
                &plugin_base.join("selected-plugin/readme.txt").unwrap(),
                WordPressMetadataResourceKind::PluginReadme {
                    slug: "selected-plugin".to_owned(),
                },
                WordPressMetadataRequestSource::ExplicitOperator,
            ),
        ] {
            descriptor.unwrap();
        }

        let invalid_cases = [
            WordPressMetadataRequestDescriptor::new(
                "termivar.wordpress-metadata-discovery/v1",
                &application,
                &application,
                &application.join("wp-json/").unwrap(),
                WordPressMetadataResourceKind::RestIndex,
                WordPressMetadataRequestSource::StructuredAdvertisement,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &core_base,
                &core_base.join("wp-json/").unwrap(),
                WordPressMetadataResourceKind::RestIndex,
                WordPressMetadataRequestSource::StructuredAdvertisement,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &url::Url::parse("https://example.test/shop/wp-content/themes/").unwrap(),
                &url::Url::parse("https://example.test/shop/wp-content/themes/sibling/style.css")
                    .unwrap(),
                WordPressMetadataResourceKind::ThemeStylesheet {
                    slug: "sibling".to_owned(),
                },
                WordPressMetadataRequestSource::ObservedConventional,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &url::Url::parse("https://example.test/blog/arbitrary/themes/").unwrap(),
                &url::Url::parse("https://example.test/blog/arbitrary/themes/sibling/style.css")
                    .unwrap(),
                WordPressMetadataResourceKind::ThemeStylesheet {
                    slug: "sibling".to_owned(),
                },
                WordPressMetadataRequestSource::ObservedConventional,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &url::Url::parse("https://example.test/").unwrap(),
                &url::Url::parse("https://example.test/selected-plugin/readme.txt").unwrap(),
                WordPressMetadataResourceKind::PluginReadme {
                    slug: "selected-plugin".to_owned(),
                },
                WordPressMetadataRequestSource::ExplicitOperator,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &theme_base,
                &theme_base.join("child-theme/readme.txt").unwrap(),
                WordPressMetadataResourceKind::ThemeStylesheet {
                    slug: "child-theme".to_owned(),
                },
                WordPressMetadataRequestSource::ObservedConventional,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &plugin_base,
                &url::Url::parse("https://other.test/modules/selected-plugin/readme.txt").unwrap(),
                WordPressMetadataResourceKind::PluginReadme {
                    slug: "selected-plugin".to_owned(),
                },
                WordPressMetadataRequestSource::ExplicitOperator,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &plugin_base,
                &plugin_base
                    .join("selected-plugin/readme.txt?token=inert")
                    .unwrap(),
                WordPressMetadataResourceKind::PluginReadme {
                    slug: "selected-plugin".to_owned(),
                },
                WordPressMetadataRequestSource::ExplicitOperator,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &plugin_base,
                &plugin_base.join("selected-plugin/readme.txt").unwrap(),
                WordPressMetadataResourceKind::PluginReadme {
                    slug: "../selected-plugin".to_owned(),
                },
                WordPressMetadataRequestSource::ExplicitOperator,
            ),
            WordPressMetadataRequestDescriptor::new(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &application,
                &application.join("private/data").unwrap(),
                WordPressMetadataResourceKind::RestIndex,
                WordPressMetadataRequestSource::StructuredAdvertisement,
            ),
            WordPressMetadataRequestDescriptor::from_source_evidence(
                WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
                &application,
                &theme_base,
                &theme_base.join("child-theme/style.css").unwrap(),
                WordPressMetadataResourceKind::ThemeStylesheet {
                    slug: "child-theme".to_owned(),
                },
                WordPressMetadataRequestSource::ObservedConventional,
                0,
            ),
        ];
        assert!(invalid_cases.into_iter().all(|result| matches!(
            result,
            Err(HttpEvidenceError::InvalidWordPressMetadataRequest)
        )));
    }

    #[cfg(feature = "wordpress-review")]
    #[tokio::test]
    async fn forged_wordpress_descriptor_is_denied_before_request_accounting() {
        let application = url::Url::parse("http://127.0.0.1:1/blog/").unwrap();
        let role_base = url::Url::parse("http://127.0.0.1:1/blog/wp-content/plugins/").unwrap();
        let target = role_base.join("selected-plugin/readme.txt").unwrap();
        let mut descriptor = WordPressMetadataRequestDescriptor::new(
            WORDPRESS_METADATA_DISCOVERY_POLICY_ID,
            &application,
            &role_base,
            &target,
            WordPressMetadataResourceKind::PluginReadme {
                slug: "selected-plugin".to_owned(),
            },
            WordPressMetadataRequestSource::ObservedConventional,
        )
        .unwrap();
        descriptor.target = application.join("private/same-origin-data").unwrap();

        let accounting = RequestAccountingBroker::new(crate::RuntimeBudget::default());
        let broker = HttpRequestBroker::new_metered(
            HttpEvidencePolicy::for_origin(application).unwrap(),
            accounting.clone(),
        )
        .unwrap();
        let result = broker
            .collect_anonymous_wordpress_get_for_runtime(
                "wordpress.metadata-discovery",
                DecisionExecutionStage::Passive,
                Some(DecisionActionOrigin::Planned),
                DecisionExecutionLimits::new(),
                &descriptor,
            )
            .await;

        assert!(matches!(
            result,
            Err(HttpRequestBrokerError::Http(
                HttpEvidenceError::InvalidWordPressMetadataRequest
            ))
        ));
        assert_eq!(accounting.snapshot().total_requests(), 0);
        assert_eq!(accounting.snapshot().response_bytes(), 0);
        assert!(accounting.dispatch_audit().is_empty());
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
