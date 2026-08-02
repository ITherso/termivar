//! Stable predicate vocabulary shared by evidence producers and reasoners.
//!
//! The descriptors in this module compile into [`KnowledgePredicate`] and do
//! not introduce a second serialized predicate format. Custom predicates and
//! the open `http.header.*` family remain supported.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate, KnowledgeRelation, ReasoningModelError, RelationId, RelationKind,
};

const MAX_OPAQUE_CONTEXT_BYTES: usize = 256;

/// A validated static name that converts to the canonical predicate contract.
///
/// Descriptors deliberately do not implement Serde. Persisted definitions
/// continue to use the existing `{ "namespace", "name" }`
/// [`KnowledgePredicate`] representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PredicateDescriptor {
    namespace: &'static str,
    name: &'static str,
    dotted: &'static str,
}

impl PredicateDescriptor {
    const fn new(namespace: &'static str, name: &'static str, dotted: &'static str) -> Self {
        Self {
            namespace,
            name,
            dotted,
        }
    }

    /// Returns the predicate namespace.
    pub const fn namespace(self) -> &'static str {
        self.namespace
    }

    /// Returns the predicate name within its namespace.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the stable dotted identifier used in diagnostics.
    pub const fn dotted(self) -> &'static str {
        self.dotted
    }

    /// Converts this descriptor to the canonical owned predicate type.
    pub fn into_knowledge(self) -> KnowledgePredicate {
        KnowledgePredicate::new(self.namespace, self.name)
            .expect("static predicate descriptors contain non-empty components")
    }
}

impl From<PredicateDescriptor> for KnowledgePredicate {
    fn from(value: PredicateDescriptor) -> Self {
        value.into_knowledge()
    }
}

/// Standard raw HTTP observations emitted by Venom evidence producers.
///
/// This is an open vocabulary: [`Self::response_header`] supports custom
/// normalized response header names in addition to the common constants.
pub struct HttpEvidencePredicate;

impl HttpEvidencePredicate {
    /// HTTP request method.
    pub const REQUEST_METHOD: PredicateDescriptor =
        PredicateDescriptor::new("http.request", "method", "http.request.method");
    /// Requested URL.
    pub const REQUEST_URL: PredicateDescriptor =
        PredicateDescriptor::new("http.request", "url", "http.request.url");
    /// One bounded, non-empty URL path segment.
    pub const REQUEST_PATH_SEGMENT: PredicateDescriptor =
        PredicateDescriptor::new("http.request", "path-segment", "http.request.path-segment");
    /// Numeric HTTP response status.
    pub const RESPONSE_STATUS: PredicateDescriptor =
        PredicateDescriptor::new("http.response", "status", "http.response.status");
    /// Final URL after redirects.
    pub const RESPONSE_FINAL_URL: PredicateDescriptor =
        PredicateDescriptor::new("http.response", "final-url", "http.response.final-url");
    /// Debug-formatted HTTP protocol version.
    pub const RESPONSE_VERSION: PredicateDescriptor =
        PredicateDescriptor::new("http.response", "version", "http.response.version");
    /// Validated, lowercase media-type essence without parameters.
    pub const RESPONSE_MEDIA_TYPE: PredicateDescriptor =
        PredicateDescriptor::new("http.response", "media-type", "http.response.media-type");
    /// Whether the validated media type uses JSON or a `+json` suffix.
    pub const RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE: PredicateDescriptor = PredicateDescriptor::new(
        "http.response",
        "media-type-json-compatible",
        "http.response.media-type-json-compatible",
    );
    /// Number of response body bytes retained by the bounded collector.
    pub const RESPONSE_BODY_BYTES_OBSERVED: PredicateDescriptor = PredicateDescriptor::new(
        "http.response",
        "body-bytes-observed",
        "http.response.body-bytes-observed",
    );
    /// Whether the bounded response body was truncated.
    pub const RESPONSE_BODY_TRUNCATED: PredicateDescriptor = PredicateDescriptor::new(
        "http.response",
        "body-truncated",
        "http.response.body-truncated",
    );
    /// SHA-256 digest of the observed response body bytes.
    pub const RESPONSE_BODY_SHA256: PredicateDescriptor =
        PredicateDescriptor::new("http.response", "body-sha256", "http.response.body-sha256");
    /// Optional bounded textual response body sample.
    pub const RESPONSE_BODY_SAMPLE: PredicateDescriptor =
        PredicateDescriptor::new("http.response", "body-sample", "http.response.body-sample");
    /// Time to first response byte in milliseconds.
    pub const TIMING_TTFB_MS: PredicateDescriptor =
        PredicateDescriptor::new("http.timing", "ttfb-ms", "http.timing.ttfb-ms");
    /// Total request duration in milliseconds.
    pub const TIMING_TOTAL_MS: PredicateDescriptor =
        PredicateDescriptor::new("http.timing", "total-ms", "http.timing.total-ms");
    /// Response cookie name. Cookie values are never represented here.
    pub const COOKIE_NAME: PredicateDescriptor =
        PredicateDescriptor::new("http.cookie", "name", "http.cookie.name");
    /// Captured `Allow` response header.
    pub const HEADER_ALLOW: PredicateDescriptor =
        PredicateDescriptor::new("http.header", "allow", "http.header.allow");
    /// Captured `Content-Type` response header.
    pub const HEADER_CONTENT_TYPE: PredicateDescriptor =
        PredicateDescriptor::new("http.header", "content-type", "http.header.content-type");
    /// Captured `Server` response header.
    pub const HEADER_SERVER: PredicateDescriptor =
        PredicateDescriptor::new("http.header", "server", "http.header.server");
    /// Captured `WWW-Authenticate` response header.
    pub const HEADER_WWW_AUTHENTICATE: PredicateDescriptor = PredicateDescriptor::new(
        "http.header",
        "www-authenticate",
        "http.header.www-authenticate",
    );
    /// Captured `X-Powered-By` response header.
    pub const HEADER_X_POWERED_BY: PredicateDescriptor =
        PredicateDescriptor::new("http.header", "x-powered-by", "http.header.x-powered-by");
    /// Whether the response status directly indicated rate limiting.
    pub const RATE_LIMIT_DETECTED: PredicateDescriptor =
        PredicateDescriptor::new("http.rate-limit", "detected", "http.rate-limit.detected");
    /// Whether the response advertised rate-limit metadata.
    pub const RATE_LIMIT_ADVERTISED: PredicateDescriptor = PredicateDescriptor::new(
        "http.rate-limit",
        "advertised",
        "http.rate-limit.advertised",
    );
    /// Normalized `Retry-After` value.
    pub const RATE_LIMIT_RETRY_AFTER: PredicateDescriptor = PredicateDescriptor::new(
        "http.rate-limit",
        "retry-after",
        "http.rate-limit.retry-after",
    );
    /// Normalized rate-limit capacity.
    pub const RATE_LIMIT_LIMIT: PredicateDescriptor =
        PredicateDescriptor::new("http.rate-limit", "limit", "http.rate-limit.limit");
    /// Normalized remaining rate-limit capacity.
    pub const RATE_LIMIT_REMAINING: PredicateDescriptor =
        PredicateDescriptor::new("http.rate-limit", "remaining", "http.rate-limit.remaining");
    /// Normalized rate-limit reset value.
    pub const RATE_LIMIT_RESET: PredicateDescriptor =
        PredicateDescriptor::new("http.rate-limit", "reset", "http.rate-limit.reset");

    /// Creates an open-family predicate for a validated, normalized header.
    ///
    /// HTTP producers remain responsible for header syntax validation and
    /// lowercase normalization before calling this method.
    pub fn response_header(
        normalized_name: impl Into<String>,
    ) -> Result<KnowledgePredicate, ReasoningModelError> {
        KnowledgePredicate::new("http.header", normalized_name)
    }

    /// Returns every fixed descriptor in stable declaration order.
    pub const fn fixed() -> &'static [PredicateDescriptor] {
        &[
            Self::REQUEST_METHOD,
            Self::REQUEST_URL,
            Self::REQUEST_PATH_SEGMENT,
            Self::RESPONSE_STATUS,
            Self::RESPONSE_FINAL_URL,
            Self::RESPONSE_VERSION,
            Self::RESPONSE_MEDIA_TYPE,
            Self::RESPONSE_MEDIA_TYPE_JSON_COMPATIBLE,
            Self::RESPONSE_BODY_BYTES_OBSERVED,
            Self::RESPONSE_BODY_TRUNCATED,
            Self::RESPONSE_BODY_SHA256,
            Self::RESPONSE_BODY_SAMPLE,
            Self::TIMING_TTFB_MS,
            Self::TIMING_TOTAL_MS,
            Self::COOKIE_NAME,
            Self::HEADER_ALLOW,
            Self::HEADER_CONTENT_TYPE,
            Self::HEADER_SERVER,
            Self::HEADER_WWW_AUTHENTICATE,
            Self::HEADER_X_POWERED_BY,
            Self::RATE_LIMIT_DETECTED,
            Self::RATE_LIMIT_ADVERTISED,
            Self::RATE_LIMIT_RETRY_AFTER,
            Self::RATE_LIMIT_LIMIT,
            Self::RATE_LIMIT_REMAINING,
            Self::RATE_LIMIT_RESET,
        ]
    }
}

/// Standard conclusions produced by web fingerprint reasoning.
pub struct WebKnowledgePredicate;

impl WebKnowledgePredicate {
    /// Disclosed or inferred web server product.
    pub const TECHNOLOGY_WEB_SERVER: PredicateDescriptor =
        PredicateDescriptor::new("technology", "web-server", "technology.web-server");
    /// Disclosed or inferred implementation language.
    pub const TECHNOLOGY_LANGUAGE: PredicateDescriptor =
        PredicateDescriptor::new("technology", "language", "technology.language");
    /// Disclosed or inferred server-side framework.
    pub const TECHNOLOGY_FRAMEWORK: PredicateDescriptor =
        PredicateDescriptor::new("technology", "framework", "technology.framework");
    /// Disclosed or inferred UI framework.
    pub const TECHNOLOGY_UI_FRAMEWORK: PredicateDescriptor =
        PredicateDescriptor::new("technology", "ui-framework", "technology.ui-framework");
    /// Disclosed or inferred authentication mechanism.
    pub const AUTHENTICATION_MECHANISM: PredicateDescriptor =
        PredicateDescriptor::new("authentication", "mechanism", "authentication.mechanism");
}

/// Raw, atomic API comparison observations.
pub struct ApiEvidencePredicate;

impl ApiEvidencePredicate {
    /// JSON UI/API comparison found a difference.
    pub const JSON_UI_API_DIFFERENCE: PredicateDescriptor = PredicateDescriptor::new(
        "api.visibility.json.ui-api",
        "difference",
        "api.visibility.json.ui-api.difference",
    );
    /// JSON UI/API comparison found equivalent visibility.
    pub const JSON_UI_API_EQUIVALENT: PredicateDescriptor = PredicateDescriptor::new(
        "api.visibility.json.ui-api",
        "equivalent",
        "api.visibility.json.ui-api.equivalent",
    );
    /// JSON authorization-context comparison found a difference.
    pub const JSON_AUTHORIZATION_CONTEXT_DIFFERENCE: PredicateDescriptor = PredicateDescriptor::new(
        "api.visibility.json.authorization-context",
        "difference",
        "api.visibility.json.authorization-context.difference",
    );
    /// JSON authorization-context comparison found equivalent visibility.
    pub const JSON_AUTHORIZATION_CONTEXT_EQUIVALENT: PredicateDescriptor = PredicateDescriptor::new(
        "api.visibility.json.authorization-context",
        "equivalent",
        "api.visibility.json.authorization-context.equivalent",
    );
    /// GraphQL UI/API comparison found a difference.
    pub const GRAPHQL_UI_API_DIFFERENCE: PredicateDescriptor = PredicateDescriptor::new(
        "api.visibility.graphql.ui-api",
        "difference",
        "api.visibility.graphql.ui-api.difference",
    );
    /// GraphQL UI/API comparison found equivalent visibility.
    pub const GRAPHQL_UI_API_EQUIVALENT: PredicateDescriptor = PredicateDescriptor::new(
        "api.visibility.graphql.ui-api",
        "equivalent",
        "api.visibility.graphql.ui-api.equivalent",
    );
    /// GraphQL authorization-context comparison found a difference.
    pub const GRAPHQL_AUTHORIZATION_CONTEXT_DIFFERENCE: PredicateDescriptor =
        PredicateDescriptor::new(
            "api.visibility.graphql.authorization-context",
            "difference",
            "api.visibility.graphql.authorization-context.difference",
        );
    /// GraphQL authorization-context comparison found equivalent visibility.
    pub const GRAPHQL_AUTHORIZATION_CONTEXT_EQUIVALENT: PredicateDescriptor =
        PredicateDescriptor::new(
            "api.visibility.graphql.authorization-context",
            "equivalent",
            "api.visibility.graphql.authorization-context.equivalent",
        );

    /// Selects the one predicate that completely classifies a paired result.
    pub const fn visibility(
        surface: ApiSurfaceKind,
        pair: ApiVisibilityPairKind,
        result: ApiVisibilityResult,
    ) -> PredicateDescriptor {
        match (surface, pair, result) {
            (
                ApiSurfaceKind::JsonHttp,
                ApiVisibilityPairKind::UiApi,
                ApiVisibilityResult::Different,
            ) => Self::JSON_UI_API_DIFFERENCE,
            (
                ApiSurfaceKind::JsonHttp,
                ApiVisibilityPairKind::UiApi,
                ApiVisibilityResult::Equivalent,
            ) => Self::JSON_UI_API_EQUIVALENT,
            (
                ApiSurfaceKind::JsonHttp,
                ApiVisibilityPairKind::AuthorizationContext,
                ApiVisibilityResult::Different,
            ) => Self::JSON_AUTHORIZATION_CONTEXT_DIFFERENCE,
            (
                ApiSurfaceKind::JsonHttp,
                ApiVisibilityPairKind::AuthorizationContext,
                ApiVisibilityResult::Equivalent,
            ) => Self::JSON_AUTHORIZATION_CONTEXT_EQUIVALENT,
            (
                ApiSurfaceKind::GraphQl,
                ApiVisibilityPairKind::UiApi,
                ApiVisibilityResult::Different,
            ) => Self::GRAPHQL_UI_API_DIFFERENCE,
            (
                ApiSurfaceKind::GraphQl,
                ApiVisibilityPairKind::UiApi,
                ApiVisibilityResult::Equivalent,
            ) => Self::GRAPHQL_UI_API_EQUIVALENT,
            (
                ApiSurfaceKind::GraphQl,
                ApiVisibilityPairKind::AuthorizationContext,
                ApiVisibilityResult::Different,
            ) => Self::GRAPHQL_AUTHORIZATION_CONTEXT_DIFFERENCE,
            (
                ApiSurfaceKind::GraphQl,
                ApiVisibilityPairKind::AuthorizationContext,
                ApiVisibilityResult::Equivalent,
            ) => Self::GRAPHQL_AUTHORIZATION_CONTEXT_EQUIVALENT,
        }
    }
}

/// Standard hypotheses produced by API reasoning profiles.
pub struct ApiKnowledgePredicate;

impl ApiKnowledgePredicate {
    /// Observed response representation.
    pub const RESPONSE_FORMAT: PredicateDescriptor =
        PredicateDescriptor::new("api", "response-format", "api.response-format");
    /// Inferred API surface kind.
    pub const SURFACE_KIND: PredicateDescriptor =
        PredicateDescriptor::new("api.surface", "kind", "api.surface.kind");
    /// Paired visibility boundary that deserves review.
    pub const VISIBILITY_BOUNDARY: PredicateDescriptor =
        PredicateDescriptor::new("api.visibility", "boundary", "api.visibility.boundary");
}

/// Response representations recognized by the standard API vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ApiResponseFormat {
    /// JavaScript Object Notation.
    Json,
}

impl ApiResponseFormat {
    /// Returns the stable ontology value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
        }
    }
}

impl From<ApiResponseFormat> for EvidenceValue {
    fn from(value: ApiResponseFormat) -> Self {
        Self::Text(value.as_str().to_owned())
    }
}

/// API surface families represented by paired observations and hypotheses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ApiSurfaceKind {
    /// Conventional HTTP API with JSON representations.
    JsonHttp,
    /// GraphQL API surface.
    #[serde(rename = "graphql")]
    GraphQl,
}

impl ApiSurfaceKind {
    /// Returns the stable ontology value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonHttp => "json-http-api",
            Self::GraphQl => "graphql-api",
        }
    }
}

impl From<ApiSurfaceKind> for EvidenceValue {
    fn from(value: ApiSurfaceKind) -> Self {
        Self::Text(value.as_str().to_owned())
    }
}

/// The two views compared by one atomic visibility observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ApiVisibilityPairKind {
    /// User-interface behavior compared with its backing API behavior.
    UiApi,
    /// The same logical resource compared across authorization contexts.
    AuthorizationContext,
}

impl ApiVisibilityPairKind {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UiApi => "ui-api",
            Self::AuthorizationContext => "authorization-context",
        }
    }
}

/// Outcome of an already paired visibility comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ApiVisibilityResult {
    /// The candidate view differed from the baseline view.
    Different,
    /// The compared views were equivalent for the selected dimension.
    Equivalent,
}

impl ApiVisibilityResult {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Different => "different",
            Self::Equivalent => "equivalent",
        }
    }
}

/// Dimension measured by a paired visibility comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ApiVisibilityDimension {
    /// Logical resources or records.
    Resources,
    /// Object fields or properties.
    Fields,
    /// HTTP or protocol result status.
    Status,
}

impl ApiVisibilityDimension {
    /// Returns the stable evidence value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resources => "resources",
            Self::Fields => "fields",
            Self::Status => "status",
        }
    }

    /// Returns every currently standardized comparison dimension.
    pub const fn all() -> [Self; 3] {
        [Self::Resources, Self::Fields, Self::Status]
    }
}

impl From<ApiVisibilityDimension> for EvidenceValue {
    fn from(value: ApiVisibilityDimension) -> Self {
        Self::Text(value.as_str().to_owned())
    }
}

/// Visibility-boundary hypotheses emitted by the standard API profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ApiVisibilityBoundaryKind {
    /// UI behavior and backing API behavior expose different views.
    UiApi,
    /// Two authorization contexts expose different views.
    AuthorizationContext,
}

impl ApiVisibilityBoundaryKind {
    /// Returns the stable ontology value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UiApi => "ui-api-visibility-boundary",
            Self::AuthorizationContext => "authorization-context-visibility-boundary",
        }
    }
}

impl From<ApiVisibilityBoundaryKind> for EvidenceValue {
    fn from(value: ApiVisibilityBoundaryKind) -> Self {
        Self::Text(value.as_str().to_owned())
    }
}

/// Validation failures for typed API comparison observations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ApiVocabularyError {
    /// A core reasoning identifier was invalid.
    #[error(transparent)]
    Reasoning(#[from] ReasoningModelError),

    /// An opaque context identifier was empty.
    #[error("{field} must not be empty")]
    EmptyContext { field: &'static str },

    /// An opaque context identifier exceeded the bounded contract.
    #[error("{field} exceeds the {maximum}-byte limit")]
    ContextTooLong {
        /// Invalid field name.
        field: &'static str,
        /// Inclusive maximum length.
        maximum: usize,
    },

    /// A comparison attempted to use the same baseline and candidate view.
    #[error("baseline and candidate context ids must identify different views")]
    IdenticalContexts,

    /// A paired observation cannot claim zero source reliability.
    #[error("API visibility comparison reliability must be greater than zero")]
    ZeroReliability,
}

/// One atomic API comparison observation plus its resource-scope graph edge.
///
/// The evidence remains scoped to a pseudonymous comparison subject so rule
/// evaluation cannot merge principals accidentally. The relation makes that
/// subject discoverable from the host-provided resource entity without
/// putting context handles into the evidence value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiVisibilityObservation {
    evidence: Evidence,
    resource_scope: EntityId,
    scope_relation: KnowledgeRelation,
}

impl ApiVisibilityObservation {
    /// Returns the canonical paired-comparison evidence.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Returns the opaque resource entity compared by the host.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns the evidence-backed comparison-to-resource edge.
    pub fn scope_relation(&self) -> &KnowledgeRelation {
        &self.scope_relation
    }

    /// Splits the bundle into records for atomic knowledge-base insertion.
    pub fn into_parts(self) -> (Evidence, KnowledgeRelation) {
        (self.evidence, self.scope_relation)
    }
}

/// One host-paired API visibility comparison.
///
/// This contract is intentionally atomic. The host must compare the same
/// logical resource under the declared views before constructing it; the rule
/// engine never combines independent UI, API, or principal observations.
/// Context and scope identifiers must be opaque, non-secret handles. Raw
/// credentials, tokens, URLs, response values, and resource names do not
/// belong in this contract or its resulting evidence.
///
/// # Examples
///
/// ```rust
/// use venom_core::{
///     ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension,
///     ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore,
/// };
///
/// let comparison = ApiVisibilityComparison::new(
///     "comparison-17",
///     ApiSurfaceKind::JsonHttp,
///     ApiVisibilityPairKind::AuthorizationContext,
///     ApiVisibilityResult::Different,
///     ApiVisibilityDimension::Fields,
///     "anonymous-context",
///     "member-context",
///     "account-resource",
/// )?;
/// let observation = comparison.to_observation("host.api-comparator", ConfidenceScore::MAX)?;
/// let evidence = observation.evidence();
///
/// assert!(evidence.subject().as_str().starts_with("api-comparison:"));
/// assert_eq!(evidence.source().correlation_id(), Some(evidence.subject().as_str()));
/// assert_eq!(observation.scope_relation().to(), observation.resource_scope());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityComparison {
    comparison_id: String,
    surface: ApiSurfaceKind,
    pair: ApiVisibilityPairKind,
    result: ApiVisibilityResult,
    dimension: ApiVisibilityDimension,
    baseline_context_id: String,
    candidate_context_id: String,
    resource_scope_id: String,
    observed_at_ms: u64,
}

impl ApiVisibilityComparison {
    /// Creates one validated, already-paired observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        comparison_id: impl Into<String>,
        surface: ApiSurfaceKind,
        pair: ApiVisibilityPairKind,
        result: ApiVisibilityResult,
        dimension: ApiVisibilityDimension,
        baseline_context_id: impl Into<String>,
        candidate_context_id: impl Into<String>,
        resource_scope_id: impl Into<String>,
    ) -> Result<Self, ApiVocabularyError> {
        let baseline_context_id = opaque_context(baseline_context_id, "baseline context id")?;
        let candidate_context_id = opaque_context(candidate_context_id, "candidate context id")?;
        if baseline_context_id == candidate_context_id {
            return Err(ApiVocabularyError::IdenticalContexts);
        }
        Ok(Self {
            comparison_id: opaque_context(comparison_id, "comparison id")?,
            surface,
            pair,
            result,
            dimension,
            baseline_context_id,
            candidate_context_id,
            resource_scope_id: opaque_context(resource_scope_id, "resource scope id")?,
            observed_at_ms: unix_time_ms(),
        })
    }

    /// Returns the opaque host comparison identifier.
    pub fn comparison_id(&self) -> &str {
        &self.comparison_id
    }

    /// Returns the API surface that was compared.
    pub const fn surface(&self) -> ApiSurfaceKind {
        self.surface
    }

    /// Returns the pair of views that was compared.
    pub const fn pair(&self) -> ApiVisibilityPairKind {
        self.pair
    }

    /// Returns the paired comparison result.
    pub const fn result(&self) -> ApiVisibilityResult {
        self.result
    }

    /// Returns the measured visibility dimension.
    pub const fn dimension(&self) -> ApiVisibilityDimension {
        self.dimension
    }

    /// Returns when the host constructed this paired observation.
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    /// Replaces the observation time for deterministic replay or import.
    pub fn with_observed_at_ms(mut self, observed_at_ms: u64) -> Self {
        self.observed_at_ms = observed_at_ms;
        self
    }

    /// Returns a raw-value-free, stable entity ID unique to this comparison.
    ///
    /// This SHA-256 identity is pseudonymous, not a cryptographic attestation;
    /// hosts should supply non-secret, suitably opaque context handles.
    pub fn subject(&self) -> EntityId {
        comparison_subject(&self.digest())
    }

    /// Returns the opaque resource entity that the host compared.
    pub fn resource_scope(&self) -> EntityId {
        EntityId::new(self.resource_scope_id.clone())
            .expect("validated opaque resource scope is a valid entity id")
    }

    /// Emits the evidence and a stable evidence-backed resource-scope edge.
    pub fn to_observation(
        &self,
        component: impl Into<String>,
        reliability: ConfidenceScore,
    ) -> Result<ApiVisibilityObservation, ApiVocabularyError> {
        let evidence = self.build_evidence(component, reliability)?;
        let digest = self.digest();
        let resource_scope = self.resource_scope();
        let scope_relation = KnowledgeRelation::with_id(
            RelationId::parse(format!("api-comparison-scope:{digest}"))?,
            evidence.subject().clone(),
            resource_scope.clone(),
            RelationKind::Custom("api.visibility.resource-scope".to_owned()),
            reliability,
            evidence.id().clone(),
        );
        Ok(ApiVisibilityObservation {
            evidence,
            resource_scope,
            scope_relation,
        })
    }

    /// Emits a detached immutable evidence record for this comparison.
    ///
    /// The source correlation and subject use the same digest, so separate
    /// principals or comparison turns cannot contaminate one another. Prefer
    /// [`Self::to_observation`] for durable storage; callers using this lower-
    /// level method must persist an equivalent resource mapping themselves.
    pub fn to_evidence(
        &self,
        component: impl Into<String>,
        reliability: ConfidenceScore,
    ) -> Result<Evidence, ApiVocabularyError> {
        self.build_evidence(component, reliability)
    }

    fn build_evidence(
        &self,
        component: impl Into<String>,
        reliability: ConfidenceScore,
    ) -> Result<Evidence, ApiVocabularyError> {
        if reliability == ConfidenceScore::NONE {
            return Err(ApiVocabularyError::ZeroReliability);
        }
        let digest = self.digest();
        let subject = comparison_subject(&digest);
        let evidence_id = EvidenceId::parse(format!("api-comparison-evidence:{digest}"))?;
        let source = EvidenceSource::new(component, "paired-api-visibility")?
            .with_correlation_id(subject.as_str())?;
        Ok(Evidence::with_id_at(
            evidence_id,
            subject,
            EvidenceKind::Custom("api.visibility-comparison".to_owned()),
            ApiEvidencePredicate::visibility(self.surface, self.pair, self.result).into(),
            self.dimension.into(),
            source,
            reliability,
            self.observed_at_ms,
        ))
    }

    fn digest(&self) -> String {
        let mut digest = Sha256::new();
        for value in [
            self.comparison_id.as_str(),
            self.surface.as_str(),
            self.pair.as_str(),
            self.result.as_str(),
            self.dimension.as_str(),
            self.baseline_context_id.as_str(),
            self.candidate_context_id.as_str(),
            self.resource_scope_id.as_str(),
        ] {
            let bytes = value.as_bytes();
            digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(bytes);
        }
        hex::encode(digest.finalize())
    }
}

fn comparison_subject(digest: &str) -> EntityId {
    EntityId::new(format!("api-comparison:{digest}"))
        .expect("a prefixed SHA-256 digest is a valid entity id")
}

impl<'de> Deserialize<'de> for ApiVisibilityComparison {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireComparison {
            comparison_id: String,
            surface: ApiSurfaceKind,
            pair: ApiVisibilityPairKind,
            result: ApiVisibilityResult,
            dimension: ApiVisibilityDimension,
            baseline_context_id: String,
            candidate_context_id: String,
            resource_scope_id: String,
            observed_at_ms: u64,
        }

        let wire = WireComparison::deserialize(deserializer)?;
        Self::new(
            wire.comparison_id,
            wire.surface,
            wire.pair,
            wire.result,
            wire.dimension,
            wire.baseline_context_id,
            wire.candidate_context_id,
            wire.resource_scope_id,
        )
        .map(|comparison| comparison.with_observed_at_ms(wire.observed_at_ms))
        .map_err(serde::de::Error::custom)
    }
}

fn opaque_context(
    value: impl Into<String>,
    field: &'static str,
) -> Result<String, ApiVocabularyError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(ApiVocabularyError::EmptyContext { field });
    }
    if value.len() > MAX_OPAQUE_CONTEXT_BYTES {
        return Err(ApiVocabularyError::ContextTooLong {
            field,
            maximum: MAX_OPAQUE_CONTEXT_BYTES,
        });
    }
    Ok(value)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn fixed_http_descriptors_are_unique_and_preserve_wire_shape() {
        let descriptors = HttpEvidencePredicate::fixed();
        let unique = descriptors
            .iter()
            .map(|descriptor| descriptor.dotted())
            .collect::<BTreeSet<_>>();

        assert_eq!(unique.len(), descriptors.len());
        assert_eq!(
            serde_json::to_value(HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge()).unwrap(),
            serde_json::json!({"namespace": "http.response", "name": "status"})
        );
        for descriptor in descriptors {
            assert_eq!(descriptor.into_knowledge().dotted(), descriptor.dotted());
        }
    }

    #[test]
    fn dynamic_header_family_remains_open() {
        let predicate = HttpEvidencePredicate::response_header("x-private-signal").unwrap();

        assert_eq!(predicate.namespace(), "http.header");
        assert_eq!(predicate.name(), "x-private-signal");
    }

    fn comparison(candidate: &str) -> ApiVisibilityComparison {
        ApiVisibilityComparison::new(
            "comparison-7",
            ApiSurfaceKind::GraphQl,
            ApiVisibilityPairKind::AuthorizationContext,
            ApiVisibilityResult::Different,
            ApiVisibilityDimension::Fields,
            "anonymous",
            candidate,
            "resource-42",
        )
        .unwrap()
    }

    #[test]
    fn comparison_emits_one_atomic_pseudonymous_observation() {
        let comparison = comparison("member");
        let evidence = comparison
            .to_evidence("api.visibility", ConfidenceScore::from_percent(95).unwrap())
            .unwrap();

        assert!(evidence.subject().as_str().starts_with("api-comparison:"));
        assert_eq!(
            evidence.predicate(),
            &ApiEvidencePredicate::GRAPHQL_AUTHORIZATION_CONTEXT_DIFFERENCE.into_knowledge()
        );
        assert_eq!(evidence.value(), &EvidenceValue::Text("fields".to_owned()));
        assert_eq!(
            evidence.source().correlation_id(),
            Some(evidence.subject().as_str())
        );
        assert_eq!(evidence.source().method(), "paired-api-visibility");
        let encoded = serde_json::to_string(&evidence).unwrap();
        for secret_adjacent_value in ["anonymous", "member", "resource-42"] {
            assert!(!encoded.contains(secret_adjacent_value));
        }
    }

    #[test]
    fn comparison_bundle_links_pseudonymous_subject_to_resource_scope() {
        let observation = comparison("member")
            .with_observed_at_ms(1_000)
            .to_observation("api.visibility", ConfidenceScore::MAX)
            .unwrap();

        assert_eq!(
            observation.scope_relation().from(),
            observation.evidence().subject()
        );
        assert_eq!(
            observation.scope_relation().to(),
            observation.resource_scope()
        );
        assert_eq!(observation.resource_scope().as_str(), "resource-42");
        assert_eq!(
            observation.scope_relation().evidence_ids(),
            &std::collections::BTreeSet::from([observation.evidence().id().clone()])
        );
        assert!(matches!(
            observation.scope_relation().kind(),
            RelationKind::Custom(kind) if kind == "api.visibility.resource-scope"
        ));
        assert!(observation
            .scope_relation()
            .id()
            .as_str()
            .starts_with("api-comparison-scope:"));
    }

    #[test]
    fn comparison_identity_is_stable_and_context_scoped() {
        let paired = comparison("member").with_observed_at_ms(1_000);
        let first = paired
            .to_evidence("api.visibility", ConfidenceScore::MAX)
            .unwrap();
        let replay = paired
            .to_evidence("api.visibility", ConfidenceScore::MAX)
            .unwrap();
        let later = comparison("member")
            .with_observed_at_ms(2_000)
            .to_evidence("api.visibility", ConfidenceScore::MAX)
            .unwrap();

        assert_eq!(
            comparison("member").subject(),
            comparison("member").subject()
        );
        assert_eq!(first, replay);
        assert_eq!(first.id(), later.id());
        assert_ne!(first, later);
        assert_ne!(
            comparison("member").subject(),
            comparison("admin").subject()
        );
    }

    #[test]
    fn comparison_round_trip_revalidates_bounded_contexts() {
        let paired = comparison("member");
        let encoded = serde_json::to_value(&paired).unwrap();

        assert_eq!(encoded["surface"], "graphql");

        assert_eq!(
            serde_json::from_value::<ApiVisibilityComparison>(encoded).unwrap(),
            paired
        );
        assert!(ApiVisibilityComparison::new(
            " ",
            ApiSurfaceKind::JsonHttp,
            ApiVisibilityPairKind::UiApi,
            ApiVisibilityResult::Equivalent,
            ApiVisibilityDimension::Status,
            "ui",
            "api",
            "scope",
        )
        .is_err());
        assert!(matches!(
            ApiVisibilityComparison::new(
                "comparison",
                ApiSurfaceKind::JsonHttp,
                ApiVisibilityPairKind::AuthorizationContext,
                ApiVisibilityResult::Different,
                ApiVisibilityDimension::Fields,
                "same-view",
                "same-view",
                "scope",
            ),
            Err(ApiVocabularyError::IdenticalContexts)
        ));
        assert!(matches!(
            comparison("member").to_evidence("api.visibility", ConfidenceScore::NONE),
            Err(ApiVocabularyError::ZeroReliability)
        ));
        assert!(ApiVisibilityComparison::new(
            "comparison",
            ApiSurfaceKind::JsonHttp,
            ApiVisibilityPairKind::UiApi,
            ApiVisibilityResult::Equivalent,
            ApiVisibilityDimension::Status,
            "a".repeat(MAX_OPAQUE_CONTEXT_BYTES + 1),
            "api",
            "scope",
        )
        .is_err());
    }
}
