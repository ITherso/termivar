//! Transport-neutral contracts for the opt-in bounded GraphQL review.
//!
//! This module owns deterministic endpoint selection, scanner-owned operation
//! generation, a metadata-first review catalog, and strict response
//! classification. It deliberately owns no executor, credential source, HTTP
//! client, report projection, or request authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use url::Url;

pub(crate) const GRAPHQL_REVIEW_STRATEGY_ID: &str = "web.review.graphql.introspection-pair@1";
pub(crate) const GRAPHQL_REVIEW_ALGORITHM_VERSION: &str = "graphql.surface-review/v1";
pub(crate) const MAX_GRAPHQL_SELECTED_ENDPOINTS: usize = 1;
pub(crate) const MAX_GRAPHQL_CHILD_REQUESTS: usize = 3;
pub(crate) const MAX_GRAPHQL_ACTIVE_VERIFICATIONS: usize = 1;
pub(crate) const MAX_GRAPHQL_ITEM_EVIDENCE_REFERENCES: usize = 3;
pub(crate) const MAX_GRAPHQL_NAME_BYTES: usize = 64;
pub(crate) const MAX_GRAPHQL_OPERATION_BYTES: usize = 768;
pub(crate) const MAX_GRAPHQL_REQUEST_JSON_BYTES: usize = 1_024;
pub(crate) const MAX_GRAPHQL_ENDPOINT_URL_BYTES: usize = 2_048;
pub(crate) const MAX_GRAPHQL_ENDPOINT_PATH_BYTES: usize = 1_024;
pub(crate) const MAX_GRAPHQL_ENDPOINT_HINTS: usize = 32;
pub(crate) const MAX_GRAPHQL_MEDIA_TYPE_BYTES: usize = 256;
pub(crate) const MAX_GRAPHQL_RESPONSE_BYTES: usize = 256 * 1_024;
pub(crate) const MAX_GRAPHQL_JSON_DEPTH: usize = 16;
pub(crate) const MAX_GRAPHQL_JSON_NODES: usize = 512;
pub(crate) const MAX_GRAPHQL_JSON_OBJECT_MEMBERS: usize = 128;
pub(crate) const MAX_GRAPHQL_JSON_ARRAY_LENGTH: usize = 32;
pub(crate) const MAX_GRAPHQL_JSON_STRING_BYTES: usize = 1_024;
pub(crate) const MAX_GRAPHQL_ERRORS: usize = 8;

const CONTROL_OPERATION_NAME: &str = "VenomGraphqlControlV1";
const CONTROL_ALIAS: &str = "venomControlV1";
const CANDIDATE_OPERATION_NAME: &str = "VenomGraphqlCandidateV1";
const CANDIDATE_ALIAS: &str = "venomCandidateV1";
const REPLAY_OPERATION_NAME: &str = "VenomGraphqlReplayV1";
const REPLAY_ALIAS: &str = "venomReplayV1";
const GRAPHQL_RESPONSE_MEDIA_TYPE: &str = "application/graphql-response+json";
const DUPLICATE_KEY_MARKER: &str = "graphql response contains a duplicate object key";
const LIMIT_MARKER: &str = "graphql response exceeded a checked parser limit";

/// Closed errors emitted before any transport operation exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum GraphqlReviewContractError {
    #[error("GraphQL name violates the bounded GraphQL Name contract")]
    InvalidName,
    #[error("GraphQL endpoint violates exact-origin or bounded endpoint policy")]
    InvalidEndpoint,
    #[error("GraphQL endpoint candidate count exceeds its compiled bound")]
    CandidateLimit,
    #[error("GraphQL operation exceeds its checked byte limit")]
    OperationLimit,
    #[error("GraphQL response limits exceed compiled hard ceilings")]
    InvalidLimits,
}

/// A bounded GraphQL Name. Debug output intentionally omits the token.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct GraphqlName(String);

impl GraphqlName {
    pub(crate) fn new(value: &str) -> Result<Self, GraphqlReviewContractError> {
        if value.is_empty()
            || value.len() > MAX_GRAPHQL_NAME_BYTES
            || !value.is_ascii()
            || !is_graphql_name_start(value.as_bytes()[0])
            || !value.as_bytes()[1..]
                .iter()
                .copied()
                .all(is_graphql_name_continue)
        {
            return Err(GraphqlReviewContractError::InvalidName);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GraphqlName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphqlName")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

fn is_graphql_name_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_graphql_name_continue(byte: u8) -> bool {
    is_graphql_name_start(byte) || byte.is_ascii_digit()
}

/// Strength and provenance of a candidate GraphQL endpoint.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum GraphqlEndpointSource {
    ExactResponseMediaType,
    ExactPathSegment,
    DiscoveredExactOriginReference,
    ConventionalGraphqlFallback,
    ConventionalApiGraphqlFallback,
}

impl GraphqlEndpointSource {
    const fn priority(self) -> u8 {
        match self {
            Self::ExactResponseMediaType => 0,
            Self::ExactPathSegment => 1,
            Self::DiscoveredExactOriginReference => 2,
            Self::ConventionalGraphqlFallback => 3,
            Self::ConventionalApiGraphqlFallback => 4,
        }
    }
}

/// A bounded candidate hint. The URL never appears in Debug output.
#[derive(Clone)]
pub(crate) struct GraphqlEndpointHint {
    url: Url,
    source: GraphqlEndpointSource,
}

impl GraphqlEndpointHint {
    pub(crate) fn response_media(
        url: Url,
        media_type: &str,
    ) -> Result<Option<Self>, GraphqlReviewContractError> {
        if normalize_media_type(media_type).as_deref() != Some(GRAPHQL_RESPONSE_MEDIA_TYPE) {
            return Ok(None);
        }
        validate_endpoint_shape(&url)?;
        Ok(Some(Self {
            url,
            source: GraphqlEndpointSource::ExactResponseMediaType,
        }))
    }

    pub(crate) fn exact_path(url: Url) -> Result<Option<Self>, GraphqlReviewContractError> {
        validate_endpoint_shape(&url)?;
        if !has_exact_graphql_path_segment(&url) {
            return Ok(None);
        }
        Ok(Some(Self {
            url,
            source: GraphqlEndpointSource::ExactPathSegment,
        }))
    }

    pub(crate) fn discovered_reference(
        url: Url,
    ) -> Result<Option<Self>, GraphqlReviewContractError> {
        validate_endpoint_shape(&url)?;
        if !has_exact_graphql_path_segment(&url) {
            return Ok(None);
        }
        Ok(Some(Self {
            url,
            source: GraphqlEndpointSource::DiscoveredExactOriginReference,
        }))
    }
}

impl fmt::Debug for GraphqlEndpointHint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphqlEndpointHint")
            .field("source", &self.source)
            .field("url_bytes", &self.url.as_str().len())
            .finish_non_exhaustive()
    }
}

/// Deduplicates and bounds discovery-owned hints before the strict selector.
///
/// The public contract selector intentionally rejects an over-limit caller.
/// Runtime discovery, however, is target-controlled and must not turn a large
/// or duplicate hint set into a code invariant. This adapter retains the
/// strongest source for each exact URL, ranks the distinct candidates, and
/// only then applies the compiled bound.
pub(crate) fn bound_runtime_graphql_endpoint_hints(
    authorized_origin: &Url,
    hints: impl IntoIterator<Item = GraphqlEndpointHint>,
) -> Vec<GraphqlEndpointHint> {
    let mut distinct = BTreeMap::<String, GraphqlEndpointHint>::new();
    for hint in hints {
        if !same_origin(authorized_origin, &hint.url) {
            continue;
        }
        let key = hint.url.as_str().to_owned();
        match distinct.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(hint);
            },
            std::collections::btree_map::Entry::Occupied(mut entry)
                if hint.source.priority() < entry.get().source.priority() =>
            {
                entry.insert(hint);
            },
            std::collections::btree_map::Entry::Occupied(_) => {},
        }
    }
    let mut ranked = distinct.into_values().collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        left.source
            .priority()
            .cmp(&right.source.priority())
            .then_with(|| left.url.path().len().cmp(&right.url.path().len()))
            .then_with(|| left.url.as_str().cmp(right.url.as_str()))
    });
    ranked.truncate(MAX_GRAPHQL_ENDPOINT_HINTS);
    ranked
}

/// Which conventional candidates an explicitly enabled host makes available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlFallbackPolicy {
    Disabled,
    GraphqlOnly,
    ApiGraphqlOnly,
    GraphqlThenApiGraphql,
}

impl GraphqlFallbackPolicy {
    /// Complete closed policy vocabulary for catalog and architecture checks.
    pub(crate) const fn all() -> [Self; 4] {
        [
            Self::Disabled,
            Self::GraphqlOnly,
            Self::ApiGraphqlOnly,
            Self::GraphqlThenApiGraphql,
        ]
    }
}

/// The single checked endpoint selected for V1. Debug is path-redacted.
#[derive(Clone)]
pub(crate) struct GraphqlEndpoint {
    url: Url,
    source: GraphqlEndpointSource,
    binding_digest: [u8; 32],
}

impl GraphqlEndpoint {
    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    pub(crate) const fn source(&self) -> GraphqlEndpointSource {
        self.source
    }

    pub(crate) const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
}

impl fmt::Debug for GraphqlEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphqlEndpoint")
            .field("source", &self.source)
            .field("binding", &encode_hex(self.binding_digest))
            .finish_non_exhaustive()
    }
}

/// Deterministically selects no more than one exact-origin endpoint.
pub(crate) fn select_graphql_endpoint(
    authorized_origin: &Url,
    hints: impl IntoIterator<Item = GraphqlEndpointHint>,
    fallback_policy: GraphqlFallbackPolicy,
) -> Result<Option<GraphqlEndpoint>, GraphqlReviewContractError> {
    validate_authorized_origin(authorized_origin)?;

    let mut candidates = Vec::new();
    for (index, hint) in hints.into_iter().enumerate() {
        if index >= MAX_GRAPHQL_ENDPOINT_HINTS {
            return Err(GraphqlReviewContractError::CandidateLimit);
        }
        if same_origin(authorized_origin, &hint.url) {
            candidates.push((hint.source, hint.url));
        }
    }
    append_fallbacks(authorized_origin, fallback_policy, &mut candidates)?;

    candidates.sort_by(|left, right| {
        left.0
            .priority()
            .cmp(&right.0.priority())
            .then_with(|| left.1.path().len().cmp(&right.1.path().len()))
            .then_with(|| left.1.as_str().cmp(right.1.as_str()))
    });
    candidates.dedup_by(|left, right| left.1 == right.1);

    Ok(candidates
        .into_iter()
        .take(MAX_GRAPHQL_SELECTED_ENDPOINTS)
        .next()
        .map(|(source, url)| GraphqlEndpoint {
            binding_digest: endpoint_binding_digest(&url),
            url,
            source,
        }))
}

fn append_fallbacks(
    authorized_origin: &Url,
    fallback_policy: GraphqlFallbackPolicy,
    candidates: &mut Vec<(GraphqlEndpointSource, Url)>,
) -> Result<(), GraphqlReviewContractError> {
    if matches!(
        fallback_policy,
        GraphqlFallbackPolicy::GraphqlOnly | GraphqlFallbackPolicy::GraphqlThenApiGraphql
    ) {
        candidates.push((
            GraphqlEndpointSource::ConventionalGraphqlFallback,
            fallback_url(authorized_origin, "/graphql")?,
        ));
    }
    if matches!(
        fallback_policy,
        GraphqlFallbackPolicy::ApiGraphqlOnly | GraphqlFallbackPolicy::GraphqlThenApiGraphql
    ) {
        candidates.push((
            GraphqlEndpointSource::ConventionalApiGraphqlFallback,
            fallback_url(authorized_origin, "/api/graphql")?,
        ));
    }
    Ok(())
}

fn fallback_url(origin: &Url, path: &str) -> Result<Url, GraphqlReviewContractError> {
    let mut url = origin.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    validate_endpoint_shape(&url)?;
    Ok(url)
}

fn validate_authorized_origin(origin: &Url) -> Result<(), GraphqlReviewContractError> {
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(GraphqlReviewContractError::InvalidEndpoint);
    }
    Ok(())
}

fn validate_endpoint_shape(url: &Url) -> Result<(), GraphqlReviewContractError> {
    validate_authorized_origin(url)?;
    if url.as_str().len() > MAX_GRAPHQL_ENDPOINT_URL_BYTES
        || url.path().len() > MAX_GRAPHQL_ENDPOINT_PATH_BYTES
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(GraphqlReviewContractError::InvalidEndpoint);
    }
    Ok(())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn has_exact_graphql_path_segment(url: &Url) -> bool {
    url.path_segments()
        .is_some_and(|segments| segments.into_iter().any(|segment| segment == "graphql"))
}

fn endpoint_binding_digest(url: &Url) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_framed(&mut hasher, b"graphql-endpoint-binding/v1");
    update_framed(&mut hasher, GRAPHQL_REVIEW_ALGORITHM_VERSION.as_bytes());
    update_framed(&mut hasher, url.scheme().as_bytes());
    update_framed(&mut hasher, url.host_str().unwrap_or_default().as_bytes());
    update_framed(
        &mut hasher,
        &url.port_or_known_default()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    update_framed(&mut hasher, url.path().as_bytes());
    hasher.finalize().into()
}

/// Closed operation roles for the exact three-request V1 protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlOperationRole {
    Control,
    IntrospectionCandidate,
    IntrospectionReplay,
}

/// One deterministic scanner-owned operation and its redacted receipt fields.
#[derive(Clone)]
pub(crate) struct GraphqlOperation {
    role: GraphqlOperationRole,
    operation_name: GraphqlName,
    alias: GraphqlName,
    body: Vec<u8>,
    body_digest: [u8; 32],
    endpoint_binding: [u8; 32],
}

impl GraphqlOperation {
    pub(crate) const fn role(&self) -> GraphqlOperationRole {
        self.role
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) const fn body_digest(&self) -> [u8; 32] {
        self.body_digest
    }

    pub(crate) fn body_digest_hex(&self) -> String {
        encode_hex(self.body_digest)
    }

    pub(crate) fn operation_name(&self) -> &GraphqlName {
        &self.operation_name
    }

    pub(crate) fn alias(&self) -> &GraphqlName {
        &self.alias
    }

    pub(crate) const fn endpoint_binding(&self) -> [u8; 32] {
        self.endpoint_binding
    }
}

impl fmt::Debug for GraphqlOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphqlOperation")
            .field("role", &self.role)
            .field("operation_name_bytes", &self.operation_name.as_str().len())
            .field("body_bytes", &self.body.len())
            .field("body_digest", &self.body_digest_hex())
            .field("endpoint_binding", &encode_hex(self.endpoint_binding))
            .finish_non_exhaustive()
    }
}

/// The complete deterministic operation set. It contains no target-controlled token.
#[derive(Clone, Debug)]
pub(crate) struct GraphqlOperationSet {
    control: GraphqlOperation,
    candidate: GraphqlOperation,
    replay: GraphqlOperation,
}

impl GraphqlOperationSet {
    pub(crate) fn v1(endpoint: &GraphqlEndpoint) -> Result<Self, GraphqlReviewContractError> {
        let endpoint_binding = endpoint.binding_digest();
        let operations = Self {
            control: build_operation(
                GraphqlOperationRole::Control,
                CONTROL_OPERATION_NAME,
                CONTROL_ALIAS,
                &format!("query {CONTROL_OPERATION_NAME} {{ {CONTROL_ALIAS}: __typename }}"),
                endpoint_binding,
            )?,
            candidate: build_operation(
                GraphqlOperationRole::IntrospectionCandidate,
                CANDIDATE_OPERATION_NAME,
                CANDIDATE_ALIAS,
                &format!(
                    "query {CANDIDATE_OPERATION_NAME} {{ {CANDIDATE_ALIAS}: __typename __schema {{ queryType {{ name }} mutationType {{ name }} subscriptionType {{ name }} }} }}"
                ),
                endpoint_binding,
            )?,
            replay: build_operation(
                GraphqlOperationRole::IntrospectionReplay,
                REPLAY_OPERATION_NAME,
                REPLAY_ALIAS,
                &format!(
                    "query {REPLAY_OPERATION_NAME} {{ {REPLAY_ALIAS}: __typename __schema {{ queryType {{ name }} mutationType {{ name }} subscriptionType {{ name }} }} }}"
                ),
                endpoint_binding,
            )?,
        };
        if operations.ordered().len() != MAX_GRAPHQL_CHILD_REQUESTS {
            return Err(GraphqlReviewContractError::OperationLimit);
        }
        Ok(operations)
    }

    pub(crate) fn control(&self) -> &GraphqlOperation {
        &self.control
    }

    pub(crate) fn candidate(&self) -> &GraphqlOperation {
        &self.candidate
    }

    pub(crate) fn replay(&self) -> &GraphqlOperation {
        &self.replay
    }

    pub(crate) fn ordered(&self) -> [&GraphqlOperation; MAX_GRAPHQL_CHILD_REQUESTS] {
        [&self.control, &self.candidate, &self.replay]
    }
}

fn build_operation(
    role: GraphqlOperationRole,
    operation_name: &str,
    alias: &str,
    query: &str,
    endpoint_binding: [u8; 32],
) -> Result<GraphqlOperation, GraphqlReviewContractError> {
    let operation_name = GraphqlName::new(operation_name)?;
    let alias = GraphqlName::new(alias)?;
    if query.len() > MAX_GRAPHQL_OPERATION_BYTES {
        return Err(GraphqlReviewContractError::OperationLimit);
    }
    let body = serde_json::to_vec(&serde_json::json!({ "query": query }))
        .map_err(|_| GraphqlReviewContractError::OperationLimit)?;
    if body.len() > MAX_GRAPHQL_REQUEST_JSON_BYTES {
        return Err(GraphqlReviewContractError::OperationLimit);
    }
    let mut hasher = Sha256::new();
    update_framed(&mut hasher, b"graphql-request-body/v1");
    update_framed(&mut hasher, &body);
    let body_digest = hasher.finalize().into();
    Ok(GraphqlOperation {
        role,
        operation_name,
        alias,
        body,
        body_digest,
        endpoint_binding,
    })
}

/// Execution availability is metadata, not request authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlReviewAvailability {
    Executable,
    MetadataOnly,
}

/// Closed V1/future protocol families. Only bounded root introspection executes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlReviewFamily {
    BoundedRootIntrospection,
    GetQuerySupport,
    JsonArrayBatching,
    FullSchemaEnumeration,
    DetailedErrorDisclosure,
    FieldSuggestions,
    AliasFanOut,
    DepthComplexity,
    PersistedQueries,
    MultipartUpload,
    Subscriptions,
    MutationCsrf,
    AuthorizationContext,
}

/// One stable catalog entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphqlReviewCatalogEntry {
    pub(crate) family: GraphqlReviewFamily,
    pub(crate) id: &'static str,
    pub(crate) revision: u16,
    pub(crate) availability: GraphqlReviewAvailability,
    pub(crate) request_cost: usize,
    pub(crate) active_verifications: usize,
}

/// Metadata-first catalog; catalog breadth never changes the executable count.
#[derive(Clone, Debug)]
pub(crate) struct GraphqlReviewCatalog {
    entries: Vec<GraphqlReviewCatalogEntry>,
}

impl GraphqlReviewCatalog {
    pub(crate) fn v1() -> Self {
        use GraphqlReviewAvailability::{Executable, MetadataOnly};
        use GraphqlReviewFamily::{
            AliasFanOut, AuthorizationContext, BoundedRootIntrospection, DepthComplexity,
            DetailedErrorDisclosure, FieldSuggestions, FullSchemaEnumeration, GetQuerySupport,
            JsonArrayBatching, MultipartUpload, MutationCsrf, PersistedQueries, Subscriptions,
        };
        Self {
            entries: vec![
                catalog_entry(
                    BoundedRootIntrospection,
                    "graphql.root-introspection",
                    Executable,
                ),
                catalog_entry(GetQuerySupport, "graphql.get-query", MetadataOnly),
                catalog_entry(
                    JsonArrayBatching,
                    "graphql.json-array-batching",
                    MetadataOnly,
                ),
                catalog_entry(FullSchemaEnumeration, "graphql.full-schema", MetadataOnly),
                catalog_entry(
                    DetailedErrorDisclosure,
                    "graphql.detailed-errors",
                    MetadataOnly,
                ),
                catalog_entry(FieldSuggestions, "graphql.field-suggestions", MetadataOnly),
                catalog_entry(AliasFanOut, "graphql.alias-fan-out", MetadataOnly),
                catalog_entry(DepthComplexity, "graphql.depth-complexity", MetadataOnly),
                catalog_entry(PersistedQueries, "graphql.persisted-queries", MetadataOnly),
                catalog_entry(MultipartUpload, "graphql.multipart-upload", MetadataOnly),
                catalog_entry(Subscriptions, "graphql.subscriptions", MetadataOnly),
                catalog_entry(MutationCsrf, "graphql.mutation-csrf", MetadataOnly),
                catalog_entry(
                    AuthorizationContext,
                    "graphql.authorization-context",
                    MetadataOnly,
                ),
            ],
        }
    }

    pub(crate) fn entries(&self) -> &[GraphqlReviewCatalogEntry] {
        &self.entries
    }

    pub(crate) fn executable(&self) -> Option<GraphqlReviewCatalogEntry> {
        self.entries.iter().copied().find(|entry| {
            entry.availability == GraphqlReviewAvailability::Executable
                && entry.request_cost == MAX_GRAPHQL_CHILD_REQUESTS
                && entry.active_verifications == MAX_GRAPHQL_ACTIVE_VERIFICATIONS
        })
    }
}

fn catalog_entry(
    family: GraphqlReviewFamily,
    id: &'static str,
    availability: GraphqlReviewAvailability,
) -> GraphqlReviewCatalogEntry {
    GraphqlReviewCatalogEntry {
        family,
        id,
        revision: 1,
        availability,
        request_cost: usize::from(availability == GraphqlReviewAvailability::Executable)
            * MAX_GRAPHQL_CHILD_REQUESTS,
        active_verifications: usize::from(availability == GraphqlReviewAvailability::Executable)
            * MAX_GRAPHQL_ACTIVE_VERIFICATIONS,
    }
}

/// Checked parser ceilings. A caller may narrow but never widen hard limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphqlResponseLimits {
    pub(crate) body_bytes: usize,
    pub(crate) depth: usize,
    pub(crate) nodes: usize,
    pub(crate) object_members: usize,
    pub(crate) array_length: usize,
    pub(crate) string_bytes: usize,
    pub(crate) errors: usize,
}

impl GraphqlResponseLimits {
    pub(crate) fn checked(self) -> Result<Self, GraphqlReviewContractError> {
        if self.body_bytes == 0
            || self.body_bytes > MAX_GRAPHQL_RESPONSE_BYTES
            || self.depth == 0
            || self.depth > MAX_GRAPHQL_JSON_DEPTH
            || self.nodes == 0
            || self.nodes > MAX_GRAPHQL_JSON_NODES
            || self.object_members == 0
            || self.object_members > MAX_GRAPHQL_JSON_OBJECT_MEMBERS
            || self.array_length == 0
            || self.array_length > MAX_GRAPHQL_JSON_ARRAY_LENGTH
            || self.string_bytes == 0
            || self.string_bytes > MAX_GRAPHQL_JSON_STRING_BYTES
            || self.errors == 0
            || self.errors > MAX_GRAPHQL_ERRORS
        {
            return Err(GraphqlReviewContractError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for GraphqlResponseLimits {
    fn default() -> Self {
        Self {
            body_bytes: MAX_GRAPHQL_RESPONSE_BYTES,
            depth: MAX_GRAPHQL_JSON_DEPTH,
            nodes: MAX_GRAPHQL_JSON_NODES,
            object_members: MAX_GRAPHQL_JSON_OBJECT_MEMBERS,
            array_length: MAX_GRAPHQL_JSON_ARRAY_LENGTH,
            string_bytes: MAX_GRAPHQL_JSON_STRING_BYTES,
            errors: MAX_GRAPHQL_ERRORS,
        }
    }
}

/// Bounded error categories; raw server messages are never retained.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum GraphqlErrorCategory {
    IntrospectionRestricted,
    ValidationError,
    ParseError,
    UnknownGraphqlError,
}

/// Transient schema-root equivalence evidence.
///
/// Equality includes a private digest of the exact bounded root names, while
/// Debug and report-facing accessors disclose only root presence. Runtime code
/// may use that digest inside its executor to compare the candidate and replay,
/// but it must never persist the digest as evidence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct GraphqlIntrospectionShape {
    query_root_present: bool,
    mutation_root_present: bool,
    subscription_root_present: bool,
    root_identity: [u8; 32],
}

impl GraphqlIntrospectionShape {
    pub(crate) const fn query_root_present(&self) -> bool {
        self.query_root_present
    }

    pub(crate) const fn mutation_root_present(&self) -> bool {
        self.mutation_root_present
    }

    pub(crate) const fn subscription_root_present(&self) -> bool {
        self.subscription_root_present
    }

    #[cfg(test)]
    pub(crate) fn semantically_matches(&self, replay: &Self) -> bool {
        self == replay
    }

    pub(crate) const fn root_identity_digest(&self) -> [u8; 32] {
        self.root_identity
    }
}

impl fmt::Debug for GraphqlIntrospectionShape {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphqlIntrospectionShape")
            .field("query_root_present", &self.query_root_present())
            .field("mutation_root_present", &self.mutation_root_present())
            .field(
                "subscription_root_present",
                &self.subscription_root_present(),
            )
            .finish_non_exhaustive()
    }
}

/// Strict classification of one correlated response leg.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlResponseClassification {
    ExactControlEnvelope,
    ExactIntrospectionEnvelope(GraphqlIntrospectionShape),
    StructuredGraphqlErrors(GraphqlErrorCategory),
    GenericJson,
    Html,
    UnsupportedMedia,
    MalformedJson,
    Ambiguous,
    Incomplete,
    Truncated,
}

/// Persistable response kind with no schema-root names or name-derived digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlResponseKind {
    ExactControlEnvelope,
    ExactIntrospectionEnvelope,
    StructuredGraphqlErrors(GraphqlErrorCategory),
    GenericJson,
    Html,
    UnsupportedMedia,
    MalformedJson,
    Ambiguous,
    Incomplete,
    Truncated,
}

impl GraphqlResponseClassification {
    pub(crate) const fn kind(self) -> GraphqlResponseKind {
        match self {
            Self::ExactControlEnvelope => GraphqlResponseKind::ExactControlEnvelope,
            Self::ExactIntrospectionEnvelope(_) => GraphqlResponseKind::ExactIntrospectionEnvelope,
            Self::StructuredGraphqlErrors(category) => {
                GraphqlResponseKind::StructuredGraphqlErrors(category)
            },
            Self::GenericJson => GraphqlResponseKind::GenericJson,
            Self::Html => GraphqlResponseKind::Html,
            Self::UnsupportedMedia => GraphqlResponseKind::UnsupportedMedia,
            Self::MalformedJson => GraphqlResponseKind::MalformedJson,
            Self::Ambiguous => GraphqlResponseKind::Ambiguous,
            Self::Incomplete => GraphqlResponseKind::Incomplete,
            Self::Truncated => GraphqlResponseKind::Truncated,
        }
    }
}

/// Response inputs are borrowed and deliberately have no Debug implementation.
pub(crate) struct GraphqlResponseInput<'a> {
    pub(crate) media_type: Option<&'a str>,
    pub(crate) body: &'a [u8],
    pub(crate) complete: bool,
    pub(crate) truncated: bool,
    pub(crate) operation: &'a GraphqlOperation,
}

/// Strict, bounded response classifier with no transport authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphqlResponseClassifier {
    limits: GraphqlResponseLimits,
}

impl GraphqlResponseClassifier {
    pub(crate) fn new(limits: GraphqlResponseLimits) -> Result<Self, GraphqlReviewContractError> {
        Ok(Self {
            limits: limits.checked()?,
        })
    }

    pub(crate) fn classify(
        &self,
        input: GraphqlResponseInput<'_>,
    ) -> GraphqlResponseClassification {
        if input.truncated {
            return GraphqlResponseClassification::Truncated;
        }
        if !input.complete || input.body.len() > self.limits.body_bytes {
            return GraphqlResponseClassification::Incomplete;
        }
        match classify_graphql_response_media(input.media_type) {
            GraphqlResponseMedia::Html => return GraphqlResponseClassification::Html,
            GraphqlResponseMedia::Unsupported => {
                return GraphqlResponseClassification::UnsupportedMedia;
            },
            GraphqlResponseMedia::JsonCompatible => {},
        }

        let value = match parse_strict_json(input.body, self.limits) {
            Ok(value) => value,
            Err(StrictParseFailure::DuplicateKey) => {
                return GraphqlResponseClassification::Ambiguous;
            },
            Err(StrictParseFailure::Limit) => return GraphqlResponseClassification::Incomplete,
            Err(StrictParseFailure::Malformed) => {
                return GraphqlResponseClassification::MalformedJson;
            },
        };
        classify_envelope(&value, input.operation, self.limits)
    }
}

impl Default for GraphqlResponseClassifier {
    fn default() -> Self {
        Self::new(GraphqlResponseLimits::default()).expect("compiled limits are valid")
    }
}

/// Terminal internal states; callers must not collapse incomplete states into success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlReviewOutcome {
    EndpointObserved,
    IntrospectionAvailable,
    IntrospectionRestricted,
    GenericJsonOnly,
    ReplayMismatch,
    Unsupported,
    Ambiguous,
    Incomplete,
}

/// Derives an outcome from the exact ordered response trio.
#[cfg(test)]
pub(crate) fn classify_graphql_review_outcome(
    control: GraphqlResponseClassification,
    candidate: GraphqlResponseClassification,
    replay: GraphqlResponseClassification,
) -> GraphqlReviewOutcome {
    let replay_matches_candidate_roots = match (candidate, replay) {
        (
            GraphqlResponseClassification::ExactIntrospectionEnvelope(candidate_shape),
            GraphqlResponseClassification::ExactIntrospectionEnvelope(replay_shape),
        ) => Some(candidate_shape.semantically_matches(&replay_shape)),
        _ => None,
    };
    classify_graphql_transport_outcome(
        control.kind(),
        candidate.kind(),
        replay.kind(),
        replay_matches_candidate_roots,
    )
}

/// Reconstructs the exact V1 outcome from persisted response kinds.
///
/// The executor performs schema-root name comparison while both bounded
/// responses are transient. Only the resulting boolean crosses the evidence
/// boundary, so low-entropy schema names and name-derived digests are not
/// retained.
pub(crate) fn classify_graphql_transport_outcome(
    control: GraphqlResponseKind,
    candidate: GraphqlResponseKind,
    replay: GraphqlResponseKind,
    replay_matches_candidate_roots: Option<bool>,
) -> GraphqlReviewOutcome {
    use GraphqlResponseKind as Response;
    use GraphqlReviewOutcome as Outcome;

    if is_incomplete_kind(control) || is_incomplete_kind(candidate) || is_incomplete_kind(replay) {
        return Outcome::Incomplete;
    }
    if control != Response::ExactControlEnvelope {
        return match control {
            Response::GenericJson => Outcome::GenericJsonOnly,
            Response::Ambiguous | Response::MalformedJson => Outcome::Ambiguous,
            _ => Outcome::Unsupported,
        };
    }
    match (candidate, replay) {
        (Response::ExactIntrospectionEnvelope, Response::ExactIntrospectionEnvelope)
            if replay_matches_candidate_roots == Some(true) =>
        {
            Outcome::IntrospectionAvailable
        },
        (
            Response::StructuredGraphqlErrors(GraphqlErrorCategory::IntrospectionRestricted),
            Response::StructuredGraphqlErrors(GraphqlErrorCategory::IntrospectionRestricted),
        ) => Outcome::IntrospectionRestricted,
        (Response::ExactIntrospectionEnvelope, _) => Outcome::ReplayMismatch,
        (Response::GenericJson, _) => Outcome::EndpointObserved,
        (Response::Ambiguous | Response::MalformedJson, _) => Outcome::Ambiguous,
        _ => Outcome::EndpointObserved,
    }
}

fn is_incomplete_kind(classification: GraphqlResponseKind) -> bool {
    matches!(
        classification,
        GraphqlResponseKind::Incomplete | GraphqlResponseKind::Truncated
    )
}

/// Logical items supported by this core. Both are observations only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlAssessmentKind {
    SurfaceObserved,
    AnonymousRootIntrospectionAvailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlMaximumDisposition {
    Informational,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlMaximumAuthority {
    KnowledgeOnly,
}

impl GraphqlAssessmentKind {
    pub(crate) const fn maximum_disposition(self) -> GraphqlMaximumDisposition {
        GraphqlMaximumDisposition::Informational
    }

    pub(crate) const fn maximum_authority(self) -> GraphqlMaximumAuthority {
        GraphqlMaximumAuthority::KnowledgeOnly
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphqlResponseMedia {
    JsonCompatible,
    Html,
    Unsupported,
}

/// Normalizes only the media-type essence and returns a closed input class.
/// Parameters are ignored; invalid/control-bearing values fail closed.
pub(crate) fn classify_graphql_response_media(media_type: Option<&str>) -> GraphqlResponseMedia {
    let Some(media_type) = media_type.and_then(normalize_media_type) else {
        return GraphqlResponseMedia::Unsupported;
    };
    if media_type == "text/html" {
        return GraphqlResponseMedia::Html;
    }
    if media_type == "application/json"
        || media_type == GRAPHQL_RESPONSE_MEDIA_TYPE
        || media_type.ends_with("+json")
    {
        return GraphqlResponseMedia::JsonCompatible;
    }
    GraphqlResponseMedia::Unsupported
}

fn normalize_media_type(value: &str) -> Option<String> {
    if value.len() > MAX_GRAPHQL_MEDIA_TYPE_BYTES {
        return None;
    }
    let essence = value.split(';').next()?.trim();
    if essence.is_empty()
        || !essence.is_ascii()
        || essence.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    Some(essence.to_ascii_lowercase())
}

enum StrictJsonValue {
    Null,
    Bool,
    Number,
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl StrictJsonValue {
    fn object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    fn array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    fn string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictParseFailure {
    DuplicateKey,
    Limit,
    Malformed,
}

#[derive(Default)]
struct ParseCounters {
    nodes: usize,
}

struct StrictJsonSeed<'a> {
    limits: GraphqlResponseLimits,
    counters: &'a mut ParseCounters,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = StrictJsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > self.limits.depth {
            return Err(de::Error::custom(LIMIT_MARKER));
        }
        deserializer.deserialize_any(StrictJsonVisitor {
            limits: self.limits,
            counters: self.counters,
            depth: self.depth,
        })
    }
}

struct StrictJsonVisitor<'a> {
    limits: GraphqlResponseLimits,
    counters: &'a mut ParseCounters,
    depth: usize,
}

impl StrictJsonVisitor<'_> {
    fn count_node<E: de::Error>(&mut self) -> Result<(), E> {
        self.counters.nodes = self
            .counters
            .nodes
            .checked_add(1)
            .ok_or_else(|| E::custom(LIMIT_MARKER))?;
        if self.counters.nodes > self.limits.nodes {
            return Err(E::custom(LIMIT_MARKER));
        }
        Ok(())
    }
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_unit<E: de::Error>(mut self) -> Result<Self::Value, E> {
        self.count_node()?;
        Ok(StrictJsonValue::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }

    fn visit_bool<E: de::Error>(mut self, _value: bool) -> Result<Self::Value, E> {
        self.count_node()?;
        Ok(StrictJsonValue::Bool)
    }

    fn visit_i64<E: de::Error>(mut self, _value: i64) -> Result<Self::Value, E> {
        self.count_node()?;
        Ok(StrictJsonValue::Number)
    }

    fn visit_u64<E: de::Error>(mut self, _value: u64) -> Result<Self::Value, E> {
        self.count_node()?;
        Ok(StrictJsonValue::Number)
    }

    fn visit_f64<E: de::Error>(mut self, _value: f64) -> Result<Self::Value, E> {
        self.count_node()?;
        Ok(StrictJsonValue::Number)
    }

    fn visit_str<E: de::Error>(mut self, value: &str) -> Result<Self::Value, E> {
        self.count_node()?;
        if value.len() > self.limits.string_bytes {
            return Err(E::custom(LIMIT_MARKER));
        }
        Ok(StrictJsonValue::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.visit_str(&value)
    }

    fn visit_seq<A>(mut self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.count_node()?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            limits: self.limits,
            counters: &mut *self.counters,
            depth: self.depth + 1,
        })? {
            if values.len() >= self.limits.array_length {
                return Err(de::Error::custom(LIMIT_MARKER));
            }
            values.push(value);
        }
        Ok(StrictJsonValue::Array(values))
    }

    fn visit_map<A>(mut self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.count_node()?;
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > self.limits.string_bytes {
                return Err(de::Error::custom(LIMIT_MARKER));
            }
            if values.len() >= self.limits.object_members {
                return Err(de::Error::custom(LIMIT_MARKER));
            }
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            let value = map.next_value_seed(StrictJsonSeed {
                limits: self.limits,
                counters: &mut *self.counters,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(StrictJsonValue::Object(values))
    }
}

fn parse_strict_json(
    body: &[u8],
    limits: GraphqlResponseLimits,
) -> Result<StrictJsonValue, StrictParseFailure> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let mut counters = ParseCounters::default();
    let parsed = StrictJsonSeed {
        limits,
        counters: &mut counters,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| {
        let message = error.to_string();
        if message.contains(DUPLICATE_KEY_MARKER) {
            StrictParseFailure::DuplicateKey
        } else if message.contains(LIMIT_MARKER) {
            StrictParseFailure::Limit
        } else {
            StrictParseFailure::Malformed
        }
    })?;
    deserializer
        .end()
        .map_err(|_| StrictParseFailure::Malformed)?;
    Ok(parsed)
}

fn classify_envelope(
    value: &StrictJsonValue,
    operation: &GraphqlOperation,
    limits: GraphqlResponseLimits,
) -> GraphqlResponseClassification {
    let Some(root) = value.object() else {
        return GraphqlResponseClassification::GenericJson;
    };
    if root.contains_key("errors") {
        if root.contains_key("data") {
            return GraphqlResponseClassification::Ambiguous;
        }
        return classify_error_envelope(root.get("errors"), limits);
    }
    let Some(data) = root.get("data").and_then(StrictJsonValue::object) else {
        return GraphqlResponseClassification::GenericJson;
    };
    if root.len() != 1 {
        return GraphqlResponseClassification::Ambiguous;
    }
    match operation.role() {
        GraphqlOperationRole::Control => classify_control_data(data, operation.alias()),
        GraphqlOperationRole::IntrospectionCandidate
        | GraphqlOperationRole::IntrospectionReplay => {
            classify_introspection_data(data, operation.alias())
        },
    }
}

fn classify_control_data(
    data: &BTreeMap<String, StrictJsonValue>,
    alias: &GraphqlName,
) -> GraphqlResponseClassification {
    if data.len() == 1
        && !data.contains_key("__schema")
        && data
            .get(alias.as_str())
            .and_then(StrictJsonValue::string)
            .is_some()
    {
        GraphqlResponseClassification::ExactControlEnvelope
    } else {
        GraphqlResponseClassification::Ambiguous
    }
}

fn classify_introspection_data(
    data: &BTreeMap<String, StrictJsonValue>,
    alias: &GraphqlName,
) -> GraphqlResponseClassification {
    if data.len() != 2 {
        return GraphqlResponseClassification::Ambiguous;
    }
    let Some(response_typename) = data
        .get(alias.as_str())
        .and_then(StrictJsonValue::string)
        .and_then(|name| GraphqlName::new(name).ok())
    else {
        return GraphqlResponseClassification::Ambiguous;
    };
    let Some(schema) = data.get("__schema").and_then(StrictJsonValue::object) else {
        return GraphqlResponseClassification::Ambiguous;
    };
    if schema.len() != 3 {
        return GraphqlResponseClassification::Ambiguous;
    }
    let Some(query_root) = root_type_name(schema.get("queryType"), true) else {
        return GraphqlResponseClassification::Ambiguous;
    };
    let Some(mutation_root) = root_type_name(schema.get("mutationType"), false) else {
        return GraphqlResponseClassification::Ambiguous;
    };
    let Some(subscription_root) = root_type_name(schema.get("subscriptionType"), false) else {
        return GraphqlResponseClassification::Ambiguous;
    };
    let Some(query_root) = query_root else {
        return GraphqlResponseClassification::Ambiguous;
    };
    if response_typename != query_root {
        return GraphqlResponseClassification::Ambiguous;
    }
    let mut hasher = Sha256::new();
    update_framed(&mut hasher, b"graphql-schema-root-identity/v1");
    update_framed(&mut hasher, query_root.as_str().as_bytes());
    update_optional_name(&mut hasher, mutation_root.as_ref());
    update_optional_name(&mut hasher, subscription_root.as_ref());
    GraphqlResponseClassification::ExactIntrospectionEnvelope(GraphqlIntrospectionShape {
        query_root_present: true,
        mutation_root_present: mutation_root.is_some(),
        subscription_root_present: subscription_root.is_some(),
        root_identity: hasher.finalize().into(),
    })
}

fn root_type_name(value: Option<&StrictJsonValue>, required: bool) -> Option<Option<GraphqlName>> {
    match value? {
        StrictJsonValue::Null if !required => Some(None),
        StrictJsonValue::Object(object) if object.len() == 1 => {
            let name = object.get("name")?.string()?;
            GraphqlName::new(name).ok().map(Some)
        },
        _ => None,
    }
}

fn update_optional_name(hasher: &mut Sha256, value: Option<&GraphqlName>) {
    match value {
        Some(value) => {
            update_framed(hasher, b"present");
            update_framed(hasher, value.as_str().as_bytes());
        },
        None => update_framed(hasher, b"absent"),
    }
}

fn classify_error_envelope(
    value: Option<&StrictJsonValue>,
    limits: GraphqlResponseLimits,
) -> GraphqlResponseClassification {
    let Some(errors) = value.and_then(StrictJsonValue::array) else {
        return GraphqlResponseClassification::Ambiguous;
    };
    if errors.is_empty() || errors.len() > limits.errors {
        return if errors.len() > limits.errors {
            GraphqlResponseClassification::Incomplete
        } else {
            GraphqlResponseClassification::Ambiguous
        };
    }

    let mut categories = BTreeSet::new();
    for error in errors {
        let Some(message) = error
            .object()
            .and_then(|object| object.get("message"))
            .and_then(StrictJsonValue::string)
        else {
            return GraphqlResponseClassification::Ambiguous;
        };
        categories.insert(classify_error_message(message));
    }
    let category = if categories.contains(&GraphqlErrorCategory::IntrospectionRestricted) {
        GraphqlErrorCategory::IntrospectionRestricted
    } else if categories.len() == 1 {
        *categories
            .first()
            .expect("a non-empty error vector produces one category")
    } else {
        GraphqlErrorCategory::UnknownGraphqlError
    };
    GraphqlResponseClassification::StructuredGraphqlErrors(category)
}

fn classify_error_message(message: &str) -> GraphqlErrorCategory {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("introspection")
        && ["disabled", "denied", "not allowed", "forbidden"]
            .iter()
            .any(|marker| normalized.contains(marker))
    {
        GraphqlErrorCategory::IntrospectionRestricted
    } else if normalized.contains("validation")
        || normalized.contains("cannot query field")
        || normalized.contains("unknown field")
    {
        GraphqlErrorCategory::ValidationError
    } else if normalized.contains("syntax") || normalized.contains("parse") {
        GraphqlErrorCategory::ParseError
    } else {
        GraphqlErrorCategory::UnknownGraphqlError
    }
}

fn update_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn encode_hex(bytes: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "GRAPHQL-REVIEW-MUST-NOT-LEAK-SECRET-1F92A7";

    fn origin() -> Url {
        Url::parse("https://example.test/base").unwrap()
    }

    fn endpoint() -> GraphqlEndpoint {
        select_graphql_endpoint(&origin(), [], GraphqlFallbackPolicy::GraphqlThenApiGraphql)
            .unwrap()
            .unwrap()
    }

    fn operations() -> GraphqlOperationSet {
        GraphqlOperationSet::v1(&endpoint()).unwrap()
    }

    fn classify(
        operation: &GraphqlOperation,
        media_type: Option<&str>,
        body: &[u8],
    ) -> GraphqlResponseClassification {
        GraphqlResponseClassifier::default().classify(GraphqlResponseInput {
            media_type,
            body,
            complete: true,
            truncated: false,
            operation,
        })
    }

    fn introspection_body(alias: &str, mutation: &str, subscription: &str) -> Vec<u8> {
        format!(
            r#"{{"data":{{"{alias}":"Query","__schema":{{"queryType":{{"name":"Query"}},"mutationType":{mutation},"subscriptionType":{subscription}}}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn graphql_names_pin_the_bounded_grammar() {
        for valid in ["_", "Query", "_root2", "A0_b"] {
            assert_eq!(GraphqlName::new(valid).unwrap().as_str(), valid);
        }
        for invalid in ["", "0Query", "with-hyphen", "two names", "é"] {
            assert_eq!(
                GraphqlName::new(invalid).unwrap_err(),
                GraphqlReviewContractError::InvalidName
            );
        }
        assert!(GraphqlName::new(&"a".repeat(MAX_GRAPHQL_NAME_BYTES)).is_ok());
        assert!(GraphqlName::new(&"a".repeat(MAX_GRAPHQL_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn arbitrary_bounded_name_bytes_never_escape_the_name_grammar() {
        for length in 0..=MAX_GRAPHQL_NAME_BYTES + 1 {
            for byte in [0_u8, b' ', b'-', b'0', b'A', b'_', b'z', 0x7f, 0xff] {
                let candidate = String::from_utf8(vec![byte; length]);
                if let Ok(candidate) = candidate {
                    if let Ok(name) = GraphqlName::new(&candidate) {
                        let bytes = name.as_str().as_bytes();
                        assert!(is_graphql_name_start(bytes[0]));
                        assert!(bytes[1..].iter().copied().all(is_graphql_name_continue));
                    }
                }
            }
        }
    }

    #[test]
    fn endpoint_selection_uses_strength_then_canonical_order() {
        let path =
            GraphqlEndpointHint::exact_path(Url::parse("https://example.test/z/graphql").unwrap())
                .unwrap()
                .unwrap();
        let media = GraphqlEndpointHint::response_media(
            Url::parse("https://example.test/longer-endpoint").unwrap(),
            "Application/GraphQL-Response+JSON; charset=utf-8",
        )
        .unwrap()
        .unwrap();
        let selected = select_graphql_endpoint(
            &origin(),
            [path, media],
            GraphqlFallbackPolicy::GraphqlThenApiGraphql,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected.source(),
            GraphqlEndpointSource::ExactResponseMediaType
        );
        assert_eq!(selected.url().path(), "/longer-endpoint");
    }

    #[test]
    fn discovered_reference_is_bounded_exact_origin_evidence() {
        let hint = GraphqlEndpointHint::discovered_reference(
            Url::parse("https://example.test/forms/graphql").unwrap(),
        )
        .unwrap()
        .unwrap();
        let selected = select_graphql_endpoint(&origin(), [hint], GraphqlFallbackPolicy::Disabled)
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.source(),
            GraphqlEndpointSource::DiscoveredExactOriginReference
        );
        assert_eq!(selected.url().path(), "/forms/graphql");
    }

    #[test]
    fn endpoint_selection_is_exact_origin_and_maximum_one() {
        let cross_origin =
            GraphqlEndpointHint::exact_path(Url::parse("https://outside.test/graphql").unwrap())
                .unwrap()
                .unwrap();
        let same_origin =
            GraphqlEndpointHint::exact_path(Url::parse("https://example.test/a/graphql").unwrap())
                .unwrap()
                .unwrap();
        let selected = select_graphql_endpoint(
            &origin(),
            [cross_origin, same_origin],
            GraphqlFallbackPolicy::Disabled,
        )
        .unwrap();
        assert_eq!(
            MAX_GRAPHQL_SELECTED_ENDPOINTS,
            usize::from(selected.is_some())
        );
        assert_eq!(selected.unwrap().url().path(), "/a/graphql");
    }

    #[test]
    fn endpoint_hint_count_is_bounded_before_selection() {
        let hint =
            GraphqlEndpointHint::exact_path(Url::parse("https://example.test/graphql").unwrap())
                .unwrap()
                .unwrap();
        assert_eq!(
            select_graphql_endpoint(
                &origin(),
                vec![hint; MAX_GRAPHQL_ENDPOINT_HINTS + 1],
                GraphqlFallbackPolicy::Disabled,
            )
            .unwrap_err(),
            GraphqlReviewContractError::CandidateLimit
        );
    }

    #[test]
    fn runtime_hints_deduplicate_rank_and_bound_before_strict_selection() {
        let authorized_origin = origin();
        let strongest_url = Url::parse("https://example.test/observed").unwrap();
        let mut hints = Vec::new();
        for index in 0..(MAX_GRAPHQL_ENDPOINT_HINTS * 2) {
            hints.push(
                GraphqlEndpointHint::exact_path(
                    Url::parse(&format!("https://example.test/{index:03}/graphql")).unwrap(),
                )
                .unwrap()
                .unwrap(),
            );
        }
        let duplicate_path = Url::parse("https://example.test/shared/graphql").unwrap();
        hints.extend(
            std::iter::repeat_with(|| {
                GraphqlEndpointHint::exact_path(duplicate_path.clone())
                    .unwrap()
                    .unwrap()
            })
            .take(MAX_GRAPHQL_ENDPOINT_HINTS * 2),
        );
        hints.extend(
            std::iter::repeat_with(|| {
                GraphqlEndpointHint::response_media(
                    strongest_url.clone(),
                    "application/graphql-response+json",
                )
                .unwrap()
                .unwrap()
            })
            .take(MAX_GRAPHQL_ENDPOINT_HINTS * 2),
        );
        hints.push(
            GraphqlEndpointHint::exact_path(Url::parse("https://outside.test/graphql").unwrap())
                .unwrap()
                .unwrap(),
        );

        let bounded = bound_runtime_graphql_endpoint_hints(&authorized_origin, hints);
        assert_eq!(bounded.len(), MAX_GRAPHQL_ENDPOINT_HINTS);
        assert_eq!(
            bounded[0].source,
            GraphqlEndpointSource::ExactResponseMediaType
        );
        assert_eq!(bounded[0].url, strongest_url);
        assert_eq!(
            bounded
                .iter()
                .map(|hint| hint.url.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            bounded.len()
        );
        assert_eq!(
            bounded
                .iter()
                .filter(|hint| hint.url == strongest_url)
                .count(),
            1
        );
        let selected = select_graphql_endpoint(
            &authorized_origin,
            bounded,
            GraphqlFallbackPolicy::GraphqlThenApiGraphql,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected.source(),
            GraphqlEndpointSource::ExactResponseMediaType
        );
        assert_eq!(selected.url(), &strongest_url);
    }

    #[test]
    fn endpoint_policy_rejects_credentials_fragments_queries_and_bounds() {
        for raw in [
            "https://user:secret@example.test/graphql",
            "https://example.test/graphql#fragment",
            "https://example.test/graphql?secret=value",
            "file:///graphql",
        ] {
            assert_eq!(
                GraphqlEndpointHint::exact_path(Url::parse(raw).unwrap()).unwrap_err(),
                GraphqlReviewContractError::InvalidEndpoint
            );
        }
        let oversized = format!("https://example.test/{}/graphql", "a".repeat(2_100));
        assert_eq!(
            GraphqlEndpointHint::exact_path(Url::parse(&oversized).unwrap()).unwrap_err(),
            GraphqlReviewContractError::InvalidEndpoint
        );
    }

    #[test]
    fn exact_path_and_media_evidence_are_not_substring_matches() {
        assert!(GraphqlEndpointHint::exact_path(
            Url::parse("https://example.test/notgraphql").unwrap()
        )
        .unwrap()
        .is_none());
        assert!(GraphqlEndpointHint::response_media(
            Url::parse("https://example.test/graphql").unwrap(),
            "application/jsonp; note=application/graphql-response+json"
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn conventional_fallbacks_are_explicit_and_deterministic() {
        let primary =
            select_graphql_endpoint(&origin(), [], GraphqlFallbackPolicy::GraphqlThenApiGraphql)
                .unwrap()
                .unwrap();
        assert_eq!(primary.url().path(), "/graphql");
        let secondary =
            select_graphql_endpoint(&origin(), [], GraphqlFallbackPolicy::ApiGraphqlOnly)
                .unwrap()
                .unwrap();
        assert_eq!(secondary.url().path(), "/api/graphql");
        assert!(
            select_graphql_endpoint(&origin(), [], GraphqlFallbackPolicy::Disabled)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn operation_trio_is_fixed_bounded_read_only_and_distinct() {
        let operations = operations();
        assert_eq!(operations.ordered().len(), MAX_GRAPHQL_CHILD_REQUESTS);
        let mut digests = BTreeSet::new();
        for operation in operations.ordered() {
            assert!(operation.body().len() <= MAX_GRAPHQL_REQUEST_JSON_BYTES);
            assert!(digests.insert(operation.body_digest()));
            assert!(GraphqlName::new(operation.operation_name().as_str()).is_ok());
            assert!(GraphqlName::new(operation.alias().as_str()).is_ok());
            let body = std::str::from_utf8(operation.body()).unwrap();
            assert!(body.contains("\"query\""));
            assert!(!body.contains("mutation "));
            assert!(!body.contains("subscription "));
            assert!(!body.contains("variables"));
            assert!(!body.contains("fragment "));
            assert!(!body.contains('@'));
        }
        assert!(std::str::from_utf8(operations.control().body())
            .unwrap()
            .contains("__typename"));
        assert!(!std::str::from_utf8(operations.control().body())
            .unwrap()
            .contains("__schema"));
        for operation in [operations.candidate(), operations.replay()] {
            let body = std::str::from_utf8(operation.body()).unwrap();
            assert!(body.contains("__schema"));
            assert!(body.contains("queryType"));
            assert!(body.contains("mutationType"));
            assert!(body.contains("subscriptionType"));
            assert!(!body.contains("types"));
            assert!(!body.contains("fields"));
        }
    }

    #[test]
    fn operation_generation_is_repeatedly_deterministic_and_endpoint_bound() {
        let first = operations();
        let second = operations();
        for (left, right) in first.ordered().into_iter().zip(second.ordered()) {
            assert_eq!(left.body(), right.body());
            assert_eq!(left.body_digest(), right.body_digest());
            assert_eq!(left.endpoint_binding(), right.endpoint_binding());
        }
        let other = select_graphql_endpoint(
            &Url::parse("https://example.test/root").unwrap(),
            [],
            GraphqlFallbackPolicy::ApiGraphqlOnly,
        )
        .unwrap()
        .unwrap();
        let other = GraphqlOperationSet::v1(&other).unwrap();
        assert_eq!(first.control().body(), other.control().body());
        assert_ne!(
            first.control().endpoint_binding(),
            other.control().endpoint_binding()
        );
    }

    #[test]
    fn catalog_has_one_executable_and_future_metadata_adds_no_obligation() {
        let catalog = GraphqlReviewCatalog::v1();
        assert!(catalog.entries().len() > 10);
        assert_eq!(
            catalog
                .entries()
                .iter()
                .filter(|entry| entry.availability == GraphqlReviewAvailability::Executable)
                .count(),
            1
        );
        assert_eq!(
            catalog.executable().unwrap().family,
            GraphqlReviewFamily::BoundedRootIntrospection
        );
        assert_eq!(
            catalog.executable().unwrap().request_cost,
            MAX_GRAPHQL_CHILD_REQUESTS
        );
        assert_eq!(
            catalog.executable().unwrap().active_verifications,
            MAX_GRAPHQL_ACTIVE_VERIFICATIONS
        );
        assert!(catalog
            .entries()
            .iter()
            .filter(|entry| entry.availability == GraphqlReviewAvailability::MetadataOnly)
            .all(|entry| entry.request_cost == 0 && entry.active_verifications == 0));
        assert!(catalog.entries().iter().all(|entry| entry.revision == 1));
    }

    #[test]
    fn exact_control_envelope_requires_only_the_correlated_alias() {
        let operations = operations();
        let body = format!(r#"{{"data":{{"{}":"Query"}}}}"#, CONTROL_ALIAS);
        assert_eq!(
            classify(
                operations.control(),
                Some("application/graphql-response+json"),
                body.as_bytes()
            ),
            GraphqlResponseClassification::ExactControlEnvelope
        );
        for body in [
            r#"{"data":{"wrong":"Query"}}"#,
            r#"{"data":{"venomControlV1":"Query","extra":true}}"#,
            r#"{"data":{"venomControlV1":7}}"#,
            r#"{"data":{"venomControlV1":"Query","__schema":{}}}"#,
        ] {
            assert_eq!(
                classify(
                    operations.control(),
                    Some("application/json"),
                    body.as_bytes()
                ),
                GraphqlResponseClassification::Ambiguous
            );
        }
    }

    #[test]
    fn exact_introspection_envelope_retains_booleans_not_root_names() {
        let operations = operations();
        let body = introspection_body(CANDIDATE_ALIAS, r#"{"name":"Mutation"}"#, "null");
        let classification = classify(
            operations.candidate(),
            Some("application/json; charset=utf-8"),
            &body,
        );
        let GraphqlResponseClassification::ExactIntrospectionEnvelope(shape) = classification
        else {
            panic!("expected exact introspection envelope");
        };
        assert!(shape.query_root_present());
        assert!(shape.mutation_root_present());
        assert!(!shape.subscription_root_present());
        let rendered = format!(
            "{:?}",
            classify(operations.candidate(), Some("application/json"), &body)
        );
        assert!(!rendered.contains("Query"));
        assert!(!rendered.contains("Mutation"));
    }

    #[test]
    fn exact_introspection_envelope_records_subscription_root_presence() {
        let operations = operations();
        let body = introspection_body(
            CANDIDATE_ALIAS,
            r#"{"name":"Mutation"}"#,
            r#"{"name":"Subscription"}"#,
        );
        let GraphqlResponseClassification::ExactIntrospectionEnvelope(shape) = classify(
            operations.candidate(),
            Some("application/graphql-response+json"),
            &body,
        ) else {
            panic!("expected exact introspection envelope");
        };
        assert!(shape.query_root_present());
        assert!(shape.mutation_root_present());
        assert!(shape.subscription_root_present());
        let debug = format!("{shape:?}");
        assert!(!debug.contains("Query"));
        assert!(!debug.contains("Mutation"));
        assert!(!debug.contains("Subscription"));
    }

    #[test]
    fn replay_requires_its_distinct_alias() {
        let operations = operations();
        let candidate = introspection_body(CANDIDATE_ALIAS, "null", "null");
        assert_eq!(
            classify(operations.replay(), Some("application/json"), &candidate),
            GraphqlResponseClassification::Ambiguous
        );
        let replay = introspection_body(REPLAY_ALIAS, "null", "null");
        assert!(matches!(
            classify(operations.replay(), Some("application/json"), &replay),
            GraphqlResponseClassification::ExactIntrospectionEnvelope(_)
        ));
    }

    #[test]
    fn malformed_missing_and_ambiguous_root_shapes_fail_closed() {
        let operations = operations();
        for body in [
            format!(
                r#"{{"data":{{"{CANDIDATE_ALIAS}":"Query","__schema":{{"queryType":null,"mutationType":null,"subscriptionType":null}}}}}}"#
            ),
            format!(
                r#"{{"data":{{"{CANDIDATE_ALIAS}":"Query","__schema":{{"queryType":{{"name":"not valid"}},"mutationType":null,"subscriptionType":null}}}}}}"#
            ),
            format!(r#"{{"data":{{"{CANDIDATE_ALIAS}":"Query"}}}}"#),
        ] {
            assert_eq!(
                classify(
                    operations.candidate(),
                    Some("application/json"),
                    body.as_bytes()
                ),
                GraphqlResponseClassification::Ambiguous
            );
        }
    }

    #[test]
    fn duplicate_keys_at_any_depth_are_ambiguous() {
        let operations = operations();
        for body in [
            r#"{"data":{},"data":{}}"#,
            r#"{"data":{"venomControlV1":"Query","venomControlV1":"Other"}}"#,
            r#"{"data":{"venomCandidateV1":"Query","__schema":{"queryType":{"name":"Query","name":"Other"},"mutationType":null,"subscriptionType":null}}}"#,
        ] {
            assert_eq!(
                classify(
                    operations.control(),
                    Some("application/json"),
                    body.as_bytes()
                ),
                GraphqlResponseClassification::Ambiguous
            );
        }
    }

    #[test]
    fn structured_errors_are_bounded_and_conservative() {
        let operations = operations();
        for (message, expected) in [
            (
                "GraphQL introspection is disabled",
                GraphqlErrorCategory::IntrospectionRestricted,
            ),
            (
                "Cannot query field __schema",
                GraphqlErrorCategory::ValidationError,
            ),
            ("Syntax error", GraphqlErrorCategory::ParseError),
            ("opaque failure", GraphqlErrorCategory::UnknownGraphqlError),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({
                "errors": [{"message": message}]
            }))
            .unwrap();
            assert_eq!(
                classify(
                    operations.candidate(),
                    Some("application/graphql-response+json"),
                    &body
                ),
                GraphqlResponseClassification::StructuredGraphqlErrors(expected)
            );
        }
        assert_eq!(
            classify(
                operations.candidate(),
                Some("application/json"),
                br#"{"errors":[]}"#
            ),
            GraphqlResponseClassification::Ambiguous
        );
    }

    #[test]
    fn partial_data_with_errors_is_never_introspection_success() {
        let operations = operations();
        let body = format!(
            r#"{{"data":{{"{CANDIDATE_ALIAS}":"Query"}},"errors":[{{"message":"introspection disabled"}}]}}"#
        );
        assert_eq!(
            classify(
                operations.candidate(),
                Some("application/json"),
                body.as_bytes()
            ),
            GraphqlResponseClassification::Ambiguous
        );
    }

    #[test]
    fn generic_json_html_unsupported_and_malformed_are_distinct() {
        let operations = operations();
        assert_eq!(
            classify(
                operations.control(),
                Some("application/json"),
                br#"{"ok":true}"#
            ),
            GraphqlResponseClassification::GenericJson
        );
        assert_eq!(
            classify(
                operations.control(),
                Some("text/html; charset=utf-8"),
                b"<p>graphql</p>"
            ),
            GraphqlResponseClassification::Html
        );
        assert_eq!(
            classify(
                operations.control(),
                Some("application/octet-stream"),
                b"{}"
            ),
            GraphqlResponseClassification::UnsupportedMedia
        );
        assert_eq!(
            classify(operations.control(), Some("application/json"), b"{"),
            GraphqlResponseClassification::MalformedJson
        );
    }

    #[test]
    fn normalized_media_classification_is_closed_and_parameter_tolerant() {
        assert_eq!(
            classify_graphql_response_media(Some(
                "Application/GraphQL-Response+JSON; charset=utf-8"
            )),
            GraphqlResponseMedia::JsonCompatible
        );
        assert_eq!(
            classify_graphql_response_media(Some("application/problem+json")),
            GraphqlResponseMedia::JsonCompatible
        );
        assert_eq!(
            classify_graphql_response_media(Some("text/html; charset=utf-8")),
            GraphqlResponseMedia::Html
        );
        for unsupported in [None, Some(""), Some("application/octet-stream")] {
            assert_eq!(
                classify_graphql_response_media(unsupported),
                GraphqlResponseMedia::Unsupported
            );
        }
        assert_eq!(
            classify_graphql_response_media(Some(&"a".repeat(MAX_GRAPHQL_MEDIA_TYPE_BYTES + 1))),
            GraphqlResponseMedia::Unsupported
        );
    }

    #[test]
    fn truncation_completion_and_body_limits_never_become_success() {
        let operations = operations();
        let classifier = GraphqlResponseClassifier::default();
        let body = format!(r#"{{"data":{{"{CONTROL_ALIAS}":"Query"}}}}"#);
        assert_eq!(
            classifier.classify(GraphqlResponseInput {
                media_type: Some("application/json"),
                body: body.as_bytes(),
                complete: true,
                truncated: true,
                operation: operations.control(),
            }),
            GraphqlResponseClassification::Truncated
        );
        assert_eq!(
            classifier.classify(GraphqlResponseInput {
                media_type: Some("application/json"),
                body: body.as_bytes(),
                complete: false,
                truncated: false,
                operation: operations.control(),
            }),
            GraphqlResponseClassification::Incomplete
        );
        let narrow = GraphqlResponseClassifier::new(GraphqlResponseLimits {
            body_bytes: body.len() - 1,
            ..GraphqlResponseLimits::default()
        })
        .unwrap();
        assert_eq!(
            narrow.classify(GraphqlResponseInput {
                media_type: Some("application/json"),
                body: body.as_bytes(),
                complete: true,
                truncated: false,
                operation: operations.control(),
            }),
            GraphqlResponseClassification::Incomplete
        );
    }

    #[test]
    fn depth_node_member_array_string_and_error_limits_are_enforced() {
        let operations = operations();
        let base = GraphqlResponseLimits {
            depth: 2,
            nodes: 4,
            object_members: 2,
            array_length: 1,
            string_bytes: 8,
            errors: 1,
            ..GraphqlResponseLimits::default()
        };
        let classifier = GraphqlResponseClassifier::new(base).unwrap();
        for body in [
            br#"{"a":{"b":{"c":null}}}"#.as_slice(),
            br#"{"a":1,"b":2,"c":3}"#.as_slice(),
            br#"[1,2]"#.as_slice(),
            br#"{"long-key-name":1}"#.as_slice(),
        ] {
            assert_eq!(
                classifier.classify(GraphqlResponseInput {
                    media_type: Some("application/json"),
                    body,
                    complete: true,
                    truncated: false,
                    operation: operations.control(),
                }),
                GraphqlResponseClassification::Incomplete
            );
        }
        let errors = br#"{"errors":[{"message":"one"},{"message":"two"}]}"#;
        let error_classifier = GraphqlResponseClassifier::new(GraphqlResponseLimits {
            errors: 1,
            ..GraphqlResponseLimits::default()
        })
        .unwrap();
        assert_eq!(
            error_classifier.classify(GraphqlResponseInput {
                media_type: Some("application/json"),
                body: errors,
                complete: true,
                truncated: false,
                operation: operations.candidate(),
            }),
            GraphqlResponseClassification::Incomplete
        );
    }

    #[test]
    fn arbitrary_bounded_json_classification_is_deterministic_and_never_panics() {
        let operations = operations();
        for length in 0..=128 {
            let mut input = Vec::with_capacity(length);
            for index in 0..length {
                input
                    .push([b'{', b'}', b'[', b']', b'"', b':', b',', b'a', b'0', 0xff][index % 10]);
            }
            let first = classify(operations.control(), Some("application/json"), &input);
            let second = classify(operations.control(), Some("application/json"), &input);
            assert_eq!(first, second);
        }
    }

    #[test]
    fn outcome_requires_exact_distinct_replay_semantics() {
        let operations = operations();
        let candidate_body = introspection_body(CANDIDATE_ALIAS, "null", "null");
        let replay_body = introspection_body(REPLAY_ALIAS, "null", "null");
        let exact_candidate = classify(
            operations.candidate(),
            Some("application/json"),
            &candidate_body,
        );
        let exact_replay = classify(operations.replay(), Some("application/json"), &replay_body);
        assert_eq!(
            classify_graphql_review_outcome(
                GraphqlResponseClassification::ExactControlEnvelope,
                exact_candidate,
                exact_replay
            ),
            GraphqlReviewOutcome::IntrospectionAvailable
        );
        assert_eq!(
            classify_graphql_review_outcome(
                GraphqlResponseClassification::ExactControlEnvelope,
                exact_candidate,
                GraphqlResponseClassification::GenericJson
            ),
            GraphqlReviewOutcome::ReplayMismatch
        );
        assert_eq!(
            classify_graphql_review_outcome(
                GraphqlResponseClassification::ExactControlEnvelope,
                GraphqlResponseClassification::Truncated,
                exact_replay
            ),
            GraphqlReviewOutcome::Incomplete
        );

        let different_root_body =
            String::from_utf8(introspection_body(REPLAY_ALIAS, "null", "null"))
                .unwrap()
                .replace(
                    r#""queryType":{"name":"Query"}"#,
                    r#""queryType":{"name":"DifferentQueryRoot"}"#,
                )
                .replace(
                    r#""venomReplayV1":"Query""#,
                    r#""venomReplayV1":"DifferentQueryRoot""#,
                )
                .into_bytes();
        let different_replay = classify(
            operations.replay(),
            Some("application/json"),
            &different_root_body,
        );
        let (
            GraphqlResponseClassification::ExactIntrospectionEnvelope(candidate_shape),
            GraphqlResponseClassification::ExactIntrospectionEnvelope(different_shape),
        ) = (exact_candidate, different_replay)
        else {
            panic!("expected exact introspection shapes");
        };
        assert!(!candidate_shape.semantically_matches(&different_shape));
        assert_eq!(
            classify_graphql_review_outcome(
                GraphqlResponseClassification::ExactControlEnvelope,
                exact_candidate,
                different_replay
            ),
            GraphqlReviewOutcome::ReplayMismatch
        );
    }

    #[test]
    fn persisted_outcome_uses_only_the_transient_replay_match_boolean() {
        assert_eq!(
            classify_graphql_transport_outcome(
                GraphqlResponseKind::ExactControlEnvelope,
                GraphqlResponseKind::ExactIntrospectionEnvelope,
                GraphqlResponseKind::ExactIntrospectionEnvelope,
                Some(true),
            ),
            GraphqlReviewOutcome::IntrospectionAvailable
        );
        for replay_matches in [Some(false), None] {
            assert_eq!(
                classify_graphql_transport_outcome(
                    GraphqlResponseKind::ExactControlEnvelope,
                    GraphqlResponseKind::ExactIntrospectionEnvelope,
                    GraphqlResponseKind::ExactIntrospectionEnvelope,
                    replay_matches,
                ),
                GraphqlReviewOutcome::ReplayMismatch
            );
        }
    }

    #[test]
    fn restricted_introspection_retains_only_endpoint_observation() {
        let restricted = GraphqlResponseClassification::StructuredGraphqlErrors(
            GraphqlErrorCategory::IntrospectionRestricted,
        );
        assert_eq!(
            classify_graphql_review_outcome(
                GraphqlResponseClassification::ExactControlEnvelope,
                restricted,
                restricted
            ),
            GraphqlReviewOutcome::IntrospectionRestricted
        );
    }

    #[test]
    fn every_graphql_item_is_informational_and_knowledge_only() {
        for kind in [
            GraphqlAssessmentKind::SurfaceObserved,
            GraphqlAssessmentKind::AnonymousRootIntrospectionAvailable,
        ] {
            assert_eq!(
                kind.maximum_disposition(),
                GraphqlMaximumDisposition::Informational
            );
            assert_eq!(
                kind.maximum_authority(),
                GraphqlMaximumAuthority::KnowledgeOnly
            );
        }
    }

    #[test]
    fn debug_contracts_never_reveal_urls_tokens_bodies_errors_or_sentinel() {
        let secret_url = Url::parse(&format!("https://example.test/{SENTINEL}/graphql")).unwrap();
        let hint = GraphqlEndpointHint::exact_path(secret_url)
            .unwrap()
            .unwrap();
        let selected =
            select_graphql_endpoint(&origin(), [hint], GraphqlFallbackPolicy::GraphqlOnly)
                .unwrap()
                .unwrap();
        let operations = GraphqlOperationSet::v1(&selected).unwrap();
        let rendered = format!(
            "{:?}{:?}{:?}{:?}",
            selected,
            operations,
            GraphqlName::new("ScannerOwnedAlias").unwrap(),
            GraphqlResponseClassification::StructuredGraphqlErrors(
                GraphqlErrorCategory::UnknownGraphqlError
            )
        );
        assert!(!rendered.contains(SENTINEL));
        assert!(!rendered.contains("example.test"));
        assert!(!rendered.contains("__schema"));
        assert!(!rendered.contains("opaque failure"));
    }

    #[test]
    fn compiled_limits_and_protocol_costs_are_exact() {
        assert!(GraphqlResponseLimits::default().checked().is_ok());
        assert!(GraphqlResponseLimits {
            body_bytes: MAX_GRAPHQL_RESPONSE_BYTES + 1,
            ..GraphqlResponseLimits::default()
        }
        .checked()
        .is_err());
        assert_eq!(MAX_GRAPHQL_CHILD_REQUESTS, 3);
        assert_eq!(MAX_GRAPHQL_ACTIVE_VERIFICATIONS, 1);
        assert_eq!(MAX_GRAPHQL_SELECTED_ENDPOINTS, 1);
        assert_eq!(
            GRAPHQL_REVIEW_ALGORITHM_VERSION,
            "graphql.surface-review/v1"
        );
        assert_eq!(
            GRAPHQL_REVIEW_STRATEGY_ID,
            "web.review.graphql.introspection-pair@1"
        );
    }
}
