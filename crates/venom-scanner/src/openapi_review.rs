//! Transport-neutral, bounded OpenAPI document classification and cataloging.
//!
//! This module deliberately owns no transport, authority, request planner, or
//! executor. It reduces a bounded JSON document to deterministic protocol
//! metadata. Prose, examples, defaults, raw security-scheme names, and server
//! values are never retained.

use std::{collections::BTreeSet, fmt};

use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const MAX_OPENAPI_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_OPENAPI_JSON_DEPTH: usize = 64;
pub const MAX_OPENAPI_JSON_NODES: usize = 100_000;
pub const MAX_OPENAPI_OBJECT_MEMBERS: usize = 50_000;
pub const MAX_OPENAPI_ARRAY_LENGTH: usize = 4_096;
pub const MAX_OPENAPI_STRING_BYTES: usize = 256 * 1024;
pub const MAX_OPENAPI_PATHS: usize = 4_096;
pub const MAX_OPENAPI_OPERATIONS: usize = 4_096;
pub const MAX_OPENAPI_PARAMETERS_PER_OPERATION: usize = 64;
pub const MAX_OPENAPI_MEDIA_TYPES_PER_OPERATION: usize = 32;
pub const MAX_MEDIA_ENTRIES_PER_OPERATION: usize = 64;
pub const MAX_OPENAPI_RESPONSES_PER_OPERATION: usize = 64;
pub const MAX_OPENAPI_SECURITY_REQUIREMENTS: usize = 64;
pub const MAX_OPENAPI_SERVERS: usize = 16;
pub const MAX_OPENAPI_PATH_BYTES: usize = 2_048;
pub const MAX_OPENAPI_PATH_SEGMENTS: usize = 256;
pub const MAX_OPENAPI_TOKEN_BYTES: usize = 256;
pub const OPENAPI_CATALOG_ALGORITHM: &str = "security.openapi-catalog/v1";

/// Checked parser ceilings. Callers may narrow, but cannot widen, hard limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenApiDocumentLimits {
    pub document_bytes: usize,
    pub depth: usize,
    pub nodes: usize,
    pub object_members: usize,
    pub array_length: usize,
    pub string_bytes: usize,
    pub paths: usize,
    pub operations: usize,
}

impl OpenApiDocumentLimits {
    pub fn checked(self) -> Result<Self, OpenApiReviewError> {
        if self.document_bytes == 0
            || self.document_bytes > MAX_OPENAPI_DOCUMENT_BYTES
            || self.depth == 0
            || self.depth > MAX_OPENAPI_JSON_DEPTH
            || self.nodes == 0
            || self.nodes > MAX_OPENAPI_JSON_NODES
            || self.object_members == 0
            || self.object_members > MAX_OPENAPI_OBJECT_MEMBERS
            || self.array_length == 0
            || self.array_length > MAX_OPENAPI_ARRAY_LENGTH
            || self.string_bytes == 0
            || self.string_bytes > MAX_OPENAPI_STRING_BYTES
            || self.paths == 0
            || self.paths > MAX_OPENAPI_PATHS
            || self.operations == 0
            || self.operations > MAX_OPENAPI_OPERATIONS
        {
            return Err(OpenApiReviewError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for OpenApiDocumentLimits {
    fn default() -> Self {
        Self {
            document_bytes: MAX_OPENAPI_DOCUMENT_BYTES,
            depth: MAX_OPENAPI_JSON_DEPTH,
            nodes: MAX_OPENAPI_JSON_NODES,
            object_members: MAX_OPENAPI_OBJECT_MEMBERS,
            array_length: MAX_OPENAPI_ARRAY_LENGTH,
            string_bytes: MAX_OPENAPI_STRING_BYTES,
            paths: MAX_OPENAPI_PATHS,
            operations: MAX_OPENAPI_OPERATIONS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiDocumentKind {
    OpenApi30,
    OpenApi31,
    Swagger20MetadataOnly,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiVersion {
    OpenApi30,
    OpenApi31,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenApiParseOutcome {
    Complete(OpenApiDocument),
    Swagger20MetadataOnly,
    UnsupportedVersion,
    Malformed,
    LimitExceeded,
    TooLarge,
}

/// Classifies and reduces one repository- or host-retained document.
///
/// `document_origin` is used only to classify server metadata conservatively.
/// It never grants authority, resolves references, performs I/O, or selects a
/// request target. A runtime must authorize every selected URL independently.
pub fn parse_openapi_document(body: &[u8], document_origin: &Url) -> OpenApiParseOutcome {
    match parse_json_at_origin(body, OpenApiDocumentLimits::default(), document_origin) {
        Ok(document) if document.kind == OpenApiDocumentKind::Swagger20MetadataOnly => {
            OpenApiParseOutcome::Swagger20MetadataOnly
        },
        Ok(document) => OpenApiParseOutcome::Complete(document),
        Err(OpenApiReviewError::DocumentSize) => OpenApiParseOutcome::TooLarge,
        Err(OpenApiReviewError::MalformedJson | OpenApiReviewError::UnsupportedDocument) => {
            OpenApiParseOutcome::Malformed
        },
        Err(OpenApiReviewError::UnsupportedVersion) => OpenApiParseOutcome::UnsupportedVersion,
        Err(
            OpenApiReviewError::InvalidLimits
            | OpenApiReviewError::JsonLimit
            | OpenApiReviewError::ExternalReference
            | OpenApiReviewError::InvalidPaths
            | OpenApiReviewError::InvalidOperation
            | OpenApiReviewError::CatalogLimit,
        ) => OpenApiParseOutcome::LimitExceeded,
    }
}

fn parse_json_at_origin(
    body: &[u8],
    limits: OpenApiDocumentLimits,
    origin: &Url,
) -> Result<OpenApiDocument, OpenApiReviewError> {
    let limits = limits.checked()?;
    if body.is_empty() {
        return Err(OpenApiReviewError::MalformedJson);
    }
    if body.len() > limits.document_bytes {
        return Err(OpenApiReviewError::DocumentSize);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let root = UniqueValue::deserialize(&mut deserializer)
        .map_err(|_| OpenApiReviewError::MalformedJson)?
        .0;
    deserializer
        .end()
        .map_err(|_| OpenApiReviewError::MalformedJson)?;
    validate_json_limits(&root, limits)?;
    validate_references(&root)?;
    parse_document(root, limits, origin)
}

impl OpenApiDocumentKind {
    const fn token(self) -> &'static str {
        match self {
            Self::OpenApi30 => "openapi-3.0",
            Self::OpenApi31 => "openapi-3.1",
            Self::Swagger20MetadataOnly => "swagger-2.0-metadata-only",
        }
    }

    pub const fn executable_catalog(self) -> bool {
        !matches!(self, Self::Swagger20MetadataOnly)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiHttpMethod {
    Get,
    Put,
    Post,
    Delete,
    Options,
    Head,
    Patch,
    Trace,
}

impl OpenApiHttpMethod {
    const ALL: [Self; 8] = [
        Self::Get,
        Self::Put,
        Self::Post,
        Self::Delete,
        Self::Options,
        Self::Head,
        Self::Patch,
        Self::Trace,
    ];

    const fn token(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Put => "put",
            Self::Post => "post",
            Self::Delete => "delete",
            Self::Options => "options",
            Self::Head => "head",
            Self::Patch => "patch",
            Self::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiParameterLocation {
    Query,
    Header,
    Path,
    Cookie,
}

impl OpenApiParameterLocation {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "query" => Some(Self::Query),
            "header" => Some(Self::Header),
            "path" => Some(Self::Path),
            "cookie" => Some(Self::Cookie),
            _ => None,
        }
    }

    const fn token(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Header => "header",
            Self::Path => "path",
            Self::Cookie => "cookie",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiSecuritySchemeKind {
    ApiKeyQuery,
    ApiKeyHeader,
    ApiKeyCookie,
    HttpBasic,
    HttpBearer,
    HttpOther,
    MutualTls,
    OAuth2,
    OpenIdConnect,
    Unknown,
}

impl OpenApiSecuritySchemeKind {
    const fn token(self) -> &'static str {
        match self {
            Self::ApiKeyQuery => "api-key-query",
            Self::ApiKeyHeader => "api-key-header",
            Self::ApiKeyCookie => "api-key-cookie",
            Self::HttpBasic => "http-basic",
            Self::HttpBearer => "http-bearer",
            Self::HttpOther => "http-other",
            Self::MutualTls => "mutual-tls",
            Self::OAuth2 => "oauth2",
            Self::OpenIdConnect => "openid-connect",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiServerKind {
    ExactOrigin,
    Relative,
    CrossOrigin,
    Templated,
    Unsupported,
}

impl OpenApiServerKind {
    const fn token(self) -> &'static str {
        match self {
            Self::ExactOrigin => "exact-origin",
            Self::Relative => "relative-path",
            Self::CrossOrigin => "cross-origin",
            Self::Templated => "templated",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiCandidateTag {
    ReadOnly,
    BodyBearing,
    Parameterized,
    DeclaresSecurity,
    DeclaresAnonymousAccess,
    JsonRequest,
    JsonResponse,
    Deprecated,
    AuthorizationReviewCandidate,
    SqlInputCandidate,
    SsrfUrlCandidate,
    UploadCandidate,
    OAuthCandidate,
    BinaryResponse,
}

impl OpenApiCandidateTag {
    const fn token(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::BodyBearing => "body-bearing",
            Self::Parameterized => "parameterized",
            Self::DeclaresSecurity => "declares-security",
            Self::DeclaresAnonymousAccess => "declares-anonymous-access",
            Self::JsonRequest => "json-request",
            Self::JsonResponse => "json-response",
            Self::Deprecated => "deprecated",
            Self::AuthorizationReviewCandidate => "authorization-review-candidate",
            Self::SqlInputCandidate => "sql-input-candidate",
            Self::SsrfUrlCandidate => "ssrf-url-candidate",
            Self::UploadCandidate => "upload-candidate",
            Self::OAuthCandidate => "oauth-candidate",
            Self::BinaryResponse => "binary-response",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiSchemaPrimitiveKind {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiFormatClass {
    Uri,
    Url,
    Hostname,
    Uuid,
    Email,
    Password,
    Binary,
    Byte,
    DateTime,
    Date,
    Other,
    None,
}

impl OpenApiFormatClass {
    const fn token(self) -> &'static str {
        match self {
            Self::Uri => "uri",
            Self::Url => "url",
            Self::Hostname => "hostname",
            Self::Uuid => "uuid",
            Self::Email => "email",
            Self::Password => "password",
            Self::Binary => "binary",
            Self::Byte => "byte",
            Self::DateTime => "date-time",
            Self::Date => "date",
            Self::Other => "other",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiMediaFamily {
    Json,
    JsonSuffix,
    FormUrlEncoded,
    Multipart,
    Xml,
    Text,
    Binary,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiResponseStatus {
    Exact(u16),
    Default,
    Range(u8),
}
impl OpenApiResponseStatus {
    const fn token(self) -> &'static str {
        match self {
            Self::Exact(_) => "exact",
            Self::Default => "default",
            Self::Range(_) => "range",
        }
    }
    const fn class(self) -> Option<u8> {
        match self {
            Self::Exact(value) => Some((value / 100) as u8),
            Self::Range(class) => Some(class),
            Self::Default => None,
        }
    }
}

impl OpenApiSchemaPrimitiveKind {
    const fn token(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct OpenApiOperationId(String);

impl OpenApiOperationId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpenApiOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenApiOperationId(")?;
        formatter.write_str(&self.0)?;
        formatter.write_str(")")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OpenApiParameterMetadata {
    location: OpenApiParameterLocation,
    required: bool,
    name_digest: [u8; 32],
    schema_kind: OpenApiSchemaPrimitiveKind,
    format_class: OpenApiFormatClass,
}

impl OpenApiParameterMetadata {
    pub const fn location(&self) -> OpenApiParameterLocation {
        self.location
    }

    pub const fn required(&self) -> bool {
        self.required
    }

    pub const fn schema_kind(&self) -> OpenApiSchemaPrimitiveKind {
        self.schema_kind
    }
    pub const fn format_class(&self) -> OpenApiFormatClass {
        self.format_class
    }

    /// Stable raw-value-free fingerprint of the declared parameter name.
    pub const fn name_fingerprint(&self) -> &[u8; 32] {
        &self.name_digest
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OpenApiResponseMetadata {
    status: OpenApiResponseStatus,
    media_types: Vec<String>,
    media_families: Vec<OpenApiMediaFamily>,
}

impl OpenApiResponseMetadata {
    pub const fn status(&self) -> OpenApiResponseStatus {
        self.status
    }
    pub fn media_families(&self) -> &[OpenApiMediaFamily] {
        &self.media_families
    }

    pub fn media_types(&self) -> &[String] {
        &self.media_types
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OpenApiResponseSummary {
    success: bool,
    authentication: bool,
    client_error: bool,
    server_error: bool,
    media_families: Vec<OpenApiMediaFamily>,
}
impl OpenApiResponseSummary {
    pub const fn success(&self) -> bool {
        self.success
    }
    pub const fn authentication(&self) -> bool {
        self.authentication
    }
    pub const fn client_error(&self) -> bool {
        self.client_error
    }
    pub const fn server_error(&self) -> bool {
        self.server_error
    }
    pub fn media_families(&self) -> &[OpenApiMediaFamily] {
        &self.media_families
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OpenApiSecurityMetadata {
    alternatives: usize,
    permits_anonymous: bool,
    declares_auth: bool,
    scheme_kinds: Vec<OpenApiSecuritySchemeKind>,
    scope_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenApiSecuritySource {
    Inherited,
    OperationOverride,
    OperationAnonymousOverride,
}
impl OpenApiSecuritySource {
    const fn token(self) -> &'static str {
        match self {
            Self::Inherited => "inherited",
            Self::OperationOverride => "operation-override",
            Self::OperationAnonymousOverride => "operation-anonymous-override",
        }
    }
}

impl OpenApiSecurityMetadata {
    pub const fn alternatives(&self) -> usize {
        self.alternatives
    }

    pub const fn permits_anonymous(&self) -> bool {
        self.permits_anonymous
    }
    pub const fn declares_auth(&self) -> bool {
        self.declares_auth
    }

    pub fn scheme_kinds(&self) -> &[OpenApiSecuritySchemeKind] {
        &self.scheme_kinds
    }
    pub const fn scope_count(&self) -> usize {
        self.scope_count
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OpenApiServerMetadata {
    kind: OpenApiServerKind,
    variable_count: usize,
    canonical_identity: [u8; 32],
}

impl OpenApiServerMetadata {
    pub const fn kind(&self) -> OpenApiServerKind {
        self.kind
    }

    pub const fn variable_count(&self) -> usize {
        self.variable_count
    }
}

/// Reduced operation metadata. Debug deliberately omits the raw path.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenApiOperation {
    id: OpenApiOperationId,
    path: String,
    method: OpenApiHttpMethod,
    parameters: Vec<OpenApiParameterMetadata>,
    request_media_types: Vec<String>,
    request_media_families: Vec<OpenApiMediaFamily>,
    responses: Vec<OpenApiResponseMetadata>,
    response_summary: OpenApiResponseSummary,
    security: OpenApiSecurityMetadata,
    security_source: OpenApiSecuritySource,
    servers: Vec<OpenApiServerMetadata>,
    candidate_tags: Vec<OpenApiCandidateTag>,
    declared_operation_id: Option<[u8; 32]>,
    deprecated: bool,
    source_document_identity: String,
}

impl OpenApiOperation {
    pub fn id(&self) -> &OpenApiOperationId {
        &self.id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn method(&self) -> OpenApiHttpMethod {
        self.method
    }

    pub fn parameters(&self) -> &[OpenApiParameterMetadata] {
        &self.parameters
    }

    pub fn request_media_types(&self) -> &[String] {
        &self.request_media_types
    }
    pub fn request_media_families(&self) -> &[OpenApiMediaFamily] {
        &self.request_media_families
    }

    pub fn responses(&self) -> &[OpenApiResponseMetadata] {
        &self.responses
    }
    pub const fn response_summary(&self) -> &OpenApiResponseSummary {
        &self.response_summary
    }

    pub const fn security(&self) -> &OpenApiSecurityMetadata {
        &self.security
    }

    pub const fn security_source(&self) -> OpenApiSecuritySource {
        self.security_source
    }

    pub fn servers(&self) -> &[OpenApiServerMetadata] {
        &self.servers
    }

    pub fn candidate_tags(&self) -> &[OpenApiCandidateTag] {
        &self.candidate_tags
    }
    pub const fn has_declared_operation_id(&self) -> bool {
        self.declared_operation_id.is_some()
    }
    /// Stable raw-value-free fingerprint of the declared `operationId`.
    pub const fn declared_operation_id_fingerprint(&self) -> Option<&[u8; 32]> {
        self.declared_operation_id.as_ref()
    }
    pub const fn deprecated(&self) -> bool {
        self.deprecated
    }
    pub fn source_document_identity(&self) -> &str {
        &self.source_document_identity
    }
}

impl fmt::Debug for OpenApiOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenApiOperation")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("parameter_count", &self.parameters.len())
            .field("request_media_types", &self.request_media_types)
            .field("responses", &self.responses)
            .field("security", &self.security)
            .field("servers", &self.servers)
            .field("candidate_tags", &self.candidate_tags)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiCatalog {
    operations: Vec<OpenApiOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiCatalogSummary {
    pub path_parameter_count: u64,
    pub query_parameter_count: u64,
    pub url_like_parameter_count: u64,
    pub multipart_operation_count: u64,
    pub anonymous_operation_count: u64,
    pub explicit_auth_operation_count: u64,
    pub json_compatible_operation_count: u64,
    pub method_counts: Vec<(OpenApiHttpMethod, u64)>,
    pub media_family_counts: Vec<(OpenApiMediaFamily, u64)>,
    pub security_kind_counts: Vec<(OpenApiSecuritySchemeKind, u64)>,
}

impl OpenApiCatalog {
    pub fn operations(&self) -> &[OpenApiOperation] {
        &self.operations
    }

    pub fn operation(&self, id: &OpenApiOperationId) -> Option<&OpenApiOperation> {
        self.operations.iter().find(|operation| operation.id == *id)
    }

    pub fn by_method(&self, method: OpenApiHttpMethod) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| operation.method == method)
            .collect()
    }

    pub fn with_candidate_tag(&self, tag: OpenApiCandidateTag) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| operation.candidate_tags.binary_search(&tag).is_ok())
            .collect()
    }

    pub fn with_any_parameter(&self) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| !operation.parameters.is_empty())
            .collect()
    }

    pub fn with_parameter_location(
        &self,
        location: OpenApiParameterLocation,
    ) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| {
                operation
                    .parameters
                    .iter()
                    .any(|parameter| parameter.location == location)
            })
            .collect()
    }

    pub fn with_path_parameter(&self) -> Vec<&OpenApiOperation> {
        self.with_parameter_location(OpenApiParameterLocation::Path)
    }
    pub fn with_query_parameter(&self) -> Vec<&OpenApiOperation> {
        self.with_parameter_location(OpenApiParameterLocation::Query)
    }
    pub fn with_header_parameter(&self) -> Vec<&OpenApiOperation> {
        self.with_parameter_location(OpenApiParameterLocation::Header)
    }
    pub fn with_cookie_parameter(&self) -> Vec<&OpenApiOperation> {
        self.with_parameter_location(OpenApiParameterLocation::Cookie)
    }
    pub fn with_url_like_input(&self) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| {
                operation.parameters.iter().any(|parameter| {
                    matches!(
                        parameter.format_class,
                        OpenApiFormatClass::Uri
                            | OpenApiFormatClass::Url
                            | OpenApiFormatClass::Hostname
                    )
                })
            })
            .collect()
    }
    pub fn with_multipart_request(&self) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| {
                operation
                    .request_media_families
                    .contains(&OpenApiMediaFamily::Multipart)
            })
            .collect()
    }
    pub fn declaring_anonymous_access(&self) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| operation.security.permits_anonymous)
            .collect()
    }
    pub fn declaring_explicit_auth(&self) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| operation.security.declares_auth)
            .collect()
    }
    pub fn with_json_compatible_response(&self) -> Vec<&OpenApiOperation> {
        self.operations
            .iter()
            .filter(|operation| {
                operation
                    .response_summary
                    .media_families
                    .iter()
                    .any(|family| {
                        matches!(
                            family,
                            OpenApiMediaFamily::Json | OpenApiMediaFamily::JsonSuffix
                        )
                    })
            })
            .collect()
    }

    pub fn summary(&self) -> OpenApiCatalogSummary {
        let mut path = 0u64;
        let mut query = 0u64;
        let mut url_like = 0u64;
        let mut multipart = 0u64;
        let mut anonymous = 0u64;
        let mut auth = 0u64;
        let mut json = 0u64;
        let mut methods = std::collections::BTreeMap::new();
        let mut media = std::collections::BTreeMap::new();
        let mut security = std::collections::BTreeMap::new();
        for operation in &self.operations {
            *methods.entry(operation.method).or_insert(0u64) += 1;
            for parameter in &operation.parameters {
                match parameter.location {
                    OpenApiParameterLocation::Path => path += 1,
                    OpenApiParameterLocation::Query => query += 1,
                    _ => {},
                }
                if matches!(
                    parameter.format_class,
                    OpenApiFormatClass::Uri
                        | OpenApiFormatClass::Url
                        | OpenApiFormatClass::Hostname
                ) {
                    url_like += 1;
                }
            }
            let families = operation
                .request_media_families
                .iter()
                .chain(operation.response_summary.media_families.iter())
                .copied()
                .collect::<BTreeSet<_>>();
            for family in families {
                *media.entry(family).or_insert(0u64) += 1;
            }
            if operation
                .request_media_families
                .contains(&OpenApiMediaFamily::Multipart)
            {
                multipart += 1;
            }
            anonymous += u64::from(operation.security.permits_anonymous);
            auth += u64::from(operation.security.declares_auth);
            if operation
                .response_summary
                .media_families
                .iter()
                .any(|family| {
                    matches!(
                        family,
                        OpenApiMediaFamily::Json | OpenApiMediaFamily::JsonSuffix
                    )
                })
            {
                json += 1;
            }
            for kind in &operation.security.scheme_kinds {
                *security.entry(*kind).or_insert(0u64) += 1;
            }
        }
        OpenApiCatalogSummary {
            path_parameter_count: path,
            query_parameter_count: query,
            url_like_parameter_count: url_like,
            multipart_operation_count: multipart,
            anonymous_operation_count: anonymous,
            explicit_auth_operation_count: auth,
            json_compatible_operation_count: json,
            method_counts: methods.into_iter().collect(),
            media_family_counts: media.into_iter().collect(),
            security_kind_counts: security.into_iter().collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiDocument {
    kind: OpenApiDocumentKind,
    path_count: usize,
    digest: String,
    servers: Vec<OpenApiServerMetadata>,
    security_schemes: Vec<OpenApiSecuritySchemeKind>,
    catalog: OpenApiCatalog,
    title_present: bool,
    root_security: OpenApiSecurityMetadata,
    root_security_declared: bool,
}

impl OpenApiDocument {
    pub fn parse_json(body: &[u8]) -> Result<Self, OpenApiReviewError> {
        Self::parse_json_with_limits(body, OpenApiDocumentLimits::default())
    }

    pub fn parse_json_with_limits(
        body: &[u8],
        limits: OpenApiDocumentLimits,
    ) -> Result<Self, OpenApiReviewError> {
        let origin = Url::parse("https://example.invalid/").expect("compiled URL is valid");
        parse_json_at_origin(body, limits, &origin)
    }

    pub const fn kind(&self) -> OpenApiDocumentKind {
        self.kind
    }

    pub const fn version(&self) -> Option<OpenApiVersion> {
        match self.kind {
            OpenApiDocumentKind::OpenApi30 => Some(OpenApiVersion::OpenApi30),
            OpenApiDocumentKind::OpenApi31 => Some(OpenApiVersion::OpenApi31),
            OpenApiDocumentKind::Swagger20MetadataOnly => None,
        }
    }

    pub const fn path_count(&self) -> usize {
        self.path_count
    }

    pub fn operation_count(&self) -> usize {
        self.catalog.operations.len()
    }

    pub fn semantic_digest(&self) -> &str {
        &self.digest
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn servers(&self) -> &[OpenApiServerMetadata] {
        &self.servers
    }

    pub fn security_schemes(&self) -> &[OpenApiSecuritySchemeKind] {
        &self.security_schemes
    }

    pub const fn catalog(&self) -> &OpenApiCatalog {
        &self.catalog
    }
    pub const fn title_present(&self) -> bool {
        self.title_present
    }
    pub const fn root_security(&self) -> &OpenApiSecurityMetadata {
        &self.root_security
    }
    pub const fn root_security_declared(&self) -> bool {
        self.root_security_declared
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OpenApiReviewError {
    #[error("the OpenAPI parser limits are invalid")]
    InvalidLimits,
    #[error("the OpenAPI document size is outside the allowed range")]
    DocumentSize,
    #[error("the OpenAPI document is malformed JSON")]
    MalformedJson,
    #[error("the OpenAPI document JSON exceeds a structural limit")]
    JsonLimit,
    #[error("the document is not a supported OpenAPI JSON shape")]
    UnsupportedDocument,
    #[error("the OpenAPI version is unsupported")]
    UnsupportedVersion,
    #[error("an external reference is unsupported")]
    ExternalReference,
    #[error("the OpenAPI paths catalog is invalid")]
    InvalidPaths,
    #[error("the OpenAPI operation metadata is invalid")]
    InvalidOperation,
    #[error("the OpenAPI catalog exceeds a compiled limit")]
    CatalogLimit,
}

fn parse_document(
    root: Value,
    limits: OpenApiDocumentLimits,
    origin: &Url,
) -> Result<OpenApiDocument, OpenApiReviewError> {
    let object = root
        .as_object()
        .ok_or(OpenApiReviewError::UnsupportedDocument)?;
    let kind = classify_document(object)?;
    if !kind.executable_catalog() {
        let catalog = OpenApiCatalog {
            operations: Vec::new(),
        };
        let servers = Vec::new();
        let security_schemes = Vec::new();
        let root_security = OpenApiSecurityMetadata {
            alternatives: 0,
            permits_anonymous: true,
            declares_auth: false,
            scheme_kinds: Vec::new(),
            scope_count: 0,
        };
        let digest = document_digest(
            kind,
            false,
            0,
            &root_security,
            &servers,
            &security_schemes,
            &catalog,
        );
        return Ok(OpenApiDocument {
            kind,
            path_count: 0,
            digest,
            servers,
            security_schemes,
            catalog,
            title_present: false,
            root_security,
            root_security_declared: false,
        });
    }

    let servers = parse_servers(object.get("servers"), origin)?;
    let security_scheme_map = parse_security_schemes(object)?;
    let mut security_schemes = security_scheme_map
        .iter()
        .map(|(_, kind)| *kind)
        .collect::<Vec<_>>();
    security_schemes.sort_unstable();
    security_schemes.dedup();
    let inherited_security = parse_security(object.get("security"), &security_scheme_map)?;
    let root_security_declared = object.contains_key("security");
    let title_present = object
        .get("info")
        .and_then(Value::as_object)
        .and_then(|info| info.get("title"))
        .and_then(Value::as_str)
        .is_some_and(|title| !title.is_empty());
    let paths = object
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(OpenApiReviewError::InvalidPaths)?;
    let path_count = paths.keys().filter(|path| !path.starts_with("x-")).count();
    if path_count > limits.paths {
        return Err(OpenApiReviewError::CatalogLimit);
    }
    let mut operations = Vec::new();
    for (path, path_item) in paths {
        if path.starts_with("x-") {
            continue;
        }
        validate_path(path)?;
        let path_item = path_item
            .as_object()
            .ok_or(OpenApiReviewError::InvalidPaths)?;
        let inherited_parameters = parse_parameters(path_item.get("parameters"), &root)?;
        let path_servers_declared = path_item.contains_key("servers");
        let path_servers = parse_servers(path_item.get("servers"), origin)?;
        for method in OpenApiHttpMethod::ALL {
            let Some(operation) = path_item.get(method.token()) else {
                continue;
            };
            let operation = operation
                .as_object()
                .ok_or(OpenApiReviewError::InvalidOperation)?;
            let operation_parameters = parse_parameters(operation.get("parameters"), &root)?;
            let mut parameters = inherited_parameters.clone();
            for replacement in operation_parameters {
                parameters.retain(|existing| {
                    existing.location != replacement.location
                        || existing.name_digest != replacement.name_digest
                });
                parameters.push(replacement);
            }
            parameters.sort_unstable();
            parameters.dedup();
            if parameters.len() > MAX_OPENAPI_PARAMETERS_PER_OPERATION {
                return Err(OpenApiReviewError::CatalogLimit);
            }
            let placeholders = path_placeholder_digests(path)?;
            let declared_path_parameters = parameters
                .iter()
                .filter(|parameter| parameter.location == OpenApiParameterLocation::Path)
                .map(|parameter| parameter.name_digest)
                .collect::<BTreeSet<_>>();
            if placeholders != declared_path_parameters {
                return Err(OpenApiReviewError::InvalidOperation);
            }
            let request_media_types = parse_request_media(operation.get("requestBody"))?;
            let request_media_families = media_families(&request_media_types);
            let responses = parse_responses(operation.get("responses"))?;
            let media_entry_count = responses
                .iter()
                .try_fold(request_media_types.len(), |count, response| {
                    count.checked_add(response.media_types.len())
                })
                .ok_or(OpenApiReviewError::CatalogLimit)?;
            if media_entry_count > MAX_MEDIA_ENTRIES_PER_OPERATION {
                return Err(OpenApiReviewError::CatalogLimit);
            }
            let response_summary = summarize_responses(&responses);
            let (security, security_source) = if operation.contains_key("security") {
                let security = parse_security(operation.get("security"), &security_scheme_map)?;
                let source = if security.permits_anonymous && security.alternatives == 0 {
                    OpenApiSecuritySource::OperationAnonymousOverride
                } else {
                    OpenApiSecuritySource::OperationOverride
                };
                (security, source)
            } else {
                (inherited_security.clone(), OpenApiSecuritySource::Inherited)
            };
            let servers = if operation.contains_key("servers") {
                parse_servers(operation.get("servers"), origin)?
            } else if path_servers_declared {
                path_servers.clone()
            } else {
                servers.clone()
            };
            let deprecated = operation
                .get("deprecated")
                .map(|value| value.as_bool().ok_or(OpenApiReviewError::InvalidOperation))
                .transpose()?
                .unwrap_or(false);
            let declared_operation_id = operation
                .get("operationId")
                .map(|value| bounded_token(Some(value)))
                .transpose()?
                .map(|value| digest_bytes(b"openapi-declared-operation-id/v1", value.as_bytes()));
            let candidate_tags = candidate_tags(
                method,
                &parameters,
                &request_media_types,
                &responses,
                &security,
                deprecated,
            );
            let id = operation_id(OperationIdentityInput {
                path,
                method,
                parameters: &parameters,
                request_media: &request_media_types,
                responses: &responses,
                security: &security,
                security_source,
                servers: &servers,
                tags: &candidate_tags,
                declared_operation_id: declared_operation_id.as_ref(),
                deprecated,
            });
            operations.push(OpenApiOperation {
                id,
                path: path.clone(),
                method,
                parameters,
                request_media_types,
                request_media_families,
                responses,
                response_summary,
                security,
                security_source,
                servers,
                candidate_tags,
                declared_operation_id,
                deprecated,
                source_document_identity: String::new(),
            });
            if operations.len() > limits.operations {
                return Err(OpenApiReviewError::CatalogLimit);
            }
        }
    }
    operations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.method.cmp(&right.method))
    });
    let mut catalog = OpenApiCatalog { operations };
    let digest = document_digest(
        kind,
        root_security_declared,
        path_count,
        &inherited_security,
        &servers,
        &security_schemes,
        &catalog,
    );
    for operation in &mut catalog.operations {
        operation.source_document_identity = digest.clone();
        operation.id = scoped_operation_id(&digest, &operation.id);
    }
    Ok(OpenApiDocument {
        kind,
        path_count,
        digest,
        servers,
        security_schemes,
        catalog,
        title_present,
        root_security: inherited_security,
        root_security_declared,
    })
}

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.to_owned())))
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                Deserialize::deserialize(deserializer)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate object key"));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn classify_document(
    object: &Map<String, Value>,
) -> Result<OpenApiDocumentKind, OpenApiReviewError> {
    if object.contains_key("openapi") && object.contains_key("swagger") {
        return Err(OpenApiReviewError::UnsupportedDocument);
    }
    if let Some(version) = object.get("openapi").and_then(Value::as_str) {
        let valid_patch = |prefix: &str| {
            version.strip_prefix(prefix).is_some_and(|patch| {
                !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit())
            })
        };
        return if valid_patch("3.0.") {
            Ok(OpenApiDocumentKind::OpenApi30)
        } else if valid_patch("3.1.") {
            Ok(OpenApiDocumentKind::OpenApi31)
        } else {
            Err(OpenApiReviewError::UnsupportedVersion)
        };
    }
    if object.get("swagger").and_then(Value::as_str) == Some("2.0") {
        return Ok(OpenApiDocumentKind::Swagger20MetadataOnly);
    }
    Err(OpenApiReviewError::UnsupportedDocument)
}

#[derive(Default)]
struct JsonCount {
    nodes: usize,
    members: usize,
}

fn validate_json_limits(
    value: &Value,
    limits: OpenApiDocumentLimits,
) -> Result<(), OpenApiReviewError> {
    let mut count = JsonCount::default();
    validate_json_value(value, 1, limits, &mut count)
}

fn validate_json_value(
    value: &Value,
    depth: usize,
    limits: OpenApiDocumentLimits,
    count: &mut JsonCount,
) -> Result<(), OpenApiReviewError> {
    count.nodes = count
        .nodes
        .checked_add(1)
        .ok_or(OpenApiReviewError::JsonLimit)?;
    if depth > limits.depth || count.nodes > limits.nodes {
        return Err(OpenApiReviewError::JsonLimit);
    }
    match value {
        Value::String(value) if value.len() > limits.string_bytes => {
            Err(OpenApiReviewError::JsonLimit)
        },
        Value::Array(values) => {
            if values.len() > limits.array_length {
                return Err(OpenApiReviewError::JsonLimit);
            }
            for value in values {
                validate_json_value(value, depth + 1, limits, count)?;
            }
            Ok(())
        },
        Value::Object(values) => {
            count.members = count
                .members
                .checked_add(values.len())
                .ok_or(OpenApiReviewError::JsonLimit)?;
            if values.len() > limits.object_members || count.members > limits.object_members {
                return Err(OpenApiReviewError::JsonLimit);
            }
            for (key, value) in values {
                if key.len() > limits.string_bytes {
                    return Err(OpenApiReviewError::JsonLimit);
                }
                validate_json_value(value, depth + 1, limits, count)?;
            }
            Ok(())
        },
        _ => Ok(()),
    }
}

fn validate_references(value: &Value) -> Result<(), OpenApiReviewError> {
    match value {
        Value::Array(values) => values.iter().try_for_each(validate_references),
        Value::Object(values) => {
            if values.get("$ref").is_some_and(|value| !value.is_string()) {
                return Err(OpenApiReviewError::ExternalReference);
            }
            if let Some(reference) = values.get("$ref").and_then(Value::as_str) {
                if !reference.starts_with("#/") {
                    return Err(OpenApiReviewError::ExternalReference);
                }
            }
            values.values().try_for_each(validate_references)
        },
        _ => Ok(()),
    }
}

fn validate_path(path: &str) -> Result<(), OpenApiReviewError> {
    if path.is_empty()
        || path.len() > MAX_OPENAPI_PATH_BYTES
        || !path.starts_with('/')
        || path.contains(['?', '#', '\r', '\n', '\0'])
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        || path.to_ascii_lowercase().contains("%2f")
        || path.to_ascii_lowercase().contains("%5c")
        || path.to_ascii_lowercase().contains("%2e")
        || path.contains('\\')
        || path.contains("//")
        || path.split('/').count().saturating_sub(1) > MAX_OPENAPI_PATH_SEGMENTS
    {
        return Err(OpenApiReviewError::InvalidPaths);
    }
    let mut placeholders = BTreeSet::new();
    for name in braced_tokens(path).map_err(|()| OpenApiReviewError::InvalidPaths)? {
        if name.is_empty()
            || name.len() > MAX_OPENAPI_TOKEN_BYTES
            || !name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[0] != b'_'
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !placeholders.insert(name)
        {
            return Err(OpenApiReviewError::InvalidPaths);
        }
    }
    Ok(())
}

fn path_placeholder_digests(path: &str) -> Result<BTreeSet<[u8; 32]>, OpenApiReviewError> {
    let mut placeholders = BTreeSet::new();
    for name in braced_tokens(path).map_err(|()| OpenApiReviewError::InvalidPaths)? {
        placeholders.insert(digest_bytes(b"openapi-parameter-name/v1", name.as_bytes()));
    }
    Ok(placeholders)
}

fn parse_parameters(
    value: Option<&Value>,
    document: &Value,
) -> Result<Vec<OpenApiParameterMetadata>, OpenApiReviewError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    if values.len() > MAX_OPENAPI_PARAMETERS_PER_OPERATION {
        return Err(OpenApiReviewError::CatalogLimit);
    }
    let mut parameters = Vec::with_capacity(values.len());
    let mut identities = BTreeSet::new();
    for value in values {
        let mut object = value
            .as_object()
            .ok_or(OpenApiReviewError::InvalidOperation)?;
        if let Some(reference) = object.get("$ref") {
            let reference = reference
                .as_str()
                .ok_or(OpenApiReviewError::InvalidOperation)?;
            if !reference.starts_with("#/components/parameters/") {
                return Err(OpenApiReviewError::InvalidOperation);
            }
            object = document
                .pointer(&reference[1..])
                .and_then(Value::as_object)
                .ok_or(OpenApiReviewError::InvalidOperation)?;
            if object.contains_key("$ref") {
                return Err(OpenApiReviewError::InvalidOperation);
            }
        }
        let name = bounded_token(object.get("name"))?;
        let location = object
            .get("in")
            .and_then(Value::as_str)
            .and_then(OpenApiParameterLocation::parse)
            .ok_or(OpenApiReviewError::InvalidOperation)?;
        let required = object
            .get("required")
            .map(|value| value.as_bool().ok_or(OpenApiReviewError::InvalidOperation))
            .transpose()?
            .unwrap_or(false);
        if location == OpenApiParameterLocation::Path && !required {
            return Err(OpenApiReviewError::InvalidOperation);
        }
        let schema = object
            .get("schema")
            .map(|value| {
                value
                    .as_object()
                    .ok_or(OpenApiReviewError::InvalidOperation)
            })
            .transpose()?;
        if schema
            .and_then(|value| value.get("type"))
            .is_some_and(|value| !value.is_string())
            || schema
                .and_then(|value| value.get("format"))
                .is_some_and(|value| !value.is_string())
        {
            return Err(OpenApiReviewError::InvalidOperation);
        }
        let schema_kind = match schema
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
        {
            Some("string") => OpenApiSchemaPrimitiveKind::String,
            Some("integer") => OpenApiSchemaPrimitiveKind::Integer,
            Some("number") => OpenApiSchemaPrimitiveKind::Number,
            Some("boolean") => OpenApiSchemaPrimitiveKind::Boolean,
            Some("array") => OpenApiSchemaPrimitiveKind::Array,
            Some("object") => OpenApiSchemaPrimitiveKind::Object,
            _ => OpenApiSchemaPrimitiveKind::Unknown,
        };
        let format_class = match schema
            .and_then(|value| value.get("format"))
            .and_then(Value::as_str)
        {
            Some("uri") => OpenApiFormatClass::Uri,
            Some("url") => OpenApiFormatClass::Url,
            Some("hostname") => OpenApiFormatClass::Hostname,
            Some("uuid") => OpenApiFormatClass::Uuid,
            Some("email") => OpenApiFormatClass::Email,
            Some("password") => OpenApiFormatClass::Password,
            Some("binary") => OpenApiFormatClass::Binary,
            Some("byte") => OpenApiFormatClass::Byte,
            Some("date-time") => OpenApiFormatClass::DateTime,
            Some("date") => OpenApiFormatClass::Date,
            Some(_) => OpenApiFormatClass::Other,
            None => OpenApiFormatClass::None,
        };
        let metadata = OpenApiParameterMetadata {
            location,
            required,
            name_digest: digest_bytes(b"openapi-parameter-name/v1", name.as_bytes()),
            schema_kind,
            format_class,
        };
        if !identities.insert((metadata.location, metadata.name_digest)) {
            return Err(OpenApiReviewError::InvalidOperation);
        }
        parameters.push(metadata);
    }
    Ok(parameters)
}

fn parse_request_media(value: Option<&Value>) -> Result<Vec<String>, OpenApiReviewError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    parse_media_map(object.get("content"))
}

fn parse_media_map(value: Option<&Value>) -> Result<Vec<String>, OpenApiReviewError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    if object.len() > MAX_OPENAPI_MEDIA_TYPES_PER_OPERATION {
        return Err(OpenApiReviewError::CatalogLimit);
    }
    if object.values().any(|value| !value.is_object()) {
        return Err(OpenApiReviewError::InvalidOperation);
    }
    let mut media = object
        .keys()
        .map(|value| normalize_media_type(value))
        .collect::<Result<Vec<_>, _>>()?;
    media.sort();
    media.dedup();
    Ok(media)
}

fn normalize_media_type(value: &str) -> Result<String, OpenApiReviewError> {
    if value.is_empty() || value.len() > MAX_OPENAPI_TOKEN_BYTES || !value.is_ascii() {
        return Err(OpenApiReviewError::InvalidOperation);
    }
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if essence.matches('/').count() != 1 {
        return Err(OpenApiReviewError::InvalidOperation);
    }
    let Some((kind, subtype)) = essence.split_once('/') else {
        return Err(OpenApiReviewError::InvalidOperation);
    };
    if kind.is_empty()
        || subtype.is_empty()
        || !essence.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'*' | b'/'
                )
        })
    {
        return Err(OpenApiReviewError::InvalidOperation);
    }
    Ok(essence)
}

fn media_family(essence: &str) -> OpenApiMediaFamily {
    if essence == "application/json" {
        OpenApiMediaFamily::Json
    } else if essence.ends_with("+json") {
        OpenApiMediaFamily::JsonSuffix
    } else if essence == "application/x-www-form-urlencoded" {
        OpenApiMediaFamily::FormUrlEncoded
    } else if essence.starts_with("multipart/") {
        OpenApiMediaFamily::Multipart
    } else if essence == "application/xml" || essence == "text/xml" || essence.ends_with("+xml") {
        OpenApiMediaFamily::Xml
    } else if essence.starts_with("text/") {
        OpenApiMediaFamily::Text
    } else if essence == "application/octet-stream"
        || essence.starts_with("image/")
        || essence.starts_with("audio/")
        || essence.starts_with("video/")
        || essence == "application/pdf"
    {
        OpenApiMediaFamily::Binary
    } else {
        OpenApiMediaFamily::Unknown
    }
}

fn media_families(media: &[String]) -> Vec<OpenApiMediaFamily> {
    media
        .iter()
        .map(|value| media_family(value))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn parse_responses(
    value: Option<&Value>,
) -> Result<Vec<OpenApiResponseMetadata>, OpenApiReviewError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    if object.len() > MAX_OPENAPI_RESPONSES_PER_OPERATION {
        return Err(OpenApiReviewError::CatalogLimit);
    }
    let mut responses = Vec::with_capacity(object.len());
    for (status, response) in object {
        let status = if status == "default" {
            OpenApiResponseStatus::Default
        } else if status.len() == 3
            && status.as_bytes()[1..] == *b"XX"
            && matches!(status.as_bytes()[0], b'1'..=b'5')
        {
            OpenApiResponseStatus::Range(status.as_bytes()[0] - b'0')
        } else if status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()) {
            let code = status
                .parse::<u16>()
                .map_err(|_| OpenApiReviewError::InvalidOperation)?;
            if !(100..=599).contains(&code) {
                return Err(OpenApiReviewError::InvalidOperation);
            }
            OpenApiResponseStatus::Exact(code)
        } else {
            return Err(OpenApiReviewError::InvalidOperation);
        };
        let response_object = response
            .as_object()
            .ok_or(OpenApiReviewError::InvalidOperation)?;
        let media_types = parse_media_map(response_object.get("content"))?;
        responses.push(OpenApiResponseMetadata {
            status,
            media_families: media_families(&media_types),
            media_types,
        });
    }
    responses.sort_unstable();
    Ok(responses)
}

fn summarize_responses(responses: &[OpenApiResponseMetadata]) -> OpenApiResponseSummary {
    let mut families = BTreeSet::new();
    let mut success = false;
    let mut authentication = false;
    let mut client_error = false;
    let mut server_error = false;
    for response in responses {
        families.extend(response.media_families.iter().copied());
        match response.status {
            OpenApiResponseStatus::Exact(401 | 403) => {
                authentication = true;
                client_error = true;
            },
            status => match status.class() {
                Some(2) => success = true,
                Some(4) => client_error = true,
                Some(5) => server_error = true,
                _ => {},
            },
        }
    }
    OpenApiResponseSummary {
        success,
        authentication,
        client_error,
        server_error,
        media_families: families.into_iter().collect(),
    }
}

fn parse_security_schemes(
    object: &Map<String, Value>,
) -> Result<Vec<(String, OpenApiSecuritySchemeKind)>, OpenApiReviewError> {
    let Some(components) = object.get("components") else {
        return Ok(Vec::new());
    };
    let components = components
        .as_object()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    let Some(schemes_value) = components.get("securitySchemes") else {
        return Ok(Vec::new());
    };
    let schemes = schemes_value
        .as_object()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    if schemes.len() > MAX_OPENAPI_SECURITY_REQUIREMENTS {
        return Err(OpenApiReviewError::CatalogLimit);
    }
    let mut result = Vec::with_capacity(schemes.len());
    for (name, value) in schemes {
        if name.is_empty() || name.len() > MAX_OPENAPI_TOKEN_BYTES {
            return Err(OpenApiReviewError::InvalidOperation);
        }
        let object = value
            .as_object()
            .ok_or(OpenApiReviewError::InvalidOperation)?;
        if object.get("type").is_some_and(|value| !value.is_string())
            || object.get("in").is_some_and(|value| !value.is_string())
            || object.get("scheme").is_some_and(|value| !value.is_string())
        {
            return Err(OpenApiReviewError::InvalidOperation);
        }
        let kind = match object.get("type").and_then(Value::as_str) {
            Some("apiKey") => match object.get("in").and_then(Value::as_str) {
                Some("query") => OpenApiSecuritySchemeKind::ApiKeyQuery,
                Some("header") => OpenApiSecuritySchemeKind::ApiKeyHeader,
                Some("cookie") => OpenApiSecuritySchemeKind::ApiKeyCookie,
                _ => OpenApiSecuritySchemeKind::Unknown,
            },
            Some("http") => match object
                .get("scheme")
                .and_then(Value::as_str)
                .map(|value| value.to_ascii_lowercase())
                .as_deref()
            {
                Some("basic") => OpenApiSecuritySchemeKind::HttpBasic,
                Some("bearer") => OpenApiSecuritySchemeKind::HttpBearer,
                _ => OpenApiSecuritySchemeKind::HttpOther,
            },
            Some("mutualTLS") => OpenApiSecuritySchemeKind::MutualTls,
            Some("oauth2") => OpenApiSecuritySchemeKind::OAuth2,
            Some("openIdConnect") => OpenApiSecuritySchemeKind::OpenIdConnect,
            _ => OpenApiSecuritySchemeKind::Unknown,
        };
        result.push((name.clone(), kind));
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(result)
}

fn parse_security(
    value: Option<&Value>,
    schemes: &[(String, OpenApiSecuritySchemeKind)],
) -> Result<OpenApiSecurityMetadata, OpenApiReviewError> {
    let Some(value) = value else {
        return Ok(OpenApiSecurityMetadata {
            alternatives: 0,
            permits_anonymous: true,
            declares_auth: false,
            scheme_kinds: Vec::new(),
            scope_count: 0,
        });
    };
    let requirements = value
        .as_array()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    if requirements.len() > MAX_OPENAPI_SECURITY_REQUIREMENTS {
        return Err(OpenApiReviewError::CatalogLimit);
    }
    let mut kinds = BTreeSet::new();
    let mut permits_anonymous = requirements.is_empty();
    let mut declares_auth = false;
    let mut scheme_count = 0usize;
    let mut scope_count = 0usize;
    for requirement in requirements {
        let requirement = requirement
            .as_object()
            .ok_or(OpenApiReviewError::InvalidOperation)?;
        permits_anonymous |= requirement.is_empty();
        declares_auth |= !requirement.is_empty();
        for (name, scopes) in requirement {
            scheme_count = scheme_count
                .checked_add(1)
                .ok_or(OpenApiReviewError::CatalogLimit)?;
            if scheme_count > MAX_OPENAPI_SECURITY_REQUIREMENTS {
                return Err(OpenApiReviewError::CatalogLimit);
            }
            kinds.insert(
                schemes
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .map_or(OpenApiSecuritySchemeKind::Unknown, |(_, kind)| *kind),
            );
            let scopes = scopes
                .as_array()
                .ok_or(OpenApiReviewError::InvalidOperation)?;
            if scopes.iter().any(|scope| !scope.is_string()) {
                return Err(OpenApiReviewError::InvalidOperation);
            }
            scope_count = scope_count
                .checked_add(scopes.len())
                .ok_or(OpenApiReviewError::CatalogLimit)?;
            if scope_count > MAX_OPENAPI_SECURITY_REQUIREMENTS {
                return Err(OpenApiReviewError::CatalogLimit);
            }
        }
    }
    Ok(OpenApiSecurityMetadata {
        alternatives: requirements.len(),
        permits_anonymous,
        declares_auth,
        scheme_kinds: kinds.into_iter().collect(),
        scope_count,
    })
}

fn parse_servers(
    value: Option<&Value>,
    origin: &Url,
) -> Result<Vec<OpenApiServerMetadata>, OpenApiReviewError> {
    let Some(values) = value else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    if values.len() > MAX_OPENAPI_SERVERS {
        return Err(OpenApiReviewError::CatalogLimit);
    }
    let mut servers = Vec::with_capacity(values.len());
    for value in values {
        let object = value
            .as_object()
            .ok_or(OpenApiReviewError::InvalidOperation)?;
        let url = bounded_token(object.get("url"))?;
        let variables = object
            .get("variables")
            .map(|value| {
                value
                    .as_object()
                    .ok_or(OpenApiReviewError::InvalidOperation)
            })
            .transpose()?;
        if variables.is_some_and(|values| values.values().any(|value| !value.is_object())) {
            return Err(OpenApiReviewError::InvalidOperation);
        }
        let variable_count = variables.map_or(0, Map::len);
        if variable_count > MAX_OPENAPI_SECURITY_REQUIREMENTS {
            return Err(OpenApiReviewError::CatalogLimit);
        }
        let normalized_input = url.trim().replace('\\', "/");
        let (kind, canonical_value) =
            if normalized_input.contains('{') || normalized_input.contains('}') {
                let names = server_template_names(&normalized_input)?;
                let declared = variables
                    .map(|values| values.keys().map(String::as_str).collect::<BTreeSet<_>>())
                    .unwrap_or_default();
                if names != declared {
                    return Err(OpenApiReviewError::InvalidOperation);
                }
                (OpenApiServerKind::Templated, normalized_input)
            } else {
                let absolute = Url::parse(&normalized_input).ok();
                let network_path = normalized_input.starts_with("//");
                let resolved = absolute
                    .clone()
                    .map(Ok)
                    .unwrap_or_else(|| origin.join(&normalized_input));
                match resolved {
                    Ok(server) if !matches!(server.scheme(), "http" | "https") => {
                        (OpenApiServerKind::Unsupported, server.to_string())
                    },
                    Ok(server) if !same_origin(&server, origin) => {
                        (OpenApiServerKind::CrossOrigin, server.to_string())
                    },
                    Ok(server) if absolute.is_some() || network_path => {
                        (OpenApiServerKind::ExactOrigin, server.to_string())
                    },
                    Ok(server) => (OpenApiServerKind::Relative, server.to_string()),
                    Err(_) => (OpenApiServerKind::Unsupported, normalized_input),
                }
            };
        servers.push(OpenApiServerMetadata {
            kind,
            variable_count,
            canonical_identity: digest_bytes(
                b"openapi-canonical-server/v1",
                canonical_value.as_bytes(),
            ),
        });
    }
    servers.sort_unstable();
    servers.dedup();
    Ok(servers)
}

fn server_template_names(value: &str) -> Result<BTreeSet<&str>, OpenApiReviewError> {
    let mut names = BTreeSet::new();
    for name in braced_tokens(value).map_err(|()| OpenApiReviewError::InvalidOperation)? {
        if name.is_empty()
            || (!name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[0] != b'_')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || !names.insert(name)
        {
            return Err(OpenApiReviewError::InvalidOperation);
        }
    }
    Ok(names)
}

fn braced_tokens(value: &str) -> Result<Vec<&str>, ()> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (index, byte) in value.bytes().enumerate() {
        match (byte, start) {
            (b'{', None) => start = Some(index + 1),
            (b'{', Some(_)) | (b'}', None) => return Err(()),
            (b'}', Some(token_start)) => {
                tokens.push(&value[token_start..index]);
                start = None;
            },
            _ => {},
        }
    }
    if start.is_some() {
        return Err(());
    }
    Ok(tokens)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn bounded_token(value: Option<&Value>) -> Result<&str, OpenApiReviewError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(OpenApiReviewError::InvalidOperation)?;
    if value.is_empty()
        || value.len() > MAX_OPENAPI_TOKEN_BYTES
        || value.contains(['\r', '\n', '\0'])
    {
        return Err(OpenApiReviewError::InvalidOperation);
    }
    Ok(value)
}

fn candidate_tags(
    method: OpenApiHttpMethod,
    parameters: &[OpenApiParameterMetadata],
    request_media: &[String],
    responses: &[OpenApiResponseMetadata],
    security: &OpenApiSecurityMetadata,
    deprecated: bool,
) -> Vec<OpenApiCandidateTag> {
    let mut tags = BTreeSet::new();
    if matches!(
        method,
        OpenApiHttpMethod::Get | OpenApiHttpMethod::Head | OpenApiHttpMethod::Options
    ) {
        tags.insert(OpenApiCandidateTag::ReadOnly);
    }
    if !request_media.is_empty() {
        tags.insert(OpenApiCandidateTag::BodyBearing);
    }
    if !parameters.is_empty() {
        tags.insert(OpenApiCandidateTag::Parameterized);
    }
    if security.permits_anonymous {
        tags.insert(OpenApiCandidateTag::DeclaresAnonymousAccess);
    }
    if security.declares_auth {
        tags.insert(OpenApiCandidateTag::DeclaresSecurity);
    }
    if request_media.iter().any(|value| {
        matches!(
            media_family(value),
            OpenApiMediaFamily::Json | OpenApiMediaFamily::JsonSuffix
        )
    }) {
        tags.insert(OpenApiCandidateTag::JsonRequest);
    }
    if responses
        .iter()
        .flat_map(|response| response.media_types.iter())
        .any(|value| {
            matches!(
                media_family(value),
                OpenApiMediaFamily::Json | OpenApiMediaFamily::JsonSuffix
            )
        })
    {
        tags.insert(OpenApiCandidateTag::JsonResponse);
    }
    if deprecated {
        tags.insert(OpenApiCandidateTag::Deprecated);
    }
    if method == OpenApiHttpMethod::Get && security.declares_auth {
        tags.insert(OpenApiCandidateTag::AuthorizationReviewCandidate);
    }
    if parameters.iter().any(|parameter| {
        matches!(
            parameter.location,
            OpenApiParameterLocation::Query | OpenApiParameterLocation::Path
        ) && matches!(
            parameter.schema_kind,
            OpenApiSchemaPrimitiveKind::String
                | OpenApiSchemaPrimitiveKind::Integer
                | OpenApiSchemaPrimitiveKind::Number
                | OpenApiSchemaPrimitiveKind::Unknown
        )
    }) {
        tags.insert(OpenApiCandidateTag::SqlInputCandidate);
    }
    if parameters.iter().any(|parameter| {
        matches!(
            parameter.format_class,
            OpenApiFormatClass::Uri | OpenApiFormatClass::Url | OpenApiFormatClass::Hostname
        )
    }) {
        tags.insert(OpenApiCandidateTag::SsrfUrlCandidate);
    }
    if request_media.iter().any(|media| {
        matches!(
            media_family(media),
            OpenApiMediaFamily::Multipart | OpenApiMediaFamily::Binary
        )
    }) || parameters
        .iter()
        .any(|parameter| parameter.format_class == OpenApiFormatClass::Binary)
    {
        tags.insert(OpenApiCandidateTag::UploadCandidate);
    }
    if security.scheme_kinds.iter().any(|kind| {
        matches!(
            kind,
            OpenApiSecuritySchemeKind::OAuth2 | OpenApiSecuritySchemeKind::OpenIdConnect
        )
    }) {
        tags.insert(OpenApiCandidateTag::OAuthCandidate);
    }
    if responses
        .iter()
        .flat_map(|response| &response.media_types)
        .any(|media| media_family(media) == OpenApiMediaFamily::Binary)
    {
        tags.insert(OpenApiCandidateTag::BinaryResponse);
    }
    tags.into_iter().collect()
}

struct OperationIdentityInput<'a> {
    path: &'a str,
    method: OpenApiHttpMethod,
    parameters: &'a [OpenApiParameterMetadata],
    request_media: &'a [String],
    responses: &'a [OpenApiResponseMetadata],
    security: &'a OpenApiSecurityMetadata,
    security_source: OpenApiSecuritySource,
    servers: &'a [OpenApiServerMetadata],
    tags: &'a [OpenApiCandidateTag],
    declared_operation_id: Option<&'a [u8; 32]>,
    deprecated: bool,
}

fn operation_id(input: OperationIdentityInput<'_>) -> OpenApiOperationId {
    let mut digest = Sha256::new();
    update_framed(&mut digest, b"security.openapi-operation/v1");
    update_framed(&mut digest, input.path.as_bytes());
    update_framed(&mut digest, input.method.token().as_bytes());
    frame_operation_metadata(
        &mut digest,
        input.parameters,
        input.request_media,
        input.responses,
        input.security,
        input.servers,
        input.tags,
    );
    update_framed(&mut digest, input.security_source.token().as_bytes());
    update_framed(
        &mut digest,
        input
            .declared_operation_id
            .map_or(&[][..], |value| &value[..]),
    );
    update_framed(&mut digest, &[u8::from(input.deprecated)]);
    OpenApiOperationId(format!(
        "openapi-operation-sha256:{}",
        hex(&digest.finalize())
    ))
}

fn scoped_operation_id(document_identity: &str, local: &OpenApiOperationId) -> OpenApiOperationId {
    let mut digest = Sha256::new();
    update_framed(&mut digest, b"security.openapi-document-operation/v1");
    update_framed(&mut digest, document_identity.as_bytes());
    update_framed(&mut digest, local.as_str().as_bytes());
    OpenApiOperationId(format!(
        "openapi-operation-sha256:{}",
        hex(&digest.finalize())
    ))
}

fn document_digest(
    kind: OpenApiDocumentKind,
    root_security_declared: bool,
    path_count: usize,
    root_security: &OpenApiSecurityMetadata,
    servers: &[OpenApiServerMetadata],
    security_schemes: &[OpenApiSecuritySchemeKind],
    catalog: &OpenApiCatalog,
) -> String {
    let mut digest = Sha256::new();
    update_framed(&mut digest, OPENAPI_CATALOG_ALGORITHM.as_bytes());
    update_framed(&mut digest, kind.token().as_bytes());
    update_framed(&mut digest, &[u8::from(root_security_declared)]);
    frame_count(&mut digest, path_count);
    frame_count(&mut digest, root_security.alternatives);
    update_framed(&mut digest, &[u8::from(root_security.permits_anonymous)]);
    update_framed(&mut digest, &[u8::from(root_security.declares_auth)]);
    frame_count(&mut digest, root_security.scope_count);
    for scheme in &root_security.scheme_kinds {
        update_framed(&mut digest, scheme.token().as_bytes());
    }
    for server in servers {
        frame_server(&mut digest, server);
    }
    for scheme in security_schemes {
        update_framed(&mut digest, scheme.token().as_bytes());
    }
    for operation in &catalog.operations {
        update_framed(&mut digest, operation.id.as_str().as_bytes());
    }
    format!("openapi-catalog-sha256:{}", hex(&digest.finalize()))
}

fn frame_operation_metadata(
    digest: &mut Sha256,
    parameters: &[OpenApiParameterMetadata],
    request_media: &[String],
    responses: &[OpenApiResponseMetadata],
    security: &OpenApiSecurityMetadata,
    servers: &[OpenApiServerMetadata],
    tags: &[OpenApiCandidateTag],
) {
    for parameter in parameters {
        update_framed(digest, parameter.location.token().as_bytes());
        update_framed(digest, &[u8::from(parameter.required)]);
        update_framed(digest, &parameter.name_digest);
        update_framed(digest, parameter.schema_kind.token().as_bytes());
        update_framed(digest, parameter.format_class.token().as_bytes());
    }
    for media in request_media {
        update_framed(digest, media.as_bytes());
    }
    for response in responses {
        update_framed(digest, response.status.token().as_bytes());
        match response.status {
            OpenApiResponseStatus::Exact(value) => update_framed(digest, &value.to_be_bytes()),
            OpenApiResponseStatus::Range(value) => update_framed(digest, &[value]),
            OpenApiResponseStatus::Default => update_framed(digest, &[]),
        }
        for media in &response.media_types {
            update_framed(digest, media.as_bytes());
        }
    }
    frame_count(digest, security.alternatives);
    update_framed(digest, &[u8::from(security.permits_anonymous)]);
    update_framed(digest, &[u8::from(security.declares_auth)]);
    frame_count(digest, security.scope_count);
    for kind in &security.scheme_kinds {
        update_framed(digest, kind.token().as_bytes());
    }
    for server in servers {
        frame_server(digest, server);
    }
    for tag in tags {
        update_framed(digest, tag.token().as_bytes());
    }
}

fn frame_server(digest: &mut Sha256, server: &OpenApiServerMetadata) {
    update_framed(digest, server.kind.token().as_bytes());
    frame_count(digest, server.variable_count);
    update_framed(digest, &server.canonical_identity);
}
fn digest_bytes(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_framed(&mut digest, domain);
    update_framed(&mut digest, value);
    digest.finalize().into()
}
fn update_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("bounded field length fits u64")
            .to_be_bytes(),
    );
    digest.update(value);
}
fn frame_count(digest: &mut Sha256, value: usize) {
    update_framed(
        digest,
        &u64::try_from(value)
            .expect("bounded count fits u64")
            .to_be_bytes(),
    );
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0xf) as usize] as char);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {"title":"must not be retained", "version":"1", "description":"SECRET PROSE"},
            "servers": [{"url":"https://api.example.test/{version}","variables":{"version":{"default":"v1"}}}],
            "components": {"securitySchemes": {
                "header-secret": {"type":"apiKey","in":"header","name":"X-Key"},
                "oauth": {"type":"oauth2","flows":{}}
            }},
            "security": [{"header-secret":[]}],
            "paths": {
                "/pets/{petId}": {
                    "parameters": [{"name":"petId","in":"path","required":true,"schema":{"type":"string"}}],
                    "get": {
                        "operationId":"secret-operation-name", "tags":["secret-tag"], "summary":"SECRET PROSE",
                        "parameters":[{"name":"trace","in":"query"}],
                        "responses":{"200":{"description":"ok","content":{"Application/Problem+JSON; charset=utf-8": {"example":{"secret":"value"}}}}}
                    },
                    "post": {
                        "security": [], "deprecated":true,
                        "requestBody":{"content":{"application/json":{"schema":{"type":"object"}}}},
                        "responses":{"201":{"description":"ok","content":{"application/json":{}}}}
                    }
                },
                "/health": {"get":{"responses":{"204":{"description":"ok"}}}}
            }
        })
    }

    fn parse(value: &Value) -> OpenApiDocument {
        OpenApiDocument::parse_json(&serde_json::to_vec(value).unwrap()).unwrap()
    }

    #[test]
    fn parses_reduced_openapi_31_catalog_and_queries() {
        let parsed = parse(&document());
        assert_eq!(parsed.kind(), OpenApiDocumentKind::OpenApi31);
        assert_eq!(parsed.catalog().operations().len(), 3);
        assert_eq!(parsed.catalog().by_method(OpenApiHttpMethod::Get).len(), 2);
        assert_eq!(
            parsed
                .catalog()
                .with_candidate_tag(OpenApiCandidateTag::ReadOnly)
                .len(),
            2
        );
        let post = parsed.catalog().by_method(OpenApiHttpMethod::Post)[0];
        assert!(post
            .candidate_tags()
            .contains(&OpenApiCandidateTag::JsonRequest));
        assert!(post
            .candidate_tags()
            .contains(&OpenApiCandidateTag::Deprecated));
        assert!(post.security().permits_anonymous());
        let get = parsed
            .catalog()
            .operations()
            .iter()
            .find(|operation| {
                operation.path() == "/pets/{petId}" && operation.method() == OpenApiHttpMethod::Get
            })
            .unwrap();
        assert_eq!(get.parameters().len(), 2);
        assert_eq!(
            get.responses()[0].media_types(),
            &["application/problem+json"]
        );
        assert_eq!(parsed.servers()[0].kind(), OpenApiServerKind::Templated);
        assert_eq!(
            parsed.security_schemes(),
            &[
                OpenApiSecuritySchemeKind::ApiKeyHeader,
                OpenApiSecuritySchemeKind::OAuth2
            ]
        );
        assert!(parsed.catalog().operation(get.id()).is_some());
    }

    #[test]
    fn supports_openapi_30_and_classifies_swagger_without_operations() {
        let mut value = document();
        value["openapi"] = json!("3.0.3");
        assert_eq!(parse(&value).kind(), OpenApiDocumentKind::OpenApi30);
        let swagger = parse(&json!({"swagger":"2.0","paths":{"/legacy":{"get":{}}}}));
        assert_eq!(swagger.kind(), OpenApiDocumentKind::Swagger20MetadataOnly);
        assert!(!swagger.kind().executable_catalog());
        assert!(swagger.catalog().operations().is_empty());
    }

    #[test]
    fn source_order_and_unretained_prose_do_not_change_identity() {
        let first = parse(&document());
        let mut changed = document();
        changed["info"]["description"] = json!("different");
        changed["paths"]["/pets/{petId}"]["get"]["summary"] = json!("different");
        let second = parse(&changed);
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.catalog(), second.catalog());
        assert!(!format!("{first:?}").contains("SECRET"));
        assert!(!format!("{first:?}").contains("secret-operation-name"));
        assert!(!format!("{first:?}").contains("api.example.test"));
    }

    #[test]
    fn material_metadata_changes_document_and_operation_identity() {
        let first = parse(&document());
        let mut changed = document();
        changed["paths"]["/pets/{petId}"]["get"]["responses"]["200"]["content"] =
            json!({"text/plain":{}});
        let second = parse(&changed);
        assert_ne!(first.digest(), second.digest());
        assert_ne!(
            first.catalog().by_method(OpenApiHttpMethod::Get)[1].id(),
            second.catalog().by_method(OpenApiHttpMethod::Get)[1].id()
        );
    }

    #[test]
    fn facade_classifies_complete_swagger_version_malformed_limits_and_size() {
        let origin = Url::parse("https://api.example.test/base").unwrap();
        let bytes = serde_json::to_vec(&document()).unwrap();
        let OpenApiParseOutcome::Complete(parsed) = parse_openapi_document(&bytes, &origin) else {
            panic!("OpenAPI 3.1 document should complete");
        };
        assert_eq!(parsed.version(), Some(OpenApiVersion::OpenApi31));
        assert_eq!(parsed.path_count(), 2);
        assert_eq!(parsed.operation_count(), 3);
        assert_eq!(parsed.semantic_digest(), parsed.digest());
        assert_eq!(
            parse_openapi_document(br#"{"swagger":"2.0"}"#, &origin),
            OpenApiParseOutcome::Swagger20MetadataOnly
        );
        assert_eq!(
            parse_openapi_document(br#"{"openapi":"4.0.0","paths":{}}"#, &origin),
            OpenApiParseOutcome::UnsupportedVersion
        );
        assert_eq!(
            parse_openapi_document(b"openapi: 3.1.0", &origin),
            OpenApiParseOutcome::Malformed
        );
        assert_eq!(
            parse_openapi_document(br#"{"openapi":"3.1.0","paths":{"relative":{}}}"#, &origin),
            OpenApiParseOutcome::LimitExceeded
        );
        assert_eq!(
            parse_openapi_document(&vec![b' '; MAX_OPENAPI_DOCUMENT_BYTES + 1], &origin),
            OpenApiParseOutcome::TooLarge
        );
    }

    #[test]
    fn duplicate_json_keys_fail_closed() {
        assert_eq!(
            OpenApiDocument::parse_json(br#"{"openapi":"3.1.0","paths":{},"paths":{}}"#),
            Err(OpenApiReviewError::MalformedJson)
        );
    }

    #[test]
    fn server_classification_uses_document_origin_without_retaining_urls() {
        let origin = Url::parse("https://api.example.test/source").unwrap();
        let body = br#"{"openapi":"3.1.0","servers":[{"url":"https://api.example.test/v1"},{"url":"https://other.test/v1"},{"url":"/v1"},{"url":"https://{tenant}.example.test","variables":{"tenant":{"default":"api"}}},{"url":"ftp://example.test"}],"paths":{}}"#;
        let OpenApiParseOutcome::Complete(parsed) = parse_openapi_document(body, &origin) else {
            panic!("expected complete")
        };
        let kinds = parsed
            .servers()
            .iter()
            .map(OpenApiServerMetadata::kind)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            kinds,
            BTreeSet::from([
                OpenApiServerKind::ExactOrigin,
                OpenApiServerKind::CrossOrigin,
                OpenApiServerKind::Relative,
                OpenApiServerKind::Templated,
                OpenApiServerKind::Unsupported
            ])
        );
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("api.example.test"));
        assert!(!debug.contains("other.test"));
    }

    #[test]
    fn rejects_ambiguous_paths_and_binds_declared_operation_identity() {
        for path in [
            "/a/../b",
            "/a//b",
            "/a%2Fb",
            "/{id}/{id}",
            "/{bad.name}",
            "/{open",
            "/stray}",
            "/{outer{inner}}",
            "/{{id}}",
            "/{id}}",
        ] {
            let value = json!({"openapi":"3.1.0","paths":{path:{"get":{}}}});
            assert_eq!(
                OpenApiDocument::parse_json(&serde_json::to_vec(&value).unwrap()),
                Err(OpenApiReviewError::InvalidPaths)
            );
        }
        let first = parse(&document());
        let mut second_value = document();
        second_value["paths"]["/pets/{petId}"]["get"]["operationId"] = json!("different");
        let second = parse(&second_value);
        let first_get = first
            .catalog()
            .operations()
            .iter()
            .find(|operation| {
                operation.path() == "/pets/{petId}" && operation.method() == OpenApiHttpMethod::Get
            })
            .unwrap();
        let second_get = second
            .catalog()
            .operations()
            .iter()
            .find(|operation| {
                operation.path() == "/pets/{petId}" && operation.method() == OpenApiHttpMethod::Get
            })
            .unwrap();
        assert!(first_get.has_declared_operation_id());
        assert_ne!(first_get.id(), second_get.id());
    }

    #[test]
    fn versions_types_and_parameter_override_fail_closed_or_reduce_exactly() {
        for version in ["3.1.", "3.1.foo", "3.0.1-beta", "3.2.0"] {
            let value = json!({"openapi":version,"paths":{}});
            assert_eq!(
                OpenApiDocument::parse_json(&serde_json::to_vec(&value).unwrap()),
                Err(OpenApiReviewError::UnsupportedVersion)
            );
        }
        for value in [
            json!({"openapi":"3.1.0","components":[],"paths":{}}),
            json!({"openapi":"3.1.0","components":{"securitySchemes":[]},"paths":{}}),
            json!({"openapi":"3.1.0","paths":{"/x":{"get":{"requestBody":[],"responses":{}}}}}),
            json!({"openapi":"3.1.0","paths":{"/x":{"get":{"responses":[]}}}}),
        ] {
            assert_eq!(
                OpenApiDocument::parse_json(&serde_json::to_vec(&value).unwrap()),
                Err(OpenApiReviewError::InvalidOperation)
            );
        }

        let value = json!({"openapi":"3.1.0","paths":{"/x":{
            "parameters":[{"name":"id","in":"query","schema":{"type":"string"}}],
            "get":{"parameters":[{"name":"id","in":"query","schema":{"type":"integer"}}],"responses":{}}
        }}});
        let parsed = parse(&value);
        assert_eq!(parsed.catalog().operations()[0].parameters().len(), 1);
        assert_eq!(
            parsed.catalog().operations()[0].parameters()[0].schema_kind(),
            OpenApiSchemaPrimitiveKind::Integer
        );
    }

    #[test]
    fn explicit_empty_path_servers_override_root_servers() {
        let origin = Url::parse("https://api.example.test/").unwrap();
        let body = br#"{"openapi":"3.1.0","servers":[{"url":"https://api.example.test"}],"paths":{"/x":{"servers":[],"get":{"responses":{}}}}}"#;
        let OpenApiParseOutcome::Complete(parsed) = parse_openapi_document(body, &origin) else {
            panic!("expected complete")
        };
        assert_eq!(parsed.servers().len(), 1);
        assert!(parsed.catalog().operations()[0].servers().is_empty());
    }

    #[test]
    fn duplicate_parameter_identity_is_rejected() {
        let value = json!({"openapi":"3.1.0","paths":{"/x":{"get":{"parameters":[{"name":"id","in":"query"},{"name":"id","in":"query"}],"responses":{}}}}});
        assert_eq!(
            OpenApiDocument::parse_json(&serde_json::to_vec(&value).unwrap()),
            Err(OpenApiReviewError::InvalidOperation)
        );
    }

    #[test]
    fn schema_security_and_future_candidate_metadata_are_bounded() {
        let mut value = document();
        value["paths"]["/pets/{petId}"]["get"]["parameters"][0]["schema"] =
            json!({"type":"string","format":"uri"});
        value["paths"]["/pets/{petId}"]["get"]["responses"]["200"]["content"] =
            json!({"application/octet-stream":{}});
        let parsed = parse(&value);
        let get = parsed
            .catalog()
            .operations()
            .iter()
            .find(|operation| {
                operation.path() == "/pets/{petId}" && operation.method() == OpenApiHttpMethod::Get
            })
            .unwrap();
        let query = get
            .parameters()
            .iter()
            .find(|parameter| parameter.location() == OpenApiParameterLocation::Query)
            .expect("query parameter");
        assert_eq!(query.schema_kind(), OpenApiSchemaPrimitiveKind::String);
        assert_eq!(query.format_class(), OpenApiFormatClass::Uri);
        for tag in [
            OpenApiCandidateTag::AuthorizationReviewCandidate,
            OpenApiCandidateTag::SqlInputCandidate,
            OpenApiCandidateTag::SsrfUrlCandidate,
            OpenApiCandidateTag::BinaryResponse,
        ] {
            assert!(get.candidate_tags().contains(&tag));
        }
        assert!(parsed.title_present());
        assert_eq!(parsed.root_security().alternatives(), 1);
        assert_eq!(parsed.root_security().scope_count(), 0);
        assert!(!get.deprecated());
    }

    #[test]
    fn rejects_size_malformed_versions_external_refs_and_invalid_paths() {
        assert_eq!(
            OpenApiDocument::parse_json(&vec![b' '; MAX_OPENAPI_DOCUMENT_BYTES + 1]).unwrap_err(),
            OpenApiReviewError::DocumentSize
        );
        assert_eq!(
            OpenApiDocument::parse_json(b"{").unwrap_err(),
            OpenApiReviewError::MalformedJson
        );
        assert_eq!(
            OpenApiDocument::parse_json(br#"{"openapi":"2.0","paths":{}}"#).unwrap_err(),
            OpenApiReviewError::UnsupportedVersion
        );
        assert_eq!(OpenApiDocument::parse_json(br#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"x":{"$ref":"https://example.test/x"}}}}"#).unwrap_err(), OpenApiReviewError::ExternalReference);
        assert_eq!(
            OpenApiDocument::parse_json(br#"{"openapi":"3.1.0","paths":{"relative":{"get":{}}}}"#)
                .unwrap_err(),
            OpenApiReviewError::InvalidPaths
        );
    }

    #[test]
    fn enforces_every_json_structure_limit() {
        let base = OpenApiDocumentLimits::default();
        let mut value = document();
        value["paths"]["/pets/{petId}"]["get"]["tags"] = json!(["one", "two"]);
        let body = serde_json::to_vec(&value).unwrap();
        for limits in [
            OpenApiDocumentLimits { depth: 2, ..base },
            OpenApiDocumentLimits { nodes: 2, ..base },
            OpenApiDocumentLimits {
                object_members: 2,
                ..base
            },
            OpenApiDocumentLimits {
                array_length: 1,
                ..base
            },
            OpenApiDocumentLimits {
                string_bytes: 4,
                ..base
            },
        ] {
            assert_eq!(
                OpenApiDocument::parse_json_with_limits(&body, limits,).unwrap_err(),
                OpenApiReviewError::JsonLimit
            );
        }
        assert_eq!(
            OpenApiDocumentLimits {
                document_bytes: 0,
                ..base
            }
            .checked()
            .unwrap_err(),
            OpenApiReviewError::InvalidLimits
        );
    }

    #[test]
    fn rejects_invalid_parameter_media_response_and_catalog_bounds() {
        let mut path_parameter = document();
        path_parameter["paths"]["/pets/{petId}"]["parameters"][0]["required"] = json!(false);
        assert_eq!(
            OpenApiDocument::parse_json(&serde_json::to_vec(&path_parameter).unwrap()).unwrap_err(),
            OpenApiReviewError::InvalidOperation
        );
        let mut media = document();
        media["paths"]["/health"]["get"]["responses"]["204"]["content"] = json!({"invalid":{}});
        assert_eq!(
            OpenApiDocument::parse_json(&serde_json::to_vec(&media).unwrap()).unwrap_err(),
            OpenApiReviewError::InvalidOperation
        );
        let limits = OpenApiDocumentLimits {
            paths: 1,
            ..OpenApiDocumentLimits::default()
        };
        assert_eq!(
            OpenApiDocument::parse_json_with_limits(
                &serde_json::to_vec(&document()).unwrap(),
                limits
            )
            .unwrap_err(),
            OpenApiReviewError::CatalogLimit
        );
    }

    #[test]
    fn local_references_are_metadata_only_and_unknown_extensions_are_ignored() {
        let parsed = parse(
            &json!({"openapi":"3.1.0","x-vendor":{"anything":true},"paths":{"/pets":{"get":{"parameters":[{"$ref":"#/components/parameters/Trace"}],"responses":{"200":{"$ref":"#/components/responses/Pets"}}}}},"components":{"parameters":{"Trace":{"name":"trace","in":"query"}},"responses":{"Pets":{"description":"ok"}}}}),
        );
        assert_eq!(parsed.catalog().operations().len(), 1);
        assert_eq!(parsed.catalog().operations()[0].parameters().len(), 1);
    }

    #[test]
    fn security_declarations_are_metadata_not_authorization_claims() {
        let parsed = parse(&document());
        let secured = parsed
            .catalog()
            .by_method(OpenApiHttpMethod::Get)
            .into_iter()
            .find(|operation| operation.path() == "/pets/{petId}")
            .unwrap();
        assert!(!secured.security().permits_anonymous());
        assert_eq!(secured.security().alternatives(), 1);
        assert_eq!(
            secured.security().scheme_kinds(),
            &[OpenApiSecuritySchemeKind::ApiKeyHeader]
        );

        let requirement = (0..=MAX_OPENAPI_SECURITY_REQUIREMENTS)
            .map(|index| (format!("scheme-{index}"), json!([])))
            .collect::<Map<_, _>>();
        let over_limit = json!({
            "openapi": "3.1.0",
            "security": [Value::Object(requirement)],
            "paths": {},
        });
        assert_eq!(
            OpenApiDocument::parse_json(&serde_json::to_vec(&over_limit).unwrap()).unwrap_err(),
            OpenApiReviewError::CatalogLimit
        );
    }

    #[test]
    fn media_status_response_and_catalog_summaries_are_typed() {
        let value = json!({"openapi":"3.1.0","components":{"securitySchemes":{"basic":{"type":"http","scheme":"basic"}}},"security":[{"basic":[]}],"paths":{"/x/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string","format":"hostname"}},{"name":"q","in":"query","schema":{"type":"string","format":"date"}}],"responses":{"200":{"content":{"application/json":{}}},"401":{"content":{"application/problem+json":{}}},"4XX":{"content":{"text/plain":{}}},"500":{"content":{"application/octet-stream":{}}},"default":{}}}}}});
        let parsed = parse(&value);
        let operation = &parsed.catalog().operations()[0];
        let summary = operation.response_summary();
        assert!(
            summary.success()
                && summary.authentication()
                && summary.client_error()
                && summary.server_error()
        );
        assert_eq!(
            operation.responses()[0].status(),
            OpenApiResponseStatus::Exact(200)
        );
        assert!(summary.media_families().contains(&OpenApiMediaFamily::Json));
        assert!(summary
            .media_families()
            .contains(&OpenApiMediaFamily::JsonSuffix));
        assert!(summary
            .media_families()
            .contains(&OpenApiMediaFamily::Binary));
        let catalog = parsed.catalog().summary();
        assert_eq!(catalog.path_parameter_count, 1);
        assert_eq!(catalog.query_parameter_count, 1);
        assert_eq!(catalog.url_like_parameter_count, 1);
        assert_eq!(catalog.explicit_auth_operation_count, 1);
        assert_eq!(catalog.anonymous_operation_count, 0);
        assert_eq!(catalog.json_compatible_operation_count, 1);
        assert_eq!(
            operation
                .parameters()
                .iter()
                .find(|parameter| parameter.location() == OpenApiParameterLocation::Path)
                .unwrap()
                .format_class(),
            OpenApiFormatClass::Hostname
        );
        assert_eq!(
            operation
                .parameters()
                .iter()
                .find(|parameter| parameter.location() == OpenApiParameterLocation::Query)
                .unwrap()
                .format_class(),
            OpenApiFormatClass::Date
        );
    }

    #[test]
    fn response_status_and_media_grammar_are_strict() {
        for status in ["099", "600", "2xx", "20X", "6XX", "XXX"] {
            let value = json!({"openapi":"3.1.0","paths":{"/x":{"get":{"responses":{status:{}}}}}});
            assert_eq!(
                OpenApiDocument::parse_json(&serde_json::to_vec(&value).unwrap()),
                Err(OpenApiReviewError::InvalidOperation)
            );
        }
        for media in [
            "application//json",
            "/json",
            "application/",
            "application/json/extra",
            "application json",
        ] {
            let value = json!({"openapi":"3.1.0","paths":{"/x":{"get":{"responses":{"200":{"content":{media:{}}}}}}}});
            assert_eq!(
                OpenApiDocument::parse_json(&serde_json::to_vec(&value).unwrap()),
                Err(OpenApiReviewError::InvalidOperation)
            );
        }
    }

    #[test]
    fn operation_ids_are_scoped_to_semantic_document_basis() {
        let first = parse(&document());
        let mut changed = document();
        changed["servers"][0]["url"] = json!("https://other.example.test/{version}");
        let second = parse(&changed);
        assert_ne!(
            first.catalog().operations()[0].id(),
            second.catalog().operations()[0].id()
        );
        changed["servers"][0] = json!({"url":"/v1"});
        let third = parse(&changed);
        assert_ne!(
            first.catalog().operations()[0].id(),
            third.catalog().operations()[0].id()
        );
        assert_eq!(
            first.catalog().operations()[0].source_document_identity(),
            first.semantic_digest()
        );
    }

    #[test]
    fn swagger_version_access_is_panic_free() {
        let swagger = parse(&json!({"swagger":"2.0"}));
        assert_eq!(swagger.version(), None);
    }

    #[test]
    fn source_contract_has_no_transport_or_action_authority() {
        let source = include_str!("openapi_review.rs");
        for forbidden in [
            ["reqwest", "::"].concat(),
            ["HttpRequest", "Broker"].concat(),
            ["SharedWebRuntime", "Authority"].concat(),
            ["Decision", "Executor"].concat(),
            ["Runtime", "Budget"].concat(),
            ["async", " fn"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "forbidden authority marker: {forbidden}"
            );
        }
    }

    #[test]
    fn malformed_server_template_braces_and_unsupported_servers_are_exact() {
        let origin = Url::parse("https://api.example.test/").unwrap();
        for server in [
            "https://{tenant.example.test",
            "https://tenant}.example.test",
            "https://{{tenant}}.example.test",
            "https://{outer{inner}}.example.test",
            "https://{tenant}}.example.test",
        ] {
            let value = json!({"openapi":"3.1.0","servers":[{"url":server,"variables":{"tenant":{},"outer":{},"inner":{}}}],"paths":{}});
            assert_eq!(
                parse_openapi_document(&serde_json::to_vec(&value).unwrap(), &origin),
                OpenApiParseOutcome::LimitExceeded
            );
        }
        let value = json!({"openapi":"3.1.0","servers":[{"url":"mailto:security@example.test"}],"paths":{}});
        let OpenApiParseOutcome::Complete(document) =
            parse_openapi_document(&serde_json::to_vec(&value).unwrap(), &origin)
        else {
            panic!("expected complete document")
        };
        assert_eq!(document.servers()[0].kind(), OpenApiServerKind::Unsupported);
    }

    #[test]
    fn catalog_queries_return_deterministic_operations() {
        let value = json!({"openapi":"3.1.0","components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},"paths":{
            "/upload/{id}":{"post":{"security":[{"bearer":[]}],"parameters":[{"name":"id","in":"path","required":true},{"name":"target","in":"query","schema":{"type":"string","format":"uri"}},{"name":"trace","in":"header"},{"name":"session","in":"cookie"}],"requestBody":{"content":{"multipart/form-data":{}}},"responses":{"200":{"content":{"application/problem+json":{}}}}}},
            "/public":{"get":{"security":[],"responses":{"200":{"content":{"text/plain":{}}}}}}
        }});
        let document = parse(&value);
        let catalog = document.catalog();
        assert_eq!(catalog.with_any_parameter().len(), 1);
        assert_eq!(catalog.with_path_parameter().len(), 1);
        assert_eq!(catalog.with_query_parameter().len(), 1);
        assert_eq!(catalog.with_header_parameter().len(), 1);
        assert_eq!(catalog.with_cookie_parameter().len(), 1);
        assert_eq!(catalog.with_url_like_input().len(), 1);
        assert_eq!(catalog.with_multipart_request().len(), 1);
        assert_eq!(catalog.declaring_explicit_auth().len(), 1);
        assert_eq!(catalog.declaring_anonymous_access().len(), 1);
        assert_eq!(catalog.with_json_compatible_response().len(), 1);
        assert_eq!(
            catalog.with_any_parameter()[0].id(),
            catalog.with_url_like_input()[0].id()
        );
    }

    #[test]
    fn media_parameter_and_security_taxonomies_are_closed_and_typed() {
        for (media, expected) in [
            ("application/json", OpenApiMediaFamily::Json),
            ("application/problem+json", OpenApiMediaFamily::JsonSuffix),
            (
                "application/x-www-form-urlencoded",
                OpenApiMediaFamily::FormUrlEncoded,
            ),
            ("multipart/form-data", OpenApiMediaFamily::Multipart),
            ("application/xml", OpenApiMediaFamily::Xml),
            ("text/plain", OpenApiMediaFamily::Text),
            ("application/octet-stream", OpenApiMediaFamily::Binary),
            ("application/cbor", OpenApiMediaFamily::Unknown),
        ] {
            assert_eq!(media_family(media), expected);
        }

        let formats = [
            (Some("uri"), OpenApiFormatClass::Uri),
            (Some("url"), OpenApiFormatClass::Url),
            (Some("hostname"), OpenApiFormatClass::Hostname),
            (Some("uuid"), OpenApiFormatClass::Uuid),
            (Some("email"), OpenApiFormatClass::Email),
            (Some("password"), OpenApiFormatClass::Password),
            (Some("binary"), OpenApiFormatClass::Binary),
            (Some("byte"), OpenApiFormatClass::Byte),
            (Some("date-time"), OpenApiFormatClass::DateTime),
            (Some("date"), OpenApiFormatClass::Date),
            (Some("future"), OpenApiFormatClass::Other),
            (None, OpenApiFormatClass::None),
        ];
        let parameters = formats
            .iter()
            .enumerate()
            .map(|(index, (format, _))| {
                let mut schema = Map::new();
                schema.insert("type".to_owned(), json!("string"));
                if let Some(format) = format {
                    schema.insert("format".to_owned(), json!(format));
                }
                json!({"name":format!("value-{index}"),"in":"query","schema":schema})
            })
            .collect::<Vec<_>>();
        let value = json!({"openapi":"3.1.0","paths":{"/x":{"get":{"parameters":parameters,"responses":{}}}}});
        let document = parse(&value);
        let observed = document.catalog().operations()[0]
            .parameters()
            .iter()
            .map(OpenApiParameterMetadata::format_class)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed,
            formats
                .iter()
                .map(|(_, expected)| *expected)
                .collect::<BTreeSet<_>>()
        );

        let value = json!({
            "openapi":"3.1.0",
            "components":{"securitySchemes":{
                "api-query":{"type":"apiKey","in":"query"},
                "api-header":{"type":"apiKey","in":"header"},
                "api-cookie":{"type":"apiKey","in":"cookie"},
                "api-unknown":{"type":"apiKey","in":"future"},
                "basic":{"type":"http","scheme":"basic"},
                "bearer":{"type":"http","scheme":"bearer"},
                "http-other":{"type":"http","scheme":"digest"},
                "mtls":{"type":"mutualTLS"},
                "oauth":{"type":"oauth2"},
                "oidc":{"type":"openIdConnect"},
                "future":{"type":"future"}
            }},
            "security":[{
                "api-query":[],"api-header":[],"api-cookie":[],"api-unknown":[],
                "basic":[],"bearer":[],"http-other":[],"mtls":[],"oauth":[],
                "oidc":[],"future":[]
            }],
            "paths":{}
        });
        let document = parse(&value);
        assert_eq!(
            document.security_schemes(),
            &[
                OpenApiSecuritySchemeKind::ApiKeyQuery,
                OpenApiSecuritySchemeKind::ApiKeyHeader,
                OpenApiSecuritySchemeKind::ApiKeyCookie,
                OpenApiSecuritySchemeKind::HttpBasic,
                OpenApiSecuritySchemeKind::HttpBearer,
                OpenApiSecuritySchemeKind::HttpOther,
                OpenApiSecuritySchemeKind::MutualTls,
                OpenApiSecuritySchemeKind::OAuth2,
                OpenApiSecuritySchemeKind::OpenIdConnect,
                OpenApiSecuritySchemeKind::Unknown,
            ]
        );
        assert_eq!(
            document.root_security().scheme_kinds(),
            document.security_schemes()
        );
    }

    #[test]
    fn catalog_component_limits_fail_closed() {
        let parse_error = |value: Value| {
            OpenApiDocument::parse_json(&serde_json::to_vec(&value).unwrap()).unwrap_err()
        };

        let parameters = (0..=MAX_OPENAPI_PARAMETERS_PER_OPERATION)
            .map(|index| json!({"name":format!("p-{index}"),"in":"query"}))
            .collect::<Vec<_>>();
        assert_eq!(
            parse_error(
                json!({"openapi":"3.1.0","paths":{"/x":{"get":{"parameters":parameters}}}})
            ),
            OpenApiReviewError::CatalogLimit
        );

        let media = (0..=MAX_OPENAPI_MEDIA_TYPES_PER_OPERATION)
            .map(|index| (format!("application/x-{index}"), json!({})))
            .collect::<Map<_, _>>();
        assert_eq!(
            parse_error(
                json!({"openapi":"3.1.0","paths":{"/x":{"post":{"requestBody":{"content":media}}}}})
            ),
            OpenApiReviewError::CatalogLimit
        );

        let responses = (100..=100 + MAX_OPENAPI_RESPONSES_PER_OPERATION)
            .map(|status| (status.to_string(), json!({})))
            .collect::<Map<_, _>>();
        assert_eq!(
            parse_error(json!({"openapi":"3.1.0","paths":{"/x":{"get":{"responses":responses}}}})),
            OpenApiReviewError::CatalogLimit
        );

        let schemes = (0..=MAX_OPENAPI_SECURITY_REQUIREMENTS)
            .map(|index| {
                (
                    format!("s-{index}"),
                    json!({"type":"http","scheme":"bearer"}),
                )
            })
            .collect::<Map<_, _>>();
        assert_eq!(
            parse_error(
                json!({"openapi":"3.1.0","components":{"securitySchemes":schemes},"paths":{}})
            ),
            OpenApiReviewError::CatalogLimit
        );

        let servers = (0..=MAX_OPENAPI_SERVERS)
            .map(|index| json!({"url":format!("/server-{index}")}))
            .collect::<Vec<_>>();
        assert_eq!(
            parse_error(json!({"openapi":"3.1.0","servers":servers,"paths":{}})),
            OpenApiReviewError::CatalogLimit
        );

        let limits = OpenApiDocumentLimits {
            operations: 1,
            ..OpenApiDocumentLimits::default()
        };
        assert_eq!(
            OpenApiDocument::parse_json_with_limits(
                br#"{"openapi":"3.1.0","paths":{"/x":{"get":{},"post":{}}}}"#,
                limits,
            )
            .unwrap_err(),
            OpenApiReviewError::CatalogLimit
        );
    }

    #[test]
    fn arbitrary_bounded_bytes_are_deterministic_and_never_panic() {
        let origin = Url::parse("https://example.test/").unwrap();
        let mut state = 0x9e37_79b9_u32;
        for length in (0..=4096).step_by(31) {
            let mut bytes = Vec::with_capacity(length);
            for _ in 0..length {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                bytes.push((state >> 24) as u8);
            }
            let first = std::panic::catch_unwind(|| parse_openapi_document(&bytes, &origin))
                .expect("bounded parser must not panic");
            assert_eq!(first, parse_openapi_document(&bytes, &origin));
        }
    }

    #[test]
    fn server_resolution_is_conservative_and_normalized_identity_is_material() {
        let origin = Url::parse("https://api.example.test/base/document.json").unwrap();
        for raw in [
            "//evil.example/x",
            "  //evil.example/x",
            "\\\\evil.example\\x",
        ] {
            let value = json!({"openapi":"3.1.0","servers":[{"url":raw}],"paths":{}});
            let OpenApiParseOutcome::Complete(document) =
                parse_openapi_document(&serde_json::to_vec(&value).unwrap(), &origin)
            else {
                panic!("expected complete")
            };
            assert_eq!(document.servers()[0].kind(), OpenApiServerKind::CrossOrigin);
        }
        let relative = json!({"openapi":"3.1.0","servers":[{"url":"v1"}],"paths":{}});
        let equivalent = json!({"openapi":"3.1.0","servers":[{"url":"./v1"}],"paths":{}});
        assert_eq!(
            parse(&relative).semantic_digest(),
            parse(&equivalent).semantic_digest()
        );
        let changed = json!({"openapi":"3.1.0","servers":[{"url":"v2"}],"paths":{}});
        assert_ne!(
            parse(&relative).semantic_digest(),
            parse(&changed).semantic_digest()
        );
    }

    #[test]
    fn cumulative_media_limit_ranges_extensions_and_mixed_security_are_exact() {
        let request = (0..32)
            .map(|index| (format!("application/request-{index}"), json!({})))
            .collect::<serde_json::Map<_, _>>();
        let response = (0..32)
            .map(|index| (format!("application/response-{index}"), json!({})))
            .collect::<serde_json::Map<_, _>>();
        let accepted = json!({"openapi":"3.1.0","components":{"securitySchemes":{"basic":{"type":"http","scheme":"basic"}}},"security":[{}, {"basic":[]}],"paths":{"x-note":{"safe":true},"/x":{"get":{"operationId":"boundedOperation","parameters":[{"name":"host","in":"query","schema":{"type":"string","format":"hostname"}}],"requestBody":{"content":request},"responses":{"2XX":{"content":response}}}}}});
        let document = parse(&accepted);
        let operation = &document.catalog().operations()[0];
        assert_eq!(document.path_count(), 1);
        assert_eq!(
            operation.responses()[0].status(),
            OpenApiResponseStatus::Range(2)
        );
        assert!(operation.security().permits_anonymous() && operation.security().declares_auth());
        assert!(operation
            .candidate_tags()
            .contains(&OpenApiCandidateTag::DeclaresAnonymousAccess));
        assert!(operation
            .candidate_tags()
            .contains(&OpenApiCandidateTag::DeclaresSecurity));
        assert!(operation
            .candidate_tags()
            .contains(&OpenApiCandidateTag::SsrfUrlCandidate));
        assert_eq!(document.catalog().declaring_anonymous_access().len(), 1);
        assert_eq!(document.catalog().declaring_explicit_auth().len(), 1);
        for range in ["*/*", "application/*"] {
            assert!(normalize_media_type(range).is_ok());
        }
        let mut too_many = accepted;
        too_many["paths"]["/x"]["get"]["responses"]["3XX"] =
            json!({"content":{"application/extra":{}}});
        assert_eq!(
            OpenApiDocument::parse_json(&serde_json::to_vec(&too_many).unwrap()),
            Err(OpenApiReviewError::CatalogLimit)
        );
        assert_eq!(operation.parameters()[0].name_fingerprint().len(), 32);
        assert_eq!(
            operation.declared_operation_id_fingerprint().unwrap().len(),
            32
        );
    }
}
