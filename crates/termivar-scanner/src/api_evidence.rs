//! Pure, bounded evidence preparation for paired API visibility comparisons.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B support (paired API visibility workflow).
//! - **Default `termivar scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This module deliberately performs no network I/O, knowledge-base writes,
//! rule evaluation, or planning. A host captures two already-authorized JSON
//! views, then compares one explicit visibility dimension. Raw JSON is borrowed
//! only while canonical signatures are calculated and is never retained.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use termivar_core::{
    ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension, ApiVisibilityPairKind,
    ApiVisibilityResult, ApiVocabularyError,
};
use thiserror::Error;

mod profiled;

pub use profiled::{
    ApiComparisonProfile, CanonicalizationVersion, ComparisonAlgorithmVersion, JsonPathPattern,
    PathDigest, ProfiledApiVisibilityComparison, ProfiledApiVisibilityError,
    ProfiledApiVisibilityView, ProjectionPolicyId, RedactedVisibilityDiff,
    VisibilityExplanationDisposition, CURRENT_API_COMPARISON_ALGORITHM_VERSION,
    CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION, DEFAULT_API_VISIBILITY_DIFF_PATHS,
    HARD_MAX_API_COMPARISON_PATH_BYTES, HARD_MAX_API_COMPARISON_PATH_DEPTH,
    HARD_MAX_API_COMPARISON_PROFILE_PATHS, HARD_MAX_API_VISIBILITY_DIFF_PATHS,
};

const MAX_OPAQUE_HANDLE_BYTES: usize = 256;
const RESOURCE_SIGNATURE_DOMAIN: &[u8] = b"venom.api-visibility.resource.v1\0";
const FIELD_SIGNATURE_DOMAIN: &[u8] = b"venom.api-visibility.fields.v1\0";

/// Hard ceiling for the maximum JSON nesting depth accepted by a comparator.
pub const HARD_MAX_API_VISIBILITY_DEPTH: u16 = 128;
/// Hard ceiling for the maximum JSON values accepted by one captured view.
pub const HARD_MAX_API_VISIBILITY_NODES: u32 = 1_000_000;
/// Hard ceiling for the total object members accepted by one captured view.
pub const HARD_MAX_API_VISIBILITY_FIELDS: u32 = 250_000;
/// Hard ceiling for either canonical signature stream.
pub const HARD_MAX_API_VISIBILITY_CANONICAL_BYTES: u64 = 64 * 1024 * 1024;

/// Default maximum JSON nesting depth.
pub const DEFAULT_API_VISIBILITY_DEPTH: u16 = 64;
/// Default maximum number of JSON values in one view.
pub const DEFAULT_API_VISIBILITY_NODES: u32 = 100_000;
/// Default maximum number of object members in one view.
pub const DEFAULT_API_VISIBILITY_FIELDS: u32 = 50_000;
/// Default maximum number of bytes in either canonical signature stream.
pub const DEFAULT_API_VISIBILITY_CANONICAL_BYTES: u64 = 8 * 1024 * 1024;

/// Fail-closed resource limits for canonicalizing one API visibility view.
///
/// Root JSON values have depth one. `max_nodes` counts every array, object, and
/// scalar value, while `max_fields` counts object members across the complete
/// tree. `max_canonical_bytes` is applied independently to the full-resource
/// stream and the fields-only schema stream.
///
/// Limits are serialized so a host can persist the policy used for a replay.
/// Deserialization revalidates every value, rejects unknown fields, and never
/// permits a persisted policy to exceed the compiled hard ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityLimits {
    max_depth: u16,
    max_nodes: u32,
    max_fields: u32,
    max_canonical_bytes: u64,
}

impl ApiVisibilityLimits {
    /// Creates a validated canonicalization envelope.
    pub fn new(
        max_depth: u16,
        max_nodes: u32,
        max_fields: u32,
        max_canonical_bytes: u64,
    ) -> Result<Self, ApiVisibilityEvidenceError> {
        validate_limit(
            "max_depth",
            u64::from(max_depth),
            u64::from(HARD_MAX_API_VISIBILITY_DEPTH),
        )?;
        validate_limit(
            "max_nodes",
            u64::from(max_nodes),
            u64::from(HARD_MAX_API_VISIBILITY_NODES),
        )?;
        validate_limit(
            "max_fields",
            u64::from(max_fields),
            u64::from(HARD_MAX_API_VISIBILITY_FIELDS),
        )?;
        validate_limit(
            "max_canonical_bytes",
            max_canonical_bytes,
            HARD_MAX_API_VISIBILITY_CANONICAL_BYTES,
        )?;
        Ok(Self {
            max_depth,
            max_nodes,
            max_fields,
            max_canonical_bytes,
        })
    }

    /// Returns the inclusive JSON nesting-depth limit.
    pub const fn max_depth(self) -> u16 {
        self.max_depth
    }

    /// Returns the inclusive JSON value-count limit.
    pub const fn max_nodes(self) -> u32 {
        self.max_nodes
    }

    /// Returns the inclusive object-member count limit.
    pub const fn max_fields(self) -> u32 {
        self.max_fields
    }

    /// Returns the inclusive byte limit for each canonical signature stream.
    pub const fn max_canonical_bytes(self) -> u64 {
        self.max_canonical_bytes
    }
}

impl Default for ApiVisibilityLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_API_VISIBILITY_DEPTH,
            max_nodes: DEFAULT_API_VISIBILITY_NODES,
            max_fields: DEFAULT_API_VISIBILITY_FIELDS,
            max_canonical_bytes: DEFAULT_API_VISIBILITY_CANONICAL_BYTES,
        }
    }
}

impl<'de> Deserialize<'de> for ApiVisibilityLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireLimits {
            max_depth: u16,
            max_nodes: u32,
            max_fields: u32,
            max_canonical_bytes: u64,
        }

        let wire = WireLimits::deserialize(deserializer)?;
        Self::new(
            wire.max_depth,
            wire.max_nodes,
            wire.max_fields,
            wire.max_canonical_bytes,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// A bounded, raw-value-free API response view ready for paired comparison.
///
/// The view retains opaque context and resource handles, the API surface, the
/// exact HTTP status, and two SHA-256 signatures. It does **not** retain the
/// supplied [`serde_json::Value`] or any canonical byte buffer. This type is
/// intentionally not serializable: persist the resulting
/// [`ApiVisibilityComparison`] and the [`ApiVisibilityLimits`] policy instead.
///
/// The signatures are deterministic pseudonymous fingerprints, not MACs,
/// signatures, attestations, or substitutes for an authorized evidence-write
/// boundary. Context and scope handles are serialized by the resulting core
/// comparison, so callers must use bounded, non-secret opaque identifiers.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiVisibilityView {
    context_id: String,
    resource_scope_id: String,
    surface: ApiSurfaceKind,
    status: u16,
    resource_signature: [u8; 32],
    field_signature: [u8; 32],
    limits: ApiVisibilityLimits,
}

/// Raw-value-free equality across the three exact replay dimensions.
///
/// This crate-private result lets native replay capabilities reuse the
/// canonical API signatures without inventing a semantically inaccurate
/// public [`ApiVisibilityPairKind`] or exposing either signature.
#[cfg(feature = "rest-review")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApiExactReplayComparison {
    status: bool,
    fields: bool,
    resources: bool,
}

#[cfg(feature = "rest-review")]
impl ApiExactReplayComparison {
    pub(crate) const fn status(self) -> bool {
        self.status
    }

    pub(crate) const fn fields(self) -> bool {
        self.fields
    }

    pub(crate) const fn resources(self) -> bool {
        self.resources
    }

    pub(crate) const fn all_equivalent(self) -> bool {
        self.status && self.fields && self.resources
    }
}

impl std::fmt::Debug for ApiVisibilityView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiVisibilityView")
            .field("context_id", &"<redacted>")
            .field("resource_scope_id", &"<redacted>")
            .field("surface", &self.surface)
            .field("status", &self.status)
            .field("resource_signature", &"<redacted>")
            .field("field_signature", &"<redacted>")
            .field("limits", &self.limits)
            .finish()
    }
}

impl ApiVisibilityView {
    /// Returns the non-secret opaque authorization or presentation context.
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the non-secret opaque logical-resource scope.
    pub fn resource_scope_id(&self) -> &str {
        &self.resource_scope_id
    }

    /// Returns the declared API surface.
    pub const fn surface(&self) -> ApiSurfaceKind {
        self.surface
    }

    /// Returns the exact HTTP response status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the policy used to create this view.
    pub const fn limits(&self) -> ApiVisibilityLimits {
        self.limits
    }
}

/// Pure canonicalizer and comparator for two authorized API response views.
///
/// Object keys are compared in UTF-8 byte order, so input map insertion order
/// never changes a signature. Array position and duplicate elements remain
/// meaningful. `Fields` compares only key/schema structure, `Resources`
/// compares the complete canonical JSON value, and `Status` compares the exact
/// validated HTTP status.
///
/// JSON-number text follows the pinned `serde_json` implementation. Signatures
/// are deterministic within this comparator version, but are not a permanent
/// cross-version wire-hash promise; persisted replay data should record the
/// comparator version and dependency set.
///
/// Comparison itself reads no clock. The caller supplies both a stable
/// observation identity and `observed_at_ms`; replaying the same inputs with
/// those same values produces the same [`ApiVisibilityComparison`]. A caller
/// must allocate a new comparison identity for a genuinely new observation.
///
/// # Examples
///
/// ```rust
/// use serde_json::json;
/// use termivar_core::{
///     ApiSurfaceKind, ApiVisibilityDimension, ApiVisibilityPairKind,
///     ApiVisibilityResult,
/// };
/// use termivar_scanner::ApiVisibilityComparator;
///
/// let comparator = ApiVisibilityComparator::default();
/// let baseline = comparator.capture_view(
///     "anonymous-view",
///     "resource:account-42",
///     ApiSurfaceKind::JsonHttp,
///     200,
///     &json!({"id": 42}),
/// )?;
/// let candidate = comparator.capture_view(
///     "member-view",
///     "resource:account-42",
///     ApiSurfaceKind::JsonHttp,
///     200,
///     &json!({"id": 42, "email": "redacted@example.test"}),
/// )?;
/// let comparison = comparator.compare(
///     "comparison-17",
///     ApiVisibilityPairKind::AuthorizationContext,
///     ApiVisibilityDimension::Fields,
///     &baseline,
///     &candidate,
///     1_800_000_000_000,
/// )?;
///
/// assert_eq!(comparison.result(), ApiVisibilityResult::Different);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiVisibilityComparator {
    limits: ApiVisibilityLimits,
}

impl ApiVisibilityComparator {
    /// Creates a pure comparator under an already validated resource envelope.
    pub const fn new(limits: ApiVisibilityLimits) -> Self {
        Self { limits }
    }

    /// Returns the immutable canonicalization envelope.
    pub const fn limits(&self) -> ApiVisibilityLimits {
        self.limits
    }

    /// Captures bounded signatures from one borrowed JSON snapshot.
    ///
    /// The snapshot is traversed once and discarded when this call returns. No
    /// raw scalar, key, body, token, or canonical byte stream is retained in the
    /// returned view, and deterministic signatures are redacted from its
    /// [`std::fmt::Debug`] representation.
    ///
    /// The supplied [`serde_json::Value`] has already been read and parsed, so
    /// these traversal limits cannot bound transport reads or parser allocation.
    /// The host must enforce its response-byte budget before parsing untrusted
    /// JSON and must keep raw response values out of logs.
    pub fn capture_view(
        &self,
        context_id: impl Into<String>,
        resource_scope_id: impl Into<String>,
        surface: ApiSurfaceKind,
        status: u16,
        snapshot: &Value,
    ) -> Result<ApiVisibilityView, ApiVisibilityEvidenceError> {
        let context_id = opaque_handle(context_id, "context id")?;
        let resource_scope_id = opaque_handle(resource_scope_id, "resource scope id")?;
        if !(100..=599).contains(&status) {
            return Err(ApiVisibilityEvidenceError::InvalidHttpStatus { status });
        }

        let signatures = canonical_signatures(snapshot, self.limits)?;
        Ok(ApiVisibilityView {
            context_id,
            resource_scope_id,
            surface,
            status,
            resource_signature: signatures.resource,
            field_signature: signatures.fields,
            limits: self.limits,
        })
    }

    /// Compares one explicit dimension and emits only the typed core contract.
    ///
    /// Views must use this comparator's limits, the same resource scope and API
    /// surface, and distinct context handles. `comparison_id` is a caller-owned
    /// immutable observation identity. It and both handles must be non-secret
    /// because the core comparison's replay form serializes them.
    #[allow(clippy::too_many_arguments)]
    pub fn compare(
        &self,
        comparison_id: impl Into<String>,
        pair: ApiVisibilityPairKind,
        dimension: ApiVisibilityDimension,
        baseline: &ApiVisibilityView,
        candidate: &ApiVisibilityView,
        observed_at_ms: u64,
    ) -> Result<ApiVisibilityComparison, ApiVisibilityEvidenceError> {
        if baseline.limits != self.limits || candidate.limits != self.limits {
            return Err(ApiVisibilityEvidenceError::LimitsMismatch);
        }
        if baseline.context_id == candidate.context_id {
            return Err(ApiVisibilityEvidenceError::IdenticalContexts);
        }
        if baseline.resource_scope_id != candidate.resource_scope_id {
            return Err(ApiVisibilityEvidenceError::ResourceScopeMismatch);
        }
        if baseline.surface != candidate.surface {
            return Err(ApiVisibilityEvidenceError::SurfaceMismatch);
        }

        let equivalent = match dimension {
            ApiVisibilityDimension::Fields => baseline.field_signature == candidate.field_signature,
            ApiVisibilityDimension::Resources => {
                baseline.resource_signature == candidate.resource_signature
            },
            ApiVisibilityDimension::Status => baseline.status == candidate.status,
            _ => return Err(ApiVisibilityEvidenceError::UnsupportedDimension),
        };
        let result = if equivalent {
            ApiVisibilityResult::Equivalent
        } else {
            ApiVisibilityResult::Different
        };

        Ok(ApiVisibilityComparison::new(
            comparison_id,
            baseline.surface,
            pair,
            result,
            dimension,
            baseline.context_id.clone(),
            candidate.context_id.clone(),
            baseline.resource_scope_id.clone(),
        )?
        .with_observed_at_ms(observed_at_ms))
    }

    /// Compares two captures of one exact resource without assigning them an
    /// authorization- or UI-specific public pair meaning.
    ///
    /// The validation is intentionally identical to [`Self::compare`]: both
    /// views must use this comparator's bounds and the same resource/surface,
    /// while their scanner-owned replay contexts must remain distinct.
    #[cfg(feature = "rest-review")]
    pub(crate) fn compare_exact_replay(
        &self,
        candidate: &ApiVisibilityView,
        replay: &ApiVisibilityView,
    ) -> Result<ApiExactReplayComparison, ApiVisibilityEvidenceError> {
        if candidate.limits != self.limits || replay.limits != self.limits {
            return Err(ApiVisibilityEvidenceError::LimitsMismatch);
        }
        if candidate.context_id == replay.context_id {
            return Err(ApiVisibilityEvidenceError::IdenticalContexts);
        }
        if candidate.resource_scope_id != replay.resource_scope_id {
            return Err(ApiVisibilityEvidenceError::ResourceScopeMismatch);
        }
        if candidate.surface != replay.surface {
            return Err(ApiVisibilityEvidenceError::SurfaceMismatch);
        }

        Ok(ApiExactReplayComparison {
            status: candidate.status == replay.status,
            fields: candidate.field_signature == replay.field_signature,
            resources: candidate.resource_signature == replay.resource_signature,
        })
    }
}

impl Default for ApiVisibilityComparator {
    fn default() -> Self {
        Self::new(ApiVisibilityLimits::default())
    }
}

/// Validation and canonicalization failures for API visibility evidence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ApiVisibilityEvidenceError {
    /// A configurable resource limit was zero.
    #[error("API visibility limit {dimension} must be greater than zero")]
    ZeroLimit { dimension: &'static str },

    /// A configurable resource limit exceeded its compiled hard ceiling.
    #[error("API visibility limit {dimension} value {actual} exceeds hard ceiling {maximum}")]
    HardLimitExceeded {
        /// Rejected limit name.
        dimension: &'static str,
        /// Rejected value.
        actual: u64,
        /// Inclusive compiled ceiling.
        maximum: u64,
    },

    /// An opaque context or scope handle was empty.
    #[error("API visibility {field} must not be empty")]
    EmptyHandle { field: &'static str },

    /// An opaque context or scope handle exceeded the bounded core contract.
    #[error("API visibility {field} exceeds the {maximum}-byte limit")]
    HandleTooLong {
        /// Rejected handle role.
        field: &'static str,
        /// Inclusive byte limit.
        maximum: usize,
    },

    /// A response status was outside the standard HTTP range.
    #[error("API visibility HTTP status {status} is outside 100..=599")]
    InvalidHttpStatus { status: u16 },

    /// JSON nesting exceeded the selected policy.
    #[error("API visibility JSON depth {observed} exceeds limit {limit}")]
    DepthLimitExceeded { limit: u16, observed: u64 },

    /// JSON value count exceeded the selected policy.
    #[error("API visibility JSON node count {observed} exceeds limit {limit}")]
    NodeLimitExceeded { limit: u32, observed: u64 },

    /// Object-member count exceeded the selected policy.
    #[error("API visibility JSON field count {observed} exceeds limit {limit}")]
    FieldLimitExceeded { limit: u32, observed: u64 },

    /// A canonical signature stream exceeded the selected byte policy.
    #[error(
        "API visibility {signature} canonical stream reached {observed} bytes, above limit {limit}"
    )]
    CanonicalBytesLimitExceeded {
        /// Stable stream name (`resources` or `fields`).
        signature: &'static str,
        /// Inclusive configured limit.
        limit: u64,
        /// Bytes required by the attempted write.
        observed: u64,
    },

    /// Views captured under another policy cannot be mixed silently.
    #[error("API visibility views were captured under different limits")]
    LimitsMismatch,

    /// A pair must compare two distinct authorization or presentation contexts.
    #[error("API visibility comparison contexts must be different")]
    IdenticalContexts,

    /// Both views must describe the same host-asserted logical resource.
    #[error("API visibility comparison resource scopes do not match")]
    ResourceScopeMismatch,

    /// Both views must describe the same declared API surface.
    #[error("API visibility comparison surfaces do not match")]
    SurfaceMismatch,

    /// A future core dimension is not yet supported by this comparator version.
    #[error("API visibility comparison dimension is unsupported by this comparator")]
    UnsupportedDimension,

    /// The resulting core comparison contract rejected an identifier or value.
    #[error(transparent)]
    Vocabulary(#[from] ApiVocabularyError),
}

fn validate_limit(
    dimension: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), ApiVisibilityEvidenceError> {
    if actual == 0 {
        return Err(ApiVisibilityEvidenceError::ZeroLimit { dimension });
    }
    if actual > maximum {
        return Err(ApiVisibilityEvidenceError::HardLimitExceeded {
            dimension,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn opaque_handle(
    value: impl Into<String>,
    field: &'static str,
) -> Result<String, ApiVisibilityEvidenceError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(ApiVisibilityEvidenceError::EmptyHandle { field });
    }
    if value.len() > MAX_OPAQUE_HANDLE_BYTES {
        return Err(ApiVisibilityEvidenceError::HandleTooLong {
            field,
            maximum: MAX_OPAQUE_HANDLE_BYTES,
        });
    }
    Ok(value)
}

struct CanonicalSignatures {
    resource: [u8; 32],
    fields: [u8; 32],
}

fn canonical_signatures(
    value: &Value,
    limits: ApiVisibilityLimits,
) -> Result<CanonicalSignatures, ApiVisibilityEvidenceError> {
    let mut state = CanonicalState {
        limits,
        nodes: 0,
        fields: 0,
        resource: SignatureWriter::new("resources", RESOURCE_SIGNATURE_DOMAIN, limits),
        schema: SignatureWriter::new("fields", FIELD_SIGNATURE_DOMAIN, limits),
    };
    state.visit(value, 1)?;
    Ok(CanonicalSignatures {
        resource: state.resource.finish(),
        fields: state.schema.finish(),
    })
}

struct CanonicalState {
    limits: ApiVisibilityLimits,
    nodes: u64,
    fields: u64,
    resource: SignatureWriter,
    schema: SignatureWriter,
}

impl CanonicalState {
    fn visit(&mut self, value: &Value, depth: u64) -> Result<(), ApiVisibilityEvidenceError> {
        if depth > u64::from(self.limits.max_depth) {
            return Err(ApiVisibilityEvidenceError::DepthLimitExceeded {
                limit: self.limits.max_depth,
                observed: depth,
            });
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > u64::from(self.limits.max_nodes) {
            return Err(ApiVisibilityEvidenceError::NodeLimitExceeded {
                limit: self.limits.max_nodes,
                observed: self.nodes,
            });
        }

        match value {
            Value::Null => {
                self.resource.write(b"0")?;
                self.schema.write(b"0")?;
            },
            Value::Bool(value) => {
                self.resource.write(if *value { b"t" } else { b"f" })?;
                self.schema.write(b"b")?;
            },
            Value::Number(value) => {
                self.resource.write(b"n")?;
                self.resource.write_framed(value.to_string().as_bytes())?;
                self.schema.write(if value.is_i64() || value.is_u64() {
                    b"i"
                } else {
                    b"n"
                })?;
            },
            Value::String(value) => {
                self.resource.write(b"s")?;
                self.resource.write_framed(value.as_bytes())?;
                self.schema.write(b"s")?;
            },
            Value::Array(values) => {
                self.resource.write(b"[")?;
                self.resource.write_len(values.len())?;
                self.schema.write(b"[")?;
                self.schema.write_len(values.len())?;
                for value in values {
                    self.visit(value, depth.saturating_add(1))?;
                }
                self.resource.write(b"]")?;
                self.schema.write(b"]")?;
            },
            Value::Object(values) => {
                self.fields = self
                    .fields
                    .saturating_add(u64::try_from(values.len()).unwrap_or(u64::MAX));
                if self.fields > u64::from(self.limits.max_fields) {
                    return Err(ApiVisibilityEvidenceError::FieldLimitExceeded {
                        limit: self.limits.max_fields,
                        observed: self.fields,
                    });
                }

                self.resource.write(b"{")?;
                self.resource.write_len(values.len())?;
                self.schema.write(b"{")?;
                self.schema.write_len(values.len())?;
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
                for (key, value) in entries {
                    self.resource.write_framed(key.as_bytes())?;
                    self.schema.write_framed(key.as_bytes())?;
                    self.visit(value, depth.saturating_add(1))?;
                }
                self.resource.write(b"}")?;
                self.schema.write(b"}")?;
            },
        }
        Ok(())
    }
}

struct SignatureWriter {
    name: &'static str,
    limit: u64,
    written: u64,
    hasher: Sha256,
}

impl SignatureWriter {
    fn new(name: &'static str, domain: &[u8], limits: ApiVisibilityLimits) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        Self {
            name,
            limit: limits.max_canonical_bytes,
            written: 0,
            hasher,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), ApiVisibilityEvidenceError> {
        let observed = self
            .written
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if observed > self.limit {
            return Err(ApiVisibilityEvidenceError::CanonicalBytesLimitExceeded {
                signature: self.name,
                limit: self.limit,
                observed,
            });
        }
        self.hasher.update(bytes);
        self.written = observed;
        Ok(())
    }

    fn write_len(&mut self, length: usize) -> Result<(), ApiVisibilityEvidenceError> {
        self.write(&u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes())
    }

    fn write_framed(&mut self, bytes: &[u8]) -> Result<(), ApiVisibilityEvidenceError> {
        self.write_len(bytes.len())?;
        self.write(bytes)
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
#[path = "api_evidence_tests.rs"]
mod tests;
