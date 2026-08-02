//! Host-facing ingestion and projection for paired API visibility observations.
//!
//! This module bridges the evidence and decision engines without moving
//! network, credential, comparison, or planning policy into reasoning. The
//! authorized host establishes that two views describe the same logical
//! resource before it constructs an [`ApiVisibilityObservation`].

use std::fmt;

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use venom_core::{
    ApiEvidencePredicate, ApiKnowledgePredicate, ApiVisibilityBoundaryKind, ApiVisibilityDimension,
    ApiVisibilityObservation, ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind,
    EvidenceValue, Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate,
    KnowledgeRelation, RelationId, RelationKind,
};

use crate::{
    knowledge::{
        KnowledgeBase, KnowledgeBaseError, KnowledgeWrite, MAX_KNOWLEDGE_RELATION_ID_BYTES,
    },
    rules::{hypothesis_id_for_rule, RuleApplication, RuleEngine, RuleEngineError},
};

const API_VISIBILITY_RELATION: &str = "api.visibility.resource-scope";
const API_VISIBILITY_EVIDENCE_KIND: &str = "api.visibility-comparison";
const API_VISIBILITY_SOURCE_METHOD: &str = "paired-api-visibility";
const COMPARISON_SUBJECT_PREFIX: &str = "api-comparison:";
const COMPARISON_EVIDENCE_PREFIX: &str = "api-comparison-evidence:";
const COMPARISON_RELATION_PREFIX: &str = "api-comparison-scope:";
const UI_API_BOUNDARY_RULE: &str = "api.visibility.ui-api.paired-difference";
const AUTHORIZATION_BOUNDARY_RULE: &str = "api.visibility.authorization-context.paired-difference";
const API_VISIBILITY_REVIEW_CURSOR_PREFIX: &str = "venom-api-review-v2:";
const API_VISIBILITY_REVIEW_CURSOR_DOMAIN: &[u8] = b"venom.api-visibility.review-cursor.v2\0";
const API_VISIBILITY_REVIEW_RESOURCE_DIGEST_HEX_BYTES: usize = 64;

/// Default number of incoming resource relations scanned by one review page.
pub const DEFAULT_API_VISIBILITY_REVIEW_SCAN_LIMIT: u16 = 128;
/// Hard ceiling for incoming resource relations scanned by one review page.
pub const HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT: u16 = 1_024;
/// Hard byte ceiling for the producer component stored in a reviewable observation.
pub const MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES: usize = 256;
/// Hard byte ceiling for one boundary-hypothesis explanation in a review page.
pub const MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES: usize = 1_024;
/// Hard byte ceiling for one serialized resource-bound review cursor.
pub const MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES: usize = API_VISIBILITY_REVIEW_CURSOR_PREFIX.len()
    + API_VISIBILITY_REVIEW_RESOURCE_DIGEST_HEX_BYTES
    + 1
    + (MAX_KNOWLEDGE_RELATION_ID_BYTES * 2);

/// Receipt for an observation pair committed to one [`KnowledgeBase`] instance.
///
/// Evidence and its resource-scope relation are committed atomically. Rule
/// application happens afterwards and is deliberately not part of that write
/// transaction. This receipt does not imply that the in-memory knowledge base
/// has been persisted by its host.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiObservationCommitReceipt {
    comparison_subject: EntityId,
    resource_scope: EntityId,
    evidence_id: EvidenceId,
    relation_id: RelationId,
    evidence_write: KnowledgeWrite,
    relation_write: KnowledgeWrite,
}

impl fmt::Debug for ApiObservationCommitReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiObservationCommitReceipt")
            .field("comparison_subject", &"<redacted>")
            .field("resource_scope", &"<redacted>")
            .field("evidence_id", &"<redacted>")
            .field("relation_id", &"<redacted>")
            .field("evidence_write", &self.evidence_write)
            .field("relation_write", &self.relation_write)
            .finish()
    }
}

impl ApiObservationCommitReceipt {
    /// Returns the isolated subject on which comparison reasoning runs.
    pub fn comparison_subject(&self) -> &EntityId {
        &self.comparison_subject
    }

    /// Returns the host-declared logical resource that was compared.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns the immutable comparison evidence identity.
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence_id
    }

    /// Returns the evidence-backed resource relation identity.
    pub fn relation_id(&self) -> &RelationId {
        &self.relation_id
    }

    /// Returns whether evidence was inserted or replayed unchanged.
    pub const fn evidence_write(&self) -> KnowledgeWrite {
        self.evidence_write
    }

    /// Returns whether the resource relation was inserted or replayed unchanged.
    pub const fn relation_write(&self) -> KnowledgeWrite {
        self.relation_write
    }
}

/// Complete successful observation and reasoning receipt.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiObservationReceipt {
    commit: ApiObservationCommitReceipt,
    applications: Vec<RuleApplication>,
}

impl fmt::Debug for ApiObservationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiObservationReceipt")
            .field("commit", &self.commit)
            .field("application_count", &self.applications.len())
            .finish()
    }
}

impl ApiObservationReceipt {
    /// Returns the observation commit for the supplied knowledge-base instance.
    pub fn commit(&self) -> &ApiObservationCommitReceipt {
        &self.commit
    }

    /// Returns rule evaluations and hypothesis writes in stable rule-ID order.
    ///
    /// Materialized hypotheses retain their evaluation timestamps, so complete
    /// receipt bytes are not guaranteed to be identical across exact replays.
    /// Each application carries the evaluated snapshot candidate and its write
    /// status, not a fresh clone of committed state. If terminal-state
    /// preservation matters, re-read the hypothesis from the knowledge base.
    pub fn applications(&self) -> &[RuleApplication] {
        &self.applications
    }

    /// Splits the receipt into its observation commit and reasoning applications.
    pub fn into_parts(self) -> (ApiObservationCommitReceipt, Vec<RuleApplication>) {
        (self.commit, self.applications)
    }
}

/// Failure while accepting or reasoning over an API visibility observation.
#[derive(Error)]
#[non_exhaustive]
pub enum ApiObservationError {
    /// The observation described a resource outside the host-selected scope.
    #[error("API visibility observation resource does not match expected resource")]
    ResourceMismatch {
        /// Resource authorized by the caller.
        expected: EntityId,
        /// Resource declared by the observation.
        actual: EntityId,
    },

    /// A review query cannot make progress with an empty scan window.
    #[error("API visibility review scan limit must be greater than zero")]
    ZeroReviewScanLimit,

    /// A review query exceeded the compiled per-page scan ceiling.
    #[error("API visibility review scan limit {actual} exceeds hard ceiling {maximum}")]
    ReviewScanLimitExceeded {
        /// Rejected requested relation count.
        actual: u16,
        /// Inclusive compiled ceiling.
        maximum: u16,
    },

    /// A review cursor exceeded the relation-store identifier ceiling.
    #[error("API visibility review cursor is {actual} bytes, above hard ceiling {maximum}")]
    ReviewCursorTooLong {
        /// Rejected cursor byte length.
        actual: usize,
        /// Inclusive relation identifier ceiling.
        maximum: usize,
    },

    /// A serialized resource-bound review cursor exceeded its compiled ceiling.
    #[error("API visibility resource-bound review cursor is {actual} bytes, above hard ceiling {maximum}")]
    ResourceBoundReviewCursorTooLong {
        /// Rejected serialized cursor byte length.
        actual: usize,
        /// Inclusive compiled cursor ceiling.
        maximum: usize,
    },

    /// A serialized resource-bound review cursor was not canonical v2 syntax.
    #[error("invalid API visibility resource-bound review cursor: {reason}")]
    InvalidResourceBoundReviewCursor {
        /// Stable parse reason that never contains cursor input.
        reason: &'static str,
    },

    /// A resource-bound review cursor used an unsupported wire version.
    #[error("unsupported API visibility resource-bound review cursor version")]
    UnsupportedResourceBoundReviewCursorVersion,

    /// A resource-bound review cursor was replayed against another resource.
    #[error("API visibility resource-bound review cursor does not match requested resource")]
    ResourceBoundReviewCursorMismatch,

    /// An observation field exceeded the review model's storage ceiling.
    #[error("API visibility observation {field} size {actual} exceeds hard ceiling {maximum}")]
    ObservationLimitExceeded {
        /// Stable field name (`source.component`).
        field: &'static str,
        /// Rejected UTF-8 byte count.
        actual: usize,
        /// Inclusive compiled ceiling.
        maximum: usize,
    },

    /// The atomic evidence and relation write failed before anything committed.
    #[error(transparent)]
    Knowledge(#[from] KnowledgeBaseError),

    /// Reasoning failed after the observation pair had committed.
    #[error("API visibility observation committed before reasoning failed: {source}")]
    ReasoningAfterCommit {
        /// Committed observation that must not be retried as if no write occurred.
        commit: Box<ApiObservationCommitReceipt>,
        /// Rule evaluation or hypothesis-write failure.
        #[source]
        source: RuleEngineError,
    },
}

impl fmt::Debug for ApiObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceMismatch { .. } => formatter
                .debug_struct("ResourceMismatch")
                .field("expected", &"<redacted>")
                .field("actual", &"<redacted>")
                .finish(),
            Self::ZeroReviewScanLimit => formatter.write_str("ZeroReviewScanLimit"),
            Self::ReviewScanLimitExceeded { actual, maximum } => formatter
                .debug_struct("ReviewScanLimitExceeded")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::ReviewCursorTooLong { actual, maximum } => formatter
                .debug_struct("ReviewCursorTooLong")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::ResourceBoundReviewCursorTooLong { actual, maximum } => formatter
                .debug_struct("ResourceBoundReviewCursorTooLong")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::InvalidResourceBoundReviewCursor { reason } => formatter
                .debug_struct("InvalidResourceBoundReviewCursor")
                .field("reason", reason)
                .finish(),
            Self::UnsupportedResourceBoundReviewCursorVersion => {
                formatter.write_str("UnsupportedResourceBoundReviewCursorVersion")
            },
            Self::ResourceBoundReviewCursorMismatch => {
                formatter.write_str("ResourceBoundReviewCursorMismatch")
            },
            Self::ObservationLimitExceeded {
                field,
                actual,
                maximum,
            } => formatter
                .debug_struct("ObservationLimitExceeded")
                .field("field", field)
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::Knowledge(source) => formatter.debug_tuple("Knowledge").field(source).finish(),
            Self::ReasoningAfterCommit { commit, source } => formatter
                .debug_struct("ReasoningAfterCommit")
                .field("commit", commit)
                .field("source", source)
                .finish(),
        }
    }
}

impl ApiObservationError {
    /// Returns the committed observation receipt when failure happened post-commit.
    pub fn committed_observation(&self) -> Option<&ApiObservationCommitReceipt> {
        match self {
            Self::ReasoningAfterCommit { commit, .. } => Some(commit),
            Self::ResourceMismatch { .. }
            | Self::ZeroReviewScanLimit
            | Self::ReviewScanLimitExceeded { .. }
            | Self::ReviewCursorTooLong { .. }
            | Self::ResourceBoundReviewCursorTooLong { .. }
            | Self::InvalidResourceBoundReviewCursor { .. }
            | Self::UnsupportedResourceBoundReviewCursorVersion
            | Self::ResourceBoundReviewCursorMismatch
            | Self::ObservationLimitExceeded { .. }
            | Self::Knowledge(_) => None,
        }
    }

    /// Takes the committed receipt without cloning it.
    pub fn into_committed_observation(self) -> Option<ApiObservationCommitReceipt> {
        match self {
            Self::ReasoningAfterCommit { commit, .. } => Some(*commit),
            Self::ResourceMismatch { .. }
            | Self::ZeroReviewScanLimit
            | Self::ReviewScanLimitExceeded { .. }
            | Self::ReviewCursorTooLong { .. }
            | Self::ResourceBoundReviewCursorTooLong { .. }
            | Self::InvalidResourceBoundReviewCursor { .. }
            | Self::UnsupportedResourceBoundReviewCursorVersion
            | Self::ResourceBoundReviewCursorMismatch
            | Self::ObservationLimitExceeded { .. }
            | Self::Knowledge(_) => None,
        }
    }

    /// Returns the post-commit reasoning error, when applicable.
    pub fn reasoning_source(&self) -> Option<&RuleEngineError> {
        match self {
            Self::ReasoningAfterCommit { source, .. } => Some(source),
            Self::ResourceMismatch { .. }
            | Self::ZeroReviewScanLimit
            | Self::ReviewScanLimitExceeded { .. }
            | Self::ReviewCursorTooLong { .. }
            | Self::ResourceBoundReviewCursorTooLong { .. }
            | Self::InvalidResourceBoundReviewCursor { .. }
            | Self::UnsupportedResourceBoundReviewCursorVersion
            | Self::ResourceBoundReviewCursorMismatch
            | Self::ObservationLimitExceeded { .. }
            | Self::Knowledge(_) => None,
        }
    }
}

/// Accepts one host-paired visibility observation and applies installed rules.
///
/// The expected resource is checked before any write. Evidence and its sole
/// `api.visibility.resource-scope` relation are then inserted atomically, and
/// rules are applied to the isolated comparison subject. If reasoning fails,
/// the observation pair remains committed and the error carries its
/// receipt; callers must not infer rollback from a failed return value. The
/// host remains responsible for persistence beyond this in-memory store.
///
/// This boundary validates scope and canonical storage shape, not producer
/// identity or truth. Predicate names and deterministic digests are public and
/// are not signatures. The host must authenticate the producer, authorize the
/// comparison, and keep raw credentials and response values outside this API.
///
/// # Examples
///
/// ```rust
/// use venom_core::{
///     ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension,
///     ApiVisibilityPairKind, ApiVisibilityResult, ConfidenceScore, EntityId,
/// };
/// use venom_scanner::{
///     KnowledgeBase, RuleEngine, StandardApiReasoning,
///     ingest_api_visibility_observation,
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
/// .with_observed_at_ms(1_800_000_000_000)
/// .to_observation("host.api-comparator", ConfidenceScore::MAX)?;
/// let knowledge = KnowledgeBase::new();
/// let mut rules = RuleEngine::new();
/// StandardApiReasoning::new()?.install(&knowledge, &mut rules)?;
///
/// let receipt = ingest_api_visibility_observation(
///     observation,
///     &resource,
///     &knowledge,
///     &rules,
/// )?;
/// assert_eq!(receipt.commit().resource_scope(), &resource);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn ingest_api_visibility_observation(
    observation: ApiVisibilityObservation,
    expected_resource: &EntityId,
    knowledge: &KnowledgeBase,
    rules: &RuleEngine,
) -> Result<ApiObservationReceipt, ApiObservationError> {
    if observation.resource_scope() != expected_resource {
        return Err(ApiObservationError::ResourceMismatch {
            expected: expected_resource.clone(),
            actual: observation.resource_scope().clone(),
        });
    }
    validate_observation_bounds(observation.evidence())?;

    let comparison_subject = observation.evidence().subject().clone();
    let resource_scope = observation.resource_scope().clone();
    let evidence_id = observation.evidence().id().clone();
    let relation_id = observation.scope_relation().id().clone();
    let (evidence, relation) = observation.into_parts();
    let (evidence_write, relation_write) =
        knowledge.insert_evidence_with_relation(evidence, relation)?;
    let commit = ApiObservationCommitReceipt {
        comparison_subject,
        resource_scope,
        evidence_id,
        relation_id,
        evidence_write,
        relation_write,
    };

    rules
        .apply(knowledge, commit.comparison_subject())
        .map(|applications| ApiObservationReceipt {
            commit: commit.clone(),
            applications,
        })
        .map_err(|source| ApiObservationError::ReasoningAfterCommit {
            commit: Box::new(commit),
            source,
        })
}

/// Bounded cursor for one resource-scoped API visibility review page.
///
/// The scan limit counts incoming relations inspected, including malformed or
/// unrelated relations that the projection rejects. This prevents a resource
/// with many noncanonical edges from forcing an unbounded clone or scan.
///
/// Relation cursors are opaque continuation capabilities, not authenticated
/// pagination tokens. A cursor can identify the last relation inspected even
/// when that relation was omitted from the review page. Hosts must authorize
/// access to the resource before accepting a query, use non-secret relation
/// identifiers, scope a cursor to the same resource, and avoid logging it.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityReviewQuery {
    after_relation_id: Option<RelationId>,
    scan_limit: u16,
}

impl fmt::Debug for ApiVisibilityReviewQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityReviewQuery")
            .field(
                "after_relation_id",
                &self.after_relation_id.as_ref().map(|_| "<redacted>"),
            )
            .field("scan_limit", &self.scan_limit)
            .finish()
    }
}

impl ApiVisibilityReviewQuery {
    /// Creates a query with a positive scan limit under the compiled ceiling.
    pub fn new(scan_limit: u16) -> Result<Self, ApiObservationError> {
        if scan_limit == 0 {
            return Err(ApiObservationError::ZeroReviewScanLimit);
        }
        if scan_limit > HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT {
            return Err(ApiObservationError::ReviewScanLimitExceeded {
                actual: scan_limit,
                maximum: HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT,
            });
        }
        Ok(Self {
            after_relation_id: None,
            scan_limit,
        })
    }

    /// Starts after one previously scanned opaque, non-secret relation cursor.
    ///
    /// The host must reuse this cursor only for the resource and authorization
    /// context from which it was returned. Reusing it with another resource is
    /// not rejected, but has no defined traversal meaning.
    pub fn after_relation_id(
        mut self,
        relation_id: RelationId,
    ) -> Result<Self, ApiObservationError> {
        if relation_id.as_str().len() > MAX_KNOWLEDGE_RELATION_ID_BYTES {
            return Err(ApiObservationError::ReviewCursorTooLong {
                actual: relation_id.as_str().len(),
                maximum: MAX_KNOWLEDGE_RELATION_ID_BYTES,
            });
        }
        self.after_relation_id = Some(relation_id);
        Ok(self)
    }

    /// Returns the exclusive opaque relation cursor, when this is a later page.
    pub fn after(&self) -> Option<&RelationId> {
        self.after_relation_id.as_ref()
    }

    /// Returns the maximum incoming relations inspected by this page.
    pub const fn scan_limit(&self) -> u16 {
        self.scan_limit
    }
}

impl Default for ApiVisibilityReviewQuery {
    fn default() -> Self {
        Self {
            after_relation_id: None,
            scan_limit: DEFAULT_API_VISIBILITY_REVIEW_SCAN_LIMIT,
        }
    }
}

impl<'de> Deserialize<'de> for ApiVisibilityReviewQuery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireQuery {
            after_relation_id: Option<RelationId>,
            scan_limit: u16,
        }

        let wire = WireQuery::deserialize(deserializer)?;
        let mut query = Self::new(wire.scan_limit).map_err(serde::de::Error::custom)?;
        if let Some(relation_id) = wire.after_relation_id {
            query = query
                .after_relation_id(relation_id)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(query)
    }
}

/// Opaque v2 continuation token bound to one resource and relation position.
///
/// The token contains a versioned, domain-separated resource digest and the
/// last scanned relation ID encoded as lowercase hexadecimal bytes. It never
/// embeds the clear-text resource identifier. The digest is pseudonymous, not
/// confidential: low-entropy resource IDs remain susceptible to dictionary
/// attacks. The token is deterministic but is not authenticated or encrypted;
/// a transport may sign or MAC its serialized form before exposing it outside
/// a trusted boundary.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVisibilityReviewCursor {
    encoded: String,
    resource_digest: [u8; 32],
    after_relation_id: RelationId,
}

impl ApiVisibilityReviewCursor {
    /// Creates a canonical v2 cursor for one resource and relation position.
    pub fn new(
        resource_scope: &EntityId,
        after_relation_id: RelationId,
    ) -> Result<Self, ApiObservationError> {
        let actual = after_relation_id.as_str().len();
        if actual > MAX_KNOWLEDGE_RELATION_ID_BYTES {
            return Err(ApiObservationError::ReviewCursorTooLong {
                actual,
                maximum: MAX_KNOWLEDGE_RELATION_ID_BYTES,
            });
        }
        let resource_digest = review_cursor_resource_digest(resource_scope);
        let encoded = format!(
            "{API_VISIBILITY_REVIEW_CURSOR_PREFIX}{}:{}",
            encode_cursor_hex(&resource_digest),
            encode_cursor_hex(after_relation_id.as_str().as_bytes())
        );
        debug_assert!(encoded.len() <= MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES);
        Ok(Self {
            encoded,
            resource_digest,
            after_relation_id,
        })
    }

    /// Parses and validates one canonical serialized v2 cursor.
    pub fn parse(encoded: impl Into<String>) -> Result<Self, ApiObservationError> {
        let encoded = encoded.into();
        if encoded.len() > MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES {
            return Err(ApiObservationError::ResourceBoundReviewCursorTooLong {
                actual: encoded.len(),
                maximum: MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES,
            });
        }
        let Some(payload) = encoded.strip_prefix(API_VISIBILITY_REVIEW_CURSOR_PREFIX) else {
            if encoded.starts_with("venom-api-review-v") {
                return Err(ApiObservationError::UnsupportedResourceBoundReviewCursorVersion);
            }
            return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "cursor prefix is malformed",
            });
        };
        let Some((resource_digest, relation_id)) = payload.split_once(':') else {
            return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "cursor payload is incomplete",
            });
        };
        if resource_digest.len() != API_VISIBILITY_REVIEW_RESOURCE_DIGEST_HEX_BYTES {
            return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "resource digest must contain 64 lowercase hexadecimal characters",
            });
        }
        let resource_digest: [u8; 32] =
            decode_cursor_hex(resource_digest)?
                .try_into()
                .map_err(|_| ApiObservationError::InvalidResourceBoundReviewCursor {
                    reason: "resource digest must contain exactly 32 bytes",
                })?;
        let relation_id = decode_cursor_hex(relation_id)?;
        if relation_id.len() > MAX_KNOWLEDGE_RELATION_ID_BYTES {
            return Err(ApiObservationError::ReviewCursorTooLong {
                actual: relation_id.len(),
                maximum: MAX_KNOWLEDGE_RELATION_ID_BYTES,
            });
        }
        let relation_id = String::from_utf8(relation_id).map_err(|_| {
            ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "relation identifier is not valid UTF-8",
            }
        })?;
        let after_relation_id = RelationId::parse(relation_id).map_err(|_| {
            ApiObservationError::InvalidResourceBoundReviewCursor {
                reason: "relation identifier is empty",
            }
        })?;
        Ok(Self {
            encoded,
            resource_digest,
            after_relation_id,
        })
    }

    /// Returns the canonical transport representation.
    ///
    /// Callers should avoid logging this value and may wrap it in an
    /// authenticated transport token before returning it to an untrusted peer.
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Returns this token's stable wire version.
    pub const fn version(&self) -> u8 {
        2
    }

    fn matches_resource(&self, resource_scope: &EntityId) -> bool {
        self.resource_digest == review_cursor_resource_digest(resource_scope)
    }

    fn after_relation_id(&self) -> &RelationId {
        &self.after_relation_id
    }
}

impl fmt::Debug for ApiVisibilityReviewCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiVisibilityReviewCursor(<redacted>)")
    }
}

impl fmt::Display for ApiVisibilityReviewCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for ApiVisibilityReviewCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encoded)
    }
}

impl<'de> Deserialize<'de> for ApiVisibilityReviewCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CursorVisitor;

        impl Visitor<'_> for CursorVisitor {
            type Value = ApiVisibilityReviewCursor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded resource-bound API visibility review cursor")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ApiVisibilityReviewCursor::parse(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ApiVisibilityReviewCursor::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(CursorVisitor)
    }
}

/// Canonical paired observation and its reviewable boundary hypotheses.
///
/// An equivalent comparison remains visible with an empty hypothesis list. A
/// difference can contain one canonical-shaped boundary hypothesis for that
/// isolated comparison subject. The projection validates the standard rule ID
/// and semantic fields, but does not attest which rule installation produced
/// the record. Surface and response-format hypotheses are intentionally
/// excluded from this resource-scoped read model.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityReview {
    resource_scope: EntityId,
    comparison_subject: EntityId,
    relation_id: RelationId,
    evidence: Evidence,
    boundary_hypotheses: Vec<Hypothesis>,
}

/// Deterministic handling state for one canonical API visibility review.
///
/// This is a review disposition, not a vulnerability verdict and not a
/// [`crate::DecisionLoopCommand`]. A difference reaches [`Self::AwaitHumanReview`]
/// only when the standard reasoning profile produced the exact weak, supported,
/// evidence-bound boundary hypothesis. Missing reasoning remains explicitly
/// unresolved instead of being promoted to a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApiVisibilityReviewDisposition {
    /// The canonical comparison evidence described equivalent views.
    NoDifferenceObserved,
    /// A difference exists but no canonical review hypothesis was materialized.
    UnresolvedDifference,
    /// A canonical weak boundary hypothesis requires an authorized human review.
    AwaitHumanReview,
}

impl fmt::Debug for ApiVisibilityReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityReview")
            .field("resource_scope", &"<redacted>")
            .field("comparison_subject", &"<redacted>")
            .field("relation_id", &"<redacted>")
            .field("evidence", &"<redacted>")
            .field("boundary_hypothesis_count", &self.boundary_hypotheses.len())
            .finish()
    }
}

impl ApiVisibilityReview {
    /// Returns the resource selected by the host's pairing contract.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns the isolated comparison subject.
    pub fn comparison_subject(&self) -> &EntityId {
        &self.comparison_subject
    }

    /// Returns the resource-scope relation identity.
    pub fn relation_id(&self) -> &RelationId {
        &self.relation_id
    }

    /// Returns the structurally canonical paired-comparison evidence.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Returns only canonical-shaped API visibility-boundary hypotheses.
    pub fn boundary_hypotheses(&self) -> &[Hypothesis] {
        &self.boundary_hypotheses
    }

    /// Classifies this read model without turning a difference into a finding.
    pub fn disposition(&self) -> ApiVisibilityReviewDisposition {
        if expected_boundary_rule(&self.evidence).is_none() {
            ApiVisibilityReviewDisposition::NoDifferenceObserved
        } else if self.boundary_hypotheses.len() == 1 {
            ApiVisibilityReviewDisposition::AwaitHumanReview
        } else {
            ApiVisibilityReviewDisposition::UnresolvedDifference
        }
    }
}

/// One bounded page of canonical reviews for a logical resource.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiVisibilityReviewPage {
    resource_scope: EntityId,
    reviews: Vec<ApiVisibilityReview>,
    scanned_relations: u16,
    next_after_relation_id: Option<RelationId>,
}

impl fmt::Debug for ApiVisibilityReviewPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiVisibilityReviewPage")
            .field("resource_scope", &"<redacted>")
            .field("reviews", &self.reviews)
            .field("scanned_relations", &self.scanned_relations)
            .field(
                "next_after_relation_id",
                &self.next_after_relation_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ApiVisibilityReviewPage {
    /// Returns the resource whose incoming relations were scanned.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns canonical reviews found inside this bounded relation window.
    pub fn reviews(&self) -> &[ApiVisibilityReview] {
        &self.reviews
    }

    /// Returns the number of incoming relations consumed from the scan budget.
    pub const fn scanned_relations(&self) -> u16 {
        self.scanned_relations
    }

    /// Returns the exclusive opaque cursor for the next page when more relations exist.
    ///
    /// This may identify an inspected relation that was structurally rejected
    /// and therefore absent from [`Self::reviews`]. Treat it as a non-secret,
    /// capability-scoped continuation value rather than domain data.
    pub fn next_after_relation_id(&self) -> Option<&RelationId> {
        self.next_after_relation_id.as_ref()
    }

    /// Derives the resource-bound v2 continuation token for the next page.
    ///
    /// The returned token is deterministic and redacted from `Debug` and
    /// `Display`, but is not signed. A transport may authenticate its serialized
    /// form before exposing it outside a trusted host boundary.
    pub fn next_cursor(&self) -> Result<Option<ApiVisibilityReviewCursor>, ApiObservationError> {
        self.next_after_relation_id
            .as_ref()
            .map(|relation_id| {
                ApiVisibilityReviewCursor::new(&self.resource_scope, relation_id.clone())
            })
            .transpose()
    }

    /// Takes the canonical reviews without cloning them.
    pub fn into_reviews(self) -> Vec<ApiVisibilityReview> {
        self.reviews
    }
}

/// Projects one bounded review page using a resource-bound v2 cursor.
///
/// A cursor is checked against the caller-authorized resource before the
/// knowledge store is scanned. The legacy [`ApiVisibilityReviewQuery`] and
/// [`api_visibility_reviews_for_resource`] contracts remain available for
/// trusted in-process continuation, while this entry point prevents accidental
/// cross-resource cursor reuse. This cursor is deterministic, not authenticated;
/// transports may sign or MAC its serialized representation.
pub fn api_visibility_reviews_for_resource_v2(
    knowledge: &KnowledgeBase,
    resource_scope: &EntityId,
    cursor: Option<&ApiVisibilityReviewCursor>,
    scan_limit: u16,
) -> Result<ApiVisibilityReviewPage, ApiObservationError> {
    let mut query = ApiVisibilityReviewQuery::new(scan_limit)?;
    if let Some(cursor) = cursor {
        if !cursor.matches_resource(resource_scope) {
            return Err(ApiObservationError::ResourceBoundReviewCursorMismatch);
        }
        query = query.after_relation_id(cursor.after_relation_id().clone())?;
    }
    Ok(api_visibility_reviews_for_resource(
        knowledge,
        resource_scope,
        &query,
    ))
}

/// Projects canonical API visibility comparisons associated with one resource.
///
/// The query clones at most its explicit relation limit; whether another page
/// exists is checked against the borrowed relation index without cloning the
/// look-ahead record. Referenced evidence and hypotheses are also inspected
/// while borrowed and cloned only after their variable review fields satisfy
/// compiled byte ceilings. Results are ordered by stable relation identity.
/// Structurally unrelated or forged-looking incoming relations consume scan
/// budget but are omitted. These checks are a read-model hygiene boundary, not
/// cryptographic attestation.
///
/// Pagination is not a database snapshot. Concurrent inserts sort according to
/// their stable relation IDs; a new ID at or before an already consumed cursor
/// is not returned by later pages. Hosts that require a frozen export must
/// provide an external snapshot or quiesce writes for that resource.
pub fn api_visibility_reviews_for_resource(
    knowledge: &KnowledgeBase,
    resource_scope: &EntityId,
    query: &ApiVisibilityReviewQuery,
) -> ApiVisibilityReviewPage {
    let scan_limit = usize::from(query.scan_limit());
    let (relations, has_more) =
        knowledge.relations_to_page_with_more(resource_scope, query.after(), scan_limit);
    let scanned_relations =
        u16::try_from(relations.len()).expect("validated review scan limits always fit in u16");
    let next_after_relation_id = has_more
        .then(|| relations.last().map(|relation| relation.id().clone()))
        .flatten();

    let mut reviews = Vec::new();
    for relation in relations {
        if let Some(review) = project_api_visibility_review(knowledge, resource_scope, &relation) {
            reviews.push(review);
        }
    }
    ApiVisibilityReviewPage {
        resource_scope: resource_scope.clone(),
        reviews,
        scanned_relations,
        next_after_relation_id,
    }
}

#[cfg(feature = "scanning")]
pub(crate) fn api_visibility_review_for_commit(
    knowledge: &KnowledgeBase,
    commit: &ApiObservationCommitReceipt,
) -> Option<ApiVisibilityReview> {
    let relation = knowledge.relation(commit.relation_id())?;
    project_api_visibility_review(knowledge, commit.resource_scope(), &relation).filter(|review| {
        review.comparison_subject() == commit.comparison_subject()
            && review.evidence().id() == commit.evidence_id()
    })
}

fn project_api_visibility_review(
    knowledge: &KnowledgeBase,
    resource_scope: &EntityId,
    relation: &KnowledgeRelation,
) -> Option<ApiVisibilityReview> {
    if !matches!(relation.kind(), RelationKind::Custom(kind) if kind == API_VISIBILITY_RELATION)
        || relation.to() != resource_scope
        || relation.evidence_ids().len() != 1
    {
        return None;
    }
    let evidence_id = relation.evidence_ids().iter().next()?;
    let evidence = knowledge
        .inspect_evidence(evidence_id, |evidence| {
            (is_canonical_comparison(evidence, relation) && is_bounded_review_evidence(evidence))
                .then(|| evidence.clone())
        })
        .flatten()?;
    let boundary_hypotheses = canonical_boundary_hypothesis(knowledge, &evidence)
        .into_iter()
        .collect();
    Some(ApiVisibilityReview {
        resource_scope: resource_scope.clone(),
        comparison_subject: evidence.subject().clone(),
        relation_id: relation.id().clone(),
        evidence,
        boundary_hypotheses,
    })
}

fn review_cursor_resource_digest(resource_scope: &EntityId) -> [u8; 32] {
    let bytes = resource_scope.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(API_VISIBILITY_REVIEW_CURSOR_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_cursor_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_cursor_hex(value: &str) -> Result<Vec<u8>, ApiObservationError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(ApiObservationError::InvalidResourceBoundReviewCursor {
            reason: "hexadecimal payload must be non-empty and byte-aligned",
        });
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = decode_cursor_hex_nibble(pair[0])?;
        let low = decode_cursor_hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn decode_cursor_hex_nibble(value: u8) -> Result<u8, ApiObservationError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ApiObservationError::InvalidResourceBoundReviewCursor {
            reason: "cursor payload must use lowercase hexadecimal",
        }),
    }
}

fn validate_observation_bounds(evidence: &Evidence) -> Result<(), ApiObservationError> {
    let actual = evidence.source().component().len();
    if actual > MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES {
        return Err(ApiObservationError::ObservationLimitExceeded {
            field: "source.component",
            actual,
            maximum: MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES,
        });
    }
    Ok(())
}

fn is_bounded_review_evidence(evidence: &Evidence) -> bool {
    evidence.source().component().len() <= MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES
}

fn is_canonical_comparison(evidence: &Evidence, relation: &venom_core::KnowledgeRelation) -> bool {
    let Some(digest) = evidence
        .subject()
        .as_str()
        .strip_prefix(COMPARISON_SUBJECT_PREFIX)
    else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && evidence.id().as_str() == format!("{COMPARISON_EVIDENCE_PREFIX}{digest}")
        && relation.id().as_str() == format!("{COMPARISON_RELATION_PREFIX}{digest}")
        && relation.from() == evidence.subject()
        && relation.evidence_ids().len() == 1
        && relation.evidence_ids().contains(evidence.id())
        && relation.confidence() == evidence.reliability()
        && evidence.reliability() != ConfidenceScore::NONE
        && matches!(evidence.kind(), EvidenceKind::Custom(kind) if kind == API_VISIBILITY_EVIDENCE_KIND)
        && evidence.source().method() == API_VISIBILITY_SOURCE_METHOD
        && evidence.source().correlation_id() == Some(evidence.subject().as_str())
        && is_visibility_predicate(evidence.predicate())
        && is_visibility_dimension(evidence.value())
}

fn is_visibility_predicate(predicate: &KnowledgePredicate) -> bool {
    [
        ApiEvidencePredicate::JSON_UI_API_DIFFERENCE,
        ApiEvidencePredicate::JSON_UI_API_EQUIVALENT,
        ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_DIFFERENCE,
        ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_EQUIVALENT,
        ApiEvidencePredicate::GRAPHQL_UI_API_DIFFERENCE,
        ApiEvidencePredicate::GRAPHQL_UI_API_EQUIVALENT,
        ApiEvidencePredicate::GRAPHQL_AUTHORIZATION_CONTEXT_DIFFERENCE,
        ApiEvidencePredicate::GRAPHQL_AUTHORIZATION_CONTEXT_EQUIVALENT,
    ]
    .into_iter()
    .any(|descriptor| descriptor.into_knowledge() == *predicate)
}

fn is_visibility_dimension(value: &EvidenceValue) -> bool {
    ApiVisibilityDimension::all()
        .into_iter()
        .any(|dimension| EvidenceValue::from(dimension) == *value)
}

fn expected_boundary_rule(
    evidence: &Evidence,
) -> Option<(ApiVisibilityBoundaryKind, &'static str)> {
    match evidence.predicate() {
        predicate
            if predicate == &ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge()
                || predicate
                    == &ApiEvidencePredicate::GRAPHQL_UI_API_DIFFERENCE.into_knowledge() =>
        {
            Some((ApiVisibilityBoundaryKind::UiApi, UI_API_BOUNDARY_RULE))
        },
        predicate
            if predicate
                == &ApiEvidencePredicate::JSON_AUTHORIZATION_CONTEXT_DIFFERENCE
                    .into_knowledge()
                || predicate
                    == &ApiEvidencePredicate::GRAPHQL_AUTHORIZATION_CONTEXT_DIFFERENCE
                        .into_knowledge() =>
        {
            Some((
                ApiVisibilityBoundaryKind::AuthorizationContext,
                AUTHORIZATION_BOUNDARY_RULE,
            ))
        },
        _ => None,
    }
}

fn canonical_boundary_hypothesis(
    knowledge: &KnowledgeBase,
    evidence: &Evidence,
) -> Option<Hypothesis> {
    let (_, rule_id) = expected_boundary_rule(evidence)?;
    let hypothesis_id = hypothesis_id_for_rule(rule_id, evidence.subject());
    knowledge
        .inspect_hypothesis(&hypothesis_id, |hypothesis| {
            (is_canonical_boundary_hypothesis(hypothesis, evidence)
                && is_bounded_boundary_hypothesis(hypothesis))
            .then(|| hypothesis.clone())
        })
        .flatten()
}

fn is_bounded_boundary_hypothesis(hypothesis: &Hypothesis) -> bool {
    hypothesis.belief().evidence().iter().all(|observation| {
        observation.rationale().len() <= MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES
    }) && hypothesis
        .belief()
        .updates()
        .iter()
        .all(|update| update.rationale().len() <= MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES)
}

fn is_canonical_boundary_hypothesis(hypothesis: &Hypothesis, evidence: &Evidence) -> bool {
    let Some((boundary, rule_id)) = expected_boundary_rule(evidence) else {
        return false;
    };
    if hypothesis.subject() != evidence.subject()
        || hypothesis.predicate() != &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()
        || hypothesis.strength() != HypothesisStrength::Weak
        || hypothesis.state() != HypothesisState::Supported
        || hypothesis.belief().evidence().len() != 1
        || hypothesis.belief().evidence()[0].evidence_id() != evidence.id()
    {
        return false;
    }

    hypothesis.value() == &EvidenceValue::from(boundary)
        && hypothesis.id() == hypothesis_id_for_rule(rule_id, evidence.subject())
}

#[cfg(test)]
mod tests {
    use venom_core::{
        ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityPairKind, ApiVisibilityResult,
        BayesianEvidence, EvidenceSource, HypothesisState, HypothesisStrength, Probability,
    };

    use super::*;
    use crate::{
        api_reasoning::StandardApiReasoning,
        rules::{
            EvidenceCalibration, EvidenceSelector, Expression, HypothesisConclusion,
            KnowledgeLayer, ReasoningRule,
        },
    };

    fn resource() -> EntityId {
        EntityId::new("resource:account-42").unwrap()
    }

    fn comparison(
        id: &str,
        result: ApiVisibilityResult,
        pair: ApiVisibilityPairKind,
    ) -> ApiVisibilityObservation {
        comparison_with_source(id, result, pair, "host.api-comparator")
    }

    fn comparison_with_source(
        id: &str,
        result: ApiVisibilityResult,
        pair: ApiVisibilityPairKind,
        source_component: impl Into<String>,
    ) -> ApiVisibilityObservation {
        ApiVisibilityComparison::new(
            id,
            ApiSurfaceKind::JsonHttp,
            pair,
            result,
            ApiVisibilityDimension::Fields,
            "anonymous-view",
            "member-view",
            resource().as_str(),
        )
        .unwrap()
        .with_observed_at_ms(1_000)
        .to_observation(source_component, ConfidenceScore::MAX)
        .unwrap()
    }

    fn installed() -> (KnowledgeBase, RuleEngine) {
        let knowledge = KnowledgeBase::new();
        let mut rules = RuleEngine::new();
        StandardApiReasoning::new()
            .unwrap()
            .install(&knowledge, &mut rules)
            .unwrap();
        (knowledge, rules)
    }

    fn insert_forged_boundary(
        knowledge: &KnowledgeBase,
        evidence: &Evidence,
        rule_id: &str,
        boundary: ApiVisibilityBoundaryKind,
    ) {
        let mut hypothesis = Hypothesis::with_id(
            hypothesis_id_for_rule(rule_id, evidence.subject()),
            evidence.subject().clone(),
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge(),
            EvidenceValue::from(boundary),
            Probability::from_percent(10).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence.id().clone(),
                    Probability::from_percent(98).unwrap(),
                    Probability::from_percent(2).unwrap(),
                    "deliberately forged boundary",
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Weak);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
    }

    #[test]
    fn different_comparison_commits_and_projects_only_the_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "different",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        assert_eq!(receipt.commit().evidence_write(), KnowledgeWrite::Inserted);
        assert_eq!(receipt.commit().relation_write(), KnowledgeWrite::Inserted);
        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let reviews = page.reviews();
        assert_eq!(reviews.len(), 1);
        assert_eq!(
            reviews[0].disposition(),
            ApiVisibilityReviewDisposition::AwaitHumanReview
        );
        assert_eq!(reviews[0].boundary_hypotheses().len(), 1);
        let boundary = &reviews[0].boundary_hypotheses()[0];
        assert_eq!(
            boundary.value(),
            &EvidenceValue::from(ApiVisibilityBoundaryKind::AuthorizationContext)
        );
        assert_eq!(boundary.state(), HypothesisState::Supported);
        assert!(knowledge
            .hypotheses_for_subject(receipt.commit().comparison_subject())
            .iter()
            .any(|hypothesis| hypothesis.predicate()
                == &ApiKnowledgePredicate::SURFACE_KIND.into_knowledge()));
    }

    #[test]
    fn equivalent_comparison_has_a_surface_but_no_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "equivalent",
                ApiVisibilityResult::Equivalent,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        let hypotheses = knowledge.hypotheses_for_subject(receipt.commit().comparison_subject());
        assert!(hypotheses.iter().any(|hypothesis| hypothesis.predicate()
            == &ApiKnowledgePredicate::SURFACE_KIND.into_knowledge()));
        assert!(!hypotheses.iter().any(|hypothesis| hypothesis.predicate()
            == &ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge()));
        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let reviews = page.reviews();
        assert_eq!(reviews.len(), 1);
        assert_eq!(
            reviews[0].disposition(),
            ApiVisibilityReviewDisposition::NoDifferenceObserved
        );
        assert!(reviews[0].boundary_hypotheses().is_empty());
    }

    #[test]
    fn difference_without_reasoning_remains_explicitly_unresolved() {
        let knowledge = KnowledgeBase::new();
        let rules = RuleEngine::new();
        ingest_api_visibility_observation(
            comparison(
                "difference-without-rules",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.reviews().len(), 1);
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
        assert_eq!(
            page.reviews()[0].disposition(),
            ApiVisibilityReviewDisposition::UnresolvedDifference
        );
    }

    #[test]
    fn equivalent_evidence_cannot_be_projected_as_a_forged_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "equivalent-forgery",
                ApiVisibilityResult::Equivalent,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        insert_forged_boundary(
            &knowledge,
            &evidence,
            UI_API_BOUNDARY_RULE,
            ApiVisibilityBoundaryKind::UiApi,
        );

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.reviews().len(), 1);
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
    }

    #[test]
    fn authorization_evidence_ignores_a_forged_ui_boundary() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "pair-forgery",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        insert_forged_boundary(
            &knowledge,
            &evidence,
            UI_API_BOUNDARY_RULE,
            ApiVisibilityBoundaryKind::UiApi,
        );

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let boundaries = page.reviews()[0].boundary_hypotheses();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(
            boundaries[0].value(),
            &EvidenceValue::from(ApiVisibilityBoundaryKind::AuthorizationContext)
        );
    }

    #[test]
    fn nonweak_boundary_is_not_promoted_to_human_review() {
        let knowledge = KnowledgeBase::new();
        let rules = RuleEngine::new();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "strong-boundary-forgery",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        insert_forged_boundary(
            &knowledge,
            &evidence,
            AUTHORIZATION_BOUNDARY_RULE,
            ApiVisibilityBoundaryKind::AuthorizationContext,
        );
        let mut forged = knowledge
            .hypotheses_for_subject(evidence.subject())
            .into_iter()
            .next()
            .unwrap();
        forged.set_strength(HypothesisStrength::Strong);
        knowledge.upsert_hypothesis(forged).unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
        assert_eq!(
            page.reviews()[0].disposition(),
            ApiVisibilityReviewDisposition::UnresolvedDifference
        );
    }

    #[test]
    fn exact_replay_is_idempotent_across_storage_and_reasoning() {
        let (knowledge, rules) = installed();
        let observation = comparison(
            "replay",
            ApiVisibilityResult::Different,
            ApiVisibilityPairKind::UiApi,
        );
        ingest_api_visibility_observation(observation.clone(), &resource(), &knowledge, &rules)
            .unwrap();
        let replay =
            ingest_api_visibility_observation(observation, &resource(), &knowledge, &rules)
                .unwrap();

        assert_eq!(replay.commit().evidence_write(), KnowledgeWrite::Unchanged);
        assert_eq!(replay.commit().relation_write(), KnowledgeWrite::Unchanged);
        assert!(replay
            .applications()
            .iter()
            .filter_map(RuleApplication::write)
            .all(|write| write == KnowledgeWrite::Unchanged));
        assert_eq!(
            api_visibility_reviews_for_resource(
                &knowledge,
                &resource(),
                &ApiVisibilityReviewQuery::default(),
            )
            .reviews()
            .len(),
            1
        );
    }

    #[test]
    fn observation_and_review_debug_output_redacts_opaque_identifiers() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "debug-redaction",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let receipt_debug = format!("{receipt:?}");
        for opaque in [
            receipt.commit().comparison_subject().as_str(),
            receipt.commit().resource_scope().as_str(),
            receipt.commit().evidence_id().as_str(),
            receipt.commit().relation_id().as_str(),
        ] {
            assert!(!receipt_debug.contains(opaque));
        }
        assert!(receipt_debug.contains("application_count"));
        assert!(receipt_debug.contains("<redacted>"));

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        let review = &page.reviews()[0];
        let review_debug = format!("{review:?}");
        let page_debug = format!("{page:?}");
        for debug in [&review_debug, &page_debug] {
            for opaque in [
                review.resource_scope().as_str(),
                review.comparison_subject().as_str(),
                review.relation_id().as_str(),
                review.evidence().id().as_str(),
            ] {
                assert!(!debug.contains(opaque));
            }
            assert!(debug.contains("<redacted>"));
        }
    }

    #[test]
    fn resource_mismatch_fails_before_any_write() {
        let (knowledge, rules) = installed();
        let expected = EntityId::new("resource:another-account").unwrap();
        let error = ingest_api_visibility_observation(
            comparison(
                "wrong-resource",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &expected,
            &knowledge,
            &rules,
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            ApiObservationError::ResourceMismatch { .. }
        ));
        let display = error.to_string();
        let debug = format!("{error:?}");
        for opaque in [expected.as_str(), "resource:account-42"] {
            assert!(!display.contains(opaque));
            assert!(!debug.contains(opaque));
        }
        assert_eq!(
            display,
            "API visibility observation resource does not match expected resource"
        );
        assert!(debug.contains("<redacted>"));
        assert!(error.committed_observation().is_none());
        let stats = knowledge.stats();
        assert_eq!(stats.evidence, 0);
        assert_eq!(stats.relations, 0);
        assert_eq!(stats.hypotheses, 0);
    }

    #[test]
    fn post_commit_reasoning_error_carries_the_commit_receipt() {
        let knowledge = KnowledgeBase::new();
        let mut rules = RuleEngine::new();
        let comparison_predicate = ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge();
        let unrelated = KnowledgePredicate::new("test", "unrelated").unwrap();
        rules
            .register(
                ReasoningRule::new(
                    "000.invalid-calibration",
                    Expression::exists(KnowledgeLayer::Evidence, comparison_predicate),
                    HypothesisConclusion::new(
                        KnowledgePredicate::new("test", "result").unwrap(),
                        EvidenceValue::Boolean(true),
                        Probability::from_percent(10).unwrap(),
                        venom_core::HypothesisStrength::Weak,
                        HypothesisState::Supported,
                        vec![EvidenceCalibration::new(
                            EvidenceSelector::exists(unrelated),
                            Probability::from_percent(90).unwrap(),
                            Probability::from_percent(10).unwrap(),
                            "deliberately cannot bind the matched comparison",
                        )
                        .unwrap()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let error = ingest_api_visibility_observation(
            comparison(
                "post-commit-error",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap_err();

        assert!(matches!(
            error.reasoning_source(),
            Some(RuleEngineError::MissingCalibratedEvidence { .. })
        ));
        let commit = error.committed_observation().unwrap();
        assert_eq!(commit.evidence_write(), KnowledgeWrite::Inserted);
        assert_eq!(commit.relation_write(), KnowledgeWrite::Inserted);
        assert!(knowledge.evidence(commit.evidence_id()).is_some());
        assert!(knowledge.relation(commit.relation_id()).is_some());
    }

    #[test]
    fn resource_projection_is_stable_and_ignores_noncanonical_relations() {
        let (knowledge, rules) = installed();
        for observation in [
            comparison(
                "second",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::AuthorizationContext,
            ),
            comparison(
                "first",
                ApiVisibilityResult::Equivalent,
                ApiVisibilityPairKind::UiApi,
            ),
        ] {
            ingest_api_visibility_observation(observation, &resource(), &knowledge, &rules)
                .unwrap();
        }

        let unrelated = Evidence::new(
            EntityId::new("not-a-comparison").unwrap(),
            EvidenceKind::Custom(API_VISIBILITY_EVIDENCE_KIND.to_owned()),
            ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge(),
            EvidenceValue::from(ApiVisibilityDimension::Fields),
            EvidenceSource::new("forged", API_VISIBILITY_SOURCE_METHOD).unwrap(),
            ConfidenceScore::MAX,
        );
        let unrelated_id = unrelated.id().clone();
        let unrelated_subject = unrelated.subject().clone();
        knowledge.insert_evidence(unrelated).unwrap();
        knowledge
            .upsert_relation(venom_core::KnowledgeRelation::new(
                unrelated_subject,
                resource(),
                RelationKind::Custom(API_VISIBILITY_RELATION.to_owned()),
                ConfidenceScore::MAX,
                unrelated_id,
            ))
            .unwrap();

        let query = ApiVisibilityReviewQuery::default();
        let first = api_visibility_reviews_for_resource(&knowledge, &resource(), &query);
        let second = api_visibility_reviews_for_resource(&knowledge, &resource(), &query);
        assert_eq!(first, second);
        assert_eq!(first.reviews().len(), 2);
        assert!(first
            .reviews()
            .windows(2)
            .all(|pair| pair[0].relation_id() < pair[1].relation_id()));
        assert!(first.reviews().iter().all(|review| {
            review.evidence().subject() == review.comparison_subject()
                && review.resource_scope() == &resource()
        }));
    }

    #[test]
    fn oversized_observation_provenance_is_rejected_before_commit() {
        let knowledge = KnowledgeBase::new();
        let rules = RuleEngine::new();
        let observation = comparison_with_source(
            "oversized-source",
            ApiVisibilityResult::Different,
            ApiVisibilityPairKind::UiApi,
            "s".repeat(MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES + 1),
        );

        assert!(matches!(
            ingest_api_visibility_observation(observation, &resource(), &knowledge, &rules),
            Err(ApiObservationError::ObservationLimitExceeded {
                field: "source.component",
                ..
            })
        ));
        let stats = knowledge.stats();
        assert_eq!(stats.evidence, 0);
        assert_eq!(stats.relations, 0);
    }

    #[test]
    fn projection_rejects_oversized_records_from_direct_store_writers() {
        let knowledge = KnowledgeBase::new();
        let observation = comparison_with_source(
            "direct-oversized-source",
            ApiVisibilityResult::Different,
            ApiVisibilityPairKind::UiApi,
            "s".repeat(MAX_API_VISIBILITY_SOURCE_COMPONENT_BYTES + 1),
        );
        let (evidence, relation) = observation.into_parts();
        knowledge
            .insert_evidence_with_relation(evidence, relation)
            .unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.scanned_relations(), 1);
        assert!(page.reviews().is_empty());
    }

    #[test]
    fn projection_does_not_clone_an_oversized_boundary_rationale() {
        let (knowledge, rules) = installed();
        let receipt = ingest_api_visibility_observation(
            comparison(
                "oversized-rationale",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();
        let evidence = knowledge.evidence(receipt.commit().evidence_id()).unwrap();
        let mut hypothesis = Hypothesis::with_id(
            hypothesis_id_for_rule(UI_API_BOUNDARY_RULE, evidence.subject()),
            evidence.subject().clone(),
            ApiKnowledgePredicate::VISIBILITY_BOUNDARY.into_knowledge(),
            EvidenceValue::from(ApiVisibilityBoundaryKind::UiApi),
            Probability::from_percent(10).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence.id().clone(),
                    Probability::from_percent(98).unwrap(),
                    Probability::from_percent(2).unwrap(),
                    "r".repeat(MAX_API_VISIBILITY_REVIEW_RATIONALE_BYTES + 1),
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();

        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.reviews().len(), 1);
        assert!(page.reviews()[0].boundary_hypotheses().is_empty());
    }

    #[test]
    fn review_query_is_strict_and_enforces_the_compiled_ceiling() {
        assert!(matches!(
            ApiVisibilityReviewQuery::new(0),
            Err(ApiObservationError::ZeroReviewScanLimit)
        ));
        assert!(matches!(
            ApiVisibilityReviewQuery::new(HARD_MAX_API_VISIBILITY_REVIEW_SCAN_LIMIT + 1),
            Err(ApiObservationError::ReviewScanLimitExceeded { .. })
        ));
        assert!(
            serde_json::from_value::<ApiVisibilityReviewQuery>(serde_json::json!({
                "scan_limit": 0
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ApiVisibilityReviewQuery>(serde_json::json!({
                "scan_limit": 1,
                "unexpected": true
            }))
            .is_err()
        );
        let oversized_cursor =
            RelationId::parse("r".repeat(MAX_KNOWLEDGE_RELATION_ID_BYTES + 1)).unwrap();
        assert!(matches!(
            ApiVisibilityReviewQuery::new(1)
                .unwrap()
                .after_relation_id(oversized_cursor.clone()),
            Err(ApiObservationError::ReviewCursorTooLong { .. })
        ));
        assert!(
            serde_json::from_value::<ApiVisibilityReviewQuery>(serde_json::json!({
                "after_relation_id": oversized_cursor,
                "scan_limit": 1
            }))
            .is_err()
        );

        let cursor = RelationId::parse("relation:cursor").unwrap();
        let query = ApiVisibilityReviewQuery::new(7)
            .unwrap()
            .after_relation_id(cursor.clone())
            .unwrap();
        let decoded: ApiVisibilityReviewQuery =
            serde_json::from_value(serde_json::to_value(&query).unwrap()).unwrap();
        assert_eq!(decoded, query);
        assert_eq!(decoded.after(), Some(&cursor));
        assert_eq!(decoded.scan_limit(), 7);
        let debug = format!("{decoded:?}");
        assert!(!debug.contains(cursor.as_str()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn resource_bound_cursor_round_trips_and_paginates_same_resource() {
        let (knowledge, rules) = installed();
        for id in ["cursor-page-a", "cursor-page-b", "cursor-page-c"] {
            ingest_api_visibility_observation(
                comparison(
                    id,
                    ApiVisibilityResult::Different,
                    ApiVisibilityPairKind::UiApi,
                ),
                &resource(),
                &knowledge,
                &rules,
            )
            .unwrap();
        }

        let first =
            api_visibility_reviews_for_resource_v2(&knowledge, &resource(), None, 1).unwrap();
        assert_eq!(first.scanned_relations(), 1);
        assert_eq!(first.reviews().len(), 1);
        let cursor = first.next_cursor().unwrap().unwrap();
        let decoded: ApiVisibilityReviewCursor =
            serde_json::from_value(serde_json::to_value(&cursor).unwrap()).unwrap();
        assert_eq!(decoded, cursor);
        assert_eq!(decoded.version(), 2);

        let second =
            api_visibility_reviews_for_resource_v2(&knowledge, &resource(), Some(&decoded), 1)
                .unwrap();
        assert_eq!(second.scanned_relations(), 1);
        assert_eq!(second.reviews().len(), 1);
        assert_ne!(
            first.reviews()[0].relation_id(),
            second.reviews()[0].relation_id()
        );
    }

    #[test]
    fn resource_bound_cursor_rejects_cross_resource_replay_without_leaking_ids() {
        let source = resource();
        let target = EntityId::new("resource:another-sensitive-account").unwrap();
        let relation = RelationId::parse("relation:sensitive-position").unwrap();
        let cursor = ApiVisibilityReviewCursor::new(&source, relation.clone()).unwrap();
        let error = api_visibility_reviews_for_resource_v2(
            &KnowledgeBase::new(),
            &target,
            Some(&cursor),
            1,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ApiObservationError::ResourceBoundReviewCursorMismatch
        ));
        for output in [error.to_string(), format!("{error:?}")] {
            assert!(!output.contains(source.as_str()));
            assert!(!output.contains(target.as_str()));
            assert!(!output.contains(relation.as_str()));
            assert!(!output.contains(cursor.as_str()));
        }
    }

    #[test]
    fn resource_bound_cursor_rejects_malformed_versioned_and_oversized_tokens() {
        assert!(matches!(
            ApiVisibilityReviewCursor::parse("not-a-review-cursor"),
            Err(ApiObservationError::InvalidResourceBoundReviewCursor { .. })
        ));
        assert!(matches!(
            ApiVisibilityReviewCursor::parse("venom-api-review-v3:payload"),
            Err(ApiObservationError::UnsupportedResourceBoundReviewCursorVersion)
        ));
        assert!(matches!(
            ApiVisibilityReviewCursor::parse(
                "x".repeat(MAX_API_VISIBILITY_REVIEW_CURSOR_BYTES + 1)
            ),
            Err(ApiObservationError::ResourceBoundReviewCursorTooLong { .. })
        ));

        let cursor = ApiVisibilityReviewCursor::new(
            &resource(),
            RelationId::parse("relation:cursor").unwrap(),
        )
        .unwrap();
        let mut uppercase = cursor.as_str().to_owned();
        uppercase.pop();
        uppercase.push('A');
        assert!(matches!(
            ApiVisibilityReviewCursor::parse(uppercase),
            Err(ApiObservationError::InvalidResourceBoundReviewCursor { .. })
        ));
        let mut odd = cursor.as_str().to_owned();
        odd.pop();
        assert!(
            serde_json::from_value::<ApiVisibilityReviewCursor>(serde_json::json!(odd)).is_err()
        );
    }

    #[test]
    fn resource_bound_cursor_serialization_is_transparent_and_debug_is_redacted() {
        let resource = resource();
        let relation = RelationId::parse("relation:sensitive-cursor").unwrap();
        let cursor = ApiVisibilityReviewCursor::new(&resource, relation.clone()).unwrap();

        assert_eq!(
            serde_json::to_value(&cursor).unwrap(),
            serde_json::Value::String(cursor.as_str().to_owned())
        );
        assert!(!cursor.as_str().contains(resource.as_str()));
        assert!(!cursor.as_str().contains(relation.as_str()));
        for output in [format!("{cursor:?}"), cursor.to_string()] {
            assert!(output.contains("<redacted>"));
            assert!(!output.contains(cursor.as_str()));
            assert!(!output.contains(resource.as_str()));
            assert!(!output.contains(relation.as_str()));
        }
    }

    #[test]
    fn legacy_review_query_wire_shape_remains_unchanged() {
        let cursor = RelationId::parse("relation:legacy-cursor").unwrap();
        let query = ApiVisibilityReviewQuery::new(7)
            .unwrap()
            .after_relation_id(cursor)
            .unwrap();

        assert_eq!(
            serde_json::to_value(query).unwrap(),
            serde_json::json!({
                "after_relation_id": "relation:legacy-cursor",
                "scan_limit": 7
            })
        );
    }

    #[test]
    fn review_pages_advance_by_the_last_scanned_relation() {
        let (knowledge, rules) = installed();
        for id in ["page-a", "page-b", "page-c"] {
            ingest_api_visibility_observation(
                comparison(
                    id,
                    ApiVisibilityResult::Different,
                    ApiVisibilityPairKind::UiApi,
                ),
                &resource(),
                &knowledge,
                &rules,
            )
            .unwrap();
        }

        let mut query = ApiVisibilityReviewQuery::new(1).unwrap();
        let mut seen = Vec::new();
        loop {
            let page = api_visibility_reviews_for_resource(&knowledge, &resource(), &query);
            assert_eq!(page.scanned_relations(), 1);
            assert_eq!(page.reviews().len(), 1);
            seen.push(page.reviews()[0].relation_id().clone());
            let Some(cursor) = page.next_after_relation_id().cloned() else {
                break;
            };
            query = ApiVisibilityReviewQuery::new(1)
                .unwrap()
                .after_relation_id(cursor)
                .unwrap();
        }

        assert_eq!(seen.len(), 3);
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn rejected_relations_consume_the_page_scan_budget() {
        let (knowledge, rules) = installed();
        let invalid = Evidence::new(
            EntityId::new("invalid-comparison").unwrap(),
            EvidenceKind::Custom(API_VISIBILITY_EVIDENCE_KIND.to_owned()),
            ApiEvidencePredicate::JSON_UI_API_DIFFERENCE.into_knowledge(),
            EvidenceValue::from(ApiVisibilityDimension::Fields),
            EvidenceSource::new("untrusted", API_VISIBILITY_SOURCE_METHOD).unwrap(),
            ConfidenceScore::MAX,
        );
        let invalid_id = invalid.id().clone();
        let invalid_subject = invalid.subject().clone();
        knowledge.insert_evidence(invalid).unwrap();
        knowledge
            .upsert_relation(venom_core::KnowledgeRelation::with_id(
                RelationId::parse("000-invalid-relation").unwrap(),
                invalid_subject,
                resource(),
                RelationKind::Custom(API_VISIBILITY_RELATION.to_owned()),
                ConfidenceScore::MAX,
                invalid_id,
            ))
            .unwrap();
        ingest_api_visibility_observation(
            comparison(
                "valid-after-invalid",
                ApiVisibilityResult::Different,
                ApiVisibilityPairKind::UiApi,
            ),
            &resource(),
            &knowledge,
            &rules,
        )
        .unwrap();

        let first_query = ApiVisibilityReviewQuery::new(1).unwrap();
        let first = api_visibility_reviews_for_resource(&knowledge, &resource(), &first_query);
        assert_eq!(first.scanned_relations(), 1);
        assert!(first.reviews().is_empty());
        let cursor = first.next_after_relation_id().cloned().unwrap();
        assert_eq!(cursor.as_str(), "000-invalid-relation");
        let page_debug = format!("{first:?}");
        assert!(!page_debug.contains(cursor.as_str()));
        assert!(page_debug.contains("<redacted>"));

        let second_query = ApiVisibilityReviewQuery::new(1)
            .unwrap()
            .after_relation_id(cursor)
            .unwrap();
        let second = api_visibility_reviews_for_resource(&knowledge, &resource(), &second_query);
        assert_eq!(second.scanned_relations(), 1);
        assert_eq!(second.reviews().len(), 1);
        assert!(second.next_after_relation_id().is_none());
    }

    #[test]
    fn oversized_relation_is_rejected_before_it_can_reach_review_projection() {
        let knowledge = KnowledgeBase::new();
        let relation = venom_core::KnowledgeRelation::with_id(
            RelationId::parse("r".repeat(crate::knowledge::MAX_KNOWLEDGE_RELATION_ID_BYTES + 1))
                .unwrap(),
            EntityId::new("comparison:oversized-relation").unwrap(),
            resource(),
            RelationKind::Custom(API_VISIBILITY_RELATION.to_owned()),
            ConfidenceScore::MAX,
            EvidenceId::parse("evidence:oversized-relation").unwrap(),
        );

        assert!(matches!(
            knowledge.upsert_relation(relation),
            Err(KnowledgeBaseError::RelationLimitExceeded { field: "id", .. })
        ));
        let page = api_visibility_reviews_for_resource(
            &knowledge,
            &resource(),
            &ApiVisibilityReviewQuery::default(),
        );
        assert_eq!(page.scanned_relations(), 0);
        assert!(page.reviews().is_empty());
        assert!(page.next_after_relation_id().is_none());
    }
}
