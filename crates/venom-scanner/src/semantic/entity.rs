//! Strongly-typed semantic entities extracted from raw scanner evidence.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use venom_core::{EntityId, EvidenceId};

/// Closed set of semantic entity types in the target system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SemanticEntityType {
    /// Network endpoint or API route (e.g. `v1:endpoint:https://example.test/api/v1/user#GET`).
    Endpoint,
    /// Fully qualified domain name or hostname (e.g. `v1:domain:example.test`).
    Domain,
    /// IP address (v4 or v6).
    IpAddress,
    /// Authentication token or credential artifact (JWT, Session Cookie, Bearer token).
    AuthArtifact,
    /// Protocol or application header concept.
    Header,
    /// Identified technology, framework, or runtime component.
    Technology,
    /// Request parameter (query, body, path).
    Parameter,
    /// User identity, role, or permission scope.
    UserRole,
}

/// Structural categorization of authentication artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthArtifactKind {
    /// Generic Bearer token credential.
    BearerToken,
    /// Validated JSON Web Token structure (decoded base64url JSON header and payload).
    Jwt,
    /// API Key credential.
    ApiKey,
    /// Session cookie credential.
    SessionCookie,
    /// Unclassified authentication artifact.
    Unknown,
}

impl AuthArtifactKind {
    /// Returns a stable canonical slug string for artifact kind serialization and fingerprinting.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::BearerToken => "bearer_token",
            Self::Jwt => "jwt",
            Self::ApiKey => "api_key",
            Self::SessionCookie => "session_cookie",
            Self::Unknown => "unknown",
        }
    }
}

/// Errors occurring from invalid or excessive extraction limits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum LimitsError {
    /// Limit value is zero.
    #[error("limit {name} is zero, which is invalid")]
    ZeroLimit { name: &'static str },
    /// Limit value exceeds the hard safety ceiling.
    #[error("limit {name} ({requested}) exceeds maximum hard ceiling ({ceiling})")]
    ExceedsCeiling {
        name: &'static str,
        requested: usize,
        ceiling: usize,
    },
}

/// Safety limits for bounded semantic entity extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticExtractionLimits {
    /// Maximum number of entities extracted from a single evidence batch.
    pub max_entities: usize,
    /// Maximum number of attribute keys per entity.
    pub max_attribute_keys: usize,
    /// Maximum number of values per attribute.
    pub max_values_per_attribute: usize,
    /// Maximum length in bytes for any single attribute value.
    pub max_value_bytes: usize,
    /// Maximum supporting evidence IDs recorded per entity.
    pub max_source_evidence_ids: usize,
    /// Maximum URL length in bytes.
    pub max_url_bytes: usize,
}

impl SemanticExtractionLimits {
    /// Hard ceiling on entity count.
    pub const HARD_MAX_ENTITIES: usize = 10_000;
    /// Hard ceiling on attribute keys per entity.
    pub const HARD_MAX_ATTRIBUTE_KEYS: usize = 200;
    /// Hard ceiling on values per attribute key.
    pub const HARD_MAX_VALUES_PER_ATTRIBUTE: usize = 500;
    /// Hard ceiling on value bytes.
    pub const HARD_MAX_VALUE_BYTES: usize = 65_536;
    /// Hard ceiling on source evidence IDs recorded per entity.
    pub const HARD_MAX_SOURCE_EVIDENCE_IDS: usize = 10_000;
    /// Hard ceiling on URL length in bytes.
    pub const HARD_MAX_URL_BYTES: usize = 8_192;

    /// Validates and constructs new extraction limits bounded by hard ceilings.
    pub fn new(
        max_entities: usize,
        max_attribute_keys: usize,
        max_values_per_attribute: usize,
        max_value_bytes: usize,
        max_source_evidence_ids: usize,
        max_url_bytes: usize,
    ) -> Result<Self, LimitsError> {
        let check = |name: &'static str, val: usize, ceiling: usize| -> Result<(), LimitsError> {
            if val == 0 {
                return Err(LimitsError::ZeroLimit { name });
            }
            if val > ceiling {
                return Err(LimitsError::ExceedsCeiling {
                    name,
                    requested: val,
                    ceiling,
                });
            }
            Ok(())
        };

        check("max_entities", max_entities, Self::HARD_MAX_ENTITIES)?;
        check(
            "max_attribute_keys",
            max_attribute_keys,
            Self::HARD_MAX_ATTRIBUTE_KEYS,
        )?;
        check(
            "max_values_per_attribute",
            max_values_per_attribute,
            Self::HARD_MAX_VALUES_PER_ATTRIBUTE,
        )?;
        check(
            "max_value_bytes",
            max_value_bytes,
            Self::HARD_MAX_VALUE_BYTES,
        )?;
        check(
            "max_source_evidence_ids",
            max_source_evidence_ids,
            Self::HARD_MAX_SOURCE_EVIDENCE_IDS,
        )?;
        check("max_url_bytes", max_url_bytes, Self::HARD_MAX_URL_BYTES)?;

        Ok(Self {
            max_entities,
            max_attribute_keys,
            max_values_per_attribute,
            max_value_bytes,
            max_source_evidence_ids,
            max_url_bytes,
        })
    }
}

impl Default for SemanticExtractionLimits {
    fn default() -> Self {
        Self {
            max_entities: 1000,
            max_attribute_keys: 50,
            max_values_per_attribute: 50,
            max_value_bytes: 4096,
            max_source_evidence_ids: 100,
            max_url_bytes: 2048,
        }
    }
}

/// Explicit extraction receipt detailing extracted entities and truncation counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticExtractionResult {
    /// Extracted semantic entities.
    pub entities: Vec<SemanticEntity>,
    /// Whether any entity, attribute, value, or source ID limit was triggered.
    pub truncated: bool,
    /// Number of dropped entities due to `max_entities` limit.
    pub dropped_entities: usize,
    /// Number of dropped attributes due to attribute limits.
    pub dropped_attributes: usize,
    /// Number of dropped source evidence IDs due to source limits.
    pub dropped_sources: usize,
}

/// A strongly-typed semantic entity derived deterministically from evidence.
///
/// Note: Plane classification is NOT an intrinsic attribute of `SemanticEntity`.
/// Entities are reusable across multiple planes (e.g. AuthArtifact is relevant to
/// both Identity and API planes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticEntity {
    id: EntityId,
    entity_type: SemanticEntityType,
    attributes: BTreeMap<String, BTreeSet<String>>,
    source_evidence_ids: Vec<EvidenceId>,
}

impl SemanticEntity {
    /// Creates a new semantic entity with canonical identity and deterministic attribute merging.
    pub fn new(
        id: EntityId,
        entity_type: SemanticEntityType,
        attributes: BTreeMap<String, BTreeSet<String>>,
        source_evidence_ids: Vec<EvidenceId>,
    ) -> Self {
        let mut source_evidence_ids = source_evidence_ids;
        source_evidence_ids.sort();
        source_evidence_ids.dedup();

        Self {
            id,
            entity_type,
            attributes,
            source_evidence_ids,
        }
    }

    /// Returns the canonical entity identifier.
    pub fn id(&self) -> &EntityId {
        &self.id
    }

    /// Returns the semantic entity type.
    pub const fn entity_type(&self) -> SemanticEntityType {
        self.entity_type
    }

    /// Returns the multi-valued attribute map.
    pub fn attributes(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.attributes
    }

    /// Returns reference to source evidence IDs.
    pub fn source_evidence_ids(&self) -> &[EvidenceId] {
        &self.source_evidence_ids
    }

    /// Destructures entity into ID, type, attributes, and source evidence IDs.
    pub fn into_parts(
        self,
    ) -> (
        EntityId,
        SemanticEntityType,
        BTreeMap<String, BTreeSet<String>>,
        Vec<EvidenceId>,
    ) {
        (
            self.id,
            self.entity_type,
            self.attributes,
            self.source_evidence_ids,
        )
    }
}
