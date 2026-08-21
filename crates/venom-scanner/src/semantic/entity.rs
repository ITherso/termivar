//! Strongly-typed semantic entities extracted from raw scanner evidence.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use venom_core::{EntityId, EvidenceId};

/// Closed set of semantic entity types in the target system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SemanticEntityType {
    /// Network endpoint or API route (e.g. `v1:endpoint:https://example.test/api/v1/user`).
    ///
    /// Endpoint identity is method-agnostic: any observed HTTP method is recorded
    /// as a `method` attribute, never as part of the entity id.
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
    /// Assessment-only hard ceiling for one discovered parameter/control name.
    #[cfg(feature = "scanning")]
    pub(crate) const HARD_MAX_ASSESSMENT_PARAMETER_NAME_BYTES: usize = 256;
    /// Assessment-only hard ceiling for names attached to one reference.
    #[cfg(feature = "scanning")]
    pub(crate) const HARD_MAX_ASSESSMENT_PARAMETER_NAMES_PER_REFERENCE: usize = 256;
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
        let limits = Self {
            max_entities,
            max_attribute_keys,
            max_values_per_attribute,
            max_value_bytes,
            max_source_evidence_ids,
            max_url_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Revalidates every configured dimension against its compiled ceiling.
    pub fn validate(&self) -> Result<(), LimitsError> {
        validate_limit("max_entities", self.max_entities, Self::HARD_MAX_ENTITIES)?;
        validate_limit(
            "max_attribute_keys",
            self.max_attribute_keys,
            Self::HARD_MAX_ATTRIBUTE_KEYS,
        )?;
        validate_limit(
            "max_values_per_attribute",
            self.max_values_per_attribute,
            Self::HARD_MAX_VALUES_PER_ATTRIBUTE,
        )?;
        validate_limit(
            "max_value_bytes",
            self.max_value_bytes,
            Self::HARD_MAX_VALUE_BYTES,
        )?;
        validate_limit(
            "max_source_evidence_ids",
            self.max_source_evidence_ids,
            Self::HARD_MAX_SOURCE_EVIDENCE_IDS,
        )?;
        validate_limit(
            "max_url_bytes",
            self.max_url_bytes,
            Self::HARD_MAX_URL_BYTES,
        )
    }

    /// Returns the maximum number of retained entities.
    pub const fn max_entities(&self) -> usize {
        self.max_entities
    }

    /// Returns the maximum number of attribute keys on one entity.
    pub const fn max_attribute_keys(&self) -> usize {
        self.max_attribute_keys
    }

    /// Returns the maximum number of values retained for one attribute.
    pub const fn max_values_per_attribute(&self) -> usize {
        self.max_values_per_attribute
    }

    /// Returns the maximum byte length of one retained attribute value.
    pub const fn max_value_bytes(&self) -> usize {
        self.max_value_bytes
    }

    /// Returns the maximum number of source evidence identities per entity.
    pub const fn max_source_evidence_ids(&self) -> usize {
        self.max_source_evidence_ids
    }

    /// Returns the maximum accepted canonical URL byte length.
    pub const fn max_url_bytes(&self) -> usize {
        self.max_url_bytes
    }
}

fn validate_limit(name: &'static str, value: usize, ceiling: usize) -> Result<(), LimitsError> {
    if value == 0 {
        return Err(LimitsError::ZeroLimit { name });
    }
    if value > ceiling {
        return Err(LimitsError::ExceedsCeiling {
            name,
            requested: value,
            ceiling,
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_limits_round_trip_and_expose_read_only_dimensions() {
        let limits = SemanticExtractionLimits::new(7, 6, 5, 4, 3, 2).unwrap();
        assert_eq!(limits.max_entities(), 7);
        assert_eq!(limits.max_attribute_keys(), 6);
        assert_eq!(limits.max_values_per_attribute(), 5);
        assert_eq!(limits.max_value_bytes(), 4);
        assert_eq!(limits.max_source_evidence_ids(), 3);
        assert_eq!(limits.max_url_bytes(), 2);
        limits.validate().unwrap();
        let encoded = serde_json::to_string(&limits).unwrap();
        assert_eq!(
            serde_json::from_str::<SemanticExtractionLimits>(&encoded).unwrap(),
            limits
        );
    }

    #[test]
    fn validate_rejects_unchecked_public_values_without_changing_the_wire_shape() {
        let invalid = SemanticExtractionLimits {
            max_entities: 0,
            ..SemanticExtractionLimits::default()
        };
        assert!(matches!(
            invalid.validate(),
            Err(LimitsError::ZeroLimit {
                name: "max_entities"
            })
        ));
    }
}
