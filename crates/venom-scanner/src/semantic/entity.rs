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

    /// Returns supporting evidence identifiers in sorted, deduplicated order.
    pub fn source_evidence_ids(&self) -> &[EvidenceId] {
        &self.source_evidence_ids
    }
}
