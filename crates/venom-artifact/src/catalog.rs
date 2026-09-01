//! Strict signature-pack parsing and immutable deterministic catalogs.

use crate::{ArtifactError, ArtifactPattern, MAX_PATTERN_BYTES};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Strict repository and host-supplied signature-pack schema.
pub const ARTIFACT_SIGNATURE_SCHEMA: &str = "venom.artifact-signatures/v1";
/// Maximum bytes parsed from one signature manifest.
pub const MAX_SIGNATURE_MANIFEST_BYTES: usize = 256 * 1024;
/// Maximum signatures in one pack.
pub const MAX_SIGNATURES_PER_PACK: usize = 1_024;
/// Maximum packs in one sealed catalog.
pub const MAX_PACKS_PER_CATALOG: usize = 64;
/// Maximum signatures across a sealed catalog.
pub const MAX_TOTAL_SIGNATURES: usize = 4_096;
/// Maximum compiled pattern bytes across a sealed catalog.
pub const MAX_TOTAL_COMPILED_PATTERN_BYTES: usize = MAX_TOTAL_SIGNATURES * MAX_PATTERN_BYTES;
/// Maximum deterministic query results.
pub const MAX_CATALOG_QUERY_RESULTS: usize = 1_024;
/// Maximum bytes in a pack title.
pub const MAX_PACK_TITLE_BYTES: usize = 96;
/// Maximum bytes in a pack summary.
pub const MAX_PACK_SUMMARY_BYTES: usize = 512;
/// Maximum bytes in a signature label.
pub const MAX_LABEL_BYTES: usize = 96;
/// Maximum bytes in an optional non-verdict description.
pub const MAX_DESCRIPTION_BYTES: usize = 512;
/// Maximum tags on one signature.
pub const MAX_TAGS_PER_SIGNATURE: usize = 16;
/// Maximum bytes in one normalized tag.
pub const MAX_TAG_BYTES: usize = 32;
const MAX_ID_BYTES: usize = 64;

fn validate_id(value: &str, field: &'static str) -> Result<(), ArtifactError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.trim() != value
        || value.contains("..")
        || value.contains("://")
        || value.contains(['/', '\\', ':', '@'])
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(ArtifactError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! bounded_id {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses one canonical bounded identity.
            pub fn parse(value: impl Into<String>) -> Result<Self, ArtifactError> {
                let value = value.into();
                validate_id(&value, $field)?;
                Ok(Self(value))
            }

            /// Returns the canonical identity.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_id!(ArtifactPackId, "pack_id", "Stable signature-pack identity.");
bounded_id!(
    ArtifactSignatureId,
    "signature_id",
    "Stable signature identity within one pack."
);

macro_rules! positive_revision {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(u32);

        impl $name {
            /// Validates a positive monotonic revision.
            pub fn new(value: u32) -> Result<Self, ArtifactError> {
                if value == 0 {
                    return Err(ArtifactError::InvalidRevision { field: $field });
                }
                Ok(Self(value))
            }

            /// Returns the numeric revision.
            pub fn get(self) -> u32 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

positive_revision!(
    ArtifactPackRevision,
    "pack_revision",
    "Positive pack revision."
);
positive_revision!(
    ArtifactSignatureRevision,
    "signature_revision",
    "Positive signature revision."
);

/// Closed observation-only classification for one signature match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactObservationClass {
    FileFormatMarker,
    EmbeddedFormatMarker,
    UserDefinedMarker,
    TestCanary,
    SuspiciousSequence,
}

impl ArtifactObservationClass {
    /// Returns the stable V1 wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileFormatMarker => "file-format-marker",
            Self::EmbeddedFormatMarker => "embedded-format-marker",
            Self::UserDefinedMarker => "user-defined-marker",
            Self::TestCanary => "test-canary",
            Self::SuspiciousSequence => "suspicious-sequence",
        }
    }
}

/// Exact catalog identity for a versioned signature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ArtifactSignatureRef {
    pack_id: ArtifactPackId,
    signature_id: ArtifactSignatureId,
    revision: ArtifactSignatureRevision,
}

impl ArtifactSignatureRef {
    pub fn new(
        pack_id: ArtifactPackId,
        signature_id: ArtifactSignatureId,
        revision: ArtifactSignatureRevision,
    ) -> Self {
        Self {
            pack_id,
            signature_id,
            revision,
        }
    }

    pub fn pack_id(&self) -> &ArtifactPackId {
        &self.pack_id
    }

    pub fn signature_id(&self) -> &ArtifactSignatureId {
        &self.signature_id
    }

    pub fn revision(&self) -> ArtifactSignatureRevision {
        self.revision
    }
}

/// One checked, compiled signature definition from a pack.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactSignatureDefinition {
    id: ArtifactSignatureId,
    revision: ArtifactSignatureRevision,
    label: String,
    observation_class: ArtifactObservationClass,
    pattern: ArtifactPattern,
    tags: BTreeSet<String>,
    description: Option<String>,
}

impl fmt::Debug for ArtifactSignatureDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactSignatureDefinition")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("observation_class", &self.observation_class)
            .field("pattern_bytes", &self.pattern.len())
            .field("literal_bytes", &self.pattern.literal_count())
            .field("tag_count", &self.tags.len())
            .field("has_description", &self.description.is_some())
            .finish()
    }
}

impl ArtifactSignatureDefinition {
    pub fn id(&self) -> &ArtifactSignatureId {
        &self.id
    }

    pub fn revision(&self) -> ArtifactSignatureRevision {
        self.revision
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn observation_class(&self) -> ArtifactObservationClass {
        self.observation_class
    }

    pub fn pattern(&self) -> &ArtifactPattern {
        &self.pattern
    }

    pub fn tags(&self) -> impl ExactSizeIterator<Item = &str> {
        self.tags.iter().map(String::as_str)
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// One fully checked signature pack; parsing does not grant scan authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactSignaturePack {
    id: ArtifactPackId,
    revision: ArtifactPackRevision,
    title: String,
    summary: String,
    signatures: Vec<ArtifactSignatureDefinition>,
}

impl fmt::Debug for ArtifactSignaturePack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactSignaturePack")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("signature_count", &self.signatures.len())
            .finish()
    }
}

impl ArtifactSignaturePack {
    pub fn id(&self) -> &ArtifactPackId {
        &self.id
    }

    pub fn revision(&self) -> ArtifactPackRevision {
        self.revision
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub fn signatures(&self) -> impl ExactSizeIterator<Item = &ArtifactSignatureDefinition> {
        self.signatures.iter()
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignaturePack {
    schema: String,
    pack_id: ArtifactPackId,
    pack_revision: ArtifactPackRevision,
    title: String,
    summary: String,
    signatures: Vec<RawSignature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    id: ArtifactSignatureId,
    revision: ArtifactSignatureRevision,
    label: String,
    observation_class: ArtifactObservationClass,
    pattern: String,
    tags: Vec<String>,
    description: Option<String>,
}

pub(crate) fn parse_pack_source(source: &str) -> Result<ArtifactSignaturePack, ArtifactError> {
    let raw: RawSignaturePack =
        toml::from_str(source).map_err(|_| ArtifactError::InvalidManifestSyntax)?;
    if raw.schema != ARTIFACT_SIGNATURE_SCHEMA {
        return Err(ArtifactError::UnsupportedSchema);
    }
    validate_text(&raw.title, "pack title", MAX_PACK_TITLE_BYTES)?;
    validate_text(&raw.summary, "pack summary", MAX_PACK_SUMMARY_BYTES)?;
    if raw.signatures.is_empty() || raw.signatures.len() > MAX_SIGNATURES_PER_PACK {
        return Err(ArtifactError::LimitExceeded {
            field: "signatures per pack",
            limit: MAX_SIGNATURES_PER_PACK,
        });
    }

    let mut identities = BTreeMap::<ArtifactSignatureId, ArtifactSignatureRevision>::new();
    let mut patterns = BTreeSet::new();
    let mut signatures = Vec::with_capacity(raw.signatures.len());
    for signature in raw.signatures {
        validate_text(&signature.label, "signature label", MAX_LABEL_BYTES)?;
        if let Some(description) = &signature.description {
            validate_text(description, "signature description", MAX_DESCRIPTION_BYTES)?;
        }
        if signature.tags.len() > MAX_TAGS_PER_SIGNATURE {
            return Err(ArtifactError::LimitExceeded {
                field: "tags per signature",
                limit: MAX_TAGS_PER_SIGNATURE,
            });
        }
        let mut tags = BTreeSet::new();
        for tag in signature.tags {
            validate_tag(&tag)?;
            tags.insert(tag);
        }
        if tags.len() > MAX_TAGS_PER_SIGNATURE {
            return Err(ArtifactError::LimitExceeded {
                field: "tags per signature",
                limit: MAX_TAGS_PER_SIGNATURE,
            });
        }

        if let Some(previous) = identities.get(&signature.id) {
            return if *previous == signature.revision {
                Err(ArtifactError::DuplicateSignature)
            } else {
                Err(ArtifactError::ConflictingSignatureRevision)
            };
        }
        identities.insert(signature.id.clone(), signature.revision);

        let pattern = ArtifactPattern::parse(&signature.pattern)?;
        if !patterns.insert(pattern.canonical().to_owned()) {
            return Err(ArtifactError::DuplicateSemanticPattern);
        }
        signatures.push(ArtifactSignatureDefinition {
            id: signature.id,
            revision: signature.revision,
            label: signature.label,
            observation_class: signature.observation_class,
            pattern,
            tags,
            description: signature.description,
        });
    }
    signatures.sort_by(|left, right| (&left.id, left.revision).cmp(&(&right.id, right.revision)));

    Ok(ArtifactSignaturePack {
        id: raw.pack_id,
        revision: raw.pack_revision,
        title: raw.title,
        summary: raw.summary,
        signatures,
    })
}

fn validate_text(value: &str, field: &'static str, limit: usize) -> Result<(), ArtifactError> {
    if value.is_empty()
        || value.len() > limit
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ArtifactError::InvalidText { field });
    }
    Ok(())
}

fn validate_tag(value: &str) -> Result<(), ArtifactError> {
    if value.is_empty()
        || value.len() > MAX_TAG_BYTES
        || value.trim() != value
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(ArtifactError::InvalidText {
            field: "signature tag",
        });
    }
    Ok(())
}

/// Stable SHA-256 identity of one sealed semantic catalog.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ArtifactCatalogDigest(String);

impl ArtifactCatalogDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArtifactCatalogDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactCatalogDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ArtifactCatalogDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One immutable catalog entry used by the matcher and bounded queries.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactCatalogSignature {
    signature_ref: ArtifactSignatureRef,
    label: String,
    observation_class: ArtifactObservationClass,
    pattern: ArtifactPattern,
    tags: BTreeSet<String>,
    description: Option<String>,
}

impl fmt::Debug for ArtifactCatalogSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactCatalogSignature")
            .field("signature_ref", &self.signature_ref)
            .field("observation_class", &self.observation_class)
            .field("pattern_bytes", &self.pattern.len())
            .field("literal_bytes", &self.pattern.literal_count())
            .field("tag_count", &self.tags.len())
            .field("has_description", &self.description.is_some())
            .finish()
    }
}

impl ArtifactCatalogSignature {
    pub fn signature_ref(&self) -> &ArtifactSignatureRef {
        &self.signature_ref
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn observation_class(&self) -> ArtifactObservationClass {
        self.observation_class
    }

    pub fn pattern(&self) -> &ArtifactPattern {
        &self.pattern
    }

    pub fn tags(&self) -> impl ExactSizeIterator<Item = &str> {
        self.tags.iter().map(String::as_str)
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// Mutable metadata builder which must be sealed before scanning.
#[derive(Default)]
pub struct ArtifactCatalogBuilder {
    packs: BTreeMap<ArtifactPackId, ArtifactSignaturePack>,
    semantic_patterns: BTreeMap<String, ArtifactSignatureRef>,
    signature_count: usize,
    compiled_pattern_bytes: usize,
}

impl fmt::Debug for ArtifactCatalogBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactCatalogBuilder")
            .field("pack_count", &self.packs.len())
            .field("signature_count", &self.signature_count)
            .field("compiled_pattern_bytes", &self.compiled_pattern_bytes)
            .finish()
    }
}

impl ArtifactCatalogBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, pack: ArtifactSignaturePack) -> Result<&mut Self, ArtifactError> {
        if let Some(existing) = self.packs.get(pack.id()) {
            return if existing.revision() == pack.revision() {
                Err(ArtifactError::DuplicatePack)
            } else {
                Err(ArtifactError::ConflictingPackRevision)
            };
        }
        if self.packs.len() >= MAX_PACKS_PER_CATALOG {
            return Err(ArtifactError::CatalogCapacityExceeded);
        }
        let signature_count = self
            .signature_count
            .checked_add(pack.len())
            .ok_or(ArtifactError::CatalogCapacityExceeded)?;
        if signature_count > MAX_TOTAL_SIGNATURES {
            return Err(ArtifactError::CatalogCapacityExceeded);
        }
        let added_pattern_bytes = pack.signatures().try_fold(0usize, |total, signature| {
            total
                .checked_add(signature.pattern().len())
                .ok_or(ArtifactError::CatalogCapacityExceeded)
        })?;
        let compiled_pattern_bytes = self
            .compiled_pattern_bytes
            .checked_add(added_pattern_bytes)
            .ok_or(ArtifactError::CatalogCapacityExceeded)?;
        if compiled_pattern_bytes > MAX_TOTAL_COMPILED_PATTERN_BYTES {
            return Err(ArtifactError::CatalogCapacityExceeded);
        }

        let mut additions = Vec::with_capacity(pack.len());
        for signature in pack.signatures() {
            let signature_ref = ArtifactSignatureRef::new(
                pack.id().clone(),
                signature.id().clone(),
                signature.revision(),
            );
            let canonical = signature.pattern().canonical().to_owned();
            if self.semantic_patterns.contains_key(&canonical) {
                return Err(ArtifactError::DuplicateSemanticPattern);
            }
            additions.push((canonical, signature_ref));
        }
        for (canonical, signature_ref) in additions {
            self.semantic_patterns.insert(canonical, signature_ref);
        }
        self.signature_count = signature_count;
        self.compiled_pattern_bytes = compiled_pattern_bytes;
        self.packs.insert(pack.id().clone(), pack);
        Ok(self)
    }

    pub fn seal(self) -> Result<ArtifactCatalog, ArtifactError> {
        let mut signatures = Vec::with_capacity(self.signature_count);
        for pack in self.packs.values() {
            for signature in pack.signatures() {
                signatures.push(ArtifactCatalogSignature {
                    signature_ref: ArtifactSignatureRef::new(
                        pack.id().clone(),
                        signature.id().clone(),
                        signature.revision(),
                    ),
                    label: signature.label().to_owned(),
                    observation_class: signature.observation_class(),
                    pattern: signature.pattern().clone(),
                    tags: signature.tags().map(str::to_owned).collect(),
                    description: signature.description().map(str::to_owned),
                });
            }
        }
        signatures.sort_by(|left, right| left.signature_ref.cmp(&right.signature_ref));

        let mut anchor_groups = BTreeMap::<usize, BTreeMap<u8, Vec<usize>>>::new();
        let mut maximum_pattern_length = 0usize;
        for (index, signature) in signatures.iter().enumerate() {
            maximum_pattern_length = maximum_pattern_length.max(signature.pattern.len());
            let (offset, byte) = signature.pattern.anchor();
            anchor_groups
                .entry(offset)
                .or_default()
                .entry(byte)
                .or_default()
                .push(index);
        }
        let digest = digest_catalog(&self.packs);
        Ok(ArtifactCatalog {
            packs: self.packs.len(),
            signatures,
            anchor_groups,
            maximum_pattern_length,
            digest,
        })
    }
}

/// Sealed immutable signature catalog. Membership does not itself perform a scan.
pub struct ArtifactCatalog {
    packs: usize,
    signatures: Vec<ArtifactCatalogSignature>,
    anchor_groups: BTreeMap<usize, BTreeMap<u8, Vec<usize>>>,
    maximum_pattern_length: usize,
    digest: ArtifactCatalogDigest,
}

impl fmt::Debug for ArtifactCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactCatalog")
            .field("pack_count", &self.packs)
            .field("signature_count", &self.signatures.len())
            .field("maximum_pattern_length", &self.maximum_pattern_length)
            .field("digest", &self.digest)
            .finish()
    }
}

impl ArtifactCatalog {
    pub fn builder() -> ArtifactCatalogBuilder {
        ArtifactCatalogBuilder::new()
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn pack_count(&self) -> usize {
        self.packs
    }

    pub fn digest(&self) -> &ArtifactCatalogDigest {
        &self.digest
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ArtifactCatalogSignature> {
        self.signatures.iter()
    }

    pub fn get(&self, signature_ref: &ArtifactSignatureRef) -> Option<&ArtifactCatalogSignature> {
        self.signatures
            .binary_search_by(|entry| entry.signature_ref.cmp(signature_ref))
            .ok()
            .map(|index| &self.signatures[index])
    }

    pub fn by_class(
        &self,
        class: ArtifactObservationClass,
    ) -> Result<Vec<&ArtifactCatalogSignature>, ArtifactError> {
        bounded_query(
            self.signatures
                .iter()
                .filter(|entry| entry.observation_class == class),
        )
    }

    pub fn by_tag(&self, tag: &str) -> Result<Vec<&ArtifactCatalogSignature>, ArtifactError> {
        validate_tag(tag)?;
        bounded_query(
            self.signatures
                .iter()
                .filter(|entry| entry.tags.contains(tag)),
        )
    }

    pub(crate) fn anchor_groups(&self) -> &BTreeMap<usize, BTreeMap<u8, Vec<usize>>> {
        &self.anchor_groups
    }

    #[cfg(test)]
    pub(crate) fn indexed_signature_count(&self) -> usize {
        self.anchor_groups
            .values()
            .flat_map(BTreeMap::values)
            .map(Vec::len)
            .sum()
    }

    pub(crate) fn signature(&self, index: usize) -> &ArtifactCatalogSignature {
        &self.signatures[index]
    }

    pub(crate) fn maximum_pattern_length(&self) -> usize {
        self.maximum_pattern_length
    }
}

fn bounded_query<'a>(
    entries: impl Iterator<Item = &'a ArtifactCatalogSignature>,
) -> Result<Vec<&'a ArtifactCatalogSignature>, ArtifactError> {
    let mut result = Vec::new();
    for entry in entries {
        if result.len() >= MAX_CATALOG_QUERY_RESULTS {
            return Err(ArtifactError::LimitExceeded {
                field: "catalog query results",
                limit: MAX_CATALOG_QUERY_RESULTS,
            });
        }
        result.push(entry);
    }
    Ok(result)
}

fn digest_catalog(
    packs: &BTreeMap<ArtifactPackId, ArtifactSignaturePack>,
) -> ArtifactCatalogDigest {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"venom:artifact-catalog:v1");
    hash_u64(&mut hasher, packs.len() as u64);
    for pack in packs.values() {
        hash_field(&mut hasher, pack.id().as_str().as_bytes());
        hash_u64(&mut hasher, u64::from(pack.revision().get()));
        hash_field(&mut hasher, pack.title().as_bytes());
        hash_field(&mut hasher, pack.summary().as_bytes());
        hash_u64(&mut hasher, pack.len() as u64);
        for signature in pack.signatures() {
            hash_field(&mut hasher, signature.id().as_str().as_bytes());
            hash_u64(&mut hasher, u64::from(signature.revision().get()));
            hash_field(&mut hasher, signature.label().as_bytes());
            hash_field(
                &mut hasher,
                signature.observation_class().as_str().as_bytes(),
            );
            hash_field(&mut hasher, signature.pattern().canonical().as_bytes());
            hash_u64(&mut hasher, signature.tags().len() as u64);
            for tag in signature.tags() {
                hash_field(&mut hasher, tag.as_bytes());
            }
            match signature.description() {
                Some(description) => {
                    hash_field(&mut hasher, b"some");
                    hash_field(&mut hasher, description.as_bytes());
                },
                None => hash_field(&mut hasher, b"none"),
            }
        }
    }
    ArtifactCatalogDigest(format!(
        "artifact-catalog-sha256:{}",
        hex::encode(hasher.finalize())
    ))
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hash_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactScanLimits, ArtifactScanner};
    use std::fmt::Write;

    fn manifest(order: bool) -> String {
        let (first, second) = if order {
            (
                r#"id = "wild"
revision = 1
label = "Wildcard canary"
observation_class = "test-canary"
pattern = "56 ?? 4E 4D"
tags = ["lab", "canary"]"#,
                r#"id = "exact"
revision = 1
label = "Exact marker"
observation_class = "file-format-marker"
pattern = "41 42"
tags = ["format"]
description = "Harmless marker""#,
            )
        } else {
            (
                r#"id = "exact"
revision = 1
label = "Exact marker"
observation_class = "file-format-marker"
pattern = "41 42"
tags = ["format"]
description = "Harmless marker""#,
                r#"id = "wild"
revision = 1
label = "Wildcard canary"
observation_class = "test-canary"
pattern = "56 ?? 4E 4D"
tags = ["canary", "lab"]"#,
            )
        };
        format!(
            r#"schema = "venom.artifact-signatures/v1"
pack_id = "venom-canary"
pack_revision = 1
title = "Venom canary"
summary = "Harmless deterministic markers"

[[signatures]]
{first}

[[signatures]]
{second}
"#
        )
    }

    #[test]
    fn strict_pack_parsing_normalizes_order_and_tags() {
        let pack = ArtifactSignaturePack::parse_toml(manifest(true).as_bytes()).expect("pack");
        assert_eq!(pack.id().as_str(), "venom-canary");
        assert_eq!(pack.len(), 2);
        assert_eq!(
            pack.signatures()
                .map(|entry| entry.id().as_str())
                .collect::<Vec<_>>(),
            ["exact", "wild"]
        );
        assert_eq!(
            pack.signatures()
                .nth(1)
                .expect("wild")
                .tags()
                .collect::<Vec<_>>(),
            ["canary", "lab"]
        );
    }

    #[test]
    fn catalog_digest_is_semantic_and_order_independent() {
        let one = ArtifactSignaturePack::parse_toml(manifest(true).as_bytes()).expect("one");
        let two = ArtifactSignaturePack::parse_toml(manifest(false).as_bytes()).expect("two");
        let mut first = ArtifactCatalog::builder();
        first.register(one).expect("register");
        let mut second = ArtifactCatalog::builder();
        second.register(two).expect("register");
        let first = first.seal().expect("seal");
        let second = second.seal().expect("seal");
        assert_eq!(first.digest(), second.digest());
        assert_eq!(
            first.digest().as_str(),
            "artifact-catalog-sha256:42a6ca92253a07c62169e43abb629aab1a76f676e666d2d21e0c099dc12a152e"
        );
    }

    #[test]
    fn material_catalog_change_changes_digest() {
        let first = ArtifactSignaturePack::parse_toml(manifest(true).as_bytes()).expect("first");
        let changed = manifest(true).replace("41 42", "41 43");
        let changed = ArtifactSignaturePack::parse_toml(changed.as_bytes()).expect("changed");
        let mut left = ArtifactCatalog::builder();
        left.register(first).expect("register");
        let mut right = ArtifactCatalog::builder();
        right.register(changed).expect("register");
        assert_ne!(
            left.seal().expect("left").digest(),
            right.seal().expect("right").digest()
        );
    }

    #[test]
    fn exact_lookup_and_bounded_filters_are_deterministic() {
        let pack = ArtifactSignaturePack::parse_toml(manifest(true).as_bytes()).expect("pack");
        let mut builder = ArtifactCatalog::builder();
        builder.register(pack).expect("register");
        let catalog = builder.seal().expect("seal");
        let reference = ArtifactSignatureRef::new(
            ArtifactPackId::parse("venom-canary").expect("pack id"),
            ArtifactSignatureId::parse("exact").expect("signature id"),
            ArtifactSignatureRevision::new(1).expect("revision"),
        );
        assert_eq!(
            catalog.get(&reference).expect("exact").label(),
            "Exact marker"
        );
        assert_eq!(catalog.by_tag("canary").expect("tag").len(), 1);
        assert_eq!(
            catalog
                .by_class(ArtifactObservationClass::TestCanary)
                .expect("class")
                .len(),
            1
        );
        assert!(matches!(
            catalog.by_tag("../bad"),
            Err(ArtifactError::InvalidText { .. })
        ));
    }

    #[test]
    fn duplicate_and_conflicting_pack_revisions_fail_closed() {
        let pack = ArtifactSignaturePack::parse_toml(manifest(true).as_bytes()).expect("pack");
        let duplicate = pack.clone();
        let mut builder = ArtifactCatalog::builder();
        builder.register(pack).expect("register");
        assert!(matches!(
            builder.register(duplicate),
            Err(ArtifactError::DuplicatePack)
        ));

        let changed_revision = manifest(true).replace("pack_revision = 1", "pack_revision = 2");
        let changed = ArtifactSignaturePack::parse_toml(changed_revision.as_bytes()).expect("pack");
        assert!(matches!(
            builder.register(changed),
            Err(ArtifactError::ConflictingPackRevision)
        ));
    }

    #[test]
    fn duplicate_signature_identity_and_pattern_fail_closed() {
        let duplicate_id = manifest(true).replace("id = \"wild\"", "id = \"exact\"");
        assert!(matches!(
            ArtifactSignaturePack::parse_toml(duplicate_id.as_bytes()),
            Err(ArtifactError::DuplicateSignature)
        ));
        let conflicting = duplicate_id.replace(
            "revision = 1\nlabel = \"Wildcard",
            "revision = 2\nlabel = \"Wildcard",
        );
        assert!(matches!(
            ArtifactSignaturePack::parse_toml(conflicting.as_bytes()),
            Err(ArtifactError::ConflictingSignatureRevision)
        ));
        let duplicate_pattern = manifest(true).replace("56 ?? 4E 4D", "41 42");
        assert!(matches!(
            ArtifactSignaturePack::parse_toml(duplicate_pattern.as_bytes()),
            Err(ArtifactError::DuplicateSemanticPattern)
        ));
    }

    #[test]
    fn strict_schema_identity_revision_text_and_input_bounds() {
        assert_eq!(
            ArtifactSignaturePack::parse_toml(
                manifest(true)
                    .replace(ARTIFACT_SIGNATURE_SCHEMA, "venom.artifact-signatures/v2")
                    .as_bytes()
            ),
            Err(ArtifactError::UnsupportedSchema)
        );
        for replacement in [
            "pack_id = \"../bad\"",
            "pack_id = \"https://bad\"",
            "pack_id = \"Bad\"",
        ] {
            let source = manifest(true).replace("pack_id = \"venom-canary\"", replacement);
            assert!(matches!(
                ArtifactSignaturePack::parse_toml(source.as_bytes()),
                Err(ArtifactError::InvalidManifestSyntax)
            ));
        }
        let zero_revision = manifest(true).replace("pack_revision = 1", "pack_revision = 0");
        assert!(matches!(
            ArtifactSignaturePack::parse_toml(zero_revision.as_bytes()),
            Err(ArtifactError::InvalidManifestSyntax)
        ));
        let unknown =
            manifest(true).replace("pack_revision = 1", "pack_revision = 1\nextra = true");
        assert_eq!(
            ArtifactSignaturePack::parse_toml(unknown.as_bytes()),
            Err(ArtifactError::InvalidManifestSyntax)
        );
        assert_eq!(
            ArtifactSignaturePack::parse_toml(&vec![b'a'; MAX_SIGNATURE_MANIFEST_BYTES + 1]),
            Err(ArtifactError::LimitExceeded {
                field: "signature manifest bytes",
                limit: MAX_SIGNATURE_MANIFEST_BYTES
            })
        );
        assert_eq!(
            ArtifactSignaturePack::parse_toml(&[0xff]),
            Err(ArtifactError::InvalidUtf8)
        );
    }

    #[test]
    fn empty_catalog_is_intentionally_inert() {
        let catalog = ArtifactCatalog::builder().seal().expect("catalog");
        assert!(catalog.is_empty());
        assert_eq!(catalog.pack_count(), 0);
        assert_eq!(catalog.maximum_pattern_length(), 0);
    }

    #[test]
    fn free_form_manifest_metadata_never_enters_public_debug() {
        const SENTINEL: &str = "VENOM-ARTIFACT-MUST-NOT-LEAK-SECRET-123";
        let source = manifest(true)
            .replace("Venom canary", SENTINEL)
            .replace("Harmless deterministic markers", SENTINEL)
            .replace("Exact marker", SENTINEL)
            .replace("Harmless marker", SENTINEL);
        let pack = ArtifactSignaturePack::parse_toml(source.as_bytes()).expect("pack");
        assert!(!format!("{pack:?}").contains(SENTINEL));
        assert!(!format!("{:?}", pack.signatures().next().expect("signature")).contains(SENTINEL));

        let mut builder = ArtifactCatalog::builder();
        builder.register(pack).expect("register");
        assert!(!format!("{builder:?}").contains(SENTINEL));
        let catalog = builder.seal().expect("catalog");
        assert!(!format!("{catalog:?}").contains(SENTINEL));
        assert!(!format!("{:?}", catalog.iter().next().expect("entry")).contains(SENTINEL));
    }

    fn signature_range_manifest(
        pack_id: &str,
        start: usize,
        count: usize,
        reverse: bool,
    ) -> String {
        let mut source = format!(
            r#"schema = "venom.artifact-signatures/v1"
pack_id = "{pack_id}"
pack_revision = 1
title = "Metadata scale fixture"
summary = "Deterministic exact marker range"
"#
        );
        let indexes: Box<dyn Iterator<Item = usize>> = if reverse {
            Box::new((start..start + count).rev())
        } else {
            Box::new(start..start + count)
        };
        for index in indexes {
            writeln!(
                source,
                r#"
[[signatures]]
id = "sig-{index:04}"
revision = 1
label = "Scale marker {index}"
observation_class = "test-canary"
pattern = "{:02X} {:02X}"
tags = ["scale"]"#,
                index >> 8,
                index & 0xff
            )
            .expect("string write");
        }
        source
    }

    #[test]
    fn thousand_entry_catalog_is_indexed_deterministic_and_scan_bounded() {
        let forward = ArtifactSignaturePack::parse_toml(
            signature_range_manifest("metadata-scale", 0, 1_000, false).as_bytes(),
        )
        .expect("forward pack");
        let reverse = ArtifactSignaturePack::parse_toml(
            signature_range_manifest("metadata-scale", 0, 1_000, true).as_bytes(),
        )
        .expect("reverse pack");
        let mut first = ArtifactCatalog::builder();
        first.register(forward).expect("register");
        let first = first.seal().expect("seal");
        let mut second = ArtifactCatalog::builder();
        second.register(reverse).expect("register");
        let second = second.seal().expect("seal");

        assert_eq!(first.len(), 1_000);
        assert_eq!(first.digest(), second.digest());
        assert_eq!(
            first
                .iter()
                .take(3)
                .map(|entry| entry.signature_ref().signature_id().as_str())
                .collect::<Vec<_>>(),
            ["sig-0000", "sig-0001", "sig-0002"]
        );
        assert_eq!(first.indexed_signature_count(), 1_000);

        let scanner =
            ArtifactScanner::new(&first, ArtifactScanLimits::new(16, 8, 2).expect("limits"))
                .expect("scanner");
        let report = scanner.scan_bytes(&[0x00, 0x00, 0x01]).expect("scan");
        assert_eq!(
            report
                .matches()
                .map(|entry| {
                    (
                        entry.absolute_offset(),
                        entry.signature().signature_id().as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [(0, "sig-0000"), (1, "sig-0001")]
        );
    }

    #[test]
    fn identity_revision_metadata_tag_and_list_limits_are_exact() {
        assert_eq!(
            ArtifactPackId::parse("a".repeat(MAX_ID_BYTES))
                .expect("max")
                .as_str()
                .len(),
            MAX_ID_BYTES
        );
        assert_eq!(
            ArtifactPackId::parse("a".repeat(MAX_ID_BYTES + 1)),
            Err(ArtifactError::InvalidIdentifier { field: "pack_id" })
        );
        for invalid in ["", " bad", "bad ", "bad/path", "bad@host", "-bad", "bad-"] {
            assert_eq!(
                ArtifactSignatureId::parse(invalid),
                Err(ArtifactError::InvalidIdentifier {
                    field: "signature_id"
                })
            );
        }
        assert_eq!(
            ArtifactPackRevision::new(0),
            Err(ArtifactError::InvalidRevision {
                field: "pack_revision"
            })
        );
        assert_eq!(
            ArtifactSignatureRevision::new(0),
            Err(ArtifactError::InvalidRevision {
                field: "signature_revision"
            })
        );

        for (old, replacement) in [
            ("Venom canary", "x".repeat(MAX_PACK_TITLE_BYTES + 1)),
            (
                "Harmless deterministic markers",
                "x".repeat(MAX_PACK_SUMMARY_BYTES + 1),
            ),
            ("Exact marker", "x".repeat(MAX_LABEL_BYTES + 1)),
            ("Harmless marker", "x".repeat(MAX_DESCRIPTION_BYTES + 1)),
        ] {
            let source = manifest(true).replace(old, &replacement);
            assert!(matches!(
                ArtifactSignaturePack::parse_toml(source.as_bytes()),
                Err(ArtifactError::InvalidText { .. })
            ));
        }
        let invalid_tag = manifest(true).replace("tags = [\"format\"]", "tags = [\"Bad Tag\"]");
        assert!(matches!(
            ArtifactSignaturePack::parse_toml(invalid_tag.as_bytes()),
            Err(ArtifactError::InvalidText {
                field: "signature tag"
            })
        ));
        let tags = (0..=MAX_TAGS_PER_SIGNATURE)
            .map(|index| format!("\"tag-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let excessive_tags =
            manifest(true).replace("tags = [\"format\"]", &format!("tags = [{tags}]"));
        assert_eq!(
            ArtifactSignaturePack::parse_toml(excessive_tags.as_bytes()),
            Err(ArtifactError::LimitExceeded {
                field: "tags per signature",
                limit: MAX_TAGS_PER_SIGNATURE
            })
        );
        let mut empty_pack = manifest(true)
            .split("[[signatures]]")
            .next()
            .expect("header")
            .to_owned();
        empty_pack.push_str("signatures = []\n");
        assert_eq!(
            ArtifactSignaturePack::parse_toml(empty_pack.as_bytes()),
            Err(ArtifactError::LimitExceeded {
                field: "signatures per pack",
                limit: MAX_SIGNATURES_PER_PACK
            })
        );
        assert_eq!(
            ArtifactSignaturePack::parse_toml(
                signature_range_manifest("too-many", 0, MAX_SIGNATURES_PER_PACK + 1, false)
                    .as_bytes()
            ),
            Err(ArtifactError::LimitExceeded {
                field: "signatures per pack",
                limit: MAX_SIGNATURES_PER_PACK
            })
        );
    }

    #[test]
    fn cross_pack_patterns_pack_capacity_and_query_results_are_bounded() {
        let first = ArtifactSignaturePack::parse_toml(manifest(true).as_bytes()).expect("first");
        let duplicate_pattern = ArtifactSignaturePack::parse_toml(
            manifest(true)
                .replace("pack_id = \"venom-canary\"", "pack_id = \"other-pack\"")
                .as_bytes(),
        )
        .expect("other pack");
        let mut duplicate_builder = ArtifactCatalog::builder();
        duplicate_builder.register(first).expect("register");
        assert!(matches!(
            duplicate_builder.register(duplicate_pattern),
            Err(ArtifactError::DuplicateSemanticPattern)
        ));

        let mut pack_builder = ArtifactCatalog::builder();
        for index in 0..MAX_PACKS_PER_CATALOG {
            let pack = ArtifactSignaturePack::parse_toml(
                signature_range_manifest(&format!("pack-{index:02}"), index, 1, false).as_bytes(),
            )
            .expect("pack");
            pack_builder.register(pack).expect("within pack limit");
        }
        let extra = ArtifactSignaturePack::parse_toml(
            signature_range_manifest("pack-extra", MAX_PACKS_PER_CATALOG, 1, false).as_bytes(),
        )
        .expect("extra");
        assert!(matches!(
            pack_builder.register(extra),
            Err(ArtifactError::CatalogCapacityExceeded)
        ));

        let mut total_builder = ArtifactCatalog::builder();
        for pack_index in 0..4 {
            let start = pack_index * MAX_SIGNATURES_PER_PACK;
            total_builder
                .register(
                    ArtifactSignaturePack::parse_toml(
                        signature_range_manifest(
                            &format!("total-{pack_index}"),
                            start,
                            MAX_SIGNATURES_PER_PACK,
                            false,
                        )
                        .as_bytes(),
                    )
                    .expect("total pack"),
                )
                .expect("within total signature limit");
        }
        let above_total = ArtifactSignaturePack::parse_toml(
            signature_range_manifest("total-extra", MAX_TOTAL_SIGNATURES, 1, false).as_bytes(),
        )
        .expect("above total pack");
        assert!(matches!(
            total_builder.register(above_total),
            Err(ArtifactError::CatalogCapacityExceeded)
        ));

        let mut query_builder = ArtifactCatalog::builder();
        query_builder
            .register(
                ArtifactSignaturePack::parse_toml(
                    signature_range_manifest("query-main", 0, 1_024, false).as_bytes(),
                )
                .expect("main"),
            )
            .expect("register main");
        query_builder
            .register(
                ArtifactSignaturePack::parse_toml(
                    signature_range_manifest("query-tail", 1_024, 1, false).as_bytes(),
                )
                .expect("tail"),
            )
            .expect("register tail");
        let query_catalog = query_builder.seal().expect("catalog");
        assert!(matches!(
            query_catalog.by_class(ArtifactObservationClass::TestCanary),
            Err(ArtifactError::LimitExceeded {
                field: "catalog query results",
                limit: MAX_CATALOG_QUERY_RESULTS
            })
        ));
    }
}
