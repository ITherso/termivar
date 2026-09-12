//! Bounded local WordPress asset fingerprint catalogues and pure matching.
//!
//! A catalogue is an operator-supplied finite reference set. Parsing it does
//! not authenticate its publisher, establish that it covers every release, or
//! grant permission to request any target resource. The matcher accepts only
//! already-qualified complete-byte observations and never promotes a listed
//! release to installed-version evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use super::{
    parse_bounded_json, WordPressComponentIdentity, WordPressComponentKind, WordPressReviewError,
    MAX_CATALOG_JSON_NODES, MAX_WORDPRESS_IDENTIFIER_BYTES, MAX_WORDPRESS_REFERENCE_BYTES,
    MAX_WORDPRESS_VERSION_BYTES,
};

pub const WORDPRESS_ASSET_FINGERPRINT_CATALOG_SCHEMA: &str =
    "security.wordpress-asset-fingerprint-catalog/v1";
pub const WORDPRESS_ASSET_FINGERPRINT_REPRESENTATION_PROFILE: &str = "identity-content-bytes/v1";
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_COMPONENTS: usize = 16;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_RELEASES_PER_COMPONENT: usize = 128;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_FILES_PER_RELEASE: usize = 32;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_FILES: usize = 16_384;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_RETAINED_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_ASSET_BYTES: u64 = 512 * 1024;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_RESOURCES_PER_COMPONENT: usize = 2;
const MAX_WORDPRESS_ASSET_FINGERPRINT_OBSERVATIONS_PER_COMPONENT: usize = 32;
pub const MAX_WORDPRESS_ASSET_FINGERPRINT_PATH_BYTES: usize = 512;
const MAX_WORDPRESS_ASSET_FINGERPRINT_NOTICES: usize = 32;
const MAX_WORDPRESS_ASSET_FINGERPRINT_NOTICE_BYTES: usize = 2_048;
const CONSERVATIVE_ALLOCATION_OVERHEAD: usize = 64;

/// Fail-closed errors for catalogue parsing and pure candidate matching.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WordPressAssetFingerprintError {
    #[error("WordPress asset fingerprint catalogue is empty")]
    EmptyInput,
    #[error("WordPress asset fingerprint catalogue exceeds its byte limit")]
    InputTooLarge,
    #[error("WordPress asset fingerprint catalogue contains a duplicate object key")]
    DuplicateKey,
    #[error("WordPress asset fingerprint catalogue exceeds a structural limit")]
    StructuralLimitExceeded,
    #[error("WordPress asset fingerprint catalogue is malformed JSON")]
    MalformedJson,
    #[error("WordPress asset fingerprint catalogue uses an unsupported schema")]
    UnsupportedSchema,
    #[error("WordPress asset fingerprint catalogue contains an invalid value")]
    InvalidCatalog,
    #[error("WordPress asset fingerprint catalogue contains a duplicate identity")]
    DuplicateIdentity,
    #[error("WordPress asset fingerprint catalogue exceeds its retained-data limit")]
    RetainedDataTooLarge,
    #[error("observed WordPress asset fingerprints violate the matching contract")]
    InvalidObservation,
    #[error("observed WordPress asset fingerprints exceed the matching limit")]
    MatchLimitExceeded,
}

/// Exact local-input identity plus the prepared finite reference set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintCatalogImport {
    byte_length: u64,
    sha256: [u8; 32],
    semantic_sha256: [u8; 32],
    retained_bytes: usize,
    release_count: usize,
    file_count: usize,
    catalog: WordPressAssetFingerprintCatalogMetadata,
    components: Vec<WordPressAssetFingerprintComponent>,
}

pub type WordPressAssetFingerprintCatalog = WordPressAssetFingerprintCatalogImport;

impl WordPressAssetFingerprintCatalogImport {
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[must_use]
    pub const fn semantic_sha256(&self) -> &[u8; 32] {
        &self.semantic_sha256
    }

    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    #[must_use]
    pub const fn release_count(&self) -> usize {
        self.release_count
    }

    #[must_use]
    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    #[must_use]
    pub const fn catalog(&self) -> &WordPressAssetFingerprintCatalogMetadata {
        &self.catalog
    }

    #[must_use]
    pub fn components(&self) -> &[WordPressAssetFingerprintComponent] {
        &self.components
    }

    #[must_use]
    pub fn component(
        &self,
        identity: &WordPressComponentIdentity,
    ) -> Option<&WordPressAssetFingerprintComponent> {
        self.components
            .binary_search_by(|candidate| candidate.identity.cmp(identity))
            .ok()
            .map(|index| &self.components[index])
    }
}

/// Catalogue-level identity and inert source provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintCatalogMetadata {
    id: String,
    revision: String,
    source_namespace: String,
    provenance: WordPressAssetFingerprintProvenance,
}

impl WordPressAssetFingerprintCatalogMetadata {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn source_namespace(&self) -> &str {
        &self.source_namespace
    }

    #[must_use]
    pub const fn provenance(&self) -> &WordPressAssetFingerprintProvenance {
        &self.provenance
    }
}

/// Inert bibliographic provenance supplied with a finite catalogue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintProvenance {
    reference: String,
    revision: String,
    notices: Vec<WordPressAssetFingerprintNotice>,
}

impl WordPressAssetFingerprintProvenance {
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn notices(&self) -> &[WordPressAssetFingerprintNotice] {
        &self.notices
    }
}

/// Attribution retained as inert text; it is never fetched or executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintNotice {
    id: String,
    party: String,
    notice: String,
    license: String,
    license_reference: String,
}

impl WordPressAssetFingerprintNotice {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn party(&self) -> &str {
        &self.party
    }

    #[must_use]
    pub fn notice(&self) -> &str {
        &self.notice
    }

    #[must_use]
    pub fn license(&self) -> &str {
        &self.license
    }

    #[must_use]
    pub fn license_reference(&self) -> &str {
        &self.license_reference
    }
}

/// One exact plugin/theme identity represented by the finite catalogue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintComponent {
    identity: WordPressComponentIdentity,
    releases: Vec<WordPressAssetFingerprintRelease>,
}

impl WordPressAssetFingerprintComponent {
    #[must_use]
    pub const fn identity(&self) -> &WordPressComponentIdentity {
        &self.identity
    }

    #[must_use]
    pub fn releases(&self) -> &[WordPressAssetFingerprintRelease] {
        &self.releases
    }
}

/// One opaque listed release/build and its exact reference files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintRelease {
    release_id: String,
    version: String,
    build_variant: Option<String>,
    source: WordPressAssetFingerprintReleaseSource,
    files: Vec<WordPressAssetFingerprintFile>,
}

impl WordPressAssetFingerprintRelease {
    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn build_variant(&self) -> Option<&str> {
        self.build_variant.as_deref()
    }

    #[must_use]
    pub const fn source(&self) -> &WordPressAssetFingerprintReleaseSource {
        &self.source
    }

    #[must_use]
    pub fn files(&self) -> &[WordPressAssetFingerprintFile] {
        &self.files
    }

    #[must_use]
    pub fn file(&self, path: &str) -> Option<&WordPressAssetFingerprintFile> {
        self.files
            .binary_search_by(|candidate| candidate.path.as_str().cmp(path))
            .ok()
            .map(|index| &self.files[index])
    }
}

/// Inert per-release bibliography and attribution references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintReleaseSource {
    reference: String,
    revision: String,
    notice_ids: Vec<String>,
}

impl WordPressAssetFingerprintReleaseSource {
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn notice_ids(&self) -> &[String] {
        &self.notice_ids
    }
}

/// One complete identity-content byte reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintFile {
    path: String,
    byte_length: u64,
    sha256: [u8; 32],
    representation_profile: WordPressAssetFingerprintRepresentationProfile,
}

impl WordPressAssetFingerprintFile {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[must_use]
    pub const fn representation_profile(&self) -> WordPressAssetFingerprintRepresentationProfile {
        self.representation_profile
    }
}

/// The only byte representation understood by catalogue v1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressAssetFingerprintRepresentationProfile {
    IdentityContentBytesV1,
}

impl WordPressAssetFingerprintRepresentationProfile {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::IdentityContentBytesV1 => WORDPRESS_ASSET_FINGERPRINT_REPRESENTATION_PROFILE,
        }
    }
}

/// Complete-byte input prepared only after the runtime establishes transport
/// and committed-evidence eligibility.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressObservedAssetFingerprint {
    identity: WordPressComponentIdentity,
    relative_path: String,
    byte_length: u64,
    sha256: [u8; 32],
}

impl WordPressObservedAssetFingerprint {
    pub fn new(
        identity: WordPressComponentIdentity,
        relative_path: impl Into<String>,
        byte_length: u64,
        sha256: [u8; 32],
    ) -> Result<Self, WordPressAssetFingerprintError> {
        let relative_path = relative_path.into();
        if !matches!(
            identity.kind(),
            WordPressComponentKind::Plugin | WordPressComponentKind::Theme
        ) || !valid_wordpress_asset_fingerprint_path(&relative_path)
            || byte_length > MAX_WORDPRESS_ASSET_FINGERPRINT_ASSET_BYTES
        {
            return Err(WordPressAssetFingerprintError::InvalidObservation);
        }
        Ok(Self {
            identity,
            relative_path: tight_string(relative_path),
            byte_length,
            sha256,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &WordPressComponentIdentity {
        &self.identity
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Three-valued comparison of one observed resource with one release row.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressAssetFingerprintRelation {
    Match,
    Mismatch,
    Unknown,
}

/// Why a resource/release comparison could not be made.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressAssetFingerprintUnknownReason {
    MissingReference,
    ConflictingObservations,
}

/// Three-valued aggregation for one listed release.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressAssetFingerprintReleaseState {
    Compatible,
    Inconsistent,
    Undetermined,
}

/// Conditional aggregate over only the releases represented in the catalogue.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressAssetFingerprintAggregateState {
    SingleCatalogueCandidate,
    MultipleCatalogueCandidates,
    ProvisionalCandidates,
    NoConsistentCatalogueRelease,
    NoCatalogueByteMatch,
    Undetermined,
}

/// One resource path and its comparisons with all listed releases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintResourceMatch {
    relative_path: String,
    distinct_observation_count: usize,
    informative: bool,
    releases: Vec<WordPressAssetFingerprintResourceReleaseMatch>,
}

impl WordPressAssetFingerprintResourceMatch {
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    #[must_use]
    pub const fn distinct_observation_count(&self) -> usize {
        self.distinct_observation_count
    }

    #[must_use]
    pub const fn informative(&self) -> bool {
        self.informative
    }

    #[must_use]
    pub fn releases(&self) -> &[WordPressAssetFingerprintResourceReleaseMatch] {
        &self.releases
    }
}

/// One resource/release relation with an explicit unknown reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintResourceReleaseMatch {
    release_id: String,
    relation: WordPressAssetFingerprintRelation,
    unknown_reason: Option<WordPressAssetFingerprintUnknownReason>,
}

impl WordPressAssetFingerprintResourceReleaseMatch {
    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    #[must_use]
    pub const fn relation(&self) -> WordPressAssetFingerprintRelation {
        self.relation
    }

    #[must_use]
    pub const fn unknown_reason(&self) -> Option<WordPressAssetFingerprintUnknownReason> {
        self.unknown_reason
    }
}

/// Aggregate state for one opaque listed release/build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintReleaseMatch {
    release_id: String,
    version: String,
    build_variant: Option<String>,
    state: WordPressAssetFingerprintReleaseState,
}

impl WordPressAssetFingerprintReleaseMatch {
    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn build_variant(&self) -> Option<&str> {
        self.build_variant.as_deref()
    }

    #[must_use]
    pub const fn state(&self) -> WordPressAssetFingerprintReleaseState {
        self.state
    }
}

/// Pure conditional candidate result for one scoped component identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAssetFingerprintComponentMatch {
    identity: WordPressComponentIdentity,
    catalogue_component_listed: bool,
    state: WordPressAssetFingerprintAggregateState,
    candidate_resource_count: usize,
    selected_resource_count: usize,
    completely_interpreted_resource_count: usize,
    informative_resource_count: usize,
    listed_matrix_complete: bool,
    resources: Vec<WordPressAssetFingerprintResourceMatch>,
    releases: Vec<WordPressAssetFingerprintReleaseMatch>,
}

impl WordPressAssetFingerprintComponentMatch {
    #[must_use]
    pub const fn identity(&self) -> &WordPressComponentIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn catalogue_component_listed(&self) -> bool {
        self.catalogue_component_listed
    }

    #[must_use]
    pub const fn state(&self) -> WordPressAssetFingerprintAggregateState {
        self.state
    }

    #[must_use]
    pub const fn candidate_resource_count(&self) -> usize {
        self.candidate_resource_count
    }

    #[must_use]
    pub const fn selected_resource_count(&self) -> usize {
        self.selected_resource_count
    }

    #[must_use]
    pub const fn completely_interpreted_resource_count(&self) -> usize {
        self.completely_interpreted_resource_count
    }

    #[must_use]
    pub const fn omitted_resource_count(&self) -> usize {
        self.candidate_resource_count
            .saturating_sub(self.selected_resource_count)
    }

    #[must_use]
    pub const fn informative_resource_count(&self) -> usize {
        self.informative_resource_count
    }

    #[must_use]
    pub const fn listed_matrix_complete(&self) -> bool {
        self.listed_matrix_complete
    }

    #[must_use]
    pub fn resources(&self) -> &[WordPressAssetFingerprintResourceMatch] {
        &self.resources
    }

    #[must_use]
    pub fn releases(&self) -> &[WordPressAssetFingerprintReleaseMatch] {
        &self.releases
    }

    pub fn compatible_release_ids(&self) -> impl Iterator<Item = &str> {
        self.releases.iter().filter_map(|release| {
            (release.state == WordPressAssetFingerprintReleaseState::Compatible)
                .then_some(release.release_id.as_str())
        })
    }

    pub fn undetermined_release_ids(&self) -> impl Iterator<Item = &str> {
        self.releases.iter().filter_map(|release| {
            (release.state == WordPressAssetFingerprintReleaseState::Undetermined)
                .then_some(release.release_id.as_str())
        })
    }

    pub fn inconsistent_release_ids(&self) -> impl Iterator<Item = &str> {
        self.releases.iter().filter_map(|release| {
            (release.state == WordPressAssetFingerprintReleaseState::Inconsistent)
                .then_some(release.release_id.as_str())
        })
    }

    /// Applies runtime collection coverage that the pure byte matcher cannot
    /// infer from the observations alone. A selected representation that was
    /// not completely interpreted must prevent a strong finite-catalogue
    /// candidate, while preserving every reviewed per-release relation.
    pub(crate) fn with_collection_coverage(
        mut self,
        candidate_resource_count: usize,
        selected_resource_count: usize,
        completely_interpreted_resource_count: usize,
    ) -> Self {
        self.candidate_resource_count = candidate_resource_count;
        self.selected_resource_count = selected_resource_count;
        self.completely_interpreted_resource_count = completely_interpreted_resource_count;
        if candidate_resource_count != selected_resource_count
            || selected_resource_count != completely_interpreted_resource_count
        {
            self.listed_matrix_complete = false;
            self.state = match self.state {
                WordPressAssetFingerprintAggregateState::SingleCatalogueCandidate
                | WordPressAssetFingerprintAggregateState::MultipleCatalogueCandidates => {
                    WordPressAssetFingerprintAggregateState::ProvisionalCandidates
                },
                WordPressAssetFingerprintAggregateState::NoConsistentCatalogueRelease
                | WordPressAssetFingerprintAggregateState::NoCatalogueByteMatch => {
                    WordPressAssetFingerprintAggregateState::Undetermined
                },
                state => state,
            };
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ObservedFingerprintValue {
    byte_length: u64,
    sha256: [u8; 32],
}

/// Compares already-qualified complete observations with one component's
/// finite listed release matrix.
pub fn match_wordpress_asset_fingerprint_component(
    catalog: &WordPressAssetFingerprintCatalogImport,
    identity: &WordPressComponentIdentity,
    observations: &[WordPressObservedAssetFingerprint],
) -> Result<WordPressAssetFingerprintComponentMatch, WordPressAssetFingerprintError> {
    if !matches!(
        identity.kind(),
        WordPressComponentKind::Plugin | WordPressComponentKind::Theme
    ) || observations.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_OBSERVATIONS_PER_COMPONENT
        || observations
            .iter()
            .any(|observation| observation.identity() != identity)
    {
        return Err(WordPressAssetFingerprintError::InvalidObservation);
    }

    let mut observed_by_path = BTreeMap::<String, BTreeSet<ObservedFingerprintValue>>::new();
    for observation in observations {
        observed_by_path
            .entry(observation.relative_path.clone())
            .or_default()
            .insert(ObservedFingerprintValue {
                byte_length: observation.byte_length,
                sha256: observation.sha256,
            });
    }
    if observed_by_path.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_RESOURCES_PER_COMPONENT {
        return Err(WordPressAssetFingerprintError::MatchLimitExceeded);
    }

    let observed_resource_count = observed_by_path.len();
    let Some(component) = catalog.component(identity) else {
        return Ok(WordPressAssetFingerprintComponentMatch {
            identity: identity.clone(),
            catalogue_component_listed: false,
            state: WordPressAssetFingerprintAggregateState::Undetermined,
            candidate_resource_count: observed_resource_count,
            selected_resource_count: observed_resource_count,
            completely_interpreted_resource_count: observed_resource_count,
            informative_resource_count: 0,
            listed_matrix_complete: false,
            resources: observed_by_path
                .into_iter()
                .map(
                    |(relative_path, values)| WordPressAssetFingerprintResourceMatch {
                        relative_path,
                        distinct_observation_count: values.len(),
                        informative: false,
                        releases: Vec::new(),
                    },
                )
                .collect(),
            releases: Vec::new(),
        });
    };

    let mut resources = Vec::with_capacity(observed_by_path.len());
    for (relative_path, observations) in observed_by_path {
        let reference_values = component
            .releases
            .iter()
            .filter_map(|release| release.file(&relative_path))
            .map(|file| ObservedFingerprintValue {
                byte_length: file.byte_length,
                sha256: file.sha256,
            })
            .collect::<BTreeSet<_>>();
        let informative = reference_values.len() > 1;
        let releases = component
            .releases
            .iter()
            .map(|release| {
                let (relation, unknown_reason) = match release.file(&relative_path) {
                    None => (
                        WordPressAssetFingerprintRelation::Unknown,
                        Some(WordPressAssetFingerprintUnknownReason::MissingReference),
                    ),
                    Some(_) if observations.len() != 1 => (
                        WordPressAssetFingerprintRelation::Unknown,
                        Some(WordPressAssetFingerprintUnknownReason::ConflictingObservations),
                    ),
                    Some(reference) => {
                        let observed = observations
                            .iter()
                            .next()
                            .expect("one checked observed fingerprint remains");
                        let relation = if observed.byte_length == reference.byte_length
                            && observed.sha256 == reference.sha256
                        {
                            WordPressAssetFingerprintRelation::Match
                        } else {
                            WordPressAssetFingerprintRelation::Mismatch
                        };
                        (relation, None)
                    },
                };
                WordPressAssetFingerprintResourceReleaseMatch {
                    release_id: release.release_id.clone(),
                    relation,
                    unknown_reason,
                }
            })
            .collect();
        resources.push(WordPressAssetFingerprintResourceMatch {
            relative_path,
            distinct_observation_count: observations.len(),
            informative,
            releases,
        });
    }

    let releases = component
        .releases
        .iter()
        .enumerate()
        .map(|(release_index, release)| {
            let relations = resources
                .iter()
                .map(|resource| resource.releases[release_index].relation)
                .collect::<Vec<_>>();
            let state = if relations.contains(&WordPressAssetFingerprintRelation::Mismatch) {
                WordPressAssetFingerprintReleaseState::Inconsistent
            } else if !relations.is_empty()
                && relations
                    .iter()
                    .all(|relation| *relation == WordPressAssetFingerprintRelation::Match)
            {
                WordPressAssetFingerprintReleaseState::Compatible
            } else {
                WordPressAssetFingerprintReleaseState::Undetermined
            };
            WordPressAssetFingerprintReleaseMatch {
                release_id: release.release_id.clone(),
                version: release.version.clone(),
                build_variant: release.build_variant.clone(),
                state,
            }
        })
        .collect::<Vec<_>>();

    let informative_resource_count = resources
        .iter()
        .filter(|resource| resource.informative)
        .count();
    let listed_matrix_complete = !resources.is_empty()
        && resources.iter().all(|resource| {
            resource
                .releases
                .iter()
                .all(|release| release.relation != WordPressAssetFingerprintRelation::Unknown)
        });
    let compatible = releases
        .iter()
        .filter(|release| release.state == WordPressAssetFingerprintReleaseState::Compatible)
        .count();
    let undetermined = releases
        .iter()
        .filter(|release| release.state == WordPressAssetFingerprintReleaseState::Undetermined)
        .count();
    let any_match = resources.iter().any(|resource| {
        resource
            .releases
            .iter()
            .any(|release| release.relation == WordPressAssetFingerprintRelation::Match)
    });
    let state = if compatible > 0 {
        if listed_matrix_complete && informative_resource_count >= 2 && undetermined == 0 {
            if compatible == 1 {
                WordPressAssetFingerprintAggregateState::SingleCatalogueCandidate
            } else {
                WordPressAssetFingerprintAggregateState::MultipleCatalogueCandidates
            }
        } else {
            WordPressAssetFingerprintAggregateState::ProvisionalCandidates
        }
    } else if undetermined > 0 {
        WordPressAssetFingerprintAggregateState::Undetermined
    } else if any_match {
        WordPressAssetFingerprintAggregateState::NoConsistentCatalogueRelease
    } else if !resources.is_empty() {
        WordPressAssetFingerprintAggregateState::NoCatalogueByteMatch
    } else {
        WordPressAssetFingerprintAggregateState::Undetermined
    };

    Ok(WordPressAssetFingerprintComponentMatch {
        identity: identity.clone(),
        catalogue_component_listed: true,
        state,
        candidate_resource_count: observed_resource_count,
        selected_resource_count: observed_resource_count,
        completely_interpreted_resource_count: observed_resource_count,
        informative_resource_count,
        listed_matrix_complete,
        resources,
        releases,
    })
}

/// Parses one complete strict local catalogue and prepares deterministic lookup
/// state. The exact digest identifies the supplied bytes; the semantic digest
/// ignores only ordering and JSON layout.
pub fn parse_wordpress_asset_fingerprint_catalog(
    bytes: &[u8],
) -> Result<WordPressAssetFingerprintCatalogImport, WordPressAssetFingerprintError> {
    let value = parse_bounded_json(
        bytes,
        MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_BYTES,
        MAX_CATALOG_JSON_NODES,
        MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_FILES,
        WordPressReviewError::CatalogTooLarge,
    )
    .map_err(map_bounded_json_error)?;
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some(WORDPRESS_ASSET_FINGERPRINT_CATALOG_SCHEMA)
    {
        return Err(WordPressAssetFingerprintError::UnsupportedSchema);
    }
    let wire: CatalogWire = serde_json::from_value(value)
        .map_err(|_| WordPressAssetFingerprintError::InvalidCatalog)?;
    if wire.schema != WORDPRESS_ASSET_FINGERPRINT_CATALOG_SCHEMA {
        return Err(WordPressAssetFingerprintError::UnsupportedSchema);
    }

    let mut catalog = validate_catalog_metadata(wire.catalog)?;
    catalog
        .provenance
        .notices
        .sort_by(|left, right| left.id.cmp(&right.id));
    let notice_ids = catalog
        .provenance
        .notices
        .iter()
        .map(|notice| notice.id.as_str())
        .collect::<BTreeSet<_>>();
    if notice_ids.len() != catalog.provenance.notices.len() {
        return Err(WordPressAssetFingerprintError::DuplicateIdentity);
    }

    if wire.components.is_empty()
        || wire.components.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_COMPONENTS
    {
        return Err(WordPressAssetFingerprintError::InvalidCatalog);
    }
    let mut component_identities = BTreeSet::new();
    let mut components = Vec::with_capacity(wire.components.len());
    let mut release_count = 0_usize;
    let mut file_count = 0_usize;
    for component in wire.components {
        let kind = component.kind.into();
        let slug = tight_string(component.slug);
        let identity = WordPressComponentIdentity::new(kind, slug)
            .map_err(|_| WordPressAssetFingerprintError::InvalidCatalog)?;
        if !component_identities.insert(identity.clone()) {
            return Err(WordPressAssetFingerprintError::DuplicateIdentity);
        }
        if component.releases.is_empty()
            || component.releases.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_RELEASES_PER_COMPONENT
        {
            return Err(WordPressAssetFingerprintError::InvalidCatalog);
        }
        release_count = release_count
            .checked_add(component.releases.len())
            .ok_or(WordPressAssetFingerprintError::StructuralLimitExceeded)?;
        let mut release_ids = BTreeSet::new();
        let mut releases = Vec::with_capacity(component.releases.len());
        for release in component.releases {
            if !valid_identifier(&release.release_id)
                || !valid_version_label(&release.version)
                || release
                    .build_variant
                    .as_deref()
                    .is_some_and(|value| !valid_identifier(value))
                || release.files.is_empty()
                || release.files.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_FILES_PER_RELEASE
            {
                return Err(WordPressAssetFingerprintError::InvalidCatalog);
            }
            if !release_ids.insert(release.release_id.clone()) {
                return Err(WordPressAssetFingerprintError::DuplicateIdentity);
            }
            file_count = file_count
                .checked_add(release.files.len())
                .filter(|count| *count <= MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_FILES)
                .ok_or(WordPressAssetFingerprintError::StructuralLimitExceeded)?;
            let source = validate_release_source(release.source, &notice_ids)?;
            let mut paths = BTreeSet::new();
            let mut files = Vec::with_capacity(release.files.len());
            for file in release.files {
                if !valid_wordpress_asset_fingerprint_path(&file.path)
                    || file.byte_length > MAX_WORDPRESS_ASSET_FINGERPRINT_ASSET_BYTES
                    || file.representation_profile
                        != RepresentationProfileWire::IdentityContentBytesV1
                {
                    return Err(WordPressAssetFingerprintError::InvalidCatalog);
                }
                if !paths.insert(file.path.clone()) {
                    return Err(WordPressAssetFingerprintError::DuplicateIdentity);
                }
                files.push(WordPressAssetFingerprintFile {
                    path: tight_string(file.path),
                    byte_length: file.byte_length,
                    sha256: parse_sha256(&file.sha256)?,
                    representation_profile:
                        WordPressAssetFingerprintRepresentationProfile::IdentityContentBytesV1,
                });
            }
            files.sort_by(|left, right| left.path.cmp(&right.path));
            files.shrink_to_fit();
            releases.push(WordPressAssetFingerprintRelease {
                release_id: tight_string(release.release_id),
                version: tight_string(release.version),
                build_variant: release.build_variant.map(tight_string),
                source,
                files,
            });
        }
        releases.sort_by(|left, right| left.release_id.cmp(&right.release_id));
        releases.shrink_to_fit();
        components.push(WordPressAssetFingerprintComponent { identity, releases });
    }
    components.sort_by(|left, right| left.identity.cmp(&right.identity));
    components.shrink_to_fit();
    catalog.provenance.notices.shrink_to_fit();

    let semantic_sha256 = semantic_digest(&catalog, &components);
    let byte_length =
        u64::try_from(bytes.len()).map_err(|_| WordPressAssetFingerprintError::InputTooLarge)?;
    let mut import = WordPressAssetFingerprintCatalogImport {
        byte_length,
        sha256: Sha256::digest(bytes).into(),
        semantic_sha256,
        retained_bytes: 0,
        release_count,
        file_count,
        catalog,
        components,
    };
    import.retained_bytes = retained_bytes(&import)?;
    if import.retained_bytes > MAX_WORDPRESS_ASSET_FINGERPRINT_RETAINED_BYTES {
        return Err(WordPressAssetFingerprintError::RetainedDataTooLarge);
    }
    Ok(import)
}

fn map_bounded_json_error(error: WordPressReviewError) -> WordPressAssetFingerprintError {
    match error {
        WordPressReviewError::EmptyInput => WordPressAssetFingerprintError::EmptyInput,
        WordPressReviewError::CatalogTooLarge => WordPressAssetFingerprintError::InputTooLarge,
        WordPressReviewError::DuplicateKey => WordPressAssetFingerprintError::DuplicateKey,
        WordPressReviewError::JsonLimitExceeded => {
            WordPressAssetFingerprintError::StructuralLimitExceeded
        },
        WordPressReviewError::MalformedJson => WordPressAssetFingerprintError::MalformedJson,
        _ => WordPressAssetFingerprintError::InvalidCatalog,
    }
}

fn validate_catalog_metadata(
    wire: CatalogMetadataWire,
) -> Result<WordPressAssetFingerprintCatalogMetadata, WordPressAssetFingerprintError> {
    if !valid_identifier(&wire.id)
        || !valid_identifier(&wire.revision)
        || !valid_identifier(&wire.source_namespace)
        || wire.provenance.notices.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_NOTICES
    {
        return Err(WordPressAssetFingerprintError::InvalidCatalog);
    }
    validate_reference(&wire.provenance.reference)?;
    if !valid_identifier(&wire.provenance.revision) {
        return Err(WordPressAssetFingerprintError::InvalidCatalog);
    }
    let mut notices = Vec::with_capacity(wire.provenance.notices.len());
    for notice in wire.provenance.notices {
        if !valid_identifier(&notice.id)
            || !valid_bounded_text(&notice.party, MAX_WORDPRESS_ASSET_FINGERPRINT_NOTICE_BYTES)
            || !valid_bounded_text(&notice.notice, MAX_WORDPRESS_ASSET_FINGERPRINT_NOTICE_BYTES)
            || !valid_bounded_text(
                &notice.license,
                MAX_WORDPRESS_ASSET_FINGERPRINT_NOTICE_BYTES,
            )
        {
            return Err(WordPressAssetFingerprintError::InvalidCatalog);
        }
        validate_reference(&notice.license_reference)?;
        notices.push(WordPressAssetFingerprintNotice {
            id: tight_string(notice.id),
            party: tight_string(notice.party),
            notice: tight_string(notice.notice),
            license: tight_string(notice.license),
            license_reference: tight_string(notice.license_reference),
        });
    }
    Ok(WordPressAssetFingerprintCatalogMetadata {
        id: tight_string(wire.id),
        revision: tight_string(wire.revision),
        source_namespace: tight_string(wire.source_namespace),
        provenance: WordPressAssetFingerprintProvenance {
            reference: tight_string(wire.provenance.reference),
            revision: tight_string(wire.provenance.revision),
            notices,
        },
    })
}

fn validate_release_source(
    wire: ReleaseSourceWire,
    catalogue_notice_ids: &BTreeSet<&str>,
) -> Result<WordPressAssetFingerprintReleaseSource, WordPressAssetFingerprintError> {
    validate_reference(&wire.reference)?;
    if !valid_identifier(&wire.revision)
        || wire.notice_ids.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_NOTICES
    {
        return Err(WordPressAssetFingerprintError::InvalidCatalog);
    }
    let mut notice_ids = BTreeSet::new();
    for notice_id in wire.notice_ids {
        if !valid_identifier(&notice_id)
            || !catalogue_notice_ids.contains(notice_id.as_str())
            || !notice_ids.insert(tight_string(notice_id))
        {
            return Err(WordPressAssetFingerprintError::InvalidCatalog);
        }
    }
    Ok(WordPressAssetFingerprintReleaseSource {
        reference: tight_string(wire.reference),
        revision: tight_string(wire.revision),
        notice_ids: notice_ids.into_iter().collect(),
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn valid_version_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_VERSION_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_reference(value: &str) -> Result<(), WordPressAssetFingerprintError> {
    if value.is_empty()
        || value.len() > MAX_WORDPRESS_REFERENCE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(WordPressAssetFingerprintError::InvalidCatalog);
    }
    let parsed = Url::parse(value).map_err(|_| WordPressAssetFingerprintError::InvalidCatalog)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.has_host()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
    {
        return Err(WordPressAssetFingerprintError::InvalidCatalog);
    }
    Ok(())
}

pub(crate) fn valid_wordpress_asset_fingerprint_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_WORDPRESS_ASSET_FINGERPRINT_PATH_BYTES
        || !path.is_ascii()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['\\', '%', '?', '#', ':'])
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || !(path.ends_with(".js") || path.ends_with(".css"))
    {
        return false;
    }
    path.split('/')
        .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
}

fn parse_sha256(value: &str) -> Result<[u8; 32], WordPressAssetFingerprintError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WordPressAssetFingerprintError::InvalidCatalog);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = hex_nibble(pair[0])
            .and_then(|high| hex_nibble(pair[1]).map(|low| (high << 4) | low))
            .ok_or(WordPressAssetFingerprintError::InvalidCatalog)?;
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn tight_string(value: String) -> String {
    value.into_boxed_str().into_string()
}

fn semantic_digest(
    catalog: &WordPressAssetFingerprintCatalogMetadata,
    components: &[WordPressAssetFingerprintComponent],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordpress-asset-fingerprint-catalog.semantic/v1\0");
    for value in [
        WORDPRESS_ASSET_FINGERPRINT_CATALOG_SCHEMA,
        catalog.id.as_str(),
        catalog.revision.as_str(),
        catalog.source_namespace.as_str(),
        catalog.provenance.reference.as_str(),
        catalog.provenance.revision.as_str(),
    ] {
        frame(&mut digest, value.as_bytes());
    }
    frame_usize(&mut digest, catalog.provenance.notices.len());
    for notice in &catalog.provenance.notices {
        for value in [
            notice.id.as_str(),
            notice.party.as_str(),
            notice.notice.as_str(),
            notice.license.as_str(),
            notice.license_reference.as_str(),
        ] {
            frame(&mut digest, value.as_bytes());
        }
    }
    frame_usize(&mut digest, components.len());
    for component in components {
        digest.update([match component.identity.kind() {
            WordPressComponentKind::Plugin => 1,
            WordPressComponentKind::Theme => 2,
            WordPressComponentKind::Core => 0,
        }]);
        frame(&mut digest, component.identity.slug().as_bytes());
        frame_usize(&mut digest, component.releases.len());
        for release in &component.releases {
            frame(&mut digest, release.release_id.as_bytes());
            frame(&mut digest, release.version.as_bytes());
            frame_optional(&mut digest, release.build_variant.as_deref());
            frame(&mut digest, release.source.reference.as_bytes());
            frame(&mut digest, release.source.revision.as_bytes());
            frame_usize(&mut digest, release.source.notice_ids.len());
            for notice_id in &release.source.notice_ids {
                frame(&mut digest, notice_id.as_bytes());
            }
            frame_usize(&mut digest, release.files.len());
            for file in &release.files {
                frame(&mut digest, file.path.as_bytes());
                digest.update(file.byte_length.to_be_bytes());
                digest.update(file.sha256);
                frame(&mut digest, file.representation_profile.id().as_bytes());
            }
        }
    }
    digest.finalize().into()
}

fn frame(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn frame_optional(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            frame(digest, value.as_bytes());
        },
        None => digest.update([0]),
    }
}

fn frame_usize(digest: &mut Sha256, value: usize) {
    digest.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

fn retained_bytes(
    import: &WordPressAssetFingerprintCatalogImport,
) -> Result<usize, WordPressAssetFingerprintError> {
    let mut total = size_of::<WordPressAssetFingerprintCatalogImport>();
    for value in [
        import.catalog.id.as_str(),
        import.catalog.revision.as_str(),
        import.catalog.source_namespace.as_str(),
        import.catalog.provenance.reference.as_str(),
        import.catalog.provenance.revision.as_str(),
    ] {
        charge_string(&mut total, value)?;
    }
    charge_vec::<WordPressAssetFingerprintNotice>(
        &mut total,
        import.catalog.provenance.notices.capacity(),
    )?;
    for notice in &import.catalog.provenance.notices {
        for value in [
            notice.id.as_str(),
            notice.party.as_str(),
            notice.notice.as_str(),
            notice.license.as_str(),
            notice.license_reference.as_str(),
        ] {
            charge_string(&mut total, value)?;
        }
    }
    charge_vec::<WordPressAssetFingerprintComponent>(&mut total, import.components.capacity())?;
    for component in &import.components {
        charge_string(&mut total, component.identity.slug())?;
        charge_vec::<WordPressAssetFingerprintRelease>(&mut total, component.releases.capacity())?;
        for release in &component.releases {
            for value in [
                release.release_id.as_str(),
                release.version.as_str(),
                release.source.reference.as_str(),
                release.source.revision.as_str(),
            ] {
                charge_string(&mut total, value)?;
            }
            if let Some(build_variant) = &release.build_variant {
                charge_string(&mut total, build_variant)?;
            }
            charge_vec::<String>(&mut total, release.source.notice_ids.capacity())?;
            for notice_id in &release.source.notice_ids {
                charge_string(&mut total, notice_id)?;
            }
            charge_vec::<WordPressAssetFingerprintFile>(&mut total, release.files.capacity())?;
            for file in &release.files {
                charge_string(&mut total, &file.path)?;
            }
        }
    }
    Ok(total)
}

fn charge_string(total: &mut usize, value: &str) -> Result<(), WordPressAssetFingerprintError> {
    charge(total, value.len())?;
    charge(total, CONSERVATIVE_ALLOCATION_OVERHEAD)
}

fn charge_vec<T>(total: &mut usize, capacity: usize) -> Result<(), WordPressAssetFingerprintError> {
    let bytes = capacity
        .checked_mul(size_of::<T>())
        .ok_or(WordPressAssetFingerprintError::RetainedDataTooLarge)?;
    charge(total, bytes)?;
    charge(total, CONSERVATIVE_ALLOCATION_OVERHEAD)
}

fn charge(total: &mut usize, bytes: usize) -> Result<(), WordPressAssetFingerprintError> {
    *total = total
        .checked_add(bytes)
        .ok_or(WordPressAssetFingerprintError::RetainedDataTooLarge)?;
    if *total > MAX_WORDPRESS_ASSET_FINGERPRINT_RETAINED_BYTES {
        return Err(WordPressAssetFingerprintError::RetainedDataTooLarge);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogWire {
    schema: String,
    catalog: CatalogMetadataWire,
    components: Vec<ComponentWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogMetadataWire {
    id: String,
    revision: String,
    source_namespace: String,
    provenance: ProvenanceWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceWire {
    reference: String,
    revision: String,
    notices: Vec<NoticeWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeWire {
    id: String,
    party: String,
    notice: String,
    license: String,
    license_reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentWire {
    kind: ComponentKindWire,
    slug: String,
    releases: Vec<ReleaseWire>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ComponentKindWire {
    Plugin,
    Theme,
}

impl From<ComponentKindWire> for WordPressComponentKind {
    fn from(value: ComponentKindWire) -> Self {
        match value {
            ComponentKindWire::Plugin => Self::Plugin,
            ComponentKindWire::Theme => Self::Theme,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseWire {
    release_id: String,
    version: String,
    #[serde(default)]
    build_variant: Option<String>,
    source: ReleaseSourceWire,
    files: Vec<FileWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSourceWire {
    reference: String,
    revision: String,
    notice_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileWire {
    path: String,
    byte_length: u64,
    sha256: String,
    representation_profile: RepresentationProfileWire,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum RepresentationProfileWire {
    #[serde(rename = "identity-content-bytes/v1")]
    IdentityContentBytesV1,
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    const SHA_JS_AB: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SHA_JS_C: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const SHA_CSS_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_CSS_BC: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SHA_OTHER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn file(path: &str, byte_length: u64, sha256: &str) -> Value {
        json!({
            "path": path,
            "byte_length": byte_length,
            "sha256": sha256,
            "representation_profile": "identity-content-bytes/v1"
        })
    }

    fn release(id: &str, version: &str, files: Vec<Value>) -> Value {
        json!({
            "release_id": id,
            "version": version,
            "source": {
                "reference": format!("https://example.invalid/releases/{id}"),
                "revision": id,
                "notice_ids": ["notice-main"]
            },
            "files": files
        })
    }

    fn literal_catalogue() -> Value {
        json!({
            "schema": "security.wordpress-asset-fingerprint-catalog/v1",
            "catalog": {
                "id": "task-owned-reference",
                "revision": "matrix-1",
                "source_namespace": "termivar-test",
                "provenance": {
                    "reference": "https://example.invalid/source",
                    "revision": "source-1",
                    "notices": [{
                        "id": "notice-main",
                        "party": "Termivar test authors",
                        "notice": "Original harmless reference bytes.",
                        "license": "test-only",
                        "license_reference": "https://example.invalid/license"
                    }]
                }
            },
            "components": [{
                "kind": "plugin",
                "slug": "matrix-plugin",
                "releases": [
                    release("release-a", "1.0", vec![
                        file("assets/app.js", 11, SHA_JS_AB),
                        file("assets/app.css", 21, SHA_CSS_A)
                    ]),
                    release("release-b", "1.0.0", vec![
                        file("assets/app.js", 11, SHA_JS_AB),
                        file("assets/app.css", 22, SHA_CSS_BC)
                    ]),
                    release("release-c", "2.0", vec![
                        file("assets/app.js", 12, SHA_JS_C),
                        file("assets/app.css", 22, SHA_CSS_BC)
                    ])
                ]
            }]
        })
    }

    fn parse_fixture() -> WordPressAssetFingerprintCatalogImport {
        parse_wordpress_asset_fingerprint_catalog(
            serde_json::to_vec(&literal_catalogue()).unwrap().as_slice(),
        )
        .unwrap()
    }

    fn identity() -> WordPressComponentIdentity {
        WordPressComponentIdentity::new(WordPressComponentKind::Plugin, "matrix-plugin").unwrap()
    }

    fn observed(path: &str, byte_length: u64, sha256: &str) -> WordPressObservedAssetFingerprint {
        WordPressObservedAssetFingerprint::new(
            identity(),
            path,
            byte_length,
            parse_sha256(sha256).unwrap(),
        )
        .unwrap()
    }

    fn release_states(
        matched: &WordPressAssetFingerprintComponentMatch,
    ) -> Vec<(&str, WordPressAssetFingerprintReleaseState)> {
        matched
            .releases()
            .iter()
            .map(|release| (release.release_id(), release.state()))
            .collect()
    }

    #[test]
    fn strict_catalogue_retains_raw_release_identity_and_finite_metadata() {
        let encoded = serde_json::to_vec(&literal_catalogue()).unwrap();
        let catalog = parse_wordpress_asset_fingerprint_catalog(&encoded).unwrap();
        assert_eq!(catalog.byte_length(), encoded.len() as u64);
        assert_eq!(catalog.components().len(), 1);
        assert_eq!(catalog.release_count(), 3);
        assert_eq!(catalog.file_count(), 6);
        assert!(catalog.retained_bytes() <= MAX_WORDPRESS_ASSET_FINGERPRINT_RETAINED_BYTES);
        let releases = catalog.component(&identity()).unwrap().releases();
        assert_eq!(releases[0].version(), "1.0");
        assert_eq!(releases[1].version(), "1.0.0");
        assert_ne!(releases[0].release_id(), releases[1].release_id());
        assert_eq!(
            releases[0].files()[0].representation_profile().id(),
            WORDPRESS_ASSET_FINGERPRINT_REPRESENTATION_PROFILE
        );
    }

    #[test]
    fn semantic_digest_ignores_only_layout_and_set_order() {
        let original_value = literal_catalogue();
        let original_bytes = serde_json::to_vec(&original_value).unwrap();
        let mut reordered = original_value;
        reordered["components"][0]["releases"]
            .as_array_mut()
            .unwrap()
            .reverse();
        for release in reordered["components"][0]["releases"]
            .as_array_mut()
            .unwrap()
        {
            release["files"].as_array_mut().unwrap().reverse();
        }
        let reordered_bytes = serde_json::to_vec_pretty(&reordered).unwrap();
        let original = parse_wordpress_asset_fingerprint_catalog(&original_bytes).unwrap();
        let reordered = parse_wordpress_asset_fingerprint_catalog(&reordered_bytes).unwrap();
        assert_ne!(original.sha256(), reordered.sha256());
        assert_eq!(original.semantic_sha256(), reordered.semantic_sha256());
    }

    #[test]
    fn two_independently_specified_informative_paths_select_one_listed_release() {
        let catalog = parse_fixture();
        let matched = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 11, SHA_JS_AB),
                observed("assets/app.css", 22, SHA_CSS_BC),
            ],
        )
        .unwrap();
        assert_eq!(
            matched.state(),
            WordPressAssetFingerprintAggregateState::SingleCatalogueCandidate
        );
        assert_eq!(matched.informative_resource_count(), 2);
        assert!(matched.listed_matrix_complete());
        assert_eq!(
            matched.compatible_release_ids().collect::<Vec<_>>(),
            ["release-b"]
        );
        assert_eq!(
            release_states(&matched),
            [
                (
                    "release-a",
                    WordPressAssetFingerprintReleaseState::Inconsistent
                ),
                (
                    "release-b",
                    WordPressAssetFingerprintReleaseState::Compatible
                ),
                (
                    "release-c",
                    WordPressAssetFingerprintReleaseState::Inconsistent
                ),
            ]
        );
    }

    #[test]
    fn incomplete_runtime_observation_coverage_downgrades_strong_candidate() {
        let catalog = parse_fixture();
        let matched = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 11, SHA_JS_AB),
                observed("assets/app.css", 22, SHA_CSS_BC),
            ],
        )
        .unwrap();
        let original_release_states = release_states(&matched);
        let covered = matched.clone().with_collection_coverage(3, 2, 2);

        assert_eq!(
            covered.state(),
            WordPressAssetFingerprintAggregateState::ProvisionalCandidates
        );
        assert!(!covered.listed_matrix_complete());
        assert_eq!(covered.candidate_resource_count(), 3);
        assert_eq!(covered.selected_resource_count(), 2);
        assert_eq!(covered.completely_interpreted_resource_count(), 2);
        assert_eq!(covered.omitted_resource_count(), 1);
        assert_eq!(release_states(&covered), original_release_states);
        assert_eq!(
            covered.compatible_release_ids().collect::<Vec<_>>(),
            ["release-b"]
        );
    }

    #[test]
    fn incomplete_runtime_coverage_cannot_preserve_a_strong_negative_summary() {
        let catalog = parse_fixture();
        let mixed = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 11, SHA_JS_AB),
                observed("assets/app.css", 23, SHA_OTHER),
            ],
        )
        .unwrap();
        assert_eq!(
            mixed.state(),
            WordPressAssetFingerprintAggregateState::NoConsistentCatalogueRelease
        );
        assert_eq!(
            mixed.with_collection_coverage(2, 2, 1).state(),
            WordPressAssetFingerprintAggregateState::Undetermined
        );

        let no_match = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 13, SHA_OTHER),
                observed("assets/app.css", 23, SHA_OTHER),
            ],
        )
        .unwrap();
        assert_eq!(
            no_match.state(),
            WordPressAssetFingerprintAggregateState::NoCatalogueByteMatch
        );
        assert_eq!(
            no_match.with_collection_coverage(3, 2, 2).state(),
            WordPressAssetFingerprintAggregateState::Undetermined
        );
    }

    #[test]
    fn one_file_is_provisional_even_when_its_candidate_set_is_exact_for_that_path() {
        let catalog = parse_fixture();
        let matched = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[observed("assets/app.js", 11, SHA_JS_AB)],
        )
        .unwrap();
        assert_eq!(
            matched.state(),
            WordPressAssetFingerprintAggregateState::ProvisionalCandidates
        );
        assert_eq!(
            matched.compatible_release_ids().collect::<Vec<_>>(),
            ["release-a", "release-b"]
        );
        assert_eq!(matched.informative_resource_count(), 1);
    }

    #[test]
    fn missing_reference_is_unknown_and_cannot_become_a_mismatch() {
        let mut fixture = literal_catalogue();
        fixture["components"][0]["releases"][0]["files"]
            .as_array_mut()
            .unwrap()
            .remove(1);
        let encoded = serde_json::to_vec(&fixture).unwrap();
        let catalog = parse_wordpress_asset_fingerprint_catalog(&encoded).unwrap();
        let matched = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 11, SHA_JS_AB),
                observed("assets/app.css", 22, SHA_CSS_BC),
            ],
        )
        .unwrap();
        assert_eq!(
            matched.state(),
            WordPressAssetFingerprintAggregateState::ProvisionalCandidates
        );
        assert_eq!(
            matched.undetermined_release_ids().collect::<Vec<_>>(),
            ["release-a"]
        );
        let css = matched
            .resources()
            .iter()
            .find(|resource| resource.relative_path() == "assets/app.css")
            .unwrap();
        assert_eq!(
            css.releases()[0].relation(),
            WordPressAssetFingerprintRelation::Unknown
        );
        assert_eq!(
            css.releases()[0].unknown_reason(),
            Some(WordPressAssetFingerprintUnknownReason::MissingReference)
        );
    }

    #[test]
    fn contradictory_complete_observations_do_not_choose_a_favourite() {
        let catalog = parse_fixture();
        let matched = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 11, SHA_JS_AB),
                observed("assets/app.js", 12, SHA_JS_C),
            ],
        )
        .unwrap();
        assert_eq!(
            matched.state(),
            WordPressAssetFingerprintAggregateState::Undetermined
        );
        assert_eq!(matched.resources()[0].distinct_observation_count(), 2);
        assert!(matched.releases().iter().all(|release| {
            release.state() == WordPressAssetFingerprintReleaseState::Undetermined
        }));
        assert!(matched.resources()[0].releases().iter().all(|release| {
            release.unknown_reason()
                == Some(WordPressAssetFingerprintUnknownReason::ConflictingObservations)
        }));
    }

    #[test]
    fn no_consistent_release_and_no_byte_match_are_distinct() {
        let catalog = parse_fixture();
        let mixed = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 11, SHA_JS_AB),
                observed("assets/app.css", 23, SHA_OTHER),
            ],
        )
        .unwrap();
        assert_eq!(
            mixed.state(),
            WordPressAssetFingerprintAggregateState::NoConsistentCatalogueRelease
        );
        let none = match_wordpress_asset_fingerprint_component(
            &catalog,
            &identity(),
            &[
                observed("assets/app.js", 13, SHA_OTHER),
                observed("assets/app.css", 23, SHA_OTHER),
            ],
        )
        .unwrap();
        assert_eq!(
            none.state(),
            WordPressAssetFingerprintAggregateState::NoCatalogueByteMatch
        );
    }

    #[test]
    fn unlisted_component_and_empty_observations_remain_undetermined() {
        let catalog = parse_fixture();
        let unlisted =
            WordPressComponentIdentity::new(WordPressComponentKind::Theme, "unlisted-theme")
                .unwrap();
        let matched =
            match_wordpress_asset_fingerprint_component(&catalog, &unlisted, &[]).unwrap();
        assert!(!matched.catalogue_component_listed());
        assert_eq!(
            matched.state(),
            WordPressAssetFingerprintAggregateState::Undetermined
        );
        let empty =
            match_wordpress_asset_fingerprint_component(&catalog, &identity(), &[]).unwrap();
        assert!(empty.catalogue_component_listed());
        assert_eq!(
            empty.state(),
            WordPressAssetFingerprintAggregateState::Undetermined
        );
    }

    #[test]
    fn strict_parser_rejects_unknown_duplicate_and_unsafe_values() {
        let duplicate = br#"{
            "schema":"security.wordpress-asset-fingerprint-catalog/v1",
            "schema":"security.wordpress-asset-fingerprint-catalog/v1"
        }"#;
        assert_eq!(
            parse_wordpress_asset_fingerprint_catalog(duplicate),
            Err(WordPressAssetFingerprintError::DuplicateKey)
        );

        let mut unknown = literal_catalogue();
        unknown["execute"] = json!(true);
        assert_eq!(
            parse_wordpress_asset_fingerprint_catalog(&serde_json::to_vec(&unknown).unwrap()),
            Err(WordPressAssetFingerprintError::InvalidCatalog)
        );

        for invalid in [
            "../app.js",
            "/assets/app.js",
            "assets\\app.js",
            "assets/%61pp.js",
            "assets/app.js?ver=1",
            "assets/app.js#fragment",
            "assets/app.min.js.map",
            "assets/app.php",
        ] {
            let mut value = literal_catalogue();
            value["components"][0]["releases"][0]["files"][0]["path"] = json!(invalid);
            assert_eq!(
                parse_wordpress_asset_fingerprint_catalog(&serde_json::to_vec(&value).unwrap()),
                Err(WordPressAssetFingerprintError::InvalidCatalog),
                "{invalid}"
            );
        }
    }

    #[test]
    fn strict_parser_rejects_wrong_digest_length_bool_length_and_duplicate_identities() {
        let mut uppercase = literal_catalogue();
        uppercase["components"][0]["releases"][0]["files"][0]["sha256"] =
            json!(SHA_CSS_A.to_ascii_uppercase());
        assert_eq!(
            parse_wordpress_asset_fingerprint_catalog(&serde_json::to_vec(&uppercase).unwrap()),
            Err(WordPressAssetFingerprintError::InvalidCatalog)
        );

        let mut boolean = literal_catalogue();
        boolean["components"][0]["releases"][0]["files"][0]["byte_length"] = json!(true);
        assert_eq!(
            parse_wordpress_asset_fingerprint_catalog(&serde_json::to_vec(&boolean).unwrap()),
            Err(WordPressAssetFingerprintError::InvalidCatalog)
        );

        let mut duplicate_release = literal_catalogue();
        let duplicate = duplicate_release["components"][0]["releases"][0].clone();
        duplicate_release["components"][0]["releases"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(
            parse_wordpress_asset_fingerprint_catalog(
                &serde_json::to_vec(&duplicate_release).unwrap()
            ),
            Err(WordPressAssetFingerprintError::DuplicateIdentity)
        );

        let mut duplicate_path = literal_catalogue();
        let duplicate = duplicate_path["components"][0]["releases"][0]["files"][0].clone();
        duplicate_path["components"][0]["releases"][0]["files"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(
            parse_wordpress_asset_fingerprint_catalog(
                &serde_json::to_vec(&duplicate_path).unwrap()
            ),
            Err(WordPressAssetFingerprintError::DuplicateIdentity)
        );
    }

    #[test]
    fn parser_and_matcher_enforce_independent_bounds() {
        let mut too_many_components = literal_catalogue();
        let template = too_many_components["components"][0].clone();
        let components = too_many_components["components"].as_array_mut().unwrap();
        for index in 1..=MAX_WORDPRESS_ASSET_FINGERPRINT_CATALOG_COMPONENTS {
            let mut component = template.clone();
            component["slug"] = json!(format!("matrix-plugin-{index}"));
            components.push(component);
        }
        assert_eq!(
            parse_wordpress_asset_fingerprint_catalog(
                &serde_json::to_vec(&too_many_components).unwrap()
            ),
            Err(WordPressAssetFingerprintError::InvalidCatalog)
        );

        let catalog = parse_fixture();
        let observations = [
            observed("assets/app.js", 11, SHA_JS_AB),
            observed("assets/app.css", 22, SHA_CSS_BC),
            observed("assets/third.js", 7, SHA_OTHER),
        ];
        assert_eq!(
            match_wordpress_asset_fingerprint_component(&catalog, &identity(), &observations),
            Err(WordPressAssetFingerprintError::MatchLimitExceeded)
        );
    }
}
